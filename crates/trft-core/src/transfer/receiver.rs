//! 接收端（TCP / QUIC 共用逻辑）：加密升级（0x09）、可选配对门（含 IP 锁定）、
//! 前导协商（0x0A 能力 / 0x08 压缩，WIRE-PROTOCOL.md §2）、
//! 0x00 单文件、0x01 文件夹、0x02 分块、0x03/0x04 续传、0x06 文本。
//! 全部走「唯一半成品 + 校验 + 原子改名」；fail-closed：未知帧、配对失败、
//! 哈希不一致一律拒绝，半成品一律清理。

use crate::config::{ConfirmMode, DuplicatePolicy};
use crate::crypto::kdf::{ct_eq, derive_pairing_key, pairing_proof, pairing_proof_bound, pairing_proof_s2c};
use crate::error::{Error, Result, proto};
use crate::hash::{FileDigester, sha256_file};
use crate::hashcache::HashCache;
use crate::limiter::TokenBucket;
use crate::protocol::frame::{
    CAP_CHUNKED, CAP_COMPRESS, CAP_COVERAGE, CAP_RESUME_FILE, CAP_RESUME_FOLDER, MAX_TRANSFER_SIZE,
    R_CAPABILITY, R_PAIRING_SALT, STATUS_OK, STATUS_REJECT, T_CAPABILITY, T_CHUNKED, T_CHUNK_END,
    T_COMPRESS, T_COMPRESS_OK, T_COVERAGE_QUERY, T_FOLDER, T_PAIRING, T_PAIRING_BOUND,
    T_RESUME_FILE, T_RESUME_FOLDER, T_SINGLE_FILE, T_TEXT, sanitize_name,
};
use crate::protocol::io::{read_n, read_str_u16, read_u32, read_u64, read_u8, write_all, write_u8};
use crate::transfer::chunked::{self, ChunkTracker};
use crate::transfer::compress::Compressed;
use crate::transfer::encrypted;
use crate::transfer::folder::recv_folder_over;
use crate::transfer::resume;
use crate::transfer::CHUNK;
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::task::JoinSet;

/// 规格 §4.1/§6.1：按来源 IP 计数锁定——10 次失败锁 10 分钟，成功清零。
const LOCKOUT_THRESHOLD: u32 = 10;
const LOCKOUT_DURATION: Duration = Duration::from_secs(600);

/// 接收前确认（规格 §3.3）：确认框超时；同 IP 免重复窗口。
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(30);
const CONFIRM_REMEMBER: Duration = Duration::from_secs(600);

/// 接收前确认请求：GUI（或测试）经 `reply` 应答；**无应答 = 拒绝（fail-closed）**。
pub struct ConfirmRequest {
    pub peer: IpAddr,
    /// 设备记忆名（未知设备 = IP 字符串）。
    pub device: String,
    pub reply: tokio::sync::oneshot::Sender<bool>,
}

/// 锁定门聚合键（轮 6 P2-3）：IPv4 按地址；**IPv6 按 /64 前缀**——
/// SLAAC/隐私扩展让单机持有海量地址，按 /128 计数时每地址 ≤9 次即可无限绕过锁定。
pub fn gate_key(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(*v4),
        IpAddr::V6(v6) => {
            let seg = u128::from(*v6) & !0xFFFF_FFFF_FFFF_FFFF; // 高 64 位
            IpAddr::V6(std::net::Ipv6Addr::from(seg))
        }
    }
}

#[derive(Default)]
pub struct PairingGate {
    fails: HashMap<IpAddr, u32>,
    locked_until: HashMap<IpAddr, Instant>,
}

impl PairingGate {
    pub fn locked(&self, ip: &IpAddr) -> bool {
        let k = gate_key(ip);
        self.locked_until.get(&k).is_some_and(|t| *t > Instant::now())
    }

    pub fn fail(&mut self, ip: &IpAddr) {
        let k = gate_key(ip);
        // 容量防线：表过大时先扫过期，仍超则整体重置（fail-closed）。
        if self.fails.len() + self.locked_until.len() > 4096 {
            let now = Instant::now();
            self.locked_until.retain(|_, t| *t > now);
            if self.fails.len() > 8192 {
                // 只重置失败计数；生效中的锁定不得被洪水重置（规格 §4.1）。
                self.fails.clear();
            }
        }
        let f = self.fails.entry(k).or_default();
        *f += 1;
        if *f >= LOCKOUT_THRESHOLD {
            self.locked_until.insert(k, Instant::now() + LOCKOUT_DURATION);
            self.fails.remove(&k);
        }
    }

    pub fn success(&mut self, ip: &IpAddr) {
        let k = gate_key(ip);
        self.fails.remove(&k);
        self.locked_until.remove(&k);
    }
}

/// 错误路径清理守卫：半成品文件活到守卫结束仍未改名 → 删除。
pub(crate) struct PartGuard(pub(crate) PathBuf);
impl Drop for PartGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// 磁盘预检（规格 §3.1：可用 ≥ 声明 + 64MB 余量；探测失败按规格放行）。
/// IP 过滤匹配（规格 §3.3）：精确地址、`192.168.1.*` 通配（v4 末段）、CIDR（v4/v6
/// 前缀位比对，跨族永不匹配）；坏条目不匹配（fail-closed）。
pub fn ip_match(ip: IpAddr, pattern: &str) -> bool {
    let pat = pattern.trim();
    if pat.is_empty() {
        return false;
    }
    // CIDR：a.b.c.d/nn 或 x::/nn
    if let Some((addr_part, len_part)) = pat.split_once('/') {
        let Ok(net) = addr_part.parse::<IpAddr>() else { return false };
        let Ok(len) = len_part.parse::<u8>() else { return false };
        match (net, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                if len > 32 {
                    return false;
                }
                // /0 = 匹配全部同族地址（轮 4 P3-5：位移 32 在 debug panic、
                // release 掩码成精确比较使 deny fail-open）。
                if len == 0 {
                    return true;
                }
                let shift = 32 - len as u32;
                if (u32::from(n) >> shift) != (u32::from(i) >> shift) {
                    return false;
                }
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                if len > 128 {
                    return false;
                }
                if len == 0 {
                    return true;
                }
                let shift = 128 - len as u32;
                if (u128::from(n) >> shift) != (u128::from(i) >> shift) {
                    return false;
                }
            }
            _ => return false, // 跨族永不匹配
        }
        true
    } else if pat.contains('*') {
        // v4 通配：按 '.' 分组，'*' 组匹配任意；'*' 之后不得再有非通配组（前缀语义）。
        let IpAddr::V4(v4) = ip else { return false };
        let octets = v4.octets();
        let groups: Vec<&str> = pat.split('.').collect();
        if groups.len() > 4 {
            return false;
        }
        for (i, g) in groups.iter().enumerate() {
            if *g == "*" {
                return groups[i..].iter().all(|x| *x == "*");
            }
            match g.parse::<u8>() {
                Ok(o) if i < 4 && octets[i] == o => {}
                _ => return false,
            }
        }
        true
    } else {
        // 精确
        pat.parse::<IpAddr>().map(|p| p == ip).unwrap_or(false)
    }
}

/// IP 过滤判定（规格 §3.3：off / allow（至少一条匹配）/ deny（不得匹配任何条目））。
pub fn ip_allowed(ip: IpAddr, mode: crate::config::FilterMode, list: &[String]) -> bool {
    use crate::config::FilterMode;
    match mode {
        FilterMode::Off => true,
        FilterMode::Allow => list.iter().any(|p| ip_match(ip, p)),
        FilterMode::Deny => !list.iter().any(|p| ip_match(ip, p)),
    }
}

pub(crate) fn space_ok(dir: &Path, need: u64) -> bool {
    match fs4::available_space(dir) {
        Ok(avail) => avail >= need.saturating_add(64 * 1024 * 1024),
        Err(_) => true,
    }
}

/// 唯一半成品路径：随机段隔离并发同名传输（修复交叉写竞态）。
pub(crate) fn unique_part(dir: &Path, name: &str) -> PathBuf {
    let p = Path::new(name);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = p
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let mut rnd = [0u8; 4];
    OsRng.fill_bytes(&mut rnd);
    dir.join(format!("{stem}.{:08x}{ext}.trft-part", u32::from_le_bytes(rnd)))
}

#[derive(Clone)]
pub struct RecvOptions {
    pub save_dir: PathBuf,
    pub pairing_code: Option<String>,
    pub recv_limit_bps: u64,
    pub duplicate: DuplicatePolicy,
    /// 成功帧数上限（任一帧成功处理即计 1），达到即停（对应 CLI --count）。
    pub max_count: Option<u64>,
    /// 收到文本的回调通道（GUI/Web 面接入点；None 时仅打印）。
    pub text_tx: Option<mpsc::UnboundedSender<String>>,
    /// 接受 0x09 加密升级（TCP 槽位；QUIC 由 TLS 承担）。
    pub encrypt: bool,
    /// 接受 0x08 压缩协商（仅认证后；关闭时回 0x00 宽容降级）。
    pub compress: bool,
    /// 接受 0x02/0x0B/0x0C 分块帧（false = 模拟旧对端，供降级矩阵测试）。
    pub enable_chunked: bool,
    /// 接受 0x03/0x04 续传帧（false = 模拟旧对端）。
    pub enable_resume: bool,
    /// 接收侧摘要缓存（0x00/0x01/0x03/0x02 组装免费填充；0x03 skip 判定/0x04 位图判定读取）。
    pub hash_cache: Option<Arc<Mutex<HashCache>>>,
    /// 0x02 分块会话表（groupId → 半成品 + 合并区间）。
    pub chunk_sessions: Arc<ChunkTracker>,
    /// 0x03 会话锁（对端 IP + 文件名 → 锁，防跨连接并发写坏半成品）。
    pub resume_locks: Arc<Mutex<HashMap<(IpAddr, String), Arc<Mutex<()>>>>>,
    /// 配对失败锁定状态（serve 级共享）。
    pub gate: Arc<Mutex<PairingGate>>,
    /// 常驻模式并发连接闸。
    pub permits: Arc<Semaphore>,
    /// 进度事件出口（GUI 注入；None = 不上报，CLI 路径零开销）。
    pub progress: Option<crate::progress::ProgressHub>,
    /// 同步逐字节核对（规格 §3.3 SyncVerifyContent）：开启即绕过接收侧摘要缓存
    /// 判定（strict），0x03 skip 与 0x04 位图差分全部按「无记录」处理。
    pub strict_verify: bool,
    /// IP 过滤（规格 §3.3）：off / allow / deny + 条目列表（精确/通配/CIDR）。
    pub ip_filter_mode: crate::config::FilterMode,
    pub ip_filter_list: Vec<String>,
    /// 设备记忆共享快照（M5'：PerDeviceFolder 名称解析 / ConfirmReceive 已知判定）。
    pub devices: Option<Arc<crate::devices::DeviceStore>>,
    /// 按设备分目录（规格 §3.3 PerDeviceFolder）：`<save>/<设备名|IP>/`。
    pub per_device_folder: bool,
    /// 按日期归档（规格 §3.3 AutoArchive）：在设备目录下再落 `<yyyy-mm-dd>/`。
    pub auto_archive: bool,
    /// 接收前确认模式（规格 §3.3 ConfirmReceive）。
    pub confirm_mode: ConfirmMode,
    /// 确认应答通道（GUI 注入）；mode ≠ off 而通道缺省 → 一律拒绝（fail-closed）。
    pub confirm_tx: Option<mpsc::UnboundedSender<ConfirmRequest>>,
    /// 同 IP 确认免重复窗口（10 分钟；serve 级共享）。
    pub confirm_seen: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    /// 确认等待上限（默认规格 §3.3 的 30 秒；测试注入短超时用）。
    pub confirm_timeout: Duration,
    /// 传输统计（M5'：成功完成记账；None = 不记）。
    pub stats: Option<Arc<crate::stats::StatsLog>>,
}

impl Default for RecvOptions {
    fn default() -> Self {
        Self {
            save_dir: std::env::temp_dir().join("trft-received"),
            pairing_code: None,
            recv_limit_bps: 0,
            duplicate: DuplicatePolicy::Rename,
            max_count: None,
            text_tx: None,
            encrypt: true,
            compress: true,
            enable_chunked: true,
            enable_resume: true,
            hash_cache: None,
            chunk_sessions: Arc::new(ChunkTracker::default()),
            resume_locks: Arc::new(Mutex::new(HashMap::new())),
            gate: Arc::new(Mutex::new(PairingGate::default())),
            permits: Arc::new(Semaphore::new(64)),
            progress: None,
            strict_verify: false,
            ip_filter_mode: crate::config::FilterMode::Off,
            ip_filter_list: Vec::new(),
            devices: None,
            per_device_folder: false,
            auto_archive: false,
            confirm_mode: ConfirmMode::Off,
            confirm_tx: None,
            confirm_seen: Arc::new(Mutex::new(HashMap::new())),
            confirm_timeout: CONFIRM_TIMEOUT,
            stats: None,
        }
    }
}

/// 接收侧成功记账（仅成功；与发送侧同口径——TECH-STACK §7.10）。
pub(crate) fn record_recv(
    opts: &RecvOptions,
    peer: SocketAddr,
    bytes: u64,
    files: u32,
    started: Instant,
    detail: &str,
    name: &str,
) {
    if let Some(s) = &opts.stats {
        s.record(
            crate::stats::Direction::Recv,
            &peer.ip().to_string(),
            bytes,
            files,
            started.elapsed().as_secs(),
            detail,
            name,
        );
    }
}

/// 接收落盘目录解析（规格 §3.3 PerDeviceFolder + AutoArchive）：
/// `<save>/<设备名|IP>/<yyyy-mm-dd>/`。设备名经 sanitize 防路径穿越；
/// IP 回退分量也做合法化（IPv6 含 `:`，Windows 目录名非法——轮 1 修复）；
/// 解析在会话/连接建立时执行一次并随会话固定（防设备改名孤儿化续传会话）。
pub(crate) fn resolve_save_dir(opts: &RecvOptions, peer: IpAddr) -> PathBuf {
    let mut dir = opts.save_dir.clone();
    if opts.per_device_folder {
        let comp = opts
            .devices
            .as_ref()
            .and_then(|d| d.name_for(peer))
            .and_then(|n| sanitize_name(&n).ok())
            .unwrap_or_else(|| ip_dir_component(peer));
        dir.push(comp);
    }
    if opts.auto_archive {
        dir.push(today_component());
    }
    dir
}

/// IP → 目录分量：IPv4 原样；IPv6 把 `:` 换成 `_`（Windows 文件名禁止冒号）。
pub(crate) fn ip_dir_component(peer: IpAddr) -> String {
    match peer {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("v6-{}", v6.to_string().replace(':', "_")),
    }
}

/// 本地日期段（`yyyy-mm-dd`）。本地时区获取失败回退 UTC——判错方向仅是
/// 归档桶错位（次日/同日边界），不影响完整性语义。
pub fn today_component() -> String {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    format!("{:04}-{:02}-{:02}", now.year(), u8::from(now.month()), now.day())
}

/// 每连接确认一次（规格 §3.3）：首个文件帧前判定；通过后连接内不再重复。
/// off / 窗口内 / unknown 且已知 → 直接过；其余走确认框，30s 超时或拒绝即失败。
async fn confirm_once(
    peer: SocketAddr,
    opts: &RecvOptions,
    confirmed: &mut bool,
) -> Result<()> {
    if *confirmed || opts.confirm_mode == ConfirmMode::Off {
        return Ok(());
    }
    {
        let mut seen = opts.confirm_seen.lock().await;
        // 容量防线（与 PairingGate 同纪律）：过期条目清理 + 硬上限防洪。
        if seen.len() > 4096 {
            seen.retain(|_, t| t.elapsed() < CONFIRM_REMEMBER);
            if seen.len() > 8192 {
                seen.clear();
            }
        }
        if seen
            .get(&peer.ip())
            .is_some_and(|t| t.elapsed() < CONFIRM_REMEMBER)
        {
            *confirmed = true;
            return Ok(());
        }
    }
    if opts.confirm_mode == ConfirmMode::Unknown
        && opts
            .devices
            .as_ref()
            .is_some_and(|d| d.is_known(peer.ip()))
    {
        *confirmed = true;
        return Ok(());
    }
    let Some(tx) = &opts.confirm_tx else {
        // fail-closed：要求确认却没有应答通道 → 拒绝（无人值守路径必须显式 off）。
        return Err(Error::Rejected(format!(
            "{peer}: 接收前确认未配置应答通道，已拒绝（fail-closed）"
        )));
    };
    let device = opts
        .devices
        .as_ref()
        .and_then(|d| d.name_for(peer.ip()))
        .unwrap_or_else(|| peer.ip().to_string());
    let (rtx, rrx) = tokio::sync::oneshot::channel();
    if tx
        .send(ConfirmRequest { peer: peer.ip(), device, reply: rtx })
        .is_err()
    {
        return Err(Error::Rejected(format!("{peer}: 确认通道已关闭，已拒绝")));
    }
    let ok = match tokio::time::timeout(opts.confirm_timeout, rrx).await {
        Ok(Ok(v)) => v,
        _ => false, // 超时 / 应答端丢弃 = 拒绝（规格 §3.3：无应答视为拒绝）
    };
    if !ok {
        return Err(Error::Rejected(format!("{peer}: 接收前确认未通过")));
    }
    opts.confirm_seen
        .lock()
        .await
        .insert(peer.ip(), Instant::now());
    *confirmed = true;
    Ok(())
}

pub async fn serve(addr: SocketAddr, opts: RecvOptions) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_on(listener, opts).await
}

/// TCP/QUIC 侧孤儿半成品清扫（与 UDP cleanup_orphans 同策略：7 天）。
/// PerDeviceFolder/AutoArchive 落地在子目录——递归扫描（深度封顶防符号链接环）。
pub fn cleanup_part_orphans(dir: &Path) {
    fn walk(dir: &Path, depth: u32) {
        if depth > 6 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let now = std::time::SystemTime::now();
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if p.is_dir() {
                walk(&p, depth + 1);
                continue;
            }
            if !name.ends_with(".trft-part") {
                continue;
            }
            if let Ok(md) = e.metadata() {
                if md
                    .modified()
                    .map(|t| now.duration_since(t).map(|d| d > std::time::Duration::from_secs(7 * 24 * 3600)).unwrap_or(false))
                    .unwrap_or(false)
                {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }
    walk(dir, 0);
}

pub async fn serve_on(listener: TcpListener, opts: RecvOptions) -> Result<()> {
    cleanup_part_orphans(&opts.save_dir);
    resume::cleanup_resume_orphans(&opts.save_dir);
    let served = Arc::new(AtomicU64::new(0));
    match opts.max_count {
        // 限量模式（CLI --count）：串行处理，收满即停——避免已阻塞的 accept
        // 在计数达标后仍醒不过来。
        Some(max) => loop {
            if served.load(Ordering::Relaxed) >= max {
                return Ok(());
            }
            match listener.accept().await {
                Ok((s, peer)) => {
                    if let Err(e) = handle_conn(s, peer, &opts, served.clone()).await {
                        eprintln!("[连接失败] {e}");
                    }
                }
                Err(e) => return Err(Error::Io(e)),
            }
        },
        // 常驻模式：并发处理所有连接（带并发闸）。
        None => {
            let mut set = JoinSet::new();
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let o = opts.clone();
                        let counter = served.clone();
                        set.spawn(async move {
                            if let Err(e) = handle_conn(stream, peer, &o, counter).await {
                                eprintln!("[连接失败] {e}");
                            }
                        });
                    }
                    Err(e) => {
                        while set.join_next().await.is_some() {}
                        return Err(Error::Io(e));
                    }
                }
            }
        }
    }
}

/// 连接前置检查（并发闸 + 配对锁定）与后置记账（锁定计数/成功清零）。
/// 并发闸许可（QUIC 在 TLS 握手前也要先拿闸）。
pub(crate) async fn conn_permit(opts: &RecvOptions) -> Result<tokio::sync::OwnedSemaphorePermit> {
    opts.permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| proto(e.to_string()))
}

/// 锁定门（需真实 peer IP）。
pub(crate) async fn gate_check(peer: SocketAddr, opts: &RecvOptions) -> Result<()> {
    if opts.pairing_code.is_some() && opts.gate.lock().await.locked(&peer.ip()) {
        return Err(Error::AuthRejected(format!("{peer}: 配对失败次数过多，已临时锁定")));
    }
    Ok(())
}

pub(crate) async fn conn_precheck(
    peer: SocketAddr,
    opts: &RecvOptions,
) -> Result<tokio::sync::OwnedSemaphorePermit> {
    // IP 过滤先行（规格 §3.3）：被拒连接不得消耗并发闸额度。
    if !ip_allowed(peer.ip(), opts.ip_filter_mode, &opts.ip_filter_list) {
        return Err(Error::Rejected(format!("{}: 被 IP 过滤规则拒绝", peer.ip())));
    }
    let permit = opts
        .permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| proto(e.to_string()))?;
    if opts.pairing_code.is_some() && opts.gate.lock().await.locked(&peer.ip()) {
        return Err(Error::AuthRejected(format!("{peer}: 配对失败次数过多，已临时锁定")));
    }
    Ok(permit)
}

pub(crate) async fn conn_settle(
    r: &Result<()>,
    handled: u64,
    peer: SocketAddr,
    opts: &RecvOptions,
    served: &Arc<AtomicU64>,
) {
    let mut g = opts.gate.lock().await;
    match r {
        Ok(()) => g.success(&peer.ip()),
        // 规格 §4.1：仅认证失败计数（磁盘空间等业务拒绝不计入锁定）。
        Err(Error::AuthRejected(_)) => g.fail(&peer.ip()),
        _ => {}
    }
    drop(g);
    if handled > 0 {
        served.fetch_add(handled, Ordering::Relaxed);
    }
}

/// TCP 入口：首字节 0x09 = 加密升级（规格 §4.1 认证在前、装饰器在后）。
pub(crate) async fn handle_conn<S>(
    mut s: S,
    peer: SocketAddr,
    opts: &RecvOptions,
    served: Arc<AtomicU64>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _permit = conn_precheck(peer, opts).await?;
    let mut handled = 0u64;
    let first = read_u8(&mut s).await?;
    let r = if first == encrypted::T_ENCRYPT && opts.encrypt {
        match encrypted::server_wrap(s, opts.pairing_code.as_deref()).await {
            Ok((enc, authed)) => {
                conn_loop_inner(enc, peer, opts, &mut handled, None, authed, &served, false, None).await
            }
            Err(e) => Err(e),
        }
    } else {
        conn_loop_inner(s, peer, opts, &mut handled, Some(first), false, &served, false, None).await
    };
    conn_settle(&r, handled, peer, opts, &served).await;
    r
}

/// QUIC 入口：TLS 已承担机密性，跳过 0x09，直接进帧循环（配对门在流内）。
/// `binding` = 服务端证书指纹（Some → 配对门强制 0x0D 通道绑定证明）。
pub(crate) async fn handle_conn_quic<S>(
    s: S,
    peer: SocketAddr,
    opts: &RecvOptions,
    served: Arc<AtomicU64>,
    binding: Option<[u8; 32]>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 过滤与闸由 quic.rs 的 handle_incoming 完成（IP 过滤先于握手、单次持闸）。
    let _permit = permit;
    let mut handled = 0u64;
    // QUIC：Connection drop 会隐式重置流、吞掉客户端的状态字节读取——
    // 收尾排水必须在帧循环内部（栈还活着时）执行。
    let r = conn_loop_inner(s, peer, opts, &mut handled, None, false, &served, true, binding).await;
    conn_settle(&r, handled, peer, opts, &served).await;
    r
}

/// 能力位表（0x1A）：由接收选项推导（WIRE-PROTOCOL.md §2.2）。
fn caps_of(opts: &RecvOptions) -> u8 {
    let mut c = 0u8;
    if opts.enable_chunked {
        c |= CAP_CHUNKED | CAP_COVERAGE;
    }
    if opts.enable_resume {
        c |= CAP_RESUME_FILE | CAP_RESUME_FOLDER;
    }
    if opts.compress {
        c |= CAP_COMPRESS;
    }
    c
}

/// 前导协商（认证之后、业务帧之前）：0x0A 能力探询与 0x08 压缩协商，
/// 各至多一次、顺序不限；遇业务帧字节即返回（含包装后的栈 + 待处理帧）。
async fn negotiate_stack<S>(
    mut s: S,
    mut pending: Option<u8>,
    opts: &RecvOptions,
) -> Result<(crate::transfer::Framed<S>, Option<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut caps_done = false;
    loop {
        let t = match pending.take() {
            Some(t) => t,
            None => read_u8(&mut s).await?,
        };
        match t {
            T_CAPABILITY if !caps_done => {
                caps_done = true;
                write_u8(&mut s, R_CAPABILITY).await?;
                write_u8(&mut s, caps_of(opts)).await?;
            }
            T_COMPRESS if opts.compress => {
                write_u8(&mut s, T_COMPRESS_OK).await?;
                return Ok((crate::transfer::Framed::Comp(Compressed::new(s)), pending));
            }
            T_COMPRESS => {
                // 服务端未启用压缩：宽容降级（回 0x00，明文继续——规格 §1.4）。
                write_u8(&mut s, STATUS_REJECT).await?;
            }
            other => return Ok((crate::transfer::Framed::Raw(s), Some(other))),
        }
    }
}

async fn conn_loop_inner<S>(
    mut s: S,
    peer: SocketAddr,
    opts: &RecvOptions,
    handled: &mut u64,
    first: Option<u8>,
    authed: bool,
    served: &Arc<AtomicU64>,
    always_drain: bool,
    binding: Option<[u8; 32]>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut pending = first;
    // 配对门（0x05 明文门 / 0x0D 通道绑定门）：首字节分流——
    // 0x05 → 盐→证明→结论；0x0D（仅 QUIC，binding=Some）→ 0x1D 盐→绑定证明→结论；
    // 服务端有码而首帧非法 → **不写盐**直接拒绝（消灭盐字节被误读为
    // 状态字节的 1/256 假成功窗口，规格 §7.1 红线）。
    if !authed {
        match opts.pairing_code.as_deref() {
            Some(code) => {
                let t = match pending.take() {
                    Some(t) => t,
                    None => read_u8(&mut s).await?, // QUIC：首字节仍在流里
                };
                // 拒绝收尾：写拒绝字节 + 排水后关闭（确定性拒绝的前提）。
                async fn reject_pairing<S>(s: &mut S, msg: String) -> Result<()>
                where
                    S: AsyncRead + AsyncWrite + Unpin,
                {
                    write_u8(s, STATUS_REJECT).await?;
                    let _ = tokio::time::timeout(std::time::Duration::from_millis(500), async {
                        let mut b = [0u8; 4096];
                        loop {
                            match tokio::io::AsyncReadExt::read(s, &mut b).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    })
                    .await;
                    Err(Error::AuthRejected(msg))
                }
                // 明文 0x05 验证（TCP 槽位）。
                async fn verify_plain<S>(s: &mut S, code: &str, peer: SocketAddr) -> Result<()>
                where
                    S: AsyncRead + AsyncWrite + Unpin,
                {
                    let mut salt = [0u8; 16];
                    OsRng.fill_bytes(&mut salt);
                    write_all(s, &salt).await?;
                    let proof = read_n(s, 32).await?;
                    let code_owned = code.to_string();
                    let salt_v = salt.to_vec();
                    // PBKDF2(50k) 是纯 CPU 密集：移出 async 工作线程（防 DoS 放大）。
                    let k = tokio::task::spawn_blocking(move || {
                        derive_pairing_key(&code_owned, &salt_v)
                    })
                    .await
                    .map_err(|e| proto(e.to_string()))?;
                    if !ct_eq(&proof, &pairing_proof(&k, &salt)) {
                        return reject_pairing(s, format!("{peer}: 配对码错误")).await;
                    }
                    write_u8(s, STATUS_OK).await?;
                    Ok(())
                }
                match (t, binding) {
                    // M6'：QUIC 槽位强制通道绑定证明（明文 0x05 对新服务端必拒）。
                    (T_PAIRING, Some(_)) => {
                        reject_pairing(
                            &mut s,
                            format!("{peer}: QUIC 配对必须使用通道绑定证明（0x0D，旧版对端请升级）"),
                        )
                        .await?;
                    }
                    // TCP 无通道材料可绑定：绑定帧只可能来自错槽位客户端（fail-closed）。
                    (T_PAIRING_BOUND, None) => {
                        reject_pairing(&mut s, format!("{peer}: 通道绑定配对仅支持 QUIC 槽位"))
                            .await?;
                    }
                    (T_PAIRING_BOUND, Some(fp)) => {
                        write_u8(&mut s, R_PAIRING_SALT).await?;
                        let mut salt = [0u8; 16];
                        OsRng.fill_bytes(&mut salt);
                        write_all(&mut s, &salt).await?;
                        let proof = read_n(&mut s, 32).await?;
                        let code_owned = code.to_string();
                        let salt_v = salt.to_vec();
                        let k = tokio::task::spawn_blocking(move || {
                            derive_pairing_key(&code_owned, &salt_v)
                        })
                        .await
                        .map_err(|e| proto(e.to_string()))?;
                        // 证明混入「客户端所见服务器证书指纹」——双臂中继两腿
                        // 证书必然不同，证明必败（TECH-STACK §7.11）。
                        let expected = pairing_proof_bound(&k, &salt, &fp);
                        if !ct_eq(&proof, &expected) {
                            return reject_pairing(&mut s, format!("{peer}: 配对码错误")).await;
                        }
                        // 双向确认（轮 2 P1）：服务端附带 S→C 证明 = HMAC(K, s2c 域‖盐‖自身 fp)，
                        // 封死「盲接受型假服务端」（客户端恒时校验，失败即断）。
                        write_u8(&mut s, STATUS_OK).await?;
                        write_all(&mut s, &pairing_proof_s2c(&k, &salt, &fp)).await?;
                    }
                    (T_PAIRING, None) => {
                        verify_plain(&mut s, code, peer).await?;
                    }
                    _ => {
                        reject_pairing(&mut s, format!("{peer}: 发送端未走配对流程")).await?;
                    }
                }
            }
            None => {
                // 宽容（规格 §4.1）：服务端无码时对 0x05/0x0D 回盐并吞掉证明，流程对齐；
                // 非 0x05 首帧放回原位，正常进帧循环。
                let t = match pending.take() {
                    Some(t) => t,
                    None => read_u8(&mut s).await?,
                };
                if t == T_PAIRING || t == T_PAIRING_BOUND {
                    if t == T_PAIRING_BOUND {
                        write_u8(&mut s, R_PAIRING_SALT).await?;
                    }
                    let mut salt = [0u8; 16];
                    OsRng.fill_bytes(&mut salt);
                    write_all(&mut s, &salt).await?;
                    let _ = read_n(&mut s, 32).await?;
                    // 宽容语义（规格 §4.1 未启用即接受）+ 回结论字节——否则有码客户端
                    // 等结论、无码服务端等下一帧，双端互等死锁（轮 2 P2）。
                    write_u8(&mut s, STATUS_OK).await?;
                    if t == T_PAIRING_BOUND {
                        // 0x0D 客户端在结论后必读 32B s2c 证明（轮 6 P3-1：
                        // 缺失则 QUIC 30s idle 超时才醒，期间占并发闸）。
                        write_all(&mut s, &[0u8; 32]).await?;
                    }
                } else {
                    pending = Some(t);
                }
            }
        }
    }

    // 前导协商（0x0A / 0x08）→ 帧层栈。
    let (mut s, mut pending) = negotiate_stack(s, pending, opts).await?;

    let mut count_reached = false;
    let mut confirmed = false; // 每连接确认一次（规格 §3.3；首个文件帧前判定）
    loop {
        let t = match pending.take() {
            Some(t) => t,
            None => match read_u8(&mut s).await {
                Ok(t) => t,
                // 发送端处理完即关连接，属于正常结束——统一走循环外收尾。
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            },
        };
        match t {
            T_SINGLE_FILE => {
                confirm_once(peer, opts, &mut confirmed).await?;
                if let Err(e) = recv_single(&mut s, peer, opts).await {
                    write_u8(&mut s, STATUS_REJECT).await?;
                    return Err(e);
                }
                write_u8(&mut s, STATUS_OK).await?;
                *handled += 1;
            }
            T_FOLDER => {
                confirm_once(peer, opts, &mut confirmed).await?;
                if let Err(e) = recv_folder_over(&mut s, peer, opts).await {
                    write_u8(&mut s, STATUS_REJECT).await?;
                    return Err(e);
                }
                write_u8(&mut s, STATUS_OK).await?;
                *handled += 1;
            }
            T_TEXT => {
                let t0 = Instant::now();
                let text = recv_text(&mut s).await?;
                if let Some(tx) = &opts.text_tx {
                    let _ = tx.send(text.clone());
                }
                eprintln!("[文本] 来自 {peer}: {text}");
                write_u8(&mut s, STATUS_OK).await?;
                record_recv(opts, peer, text.as_bytes().len() as u64, 0, t0, "0x06 文本", "<文本>");
                *handled += 1;
            }
            T_CHUNKED if opts.enable_chunked => {
                confirm_once(peer, opts, &mut confirmed).await?;
                // 块帧无独立应答；覆盖达成即在 handler 内组装发布。
                chunked::recv_chunk_frame(&mut s, peer, opts).await?;
            }
            T_CHUNK_END if opts.enable_chunked => {
                confirm_once(peer, opts, &mut confirmed).await?;
                // 收尾判决由 handler 直答（0x01/0x02），会话不存在回 0x00 + 连接失败。
                chunked::recv_chunk_end(&mut s, opts).await?;
                *handled += 1;
            }
            T_COVERAGE_QUERY if opts.enable_chunked => {
                // 覆盖率查询：内存 tracker 直答合并区间（规格 §3.1）。
                chunked::recv_coverage_query(&mut s, opts).await?;
            }
            T_RESUME_FILE if opts.enable_resume => {
                confirm_once(peer, opts, &mut confirmed).await?;
                if let Err(e) = resume::recv_resume_file(&mut s, peer, opts).await {
                    write_u8(&mut s, STATUS_REJECT).await?;
                    return Err(e);
                }
                write_u8(&mut s, STATUS_OK).await?;
                *handled += 1;
            }
            T_RESUME_FOLDER if opts.enable_resume => {
                confirm_once(peer, opts, &mut confirmed).await?;
                if let Err(e) = resume::recv_resume_folder(&mut s, peer, opts).await {
                    write_u8(&mut s, STATUS_REJECT).await?;
                    return Err(e);
                }
                write_u8(&mut s, STATUS_OK).await?;
                *handled += 1;
            }
            other => {
                write_u8(&mut s, STATUS_REJECT).await?;
                return Err(proto(format!("未知帧类型 0x{other:02X}")));
            }
        }
        // --count 语义按帧粒度收口：达标即收尾，杜绝单连接超收。
        //（served 此刻尚不含本连接，需叠加局部 handled。）
        if opts
            .max_count
            .is_some_and(|m| served.load(Ordering::Relaxed) + *handled >= m)
        {
            count_reached = true;
            break;
        }
    }
    if count_reached || always_drain {
        // 排水：读尽对端残余并等其 FIN，再放行上层关闭——
        // 跳过收尾读直接 drop 会在 Windows/QUIC 上以 RST 掐断客户端的状态读取。
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let mut b = [0u8; 256];
            loop {
                match tokio::io::AsyncReadExt::read(&mut s, &mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        })
        .await;
    }
    Ok(())
}

async fn recv_single<S>(s: &mut S, peer: SocketAddr, opts: &RecvOptions) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let name = read_str_u16(s).await?;
    let name = sanitize_name(&name)?;
    let size = read_u64(s).await?;
    if size > MAX_TRANSFER_SIZE {
        return Err(proto(format!("声明大小 {size} 超过 1 PiB 上限")));
    }

    // 目录解析在会话建立时固定（PerDeviceFolder/AutoArchive，规格 §3.3）。
    let dir = resolve_save_dir(opts, peer.ip());
    tokio::fs::create_dir_all(&dir).await?;
    // 磁盘预检（规格 §3.1：可用 ≥ 声明 + 64MB 余量）。
    if !space_ok(&dir, size) {
        return Err(Error::Rejected(format!(
            "{name}: 磁盘可用空间不足（需要 ≥ {size} 字节 + 64MB 余量）"
        )));
    }

    // 唯一半成品 + 错误清理守卫：并发同名互不交叉，任何失败路径不残留。
    let part = unique_part(&dir, &name);
    let _guard = PartGuard(part.clone());
    // 进度：注册后任何失败路径经 Outcome 上报 failed（skip 丢弃也是成功收尾）。
    let report = opts.progress.as_ref().map(|h| h.register("recv", name.clone(), size));
    let outcome = crate::progress::Outcome::new(report.clone());
    let mut out = tokio::fs::OpenOptions::new().write(true).create_new(true).open(&part).await?;
    let mut dig = FileDigester::new();
    let mut lim = TokenBucket::new(opts.recv_limit_bps);
    let mut remaining = size;
    let mut buf = vec![0u8; CHUNK];
    while remaining > 0 {
        let want = CHUNK.min(remaining.min(usize::MAX as u64) as usize);
        crate::protocol::io::read_exact_long(s, &mut buf[..want]).await?;
        lim.acquire(want as u64).await;
        dig.update(&buf[..want]);
        out.write_all(&buf[..want]).await?;
        if let Some(r) = &report {
            r.add(want as u64);
        }
        remaining -= want as u64;
    }
    out.flush().await?;
    out.sync_all().await?;

    // 声明哈希：30s 超时（规格 §6.1 普通读），防半开连接挂死接收器。
    let claimed: [u8; 32] = read_n(s, 32).await?.try_into().unwrap();
    let actual = dig.finalize();
    if actual != claimed {
        return Err(proto("SHA-256 不一致，已丢弃半成品"));
    }
    drop(out);

    // Skip 语义对齐规格 §3.1：收完与已有文件比对（大小+全哈希），一致删新副本。
    let dest = dir.join(&name);
    if opts.duplicate == DuplicatePolicy::Skip && tokio::fs::metadata(&dest).await.is_ok() {
        let meta_before = tokio::fs::metadata(&dest).await.ok();
        let same_size = meta_before.as_ref().map(|m| m.len() == size).unwrap_or(false);
        let d2 = dest.clone();
        let same = same_size
            && tokio::task::spawn_blocking(move || sha256_file(&d2).map(|h| h == actual).unwrap_or(false))
                .await
                .unwrap_or(false);
        // 规格 §1.4 判错方向不对称：比对后若 dest 已被并发改写（mtime 变化），
        // 宁可按改名多留一份，不得静默丢新副本。
        let meta_after = tokio::fs::metadata(&dest).await.ok();
        let unchanged = meta_before
            .zip(meta_after)
            .map(|(a, b)| {
                a.len() == b.len()
                    && a.modified().ok() == b.modified().ok()
            })
            .unwrap_or(false);
        if same && unchanged {
            outcome.finish();
            // skip 也是免费填充点（现有文件哈希已被证实——规格 §3.1 免费填充路径）。
            resume::fill_cache_at(opts, &dest, size, actual).await;
            record_recv(opts, peer, 0, 1, started, "0x00 skip", &name);
            return Ok(()); // 新副本丢弃（guard 兜底删除 part）
        }
    }

    // 冲突在发布时解析；hard_link 的 fail-if-exists 语义封死并发覆盖。
    // 缓存免费填充跟最终路径（冲突改名时不得按旧路径写缓存——轮 1 P1 同源）。
    let final_dest = publish_part(&part, &dir, &name).await?;
    resume::fill_cache_at(opts, &final_dest, size, actual).await;
    eprintln!("[接收] {name} → {}", final_dest.display());
    outcome.finish();
    record_recv(opts, peer, size, 1, started, "0x00", &name);
    Ok(())
}

async fn recv_text<S>(s: &mut S) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let len = read_u32(s).await? as usize;
    if len > crate::protocol::frame::MAX_TEXT_LEN {
        return Err(proto("文本超过 1MB 上限"));
    }
    let bytes = read_n(s, len).await?;
    String::from_utf8(bytes).map_err(|_| proto("文本不是合法 UTF-8"))
}

/// 文件冲突处理：扩展名前追加 _1、_2……（规格 §3.1）。
pub(crate) async fn resolve_conflict(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if tokio::fs::metadata(&candidate).await.is_err() {
        return candidate;
    }
    let p = Path::new(name);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file").to_string();
    let ext = p
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    for i in 1..10000u32 {
        let cand = dir.join(format!("{stem}_{i}{ext}"));
        if tokio::fs::metadata(&cand).await.is_err() {
            return cand;
        }
    }
    // 兜底也不覆盖既有文件。
    for i in 0..10000u32 {
        let cand = dir.join(format!("{stem}_dupe{i}{ext}"));
        if tokio::fs::metadata(&cand).await.is_err() {
            return cand;
        }
    }
    dir.join(format!("{stem}_dupe{ext}"))
}

/// 原子发布：hard_link 天然 fail-if-exists——两个并发发布只有一个成功，
/// 失败方重取冲突名重试（修复 Windows rename 替换语义导致的静默覆盖）。
/// 成功后删除半成品，返回最终路径。
pub(crate) async fn publish_part(part: &Path, dir: &Path, name: &str) -> Result<PathBuf> {
    for _ in 0..10000u32 {
        let candidate = resolve_conflict(dir, name).await;
        match std::fs::hard_link(part, &candidate) {
            Ok(()) => {
                let _ = std::fs::remove_file(part);
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                // 卷不支持硬链接（FAT32/exFAT/部分网络共享）：退化为
                // 「拷到临时半成品名 + rename 到最终名」——崩溃窗口内留下的
                // 也只是 .trft-part（孤儿清扫可回收），不会以最终名残留半成品（轮 1）。
                let tmp = unique_part(dir, name);
                let copied = async {
                    let mut src = tokio::fs::File::open(part).await?;
                    let mut dst = tokio::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&tmp)
                        .await?;
                    let r = tokio::io::copy(&mut src, &mut dst).await;
                    let synced = dst.sync_all().await;
                    drop(dst);
                    r.and(synced)
                }
                .await;
                if let Err(e) = copied {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(Error::Io(e));
                }
                match std::fs::rename(&tmp, &candidate) {
                    Ok(()) => {
                        let _ = std::fs::remove_file(part);
                        return Ok(candidate);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        let _ = std::fs::remove_file(&tmp);
                        continue; // 并发发布方抢先占用冲突名 → 重取冲突名
                    }
                    Err(e) => {
                        let _ = std::fs::remove_file(&tmp);
                        return Err(Error::Io(e));
                    }
                }
            }
        }
    }
    Err(proto("冲突名解析耗尽"))
}

/// 文件夹根目录冲突：对根目录名追加（规格 §3.1）。
/// 原子占用：create_dir（非 recursive）天然 fail-if-exists，封死并发同根合并。
pub(crate) async fn resolve_root(dir: &Path, name: &str) -> PathBuf {
    let _ = std::fs::create_dir_all(dir);
    for i in 0..10000u32 {
        let cand = if i == 0 { dir.join(name) } else { dir.join(format!("{name}_{i}")) };
        match std::fs::create_dir(&cand) {
            Ok(()) => return cand,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return cand, // 探测失败放行（降级为旧行为）
        }
    }
    dir.join(format!("{name}_dupe"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(ip: &str, pat: &str) -> bool {
        ip_match(ip.parse().unwrap(), pat)
    }

    #[test]
    fn ip_filter_matching_rules() {
        // 精确
        assert!(m("192.168.1.5", "192.168.1.5"));
        assert!(!m("192.168.1.5", "192.168.1.6"));
        assert!(m("::1", "::1"));
        // 通配（v4 末段 / 前缀组）
        assert!(m("192.168.1.5", "192.168.1.*"));
        assert!(m("192.168.99.5", "192.168.*"));
        assert!(!m("10.0.0.1", "192.168.*"));
        assert!(!m("::1", "192.168.*"), "跨族不匹配");
        // CIDR v4/v6
        assert!(m("192.168.1.66", "192.168.1.0/24"));
        assert!(!m("192.168.2.66", "192.168.1.0/24"));
        assert!(m("fe80::1234:5678", "fe80::/16"));
        assert!(!m("2001:db8::1", "fe80::/16"));
        assert!(!m("192.168.1.1", "fe80::/16"), "跨族 CIDR 永不匹配");
        // 坏条目 fail-closed
        assert!(!m("192.168.1.5", "garbage"));
        assert!(!m("192.168.1.5", "192.168.1.0/33"));
        assert!(!m("192.168.1.5", ""));
        // off 模式全放行；allow 需命中；deny 命中即拒
        use crate::config::FilterMode;
        let ip: IpAddr = "192.168.1.5".parse().unwrap();
        let list = vec!["192.168.1.0/24".to_string()];
        assert!(ip_allowed(ip, FilterMode::Off, &[]));
        assert!(ip_allowed(ip, FilterMode::Allow, &list));
        assert!(!ip_allowed(ip, FilterMode::Allow, &[]));
        assert!(!ip_allowed(ip, FilterMode::Deny, &list));
        assert!(ip_allowed(ip, FilterMode::Deny, &[]));
    }

    #[tokio::test]
    async fn conflict_naming() {
        let dir = tempfile::tempdir().unwrap();
        let first = resolve_conflict(dir.path(), "a.txt").await;
        std::fs::write(&first, b"x").unwrap();
        let second = resolve_conflict(dir.path(), "a.txt").await;
        std::fs::write(&second, b"x").unwrap(); // 与真实接收流程一致：解析后立即落盘
        assert_eq!(second.file_name().unwrap().to_str().unwrap(), "a_1.txt");
        let third = resolve_conflict(dir.path(), "a.txt").await;
        assert_eq!(third.file_name().unwrap().to_str().unwrap(), "a_2.txt");
    }

    #[tokio::test]
    async fn root_conflict_naming() {
        let dir = tempfile::tempdir().unwrap();
        let first = resolve_root(dir.path(), "proj").await;
        std::fs::create_dir_all(&first).unwrap();
        let second = resolve_root(dir.path(), "proj").await;
        assert_eq!(second.file_name().unwrap().to_str().unwrap(), "proj_1");
    }

    /// 轮 6 P2-3 判别：IPv6 同 /64 的不同地址必须共享锁定计数——
    /// 修复前按 /128 计数，每地址 ≤9 次即无限绕过。
    #[test]
    fn pairing_gate_aggregates_ipv6_slash64() {
        let mut g = PairingGate::default();
        // 同 /64 内轮换 40 个地址（每个 <10 次）——聚合后必须锁定。
        for i in 0..LOCKOUT_THRESHOLD {
            let ip: IpAddr = format!("fd00::1:{i:x}").parse().unwrap();
            g.fail(&ip);
        }
        let probe: IpAddr = "fd00::1:ffff".parse().unwrap();
        assert!(g.locked(&probe), "同 /64 的任意新地址必须已锁定");
        // 不同 /64 不受影响。
        let other: IpAddr = "fd01::1".parse().unwrap();
        assert!(!g.locked(&other), "不同 /64 不得被连带");
        // IPv4 仍按单地址（达阈值的那一个地址锁定，其他地址不连带）。
        let mut g4 = PairingGate::default();
        for _ in 0..LOCKOUT_THRESHOLD {
            g4.fail(&"10.0.0.1".parse::<IpAddr>().unwrap());
        }
        assert!(!g4.locked(&"10.0.0.2".parse().unwrap()), "IPv4 不同地址不得连带");
        assert!(g4.locked(&"10.0.0.1".parse().unwrap()), "IPv4 达阈值必须锁定");
    }

    #[test]
    fn pairing_gate_lockout() {
        let mut g = PairingGate::default();
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        assert!(!g.locked(&ip));
        for _ in 0..LOCKOUT_THRESHOLD - 1 {
            g.fail(&ip);
        }
        assert!(!g.locked(&ip), "未达阈值不锁");
        g.fail(&ip);
        assert!(g.locked(&ip), "达到阈值必须锁定");
        g.success(&ip);
        assert!(!g.locked(&ip), "成功清零");
    }

    #[test]
    fn part_guard_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.trft-part");
        std::fs::write(&p, b"partial").unwrap();
        {
            let _g = PartGuard(p.clone());
        }
        assert!(!p.exists(), "守卫 drop 必须清理半成品");
    }
}
