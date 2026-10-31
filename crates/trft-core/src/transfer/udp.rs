//! 单向 UDP 传输（规格 §3.1/§4.2）：无回传链路、多轮重发 + RS 前向纠错、落盘即状态。
//! 无认证无加密（协议上不可行，规格 §5.2 明示残余风险）——只适用于可信链路。
//!
//! 帧布局：20B 公共头 + 载荷
//! - START: u16 名长 + 名 + u64 大小 + u32 块长 + u8 fec + u8 parity
//! - DATA : seq = 全局块序号，载荷 = 该块实际字节（末块 = 余数，不补零；
//!          RS 编码/恢复内部按块长补零，END 前 set_len 裁剪）
//! - PARITY: u32 组号 + u8 分片序号(≥k) + 分片载荷
//! - END  : 32B SHA-256

use crate::error::{Result, config_err};
use crate::fec::FecCodec;
use crate::hash::FileDigester;
use crate::limiter::TokenBucket;
use crate::protocol::frame::{MAX_TRANSFER_SIZE, sanitize_name};
use crate::protocol::udp::{
    UDP_HEADER_LEN, U_F_DATA, U_F_END, U_F_PARITY, U_F_START, UdpHeader, session_id,
};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub const UDP_CHUNK: usize = 1200;
pub const FEC_DATA_SHARDS: usize = 4;
/// 轮间间隔（规格 §3.2：轮间 400ms）。
pub const PASS_DELAY: Duration = Duration::from_millis(400);
/// START/END 连发间隔（规格 §3.2：间隔 40ms）。
pub const BURST_GAP: Duration = Duration::from_millis(40);
/// 单向 UDP 保存目录下的半成品后缀。
pub const PART_SUFFIX: &str = ".trft-udppart";

const SESSION_CAP: usize = 64; // 规格 §6.1：UDP 接收会话表 64 会话（最旧逐出）
const SUPPRESS_CAP: usize = 256; // 已投递抑制窗口 256 会话
const SUPPRESS_TTL: Duration = Duration::from_secs(600); // 10 分钟
/// 覆盖位图预算：≈128MB / 64 会话 → 每会话 2MB 位图（规格 §6.1）。
const BITMAP_CAP_CHUNKS: u64 = 2 * 1024 * 1024 * 8;
const PARITY_GROUP_CAP: usize = 4; // FEC 待恢复缓存 ≤4 组
const PARITY_BYTE_BUDGET: usize = 256 * 1024;
const ORPHAN_TTL: Duration = Duration::from_secs(7 * 24 * 3600); // 孤儿 .part 清理 7 天
/// 空闲会话回收：超时未收到任何帧 → 逐出并删除其半成品（防磁盘放大驻留）。
const SESSION_TTL: Duration = Duration::from_secs(600);
/// 全部活跃会话声明总量上限（防伪造 START 的 set_len 预分配放大）。
const DECLARED_CAP: u64 = 64 * 1024 * 1024 * 1024; // 64 GiB

#[derive(Debug, Clone)]
pub struct UdpSendOptions {
    /// 多轮重发 1–5（规格 §3.2），默认 2。
    pub passes: u32,
    /// FEC 开关（UdpFec=0 关闭）。
    pub fec: bool,
    /// FEC 校验分片 1–8，默认 2。
    pub fec_parity: u8,
    /// 发送限速（字节/秒，0=不限）。
    pub speed_limit_bps: u64,
    /// 进度上报（规格 §3.2 单向 UDP 进度按轮加权：total = size × passes）。
    pub progress: Option<crate::progress::Reporter>,
    /// 传输统计（M5'：已发出口径；None = 不记）。
    pub stats: Option<std::sync::Arc<crate::stats::StatsLog>>,
}

impl Default for UdpSendOptions {
    fn default() -> Self {
        Self { passes: 2, fec: true, fec_parity: 2, speed_limit_bps: 0, progress: None, stats: None }
    }
}

/// 发送计划：一次计算，多轮重发复用。
pub struct UdpPlan {
    pub session: u64,
    pub name: String,
    pub size: u64,
    pub chunk_len: u32,
    pub chunk_count: u64,
    pub fec: bool,
    pub parity_shards: u8,
}

pub async fn build_plan(path: &Path, opts: &UdpSendOptions) -> Result<UdpPlan> {
    let raw = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| config_err("路径没有合法 UTF-8 文件名"))?;
    let name = sanitize_name(raw)?;
    let meta = tokio::fs::metadata(path).await?;
    if !meta.is_file() {
        return Err(config_err("路径不是普通文件"));
    }
    let size = meta.len();
    if size > MAX_TRANSFER_SIZE {
        return Err(config_err("文件超过 1 PiB 声明上限"));
    }
    let mtime = meta.modified()?.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let chunk_len = UDP_CHUNK as u32;
    let chunk_count = size.div_ceil(chunk_len as u64);
    Ok(UdpPlan {
        session: session_id(&name, size, mtime),
        name,
        size,
        chunk_len,
        chunk_count,
        fec: opts.fec,
        parity_shards: opts.fec_parity.clamp(1, 8),
    })
}

impl UdpPlan {
    fn header(&self, frame: u8, seq: u64) -> [u8; UDP_HEADER_LEN] {
        UdpHeader { frame, session: self.session, seq }.to_bytes()
    }

    pub fn start_frames(&self) -> Vec<Vec<u8>> {
        (0..3)
            .map(|_| {
                let mut f = self.header(U_F_START, 0).to_vec();
                f.extend_from_slice(&(self.name.len() as u16).to_le_bytes());
                f.extend_from_slice(self.name.as_bytes());
                f.extend_from_slice(&self.size.to_le_bytes());
                f.extend_from_slice(&self.chunk_len.to_le_bytes());
                f.push(if self.fec { 1 } else { 0 });
                f.push(self.parity_shards);
                f
            })
            .collect()
    }

    pub fn end_frames(&self, hash: &[u8; 32]) -> Vec<Vec<u8>> {
        (0..3)
            .map(|_| {
                let mut f = self.header(U_F_END, 0).to_vec();
                f.extend_from_slice(hash);
                f
            })
            .collect()
    }

    /// 流式发送一轮：逐组构建 → 限速发送 → 释放，内存 O(组)（修复整文件驻留）。
    /// 返回本轮计算的全文件哈希。
    pub async fn send_pass(
        &self,
        path: &Path,
        socket: &UdpSocket,
        addr: SocketAddr,
        lim: &mut TokenBucket,
        report: Option<&crate::progress::Reporter>,
    ) -> Result<[u8; 32]> {
        let mut f = tokio::fs::File::open(path).await?;
        let mut dig = FileDigester::new();
        if self.fec {
            let codec = FecCodec::new(FEC_DATA_SHARDS, self.parity_shards as usize)?;
            let groups = self.chunk_count.div_ceil(FEC_DATA_SHARDS as u64);
            for g in 0..groups {
                let mut shards: Vec<Vec<u8>> = Vec::with_capacity(FEC_DATA_SHARDS);
                for s in 0..FEC_DATA_SHARDS as u64 {
                    let idx = g * FEC_DATA_SHARDS as u64 + s;
                    let mut shard = vec![0u8; UDP_CHUNK];
                    if idx < self.chunk_count {
                        let want = (UDP_CHUNK as u64).min(self.size - idx * self.chunk_len as u64) as usize;
                        f.read_exact(&mut shard[..want]).await?;
                        dig.update(&shard[..want]);
                        if let Some(r) = report {
                            r.add(want as u64);
                        }
                    }
                    shards.push(shard);
                }
                let all = codec.encode_group(shards)?;
                for (idx, shard) in all.into_iter().enumerate() {
                    if idx < FEC_DATA_SHARDS {
                        let seq = g * FEC_DATA_SHARDS as u64 + idx as u64;
                        // 末组补零分片不发送：接收端视其为已知零分片。
                        if seq < self.chunk_count {
                            // 末块线上载荷 = 实际余数（与接收端精确长度校验配对，轮 1 F2；
                            // RS 编码分片仍按块长补零——恢复路径写全块长，END 前 set_len 裁剪）。
                            let real =
                                (self.chunk_len as u64).min(self.size - seq * self.chunk_len as u64) as usize;
                            let frame = self.data_frame(seq, &shard[..real]);
                            lim.acquire(frame.len() as u64).await;
                            socket.send_to(&frame, addr).await?;
                        }
                    } else {
                        let frame = self.parity_frame(g as u32, idx as u8, &shard);
                        lim.acquire(frame.len() as u64).await;
                        socket.send_to(&frame, addr).await?;
                    }
                }
            }
        } else {
            for idx in 0..self.chunk_count {
                let want = (UDP_CHUNK as u64).min(self.size - idx * self.chunk_len as u64) as usize;
                let mut chunk = vec![0u8; want];
                f.read_exact(&mut chunk).await?;
                dig.update(&chunk);
                if let Some(r) = report {
                    r.add(want as u64);
                }
                let frame = self.data_frame(idx, &chunk);
                lim.acquire(frame.len() as u64).await;
                socket.send_to(&frame, addr).await?;
            }
        }
        Ok(dig.finalize())
    }

    /// 测试专用：物化一轮的全部帧（仅供引擎测试喂帧；运行路径走 send_pass）。
    #[cfg(test)]
    pub async fn build_pass(&self, path: &Path) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>, [u8; 32])> {
        let mut f = tokio::fs::File::open(path).await?;
        let mut dig = FileDigester::new();
        let mut data = Vec::new();
        let mut parity = Vec::new();
        if self.fec {
            let codec = FecCodec::new(FEC_DATA_SHARDS, self.parity_shards as usize)?;
            let groups = self.chunk_count.div_ceil(FEC_DATA_SHARDS as u64);
            for g in 0..groups {
                let mut shards: Vec<Vec<u8>> = Vec::with_capacity(FEC_DATA_SHARDS);
                let mut real_lens = [0usize; FEC_DATA_SHARDS];
                for s in 0..FEC_DATA_SHARDS as u64 {
                    let idx = g * FEC_DATA_SHARDS as u64 + s;
                    let mut shard = vec![0u8; UDP_CHUNK];
                    if idx < self.chunk_count {
                        let want = (UDP_CHUNK as u64).min(self.size - idx * self.chunk_len as u64) as usize;
                        f.read_exact(&mut shard[..want]).await?;
                        dig.update(&shard[..want]);
                        real_lens[s as usize] = want;
                    }
                    shards.push(shard);
                }
                let _ = real_lens;
                let all = codec.encode_group(shards)?;
                for (idx, shard) in all.into_iter().enumerate() {
                    if idx < FEC_DATA_SHARDS {
                        let seq = g * FEC_DATA_SHARDS as u64 + idx as u64;
                        // 末组补零分片不发送：接收端视其为已知零分片。
                        if seq < self.chunk_count {
                            // 末块线上载荷 = 实际余数（与 send_pass 同口径，轮 1 F2）。
                            let real =
                                (self.chunk_len as u64).min(self.size - seq * self.chunk_len as u64) as usize;
                            data.push(self.data_frame(seq, &shard[..real]));
                        }
                    } else {
                        parity.push(self.parity_frame(g as u32, idx as u8, &shard));
                    }
                }
            }
        } else {
            for idx in 0..self.chunk_count {
                let want = (UDP_CHUNK as u64).min(self.size - idx * self.chunk_len as u64) as usize;
                let mut chunk = vec![0u8; want];
                f.read_exact(&mut chunk).await?;
                dig.update(&chunk);
                data.push(self.data_frame(idx, &chunk));
            }
        }
        Ok((data, parity, dig.finalize()))
    }

    fn data_frame(&self, seq: u64, payload: &[u8]) -> Vec<u8> {
        let mut f = self.header(U_F_DATA, seq).to_vec();
        f.extend_from_slice(payload);
        f
    }

    fn parity_frame(&self, group: u32, idx: u8, shard: &[u8]) -> Vec<u8> {
        let mut f = self.header(U_F_PARITY, 0).to_vec();
        f.extend_from_slice(&group.to_le_bytes());
        f.push(idx);
        f.extend_from_slice(shard);
        f
    }
}

/// 单向 UDP 发送：多轮重发，每轮 START×3 → 全部 DATA/PARITY → END×3。
/// Outcome 守卫：任何 `?` 早退（send_to 失败如 ICMP 端口不可达、读源文件失败）
/// 都必须发进度终态（轮 3 F2——此前仅成功路径 finish，失败卡片永久 running）。
pub async fn send_file_udp(addr: SocketAddr, path: &Path, opts: &UdpSendOptions) -> Result<()> {
    let started = std::time::Instant::now();
    let outcome = crate::progress::Outcome::new(opts.progress.clone());
    let plan = build_plan(path, opts).await?;
    let local = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(local).await?;
    let mut lim = TokenBucket::new(opts.speed_limit_bps);
    let passes = opts.passes.clamp(1, 5);
    // 规格 §3.2：单向 UDP 进度按轮加权（每轮完整重发 → total = size × passes）。
    if let Some(r) = &opts.progress {
        r.set_total(plan.size * passes as u64);
    }
    for pass in 0..passes {
        for st in plan.start_frames() {
            lim.acquire(st.len() as u64).await;
            socket.send_to(&st, addr).await?;
            tokio::time::sleep(BURST_GAP).await;
        }
        let hash = plan.send_pass(path, &socket, addr, &mut lim, opts.progress.as_ref()).await?;
        for e in plan.end_frames(&hash) {
            lim.acquire(e.len() as u64).await;
            socket.send_to(&e, addr).await?;
            tokio::time::sleep(BURST_GAP).await;
        }
        if pass + 1 < passes {
            tokio::time::sleep(PASS_DELAY).await;
        }
    }
    outcome.finish();
    // 单向 UDP 无回传链路：发送完成 ≠ 对端落盘（规格 §4.2 落盘即状态）——
    // 统计如实记为「已发出」口径（对端侧另在自己的 stats 记账）。
    if let Some(s) = &opts.stats {
        s.record(
            crate::stats::Direction::Send,
            &addr.ip().to_string(),
            plan.size,
            1,
            started.elapsed().as_secs(),
            &format!("UDP×{passes}轮"),
            &plan.name,
        );
    }
    Ok(())
}

/// 接收事件（测试/CLI 观测用；无回传链路下事件只在本机产生）。
#[derive(Debug, Clone)]
pub enum UdpEvent {
    Started { session: u64, name: String, size: u64, chunk_len: u32 },
    Progress { session: u64, done: u64, total: u64 },
    Completed { session: u64, path: PathBuf, size: u64, start: Instant },
    Ignored(&'static str),
}

struct Session {
    name: String,
    size: u64,
    chunk_len: u32,
    chunk_count: u64,
    fec: bool,
    parity_shards: u8,
    codec: Option<FecCodec>,
    bitmap: Vec<u64>,
    file: std::fs::File,
    part_path: PathBuf,
    parity: HashMap<u32, HashMap<u8, Vec<u8>>>,
    parity_order: VecDeque<u32>,
    parity_bytes: usize,
    last_seen: Instant,
    /// 插入序（逐出 tie-break；主序按 last_seen）。
    seq_no: u64,
    /// set_len 预分配字节数（会话结束/逐出时从声明总量扣回）。
    padded: u64,
    /// 已收块数（增量维护，替代逐包位图全扫）。
    done: u64,
    /// 落盘目录（会话建立时按来源 IP 解析并固定——规格 §3.3 PerDeviceFolder）。
    dir: PathBuf,
    /// 会话开始时刻（stats 时长记账；轮 1：不再依赖 progress 注入）。
    start: Instant,
}

/// 目录解析器（PerDeviceFolder/AutoArchive；None = 一律 save_dir）。
pub type DirResolver = std::sync::Arc<dyn Fn(std::net::IpAddr) -> PathBuf + Send + Sync>;

/// 单向 UDP 接收引擎：纯逻辑、无 socket，便于直接喂帧测试（规格 §10.1 判别纪律）。
pub struct UdpRecvEngine {
    sessions: HashMap<u64, Session>,
    suppressed: HashMap<u64, Instant>,
    suppress_order: VecDeque<u64>,
    save_dir: PathBuf,
    dir_for: Option<DirResolver>,
    next_seq: u64,
    /// 当前活跃会话声明总量（防磁盘放大）。
    declared_total: u64,
}

impl UdpRecvEngine {
    pub fn new(save_dir: PathBuf) -> Self {
        Self::with_resolver(save_dir, None)
    }

    pub fn with_resolver(save_dir: PathBuf, dir_for: Option<DirResolver>) -> Self {
        Self {
            sessions: HashMap::new(),
            suppressed: HashMap::new(),
            suppress_order: VecDeque::new(),
            save_dir,
            dir_for,
            next_seq: 0,
            declared_total: 0,
        }
    }

    /// 空闲会话回收：超 SESSION_TTL 无任何帧 → 逐出并删除半成品。
    fn sweep_idle(&mut self) {
        let expired: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.last_seen.elapsed() > SESSION_TTL)
            .map(|(k, _)| *k)
            .collect();
        for k in expired {
            if let Some(s) = self.sessions.remove(&k) {
                self.declared_total -= s.padded;
                let _ = std::fs::remove_file(&s.part_path);
            }
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn handle(&mut self, buf: &[u8]) -> UdpEvent {
        self.handle_from(buf, None)
    }

    /// 带来源地址的处理：目录解析按对端 IP（PerDeviceFolder/AutoArchive）。
    pub fn handle_from(&mut self, buf: &[u8], remote: Option<std::net::IpAddr>) -> UdpEvent {
        self.sweep_idle();
        let h = match UdpHeader::from_bytes(buf) {
            Ok(h) => h,
            Err(_) => return UdpEvent::Ignored("坏头/短包"),
        };
        if let Some(t) = self.suppressed.get(&h.session) {
            if t.elapsed() < SUPPRESS_TTL {
                return UdpEvent::Ignored("已投递抑制");
            }
            self.suppressed.remove(&h.session);
        }
        // 会话已存在（跨轮重发）沿用建立时固定的目录；仅新会话解析。
        let dir = match self.sessions.get(&h.session) {
            Some(s) => s.dir.clone(),
            None => self
                .dir_for
                .as_ref()
                .map(|f| remote.map(|ip| f(ip)).unwrap_or_else(|| self.save_dir.clone()))
                .unwrap_or_else(|| self.save_dir.clone()),
        };
        let payload = &buf[UDP_HEADER_LEN..];
        match h.frame {
            U_F_START => self.on_start(h.session, payload, dir),
            U_F_DATA => self.on_data(h.session, h.seq, payload),
            U_F_PARITY => self.on_parity(h.session, payload),
            U_F_END => self.on_end(h.session, payload),
            _ => UdpEvent::Ignored("未知帧类型"),
        }
    }

    fn on_start(&mut self, session: u64, p: &[u8], dir: PathBuf) -> UdpEvent {
        if p.len() < 2 {
            return UdpEvent::Ignored("START 过短");
        }
        let nlen = u16::from_le_bytes([p[0], p[1]]) as usize;
        if p.len() < 2 + nlen + 14 {
            return UdpEvent::Ignored("START 过短");
        }
        let name = match std::str::from_utf8(&p[2..2 + nlen]).ok().map(sanitize_name) {
            Some(Ok(n)) => n,
            _ => return UdpEvent::Ignored("坏文件名"),
        };
        let size = u64::from_le_bytes(p[2 + nlen..10 + nlen].try_into().unwrap());
        let chunk_len = u32::from_le_bytes(p[10 + nlen..14 + nlen].try_into().unwrap());
        let fec = p[14 + nlen] == 1;
        let parity_shards = p[15 + nlen].clamp(1, 8);
        if size > MAX_TRANSFER_SIZE || chunk_len == 0 || chunk_len > 1500 {
            return UdpEvent::Ignored("START 参数越界");
        }
        let chunk_count = size.div_ceil(chunk_len as u64);
        if chunk_count > BITMAP_CAP_CHUNKS {
            return UdpEvent::Ignored("声明大小超过位图预算");
        }
        if self.sessions.contains_key(&session) {
            if let Some(s) = self.sessions.get_mut(&session) {
                s.last_seen = Instant::now();
            }
            return UdpEvent::Ignored("会话已存在");
        }
        if self.sessions.len() >= SESSION_CAP {
            // 最旧逐出（规格 §6.1）：按插入序，确定性；半成品一并删除。
            let oldest = self
                .sessions
                .iter()
                .min_by_key(|(_, v)| (v.last_seen, v.seq_no))
                .map(|(k, _)| *k);
            if let Some(k) = oldest {
                if let Some(s) = self.sessions.remove(&k) {
                    self.declared_total -= s.padded;
                    let _ = std::fs::remove_file(&s.part_path);
                }
            }
        }
        let padded = chunk_count * chunk_len as u64;
        // 磁盘预检（规格 §3.1：可用 ≥ 声明 + 64MB；探测失败放行）。
        let _ = std::fs::create_dir_all(&dir);
        if !crate::transfer::receiver::space_ok(&dir, padded) {
            return UdpEvent::Ignored("磁盘可用空间不足");
        }
        // 声明总量封顶：伪造 START 无法再靠 set_len 预分配放大磁盘占用。
        if self.declared_total + padded > DECLARED_CAP {
            return UdpEvent::Ignored("会话声明总量超限");
        }
        let part_path = dir.join(format!("{session:016x}_{name}{PART_SUFFIX}"));
        // read+write：FEC 恢复需要回读已落盘分片；truncate(false) 显式声明续传语义。
        let file = match std::fs::OpenOptions::new().create(true).write(true).read(true).truncate(false).open(&part_path) {
            Ok(f) => f,
            Err(_) => return UdpEvent::Ignored("半成品文件打不开"),
        };
        if file.set_len(padded).is_err() {
            let _ = std::fs::remove_file(&part_path);
            return UdpEvent::Ignored("预分配失败");
        }
        let codec = if fec { FecCodec::new(FEC_DATA_SHARDS, parity_shards as usize).ok() } else { None };
        let seq_no = self.next_seq;
        self.next_seq += 1;
        self.declared_total += padded;
        self.sessions.insert(
            session,
            Session {
                name,
                size,
                chunk_len,
                chunk_count,
                fec,
                parity_shards,
                codec,
                bitmap: vec![0; chunk_count.div_ceil(64) as usize],
                file,
                part_path,
                parity: HashMap::new(),
                parity_order: VecDeque::new(),
                parity_bytes: 0,
                last_seen: Instant::now(),
                seq_no,
                padded,
                done: 0,
                dir,
                start: Instant::now(),
            },
        );
        let chunk_len = self.sessions[&session].chunk_len;
        UdpEvent::Started { session, name: self.sessions[&session].name.clone(), size, chunk_len }
    }

    fn on_data(&mut self, session: u64, seq: u64, p: &[u8]) -> UdpEvent {
        let (done, total) = {
            let Some(s) = self.sessions.get_mut(&session) else {
                return UdpEvent::Ignored("无此会话");
            };
            s.last_seen = Instant::now();
            if seq >= s.chunk_count {
                return UdpEvent::Ignored("块序号越界");
            }
            // 精确长度：非末块 = chunk_len，末块 = 余数。空载荷/短载荷直接拒绝，
            // 保证「位图置位 = 字节已落盘」不变量。
            let expected = (s.chunk_len as u64).min(s.size - seq * s.chunk_len as u64);
            if p.len() as u64 != expected {
                return UdpEvent::Ignored("块长度不符");
            }
            let idx = seq as usize;
            if s.bitmap[idx / 64] >> (idx % 64) & 1 == 1 {
                return UdpEvent::Ignored("重复块");
            }
            let off = seq * s.chunk_len as u64;
            if s.file.seek(SeekFrom::Start(off)).and_then(|_| s.file.write_all(p)).is_err() {
                return UdpEvent::Ignored("写盘失败");
            }
            s.bitmap[idx / 64] |= 1u64 << (idx % 64);
            s.done += 1;
            (s.done, s.chunk_count)
        };
        // 组恢复：DATA 到齐 + 已缓存的 PARITY 可能凑足 k 个已知分片。
        self.try_recover(session, seq / FEC_DATA_SHARDS as u64);
        UdpEvent::Progress { session, done, total }
    }

    fn on_parity(&mut self, session: u64, p: &[u8]) -> UdpEvent {
        let Some(s) = self.sessions.get_mut(&session) else {
            return UdpEvent::Ignored("无此会话");
        };
        s.last_seen = Instant::now();
        if !s.fec || p.len() < 5 {
            return UdpEvent::Ignored("坏 PARITY");
        }
        let group = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
        let idx = p[4];
        let shard = &p[5..];
        // idx 必须落在校验分片域 [k, k+r)，垃圾分片不占预算。
        if idx < FEC_DATA_SHARDS as u8 || idx >= (FEC_DATA_SHARDS + s.parity_shards as usize) as u8 {
            return UdpEvent::Ignored("PARITY 分片序号越界");
        }
        if shard.len() != s.chunk_len as usize {
            return UdpEvent::Ignored("PARITY 分片长度不符");
        }
        let entry = s.parity.entry(group).or_default();
        if !entry.contains_key(&idx) {
            s.parity_bytes += shard.len();
        }
        entry.insert(idx, shard.to_vec());
        if !s.parity_order.contains(&group) {
            s.parity_order.push_back(group);
        }
        // 逐出：≤4 组且 ≤256KB（规格 §6.1，FIFO + 字节预算）；当前组受保护。
        while (s.parity_order.len() > PARITY_GROUP_CAP || s.parity_bytes > PARITY_BYTE_BUDGET)
            && s.parity_order.len() > 1
        {
            let Some(pos) = s.parity_order.iter().position(|&g| g != group) else { break };
            let old = s.parity_order.remove(pos).unwrap();
            if let Some(m) = s.parity.remove(&old) {
                s.parity_bytes -= m.values().map(|v| v.len()).sum::<usize>();
            }
        }
        let (done, total) = (s.done, s.chunk_count);
        self.try_recover(session, group as u64);
        // 注意：GUI 接线 Progress 事件时必须先加 100ms 节流（规格 §3.1），
        // unbounded channel 在慢消费者下会无界增长。
        UdpEvent::Progress { session, done, total }
    }

    fn try_recover(&mut self, session: u64, group: u64) {
        let total_shards = {
            let Some(s) = self.sessions.get(&session) else { return };
            if !s.fec {
                return;
            }
            FEC_DATA_SHARDS + s.parity_shards as usize
        };
        // 组内 4 个数据位已全部置位 → 无需恢复（多轮重发的重复 PARITY 直达早退，
        // 避免重复磁盘读 + RS 重构被放大数倍）。
        {
            let Some(s) = self.sessions.get(&session) else { return };
            let g0 = group * FEC_DATA_SHARDS as u64;
            let complete = (0..FEC_DATA_SHARDS as u64).all(|i| {
                let idx = g0 + i;
                idx >= s.chunk_count
                    || s.bitmap[idx as usize / 64] >> (idx as usize % 64) & 1 == 1
            });
            if complete {
                return;
            }
        }
        let (codec_present, known) = {
            let Some(s) = self.sessions.get(&session) else { return };
            (s.codec.is_some(), known_count(s, group, total_shards))
        };
        if !codec_present || known < FEC_DATA_SHARDS {
            return;
        }
        // 组装分片：数据分片读盘，校验分片取缓存；不足的留 None。
        let shards: Vec<Option<Vec<u8>>> = {
            let s = self.sessions.get_mut(&session).unwrap();
            let g0 = group * FEC_DATA_SHARDS as u64;
            (0..total_shards as u64)
                .map(|i| {
                    if (i as usize) < FEC_DATA_SHARDS {
                        let idx = g0 + i;
                        if idx >= s.chunk_count {
                            // 末组补零分片：双方确定为全零，视为已知分片。
                            return Some(vec![0u8; s.chunk_len as usize]);
                        }
                        if s.bitmap[idx as usize / 64] >> (idx as usize % 64) & 1 == 0 {
                            return None;
                        }
                        let off = idx * s.chunk_len as u64;
                        let mut v = vec![0u8; s.chunk_len as usize];
                        if s.file.seek(SeekFrom::Start(off)).and_then(|_| s.file.read_exact(&mut v)).is_err() {
                            return None;
                        }
                        Some(v)
                    } else {
                        s.parity.get(&(group as u32)).and_then(|m| m.get(&(i as u8))).cloned()
                    }
                })
                .collect()
        };
        let recovered = {
            let s = self.sessions.get_mut(&session).unwrap();
            let codec = s.codec.as_mut().unwrap();
            match codec.try_reconstruct(shards) {
                Ok(all) => all,
                Err(_) => {
                    return;
                }
            }
        };
        // 落盘补上的数据分片。
        let s = self.sessions.get_mut(&session).unwrap();
        for (i, shard) in recovered.into_iter().enumerate() {
            if (i as u64) >= FEC_DATA_SHARDS as u64 {
                continue;
            }
            let Some(shard) = shard else { continue };
            let idx = group * FEC_DATA_SHARDS as u64 + i as u64;
            if idx >= s.chunk_count {
                continue;
            }
            if s.bitmap[idx as usize / 64] >> (idx as usize % 64) & 1 == 1 {
                continue;
            }
            let off = idx * s.chunk_len as u64;
            if s.file.seek(SeekFrom::Start(off)).and_then(|_| s.file.write_all(&shard)).is_ok() {
                s.bitmap[idx as usize / 64] |= 1u64 << (idx as usize % 64);
                s.done += 1;
            }
        }
    }

    fn on_end(&mut self, session: u64, p: &[u8]) -> UdpEvent {
        let Some(s) = self.sessions.get_mut(&session) else {
            return UdpEvent::Ignored("无此会话");
        };
        s.last_seen = Instant::now();
        if p.len() < 32 {
            return UdpEvent::Ignored("END 过短");
        }
        if s.done < s.chunk_count {
            return UdpEvent::Ignored("尚未完整，等待后续轮次");
        }
        let claimed: [u8; 32] = p[..32].try_into().unwrap();
        // 校验前先裁掉末组补零。
        if s.file.set_len(s.size).and_then(|_| s.file.sync_all()).is_err() {
            let _ = std::fs::remove_file(&s.part_path);
            let s = self.sessions.remove(&session);
            if let Some(s) = s {
                self.declared_total -= s.padded;
            }
            return UdpEvent::Ignored("收尾写失败");
        }
        let part_path = s.part_path.clone();
        let name = s.name.clone();
        let size = s.size;
        let dir = s.dir.clone();
        let start = s.start;
        let ok = std::fs::File::open(&part_path)
            .map(|mut f| {
                let mut dig = FileDigester::new();
                let mut buf = vec![0u8; 64 * 1024];
                let mut left = size;
                loop {
                    let want = buf.len().min(left as usize);
                    if want == 0 {
                        break;
                    }
                    match f.read(&mut buf[..want]) {
                        Ok(0) => break,
                        Ok(n) => {
                            dig.update(&buf[..n]);
                            left -= n as u64;
                        }
                        Err(_) => break,
                    }
                }
                left == 0 && dig.finalize() == claimed
            })
            .unwrap_or(false);
        if let Some(s) = self.sessions.remove(&session) {
            self.declared_total -= s.padded;
        }
        if !ok {
            // 校验失败必须真删除（规格 §3.1）；无回传链路，只能本机记录。
            let _ = std::fs::remove_file(&part_path);
            return UdpEvent::Ignored("SHA-256 不一致，已删除");
        }
        // 发布与 TCP 同纪律：hard_link fail-if-exists，冲突名循环重取（rename 会静默覆盖）。
        match publish_part_sync(&part_path, &dir, &name) {
            Some(dest) => {
                self.mark_suppressed(session);
                UdpEvent::Completed { session, path: dest, size, start }
            }
            None => {
                let _ = std::fs::remove_file(&part_path);
                UdpEvent::Ignored("发布失败")
            }
        }
    }

    fn mark_suppressed(&mut self, session: u64) {
        self.suppressed.insert(session, Instant::now());
        self.suppress_order.push_back(session);
        while self.suppress_order.len() > SUPPRESS_CAP {
            if let Some(old) = self.suppress_order.pop_front() {
                self.suppressed.remove(&old);
            }
        }
    }
}

fn known_count(s: &Session, group: u64, total_shards: usize) -> usize {
    let g0 = group * FEC_DATA_SHARDS as u64;
    (0..total_shards)
        .filter(|&i| {
            if i < FEC_DATA_SHARDS {
                let idx = g0 + i as u64;
                // 末组补零分片视为已知。
                idx >= s.chunk_count
                    || s.bitmap[idx as usize / 64] >> (idx as usize % 64) & 1 == 1
            } else {
                s.parity.get(&(group as u32)).map(|m| m.contains_key(&(i as u8))).unwrap_or(false)
            }
        })
        .count()
}

/// 同步版原子发布：hard_link fail-if-exists + 冲突名循环重取。
fn publish_part_sync(part: &Path, dir: &Path, name: &str) -> Option<PathBuf> {
    for _ in 0..10000u32 {
        let cand = resolve_conflict_sync(dir, name);
        match std::fs::hard_link(part, &cand) {
            Ok(()) => {
                let _ = std::fs::remove_file(part);
                return Some(cand);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                // 硬链接不可用卷的退化路径（fail-if-exists 语义不变）；
                // 失败路径清掉 candidate，不把半成品留在最终名上。
                let mut dst = match std::fs::OpenOptions::new().write(true).create_new(true).open(&cand) {
                    Ok(d) => d,
                    Err(e2) if e2.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(_) => return None,
                };
                let ok = std::fs::File::open(part).and_then(|mut src| {
                    std::io::copy(&mut src, &mut dst).and_then(|_| dst.sync_all())
                });
                drop(dst);
                if ok.is_err() {
                    let _ = std::fs::remove_file(&cand);
                    return None;
                }
                let _ = std::fs::remove_file(part);
                return Some(cand);
            }
        }
    }
    None
}

/// 同步版冲突改名（引擎在同步上下文里收尾）。
fn resolve_conflict_sync(dir: &Path, name: &str) -> PathBuf {
    let cand = dir.join(name);
    if std::fs::metadata(&cand).is_err() {
        return cand;
    }
    let p = Path::new(name);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file").to_string();
    let ext = p.extension().and_then(|s| s.to_str()).map(|e| format!(".{e}")).unwrap_or_default();
    for i in 1..10000u32 {
        let c = dir.join(format!("{stem}_{i}{ext}"));
        if std::fs::metadata(&c).is_err() {
            return c;
        }
    }
    dir.join(format!("{stem}_dupe{ext}"))
}

/// 启动前清理孤儿半成品（7 天未返回，规格 §6.1）。
pub fn cleanup_orphans(dir: &Path) {
    fn walk(dir: &Path, depth: u32) {
        if depth > 6 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let now = SystemTime::now();
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, depth + 1);
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if !name.ends_with(PART_SUFFIX) {
                continue;
            }
            if let Ok(md) = e.metadata() {
                if md.modified().map(|t| now.duration_since(t).map(|d| d > ORPHAN_TTL).unwrap_or(false)).unwrap_or(false) {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }
    walk(dir, 0);
}

pub async fn serve_udp(addr: SocketAddr, opts: UdpRecvOptions, events: Option<mpsc::UnboundedSender<UdpEvent>>) -> Result<()> {
    // 规格 §6.1：UDP 收缓冲 4 MB（设置失败仅告警不阻断）。
    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let sock2 = socket2::Socket::new(domain, socket2::Type::DGRAM, None)
        .map_err(|e| crate::error::Error::Io(std::io::Error::other(e.to_string())))?;
    sock2.set_nonblocking(true).map_err(|e| crate::error::Error::Io(std::io::Error::other(e.to_string())))?;
    sock2.bind(&addr.into()).map_err(|e| crate::error::Error::Io(std::io::Error::other(e.to_string())))?;
    if let Err(e) = sock2.set_recv_buffer_size(4 * 1024 * 1024) {
        eprintln!("[警告] UDP 收缓冲设置失败: {e}");
    }
    let std_sock: std::net::UdpSocket = sock2.into();
    let socket = UdpSocket::from_std(std_sock).map_err(|e| crate::error::Error::Io(std::io::Error::other(e.to_string())))?;
    serve_udp_on(socket, opts, events).await
}

pub async fn serve_udp_on(socket: UdpSocket, opts: UdpRecvOptions, events: Option<mpsc::UnboundedSender<UdpEvent>>) -> Result<()> {
    cleanup_orphans(&opts.save_dir);
    let _ = std::fs::create_dir_all(&opts.save_dir);
    let filter = (opts.ip_filter_mode, opts.ip_filter_list.clone());
    // 目录解析器：`<save>/<设备名|IP>/<yyyy-mm-dd>/`（规格 §3.3）；
    // 单向 UDP 无握手确认点，ConfirmReceive 不适用（TECH-STACK §7.10）。
    let dir_for: Option<DirResolver> = if opts.per_device_folder || opts.auto_archive {
        let devices = opts.devices.clone();
        let save_dir = opts.save_dir.clone();
        let per_dev = opts.per_device_folder;
        let archive = opts.auto_archive;
        Some(std::sync::Arc::new(move |ip: std::net::IpAddr| {
            let mut dir = save_dir.clone();
            if per_dev {
                let comp = devices
                    .as_ref()
                    .and_then(|d| d.name_for(ip))
                    .and_then(|n| sanitize_name(&n).ok())
                    .unwrap_or_else(|| crate::transfer::receiver::ip_dir_component(ip));
                dir.push(comp);
            }
            if archive {
                dir.push(crate::transfer::receiver::today_component());
            }
            dir
        }) as DirResolver)
    } else {
        None
    };
    let mut engine = UdpRecvEngine::with_resolver(opts.save_dir, dir_for);
    let mut buf = vec![0u8; 2048];
    // 进度映射表：session → (Reporter, chunk_len, size, 已计入字节, 开始时刻)。Reporter::add 自带
    // 100ms 节流（规格 §3.1——此处的 UdpEvent::Progress 是逐包事件，不能直发）；
    // 引擎的 done 计的是块数，此处按 chunk_len 换算字节并钳到 size（末块余数不满块）。
    // 表上限 256：引擎会话表有 TTL 逐出，这里同步封顶防映射表无界增长。
    let mut reports: HashMap<u64, (crate::progress::Reporter, u64, u64, u64, std::time::Instant)> = HashMap::new();
    let mut report_order: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
    loop {
        // 惰性清扫（轮 3 P2-5）：引擎逐出（64 会话帽/TTL）不产生 Completed——
        // 对应 Reporter 悬空会让 GUI 进度卡永久 running。超龄（TTL+60s）即补失败终态。
        let stale: Vec<u64> = reports
            .iter()
            .filter(|(_, (.., t))| t.elapsed() > SESSION_TTL + Duration::from_secs(60))
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            if let Some((r, ..)) = reports.remove(&k) {
                r.fail();
            }
            report_order.retain(|s| s != &k);
        }
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            // Windows：缓冲小于数据报 → WSAEMSGSIZE(10040)——一个超长垃圾包
            // 不得杀死整个接收器（轮 4 P1：LAN kill switch，已实测复现）。
            // 合法帧上限 1525B，超长包必为垃圾 → 丢弃续收。
            Err(e) if e.raw_os_error() == Some(10040) => {
                continue;
            }
            Err(e) => return Err(crate::error::Error::Io(e)),
        };
        // IP 过滤（规格 §3.3）：来源被拒 → 静默丢弃（引擎处理前判定，无状态污染）。
        if !crate::transfer::receiver::ip_allowed(peer.ip(), filter.0, &filter.1) {
            continue;
        }
        // 引擎放入 blocking 池：END 的整文件哈希不占 async worker。
        // 注意：逐包 await 意味着引擎仍串行——大文件 END 哈希期间后续包
        // 在内核缓冲排队，靠多轮重发收敛（规格 §4.2 落盘即状态）。
        let packet = buf[..n].to_vec();
        let remote = peer.ip();
        let (eng, ev) = match tokio::task::spawn_blocking(move || {
            let ev = engine.handle_from(&packet, Some(remote));
            (engine, ev)
        })
        .await
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[错误] UDP 引擎任务异常退出: {e}");
                return Err(crate::error::proto("UDP 引擎任务崩溃"));
            }
        };
        engine = eng;
        match &ev {
            UdpEvent::Started { session, name, size, chunk_len } => {
                if let Some(hub) = &opts.progress {
                    if reports.len() >= 256 {
                        if let Some(old) = report_order.pop_front() {
                            if let Some((r, ..)) = reports.remove(&old) {
                                r.fail();
                            }
                        }
                    }
                    let r = hub.register("recv", name.clone(), *size);
                    report_order.push_back(*session);
                    reports.insert(*session, (r, *chunk_len as u64, *size, 0, std::time::Instant::now()));
                }
            }
            UdpEvent::Progress { session, done, .. } => {
                if let Some((r, chunk_len, size, last, _)) = reports.get_mut(session) {
                    let bytes = (*done * *chunk_len).min(*size);
                    if bytes > *last {
                        r.add(bytes - *last);
                        *last = bytes;
                    }
                }
            }
            UdpEvent::Completed { session, path, size, start } => {
                let removed = reports.remove(session);
                if let Some((r, ..)) = &removed {
                    r.finish();
                }
                report_order.retain(|s| s != session);
                eprintln!("[接收-UDP] 会话 {session:016x} → {}", path.display());
                // 落盘即状态（规格 §4.2）：发布成功即记账；size/start 直接取自事件
                // （轮 1：不再依赖 progress hub 注入——CLI 无 hub 也记全）。
                if let Some(stats) = &opts.stats {
                    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    stats.record(
                        crate::stats::Direction::Recv,
                        &peer.ip().to_string(),
                        *size,
                        1,
                        start.elapsed().as_secs(),
                        "UDP 接收",
                        &name,
                    );
                }
                if let Some(tx) = &events {
                    let _ = tx.send(ev.clone());
                }
            }
            UdpEvent::Ignored(_) => {}
        }
        if matches!(ev, UdpEvent::Started { .. } | UdpEvent::Progress { .. }) {
            if let Some(tx) = &events {
                let _ = tx.send(ev);
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct UdpRecvOptions {
    pub save_dir: PathBuf,
    /// 进度事件出口（GUI 注入；serve_udp_on 内做 100ms 节流——规格 §3.1）。
    pub progress: Option<crate::progress::ProgressHub>,
    /// IP 过滤（规格 §3.3；单向 UDP 无回传，过滤即静默丢弃）。
    pub ip_filter_mode: crate::config::FilterMode,
    pub ip_filter_list: Vec<String>,
    /// 设备记忆（PerDeviceFolder 按来源 IP 解析设备名）。
    pub devices: Option<std::sync::Arc<crate::devices::DeviceStore>>,
    /// 按设备分目录（规格 §3.3 PerDeviceFolder）。
    pub per_device_folder: bool,
    /// 按日期归档（规格 §3.3 AutoArchive）。
    pub auto_archive: bool,
    /// 传输统计（M5'：落盘成功记账；None = 不记）。
    pub stats: Option<std::sync::Arc<crate::stats::StatsLog>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::RngCore;

    async fn make_file(dir: &Path, name: &str, len: usize) -> (PathBuf, Vec<u8>) {
        let mut data = vec![0u8; len];
        rand_core::OsRng.fill_bytes(&mut data);
        let p = dir.join(name);
        std::fs::write(&p, &data).unwrap();
        (p, data)
    }

    #[tokio::test]
    async fn complete_transfer_without_loss() {
        let dir = tempfile::tempdir().unwrap();
        let (src, data) = make_file(dir.path(), "a.bin", 7200).await; // 2 组 × 4 块
        let plan = build_plan(&src, &UdpSendOptions::default()).await.unwrap();
        let out = dir.path().join("out");
        let mut eng = UdpRecvEngine::new(out.clone());
        for f in plan.start_frames() {
            eng.handle(&f);
        }
        let (data_frames, _parity, hash) = plan.build_pass(&src).await.unwrap();
        for d in &data_frames {
            eng.handle(d);
        }
        for e in plan.end_frames(&hash) {
            eng.handle(&e);
        }
        let dest = out.join("a.bin");
        assert!(dest.exists(), "应已落盘");
        assert_eq!(std::fs::read(&dest).unwrap(), data);
    }

    #[tokio::test]
    async fn fec_recovers_two_lost_data_shards() {
        let dir = tempfile::tempdir().unwrap();
        let (src, data) = make_file(dir.path(), "b.bin", 7200).await;
        let plan = build_plan(&src, &UdpSendOptions { fec: true, ..Default::default() }).await.unwrap();
        let out = dir.path().join("out");
        let mut eng = UdpRecvEngine::new(out.clone());
        for f in plan.start_frames() {
            eng.handle(&f);
        }
        let (data_frames, parity, hash) = plan.build_pass(&src).await.unwrap();
        // 第 0 组丢 2 个数据分片（seq 0、1），靠 PARITY(4,5) 恢复。
        for (i, d) in data_frames.iter().enumerate() {
            if i == 0 || i == 1 {
                continue;
            }
            eng.handle(d);
        }
        for p in &parity {
            eng.handle(p);
        }
        for e in plan.end_frames(&hash) {
            eng.handle(&e);
        }
        let dest = out.join("b.bin");
        assert!(dest.exists(), "FEC 应恢复丢失分片");
        assert_eq!(std::fs::read(&dest).unwrap(), data);
    }

    /// 轮 1 F2 判别：FEC 模式 size % 1200 ≠ 0 时，末块必须能**直接经 DATA 帧**
    /// 落盘（不得依赖末组 PARITY 恢复）。修复前发送侧末块补零到块长 → 被接收端
    /// 精确长度校验拒绝 → PARITY 全丢时整文件不可交付，本测试必红。
    #[tokio::test]
    async fn fec_last_remainder_chunk_delivered_via_data_without_parity() {
        let dir = tempfile::tempdir().unwrap();
        let (src, data) = make_file(dir.path(), "r.bin", 5000).await; // 4×1200 + 余 200
        let plan = build_plan(&src, &UdpSendOptions { fec: true, ..Default::default() }).await.unwrap();
        let out = dir.path().join("out");
        let mut eng = UdpRecvEngine::new(out.clone());
        for f in plan.start_frames() {
            eng.handle(&f);
        }
        let (data_frames, _parity_dropped, hash) = plan.build_pass(&src).await.unwrap();
        // 全部 PARITY 丢失：交付只能依赖 DATA 帧。
        for d in &data_frames {
            eng.handle(d);
        }
        for e in plan.end_frames(&hash) {
            eng.handle(&e);
        }
        let dest = out.join("r.bin");
        assert!(dest.exists(), "末块必须经 DATA 帧直接落盘（不依赖 PARITY）");
        assert_eq!(std::fs::read(&dest).unwrap(), data);
    }

    #[tokio::test]
    async fn suppression_after_completion() {
        let dir = tempfile::tempdir().unwrap();
        let (src, data) = make_file(dir.path(), "c.bin", 100).await;
        let plan = build_plan(&src, &UdpSendOptions { fec: false, ..Default::default() }).await.unwrap();
        let out = dir.path().join("out");
        let mut eng = UdpRecvEngine::new(out.clone());
        for f in plan.start_frames() {
            eng.handle(&f);
        }
        let (data_frames, _, hash) = plan.build_pass(&src).await.unwrap();
        for d in &data_frames {
            eng.handle(d);
        }
        for e in plan.end_frames(&hash) {
            eng.handle(&e);
        }
        // 完成后同会话再来数据 → 抑制。
        let ev = eng.handle(&data_frames[0]);
        assert!(matches!(ev, UdpEvent::Ignored("已投递抑制")));
        assert_eq!(std::fs::read(out.join("c.bin")).unwrap(), data);
    }

    #[tokio::test]
    async fn session_table_evicts_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let mut eng = UdpRecvEngine::new(out.clone());
        // 记录第 0 个会话的一个 DATA 帧，用于验证它被逐出。
        let (p0, _) = make_file(dir.path(), "s0.bin", 10).await;
        let plan0 = build_plan(&p0, &UdpSendOptions { fec: false, ..Default::default() }).await.unwrap();
        let data0 = plan0.build_pass(&p0).await.unwrap().0;
        eng.handle(&plan0.start_frames()[0]);
        for i in 1..=64 {
            let (src, _) = make_file(dir.path(), &format!("s{i}.bin"), 10).await;
            let plan = build_plan(&src, &UdpSendOptions { fec: false, ..Default::default() }).await.unwrap();
            eng.handle(&plan.start_frames()[0]);
        }
        assert_eq!(eng.session_count(), 64);
        // 第 0 个会话应已被逐出。
        let ev = eng.handle(&data0[0]);
        assert!(matches!(ev, UdpEvent::Ignored("无此会话")));
    }

    #[tokio::test]
    async fn oversize_declaration_rejected_without_alloc() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        let mut eng = UdpRecvEngine::new(out);
        let mut f = vec![0u8; UDP_HEADER_LEN + 2 + 8 + 8 + 4 + 2];
        f[..UDP_HEADER_LEN].copy_from_slice(
            &UdpHeader { frame: U_F_START, session: 1, seq: 0 }.to_bytes(),
        );
        let name = b"huge.bin";
        f[UDP_HEADER_LEN..UDP_HEADER_LEN + 2].copy_from_slice(&(name.len() as u16).to_le_bytes());
        f[UDP_HEADER_LEN + 2..UDP_HEADER_LEN + 2 + name.len()].copy_from_slice(name);
        let base = UDP_HEADER_LEN + 2 + name.len();
        // size = (BITMAP_CAP_CHUNKS+1) * 1200 → 超位图预算
        let size = (BITMAP_CAP_CHUNKS + 1) * UDP_CHUNK as u64;
        f[base..base + 8].copy_from_slice(&size.to_le_bytes());
        f[base + 8..base + 12].copy_from_slice(&(UDP_CHUNK as u32).to_le_bytes());
        f[base + 12] = 0; // fec off
        f[base + 13] = 2;
        let ev = eng.handle(&f);
        assert!(matches!(ev, UdpEvent::Ignored("声明大小超过位图预算")));
        assert_eq!(eng.session_count(), 0);
    }

    #[tokio::test]
    async fn end_with_wrong_hash_deletes_part() {
        // 审查轮7：SHA-256 不一致 fail-closed 全链路（UDP 侧）——
        // 去掉哈希比对本测试必须变红。
        let dir = tempfile::tempdir().unwrap();
        let (src, _data) = make_file(dir.path(), "bad.bin", 100).await;
        let plan = build_plan(&src, &UdpSendOptions { fec: false, ..Default::default() }).await.unwrap();
        let out = dir.path().join("out");
        let mut eng = UdpRecvEngine::new(out.clone());
        for f in plan.start_frames() {
            eng.handle(&f);
        }
        let (data_frames, _, _) = plan.build_pass(&src).await.unwrap();
        for d in &data_frames {
            eng.handle(d);
        }
        // 伪造错误哈希的 END。
        let bad_hash = crate::hash::sha256(b"not the file");
        let ev = eng.handle(&plan.end_frames(&bad_hash)[0]);
        assert!(matches!(ev, UdpEvent::Ignored("SHA-256 不一致，已删除")), "实际: {ev:?}");
        assert!(eng.session_count() == 0, "会话必须清空");
        // 半成品必须真删除（规格 §3.1）。
        let leftover: Vec<_> = std::fs::read_dir(&out).unwrap().flatten().collect();
        assert!(leftover.is_empty(), "不得残留: {:?}", leftover.iter().map(|e| e.file_name()).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn duplicate_data_no_double_count() {
        // 审查轮7：重复 DATA 不得双计 done（否则 END 提前判完整 → 哈希失败误删）。
        let dir = tempfile::tempdir().unwrap();
        let (src, data) = make_file(dir.path(), "d.bin", 1200).await; // 单块
        let plan = build_plan(&src, &UdpSendOptions { fec: false, ..Default::default() }).await.unwrap();
        let out = dir.path().join("out");
        let mut eng = UdpRecvEngine::new(out.clone());
        for f in plan.start_frames() {
            eng.handle(&f);
        }
        let (data_frames, _, _) = plan.build_pass(&src).await.unwrap();
        // 同一块发两遍。
        eng.handle(&data_frames[0]);
        let ev = eng.handle(&data_frames[0]);
        assert!(matches!(ev, UdpEvent::Ignored("重复块")));
        for e in plan.end_frames(&plan.build_pass(&src).await.unwrap().2) {
            eng.handle(&e);
        }
        assert!(out.join("d.bin").exists());
        assert_eq!(std::fs::read(out.join("d.bin")).unwrap(), data);
    }

    #[tokio::test]
    async fn second_pass_delivers_missing_chunks() {
        // 审查轮7：UDP 二轮补传收敛（fec=false，首轮丢 2 块，二轮补齐）。
        let dir = tempfile::tempdir().unwrap();
        let (src, data) = make_file(dir.path(), "m.bin", 6000).await; // 5 块
        let plan = build_plan(&src, &UdpSendOptions { fec: false, ..Default::default() }).await.unwrap();
        let out = dir.path().join("out");
        let mut eng = UdpRecvEngine::new(out.clone());
        for f in plan.start_frames() {
            eng.handle(&f);
        }
        let (round1, _, _) = plan.build_pass(&src).await.unwrap();
        for (i, d) in round1.iter().enumerate() {
            if i == 1 || i == 3 {
                continue; // 首轮丢 2 块
            }
            eng.handle(d);
        }
        // 首轮 END：未完整，不落盘。
        let (_, _, hash) = plan.build_pass(&src).await.unwrap();
        let ev = eng.handle(&plan.end_frames(&hash)[0]);
        assert!(matches!(ev, UdpEvent::Ignored("尚未完整，等待后续轮次")));
        // 二轮全量重发 → 补齐 → END 完成。
        let (round2, _, hash2) = plan.build_pass(&src).await.unwrap();
        for d in &round2 {
            eng.handle(d);
        }
        for e in plan.end_frames(&hash2) {
            eng.handle(&e);
        }
        let dest = out.join("m.bin");
        assert!(dest.exists());
        assert_eq!(std::fs::read(&dest).unwrap(), data);
    }

    #[tokio::test]
    async fn orphans_cleaned_by_age() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join(format!("{:016x}_old{PART_SUFFIX}", 1));
        let fresh = dir.path().join(format!("{:016x}_new{PART_SUFFIX}", 2));
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(&fresh, b"x").unwrap();
        {
            let f = std::fs::File::options().write(true).open(&old).unwrap();
            f.set_modified(SystemTime::now() - Duration::from_secs(8 * 24 * 3600)).unwrap();
        }
        cleanup_orphans(dir.path());
        assert!(!old.exists());
        assert!(fresh.exists());
    }

    /// M5' 判别：会话按来源 IP 落入 `<设备>/<日期>/`（PerDeviceFolder/AutoArchive）。
    /// 走 handle_from 喂帧；去掉 resolver 接线（engine.handle 路径）即落根目录，断言变红。
    #[tokio::test]
    async fn engine_resolves_per_device_dir() {
        let dir = tempfile::tempdir().unwrap();
        let (src, data) = make_file(dir.path(), "u.bin", 2400).await;
        let out = dir.path().join("out");
        let today = crate::transfer::receiver::today_component();
        let save = out.clone();
        let today_c = today.clone();
        let store = std::sync::Arc::new(crate::devices::DeviceStore::in_memory());
        store.upsert(crate::devices::DeviceInfo {
            name: "无线端".into(),
            ip: "10.9.9.9".into(),
            port: 8080,
            proto: "tcp".into(),
            needs_pairing: false,
            last_seen: 0,
            source: crate::devices::DeviceSource::Transfer,
        });
        let resolver: DirResolver = std::sync::Arc::new(move |ip| {
            let comp = store
                .name_for(ip)
                .and_then(|n| sanitize_name(&n).ok())
                .unwrap_or_else(|| ip.to_string());
            save.join(comp).join(&today_c)
        });
        let mut eng = UdpRecvEngine::with_resolver(out.clone(), Some(resolver));
        let plan = build_plan(&src, &UdpSendOptions::default()).await.unwrap();
        let remote: std::net::IpAddr = "10.9.9.9".parse().unwrap();
        for f in plan.start_frames() {
            eng.handle_from(&f, Some(remote));
        }
        let (frames, _, hash) = plan.build_pass(&src).await.unwrap();
        for d in &frames {
            eng.handle_from(d, Some(remote));
        }
        for e in plan.end_frames(&hash) {
            eng.handle_from(&e, Some(remote));
        }
        let dest = out.join("无线端").join(&today).join("u.bin");
        assert!(dest.exists(), "UDP 会话按来源 IP 落入 <设备>/<日期>/");
        assert_eq!(std::fs::read(&dest).unwrap(), data);
        assert!(!out.join("u.bin").exists(), "根目录不得出现副本");
    }
}
