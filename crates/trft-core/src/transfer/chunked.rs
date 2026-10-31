//! 分块传输 0x02 / 0x0B / 0x0C（Rust v2 定义，WIRE-PROTOCOL.md §3.3–3.5）。
//!
//! 服务端会话模型：groupId → (半成品文件, 合并区间表, total, name)。
//! - **覆盖判完成**：区间合并排序后覆盖 `[0, total)`，不按字节累加（规格 §3.1）；
//!   合并区间数 > 8192 拒收（慢速 DoS 守卫）。
//! - 写盘决策在「文件锁 + 状态锁」下原子做出：已覆盖区间跳过写盘（幂等 +
//!   防组装与迟到写竞态——发布是 hard_link，迟到写会穿透链接改坏成品）。
//! - 覆盖达成 → 组装（现算整文件 SHA-256 → 登记摘要缓存 → 原子发布）；
//!   组装失败必须移除会话，让 0x0C 回 0x00 强制客户端整组重来（杜绝假成功）。
//! - 会话表 64 组、10 分钟无块逐出并删除半成品；孤儿 `.trft-part` 另受 7 天清扫兜底。

use crate::error::{Error, Result, config_err, proto};
use crate::hash::sha256_file;
use crate::limiter::TokenBucket;
use crate::protocol::frame::{
    MAX_CHUNK_PAYLOAD, MAX_CHUNK_SESSIONS, MAX_MERGED_RANGES, MAX_TRANSFER_SIZE, STATUS_INCOMPLETE,
    STATUS_OK, STATUS_REJECT, T_CHUNKED, T_CHUNK_END, T_COVERAGE_QUERY, sanitize_name,
};
use crate::protocol::io::{
    read_n, read_n_long, read_str_u16, read_u32, read_u64, read_u8, write_all, write_str_u16,
    write_u32, write_u64, write_u8,
};
use tokio::io::{AsyncRead, AsyncWrite};
use crate::transfer::receiver::{RecvOptions, publish_part};
use crate::transfer::resume;
use crate::transfer::sender::{SendOptions, StackPlan, connect_stack};
use crate::transfer::{BoxStream, CHUNK};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// 空闲会话逐出（与单向 UDP 会话 TTL 同源纪律）。
const SESSION_TTL: Duration = Duration::from_secs(600);

pub(crate) struct GroupState {
    ranges: Vec<(u64, u64)>, // 已写盘区间（合并、升序）
    covered: u64,
    assembling: bool,
}

pub(crate) struct GroupSession {
    name: String,
    total: u64,
    part: PathBuf,
    /// 位置写互斥：并行连接串行落盘（正确性优先；吞吐由多连接网络 I/O 重叠获得）。
    file: tokio::sync::Mutex<tokio::fs::File>,
    state: tokio::sync::Mutex<GroupState>,
    last_seen_ms: AtomicU64,
    /// 进度上报（会话创建时注册；None = 不上报）。
    report: Option<crate::progress::Reporter>,
}

#[derive(Default)]
pub struct ChunkTracker {
    sessions: tokio::sync::Mutex<HashMap<[u8; 16], std::sync::Arc<GroupSession>>>,
    /// 进度事件出口（GUI 注入；Default None = 不上报）。
    pub progress: Option<crate::progress::ProgressHub>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn group_part_path(save_dir: &Path, name: &str, gid: &[u8; 16]) -> PathBuf {
    let mut hex = String::with_capacity(32);
    for b in gid {
        hex.push_str(&format!("{b:02x}"));
    }
    save_dir.join(format!("{name}.{hex}.trft-part"))
}

/// 区间合并（升序、互不重叠）；返回新增覆盖字节数。
fn merge_range(ranges: &mut Vec<(u64, u64)>, start: u64, end: u64) -> Result<u64> {
    let mut added = end - start;
    let mut start = start;
    let mut end = end;
    let mut head = 0usize; // 完全位于新区间之前的段数
    let mut tail = ranges.len(); // 完全位于新区间之后的段起点（被吸收段不计入）
    for (i, &(rs, re)) in ranges.iter().enumerate() {
        if re < start {
            head = i + 1;
        } else if rs > end {
            tail = i;
            break;
        } else {
            // 与新区间相交/相邻 → 吸收（相邻段交叠为 0，added 不减）。
            added = added.saturating_sub(re.min(end).saturating_sub(rs.max(start)));
            start = start.min(rs);
            end = end.max(re);
        }
    }
    let mut merged_back = Vec::with_capacity(head + 1 + (ranges.len() - tail));
    merged_back.extend_from_slice(&ranges[..head]);
    merged_back.push((start, end));
    merged_back.extend_from_slice(&ranges[tail..]);
    if merged_back.len() > MAX_MERGED_RANGES {
        return Err(proto(format!(
            "合并区间数超过 {MAX_MERGED_RANGES} 上限（慢速 DoS 守卫）"
        )));
    }
    *ranges = merged_back;
    Ok(added)
}

/// `[start,end)` 是否已被现有合并区间完整覆盖。
fn covered_range(ranges: &[(u64, u64)], start: u64, end: u64) -> bool {
    let mut pos = start;
    for &(rs, re) in ranges {
        if re <= pos {
            continue;
        }
        if rs > pos {
            return false;
        }
        pos = re;
        if pos >= end {
            return true;
        }
    }
    pos >= end
}

impl ChunkTracker {
    async fn ensure(
        &self,
        gid: [u8; 16],
        name: &str,
        total: u64,
        save_dir: &Path,
    ) -> Result<std::sync::Arc<GroupSession>> {
        let mut map = self.sessions.lock().await;
        let now = now_ms();
        // 空闲逐出：删半成品（对打开句柄可能失败——best effort，句柄关闭后孤儿清扫兜底）。
        map.retain(|_, s| {
            let fresh = now.saturating_sub(s.last_seen_ms.load(Ordering::Relaxed)) < SESSION_TTL.as_millis() as u64;
            if !fresh {
                let _ = std::fs::remove_file(&s.part);
            }
            fresh
        });
        if let Some(s) = map.get(&gid) {
            if s.name != name || s.total != total {
                return Err(proto("0x02 会话字段冲突（name/total 与既有组不一致）"));
            }
            s.last_seen_ms.store(now, Ordering::Relaxed);
            return Ok(s.clone());
        }
        if map.len() >= MAX_CHUNK_SESSIONS {
            // 最旧逐出（last_seen 主序，与 UDP 引擎同策略）。
            let oldest = map
                .iter()
                .min_by_key(|(_, s)| s.last_seen_ms.load(Ordering::Relaxed))
                .map(|(k, _)| *k);
            if let Some(k) = oldest {
                if let Some(s) = map.remove(&k) {
                    let _ = std::fs::remove_file(&s.part);
                }
            }
        }
        let part = group_part_path(save_dir, name, &gid);
        // 磁盘预检（轮 1：0x02 此前缺席——规格 §3.1 口径对齐其余接收路径）。
        if !crate::transfer::receiver::space_ok(save_dir, total) {
            return Err(proto("0x02: 磁盘可用空间不足（需要 ≥ 声明 + 64MB 余量）"));
        }
        let file = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)
            .await
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // 上一会话残留（逐出删失败等）：删除后重试一次。
                let _ = std::fs::remove_file(&part);
                tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&part)
                    .await
                    .map_err(|e| proto(format!("创建分块半成品失败: {e}")))?
            }
            Err(e) => return Err(proto(format!("创建分块半成品失败: {e}"))),
        };
        let s = std::sync::Arc::new(GroupSession {
            name: name.to_string(),
            total,
            part,
            file: tokio::sync::Mutex::new(file),
            state: tokio::sync::Mutex::new(GroupState {
                ranges: Vec::new(),
                covered: 0,
                assembling: false,
            }),
            last_seen_ms: AtomicU64::new(now),
            report: self.progress.as_ref().map(|h| h.register("recv", name, total)),
        });
        map.insert(gid, s.clone());
        Ok(s)
    }

    /// 写入一个块；返回是否由本次调用完成覆盖（调用方随后组装）。
    /// 写盘决策在 file 锁 + state 锁下原子做出（见模块注释）。
    pub(crate) async fn receive(
        &self,
        gid: [u8; 16],
        name: &str,
        total: u64,
        offset: u64,
        payload: &[u8],
        save_dir: &Path,
    ) -> Result<bool> {
        if total == 0 {
            return Err(proto("0x02 拒绝空文件（total=0）"));
        }
        if total > MAX_TRANSFER_SIZE {
            return Err(proto(format!("声明大小 {total} 超过 1 PiB 上限")));
        }
        let sess = self.ensure(gid, name, total, save_dir).await?;
        let end = offset + payload.len() as u64;
        let mut completed = false;
        {
            let mut f = sess.file.lock().await;
            let mut st = sess.state.lock().await;
            if st.assembling || covered_range(&st.ranges, offset, end) {
                sess.last_seen_ms.store(now_ms(), Ordering::Relaxed);
                return Ok(false); // 幂等：已覆盖区间跳过写盘
            }
            f.seek(SeekFrom::Start(offset)).await?;
            f.write_all(payload).await?;
            let added = merge_range(&mut st.ranges, offset, end)?;
            st.covered += added;
            if let Some(r) = &sess.report {
                r.add(payload.len() as u64);
            }
            if st.covered >= total {
                st.assembling = true;
                completed = true;
            }
        }
        sess.last_seen_ms.store(now_ms(), Ordering::Relaxed);
        Ok(completed)
    }

    /// 组装：现算整文件 SHA-256 → 原子发布。**成功后会话保留为已完成态**
    /// （state.assembling 恒真）：迟到的 0x0C 判 0x01、0x0B 回满覆盖、重复块幂等
    /// 跳过——重试收敛于成功而非二次发布。失败路径移除会话（0x0C 随后回
    /// 0x00，客户端整组重来——无假成功窗口）。
    pub(crate) async fn finish(&self, gid: [u8; 16], opts: &RecvOptions) -> Result<()> {
        let (part, name, report) = {
            let map = self.sessions.lock().await;
            let Some(s) = map.get(&gid) else {
                return Err(proto("分块会话不存在（组装）"));
            };
            (s.part.clone(), s.name.clone(), s.report.clone())
        };
        if let Err(e) = self.assemble(&part, &name, opts).await {
            let mut map = self.sessions.lock().await;
            map.remove(&gid);
            let _ = std::fs::remove_file(&part);
            if let Some(r) = &report {
                r.fail();
            }
            return Err(proto(format!("分块组装失败: {e}")));
        }
        if let Some(r) = &report {
            r.finish();
        }
        Ok(())
    }

    async fn assemble(&self, part: &Path, name: &str, opts: &RecvOptions) -> Result<()> {
        let p = part.to_path_buf();
        let hash = tokio::task::spawn_blocking(move || sha256_file(&p))
            .await
            .map_err(|e| proto(e.to_string()))??;
        // 发布目录 = 会话半成品所在目录（PerDeviceFolder/AutoArchive 下即
        // 解析后的设备/日期目录）——目录在会话建立时固定，与续传语义一致。
        let dir = part.parent().map(Path::to_path_buf).unwrap_or_else(|| opts.save_dir.clone());
        let final_dest = publish_part(part, &dir, name).await?;
        let size = tokio::fs::metadata(&final_dest).await.map(|m| m.len()).unwrap_or(0);
        // 免费填充：组装后现算的哈希即完整摘要（规格 §3.1 缓存免费填充路径）。
        resume::fill_cache_at(opts, &final_dest, size, hash).await;
        eprintln!("[接收] 分块组装 {name} → {}", final_dest.display());
        Ok(())
    }

    /// 0x0B：合并区间（None = 会话不存在）。
    pub(crate) async fn ranges_of(&self, gid: [u8; 16]) -> Option<Vec<(u64, u64)>> {
        let map = self.sessions.lock().await;
        let s = map.get(&gid)?;
        let st = s.state.lock().await;
        Some(st.ranges.clone())
    }

    /// 0x0C 判决：0x01 组装完成 / 0x02 会话在但未覆盖 / 0x00 会话不存在。
    pub(crate) async fn end_status(&self, gid: [u8; 16]) -> u8 {
        let map = self.sessions.lock().await;
        match map.get(&gid) {
            None => STATUS_REJECT,
            Some(s) => {
                if s.state.lock().await.assembling {
                    STATUS_OK
                } else {
                    STATUS_INCOMPLETE
                }
            }
        }
    }
}

// ============ 服务端帧处理 ============

/// 0x02 块帧：16B groupId + u64 offset + u64 totalSize + str16 name + u32 len + payload。
pub(crate) async fn recv_chunk_frame<S>(s: &mut S, peer: SocketAddr, opts: &RecvOptions) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let gid: [u8; 16] = read_n(s, 16).await?.try_into().expect("16 字节 groupId");
    let offset = read_u64(s).await?;
    let total = read_u64(s).await?;
    let name = sanitize_name(&read_str_u16(s).await?)?;
    let plen = read_u32(s).await?;
    if total == 0 || total > MAX_TRANSFER_SIZE {
        return Err(proto(format!("0x02 声明大小非法: {total}")));
    }
    if plen as usize > MAX_CHUNK_PAYLOAD as usize {
        return Err(proto(format!("块载荷 {plen} 超过 8MB 上限")));
    }
    if offset > total || offset + plen as u64 > total {
        return Err(proto(format!("块区间 [{offset},{}) 越界（total={total}）", offset + plen as u64)));
    }
    let payload = read_n_long(s, plen as usize).await?;
    // 与其余接收路径同纪律：保存目录先建（ensure 的 create_new 依赖它存在）；
    // 目录按对端解析（PerDeviceFolder/AutoArchive），会话建立时固定。
    let dir = crate::transfer::receiver::resolve_save_dir(opts, peer.ip());
    tokio::fs::create_dir_all(&dir).await?;
    let started = std::time::Instant::now();
    let completed = opts
        .chunk_sessions
        .receive(gid, &name, total, offset, &payload, &dir)
        .await?;
    if completed {
        opts.chunk_sessions.finish(gid, opts).await?;
        // 组装发布即成功记账（0x02 无独立应答帧；重试收敛于成功不重复入账——
        // 组装后会话保留完成态，重复块/迟到 0x0C 不再触发 finish）。
        crate::transfer::receiver::record_recv(opts, peer, total, 1, started, "0x02 分块", &name);
    }
    Ok(())
}

/// 0x0C 收尾：回判决字节（会话不存在 → 0x00 + 连接失败）。
pub(crate) async fn recv_chunk_end<S>(s: &mut S, opts: &RecvOptions) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let gid: [u8; 16] = read_n(s, 16).await?.try_into().expect("16 字节 groupId");
    let st = opts.chunk_sessions.end_status(gid).await;
    write_u8(s, st).await?;
    if st == STATUS_REJECT {
        return Err(proto("分块会话不存在（收尾）"));
    }
    Ok(())
}

/// 0x0B 覆盖率查询：直答合并区间（内存 tracker，规格 §3.1）。
pub(crate) async fn recv_coverage_query<S>(s: &mut S, opts: &RecvOptions) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let gid: [u8; 16] = read_n(s, 16).await?.try_into().expect("16 字节 groupId");
    match opts.chunk_sessions.ranges_of(gid).await {
        Some(ranges) => {
            write_u8(s, STATUS_OK).await?;
            write_u32(s, ranges.len() as u32).await?;
            // 线上语义 = (offset, len)；tracker 内部是 (start, end)。
            for (start, end) in ranges {
                write_u64(s, start).await?;
                write_u64(s, end - start).await?;
            }
        }
        None => write_u8(s, STATUS_REJECT).await?,
    }
    Ok(())
}

// ============ 客户端 ============

/// 把 `[0,size)` 均分为 n 段连续区间（非空段）。
pub(crate) fn split_ranges(size: u64, n: usize) -> Vec<(u64, u64)> {
    let base = size / n as u64;
    let rem = size % n as u64;
    let mut out = Vec::new();
    let mut pos = 0u64;
    for i in 0..n as u64 {
        let len = base + if i < rem { 1 } else { 0 };
        if len > 0 {
            out.push((pos, pos + len));
        }
        pos += len;
    }
    out
}

/// 合并区间表的补集（在 `[0,size)` 内）。
pub(crate) fn complement_of(ranges: &[(u64, u64)], size: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut pos = 0u64;
    for &(rs, re) in ranges {
        if rs > pos {
            out.push((pos, rs.min(size)));
        }
        pos = pos.max(re);
        if pos >= size {
            break;
        }
    }
    if pos < size {
        out.push((pos, size));
    }
    out
}

/// 单连接发送一组连续区间的全部块 + 收尾判决字节。
async fn send_chunks_conn(
    mut s: BoxStream,
    gid: [u8; 16],
    name: &str,
    size: u64,
    ranges: &[(u64, u64)],
    path: &Path,
    speed_limit_bps: u64,
    report: Option<&crate::progress::Reporter>,
) -> Result<u8> {
    let mut f = tokio::fs::File::open(path).await?;
    let mut lim = TokenBucket::new(speed_limit_bps);
    let mut buf = vec![0u8; CHUNK];
    for &(start, end) in ranges {
        f.seek(SeekFrom::Start(start)).await?;
        let mut pos = start;
        while pos < end {
            let want = (CHUNK as u64).min(end - pos) as usize;
            f.read_exact(&mut buf[..want]).await?;
            // 所有分块（含最后一块）都必须过限速（规格 §3.1）。
            lim.acquire(want as u64).await;
            write_u8(&mut s, T_CHUNKED).await?;
            write_all(&mut s, &gid).await?;
            write_u64(&mut s, pos).await?;
            write_u64(&mut s, size).await?;
            write_str_u16(&mut s, name).await?;
            write_u32(&mut s, want as u32).await?;
            write_all(&mut s, &buf[..want]).await?;
            if let Some(r) = report {
                r.add(want as u64);
            }
            pos += want as u64;
        }
    }
    write_u8(&mut s, T_CHUNK_END).await?;
    write_all(&mut s, &gid).await?;
    let st = read_u8(&mut s).await?;
    let _ = s.shutdown().await;
    Ok(st)
}

/// 并行分块发送（规格 §3.1：1–8 路；完成判据 = 服务端覆盖 + 组装完成）。
/// 判决纪律：任一连接 0x00 → 整组失败；至少一个 0x01 → 成功；
/// 全 0x02（或个别连接网络失败）→ 0x0B 查补集补发，≤3 轮。
pub async fn send_file_chunked(
    addr: SocketAddr,
    path: &Path,
    opts: &SendOptions,
    connections: u8,
) -> Result<()> {
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
    if size == 0 {
        return Err(config_err("0x02 不支持空文件（应回退 0x00）"));
    }
    if size > MAX_TRANSFER_SIZE {
        return Err(config_err("文件超过 1 PiB 声明上限"));
    }
    // groupId 每次调用全新生成：源文件已变化必须换新 groupId 全量重发（规格 §3.1）。
    let mut gid = [0u8; 16];
    OsRng.fill_bytes(&mut gid);
    if let Some(r) = &opts.progress {
        r.set_total(size);
    }

    // 能力探询先行：旧对端短路（不发大清单）。
    let plan = StackPlan { probe_caps: true, compress: opts.compress };
    let (s0, caps) = connect_stack(addr, opts, plan).await?;
    if caps & crate::protocol::frame::CAP_CHUNKED == 0 {
        return Err(Error::Unsupported("对端不支持 0x02 分块".into()));
    }
    let ranges = split_ranges(size, connections.clamp(1, 8) as usize);
    let started = std::time::Instant::now();
    let opts2 = opts.clone();
    let path2 = path.to_path_buf();
    let name2 = name.clone();
    // JoinSet（轮 3 P1-3）：父任务被取消（GUI abort）时 drop 即 abort 全部子连接——
    // 此前 tokio::spawn 的游离句柄在取消后继续把文件传完（取消语义失效）。
    let mut set = tokio::task::JoinSet::new();
    let mut first_conn = Some(s0); // 探询连接复用为首个发送连接
    for r in ranges.iter() {
        let s_conn = match first_conn.take() {
            Some(s) => s,
            None => connect_stack(addr, &opts2, plan).await?.0,
        };
        let (gid2, name3, path3, opts3) = (gid, name2.clone(), path2.clone(), opts2.clone());
        let range = *r;
        set.spawn(async move {
            let rep = opts3.progress.clone();
            send_chunks_conn(s_conn, gid2, &name3, size, &[range], &path3, opts3.speed_limit_bps, rep.as_ref())
                .await
        });
    }
    let mut saw_complete = false;
    let mut fatal = false;
    while let Some(joined) = set.join_next().await {
        match joined.map_err(|e| proto(e.to_string()))? {
            Ok(STATUS_OK) => saw_complete = true,
            Ok(STATUS_INCOMPLETE) => {}
            Ok(_) => fatal = true, // 会话丢失 → 整组失败
            Err(_) => {}           // 网络失败 → 留给补发轮从服务端权威状态恢复
        }
    }
    if fatal {
        if let Some(r) = &opts.progress {
            r.fail();
        }
        return Err(Error::Rejected("分块会话丢失（对端逐出/重启），需整组重发".into()));
    }
    if !saw_complete {
        for _ in 0..3 {
            if send_complement(addr, &opts2, gid, &name, size, &path2).await? {
                if let Some(r) = &opts.progress {
                    r.finish();
                }
                crate::transfer::sender::record_stats(opts, addr, size, 1, started, &format!("0x02 分块（补发）"), &name);
                return Ok(());
            }
        }
        if let Some(r) = &opts.progress {
            r.fail();
        }
        return Err(Error::Rejected("分块补发 3 轮仍未覆盖完整文件".into()));
    }
    if let Some(r) = &opts.progress {
        r.finish();
    }
    crate::transfer::sender::record_stats(opts, addr, size, 1, started, &format!("0x02 分块×{connections}"), &name);
    Ok(())
}

/// 一轮补发：0x0B 查服务端权威覆盖 → 补集单连接补发 → 0x0C 判决。
/// 返回是否已组装完成（false = 仍未覆盖，调用方继续下一轮）。
async fn send_complement(
    addr: SocketAddr,
    opts: &SendOptions,
    gid: [u8; 16],
    name: &str,
    size: u64,
    path: &Path,
) -> Result<bool> {
    let (mut s, _) = connect_stack(addr, opts, StackPlan { probe_caps: false, compress: opts.compress }).await?;
    write_u8(&mut s, T_COVERAGE_QUERY).await?;
    write_all(&mut s, &gid).await?;
    let st = read_u8(&mut s).await?;
    let complement = if st == STATUS_OK {
        let n = read_u32(&mut s).await? as usize;
        // 服务端合并区间 ≤ MAX_MERGED_RANGES（轮 4 P1：恶意接收端一帧
        // 触发 with_capacity(n×16B) ≈ 64GB 分配崩溃）。
        if n > MAX_MERGED_RANGES {
            return Err(proto("0x0B 应答区间数超上限"));
        }
        let mut ranges = Vec::with_capacity(n);
        for _ in 0..n {
            let off = read_u64(&mut s).await?;
            let len = read_u64(&mut s).await?;
            if len == 0 || len > size.saturating_sub(off) {
                return Err(proto("0x0B 应答区间非法"));
            }
            ranges.push((off, off + len));
        }
        complement_of(&ranges, size)
    } else {
        vec![(0, size)] // 旧对端回退：全量重发（规格 §3.1）
    };
    let done = send_chunks_conn(
        s,
        gid,
        name,
        size,
        &complement,
        path,
        opts.speed_limit_bps,
        opts.progress.as_ref(),
    )
    .await?;
    Ok(done == STATUS_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_complement() {
        // 切分：连续、不重叠、并集 = [0,size)、段数 ≤ n（具体分点随除法实现）。
        for &(size, n) in &[(10u64, 3usize), (7, 8), (1 << 20, 4), (0, 4)] {
            let rs = split_ranges(size, n);
            assert!(rs.len() <= n);
            let mut pos = 0u64;
            for (a, b) in &rs {
                assert_eq!(*a, pos, "段必须连续不重叠");
                assert!(b > a);
                pos = *b;
            }
            assert_eq!(pos, size, "并集必须覆盖 [0,size)");
        }
        // 补集：中间缺一块
        let got = complement_of(&[(0, 100), (200, 300)], 300);
        assert_eq!(got, vec![(100, 200)]);
        assert!(complement_of(&[], 50).len() == 1);
        assert!(complement_of(&[(0, 50)], 50).is_empty());
    }

    #[test]
    fn merge_and_coverage() {
        let mut r = Vec::new();
        assert_eq!(merge_range(&mut r, 0, 100).unwrap(), 100);
        assert_eq!(merge_range(&mut r, 50, 150).unwrap(), 50);
        assert_eq!(r, vec![(0, 150)]);
        assert_eq!(merge_range(&mut r, 200, 300).unwrap(), 100);
        assert_eq!(r, vec![(0, 150), (200, 300)]);
        assert_eq!(merge_range(&mut r, 150, 200).unwrap(), 50, "填补缺口 = 新增 50");
        assert_eq!(r, vec![(0, 300)]);
        assert!(covered_range(&r, 0, 300));
        assert!(covered_range(&r, 10, 290));
        assert!(!covered_range(&r, 0, 301));
        // 部分覆盖不算覆盖（规格 §1.4 判错方向不对称）。
        assert!(!covered_range(&[(0, 50), (60, 100)], 0, 100));
    }
}
