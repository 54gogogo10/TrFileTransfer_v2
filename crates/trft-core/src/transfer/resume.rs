//! 断点续传 0x03（单文件）/ 0x04（文件夹续传/同步）与稳定会话 ID
//! （WIRE-PROTOCOL.md §3.6–3.7；规格 §3.1）。
//!
//! 服务端状态模型：**磁盘文件即状态**。
//! - 0x03：半成品 `<name>.<ip-fnv>.trft-resume` + 侧车 `.meta`（size+claimed hash）。
//!   meta 失配 = 陈旧前缀 → 删除从 0 重来（绝不拼接旧版本内容）；
//!   服务端偏移权威（max(声明, 实际)）；收完整文件重读比对，不一致真删除。
//! - 0x04：清单流式过一遍（不物化），逐项由服务端摘要缓存/现算核对，
//!   位图应答跳过项；同步语义 = 同一根目录、差异文件校验后 rename 覆盖、
//!   本地已删除文件服务端保留（增量备份）。

use crate::error::{Error, Result, config_err, proto};
use crate::hash::{FileDigester, sha256_file};
use crate::hashcache::HashCache;
use crate::limiter::TokenBucket;
use crate::protocol::frame::{
    MAX_MANIFEST_FILES, MAX_TRANSFER_SIZE, R_MANIFEST, R_RESUME_NEGO, STATUS_OK, STATUS_REJECT,
    T_RESUME_FILE, T_RESUME_FOLDER, sanitize_name, sanitize_rel,
};
use crate::protocol::io::{
    read_exact_long, read_n, read_str_u16, read_u32, read_u64, read_u8, read_u8_long, write_all,
    write_str_u16, write_u32, write_u64, write_u8,
};
use tokio::io::{AsyncRead, AsyncWrite};
use crate::transfer::folder::collect_files;
use crate::transfer::receiver::{
    PartGuard, RecvOptions, publish_part, record_recv, space_ok, unique_part,
};
use crate::transfer::sender::{SendOptions, StackPlan, connect_stack};
use crate::transfer::CHUNK;
use std::io::SeekFrom;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// 0x10 status：命中同内容文件，零传输（DuplicateFiles=skip，规格 §3.1）。
pub const NEGO_SKIP: u8 = 0x02;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// 稳定会话 ID：由 (源路径, 目标地址) 确定性派生（大小写/尾分隔符不敏感）——
/// CLI `sync` 与 GUI 同步可互相接力（规格 §3.1）。
pub fn stable_session_id(src: &Path, target: &str) -> u64 {
    let norm = src
        .to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    let mut m = Vec::new();
    m.extend_from_slice(norm.as_bytes());
    m.push(b'|');
    m.extend_from_slice(target.trim_end_matches('/').to_ascii_lowercase().as_bytes());
    u64::from_le_bytes(crate::hash::sha256(&m)[..8].try_into().expect("8 字节"))
}

// ============ 服务端共享助手 ============

/// 0x03 半成品路径：确定性派生自 (文件名, 对端 IP)——重启可恢复、跨 IP 天然隔离。
pub(crate) fn resume_part_path(save_dir: &Path, name: &str, ip: &IpAddr) -> PathBuf {
    save_dir.join(format!("{name}.{:016x}.trft-resume", fnv1a(ip.to_string().as_bytes())))
}

/// `.meta` 侧车：`fnv|size|hash_hex`（FNV-1a 行校验，坏行视为无 meta——判错方向是多传）。
fn write_meta(meta_path: &Path, size: u64, hash: &[u8; 32]) -> Result<()> {
    let body = format!("{size}|{}", crate::hash::hex(hash));
    let line = format!("{:016x}|{body}", fnv1a(body.as_bytes()));
    crate::config::atomic_write(meta_path, line.as_bytes())
}

fn read_meta(meta_path: &Path) -> Option<(u64, [u8; 32])> {
    let text = std::fs::read_to_string(meta_path).ok()?;
    let (sum_hex, rest) = text.trim_end().split_once('|')?;
    if u64::from_str_radix(sum_hex, 16).ok()? != fnv1a(rest.as_bytes()) {
        return None;
    }
    let (size_s, hash_hex) = rest.split_once('|')?;
    let size = size_s.parse().ok()?;
    if hash_hex.len() != 64 || !hash_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut h = [0u8; 32];
    for i in 0..32 {
        h[i] = u8::from_str_radix(&hash_hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some((size, h))
}

fn remove_resume_files(part: &Path) {
    let _ = std::fs::remove_file(part);
    let mut meta = part.as_os_str().to_os_string();
    meta.push(".meta");
    let _ = std::fs::remove_file(PathBuf::from(meta));
}

/// 规格 §6.1：服务器续传孤儿清理（7 天未返回）。
/// PerDeviceFolder/AutoArchive 落地在子目录——递归扫描（深度封顶防环）。
pub fn cleanup_resume_orphans(dir: &Path) {
    fn walk(dir: &Path, depth: u32) {
        if depth > 6 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let now = std::time::SystemTime::now();
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, depth + 1);
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if !(name.ends_with(".trft-resume") || name.ends_with(".trft-resume.meta")) {
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

/// 每会话锁（对端 IP + 文件名 → 锁）：防跨连接并发写坏同一半成品（规格 §3.1）。
pub(crate) async fn session_lock(
    opts: &RecvOptions,
    ip: &IpAddr,
    name: &str,
) -> Arc<tokio::sync::Mutex<()>> {
    let mut map = opts.resume_locks.lock().await;
    if map.len() > 1024 {
        // 容量防线：锁对象本身无泄漏风险（Arc 随会话消亡），只防洪水中无界增长。
        map.retain(|_, v| Arc::strong_count(v) > 1);
    }
    map.entry((*ip, name.to_string())).or_default().clone()
}

/// 目标文件哈希：先查摘要缓存（免费），未命中现算（判错方向不对称：宁可多算）。
/// 现算结果回填缓存（免费填充——刚算出的摘要就是事实，重试/下次同步收敛，
/// 否则大库冷缓存下每次同步都对同一批文件整文件重算，轮 1 F4）。
pub(crate) async fn dest_hash(
    opts: &RecvOptions,
    rel: &str,
    size: u64,
    mtime: u64,
    dest: &Path,
) -> Option<[u8; 32]> {
    if let Some(cache) = &opts.hash_cache {
        if let Some(h) = cache.lock().await.get(rel, size, mtime) {
            return Some(h);
        }
    }
    let d = dest.to_path_buf();
    let computed = tokio::task::spawn_blocking(move || sha256_file(&d).ok())
        .await
        .ok()
        .flatten();
    if let (Some(h), Some(cache)) = (&computed, &opts.hash_cache) {
        cache.lock().await.insert(rel, size, mtime, *h);
    }
    computed
}

fn mtime_of(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// dest 相对 save_dir 的摘要缓存键（与 `verify` CLI 的扫描键同口径；
/// PerDeviceFolder/AutoArchive 子目录自然进入键前缀）。
pub(crate) fn cache_key(opts: &RecvOptions, dest: &Path) -> String {
    dest.strip_prefix(&opts.save_dir)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| dest.to_string_lossy().to_string())
}

/// 收货后免费填充摘要缓存（规格 §3.1：行内哈希即完整摘要）。
pub(crate) async fn fill_cache_at(opts: &RecvOptions, dest: &Path, size: u64, hash: [u8; 32]) {
    let Some(cache) = &opts.hash_cache else { return };
    let rel = cache_key(opts, dest);
    let mtime = tokio::fs::metadata(dest)
        .await
        .map(|m| mtime_of(&m))
        .unwrap_or(0);
    cache.lock().await.insert(&rel, size, mtime, hash);
}

/// 0x04 同步语义发布：校验后 rename 覆盖（内容不同 = 更新；规格 §3.1 增量备份）。
async fn publish_replace(part: &Path, dest: &Path) -> Result<()> {
    tokio::fs::rename(part, dest).await?;
    Ok(())
}

// ============ 0x03 服务端 ============

/// 0x03 协商应答 0x10：status + serverOffset。
async fn reply_nego<S>(s: &mut S, status: u8, offset: u64) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_u8(s, R_RESUME_NEGO).await?;
    write_u8(s, status).await?;
    write_u64(s, offset).await?;
    Ok(())
}

/// 0x03 单文件续传接收。协商（0x10）在本函数内；最终判决由帧循环补 1B 状态。
pub(crate) async fn recv_resume_file<S>(s: &mut S, peer: SocketAddr, opts: &RecvOptions) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = sanitize_name(&read_str_u16(s).await?)?;
    let size = read_u64(s).await?;
    let declared = read_u64(s).await?;
    let _verify_flag = read_u8(s).await?;
    let claimed: [u8; 32] = read_n(s, 32).await?.try_into().expect("32 字节哈希");
    if size == 0 || size > MAX_TRANSFER_SIZE {
        reply_nego(s, STATUS_REJECT, 0).await?;
        return Err(proto(format!("续传声明非法（大小 {size}）")));
    }
    let started = std::time::Instant::now();
    if declared > size {
        reply_nego(s, STATUS_REJECT, 0).await?;
        return Err(proto(format!("续传偏移 {declared} 超出文件大小 {size}")));
    }

    // 进度：注册后任何失败路径经 Outcome 上报 failed；skip 是零传输成功。
    let report = opts.progress.as_ref().map(|h| h.register("recv", name.clone(), size));
    let outcome = crate::progress::Outcome::new(report.clone());

    // 目录解析在会话建立时固定（PerDeviceFolder/AutoArchive，规格 §3.3）；
    // 会话半成品路径派生自解析后的目录——确定性保证跨连接可续传。
    let dir = crate::transfer::receiver::resolve_save_dir(opts, peer.ip());
    let dest = dir.join(&name);
    let dest_key = cache_key(opts, &dest);
    if opts.duplicate == crate::config::DuplicatePolicy::Skip && !opts.strict_verify {
        if let Ok(meta) = tokio::fs::metadata(&dest).await {
            if meta.len() == size {
                let have = dest_hash(opts, &dest_key, size, mtime_of(&meta), &dest).await;
                if have == Some(claimed) {
                    reply_nego(s, NEGO_SKIP, 0).await?;
                    fill_cache_at(opts, &dest, size, claimed).await;
                    outcome.finish();
                    record_recv(opts, peer, 0, 1, started, "已存在（跳过）", &name);
                    return Ok(());
                }
            }
        }
    }

    // 会话绑定（对端 IP + 文件名）+ per-session 锁。
    let lock = session_lock(opts, &peer.ip(), &name).await;
    let _g = lock.lock().await;

    tokio::fs::create_dir_all(&dir).await?;
    let part = resume_part_path(&dir, &name, &peer.ip());
    let mut meta_path = part.as_os_str().to_os_string();
    meta_path.push(".meta");

    // 陈旧前缀保护：半成品 + meta 必须同属本会话（size + claimed hash 双绑定）。
    let mut offset: u64 = 0;
    let mut have_part = false;
    if let (Ok(pm), Some((msize, mhash))) = (
        std::fs::metadata(&part),
        read_meta(Path::new(&meta_path)),
    ) {
        if msize == size && mhash == claimed && pm.len() <= size {
            have_part = true;
            // 偏移权威 = 服务端磁盘事实（轮 4 P0：规格原文「max(声明, 实际)」信任了
            // 客户端 declared——1MiB 声明即可绕过磁盘预检把洞写满整盘，已实测复现）。
            // 客户端声明仅作咨询：声明小于实际 → 从实际续（客户端快进）；
            // 声明大于实际 → 同样从实际续（判错方向 = 多传一次，规格 §1.4）。
            offset = pm.len() as u64;
        }
    }
    if have_part && offset > size {
        remove_resume_files(&part);
        have_part = false;
        offset = 0;
    }
    if !have_part {
        remove_resume_files(&part);
        tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)
            .await
            .map_err(|e| proto(format!("创建续传临时文件失败: {e}")))?;
        write_meta(Path::new(&meta_path), size, &claimed)?;
        offset = 0;
    }
    let _ = declared; // 偏移权威修复后客户端声明不参与服务端决策（仅协议兼容保留字段）

    // 磁盘预检（剩余量 + 64MB 余量，规格 §3.1）。
    if !space_ok(&dir, size - offset) {
        reply_nego(s, STATUS_REJECT, 0).await?;
        return Err(Error::Rejected(format!(
            "{name}: 磁盘可用空间不足（需要 ≥ {} 字节 + 64MB 余量）",
            size - offset
        )));
    }

    // 服务端偏移权威（规格 §3.1）。
    reply_nego(s, STATUS_OK, offset).await?;

    // 追加流式接收（offset..size）。
    if offset < size {
        let mut f = tokio::fs::OpenOptions::new().write(true).open(&part).await?;
        f.seek(SeekFrom::Start(offset)).await?;
        let mut lim = TokenBucket::new(opts.recv_limit_bps);
        let mut remaining = size - offset;
        let mut buf = vec![0u8; CHUNK];
        while remaining > 0 {
            let want = CHUNK.min(remaining.min(usize::MAX as u64) as usize);
            read_exact_long(s, &mut buf[..want]).await?;
            lim.acquire(want as u64).await;
            f.write_all(&buf[..want]).await?;
            if let Some(r) = &report {
                r.add(want as u64);
            }
            remaining -= want as u64;
        }
    }
    // 载荷后哈希（防源文件传输中变异：两侧各自独立比对）。
    let trailing: [u8; 32] = read_n(s, 32).await?.try_into().expect("32 字节哈希");

    // 整文件重读比对（Rust v2 对 verifyFlag=0/1 均执行——完整性优先）。
    let p = part.clone();
    let actual = tokio::task::spawn_blocking(move || sha256_file(&p))
        .await
        .map_err(|e| proto(e.to_string()))??;
    if actual != claimed || actual != trailing {
        // 规格 §3.1：不一致删除文件；失配自愈由客户端作废缓存摘要后重试。
        remove_resume_files(&part);
        return Err(proto("续传校验失败（SHA-256 不一致），未完成的文件已删除"));
    }
    // 收尾硬校验（轮 4 P0 纵深）：半成品长度必须 == 声明 size——
    // 短文件（如声明巨大只收到零星字节却哈希命中空内容）不得发布。
    {
        let plen = tokio::fs::metadata(&part).await.map(|m| m.len()).unwrap_or(0);
        if plen != size {
            remove_resume_files(&part);
            return Err(proto(format!(
                "续传文件长度 {plen} 与声明 {size} 不一致，已拒绝"
            )));
        }
    }

    // 发布到真实最终路径（冲突时可能是 name_1）——缓存键必须跟最终路径，
    // 否则旧文件位置写入新哈希 = 缓存投毒（0x04 同步/0x03 skip 会静默错误跳过）。
    let final_dest = publish_part(&part, &dir, &name).await?;
    remove_resume_files(&part);
    fill_cache_at(opts, &final_dest, size, claimed).await;
    eprintln!("[接收] 续传 {name}（自 {offset}）→ {}", dest.display());
    outcome.finish();
    record_recv(opts, peer, size - offset, 1, started, "续传传输", &name);
    Ok(())
}

// ============ 0x04 服务端 ============

/// 0x04 文件夹续传/同步接收。位图协商（0x11）在本函数内；最终判决由帧循环补 1B。
pub(crate) async fn recv_resume_folder<S>(s: &mut S, peer: SocketAddr, opts: &RecvOptions) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _session_id = read_u64(s).await?;
    let root_name = sanitize_name(&read_str_u16(s).await?)?;
    let count = read_u32(s).await? as usize;
    if count > MAX_MANIFEST_FILES {
        return Err(proto(format!("清单文件数 {count} 超过上限 {MAX_MANIFEST_FILES}")));
    }
    // 同步语义：根目录固定（跨次同步同一目录），不追加冲突名；
    // 根相对的解析目录在会话建立时固定（PerDeviceFolder/AutoArchive，规格 §3.3）。
    let started = std::time::Instant::now();
    let resolved = crate::transfer::receiver::resolve_save_dir(opts, peer.ip());
    tokio::fs::create_dir_all(&resolved).await?;
    let base = resolved.join(&root_name);
    tokio::fs::create_dir_all(&base).await?;

    // 流式过清单：逐项核对跳过位（位图内存有界：≤ 100,000/8 = 12.5KB）。
    let mut bitmap = vec![0u8; count.div_ceil(8)];
    let mut to_receive: u32 = 0;
    for i in 0..count {
        let rel_raw = read_str_u16(s).await?;
        let rel_path = sanitize_rel(&rel_raw)?;
        let size = read_u64(s).await?;
        if size > MAX_TRANSFER_SIZE {
            return Err(proto(format!("{rel_raw}: 声明大小超过 1 PiB 上限")));
        }
        let has_hash = read_u8(s).await?;
        let claimed = if has_hash == 1 {
            Some(read_n(s, 32).await?)
        } else {
            None
        };
        // strict（SyncVerifyContent）：有哈希也按无记录处理 → 必发（规格 §3.3）。
        let skip = match claimed {
            Some(h) if !opts.strict_verify => {
                let dest = base.join(&rel_path);
                match tokio::fs::metadata(&dest).await {
                    Ok(meta) if meta.len() == size => {
                        // 缓存键与 fill_cache_at 同口径（dest 相对 save_dir，
                        // 含 PerDevice/AutoArchive 前缀）——判跳过与写缓存一致。
                        let rel_key = cache_key(opts, &dest);
                        dest_hash(opts, &rel_key, size, mtime_of(&meta), &dest).await == Some(h.try_into().expect("32 字节"))
                    }
                    _ => false,
                }
            }
            _ => false,
        };
        if skip {
            bitmap[i / 8] |= 1 << (i % 8);
        } else {
            to_receive += 1;
        }
    }
    write_u8(s, R_MANIFEST).await?;
    write_all(s, &bitmap).await?;

    // 逐个接收未跳过文件；差异文件校验后覆盖（同步更新语义）。
    let mut recv_bytes = 0u64;
    for _ in 0..to_receive {
        let rel_raw = read_str_u16(s).await?;
        let rel_path = sanitize_rel(&rel_raw)?;
        let size = read_u64(s).await?;
        if size > MAX_TRANSFER_SIZE {
            return Err(proto(format!("{rel_raw}: 声明大小超过 1 PiB 上限")));
        }
        let dest = base.join(&rel_path);
        let parent = dest
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        tokio::fs::create_dir_all(&parent).await?;
        if !space_ok(&parent, size) {
            return Err(Error::Rejected(format!(
                "{rel_raw}: 磁盘可用空间不足（需要 ≥ {size} 字节 + 64MB 余量）"
            )));
        }
        let file_name = dest
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| proto(format!("{rel_raw}: 非法文件名")))?
            .to_string();
        let report = opts
            .progress
            .as_ref()
            .map(|h| h.register("recv", rel_raw.clone(), size));
        let outcome = crate::progress::Outcome::new(report.clone());
        let (part, hash) =
            recv_file_payload(s, &parent, &file_name, size, opts, report.as_ref()).await?;
        let _guard = PartGuard(part.clone());
        // 同步语义：内容不同 → 校验后 rename 覆盖（增量备份更新）。
        publish_replace(&part, &dest).await?;
        fill_cache_at(opts, &dest, size, hash).await;
        outcome.finish();
        recv_bytes += size;
    }
    record_recv(opts, peer, recv_bytes, to_receive as u32, started, "文件夹同步", &root_name);
    eprintln!("[接收] 文件夹同步 {root_name}（{to_receive}/{count} 个文件）→ {}", base.display());
    Ok(())
}

/// 接收一个文件的载荷（半成品 + 流式 + 声明哈希比对）。
/// 返回半成品路径与实际哈希；守卫职责移交调用方（发布成功后路径自然消失，
/// 失败路径由调用方的 `PartGuard` 兜底清理——判错方向不留半成品）。
pub(crate) async fn recv_file_payload<S>(
    s: &mut S,
    parent: &Path,
    file_name: &str,
    size: u64,
    opts: &RecvOptions,
    report: Option<&crate::progress::Reporter>,
) -> Result<(PathBuf, [u8; 32])>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let part = unique_part(parent, file_name);
    let guard = PartGuard(part.clone());
    let mut out = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&part)
        .await?;
    let mut dig = FileDigester::new();
    let mut lim = TokenBucket::new(opts.recv_limit_bps);
    let mut remaining = size;
    let mut buf = vec![0u8; CHUNK];
    while remaining > 0 {
        let want = CHUNK.min(remaining.min(usize::MAX as u64) as usize);
        read_exact_long(s, &mut buf[..want]).await?;
        lim.acquire(want as u64).await;
        dig.update(&buf[..want]);
        out.write_all(&buf[..want]).await?;
        if let Some(r) = report {
            r.add(want as u64);
        }
        remaining -= want as u64;
    }
    out.flush().await?;
    out.sync_all().await?;
    drop(out);
    let actual = dig.finalize();
    let claimed: [u8; 32] = read_n(s, 32).await?.try_into().expect("32 字节哈希");
    if actual != claimed {
        return Err(proto(format!("{file_name}: 校验不一致，未完成的文件已删除")));
    }
    std::mem::forget(guard); // 守卫职责移交调用方
    Ok((part, actual))
}

// ============ 0x03 客户端 ============

#[derive(Debug)]
pub(crate) enum ResumeNego {
    /// 从 serverOffset 续传。
    Proceed(u64),
    /// 命中同内容文件，零传输（整体成功）。
    Skip,
    /// 对端不支持 0x03（旧对端：裸 0x00 / 断连）。
    Unsupported,
    /// 对端明确拒绝（0x10 + 0x00）。
    Rejected(String),
}

/// 0x03 协商：读服务端 0x10 应答并判别（对端不支持 → 降级 0x00 路径）。
/// 首字节用长任务窗口——服务端 skip 判定可能先对既有目标整文件现算哈希
/// （冷缓存下静默数分钟，规格 §6.1；轮 1 F4）。
async fn read_nego<S>(s: &mut S, size: u64) -> Result<ResumeNego>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let first = read_u8_long(s).await;
    let first = match first {
        Ok(b) => b,
        Err(_) => return Ok(ResumeNego::Unsupported), // 旧对端拒绝后直接断开
    };
    match first {
        R_RESUME_NEGO => {
            let st = read_u8(s).await?;
            let off = read_u64(s).await?;
            match st {
                STATUS_OK => {
                    if off > size {
                        return Err(proto(format!("续传协商偏移 {off} 超出文件大小 {size}")));
                    }
                    Ok(ResumeNego::Proceed(off))
                }
                NEGO_SKIP => Ok(ResumeNego::Skip),
                _ => Ok(ResumeNego::Rejected("对端拒绝续传（偏移/大小/空间）".into())),
            }
        }
        STATUS_REJECT => Ok(ResumeNego::Unsupported),
        _ => Err(proto("续传协商失败（对端应答无法识别）")),
    }
}

/// 单次 0x03 尝试（含建连、协商、载荷、确认）。返回实际传输字节数（跳过命中 = 0）。
async fn send_resume_once(
    addr: SocketAddr,
    path: &Path,
    opts: &SendOptions,
    claimed: [u8; 32],
    size: u64,
) -> Result<u64> {
    let raw = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| config_err("路径没有合法 UTF-8 文件名"))?;
    let name = sanitize_name(raw)?;
    // 能力探询先行：旧对端短路（不发 0x03 头），同时为压缩协商开路。
    let (mut s, caps) = connect_stack(addr, opts, StackPlan { probe_caps: true, compress: opts.compress }).await?;
    if caps & crate::protocol::frame::CAP_RESUME_FILE == 0 {
        return Err(Error::Unsupported("对端不支持续传（请升级对端）".into()));
    }
    write_u8(&mut s, T_RESUME_FILE).await?;
    write_str_u16(&mut s, &name).await?;
    write_u64(&mut s, size).await?;
    write_u64(&mut s, 0).await?; // declaredOffset=0：服务端权威取 max
    write_u8(&mut s, 1).await?; // verifyFlag=1（完整校验）
    write_all(&mut s, &claimed).await?;
    if let Some(r) = &opts.progress {
        r.set_total(size);
    }

    match read_nego(&mut s, size).await? {
        ResumeNego::Skip => {
            let _ = s.shutdown().await;
            return Ok(0); // 零传输命中
        }
        ResumeNego::Unsupported => return Err(Error::Unsupported("对端不支持续传（请升级对端）".into())),
        ResumeNego::Rejected(m) => return Err(Error::Rejected(m)),
        ResumeNego::Proceed(offset) => {
            // 从服务端权威偏移起流式发送（完整哈希已在建连前算完——规格 §3.1）。
            let mut f = tokio::fs::File::open(path).await?;
            f.seek(SeekFrom::Start(offset)).await?;
            let mut lim = TokenBucket::new(opts.speed_limit_bps);
            let mut remaining = size - offset;
            let mut buf = vec![0u8; CHUNK];
            while remaining > 0 {
                let want = CHUNK.min(remaining.min(usize::MAX as u64) as usize);
                f.read_exact(&mut buf[..want]).await?;
                lim.acquire(want as u64).await;
                s.write_all(&buf[..want]).await?;
                if let Some(r) = &opts.progress {
                    r.add(want as u64);
                }
                remaining -= want as u64;
            }
            write_all(&mut s, &claimed).await?;
            let st = read_u8(&mut s).await?;
            let _ = s.shutdown().await;
            if st != STATUS_OK {
                return Err(Error::Rejected("接收端拒绝了本次传输".into()));
            }
            return Ok(size - offset);
        }
    }
}

/// 0x03 自动重试（规格 §3.2 AutoRetry）：首次即走 0x03，退避重试共 3 次尝试，
/// 跨尝试复用服务端会话续传；旧对端降级 0x00 全量；空文件走 0x00。
pub async fn send_file_auto(addr: SocketAddr, path: &Path, opts: &SendOptions) -> Result<()> {
    let meta = tokio::fs::metadata(path).await?;
    if !meta.is_file() {
        return Err(config_err("路径不是普通文件"));
    }
    let size = meta.len();
    if size == 0 {
        // 规格 §3.2：空文件回退 0x00（0x03 拒绝 0 字节）。发送侧照常记账（轮 1）。
        let started0 = std::time::Instant::now();
        let name0 = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let r = crate::transfer::sender::send_file(addr, path, opts).await;
        if r.is_ok() {
            crate::transfer::sender::record_stats(opts, addr, 0, 1, started0, "空文件", &name0);
        }
        return r;
    }
    if size > MAX_TRANSFER_SIZE {
        return Err(config_err("文件超过 1 PiB 声明上限"));
    }
    // 完整哈希必须在建连之前算完（规格 §3.1）。
    let p = path.to_path_buf();
    let claimed = tokio::task::spawn_blocking(move || sha256_file(&p))
        .await
        .map_err(|e| proto(e.to_string()))??;
    let started = std::time::Instant::now();
    for attempt in 0..3u32 {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
        }
        match send_resume_once(addr, path, opts, claimed, size).await {
            Ok(sent_bytes) => {
                if let Some(r) = &opts.progress {
                    r.finish();
                }
                let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                crate::transfer::sender::record_stats(opts, addr, sent_bytes, 1, started, "续传传输", &name);
                return Ok(());
            }
            Err(Error::Unsupported(_)) => {
                // 旧对端：降级 0x00 全量（不计入重试退避）。0x00 路径自带终态上报。
                let r = crate::transfer::sender::send_file(addr, path, opts).await;
                if r.is_ok() {
                    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    crate::transfer::sender::record_stats(opts, addr, size, 1, started, "续传不可用，改为直接发送", &name);
                }
                return r;
            }
            Err(e @ (Error::AuthRejected(_) | Error::Rejected(_))) => {
                if let Some(r) = &opts.progress {
                    r.fail();
                }
                return Err(e);
            }
            Err(e) if attempt == 2 => {
                if let Some(r) = &opts.progress {
                    r.fail();
                }
                return Err(e);
            }
            Err(_) => continue, // 瞬断：退避重试（服务端会话保留进度，不报终态）
        }
    }
    unreachable!("重试循环必在内部返回")
}

// ============ 0x04 客户端 ============

/// 0x04 文件夹续传/同步发送。
/// `client_cache`：发送端摘要缓存（命中项免费携带哈希 → 服务端可判跳过；
/// 未命中直接入必发集合——判错方向是多传一次）。传输中计算的哈希免费回填。
pub async fn send_folder_resume(
    addr: SocketAddr,
    root: &Path,
    opts: &SendOptions,
    session_id: u64,
    client_cache: Option<&Arc<tokio::sync::Mutex<HashCache>>>,
) -> Result<()> {
    if !root.is_dir() {
        return Err(config_err("路径不是目录"));
    }
    let raw = root
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| config_err("目录名不是合法 UTF-8"))?;
    let root_name = sanitize_name(raw)?;
    let files = collect_files(root)?;
    if files.len() > MAX_MANIFEST_FILES {
        // 轮 4 P3-6：客户端/服务端上限不一致（1,000,000 vs 100,000）——
        // 合法大目录整单被拒且无降级，预检给出可读错误。
        return Err(config_err(format!(
            "文件夹含 {} 个文件，超过同步清单上限 {MAX_MANIFEST_FILES}（可改用整夹发送）",
            files.len()
        )));
    }

    // 能力探询先行：0x04 清单可能很大，旧对端直接短路（规格 §1.4 降级路径）。
    let plan = StackPlan { probe_caps: true, compress: opts.compress };
    let (mut s, caps) = connect_stack(addr, opts, plan).await?;
    if caps & crate::protocol::frame::CAP_RESUME_FOLDER == 0 {
        return Err(Error::Unsupported("对端不支持文件夹同步（请升级对端）".into()));
    }

    // 清单：rel + size + (可选哈希)。哈希仅取自发送端缓存命中（免费）。
    write_u8(&mut s, T_RESUME_FOLDER).await?;
    write_u64(&mut s, session_id).await?;
    write_str_u16(&mut s, &root_name).await?;
    write_u32(&mut s, files.len() as u32).await?;
    let mut metas = Vec::with_capacity(files.len());
    for (rel, path) in &files {
        let meta = tokio::fs::metadata(path).await?;
        let size = meta.len();
        if size > MAX_TRANSFER_SIZE {
            return Err(proto(format!("{rel}: 单文件超过 1 PiB 上限")));
        }
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let known = match client_cache {
            Some(c) => c.lock().await.get(rel, size, mtime),
            None => None,
        };
        write_str_u16(&mut s, rel).await?;
        write_u64(&mut s, size).await?;
        match known {
            Some(h) => {
                write_u8(&mut s, 1).await?;
                write_all(&mut s, &h).await?;
            }
            None => write_u8(&mut s, 0).await?,
        }
        metas.push((rel.clone(), path.clone(), size, mtime));
    }

    // 位图应答。首字节用长任务窗口——服务端逐项核对可能整文件现算哈希
    // （冷缓存大库静默数分钟，规格 §6.1；轮 1 F4）。
    let first = read_u8_long(&mut s).await?;
    if first != R_MANIFEST {
        let _ = first;
        return Err(proto("同步清单应答异常（对端数据无法识别）"));
    }
    let bitmap = read_n(&mut s, files.len().div_ceil(8)).await?;

    // 进度总量 = 位图差量（只计服务端要求发送的文件）。
    if let Some(r) = &opts.progress {
        let total: u64 = metas
            .iter()
            .enumerate()
            .filter(|(i, _)| bitmap[i / 8] & (1 << (i % 8)) == 0)
            .map(|(_, (_, _, size, _))| size)
            .sum();
        r.set_total(total);
    }

    // 发送未跳过文件。
    let started = std::time::Instant::now();
    let mut lim = TokenBucket::new(opts.speed_limit_bps);
    let mut buf = vec![0u8; CHUNK];
    let mut sent = 0u32;
    let mut sent_bytes = 0u64;
    for (i, (rel, path, size, mtime)) in metas.iter().enumerate() {
        if bitmap[i / 8] & (1 << (i % 8)) != 0 {
            continue; // 服务端确认同内容：跳过
        }
        sent_bytes += *size;
        write_str_u16(&mut s, rel).await?;
        write_u64(&mut s, *size).await?;
        let mut f = tokio::fs::File::open(path).await?;
        let mut dig = FileDigester::new();
        loop {
            let n = f.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            lim.acquire(n as u64).await;
            dig.update(&buf[..n]);
            s.write_all(&buf[..n]).await?;
            if let Some(r) = &opts.progress {
                r.add(n as u64);
            }
        }
        let hash = dig.finalize();
        write_all(&mut s, &hash).await?;
        if let Some(c) = client_cache {
            c.lock().await.insert(rel, *size, *mtime, hash); // 免费回填
        }
        sent += 1;
    }

    // 带内完成判决（规格 §3.1：正文之后服务端失败不得报成功）。
    let st = read_u8(&mut s).await?;
    let _ = s.shutdown().await;
    if st != STATUS_OK {
        if let Some(r) = &opts.progress {
            r.fail();
        }
        return Err(Error::Rejected("接收端拒绝了文件夹同步".into()));
    }
    if let Some(r) = &opts.progress {
        r.finish();
    }
    crate::transfer::sender::record_stats(opts, addr, sent_bytes, sent, started, "文件夹同步", &root_name);
    eprintln!("[发送] 同步 {root_name}：发送 {sent}/{} 个文件", metas.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_session_id_is_insensitive_to_case_and_slash() {
        let a = stable_session_id(Path::new("D:/Work/Dir"), "192.168.1.5:8080");
        let b = stable_session_id(Path::new("d:\\work\\dir\\"), "192.168.1.5:8080");
        let c = stable_session_id(Path::new("D:/Work/Other"), "192.168.1.5:8080");
        assert_eq!(a, b, "大小写/尾斜杠不敏感");
        assert_ne!(a, c, "不同源路径必须不同会话");
    }

    #[test]
    fn meta_roundtrip_and_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.trft-resume.meta");
        write_meta(&p, 123, &[7u8; 32]).unwrap();
        assert_eq!(read_meta(&p), Some((123, [7u8; 32])));
        std::fs::write(&p, "0000000000000000|garbage").unwrap();
        assert_eq!(read_meta(&p), None, "坏行视为无 meta（判错方向：多传）");
    }

    #[tokio::test]
    async fn session_lock_is_same_object_per_key() {
        let opts = RecvOptions::default();
        let ip: IpAddr = "10.1.1.1".parse().unwrap();
        let a = session_lock(&opts, &ip, "a.txt").await;
        let b = session_lock(&opts, &ip, "a.txt").await;
        let c = session_lock(&opts, &ip, "b.txt").await;
        assert!(Arc::ptr_eq(&a, &b));
        assert!(!Arc::ptr_eq(&a, &c));
    }

    /// 轮 1 F4 判别：服务端应答前 31s 哈希静默不得令 0x10 协商读判
    /// Unsupported/超时——修复前 read_nego 首字节用 30s 普通窗口，本测试必红。
    #[tokio::test(start_paused = true)]
    async fn nego_read_survives_long_hashing_silence() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            // 模拟服务端冷缓存下对目标整文件现算哈希（> 30s 普通读窗口）。
            tokio::time::sleep(std::time::Duration::from_secs(31)).await;
            server.write_all(&[R_RESUME_NEGO, STATUS_OK]).await.unwrap();
            server.write_all(&100u64.to_le_bytes()).await.unwrap();
        });
        let nego = read_nego(&mut client, 200).await.unwrap();
        assert!(
            matches!(nego, ResumeNego::Proceed(100)),
            "31s 静默后协商必须正常读到 0x10，实际: {nego:?}"
        );
    }

    /// 轮 1 F4 判别：dest_hash 现算后必须回填缓存（重试收敛）——
    /// 修复前缓存恒未命中，同一文件每次判定都整文件重算。
    #[tokio::test]
    async fn dest_hash_backfills_cache_after_fresh_compute() {
        use crate::hashcache::HashCache;
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("x.bin");
        std::fs::write(&dest, b"hello world").unwrap();
        let mtime = mtime_of(&std::fs::metadata(&dest).unwrap());
        let opts = RecvOptions {
            hash_cache: Some(Arc::new(tokio::sync::Mutex::new(HashCache::load(
                &dir.path().join("nonexistent-cache.txt"),
                7,
            )))),
            ..Default::default()
        };
        let expect = sha256_file(&dest).unwrap();
        // 第一次：缓存未命中 → 现算。
        assert_eq!(dest_hash(&opts, "x.bin", 11, mtime, &dest).await, Some(expect));
        // 第二次：必须命中缓存（回填生效——未回填则此处 Some 但经现算，
        // 判别口径改为直接查缓存表本身）。
        assert_eq!(
            opts.hash_cache.as_ref().unwrap().lock().await.get("x.bin", 11, mtime),
            Some(expect),
            "现算后必须回填缓存"
        );
    }
}
