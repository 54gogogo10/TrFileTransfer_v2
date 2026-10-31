//! 文件夹传输 0x01：根目录名 + 文件清单（相对路径/大小）+ 逐文件载荷与哈希，
//! 整夹一个完成确认字节。规格 §6.1：文件数上限 1,000,000。

use crate::config::DuplicatePolicy;
use crate::error::{Error, Result, config_err, proto};
use crate::hash::{FileDigester, sha256_file};
use crate::limiter::TokenBucket;
use crate::protocol::frame::{
    MAX_FOLDER_FILES, MAX_TRANSFER_SIZE, STATUS_OK, sanitize_name, sanitize_rel,
};
use crate::protocol::io::{
    read_str_u16, read_u32, read_u64, read_u8, write_str_u16, write_u32, write_u64, write_u8,
};
use crate::transfer::receiver::{
    PartGuard, RecvOptions, publish_part, resolve_root, space_ok,
};
use crate::transfer::resume;
use crate::transfer::sender::{SendOptions, StackPlan, connect_quic_auth, connect_stack};
use crate::transfer::{CHUNK, Transport};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 递归收集文件清单（相对路径用 '/' 分隔，跳过符号链接防环；排序保证确定性；
/// 发送端即做接收端同款净化预检，避免中途失败）。
pub fn collect_files(root: &Path) -> Result<Vec<(String, PathBuf)>> {
    fn walk(dir: &Path, rel: &str, out: &mut Vec<(String, PathBuf)>) -> Result<()> {
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            // 摘要缓存族（主文件 + .bak 镜像）是内部元数据而非内容——与 verify 同口径排除。
            if crate::hashcache::is_cache_artifact(&name) {
                continue;
            }
            let child_rel = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
            let md = e.metadata()?; // DirEntry::metadata 不追踪符号链接
            if md.file_type().is_symlink() {
                continue; // 防环：符号链接不入清单（规格 §11 非目标）
            }
            if md.is_dir() {
                walk(&p, &child_rel, out)?;
            } else if md.is_file() {
                out.push((child_rel, p));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, "", &mut out)?;
    out.sort();
    for (rel, _) in &out {
        sanitize_rel(rel).map_err(|e| config_err(format!("清单项不可发送: {e}")))?;
        if rel.len() > u16::MAX as usize {
            return Err(config_err(format!("相对路径超长: {rel}")));
        }
    }
    if out.len() > MAX_FOLDER_FILES {
        return Err(config_err(format!(
            "文件夹含 {} 个文件，超过上限 {MAX_FOLDER_FILES}",
            out.len()
        )));
    }
    Ok(out)
}

pub async fn send_folder(addr: SocketAddr, root: &Path, opts: &SendOptions) -> Result<()> {
    if !root.is_dir() {
        return Err(config_err("路径不是目录"));
    }
    let raw = root
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| config_err("目录名不是合法 UTF-8"))?;
    let root_name = sanitize_name(raw)?;
    let files = collect_files(root)?;
    // 进度总量 = 清单逐文件 stat 汇总（0x01 清单流式发送，总量先知）。
    if let Some(r) = &opts.progress {
        let mut total = 0u64;
        for (_, p) in &files {
            if let Ok(m) = tokio::fs::metadata(p).await {
                total += m.len();
            }
        }
        r.set_total(total);
    }

    let outcome = crate::progress::Outcome::new(opts.progress.clone());
    let started = std::time::Instant::now();
    let res = match opts.transport {
        // 经 connect_stack 接线 0x09 加密（轮 1 F3：此前 0x01 直连明文——
        // opts.encrypt 被静默忽略，配对场景载荷全程明文，未声明的降级）。
        // 0x01 为基础帧：无需能力探询、不协商压缩（保持既有线上行为）。
        Transport::Tcp => {
            let (mut s, _) = connect_stack(addr, opts, StackPlan::default()).await?;
            send_folder_over(&mut s, &root_name, &files, opts).await
        }
        Transport::Quic => {
            // 配对已在 connect_quic_auth 内完成（0x0D 通道绑定 / 旧端回退）。
            let mut s = connect_quic_auth(addr, opts).await?;
            send_folder_over(&mut s, &root_name, &files, opts).await
        }
    };
    match &res {
        Ok((bytes, count)) => {
            outcome.finish();
            // 发送侧统计（轮 1：0x01 此前漏记——接收侧有记而发送侧缺席）。
            crate::transfer::sender::record_stats(opts, addr, *bytes, *count, started, "0x01 文件夹", &root_name);
        }
        Err(_) => {}
    }
    res.map(|_| ())
}

/// 返回 (发送字节, 发送文件数)（发送侧统计口径）。
async fn send_folder_over<S>(
    s: &mut S,
    root_name: &str,
    files: &[(String, PathBuf)],
    opts: &SendOptions,
) -> Result<(u64, u32)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_u8(s, crate::protocol::frame::T_FOLDER).await?;
    write_str_u16(s, root_name).await?;
    write_u32(s, files.len() as u32).await?;

    let mut lim = TokenBucket::new(opts.speed_limit_bps);
    let mut buf = vec![0u8; CHUNK];
    let mut sent_bytes = 0u64;
    for (rel, path) in files {
        let meta = tokio::fs::metadata(path).await?;
        let size = meta.len();
        if size > MAX_TRANSFER_SIZE {
            return Err(proto(format!("{rel}: 单文件超过 1 PiB 上限")));
        }
        write_str_u16(s, rel).await?;
        write_u64(s, size).await?;

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
            sent_bytes += n as u64;
            if let Some(r) = &opts.progress {
                r.add(n as u64);
            }
        }
        s.write_all(&dig.finalize()).await?;
    }

    // 整夹完成确认：接收端权威。
    let st = read_u8(s).await?;
    let _ = s.shutdown().await;
    if st != STATUS_OK {
        return Err(Error::Rejected("接收端拒绝文件夹（状态 0x00）".into()));
    }
    Ok((sent_bytes, files.len() as u32))
}

pub(crate) async fn recv_folder_over<S>(s: &mut S, peer: SocketAddr, opts: &RecvOptions) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = std::time::Instant::now();
    let root_name = read_str_u16(s).await?;
    let root_name = sanitize_name(&root_name)?;
    let count = read_u32(s).await? as usize;
    if count > MAX_FOLDER_FILES {
        return Err(proto(format!("文件数 {count} 超过上限 {MAX_FOLDER_FILES}")));
    }

    // 目录解析在会话建立时固定（PerDeviceFolder/AutoArchive，规格 §3.3）。
    let dir = crate::transfer::receiver::resolve_save_dir(opts, peer.ip());
    tokio::fs::create_dir_all(&dir).await?;
    // Rename：根目录冲突时对根名追加（规格 §3.1）。
    // Skip：复用已存在的根目录——skip 的语义是「不制造重复副本」，
    // 再建 lib_1 恰恰违背它；文件级冲突在 base 内逐文件比对处理。
    let base = match opts.duplicate {
        DuplicatePolicy::Skip => dir.join(&root_name),
        DuplicatePolicy::Rename => resolve_root(&dir, &root_name).await,
    };

    tokio::fs::create_dir_all(&base).await?;

    let mut recv_bytes = 0u64;
    let mut recv_files = 0u32;
    for _ in 0..count {
        let rel = read_str_u16(s).await?;
        let rel_path = sanitize_rel(&rel)?;
        let size = read_u64(s).await?;
        if size > MAX_TRANSFER_SIZE {
            return Err(proto(format!("{rel}: 声明大小超过 1 PiB 上限")));
        }
        let dest = base.join(&rel_path);
        let parent = dest
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        tokio::fs::create_dir_all(&parent).await?;
        if !space_ok(&parent, size) {
            return Err(Error::Rejected(format!(
                "{rel}: 磁盘可用空间不足（需要 ≥ {size} 字节 + 64MB 余量）"
            )));
        }
        let file_name = dest
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| proto(format!("{rel}: 非法文件名")))?
            .to_string();

        // 唯一半成品 + 流式接收 + 声明哈希比对（与单文件路径同纪律）。
        let report = opts
            .progress
            .as_ref()
            .map(|h| h.register("recv", rel.clone(), size));
        let (part, actual) =
            resume::recv_file_payload(s, &parent, &file_name, size, opts, report.as_ref()).await?;
        if let Some(r) = &report {
            r.finish();
        }
        let _guard = PartGuard(part.clone());

        // Skip 语义（规格 §3.1）：与已有文件比对，一致 → 删除新副本（guard 兜底清理）。
        // 否则 hard_link fail-if-exists 原子发布，冲突名循环重取（封死并发覆盖）。
        let skip_same = match opts.duplicate {
            DuplicatePolicy::Skip if tokio::fs::metadata(&dest).await.is_ok() => {
                let meta_before = tokio::fs::metadata(&dest).await.ok();
                let same_size =
                    meta_before.as_ref().map(|m| m.len() == size).unwrap_or(false);
                let d2 = dest.clone();
                let same = same_size
                    && tokio::task::spawn_blocking(move || {
                        sha256_file(&d2).map(|h| h == actual).unwrap_or(false)
                    })
                    .await
                    .unwrap_or(false);
                // 规格 §1.4 判错方向不对称：比对后 dest 被并发改写 → 宁可改名多留一份。
                let meta_after = tokio::fs::metadata(&dest).await.ok();
                same
                    && meta_before
                        .zip(meta_after)
                        .map(|(a, b)| a.len() == b.len() && a.modified().ok() == b.modified().ok())
                        .unwrap_or(false)
            }
            _ => false,
        };
        if !skip_same {
            let final_dest = publish_part(&part, &parent, &file_name).await?;
            // 缓存免费填充：行内哈希即完整摘要（规格 §3.1）。
            resume::fill_cache_at(opts, &final_dest, size, actual).await;
            recv_bytes += size;
            recv_files += 1;
        }
    }
    crate::transfer::receiver::record_recv(opts, peer, recv_bytes, recv_files, started, "0x01 文件夹", &root_name);
    eprintln!("[接收] 文件夹 {root_name}（{count} 个文件）→ {}", base.display());
    Ok(())
}
