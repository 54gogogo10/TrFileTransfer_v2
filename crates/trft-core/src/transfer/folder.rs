//! 文件夹传输 0x01：根目录名 + 文件清单（相对路径/大小）+ 逐文件载荷与哈希，
//! 整夹一个完成确认字节。规格 §6.1：文件数上限 1,000,000。

use crate::config::DuplicatePolicy;
use crate::error::{config_err, proto, Error, Result};
use crate::hash::{sha256_file, FileDigester};
use crate::limiter::TokenBucket;
use crate::protocol::frame::{
    sanitize_name, sanitize_rel, MAX_FOLDER_FILES, MAX_TRANSFER_SIZE, STATUS_OK,
};
use crate::protocol::io::{
    read_str_u16, read_u32, read_u64, read_u8_long, write_str_u16, write_u32, write_u64,
    write_u8,
};
use crate::transfer::receiver::{
    ensure_contained, publish_part, resolve_root, space_ok, PartGuard, RecvOptions,
};
use crate::transfer::resume;
use crate::transfer::sender::{connect_quic_auth, connect_stack, SendOptions, StackPlan};
use crate::transfer::{Transport, CHUNK};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 递归收集文件清单（相对路径用 '/' 分隔，跳过符号链接防环；排序保证确定性；
/// 发送端即做接收端同款净化预检，避免中途失败）。
/// `exclude_exts` 为已归一化的扩展名（`crate::extext`）：命中的文件既不进清单、
/// 也不传输（发送端单侧过滤——接收端按清单落盘，本来就看不到它们的名字）。
pub fn collect_files(root: &Path, exclude_exts: &[String]) -> Result<Vec<(String, PathBuf)>> {
    collect_files_limited(root, exclude_exts, MAX_FOLDER_FILES)
}

/// `collect_files` 的带上限版本（测试可注入小上限）。P3-11：上限必须在 walk 内
/// 逐项检查——旧实现遍历完才判，百万文件目录会先把清单吃满内存。
fn collect_files_limited(
    root: &Path,
    exclude_exts: &[String],
    max_files: usize,
) -> Result<Vec<(String, PathBuf)>> {
    fn walk(
        dir: &Path,
        rel: &str,
        exclude_exts: &[String],
        max_files: usize,
        out: &mut Vec<(String, PathBuf)>,
    ) -> Result<()> {
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            // 缓存族 + 半成品（.trft-part/.trft-resume）是内部产物而非内容——
            // 与 verify 同口径整类排除，避免把残件当文件传给对端。
            if crate::hashcache::is_transient_name(&name) {
                continue;
            }
            // 用户配置的排除扩展名（整夹/同步发送共用一套口径）。
            if crate::extext::ext_excluded(&name, exclude_exts) {
                continue;
            }
            let child_rel = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            let md = e.metadata()?; // DirEntry::metadata 不追踪符号链接
            if md.file_type().is_symlink() {
                continue; // 防环：符号链接不入清单（规格 §11 非目标）
            }
            if md.is_dir() {
                walk(&p, &child_rel, exclude_exts, max_files, out)?;
            } else if md.is_file() {
                // P3-11：每 push 前查上限，立即报错中止遍历（不把整棵目录吃进内存）。
                if out.len() >= max_files {
                    return Err(config_err(format!(
                        "文件夹文件数超过上限 {max_files}（清单构建中止，未完整遍历）"
                    )));
                }
                out.push((child_rel, p));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, "", exclude_exts, max_files, &mut out)?;
    out.sort();
    for (rel, _) in &out {
        sanitize_rel(rel).map_err(|e| config_err(format!("清单项不可发送: {e}")))?;
        if rel.len() > u16::MAX as usize {
            return Err(config_err(format!("相对路径超长: {rel}")));
        }
    }
    Ok(out)
}

/// 回滚本次新建的根目录（P3-10）：仅 Rename 模式启用（`resolve_root` 原子新建，
/// 不会误删既有数据）。不跟随符号链接（file_type 是 lstat 语义），失败尽力而为。
fn remove_tree(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        let _ = std::fs::remove_dir(dir);
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        match e.file_type() {
            Ok(ft) if ft.is_dir() => remove_tree(&p),
            _ => {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    let _ = std::fs::remove_dir(dir);
}

/// Rename 新建根的回滚守卫（P3-10）：0x01 中途失败（任一 `?` 早退）时删除本次
/// 新建的整棵根目录，避免残留半套目录 / 重试生成 root_1、root_2……。
struct NewRootGuard {
    path: PathBuf,
    armed: bool,
}

impl Drop for NewRootGuard {
    fn drop(&mut self) {
        if self.armed {
            remove_tree(&self.path);
        }
    }
}

pub async fn send_folder(addr: SocketAddr, root: &Path, opts: &SendOptions) -> Result<()> {
    // TCP 槽位与 UDT 共用 C# 方言应用层（0x01 整夹 + 判决）。
    if opts.transport == Transport::Tcp {
        return crate::transfer::cswire::send_folder_cs_tcp(addr, root, opts).await;
    }
    send_folder_inner(addr, root, opts, None).await
}

/// 0x01 整夹 + 失败转 0x04 差量续传（规格 §3.2 AutoRetry「文件夹失败后转 0x04」；
/// 轮 6 P2-5 补齐——此前文件夹失败永远从零重发）。差量基础 = 0x01 发送路径
/// 逐文件回填的**本地**摘要缓存（本地计算的摘要恒为真值；已完整发出的文件
/// 在 0x04 重试轮由服务端逐项核对跳过，半途中断的那个不匹配、必发）。
/// 用法/配置/认证/不支持类错误重试无意义，直接上抛。
pub async fn send_folder_auto(addr: SocketAddr, root: &Path, opts: &SendOptions) -> Result<()> {
    // UDT 槽位走 C# 方言 0x01（TECH-STACK §7.30）。
    if opts.transport == crate::transfer::Transport::Udt {
        return crate::transfer::cswire::send_folder_cs(addr, root, opts).await;
    }
    // TCP 槽位同走 C# 方言：0x01 失败转 0x04 差量同步（规格 §3.2 AutoRetry）。
    if opts.transport == Transport::Tcp {
        let ephemeral = std::env::temp_dir()
            .join("trft-no-such-ephemeral-dir")
            .join("c.txt");
        let cache = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::hashcache::HashCache::load(&ephemeral, 0),
        ));
        return match crate::transfer::cswire::send_folder_cs_tcp(addr, root, opts).await {
            Ok(()) => Ok(()),
            Err(e) => match &e {
                Error::Config(_) | Error::AuthRejected(_) | Error::Unsupported(_) => Err(e),
                _ => {
                    eprintln!("[重试] 整夹发送失败（{e}），改用差量同步");
                    crate::transfer::cswire::send_folder_sync_cs_tcp(
                        addr,
                        root,
                        opts,
                        Some(&cache),
                    )
                    .await
                }
            },
        };
    }
    // 纯内存缓存（不可写路径 → degraded；TTL 0 = 永不过期——只活本次调用）。
    let ephemeral = std::env::temp_dir()
        .join("trft-no-such-ephemeral-dir")
        .join("c.txt");
    let cache = std::sync::Arc::new(tokio::sync::Mutex::new(crate::hashcache::HashCache::load(
        &ephemeral, 0,
    )));
    match send_folder_inner(addr, root, opts, Some(&cache)).await {
        Ok(()) => Ok(()),
        Err(e) => match &e {
            Error::Config(_) | Error::AuthRejected(_) | Error::Unsupported(_) => Err(e),
            _ => {
                eprintln!("[重试] 整夹发送失败（{e}），改用差量同步");
                let sid = resume::stable_session_id(root, &addr.to_string());
                resume::send_folder_resume(addr, root, opts, sid, Some(&cache)).await
            }
        },
    }
}

async fn send_folder_inner(
    addr: SocketAddr,
    root: &Path,
    opts: &SendOptions,
    cache: Option<&std::sync::Arc<tokio::sync::Mutex<crate::hashcache::HashCache>>>,
) -> Result<()> {
    if !root.is_dir() {
        return Err(config_err("路径不是目录"));
    }
    let raw = root
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| config_err("目录名不是合法 UTF-8"))?;
    let root_name = sanitize_name(raw)?;
    let files = collect_files(root, &opts.exclude_exts)?;
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
        // TCP 槽位已改走 C# 方言（send_folder/send_folder_auto 顶层拦截）。
        Transport::Tcp => Err(crate::error::Error::Unsupported(
            "TCP 槽位不使用 v2 帧协议（已改为 C# 方言 cswire）".into(),
        )),
        Transport::Quic => {
            // 配对已在 connect_quic_auth 内完成（0x0D 通道绑定 / 旧端回退）。
            let mut s = connect_quic_auth(addr, opts).await?;
            send_folder_over(&mut s, &root_name, &files, opts, cache).await
        }
        Transport::Rudp => {
            // 与 TCP 同口径：0x05 配对 + 可选 0x09 加密在 connect_stack 内接线
            // （RUDP 无证书体系，无 0x0D 通道绑定）。
            let (mut s, _) = connect_stack(addr, opts, StackPlan::default()).await?;
            send_folder_over(&mut s, &root_name, &files, opts, cache).await
        }
        // UDT 槽位不跑 v2 帧协议（已由 send_folder_auto 顶层拦截）。
        Transport::Udt => Err(crate::error::Error::Unsupported("UDT 槽位不使用 v2 帧协议".into())),
    };
    match &res {
        Ok((bytes, count)) => {
            outcome.finish();
            // 发送侧统计（轮 1：0x01 此前漏记——接收侧有记而发送侧缺席）。
            crate::transfer::sender::record_stats(
                opts,
                addr,
                *bytes,
                *count,
                started,
                "整夹发送",
                &root_name,
            );
        }
        Err(_) => {}
    }
    res.map(|_| ())
}

/// 返回 (发送字节, 发送文件数)（发送侧统计口径）。
/// `cache`：逐文件回填**本地**摘要（轮 6 P2-5——0x01 失败转 0x04 的差量基础；
/// 与 send_folder_resume 的免费回填同键口径 (rel, size, mtime)）。
async fn send_folder_over<S>(
    s: &mut S,
    root_name: &str,
    files: &[(String, PathBuf)],
    opts: &SendOptions,
    cache: Option<&std::sync::Arc<tokio::sync::Mutex<crate::hashcache::HashCache>>>,
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
        let hash = dig.finalize();
        s.write_all(&hash).await?;
        if let Some(c) = cache {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            c.lock().await.insert(rel, size, mtime, hash);
        }
    }

    // 整夹完成确认：接收端权威。长窗（300s）——接收端在回执前可能对最后一个
    // 文件做 Skip 策略的整文件重哈希（冷缓存大文件可达数十秒，轮 UI-5 P2：
    // 此前用 30s 普通窗口，超时会被误报成「对端拒绝」，而接收端其实已成功）。
    let st = read_u8_long(s).await?;
    let _ = s.shutdown().await;
    if st != STATUS_OK {
        return Err(Error::Rejected("接收端拒绝了文件夹传输".into()));
    }
    Ok((sent_bytes, files.len() as u32))
}

pub(crate) async fn recv_folder_over<S>(
    s: &mut S,
    peer: SocketAddr,
    opts: &RecvOptions,
) -> Result<()>
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
    // P2-17：复用既有目录前先验包含性，建目录后再验一次（封替换窗口）。
    ensure_contained(&opts.save_dir, &dir)?;
    tokio::fs::create_dir_all(&dir).await?;
    ensure_contained(&opts.save_dir, &dir)?;
    // Rename：根目录冲突时对根名追加（规格 §3.1）。
    // Skip：复用已存在的根目录——skip 的语义是「不制造重复副本」，
    // 再建 lib_1 恰恰违背它；文件级冲突在 base 内逐文件比对处理。
    let base = match opts.duplicate {
        DuplicatePolicy::Skip => dir.join(&root_name),
        DuplicatePolicy::Rename => resolve_root(&dir, &root_name).await,
    };

    // P2-17：Skip 复用既有根目录（Rename 由 resolve_root 原子新建）——建目录前后
    // 各验一次，预置 junction/符号链接不得把对端相对路径写出 save_dir。
    ensure_contained(&opts.save_dir, &base)?;
    tokio::fs::create_dir_all(&base).await?;
    ensure_contained(&opts.save_dir, &base)?;
    // P3-10：Rename 模式新建的根中途失败必须回滚（Skip 复用既有根，绝不删）。
    let mut root_guard = NewRootGuard {
        path: base.clone(),
        armed: opts.duplicate == DuplicatePolicy::Rename,
    };

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
        // P2-17：子目录同样可能是指向树外的链接——建目录前后各验一次。
        ensure_contained(&opts.save_dir, &parent)?;
        tokio::fs::create_dir_all(&parent).await?;
        ensure_contained(&opts.save_dir, &parent)?;
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
        let report = opts.progress.as_ref().map(|h| {
            let r = h.register("recv", rel.clone(), size);
            r.set_peer(&peer.ip().to_string());
            r
        });
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
                let same_size = meta_before
                    .as_ref()
                    .map(|m| m.len() == size)
                    .unwrap_or(false);
                let d2 = dest.clone();
                let same = same_size
                    && tokio::task::spawn_blocking(move || {
                        sha256_file(&d2).map(|h| h == actual).unwrap_or(false)
                    })
                    .await
                    .unwrap_or(false);
                // 规格 §1.4 判错方向不对称：比对后 dest 被并发改写 → 宁可改名多留一份。
                let meta_after = tokio::fs::metadata(&dest).await.ok();
                same && meta_before
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
    // 全部文件落盘成功：新根转正（守卫 drop 不再删除）。
    root_guard.armed = false;
    crate::transfer::receiver::record_recv(
        opts,
        peer,
        recv_bytes,
        recv_files,
        started,
        "整夹发送",
        &base,
    );
    eprintln!(
        "[接收] 文件夹 {root_name}（{count} 个文件）→ {}",
        base.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P3-11 判别：文件数上限必须在 walk 内逐项检查、立即报错——旧实现遍历完
    /// 才判，百万文件目录会先吃满内存。
    #[test]
    fn collect_files_stops_at_limit() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        for i in 0..3 {
            std::fs::write(root.join(format!("f{i}.bin")), b"x").unwrap();
        }
        std::fs::write(root.join("sub").join("g.bin"), b"x").unwrap();
        let e = collect_files_limited(&root, &[], 2).unwrap_err();
        assert!(e.to_string().contains("上限"), "错误信息应指明上限: {e}");
        assert_eq!(collect_files_limited(&root, &[], 10).unwrap().len(), 4);
    }

    /// 驱动一次 0x01 接收会话：写 root 名 + count + 逐文件 (rel, size, 载荷, 哈希)。
    async fn drive_recv_folder(
        opts: &RecvOptions,
        root_name: &str,
        files: &[(&str, &[u8], Option<[u8; 32]>)],
    ) -> Result<()> {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let o = opts.clone();
        let peer: SocketAddr = "203.0.113.45:1".parse().unwrap();
        let task = tokio::spawn(async move { recv_folder_over(&mut server, peer, &o).await });
        write_str_u16(&mut client, root_name).await?;
        write_u32(&mut client, files.len() as u32).await?;
        for (rel, data, hash_override) in files {
            write_str_u16(&mut client, rel).await?;
            write_u64(&mut client, data.len() as u64).await?;
            client.write_all(data).await?;
            let h = hash_override.unwrap_or_else(|| crate::hash::sha256(data));
            client.write_all(&h).await?;
        }
        tokio::time::timeout(std::time::Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
    }

    /// P2-17 判别：0x01(Skip) 复用既有根目录前必须验包含性——根目录若是指向
    /// 树外的 junction，落盘必须拒绝，不得写出 save_dir。
    #[tokio::test]
    async fn folder_skip_refuses_junction_root_escape() {
        let dir = tempfile::tempdir().unwrap();
        let save = dir.path().join("save");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&save).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        if !crate::transfer::receiver::test_dir_link(&save.join("lib"), &outside) {
            eprintln!("跳过：当前环境无法创建目录链接（junction/symlink）");
            return;
        }
        let opts = RecvOptions {
            save_dir: save,
            duplicate: DuplicatePolicy::Skip,
            ..Default::default()
        };
        let r = drive_recv_folder(&opts, "lib", &[("evil.bin", b"pwn", None)]).await;
        assert!(r.is_err(), "指向树外的根目录 junction 必须拒绝（P2-17）");
        assert!(
            !outside.join("evil.bin").exists(),
            "对端相对路径不得写到保存目录之外"
        );
    }

    /// P2-17 判别（续）：根目录内预置的子目录 junction 同样必须拒绝（每个 parent
    /// 建目录前后各验一次）。
    #[tokio::test]
    async fn folder_skip_refuses_junction_parent_escape() {
        let dir = tempfile::tempdir().unwrap();
        let save = dir.path().join("save");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(save.join("lib")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        if !crate::transfer::receiver::test_dir_link(&save.join("lib").join("link"), &outside) {
            eprintln!("跳过：当前环境无法创建目录链接（junction/symlink）");
            return;
        }
        let opts = RecvOptions {
            save_dir: save,
            duplicate: DuplicatePolicy::Skip,
            ..Default::default()
        };
        let r = drive_recv_folder(&opts, "lib", &[("link/evil.bin", b"pwn", None)]).await;
        assert!(r.is_err(), "指向树外的子目录 junction 必须拒绝（P2-17）");
        assert!(
            !outside.join("evil.bin").exists(),
            "对端相对路径不得经 junction 写出保存目录"
        );
    }

    /// P3-10 判别：Rename 模式新建根的中途失败必须回滚——旧实现把已发布的
    /// 文件留在 proj/，重试再生成 proj_1、proj_2……并残留半套目录。
    #[tokio::test]
    async fn folder_failure_rolls_back_new_root() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let opts = RecvOptions {
            save_dir: out.clone(),
            duplicate: DuplicatePolicy::Rename,
            ..Default::default()
        };
        // 第 2 个文件哈希不符 → 会话失败（第 1 个已发布进新根）。
        let r = drive_recv_folder(
            &opts,
            "proj",
            &[
                ("good.bin", b"ok", None),
                ("bad.bin", b"nope", Some([0u8; 32])),
            ],
        )
        .await;
        assert!(r.is_err(), "哈希不符必须报错");
        assert!(
            !out.join("proj").exists(),
            "失败会话新建的根必须回滚（P3-10）"
        );
    }
}
