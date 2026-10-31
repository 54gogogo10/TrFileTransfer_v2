//! ed25519 签名自更新器（规格 §3.7 自动升级 + §5.1 更新供应链防线）。
//!
//! 清单格式（key=value，LF 分行；`sig=` 行必须在最后一行）：
//! ```text
//! version=1.2.3
//! url=https://example.com/trft-1.2.3.exe
//! sha256=<64hex>
//! sig=<128hex ed25519，签名对象 = sig 行之前的全部字节（含结尾换行）>
//! ```
//! 防线：① 更新源强制 https（明文仅回环主机，规格 §5.1）；
//! ② 清单必须 ed25519（verify_strict）通过内嵌公钥校验；
//! ③ 下载流式 SHA-256 校验（边车缺失等价于拒绝——签名清单即边车）；
//! ④ **换入前重校验**（TOCTOU 封口，规格 §7.1）；
//! ⑤ 原子换入（旧 exe 改名 + 失败回滚）。

use crate::error::{Error, Result, config_err, proto};
use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::RngCore;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 发布签名公钥（32 字节 hex；随发布流程替换，测试注入自己的密钥）。
pub const UPDATE_PUBKEY_HEX: &str = "ab6d87ec35a8995b88a98b1a51600740d06a80d6cf2bd8a7e7cad639431b2c23";
/// 清单大小上限（清单是小文件；防响应放大）。
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// 更新包下载上限。
pub const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
/// 重定向跟随上限。
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    pub url: String,
    pub sha256: [u8; 32],
}

/// 解析 + 验签清单。
pub fn parse_manifest(bytes: &[u8], pubkey: &VerifyingKey) -> Result<Manifest> {
    let text = std::str::from_utf8(bytes).map_err(|_| proto("清单不是合法 UTF-8"))?;
    let trimmed = text.trim_end_matches(['\n', '\r']);
    let Some(sig_pos) = trimmed.rfind("\nsig=") else {
        return Err(proto("清单缺少 sig 行"));
    };
    // 签名对象 = sig 行之前的全部字节（**含其结尾换行**）——与签名侧约定一致。
    let (signed, sig_line) = trimmed.split_at(sig_pos + 1);
    let sig_hex = sig_line.strip_prefix("sig=").ok_or_else(|| proto("sig 行格式非法"))?;
    let mut sig_bytes = [0u8; 64];
    // 全字符 hex 校验先行（轮 4 P2：多字节 UTF-8 会让下标切片 panic 于字符边界）。
    if sig_hex.len() != 128 || !sig_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(proto("sig 长度/字符非法"));
    }
    for i in 0..64 {
        sig_bytes[i] = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16).map_err(|_| proto("sig 非十六进制"))?;
    }
    let sig = Signature::from_bytes(&sig_bytes);
    pubkey
        .verify_strict(signed.as_bytes(), &sig)
        .map_err(|_| proto("清单签名校验失败（拒绝安装）"))?;
    let body = signed.trim_end_matches(['\n', '\r']);
    let mut version = None;
    let mut url = None;
    let mut sha = None;
    for line in body.lines() {
        let (k, v) = line.split_once('=').ok_or_else(|| proto("清单行格式非法"))?;
        match k {
            "version" => version = Some(v.trim().to_string()),
            "url" => url = Some(v.trim().to_string()),
            "sha256" => {
                let h = v.trim();
                if h.len() != 64 {
                    return Err(proto("sha256 长度非法"));
                }
                let mut out = [0u8; 32];
                for i in 0..32 {
                    out[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|_| proto("sha256 非十六进制"))?;
                }
                sha = Some(out);
            }
            _ => {} // 未知键宽容忽略（向后兼容）
        }
    }
    let (Some(version), Some(url), Some(sha256)) = (version, url, sha) else {
        return Err(proto("清单缺少 version/url/sha256"));
    };
    if version.is_empty() || url.is_empty() {
        return Err(proto("清单字段为空"));
    }
    Ok(Manifest { version, url, sha256 })
}

/// 版本比较：按「.」分段数值比较，缺段视为 0；非数字段按 0 处理。
pub fn version_gt(candidate: &str, current: &str) -> bool {
    fn nums(v: &str) -> Vec<u64> {
        v.trim()
            .trim_start_matches('v')
            .split('.')
            .map(|p| p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().unwrap_or(0))
            .collect()
    }
    let (a, b) = (nums(candidate), nums(current));
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

// ============ 极简 HTTP/1.1 客户端（GET；https 强制，明文仅回环） ============

struct Url {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(raw: &str) -> Result<Url> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| proto(format!("URL 缺少协议: {raw}")))?;
    let https = match scheme.to_ascii_lowercase().as_str() {
        "https" => true,
        "http" => false,
        _ => return Err(proto(format!("不支持的协议: {scheme}"))),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        // IPv6 字面量：`[::1]:8443` 带端口才解析；裸 `[::1]`（无端口）走默认端口
        // 分支（轮 4 F9——此前裸 v6 字面量误入本分支，p.parse 必败报「端口非法」）。
        Some((h, p))
            if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() && h.starts_with('[') && h.ends_with(']') =>
        {
            let port: u16 = p.parse().map_err(|_| proto("端口非法"))?;
            (h.trim_matches(|c| c == '[' || c == ']'), port)
        }
        // 非字面量主机名（或裸 IPv4）带端口。
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() && !h.contains(':') => {
            let port: u16 = p.parse().map_err(|_| proto("端口非法"))?;
            (h, port)
        }
        _ => (authority.trim_matches(|c| c == '[' || c == ']'), if https { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(proto("URL 缺少主机"));
    }
    // 规格 §5.1：更新源强制 https（明文仅回环）。
    if !https && !is_loopback_host(host) {
        return Err(proto("明文更新源仅允许回环主机（规格 §5.1）"));
    }
    Ok(Url { https, host: host.to_string(), port, path: path.to_string() })
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// 单次请求 + 头部解析：返回（流, 头部信息）。
type BoxIo = crate::transfer::BoxStream;

struct Head {
    status: u16,
    location: Option<String>,
    content_length: Option<usize>,
    chunked: bool,
    body_so_far: Vec<u8>,
}

async fn open_stream(url: &Url) -> Result<BoxIo> {
    {
        use rustls::pki_types::ServerName;
        let tcp = tokio::time::timeout(Duration::from_secs(15), async {
            let t = tokio::net::TcpStream::connect((url.host.as_str(), url.port)).await?;
            t.set_nodelay(true).ok();
            Ok::<_, Error>(t)
        })
        .await
        .map_err(|_| proto("连接更新源超时"))??;
        if !url.https {
            return Ok::<BoxIo, Error>(Box::new(tcp));
        }
        // 规格 §5.1：更新源强制 https，证书走 webpki 根集（系统信任链纯 Rust 等价）。
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(cfg));
        let name = ServerName::try_from(url.host.clone()).map_err(|_| proto("更新源主机名非法"))?;
        let s = tokio::time::timeout(Duration::from_secs(15), connector.connect(name, tcp))
            .await
            .map_err(|_| proto("TLS 握手超时"))?
            .map_err(|e| proto(format!("TLS 握手失败: {e}")))?;
        Ok(Box::new(s))
    }
}

async fn request_and_head(url: &Url) -> Result<(BoxIo, Head)> {
    let mut io = open_stream(url).await?;
    let host_header = if (url.https && url.port != 443) || (!url.https && url.port != 80) {
        format!("{}:{}", url.host, url.port)
    } else {
        url.host.clone()
    };
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: trft-updater\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.path, host_header
    );
    io.write_all(req.as_bytes()).await?;
    // 头部读窗口 15s（与规格 §6.1 HTTP 头超时同源纪律）。
    let raw = tokio::time::timeout(Duration::from_secs(15), async {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = io.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if find_header_end(&buf).is_some() || buf.len() > 256 * 1024 {
                break;
            }
        }
        Ok::<_, Error>(buf)
    })
    .await
    .map_err(|_| proto("读响应头超时"))??;
    let header_end = find_header_end(&raw).ok_or_else(|| proto("响应头不完整"))?;
    let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let mut lines = head.lines();
    let status_line = lines.next().ok_or_else(|| proto("空响应"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|sv| sv.parse().ok())
        .ok_or_else(|| proto("状态行非法"))?;
    let mut location = None;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else { continue };
        match k.trim().to_ascii_lowercase().as_str() {
            "location" => location = Some(v.trim().to_string()),
            "content-length" => content_length = v.trim().parse::<usize>().ok(),
            "transfer-encoding" if v.to_ascii_lowercase().contains("chunked") => chunked = true,
            _ => {}
        }
    }
    let body_so_far = raw[(header_end + 4).min(raw.len())..].to_vec();
    Ok((io, Head { status, location, content_length, chunked, body_so_far }))
}

/// GET 请求（跟随 ≤5 次重定向；每次重定向重新执行 https/回环策略）。
async fn http_get(raw_url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    let mut url = parse_url(raw_url)?;
    for _ in 0..=MAX_REDIRECTS {
        let (io, head) = request_and_head(&url).await?;
        if (300..400).contains(&head.status) {
            let Some(loc) = head.location else {
                return Err(proto(format!("重定向缺少 Location（{}）", head.status)));
            };
            let next = if loc.contains("://") {
                loc
            } else {
                format!("{}://{}{}", if url.https { "https" } else { "http" }, url.host, loc)
            };
            url = parse_url(&next)?;
            continue; // Connection: close，旧连接自然收尾
        }
        if head.status != 200 {
            return Err(proto(format!("更新源返回 {}", head.status)));
        }
        return read_body(io, head, max_bytes).await;
    }
    Err(proto("重定向次数超限"))
}

/// 读体：Content-Length / chunked / 连接关闭三种定界，统一 size 上限。
async fn read_body(mut io: BoxIo, head: Head, max_bytes: usize) -> Result<Vec<u8>> {
    if let Some(cl) = head.content_length {
        if cl > max_bytes {
            return Err(proto("响应超过大小上限"));
        }
    }
    let mut pending = head.body_so_far;
    let mut chunk = [0u8; 16 * 1024];
    if head.chunked {
        // chunked 以块尾判定定界：先收全（受 2×max 防线）再解码。
        loop {
            let n = tokio::time::timeout(Duration::from_secs(30), io.read(&mut chunk))
                .await
                .map_err(|_| proto("读响应体超时"))??;
            if n == 0 {
                break;
            }
            pending.extend_from_slice(&chunk[..n]);
            if pending.len() > max_bytes.saturating_mul(2) {
                return Err(proto("响应超过大小上限"));
            }
        }
        let out = decode_chunked(&pending)?;
        if out.len() > max_bytes {
            return Err(proto("响应超过大小上限"));
        }
        return Ok(out);
    }
    loop {
        if let Some(cl) = head.content_length {
            if pending.len() >= cl {
                break;
            }
        }
        let n = tokio::time::timeout(Duration::from_secs(30), io.read(&mut chunk))
            .await
            .map_err(|_| proto("读响应体超时"))??;
        if n == 0 {
            break;
        }
        pending.extend_from_slice(&chunk[..n]);
        if pending.len() > max_bytes {
            return Err(proto("响应超过大小上限"));
        }
    }
    if let Some(cl) = head.content_length {
        pending.truncate(cl);
    }
    Ok(pending)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn decode_chunked(mut data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = data.windows(2).position(|w| w == b"\r\n") else {
            return Err(proto("chunked 尺寸行不完整"));
        };
        let size_str = std::str::from_utf8(&data[..line_end]).map_err(|_| proto("chunked 尺寸非法"))?;
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| proto("chunked 尺寸非法"))?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if size > data.len().saturating_sub(2) {
            return Err(proto("chunked 块不完整"));
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

// ============ 下载与换入 ============

/// 拉取并验签清单。
pub async fn fetch_manifest(url: &str, pubkey: &VerifyingKey) -> Result<Manifest> {
    let bytes = http_get(url, MAX_MANIFEST_BYTES).await?;
    parse_manifest(&bytes, pubkey)
}

fn pubkey_from_hex(hex: &str) -> Result<VerifyingKey> {
    if hex.len() != 64 {
        return Err(config_err("UPDATE_PUBKEY 配置非法（需 64 hex）"));
    }
    let mut b = [0u8; 32];
    for i in 0..32 {
        b[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| config_err("UPDATE_PUBKEY 非十六进制"))?;
    }
    VerifyingKey::from_bytes(&b).map_err(|e| config_err(format!("公钥非法: {e}")))
}

/// 默认公钥入口（内嵌常量）。
pub fn embedded_pubkey() -> Result<VerifyingKey> {
    pubkey_from_hex(UPDATE_PUBKEY_HEX)
}

/// 流式下载更新包到 `dest_dir/<guid>.part`，边下边算 SHA-256，完成后原子改名并返回路径。
/// 哈希不符 → 删除文件并报错（规格 §5.1：下载后 SHA256 校验）。
pub async fn download_package(manifest: &Manifest, dest_dir: &Path) -> Result<PathBuf> {
    let url = parse_url(&manifest.url)?;
    tokio::fs::create_dir_all(dest_dir).await?;
    let mut rnd = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut rnd);
    let part = dest_dir.join(format!("update-{:016x}.part", u64::from_le_bytes(rnd)));
    let mut out = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&part)
        .await
        .map_err(|e| proto(format!("创建更新暂存失败: {e}")))?;
    let r = download_into(&url, &mut out, MAX_PACKAGE_BYTES, manifest.sha256).await;
    drop(out);
    if let Err(e) = r {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    let final_path = part.with_extension("bin");
    tokio::fs::rename(&part, &final_path).await?;
    Ok(final_path)
}

async fn download_into<W: tokio::io::AsyncWrite + Unpin + Send>(
    url: &Url,
    out: &mut W,
    max_bytes: u64,
    expect_sha: [u8; 32],
) -> Result<()> {
    let (mut io, head) = request_and_head(url).await?;
    if head.status != 200 {
        return Err(proto(format!("更新包下载返回 {}（重定向请使用直达 URL）", head.status)));
    }
    let mut dig = crate::hash::FileDigester::new();
    let mut total: u64 = 0;
    let mut pending = head.body_so_far;
    let mut pos = 0usize;
    let mut chunk = [0u8; 64 * 1024];

    // 从 io 网络补缓冲（compact 已消费前缀）。
    macro_rules! fill {
        () => {{
            let n = tokio::time::timeout(Duration::from_secs(60), io.read(&mut chunk))
                .await
                .map_err(|_| proto("下载超时"))??;
            if n == 0 {
                false
            } else {
                pending.drain(..pos);
                pos = 0;
                pending.extend_from_slice(&chunk[..n]);
                true
            }
        }};
    }
    // 从 io/pending 取一行（CRLF 定界）——chunked 块长行用（轮 5 P2）。
    // 行长上限 8KB（轮 4 F4）：合法块长行远短于此；恶意更新源发无 CRLF 的
    // GB 级字节流不得无界缓冲（对照 read_body 已有的 2×max 上限）。
    async fn read_line(
        io: &mut (impl tokio::io::AsyncRead + Unpin + Send),
        pending: &mut Vec<u8>,
        pos: &mut usize,
        chunk: &mut [u8; 64 * 1024],
    ) -> Result<String> {
        const MAX_LINE: usize = 8 * 1024;
        loop {
            if let Some(idx) = pending[*pos..].windows(2).position(|w| w == b"
") {
                let line = String::from_utf8_lossy(&pending[*pos..*pos + idx]).to_string();
                *pos += idx + 2;
                return Ok(line);
            }
            if *pos > 0 {
                pending.drain(..*pos);
                *pos = 0;
            }
            if pending.len() > MAX_LINE {
                return Err(proto("chunked 块长行超过 8KB 上限（疑似恶意源）"));
            }
            let n = tokio::time::timeout(Duration::from_secs(60), io.read(chunk))
                .await
                .map_err(|_| proto("下载超时"))??;
            if n == 0 {
                return Err(proto("chunked 块长行被截断"));
            }
            pending.extend_from_slice(&chunk[..n]);
        }
    }
    if head.chunked {
        // chunked 定界：增量解码（轮 5 P2——此前框架字节混入安装包 → 哈希必失配）。
        loop {
            let line = read_line(&mut io, &mut pending, &mut pos, &mut chunk).await?;
            let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| proto(format!("chunked 块长非法: {line}")))?;
            if size == 0 {
                loop {
                    let l = read_line(&mut io, &mut pending, &mut pos, &mut chunk).await?;
                    if l.is_empty() {
                        break;
                    }
                }
                break;
            }
            let mut left = size as u64;
            while left > 0 {
                if pos >= pending.len() {
                    if !fill!() {
                        return Err(proto("chunked 块被截断"));
                    }
                    continue;
                }
                let take = std::cmp::min(left, (pending.len() - pos) as u64) as usize;
                let data = pending[pos..pos + take].to_vec();
                dig.update(&data);
                out.write_all(&data).await?;
                total += take as u64;
                if total > max_bytes {
                    return Err(proto("更新包超过大小上限"));
                }
                pos += take;
                left -= take as u64;
            }
            // 块尾 CRLF：读两字节并校验。
            while pending.len() - pos < 2 {
                if !fill!() {
                    return Err(proto("chunked 块尾被截断"));
                }
            }
            if &pending[pos..pos + 2] != b"
" {
                return Err(proto("chunked 块尾非 CRLF"));
            }
            pos += 2;
        }
    } else {
        loop {
            if pos >= pending.len() {
                let n = tokio::time::timeout(Duration::from_secs(60), io.read(&mut chunk))
                    .await
                    .map_err(|_| proto("下载超时"))??;
                if n == 0 {
                    break;
                }
                pending.clear();
                pos = 0;
                pending.extend_from_slice(&chunk[..n]);
                continue;
            }
            let data = &pending[pos..];
            dig.update(data);
            out.write_all(data).await?;
            total += data.len() as u64;
            pos = pending.len();
            if total > max_bytes {
                return Err(proto("更新包超过大小上限"));
            }
        }
    }
    let actual = dig.finalize();
    if actual != expect_sha {
        return Err(proto(format!(
            "更新包 SHA-256 不一致（期望 {}，实际 {}）",
            crate::hash::hex(&expect_sha),
            crate::hash::hex(&actual)
        )));
    }
    out.flush().await?;
    Ok(())
}

/// 换入：**换入前重校验**（TOCTOU 封口）→ 旧 exe 改名 → 新 exe 就位；失败回滚。
/// 返回备份路径（成功换入后由调用方决定何时清理）。
pub fn apply_update(new_file: &Path, expect_sha: [u8; 32]) -> Result<PathBuf> {
    let cur = std::env::current_exe().map_err(|e| proto(format!("无法定位当前 exe: {e}")))?;
    // 换入前重校验（规格 §7.1：下载校验后被替换的 TOCTOU 封口）。
    let actual = crate::hash::sha256_file(new_file)?;
    if actual != expect_sha {
        return Err(proto("换入前重校验失败（文件已被替换），拒绝安装"));
    }
    let bak = cur.with_extension("exe.old");
    let _ = std::fs::remove_file(&bak);
    std::fs::rename(&cur, &bak).map_err(|e| proto(format!("旧 exe 改名失败: {e}")))?;
    // 跨卷安全：先拷贝到同目录临时名，再同卷 rename 就位。
    // 轮 5 P2：**被 rename 就位的正是 staged 拷贝**——拷贝后必须对 staged
    // 再校验一次（第 3 次读盘），封住「验证通过后、拷贝进行中」的替换窗口。
    let staged = cur.with_extension("exe.new");
    let r = std::fs::copy(new_file, &staged)
        .map_err(|e| proto(format!("暂存新 exe 失败: {e}")))
        .and_then(|_| {
            let staged_sha = crate::hash::sha256_file(&staged)
                .map_err(|e| proto(format!("暂存文件校验失败: {e}")))?;
            if staged_sha != expect_sha {
                return Err(proto("暂存拷贝重校验失败（拷贝窗口内被替换），拒绝安装"));
            }
            std::fs::rename(&staged, &cur).map_err(|e| proto(format!("新 exe 就位失败: {e}")))
        });
    if let Err(e) = r {
        let _ = std::fs::remove_file(&staged);
        // 回滚：旧 exe 复位。
        if std::fs::rename(&bak, &cur).is_err() {
            return Err(proto(format!("更新失败且回滚失败（.old 保留于 {}）: {e}", bak.display())));
        }
        return Err(e);
    }
    Ok(bak)
}

/// 完整更新流程：拉清单 → 验签 → 比版本 → 下载 → 校验 → 换入。
/// 返回 Some(备份路径) 表示已换入；None 表示无需更新。
pub async fn run_update(
    manifest_url: &str,
    pubkey: &VerifyingKey,
    current_version: &str,
    work_dir: &Path,
) -> Result<Option<PathBuf>> {
    // 陈旧暂存清扫（轮 5 P3：下载与换入之间崩溃遗留 update-*.{part,bin} 永久残留）。
    if let Ok(rd) = std::fs::read_dir(work_dir) {
        let now = std::time::SystemTime::now();
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("update-") && (n.ends_with(".part") || n.ends_with(".bin")) {
                if let Ok(md) = e.metadata() {
                    if md.modified().ok().is_some_and(|t| {
                        now.duration_since(t).map(|d| d > Duration::from_secs(24 * 3600)).unwrap_or(false)
                    }) {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
        }
    }
    let m = fetch_manifest(manifest_url, pubkey).await?;
    if !version_gt(&m.version, current_version) {
        return Ok(None);
    }
    let pkg = download_package(&m, work_dir).await?;
    // 换入成功后清理安装包。
    match apply_update(&pkg, m.sha256) {
        Ok(bak) => {
            let _ = std::fs::remove_file(&pkg);
            Ok(Some(bak))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&pkg);
            Err(e)
        }
    }
}

/// 重启进程（换入后调用）：启动同路径 exe 并让调用方自行退出。
pub fn spawn_restarted() -> Result<()> {
    let exe = std::env::current_exe().map_err(|e| proto(e.to_string()))?;
    std::process::Command::new(exe)
        .spawn()
        .map(|_| ())
        .map_err(|e| proto(format!("重启失败: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;

    fn keypair() -> (SigningKey, VerifyingKey) {
        let seed = [42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn sign_manifest(sk: &SigningKey, version: &str, url: &str, sha: &str) -> Vec<u8> {
        let body = format!("version={version}\nurl={url}\nsha256={sha}\n");
        let sig = sk.sign(body.as_bytes());
        format!("{body}sig={}\n", crate::hash::hex(&sig.to_bytes())).into_bytes()
    }

    #[test]
    fn manifest_roundtrip_and_tamper() {
        let (sk, vk) = keypair();
        let sha = crate::hash::sha256(b"pkg");
        let m = sign_manifest(&sk, "1.2.3", "https://example.com/a.exe", &crate::hash::hex(&sha));
        let parsed = parse_manifest(&m, &vk).unwrap();
        assert_eq!(parsed.version, "1.2.3");
        assert_eq!(parsed.url, "https://example.com/a.exe");
        assert_eq!(parsed.sha256, sha);
        // 篡改 version → 签名失败。
        let mut tampered = m.clone();
        tampered[8] = b'9';
        assert!(parse_manifest(&tampered, &vk).is_err(), "篡改必须被签名识破");
        // 无 sig → 拒绝。
        assert!(parse_manifest(b"version=1.0.0\nurl=https://x/y\nsha256=x\n", &vk).is_err());
    }

    #[test]
    fn version_compare() {
        assert!(version_gt("1.2.3", "1.2.2"));
        assert!(version_gt("2.0", "1.9.9"));
        assert!(version_gt("v1.1", "1.0.0"));
        assert!(!version_gt("1.2.3", "1.2.3"));
        assert!(!version_gt("1.2", "1.2.1"));
    }

    #[test]
    fn url_policy_https_enforced() {
        assert!(parse_url("https://example.com/x").is_ok());
        assert!(parse_url("http://127.0.0.1:8080/x").is_ok(), "回环允许明文");
        assert!(parse_url("http://localhost/x").is_ok());
        assert!(parse_url("http://example.com/x").is_err(), "非回环明文必须拒绝");
        assert!(parse_url("ftp://example.com/x").is_err());
    }

    #[test]
    fn embedded_pubkey_parses() {
        assert!(embedded_pubkey().is_ok(), "内嵌公钥必须可解析");
    }

    #[test]
    fn chunked_decode() {
        let data = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(data).unwrap(), b"Wikipedia");
        assert!(decode_chunked(b"zz\r\nx").is_err());
    }
}
