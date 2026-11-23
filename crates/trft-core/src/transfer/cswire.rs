//! C# 方言应用层（跑在 `transfer::udt` 的 UDT4 字节流之上）。
//!
//! 原 C# 版的 UDT 槽位复用其 TCP 应用协议（C# 版 WIRE-PROTOCOL.md「UDT Protocol」节）：
//! 整数一律小端、文件名 UTF-8、每文件尾随 32B SHA-256，认证/压缩/能力以**前奏帧**
//! 挂在同一分发循环前。本模块逐字节复刻该协议（权威参考其 `WireProtocol.cs`/
//! `WireCrypto.cs`/`WireCompress.cs`），供 UDT 槽位与 C# 版互通——这是全仓库唯一
//! 承诺与外部实现互通的应用层（PRODUCT-SPEC §4.3）。
//!
//! 层叠顺序（C# AuthenticateAsync 注释原话「encrypt(compress(plain))」）：
//! 应用字节 → 0x08 deflate 段 → 0x09 AES-256-CTR+HMAC 段 → 裸 UDT 流。
//! 结尾 1 字节 ACK（0x01/0x00）走**裸流**（在装饰器之外——UDT 特有，TCP 无此分叉）。

use crate::config::DuplicatePolicy;
use crate::error::{proto, Error, Result};
use crate::limiter::TokenBucket;
use crate::transfer::receiver::{
    cleanup_part_orphans, confirm_once, conn_precheck, conn_settle, record_recv,
    resolve_save_dir, tune_tcp, RecvOptions,
};
use crate::transfer::udt::{connect_udt, UdtStream};
use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 帧头名长上限（C# nameLen 边界）。
pub const CS_MAX_NAME: usize = 4096;
/// 文本帧上限（C# MaxTextBytes = 1MB）。
pub const CS_MAX_TEXT: usize = 1_048_576;
/// 目录文件数上限（C# MaxFolderFileCount）。
pub const CS_MAX_FOLDER_FILES: usize = 1_000_000;
/// 0x04 清单路径字节总预算（第 9 轮审查 P2-4）：合法 1e6 文件 × 平均 50B
/// 远低于此值；超过即视为恶意清单，避免整表驻留把连接打成 4GiB。
pub const CS_MANIFEST_MAX_BYTES: usize = 16 * 1024 * 1024;
/// 单文件声明上限（C# MaxTransferSize = 1 PiB）。
pub const CS_MAX_TRANSFER: u64 = 1 << 50;
/// 接收体缓冲（轮 7：256KB → 4MB 对齐 C# WireProtocol bufferSize——压缩比率
/// 随段增大改善，UDT 引擎读侧聚合已就位）。
const CS_RECV_BUF: usize = 4 * 1024 * 1024;
/// 前奏静默窗（轮 9 P1-4：对齐 C# SetTimeout(30000,30000)——活而静默的
/// peer 不得无限占用连接与并发闸）。
const PRELUDE_IDLE: Duration = Duration::from_secs(30);
/// 0x09 加密段明文上限（C# EncryptedWireStream.MaxSegment）。
pub const ENC_SEGMENT_MAX: usize = 262_144;
/// 0x08 压缩段线长上限（解压炸弹防线，C# CompressedWireStream.MaxSegment）。
pub const COMP_SEGMENT_MAX: usize = 64 * 1024 * 1024;
/// 分块覆盖区间上限（C# MaxChunkRanges）。
pub const CS_MAX_CHUNK_RANGES: usize = 8192;
/// 客户端认证前奏读超时（C# 8s 窗口——旧对端不应答快速失败）。
const PRELUDE_TIMEOUT: Duration = Duration::from_secs(8);
/// 结尾 ACK 等待超时（C# UDT_RCVTIMEO 30s 口径）。
const ACK_TIMEOUT: Duration = Duration::from_secs(30);
/// 判决读窗口（C# LongReadWindowMs 同值 300s）：0x11 判决与跳过清单应答前，
/// 服务端可能对冷文件整盘现算哈希（规格 §6.1），30s 普通窗口不够。
const LONG_READ_WINDOW: Duration = Duration::from_secs(300);

pub const F_SINGLE: u8 = 0x00;
pub const F_FOLDER: u8 = 0x01;
pub const F_CHUNK: u8 = 0x02;
pub const F_RESUME: u8 = 0x03;
pub const F_FOLDER_RESUME: u8 = 0x04;
pub const F_PAIRING: u8 = 0x05;
pub const F_TEXT: u8 = 0x06;
pub const F_COMPRESS: u8 = 0x08;
pub const F_ECDH: u8 = 0x09;
pub const F_CAPS: u8 = 0x0A;
pub const F_COVER_Q: u8 = 0x0B;
pub const R_RESUME: u8 = 0x10;
pub const R_PAIRING: u8 = 0x15;
pub const R_FOLDER_RESUME: u8 = 0x11;
pub const R_COMPRESS: u8 = 0x18;
pub const R_ECDH: u8 = 0x19;
pub const R_CAPS: u8 = 0x1A;
pub const R_COVER: u8 = 0x1B;

/// 0x09 ECDH 公钥 blob 长度（CNG ECCPUBLICBLOB P-256）。
pub const ECDH_PUBLIC_BYTES: usize = 72;
/// PBKDF2 迭代（C# PairingKdfIterations）。
pub const PAIRING_KDF_ITERS: u32 = 50_000;

/* ============ 名称/路径净化（C# SafeName / SanitizeRelativePath / GetUniqueSavePath 同语义） ============ */

fn is_reserved_name(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or("");
    let up = base.to_ascii_uppercase();
    matches!(up.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (up.len() == 4
            && (up.starts_with("COM") || up.starts_with("LPT"))
            && up.as_bytes()[3].is_ascii_digit())
}

/// C# SafeName：取裸文件名、去尾点/空格、保留名加前缀。
/// 轮 UI-3 安全 P1-1：冒号必须替换——`victim.exe:Zone.Identifier` 会以 NTFS
/// 备用数据流落盘（覆写 MotW，SmartScreen 防线失效；挂隐藏流同向量）。与
/// `cs_sanitize_rel` 的冒号替换同语义（v2 帧 sanitize_name 则直接拒绝）。
pub fn cs_safe_name(raw: &str, fallback: &str) -> String {
    let name = raw.rsplit(['\\', '/']).next().unwrap_or("");
    let name = if name.trim().is_empty() { fallback } else { name };
    let name = name.trim_end_matches(['.', ' ']).replace(':', "_");
    if name.is_empty() {
        return fallback.to_string();
    }
    if is_reserved_name(&name) {
        return format!("_{name}");
    }
    avoid_cache_name(&name)
}

/// 第 9 轮审查 P2-5：落盘名与摘要缓存族撞名时加前缀。
///
/// 缓存/半成品文件只按名字识别（.trft-hash-cache*.txt、.trft-part、
/// .trft-resume）；对端若能把同名文件写进保存目录，重启后 0x04 续点会
/// 采信伪造摘要。加前缀既保留数据，又不占用缓存名。
fn avoid_cache_name(name: &str) -> String {
    if crate::hashcache::is_cache_artifact(name) || crate::hashcache::is_transient_name(name) {
        format!("_{name}")
    } else {
        name.to_string()
    }
}

/// C# SanitizeRelativePath：'/' 归一、去 '..'/'.'、':' 替换、保留名加前缀。
pub fn cs_sanitize_rel(path: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for p in path.replace('\\', "/").trim_matches('/').split('/') {
        let mut seg = if p.trim().is_empty() || p == ".." || p == "." {
            "_".to_string()
        } else {
            p.to_string()
        };
        seg = seg.replace(':', "_").trim_end_matches(['.', ' ']).to_string();
        if seg.is_empty() {
            seg = "_".into();
        } else if is_reserved_name(&seg) {
            seg = format!("_{seg}");
        }
        parts.push(avoid_cache_name(&seg));
    }
    if parts.is_empty() {
        return "_".into();
    }
    parts.join(std::path::MAIN_SEPARATOR_STR)
}

/// C# GetUniqueSavePath：`name` → `name_1.ext` → `name_2.ext` …
/// 探测上限 10000（轮 UI-3 P3-6：攻击者预填同族文件不再把探测拖成无界
/// O(N) 系统调用风暴；耗尽走随机后缀兜底名）。
pub fn cs_unique_save_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let stem = Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    let ext = Path::new(name)
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    for i in 1..=10000u32 {
        let cand = dir.join(format!("{stem}_{i}{ext}"));
        if !cand.exists() {
            return cand;
        }
    }
    dir.join(format!("{stem}.{}{ext}", random_hex(8)))
}

/// 半成品 → 最终名发布（轮 UI-3 安全 P2-1：对齐 v2 publish_part 纪律——
/// Windows rename 静默替换既有目标，探测与发布之间的拷贝窗口可被并发发布者
/// 利用做完整性冒充；hard_link fail-if-exists + 冲突名重取 + 非硬链接卷
/// create_new 拷贝回退）。返回实际落盘路径（冲突时为 `name_N`）。
fn cs_publish(temp: &Path, save_path: &Path) -> io::Result<PathBuf> {
    let dir = save_path.parent().unwrap_or_else(|| Path::new("."));
    let name = save_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let stem = Path::new(&name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&name)
        .to_string();
    let ext = Path::new(&name)
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    for i in 0..10000u32 {
        let cand = if i == 0 {
            save_path.to_path_buf()
        } else {
            dir.join(format!("{stem}_{i}{ext}"))
        };
        // 第 9 轮审查 P2-1：与 v2 发布同纪律——MoveFileExW(WRITE_THROUGH) 一步
        // 换名并落盘目录项。hard_link + remove_file 两步都不保证目录项写透，
        // 掉电后会「数据在、名字丢」，残件 7 天后被孤儿清扫删掉。
        match crate::publish::move_noreplace(temp, &cand) {
            Ok(()) => return Ok(cand),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                // 卷不支持硬链接：create_new 拷贝回退（fail-if-exists 语义不变）。
                // 轮 UI-4 F4：candidate error-guard——拷贝/sync 中途失败先删候选，
                // 不以最终名残留半成品（对齐 publish_part 轮 8 修复）。
                let copied = (|| -> io::Result<()> {
                    let mut src = std::fs::File::open(temp)?;
                    let mut dst = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&cand)?;
                    std::io::copy(&mut src, &mut dst)?;
                    dst.sync_all()?;
                    Ok(())
                })();
                match copied {
                    Ok(()) => {
                        let _ = std::fs::remove_file(temp);
                        return Ok(cand);
                    }
                    Err(e) => {
                        let _ = std::fs::remove_file(&cand);
                        return Err(e);
                    }
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "冲突名解析耗尽",
    ))
}

/// 同步替换发布（0x04 用）：新文件已整文件校验通过 → **原子覆盖**既有目标。
/// 与 cs_publish 的 fail-if-exists 语义不同：0x04 的会话语义就是「用新版本
/// 替换旧版本」（服务端已逐项核对过不 identical）。
/// 纪律（轮 UI-5 P0）：先让新内容就位再让旧档消失——rename 在 Windows
/// （MoveFileEx REPLACE_EXISTING）与 Unix 上都是原子替换；失败时旧档原样保留，
/// **绝不「先删旧档再发布」**（那会在任一步失败时让用户上一版文件凭空消失）。
fn cs_publish_replace(temp: &Path, dest: &Path) -> io::Result<()> {
    // 真机 F2：write-through 覆盖，保证断电后最终名不丢。
    crate::publish::move_replace(temp, dest)
}

/// 0x04 落盘包含性（轮 UI-5 续 3 P2）：0x04 会**复用**既有会话目录（<folder>.<guid8>），
/// 而 save_dir 内预置的 junction/符号链接会把对端可控的相对路径写到保存目录之外
/// （Windows 上 junction 不需要管理员权限；0x00/0x01/0x02/0x03 用随机半成品名或原子
/// 建目录，天然不吃这条路径）。用 canonicalize 解析目标最近的存在祖先，必须落在
/// canonical(save_dir) 前缀内。
fn ensure_contained(save_dir: &Path, target: &Path) -> Result<()> {
    // 第 9 轮审查 P2-17：实现已提升到 receiver，v2 0x01/0x04 与本处共用一份。
    crate::transfer::receiver::ensure_contained(save_dir, target)
}

fn random_hex(n: usize) -> String {
    use rand_core::RngCore;
    let mut b = vec![0u8; n];
    rand_core::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// GUID 键/日志（16B 不透明 → "N" 式十六进制）。
pub fn guid_hex(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/* ============ 0x09 加密（WireCrypto.cs 密钥调度逐字复刻） ============ */

/// CNG ECCPUBLICBLOB magic 字节 = "ECK1" ASCII 序（BCRYPT_ECDH_PUBLIC_P256 的
/// FourCC **大端**存放；数值即 0x45434b31）。真值由 .NET
/// `ECDiffieHellmanCng.PublicKey.ToByteArray()` 实机捕获（2026-11-13）——
/// 首跑钉出两处文档推断偏差：族前缀是 "ECK"（ECDH）而非 "ECC"（ECDSA），
/// 且 magic 按大端序落盘（`to_le_bytes` 会反转成 "1KCE"，CNG 拒收）。
pub const CNG_ECDH_PUBLIC_P256_MAGIC_BYTES: [u8; 4] = [0x45, 0x43, 0x4b, 0x31];

/// CNG blob：[magic "ECK1" 大端 FourCC][cbKey 32 LE][X 32 BE][Y 32 BE] = 72B。
pub fn cng_public_blob(x: &[u8; 32], y: &[u8; 32]) -> [u8; 72] {
    let mut out = [0u8; 72];
    out[..4].copy_from_slice(&CNG_ECDH_PUBLIC_P256_MAGIC_BYTES);
    out[4..8].copy_from_slice(&32u32.to_le_bytes());
    out[8..40].copy_from_slice(x);
    out[40..72].copy_from_slice(y);
    out
}

/// 解析对端 CNG blob → (X, Y) 大端坐标；长度不符 → None（fail-closed）。
pub fn cng_parse_blob(blob: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if blob.len() != ECDH_PUBLIC_BYTES {
        return None;
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&blob[8..40]);
    y.copy_from_slice(&blob[40..72]);
    Some((x, y))
}

/// CNG blob → SEC1 未压缩（p256 PublicKey::from_sec1_bytes 入口，含在曲线校验）。
fn cng_blob_to_public_key(blob: &[u8]) -> Result<p256::PublicKey> {
    let (x, y) = cng_parse_blob(blob).ok_or_else(|| proto("对端 ECDH 公钥长度非法"))?;
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| proto("对端 ECDH 公钥非法（不在曲线上）"))
}

/// PBKDF2-HMAC-SHA1（Rfc2898DeriveBytes 同算法：UTF-8 口令 + 盐 + 迭代）。
pub fn pbkdf2_sha1(password: &str, salt: &[u8], iters: u32, out: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), salt, iters, out);
}

/// DeriveAuthKey（WireCrypto.cs DeriveAuthKey 同构）：
/// authKey = SHA256("tf-ecdh-auth" ‖ material ‖ PBKDF2-HMAC-SHA1(code, SHA256(cPub‖sPub), 50k, 32B))。
/// `material` = ECDiffieHellmanCng.DeriveKeyMaterial 默认 KDF（SHA256(共享点 X 坐标)）。
pub fn cs_derive_auth_key(
    code: &str,
    client_pub: &[u8],
    server_pub: &[u8],
    material: &[u8],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut salt = Sha256::new();
    salt.update(client_pub);
    salt.update(server_pub);
    let salt = salt.finalize();

    let mut psk = [0u8; 32];
    pbkdf2_sha1(code, &salt, PAIRING_KDF_ITERS, &mut psk);

    let mut buf = Vec::with_capacity(12 + material.len() + 32);
    buf.extend_from_slice(b"tf-ecdh-auth");
    buf.extend_from_slice(material);
    buf.extend_from_slice(&psk);
    let mut h = Sha256::new();
    h.update(&buf);
    h.finalize().into()
}

/// confirm = HMAC-SHA256(authKey, label ‖ clientPub ‖ serverPub)。
pub fn cs_confirm(
    auth_key: &[u8; 32],
    label: &str,
    client_pub: &[u8],
    server_pub: &[u8],
) -> [u8; 32] {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(auth_key).expect("HMAC 接受任意长度密钥");
    mac.update(label.as_bytes());
    mac.update(client_pub);
    mac.update(server_pub);
    mac.finalize().into_bytes().into()
}

/// 会话密钥（SessionCrypto.DeriveKey 的 0x09 调用形态 psk=authKey、salt=16×0x00）：
/// master = SHA256(salt ‖ psk)；key = SHA256(master ‖ purpose)。
pub fn cs_session_key(auth_key: &[u8; 32], purpose: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update([0u8; 16]);
    h.update(auth_key);
    let master = h.finalize();
    let mut h2 = Sha256::new();
    h2.update(master);
    h2.update(purpose.as_bytes());
    h2.finalize().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}

/// 单方向写侧（AES-256-CTR 计数器跨段持续 + seq 绑定 MAC——C# EncryptedWireStream 同构）。
pub struct CsEncWrite {
    ctr: Ctr128BE<Aes256>,
    mac_key: [u8; 32],
    seq: i64,
}

impl CsEncWrite {
    pub fn new(key: [u8; 32], mac_key: [u8; 32]) -> Self {
        Self {
            ctr: Ctr128BE::<Aes256>::new(
                generic_array::GenericArray::from_slice(&key),
                generic_array::GenericArray::from_slice(&[0u8; 16]),
            ),
            mac_key,
            seq: 0,
        }
    }

    /// 编码明文为段序列（≤256KB 分段）：[seq i64 LE][len i32 LE][mac16][ct]。
    pub fn encrypt(&mut self, plain: &[u8]) -> Vec<u8> {
        let segs = plain.len().div_ceil(ENC_SEGMENT_MAX).max(1);
        let mut out = Vec::with_capacity(plain.len() + 28 * segs);
        for chunk in plain.chunks(ENC_SEGMENT_MAX) {
            let mut ct = chunk.to_vec();
            self.ctr.apply_keystream(&mut ct);
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&self.mac_key).expect("HMAC key");
            mac.update(&self.seq.to_le_bytes());
            mac.update(&(chunk.len() as i32).to_le_bytes());
            mac.update(&ct);
            let mac16 = &mac.finalize().into_bytes()[..16];
            out.extend_from_slice(&self.seq.to_le_bytes());
            out.extend_from_slice(&(chunk.len() as i32).to_le_bytes());
            out.extend_from_slice(mac16);
            out.extend_from_slice(&ct);
            self.seq += 1;
        }
        out
    }
}

/// 单方向读侧。
pub struct CsEncRead {
    ctr: Ctr128BE<Aes256>,
    mac_key: [u8; 32],
    seq: i64,
    pending: Vec<u8>,
    pos: usize,
}

impl CsEncRead {
    pub fn new(key: [u8; 32], mac_key: [u8; 32]) -> Self {
        Self {
            ctr: Ctr128BE::<Aes256>::new(
                generic_array::GenericArray::from_slice(&key),
                generic_array::GenericArray::from_slice(&[0u8; 16]),
            ),
            mac_key,
            seq: 0,
            pending: Vec::new(),
            pos: 0,
        }
    }

    fn has_pending(&self) -> bool {
        self.pos < self.pending.len()
    }

    fn take(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.pending.len() - self.pos);
        out[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
        self.pos += n;
        n
    }

    /// 从裸流读一段并验密解密入 pending。
    async fn pull<S: AsyncRead + AsyncWrite + Unpin>(&mut self, raw: &mut S) -> io::Result<()> {
        let mut hdr = [0u8; 12];
        raw.read_exact(&mut hdr).await?;
        let seq = i64::from_le_bytes(hdr[..8].try_into().expect("8B"));
        let len = i32::from_le_bytes(hdr[8..12].try_into().expect("4B"));
        if len < 0 || len as usize > ENC_SEGMENT_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "加密段长度非法"));
        }
        let mut mac16 = [0u8; 16];
        raw.read_exact(&mut mac16).await?;
        let mut ct = vec![0u8; len as usize];
        raw.read_exact(&mut ct).await?;
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&self.mac_key).expect("HMAC key");
        mac.update(&seq.to_le_bytes());
        mac.update(&len.to_le_bytes());
        mac.update(&ct);
        let expect = &mac.finalize().into_bytes()[..16];
        if !ct_eq(expect, &mac16) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MAC 校验失败（密钥不符或被篡改）",
            ));
        }
        if seq != self.seq {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "段序号失配（重排/注入）"));
        }
        self.ctr.apply_keystream(&mut ct);
        self.pending = ct;
        self.pos = 0;
        self.seq += 1;
        Ok(())
    }

    /// 按需拉段填满 out（读侧字节流语义）。
    async fn read_via<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        raw: &mut S,
        out: &mut [u8],
    ) -> io::Result<()> {
        let mut done = 0;
        while done < out.len() {
            if !self.has_pending() {
                self.pull(raw).await?;
            }
            done += self.take(&mut out[done..]);
        }
        Ok(())
    }
}

/* ============ 0x08 压缩（WireCompress.cs 段格式） ============ */

const COMP_STORED_FLAG: u32 = 0x8000_0000;

pub struct CsCompWrite;

impl CsCompWrite {
    /// 一个 write_all 调用 = 一个段：[flagsLen u32 LE][payload]（压缩反而变大 → stored）。
    /// **探测门（轮 6 P1，对齐 C# WireCompress.cs:37-54）**：先压缩头部 64KB
    /// 样本，比率 > 0.30 直接 stored——半可压数据整段 deflate 白烧 CPU（C# 注释：
    /// 此类数据 deflate 仅 ~16MB/s）。stored 标志位本就兼容，纯发送端策略。
    pub fn encode(buf: &[u8]) -> Vec<u8> {
        const SAMPLE_BYTES: usize = 64 * 1024;
        const MAX_COMPRESSED_RATIO: f64 = 0.30;
        if buf.len() > SAMPLE_BYTES {
            let mut sample = Vec::with_capacity(SAMPLE_BYTES / 2 + 64);
            let ok = {
                use std::io::Write as _;
                let mut enc = flate2::write::DeflateEncoder::new(
                    &mut sample,
                    flate2::Compression::new(2),
                );
                enc.write_all(&buf[..SAMPLE_BYTES]).is_ok() && enc.finish().is_ok()
            };
            if !ok || sample.len() as f64 > SAMPLE_BYTES as f64 * (1.0 - MAX_COMPRESSED_RATIO) {
                // 样本压缩不动 → 整段直接 stored。
                let mut out = Vec::with_capacity(4 + buf.len());
                out.extend_from_slice(&((buf.len() as u32) | COMP_STORED_FLAG).to_le_bytes());
                out.extend_from_slice(buf);
                return out;
            }
        }
        let mut compressed = Vec::with_capacity(buf.len() / 2 + 64);
        let ok = {
            use std::io::Write as _;
            let mut enc =
                flate2::write::DeflateEncoder::new(&mut compressed, flate2::Compression::new(2));
            enc.write_all(buf).is_ok() && enc.finish().is_ok()
        };
        if ok && buf.len() >= 64 && compressed.len() < buf.len() {
            let mut out = Vec::with_capacity(4 + compressed.len());
            out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            out.extend_from_slice(&compressed);
            out
        } else {
            let mut out = Vec::with_capacity(4 + buf.len());
            out.extend_from_slice(&((buf.len() as u32) | COMP_STORED_FLAG).to_le_bytes());
            out.extend_from_slice(buf);
            out
        }
    }
}

pub struct CsCompRead {
    pending: Vec<u8>,
    pos: usize,
}

impl CsCompRead {
    fn has_pending(&self) -> bool {
        self.pos < self.pending.len()
    }

    fn take(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.pending.len() - self.pos);
        out[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
        self.pos += n;
        n
    }
}

async fn comp_pull_segment<S: AsyncRead + AsyncWrite + Unpin>(
    src: &mut CsSrc<'_, S>,
) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    src.exact(&mut hdr).await?;
    let flags = u32::from_le_bytes(hdr);
    let len = (flags & !COMP_STORED_FLAG) as usize;
    if len == 0 || len > COMP_SEGMENT_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "压缩段长度非法"));
    }
    let mut wire = vec![0u8; len];
    src.exact(&mut wire).await?;
    if flags & COMP_STORED_FLAG != 0 {
        return Ok(wire);
    }
    let dec = flate2::read::DeflateDecoder::new(&wire[..]);
    let mut plain = Vec::new();
    {
        use std::io::Read as _;
        // 边界内解压（轮 6 P1：此前 read_to_end 先无界解压再查长——64MB 恶意段
        // 可膨胀至数十 GB；C# 在 inflate 循环里逐块查上限。take 截在 MAX+1，
        // 超限即非法段——真实段解压后 ≤ COMP_SEGMENT_MAX 恒不触发）。
        let mut capped = dec.take((COMP_SEGMENT_MAX + 1) as u64);
        capped.read_to_end(&mut plain)?;
    }
    if plain.len() > COMP_SEGMENT_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "解压超限（炸弹防线）"));
    }
    Ok(plain)
}

/// 压缩层上游来源（裸流或已解密流）。
enum CsSrc<'a, S> {
    Raw(&'a mut S),
    Enc(&'a mut CsEncRead, &'a mut S),
}

impl<'a, S: AsyncRead + AsyncWrite + Unpin> CsSrc<'a, S> {
    async fn exact(&mut self, out: &mut [u8]) -> io::Result<()> {
        match self {
            CsSrc::Raw(r) => r.read_exact(out).await.map(|_| ()),
            CsSrc::Enc(e, raw) => e.read_via(raw, out).await,
        }
    }
}

/* ============ 组合读写栈 ============ */

pub struct CsWire<S> {
    pub raw: S,
    enc_r: Option<CsEncRead>,
    enc_w: Option<CsEncWrite>,
    comp_r: Option<CsCompRead>,
    comp_w: Option<CsCompWrite>,
    /// 0x0A 能力探询的服务端应答位（未探询 = 0）。
    pub server_caps: u8,
    /// 结尾 1 字节判决 ACK 的承载位置（C# 两种传输不同，见下面两个构造器）。
    ack_on_wire: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> CsWire<S> {
    /// UDT 槽位：结尾 ACK 走**裸流**（装饰器之外；C# TransferUdt 的 udt_recv 同款）。
    pub fn new(raw: S) -> Self {
        Self {
            raw,
            enc_r: None,
            enc_w: None,
            comp_r: None,
            comp_w: None,
            server_caps: 0,
            ack_on_wire: false,
        }
    }

    /// TCP 槽位：结尾 ACK 走**应用层流**（经加密/压缩装饰器；C# ServerWire
    /// CompletionAck 在 TCP 上写 active 装饰流，读侧同在装饰流内）。
    pub fn new_tcp(raw: S) -> Self {
        Self {
            ack_on_wire: true,
            ..Self::new(raw)
        }
    }

    /// ACK 是否经装饰器栈（TCP=true / UDT=false）。
    pub fn ack_on_wire(&self) -> bool {
        self.ack_on_wire
    }

    /// w_* = 本端发送密钥，r_* = 本端接收密钥（调用方按角色推导）。
    pub fn enable_encrypt(
        &mut self,
        w_key: [u8; 32],
        w_mac: [u8; 32],
        r_key: [u8; 32],
        r_mac: [u8; 32],
    ) {
        self.enc_w = Some(CsEncWrite::new(w_key, w_mac));
        self.enc_r = Some(CsEncRead::new(r_key, r_mac));
    }

    pub fn enable_compress(&mut self) {
        self.comp_w = Some(CsCompWrite);
        self.comp_r = Some(CsCompRead {
            pending: Vec::new(),
            pos: 0,
        });
    }

    pub fn encrypted(&self) -> bool {
        self.enc_w.is_some()
    }

    pub fn compressed(&self) -> bool {
        self.comp_w.is_some()
    }

    /// 应用层读（解密 → 解压）。
    pub async fn read_exact(&mut self, out: &mut [u8]) -> io::Result<()> {
        if self.comp_r.is_none() && self.enc_r.is_none() {
            return self.raw.read_exact(out).await.map(|_| ());
        }
        let mut done = 0;
        while done < out.len() {
            if let Some(c) = self.comp_r.as_mut() {
                if c.has_pending() {
                    done += c.take(&mut out[done..]);
                    continue;
                }
                // 压缩层拉新段：上游 = 加密层（若有）否则裸流。
                match self.enc_r.as_mut() {
                    Some(e) => {
                        let mut src = CsSrc::Enc(e, &mut self.raw);
                        let plain = comp_pull_segment(&mut src).await?;
                        c.pending = plain;
                        c.pos = 0;
                    }
                    None => {
                        let mut src = CsSrc::Raw(&mut self.raw);
                        let plain = comp_pull_segment(&mut src).await?;
                        c.pending = plain;
                        c.pos = 0;
                    }
                }
                continue;
            }
            if let Some(e) = self.enc_r.as_mut() {
                if !e.has_pending() {
                    e.pull(&mut self.raw).await?;
                }
                done += e.take(&mut out[done..]);
                continue;
            }
            unreachable!("前置分支已覆盖无层情形");
        }
        Ok(())
    }

    /// 应用层部分读（≤out.len()；续传体按到达进度记账——0x03/0x04 用）。
    /// **P0 修复（轮 6）**：pending 耗尽（跨段边界）时必须按层拉新段——
    /// 此前直接 `raw.read` 穿透装饰器把密文/压缩段当应用字节写进文件，
    /// 0x03 续传体超过首个 256KB 加密段后必炸（小文件/无加密测试掩盖）。
    pub async fn read_some(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.comp_r.is_none() && self.enc_r.is_none() {
            return self.raw.read(out).await;
        }
        // 压缩层优先（pending 有则直取；无则拉新段）。
        if let Some(c) = self.comp_r.as_mut() {
            if c.has_pending() {
                return Ok(c.take(out));
            }
            match self.enc_r.as_mut() {
                Some(e) => {
                    let mut src = CsSrc::Enc(e, &mut self.raw);
                    let plain = comp_pull_segment(&mut src).await?;
                    c.pending = plain;
                    c.pos = 0;
                }
                None => {
                    let mut src = CsSrc::Raw(&mut self.raw);
                    let plain = comp_pull_segment(&mut src).await?;
                    c.pending = plain;
                    c.pos = 0;
                }
            }
            return Ok(c.take(out));
        }
        // 仅加密层。
        if let Some(e) = self.enc_r.as_mut() {
            if !e.has_pending() {
                e.pull(&mut self.raw).await?;
            }
            return Ok(e.take(out));
        }
        unreachable!("前置分支已覆盖无层情形")
    }

    /// 应用层写（压缩 → 加密）。
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(()); // 空载荷过压缩层会产出 len==0 段——C# 读侧判非法（轮 6 P2）
        }
        let payload: Cow<[u8]> = match self.comp_w {
            Some(_) => Cow::Owned(CsCompWrite::encode(buf)),
            None => Cow::Borrowed(buf),
        };
        match self.enc_w.as_mut() {
            Some(e) => {
                let wire = e.encrypt(&payload);
                self.raw.write_all(&wire).await
            }
            None => self.raw.write_all(&payload).await,
        }
    }

    /// 裸流写（结尾 1 字节 ACK 在装饰器之外——UDT 语义）。
    pub async fn raw_write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.raw.write_all(buf).await
    }

    /// 裸流读（客户端结尾 ACK）。
    pub async fn raw_read_exact(&mut self, out: &mut [u8]) -> io::Result<()> {
        self.raw.read_exact(out).await.map(|_| ())
    }

    /// 优雅收尾（UDT SHUTDOWN）。
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.raw.shutdown().await
    }
}

/* ============ 认证前奏 ============ */

fn sha256_code(code: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(code.as_bytes());
    h.finalize().into()
}

/// 客户端 0x09 握手结果。
pub enum CsEcdhOutcome {
    /// 会话已加密（密钥已装入 wire）。
    Encrypted,
    /// 对端无配对码（status 2）——同一连接继续明文。
    Plaintext,
}

/// 客户端 0x09：[0x09][codeHash 32][cPub 72] → [0x19][st][sPub 72][confirmS 32] → [confirmC 32]。
pub async fn cs_client_ecdh<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    code: &str,
) -> Result<CsEcdhOutcome> {
    use p256::ecdh::EphemeralSecret;
    let secret = EphemeralSecret::random(&mut rand_core::OsRng);
    let point = secret.public_key().to_encoded_point(false);
    let mut cx = [0u8; 32];
    let mut cy = [0u8; 32];
    cx.copy_from_slice(point.x().expect("未压缩编码恒有 X"));
    cy.copy_from_slice(point.y().expect("未压缩编码恒有 Y"));
    let c_pub = cng_public_blob(&cx, &cy);

    let mut frame = Vec::with_capacity(1 + 32 + ECDH_PUBLIC_BYTES);
    frame.push(F_ECDH);
    frame.extend_from_slice(&sha256_code(code));
    frame.extend_from_slice(&c_pub);
    wire.raw_write(&frame).await?;

    let mut resp = [0u8; 2 + ECDH_PUBLIC_BYTES + 32];
    tokio::time::timeout(PRELUDE_TIMEOUT, wire.raw_read_exact(&mut resp))
        .await
        .map_err(|_| proto("0x09 握手应答超时（8s）"))?
        .map_err(Error::Io)?;
    if resp[0] != R_ECDH {
        return Err(proto("0x09 应答类型不符"));
    }
    let status = resp[1];
    let s_pub = resp[2..2 + ECDH_PUBLIC_BYTES].to_vec();
    let confirm_s: [u8; 32] = resp[2 + ECDH_PUBLIC_BYTES..].try_into().expect("32B");
    if status == 1 {
        return Err(Error::AuthRejected("配对码被对端拒绝".into()));
    }
    if status == 2 {
        return Ok(CsEcdhOutcome::Plaintext);
    }
    if status != 0 {
        return Err(proto("0x09 应答状态异常"));
    }

    let peer = cng_blob_to_public_key(&s_pub)?;
    let shared = secret.diffie_hellman(&peer);
    // ECDiffieHellmanCng 默认 KDF（Hash/SHA256）：材料 = SHA256(共享点 X 坐标)。
    let material: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(shared.raw_secret_bytes());
        h.finalize().into()
    };
    let auth_key = cs_derive_auth_key(code, &c_pub, &s_pub, &material);
    let expect_s = cs_confirm(&auth_key, "s2c-confirm", &c_pub, &s_pub);
    if !ct_eq(&expect_s, &confirm_s) {
        return Err(Error::AuthRejected("服务端证明校验失败（疑似中间人）".into()));
    }
    let confirm_c = cs_confirm(&auth_key, "c2s-confirm", &c_pub, &s_pub);
    wire.raw_write(&confirm_c).await?;

    // 客户端：发 c2s、收 s2c（与 C# 客户端同构）。
    let c2s_enc = cs_session_key(&auth_key, "c2s-enc");
    let c2s_mac = cs_session_key(&auth_key, "c2s-mac");
    let s2c_enc = cs_session_key(&auth_key, "s2c-enc");
    let s2c_mac = cs_session_key(&auth_key, "s2c-mac");
    wire.enable_encrypt(c2s_enc, c2s_mac, s2c_enc, s2c_mac);
    Ok(CsEcdhOutcome::Encrypted)
}

/// 认证前奏帧体读（30s 静默窗——发半个 0x09/0x05 就挂住的 peer 不得无限占连接与并发闸）。
async fn prelude_read<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    out: &mut [u8],
) -> Result<()> {
    tokio::time::timeout(PRELUDE_IDLE, wire.raw.read_exact(out))
        .await
        .map_err(|_| proto("认证前奏静默超时（30s）"))?
        .map_err(Error::Io)
        .map(|_| ())
}

/// 服务端 0x09（HandleEcdhAuthAsync 同构）。Ok(true) = 已装入加密层；
/// Ok(false) = 对端有码但本端未启用（status 2，同一连接继续明文）。
pub async fn cs_server_ecdh<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    code: &str,
    peer: SocketAddr,
    opts: &RecvOptions,
) -> Result<bool> {
    use p256::ecdh::EphemeralSecret;
    let mut buf = [0u8; 32 + ECDH_PUBLIC_BYTES];
    prelude_read(wire, &mut buf).await?;
    let code_hash = buf[..32].to_vec();
    let c_pub = buf[32..].to_vec();

    if code.is_empty() {
        // 配对未启用：status 2，双方明文续用（C# lenient path）。
        let mut resp = vec![R_ECDH, 2u8];
        resp.extend_from_slice(&[0u8; ECDH_PUBLIC_BYTES]);
        resp.extend_from_slice(&[0u8; 32]);
        wire.raw_write(&resp).await?;
        return Ok(false);
    }
    if opts.pairing_code.is_some() && opts.gate.lock().await.locked(&peer.ip()) {
        let mut resp = vec![R_ECDH, 1u8];
        resp.extend_from_slice(&[0u8; ECDH_PUBLIC_BYTES]);
        resp.extend_from_slice(&[0u8; 32]);
        wire.raw_write(&resp).await?;
        return Err(Error::AuthRejected(format!(
            "{peer}: 配对失败次数过多，已临时锁定"
        )));
    }

    let code_ok = ct_eq(&code_hash, &sha256_code(code));
    let secret = EphemeralSecret::random(&mut rand_core::OsRng);
    let point = secret.public_key().to_encoded_point(false);
    let mut sx = [0u8; 32];
    let mut sy = [0u8; 32];
    sx.copy_from_slice(point.x().expect("未压缩编码恒有 X"));
    sy.copy_from_slice(point.y().expect("未压缩编码恒有 Y"));
    let s_pub = cng_public_blob(&sx, &sy);

    // 共享材料：blob 非法 → 随机哑材料（拒绝应答与成功除 status 外不可区分）。
    let material: [u8; 32] = match cng_blob_to_public_key(&c_pub) {
        Ok(peer_key) => {
            let shared = secret.diffie_hellman(&peer_key);
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(shared.raw_secret_bytes());
            h.finalize().into()
        }
        Err(_) => {
            let mut m = [0u8; 32];
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut m);
            m
        }
    };

    let auth_key = if code_ok {
        cs_derive_auth_key(code, &c_pub, &s_pub, &material)
    } else {
        let mut k = [0u8; 32];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut k);
        k
    };
    let confirm_s = cs_confirm(&auth_key, "s2c-confirm", &c_pub, &s_pub);
    let mut resp = vec![R_ECDH, if code_ok { 0u8 } else { 1u8 }];
    resp.extend_from_slice(&s_pub);
    resp.extend_from_slice(&confirm_s);
    wire.raw_write(&resp).await?;

    if !code_ok {
        // 第 9 轮审查 P3-6：不在握手层记失败——handle_conn_cs 的 conn_settle 会
        // 对 AuthRejected 记一次；两处都记会让锁定阈值从 10 次降到 5 次。
        return Err(Error::AuthRejected("配对码校验失败".into()));
    }
    let mut confirm_c = [0u8; 32];
    prelude_read(wire, &mut confirm_c).await?;
    let expect_c = cs_confirm(&auth_key, "c2s-confirm", &c_pub, &s_pub);
    if !ct_eq(&expect_c, &confirm_c) {
        // 代码对但证明对不上 = 对端持有不同会话密钥（中间人/异常客户端）——
        // 记账方向必须与「配对失败」一致；旧实现误记为 success 会清零锁定计数。
        // 计数交给 conn_settle（P3-6：两处都记会让阈值减半）。
        return Err(Error::AuthRejected("客户端证明校验失败".into()));
    }
    opts.gate.lock().await.success(&peer.ip());

    // 服务端：发 s2c、收 c2s。
    let c2s_enc = cs_session_key(&auth_key, "c2s-enc");
    let c2s_mac = cs_session_key(&auth_key, "c2s-mac");
    let s2c_enc = cs_session_key(&auth_key, "s2c-enc");
    let s2c_mac = cs_session_key(&auth_key, "s2c-mac");
    wire.enable_encrypt(s2c_enc, s2c_mac, c2s_enc, c2s_mac);
    Ok(true)
}

/// 客户端 0x05 明文配对：[0x05][codeHash 32] → [0x15][st]。
pub async fn cs_client_pairing<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    code: &str,
) -> Result<()> {
    let mut frame = vec![F_PAIRING];
    frame.extend_from_slice(&sha256_code(code));
    wire.raw_write(&frame).await?;
    let mut resp = [0u8; 2];
    tokio::time::timeout(PRELUDE_TIMEOUT, wire.raw_read_exact(&mut resp))
        .await
        .map_err(|_| proto("0x05 配对应答超时（8s）"))?
        .map_err(Error::Io)?;
    if resp[0] != R_PAIRING {
        return Err(proto("0x05 应答类型不符"));
    }
    if resp[1] != 0 {
        return Err(Error::AuthRejected("配对码被对端拒绝".into()));
    }
    Ok(())
}

/// 服务端 0x05（HandleAuthAsync 同构）：无配对码时 lenient 接受（status 0）。
pub async fn cs_server_pairing<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    code: &str,
    peer: SocketAddr,
    opts: &RecvOptions,
) -> Result<()> {
    let mut hash = [0u8; 32];
    prelude_read(wire, &mut hash).await?;
    if opts.pairing_code.is_some() && opts.gate.lock().await.locked(&peer.ip()) {
        wire.raw_write(&[R_PAIRING, 1]).await?;
        return Err(Error::AuthRejected(format!(
            "{peer}: 配对失败次数过多，已临时锁定"
        )));
    }
    // 未启用配对（code 为空）时 0x05 一律放行（C# lenient path，等价于无鉴权）。
    let status = if code.is_empty() || ct_eq(&hash, &sha256_code(code)) {
        0u8
    } else {
        1
    };
    wire.raw_write(&[R_PAIRING, status]).await?;
    if status == 1 {
        // 计数交给 conn_settle（P3-6），此处只回状态并报认证失败。
        return Err(Error::AuthRejected("配对码校验失败".into()));
    }
    opts.gate.lock().await.success(&peer.ip());
    Ok(())
}

/* ============ 服务端共享状态（跨连接：分块组装/断点会话/组归属） ============ */

#[derive(Default)]
pub struct CsServerState {
    /// tracker 键 → 组装器（键 "S|<guid>" 或 "<ip>|<name>"）。
    pub trackers: Mutex<HashMap<String, CsChunkTracker>>,
    /// 0x03 断点会话（guid hex → 状态；内存态，重启即失——C# 有落盘，v2 初版不落）。
    pub resume: Mutex<HashMap<String, CsResumeState>>,
    /// 续传会话单飞门（guid hex → TryLock；同名 sid 并发连接第二个即拒——
    /// C# ResumeLocks 同防线；完成路径负责摘除）。
    pub resume_gates: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// 0x04 接收侧摘要缓存（轮 9 P1-5——(path_fnv, size, mtime_ns) → hash；
    /// C# FileHashes 进程内存 Dictionary 同语义：重复同步免整盘重读；不落盘，
    /// 无磁盘产物副作用，服务端重启即失 = 保守方向）。
    pub sync_hashes: Mutex<HashMap<(u64, u64, u64), [u8; 32]>>,
    /// 同一份「已知完整」事实的**落盘**形态（保存目录下的
    /// `.trft-hash-cache-server.txt`，C# server journal 同义）。进程重启后首轮同步
    /// 靠它区分「上一个完整版本」与「断点半成品」；None = 纯内存（单测/无目录）。
    pub sync_journal: Mutex<Option<crate::hashcache::HashCache>>,
    /// 组会话归属（guid → (首个 peer IP, 最后活跃)）。
    pub group_peers: Mutex<HashMap<String, (String, Instant)>>,
    /// 跨连接存活会话（0x02 tracker + 0x03 resume）的声明总量记账
    /// （轮 UI-2 P2-2——对齐 udp.rs DECLARED_CAP 口径：无配对码 LAN 服务器上
    /// 恶意声明大 total 的 set_len 磁盘放大封顶）。
    pub declared_total: std::sync::atomic::AtomicU64,
}

/// 声明总量封顶（64 GiB——与 udp.rs DECLARED_CAP 同口径）。
const CS_DECLARED_CAP: u64 = 64 * 1024 * 1024 * 1024;
/// tracker 空闲回收窗（活动连接分块间隔远小于此——纯死条目阈值）。
const CS_TRACKER_TTL: Duration = Duration::from_secs(15 * 60);
/// 跨连接表条数上限（轮 UI-5 续 5）：declared_total 只封字节不封条数——每帧一个
/// tracker/会话即可无限建条目（每条持半成品句柄/会话名），仅靠 TTL 回收。
const CS_MAX_TRACKERS: usize = 64;
const CS_MAX_RESUME_SESSIONS: usize = 256;
/// 断点会话空闲回收窗（用户驱动的重连间隔友好余量；活跃传输逐块刷新）。
const CS_RESUME_TTL: Duration = Duration::from_secs(30 * 60);
/// 0x04 摘要缓存条目封顶（对齐 hashcache DEGRADED_MAP_CAP 纪律——轮 UI-2 P3-1）。
const CS_SYNC_HASH_CAP: usize = 200_000;

impl CsServerState {
    /// 打开保存目录的落盘摘要 journal。服务端重启后（新进程、新状态）首轮 0x04
    /// 仍能认出「上一轮写完的完整版本」——此前纯内存，重启即失，会把变长的旧档
    /// 当成断点半成品去拼接（TECH-STACK §7.64 残留项）。
    pub fn with_journal(save_dir: &Path, ttl_days: u32) -> Self {
        let st = Self::default();
        let path = crate::hashcache::server_cache_file_for(save_dir);
        *st.sync_journal.lock().expect("同步 journal 锁") =
            Some(crate::hashcache::HashCache::load(&path, ttl_days));
        st
    }
}

/// C# ChunkTracker 等价物：预分配文件 + 区间合并覆盖。
pub struct CsChunkTracker {
    pub save_path: PathBuf,
    pub total: u64,
    file: std::fs::File,
    ranges: Vec<(u64, u64)>, // 闭区间，已合并升序
    pub received: u64,
    /// 最后活跃（轮 UI-2 P2-1：连接中断的 tracker 此前永驻 + 持有文件句柄；
    /// TTL 惰性清扫用）。
    touched: Instant,
}

impl CsChunkTracker {
    fn create(save_path: PathBuf, total: u64) -> io::Result<Self> {
        use std::io::Write;
        // 磁盘预检（轮 UI-2 P2-2——对齐 v2 帧全部接收路径：恶意声明大 total
        // 的 set_len 磁盘放大在此拦下；目录取保存路径父目录）。
        if let Some(dir) = save_path.parent() {
            if !crate::transfer::receiver::space_ok(dir, total) {
                return Err(io::Error::new(io::ErrorKind::StorageFull, "磁盘可用空间不足"));
            }
        }
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&save_path)?;
        f.set_len(total)?;
        f.flush()?;
        Ok(Self {
            save_path,
            total,
            file: f,
            ranges: Vec::new(),
            received: 0,
            touched: Instant::now(),
        })
    }

    /// 写入一个偏移段的数据（**不登记覆盖**）。
    ///
    /// 覆盖登记推迟到尾哈希校验通过之后（commit_range）——实机 C# GUI
    /// 暂停/继续暴露的假成功：一块 2MiB 已整块读入、但尾哈希前连接被取消，
    /// 旧实现已把区间记入覆盖表；对端按 0x0B 查询得「0 缺口」→ 一块不补 →
    /// 客户端报成功，而组装器永远停在未发布状态（.trft-part 残留）。
    fn write_data(&mut self, off: u64, data: &[u8]) -> io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        self.touched = Instant::now();
        let end = off + data.len() as u64;
        if self.is_covered(off, end) {
            return Ok(()); // 已验过的区间：重复补发不重写盘
        }
        self.file.seek(SeekFrom::Start(off))?;
        self.file.write_all(data)
    }

    /// 区间 [start, end) 是否已被**已校验**覆盖表包含。
    fn is_covered(&self, start: u64, end: u64) -> bool {
        self.ranges
            .iter()
            .any(|&(a, b)| a <= start && end <= b + 1)
    }

    /// 尾哈希通过后登记覆盖；返回是否已完整覆盖 [0, total)。
    fn commit_range(&mut self, off: u64, len: u64) -> bool {
        self.touched = Instant::now();
        if len > 0 {
            Self::insert_range(&mut self.ranges, off, off + len - 1);
        }
        self.received = self.ranges.iter().map(|&(a, b)| b - a + 1).sum();
        // 完整 = 单一合并区间且恰覆盖 [0, total)（首尾判据会被中段洞骗过——
        // 轮 1 修复：ranges 已按升序不重叠维护，单区间即无洞）。
        self.ranges.len() == 1 && self.ranges[0] == (0, self.total - 1)
    }

    fn insert_range(ranges: &mut Vec<(u64, u64)>, start: u64, end: u64) {
        // 定位插入点后双向吸收相邻/重叠区间（并集，起点取 min——修复轮 1：
        // 只保 max 端点会吞掉前段的低地址部分）。
        let pos = ranges.partition_point(|r| r.1 + 1 < start);
        let mut merged = (start, end);
        let mut j = pos;
        while j < ranges.len() && ranges[j].0 <= merged.1 + 1 {
            merged.0 = merged.0.min(ranges[j].0);
            merged.1 = merged.1.max(ranges[j].1);
            j += 1;
        }
        let mut k = pos;
        while k > 0 && ranges[k - 1].1 + 1 >= merged.0 {
            merged.0 = merged.0.min(ranges[k - 1].0);
            merged.1 = merged.1.max(ranges[k - 1].1);
            k -= 1;
        }
        ranges.splice(k..j, [(merged.0, merged.1)]);
    }

    /// 覆盖区间 → [start, endExclusive) 对（0x0B 应答格式）。
    fn ranges_exclusive(&self) -> Vec<(u64, u64)> {
        self.ranges.iter().map(|(a, b)| (*a, *b + 1)).collect()
    }
}

pub struct CsResumeState {
    pub save_path: PathBuf,
    pub total: u64,
    pub received: u64,
    pub name: String,
    /// 首个 peer IP（轮 6 P1——外来 peer 猜中/重放 sid 不得续写他人会话；
    /// C# ResumeLocks + state.Peer 同防线）。
    pub peer_ip: String,
    /// 最后活跃（轮 UI-2 P2-1：中断会话 TTL 清扫用——活跃传输逐块刷新）。
    pub touched: Instant,
    /// 完整性已验证（尾哈希 + 可选全文件哈希通过）。**只有 verified 才允许回
    /// status 2「已完整」**：体收满但尾哈希前断连时 received == total 而未验证，
    /// 下一连接必须整组重传（轮 UI-5 P1：此前 Done 分支零校验 = 未验证即成功）。
    pub verified: bool,
    /// 验证完成时客户端携带的整文件哈希（无则 None）。0x03 的「已完整」重问
    /// 必须与它比对——只核长度的旧实现会把「同尺寸改内容」判成功（轮 9 P1-3）。
    pub verified_hash: Option<[u8; 32]>,
    /// 是否仍持有声明量（declare 记账）。完成即释放——否则已验证会话在 TTL
    /// 窗口内持续占用 64 GiB 封顶额度，大批量同步会被误拒（轮 UI-5 自查）。
    pub declared_held: bool,
}

/* ============ 跨连接会话纪律：声明总量记账 + TTL 惰性清扫（轮 UI-2 P2-1/P2-2） ============ */

/// 声明总量记账（fetch_add / fetch_sub 对称；溢出方向封顶拒绝）。
fn cs_declare(state: &CsServerState, amount: u64) -> Result<()> {
    use std::sync::atomic::Ordering;
    // CAS 循环防并发超额（fetch_add 会瞬时越界）。
    let mut cur = state.declared_total.load(Ordering::Relaxed);
    loop {
        let Some(next) = cur.checked_add(amount) else {
            return Err(Error::Rejected("声明总量超限".into()));
        };
        if next > CS_DECLARED_CAP {
            return Err(Error::Rejected(format!(
                "声明总量超过 {} GiB 上限",
                CS_DECLARED_CAP / (1 << 30)
            )));
        }
        match state.declared_total.compare_exchange_weak(
            cur,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(()),
            Err(actual) => cur = actual,
        }
    }
}

/// 会话侧声明量收尾（幂等）：只有仍持有时才减账——完成已释放的会话不重复扣。
fn release_resume_declared(state: &CsServerState, st: &mut CsResumeState) {
    if st.declared_held {
        cs_release_declared(state, st.total);
        st.declared_held = false;
    }
}

fn cs_release_declared(state: &CsServerState, amount: u64) {
    use std::sync::atomic::Ordering;
    state
        .declared_total
        .fetch_sub(amount, Ordering::Relaxed); // 记账对称：不会下溢（只有 declare 过才 release）
}

/// 惰性清扫：在 0x02/0x03 处理器入口调用。
/// - tracker 空闲 > CS_TRACKER_TTL：摘表（drop 句柄）+ 释放声明量 + 删半成品
///   （轮 UI-4 F3：组装器已改 `.trft-part` 半成品名——清扫可安全回收，时间
///   维度不再绕过磁盘封顶；重建路径本就截断重建，无残值损失）。
/// - resume 空闲 > CS_RESUME_TTL：摘会话 + 摘门 + 释放声明量（残件文件保留，
///   会话失忆后客户端重连按新传走 cs_unique_save_path，不覆盖旧残件）。
/// - group_peers 同窗清扫 + 硬上限（轮 UI-4 F9：伪造 guid 洪水防表膨胀）。
fn cs_sweep_stale(state: &CsServerState) {
    let now = Instant::now();
    {
        let mut t = state.trackers.lock().expect("tracker 锁");
        let stale: Vec<String> = t
            .iter()
            .filter(|(_, tr)| now.duration_since(tr.touched) > CS_TRACKER_TTL)
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            if let Some(tr) = t.remove(&k) {
                cs_release_declared(state, tr.total);
                let _ = std::fs::remove_file(&tr.save_path);
            }
        }
        // 条数上限：超出按 touched 最旧逐出（与 TTL 同序）。被逐连接随后会得到
        // 显式错误（组装器缺失 → 整组重发），不会假成功。
        while t.len() >= CS_MAX_TRACKERS {
            let Some(k) = t.iter().min_by_key(|(_, tr)| tr.touched).map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(tr) = t.remove(&k) {
                cs_release_declared(state, tr.total);
                let _ = std::fs::remove_file(&tr.save_path);
            }
        }
    }
    {
        let mut rs = state.resume.lock().expect("resume 锁");
        let stale: Vec<String> = rs
            .iter()
            .filter(|(_, st)| now.duration_since(st.touched) > CS_RESUME_TTL)
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            if let Some(mut st) = rs.remove(&k) {
                release_resume_declared(state, &mut st);
                state.resume_gates.lock().expect("resume 门锁").remove(&k);
            }
        }
        // 同一上限：只摘会话/释放声明量，**不删文件**（可能是已验证交付的文件）——
        // 与 TTL 路径一致，残件由孤儿清扫兜底。
        while rs.len() >= CS_MAX_RESUME_SESSIONS {
            let Some(k) = rs.iter().min_by_key(|(_, st)| st.touched).map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(mut st) = rs.remove(&k) {
                release_resume_declared(state, &mut st);
                state.resume_gates.lock().expect("resume 门锁").remove(&k);
            }
        }
    }
    state
        .group_peers
        .lock()
        .expect("组归属锁")
        .retain(|_, (_, ts)| now.duration_since(*ts) < CS_RESUME_TTL);
    // 硬上限（confirm_seen 同纪律）：TTL 窗口内洪水仍可能有界膨胀。
    {
        let mut owners = state.group_peers.lock().expect("组归属锁");
        if owners.len() > 4096 {
            let mut v: Vec<_> = owners.drain().collect();
            v.sort_by_key(|(_, (_, ts))| *ts);
            v.truncate(2048);
            owners.extend(v);
        }
    }
}


/// 文件 mtime 纳秒（缓存键；§7.31 纳秒粒度口径——秒粒度同秒同长改写漏判）。
fn mtime_nanos(p: &Path) -> u64 {
    std::fs::metadata(p)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// 0x04 接收侧哈希核对：进程缓存优先，miss 才读盘并回填（轮 9 P1-5——
/// 重复同步此前整盘重读，差量同步核心收益被接收端吃掉；C# HaveIdenticalAsync
/// 经 FileHashes 免读盘同款）。
///
/// 读盘失败返回 None 且**不写缓存/journal**：旧实现 unwrap_or_default() 把
/// 「读不到」当成「内容不符」并登记零哈希（轮 9 审查 P1-4）。
async fn sync_hash_of(state: &Arc<CsServerState>, p: &Path, size: u64) -> Option<[u8; 32]> {
    let key_path = fnv1a(p.to_string_lossy().as_bytes());
    let mtime = mtime_nanos(p);
    let key = (key_path, size, mtime);
    if let Some(h) = state.sync_hashes.lock().expect("同步缓存锁").get(&key) {
        return Some(*h);
    }
    let path_str = p.to_string_lossy().to_string();
    // 进程内未命中 → 查落盘 journal（服务端重启后的首轮：上一轮写完的完整版本
    // 仍在这里，不必重读盘）。
    if let Some(h) = state
        .sync_journal
        .lock()
        .expect("同步 journal 锁")
        .as_ref()
        .and_then(|j| j.get(&path_str, size, mtime))
    {
        let mut cache = state.sync_hashes.lock().expect("同步缓存锁");
        if cache.len() >= CS_SYNC_HASH_CAP {
            cache.clear();
        }
        cache.insert(key, h);
        return Some(h);
    }
    // 整文件哈希可能很大（0x04 冷文件），放阻塞池——否则占住 tokio worker。
    let p_owned = p.to_path_buf();
    let h = tokio::task::spawn_blocking(move || crate::hash::sha256_file(&p_owned))
        .await
        .ok()?
        .ok()?;
    let mut cache = state.sync_hashes.lock().expect("同步缓存锁");
    // 条目封顶（轮 UI-2 P3-1——对齐 hashcache DEGRADED_MAP_CAP：百万文件级
    // 目录反复同步此前无界累积；满即清空重建，miss 只多一次读盘）。
    if cache.len() >= CS_SYNC_HASH_CAP {
        cache.clear();
    }
    cache.insert(key, h);
    drop(cache);
    // 现算即「已核对完整」——登记落盘（C# VerifyFullHashFile → StoreIfUnchanged 同义）。
    if let Some(j) = state.sync_journal.lock().expect("同步 journal 锁").as_mut() {
        j.insert(&path_str, size, mtime, h);
    }
    Some(h)
}

/// 记录某路径当前 (size, mtime) 的完整摘要（C# `FileHashes.Store` 同义：写完/校验完
/// 才登记，键取登记时刻的磁盘事实——与 `sync_hash_of` 的键构造同式）。
fn remember_sync_hash(state: &Arc<CsServerState>, p: &Path, hash: &[u8; 32]) {
    let Ok(md) = std::fs::metadata(p) else {
        return;
    };
    let key = (
        fnv1a(p.to_string_lossy().as_bytes()),
        md.len(),
        mtime_nanos(p),
    );
    let mut cache = state.sync_hashes.lock().expect("同步缓存锁");
    if cache.len() >= CS_SYNC_HASH_CAP {
        cache.clear();
    }
    cache.insert(key, *hash);
    drop(cache);
    // 追加一行到落盘 journal（写失败静默退化为内存缓存，与 hashcache 同纪律）。
    if let Some(j) = state.sync_journal.lock().expect("同步 journal 锁").as_mut() {
        j.insert(&p.to_string_lossy(), md.len(), key.2, *hash);
    }
}

/// 0x04 续点判定：当前 (size, mtime) 已被本进程登记过摘要 = 盘上是某个**完整版本**
/// （C# `KnownComplete` / `FileHashes.Knows` 同义）。短于发送端的已知完整文件是
/// 「旧版本」，不能当断点前缀拼接；只有从未登记过的短文件才按半成品续传。
fn known_complete(state: &Arc<CsServerState>, p: &Path, size: u64) -> bool {
    let mtime = mtime_nanos(p);
    let key = (fnv1a(p.to_string_lossy().as_bytes()), size, mtime);
    if state
        .sync_hashes
        .lock()
        .expect("同步缓存锁")
        .contains_key(&key)
    {
        return true;
    }
    // 跨进程事实：进程重启后靠 journal 仍能认出「上一轮写完的完整版本」。
    state
        .sync_journal
        .lock()
        .expect("同步 journal 锁")
        .as_ref()
        .map(|j| j.get(&p.to_string_lossy(), size, mtime).is_some())
        .unwrap_or(false)
}

/* ============ 服务端连接处理 ============ */

#[derive(Default, Debug)]
pub struct CsOutcome {
    pub success: bool,
    pub is_chunked: bool,
    /// 0x02 本次连接把组装器补满并完成发布（--count 只在此判定为「收到一份」，
    /// 与 v2 帧 0x02 的 INCOMPLETE 不计入口径一致）。
    pub chunk_complete: bool,
    /// 0x03 的终态应答（0x10）即判决——不再发裸 ACK。
    pub has_own_final_response: bool,
    pub rejected: bool,
}

/// 连接的 C# 方言入口（serve_udt_on / serve_tcp_on 每连接调用）。
/// ack_on_wire：结尾判决 ACK 的承载位置（TCP = 装饰器流内；UDT = 裸流带外）。
pub(crate) async fn handle_conn_cs<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    peer: SocketAddr,
    opts: &RecvOptions,
    served: Arc<AtomicU64>,
    state: Arc<CsServerState>,
    ack_on_wire: bool,
) -> Result<()> {
    let _permit = conn_precheck(peer, opts).await?;
    let (r, outcome, mut stream) = conn_cs_inner(stream, peer, opts, &state, ack_on_wire).await;
    // 限量模式计数口径与 v2 帧同：只计**真实完成**的连接——被拒/失败/0x02 的
    // 中间块（INCOMPLETE）都不得消耗名额（否则 --count 1 的分块发送收首块即退）。
    let handled = if r.is_ok()
        && outcome.success
        && (!outcome.is_chunked || outcome.chunk_complete)
    {
        1
    } else {
        0
    };
    // 收尾等待（与 v2 handle_conn 同纪律）：本连接即最后一单（--count 达标）时
    // 进程即将退出，直接 close 会在 Windows 上以 RST 掐断对端读取终态字节，
    // C# 报 "Connection closed before the receiver acknowledged"（文件与哈希都对，
    // 纯对端误报）。读尽残余并等其 FIN，5s 兜底；只等达标的那一次——并发分块的
    // 其它连接若也等，会与串行 accept 互锁。
    // 仅 0x00/0x01/0x06（对端走 ConfirmCompletionAsync 读流内终态）需要等待；
    // 分块 0x02 的客户端不用该路径，等待反而会挡住后续块连接（串行 accept）。
    if handled > 0
        && !outcome.is_chunked
        && !outcome.has_own_final_response
        && opts
            .max_count
            .is_some_and(|m| served.load(std::sync::atomic::Ordering::Relaxed) + handled >= m)
    {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let mut b = [0u8; 256];
            loop {
                match stream.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        })
        .await;
    }
    conn_settle(&r, handled, peer, opts, &served).await;
    r
}

async fn conn_cs_inner<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    peer: SocketAddr,
    opts: &RecvOptions,
    state: &Arc<CsServerState>,
    ack_on_wire: bool,
) -> (Result<()>, CsOutcome, S) {
    let mut wire = if ack_on_wire {
        CsWire::new_tcp(stream)
    } else {
        CsWire::new(stream)
    };
    let mut authed = false;
    let mut confirmed = false;
    let mut per_file_skip = false;
    let mut chunk_sessions = false;
    let mut outcome = CsOutcome::default();

    let res = run_conn(
        &mut wire,
        peer,
        opts,
        state,
        &mut authed,
        &mut confirmed,
        &mut per_file_skip,
        &mut chunk_sessions,
        &mut outcome,
    )
    .await;
    // 认证前奏阶段的传输中断折算为认证失败（轮 UI-5 P1 口径，v2 帧同纪律）：
    // 否则攻击者「发 1 字节 0x09 就断」即可无限烧 50k 轮 PBKDF2 并绕过配对锁定。
    let res = match res {
        Err(e) if !authed && opts.pairing_code.is_some() => {
            Err(crate::transfer::receiver::pairing_phase_err(e, true))
        }
        other => other,
    };

    // 结尾 1 字节判决。0x03 自带终态应答（0x10），不发（与 C# 同）。
    // 承载位置随传输：UDT 裸流（装饰器之外）/ TCP 应用层流（装饰器之内）。
    let ack = if outcome.rejected {
        Some(0x00u8)
    } else if outcome.is_chunked || !outcome.has_own_final_response {
        Some(if outcome.success { 0x01 } else { 0x00 })
    } else {
        None
    };
    if let Some(b) = ack {
        if wire.ack_on_wire() {
            let _ = wire.write_all(&[b]).await;
        } else {
            let _ = wire.raw_write(&[b]).await;
        }
    }
    let _ = wire.shutdown().await;
    (res, outcome, wire.raw)
}

#[allow(clippy::too_many_arguments)]
async fn run_conn<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    peer: SocketAddr,
    opts: &RecvOptions,
    state: &Arc<CsServerState>,
    authed: &mut bool,
    confirmed: &mut bool,
    per_file_skip: &mut bool,
    chunk_sessions: &mut bool,
    outcome: &mut CsOutcome,
) -> Result<()> {
    let code = opts.pairing_code.clone().unwrap_or_default();

    // ---- 前奏循环（任意顺序的 0x05/0x09/0x08/0x0A 混合，≤8 帧——C# MaxPreludeFrames）----
    // **30s 静默窗（轮 9 P1-4，对齐 C# SetTimeout(30000,30000)）**：前奏是纯
    // 静默间隙——发一半即停的 peer 此前可无限占用连接与并发闸（活而静默）。
    let mut prelude_frames = 0u32;
    let transfer_type = loop {
        let mut t = [0u8; 1];
        tokio::time::timeout(PRELUDE_IDLE, wire.read_exact(&mut t))
            .await
            .map_err(|_| proto("前奏静默超时（30s）"))??;
        let t = t[0];
        match t {
            F_ECDH => {
                prelude_frames += 1;
                if prelude_frames > 8 {
                    return Err(proto("前奏帧数超限"));
                }
                let code_ref = opts.pairing_code.clone().unwrap_or_default();
                // RecvOptions.encrypt=false：本端明确拒绝 0x09 加密升级（v2 同口径，
                // 规格 §5.1 的开关在 C# 方言槽位同样必须生效——不得静默加密/明文续）。
                if !opts.encrypt {
                    let mut resp = vec![R_ECDH, 1u8];
                    resp.extend_from_slice(&[0u8; ECDH_PUBLIC_BYTES]);
                    resp.extend_from_slice(&[0u8; 32]);
                    let _ = wire.raw_write(&resp).await;
                    outcome.rejected = true;
                    return Err(Error::AuthRejected(format!("{peer}: 本端未启用加密（拒绝 0x09）")));
                }
                if cs_server_ecdh(wire, &code_ref, peer, opts).await? {
                    *authed = true;
                }
            }
            F_PAIRING => {
                prelude_frames += 1;
                if prelude_frames > 8 {
                    return Err(proto("前奏帧数超限"));
                }
                cs_server_pairing(wire, &code, peer, opts).await?;
                *authed = true;
            }
            F_COMPRESS => {
                prelude_frames += 1;
                if prelude_frames > 8 {
                    return Err(proto("前奏帧数超限"));
                }
                // 认证前不得协商压缩（配对必需的服务端——C# 同防线）。
                if !*authed && !code.is_empty() {
                    outcome.rejected = true;
                    return Err(Error::Rejected("认证前收到压缩协商帧".into()));
                }
                let mut pad = [0u8; 16];
                wire.read_exact(&mut pad).await?;
                // 应答走装饰器栈（write_all）：0x08 可能在 0x09 之后到达——此时
                // 加密层已装入，C# 客户端经加密流读 0x18，裸写会被 C# 的段格式
                // 解析卡死到 8s 响应窗超时（实机 F2 排障实录，TECH-STACK §7.31）。
                // 压缩层此刻尚未装入（enable_compress 在应答之后），无叠层问题。
                if opts.compress {
                    wire.write_all(&[R_COMPRESS, 0]).await?;
                    wire.enable_compress();
                } else {
                    // 状态非 0：对端继续明文（C# 客户端宽容降级，不重连）。
                    wire.write_all(&[R_COMPRESS, 1]).await?;
                }
            }
            F_CAPS => {
                prelude_frames += 1;
                if prelude_frames > 8 {
                    return Err(proto("前奏帧数超限"));
                }
                if !*authed && !code.is_empty() {
                    outcome.rejected = true;
                    return Err(Error::Rejected("认证前收到能力帧".into()));
                }
                let mut caps = [0u8; 1];
                wire.read_exact(&mut caps).await?;
                // 能力位：bit0 = 0x04 逐文件跳过清单，bit1 = 0x02 组会话 + 0x0B。
                // 默认全开（C# 服务端恒 0x03）；RecvOptions 关闭对应特性时置 0
                // ——客户端据此跳过该特性（与 C# 客户端「bit 缺失即不用」同语义）。
                let server_caps = (opts.enable_resume as u8) | ((opts.enable_chunked as u8) << 1);
                // 同 0x08：0x1A 应答必须经装饰器栈（此时可能已压缩+加密）。
                wire.write_all(&[R_CAPS, server_caps]).await?;
                *per_file_skip = caps[0] & 0x01 != 0;
                *chunk_sessions = caps[0] & 0x02 != 0;
            }
            other => break other,
        }
    };

    // ---- 配对门（要求配对但前奏里无认证 → 明文拒绝应答 + NACK）----
    if !*authed && !code.is_empty() {
        let _ = wire.raw_write(&[R_PAIRING, 1]).await;
        outcome.rejected = true;
        return Err(Error::AuthRejected(format!("{peer}: 需要配对码")));
    }

    // ---- 确认门（每连接一次）----
    confirm_once(peer, opts, confirmed).await?;

    // ---- 帧分发 ----
    let save_dir = resolve_save_dir(opts, peer.ip());
    tokio::fs::create_dir_all(&save_dir).await.ok();
    let mut limiter = if opts.recv_limit_bps > 0 {
        Some(TokenBucket::new(opts.recv_limit_bps))
    } else {
        None
    };
    let hub = opts.progress.clone();
    let limiter_ref = &mut limiter;

    // 特性门（RecvOptions.enable_chunked/enable_resume=false 模拟旧对端/显式关闭）：
    // 关闭的帧集一律按「对端不认识该帧」处理——拒收并断连，客户端据此走降级路径。
    if !opts.enable_chunked && matches!(transfer_type, F_CHUNK | F_COVER_Q) {
        outcome.rejected = true;
        return Err(Error::Rejected("本端未启用分块帧（0x02/0x0B）".into()));
    }
    if !opts.enable_resume && matches!(transfer_type, F_RESUME | F_FOLDER_RESUME) {
        outcome.rejected = true;
        return Err(Error::Rejected("本端未启用续传帧（0x03/0x04）".into()));
    }
    match transfer_type {
        F_SINGLE => {
            handle_single_file(wire, peer, opts, &save_dir, confirmed, limiter_ref, hub.as_ref())
                .await?;
            outcome.success = true;
        }
        F_FOLDER => {
            handle_folder(wire, peer, opts, &save_dir, confirmed, limiter_ref, hub.as_ref()).await?;
            outcome.success = true;
        }
        F_CHUNK => {
            outcome.is_chunked = true;
            let (ok, complete) = handle_chunk(
                wire,
                peer,
                opts,
                state,
                &save_dir,
                *chunk_sessions,
                confirmed,
                limiter_ref,
                hub.as_ref(),
            )
            .await?;
            outcome.success = ok;
            outcome.chunk_complete = complete;
        }
        F_RESUME => {
            let ok = handle_resume(
                wire,
                peer,
                opts,
                state,
                &save_dir,
                confirmed,
                limiter_ref,
                hub.as_ref(),
            )
            .await?;
            outcome.success = ok;
            outcome.has_own_final_response = true;
        }
        F_FOLDER_RESUME => {
            let (ok, _bytes, _files) = handle_folder_resume(
                wire,
                peer,
                opts,
                state,
                &save_dir,
                *per_file_skip,
                confirmed,
                limiter_ref,
                hub.as_ref(),
            )
            .await?;
            outcome.success = ok;
        }
        F_TEXT => {
            handle_text(wire, peer, opts).await?;
            outcome.success = true;
        }
        F_COVER_Q => {
            if !*chunk_sessions {
                outcome.rejected = true;
                return Err(Error::Rejected("未协商分块组会话，拒绝 0x0B".into()));
            }
            let mut id = [0u8; 16];
            wire.read_exact(&mut id).await?;
            let gid_hex = guid_hex(&id);
            let key = format!("S|{gid_hex}");
            // 组归属校验（轮 6 P1，对齐 C# WireProtocol.cs:662-671 ChunkSessionPeers——
            // 此前任何认证过的 peer 可查询他人 group 的已收区间）。归属表以**裸
            // guidHex** 为键（handle_chunk 插入时同键），带 "S|" 前缀的是组装器键。
            {
                let owners = state.group_peers.lock().expect("组归属锁");
                match owners.get(&gid_hex) {
                    Some((owner, _)) if *owner != peer.ip().to_string() => {
                        drop(owners);
                        outcome.rejected = true;
                        return Err(Error::Rejected("分块组会话属于其他设备".into()));
                    }
                    _ => {}
                }
            }
            let ranges = state
                .trackers
                .lock()
                .expect("tracker 锁")
                .get(&key)
                .map(|t| t.ranges_exclusive())
                .unwrap_or_default();
            let mut resp = vec![R_COVER];
            resp.extend_from_slice(&(ranges.len() as i32).to_le_bytes());
            for (a, b) in ranges {
                resp.extend_from_slice(&(a as i64).to_le_bytes());
                resp.extend_from_slice(&(b as i64).to_le_bytes());
            }
            wire.write_all(&resp).await?;
            outcome.success = true;
        }
        other => {
            outcome.rejected = true;
            return Err(Error::Rejected(format!("未知传输类型 0x{other:02X}")));
        }
    }
    Ok(())
}


/// TCP 槽位的 C# 方言 serve（互通改造：TCP 应用层与 UDT 同为 cswire）。
/// CsServerState 提到 serve 层——分块组装器 / 断点会话 / 组归属跨连接共享，
/// 与 serve_udt_on 同构（每连接只拿 Arc）。
pub async fn serve_tcp_on(listener: tokio::net::TcpListener, opts: RecvOptions) -> Result<()> {
    cleanup_part_orphans(&opts.save_dir);
    crate::transfer::resume::cleanup_resume_orphans(&opts.save_dir);
    let served = Arc::new(AtomicU64::new(0));
    // 落盘 journal：服务端重启后首轮 0x04 仍能区分「旧完整版本」与「断点半成品」。
    let state = Arc::new(CsServerState::with_journal(
        &opts.save_dir,
        opts.hash_cache_days,
    ));
    match opts.max_count {
        // 限量模式（CLI --count）：串行处理，收满即停（与 v2 帧同口径：只有
        // 真实完成的一次传输才计数——0x02 的中间块不计）。
        Some(max) => loop {
            if served.load(std::sync::atomic::Ordering::Relaxed) >= max {
                return Ok(());
            }
            match listener.accept().await {
                Ok((s, peer)) => {
                    tune_tcp(&s);
                    if let Err(e) =
                        handle_conn_cs(s, peer, &opts, served.clone(), state.clone(), true).await
                    {
                        eprintln!("[连接失败] {e}");
                    }
                }
                Err(e) => return Err(Error::Io(e)),
            }
        },
        // 常驻模式：并发处理（并发闸在 conn_precheck 内）。
        None => {
            let mut set = tokio::task::JoinSet::new();
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        tune_tcp(&stream);
                        // 第 9 轮审查 P2-20：连接任务 panic 此前被静默吞掉——
                        // 接收器看似在跑，实际可能每次连接都失败。至少记到 stderr。
                        while let Some(res) = set.try_join_next() {
                            if let Err(e) = res {
                                eprintln!("[连接任务异常] {e}");
                            }
                        }
                        let o = opts.clone();
                        let counter = served.clone();
                        let st = state.clone();
                        set.spawn(async move {
                            if let Err(e) =
                                handle_conn_cs(stream, peer, &o, counter, st, true).await
                            {
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

/* ============ 帧处理器（服务端收） ============ */

type CsReporter = Option<crate::progress::Reporter>;

/// 接收进度卡注册（带对端 IP——GUI 设备徽标依赖；v2 帧 record 同口径）。
fn register_recv(
    hub: Option<&crate::progress::ProgressHub>,
    peer: SocketAddr,
    name: String,
    total: u64,
) -> CsReporter {
    hub.map(|h| {
        let r = h.register("recv", name, total);
        r.set_peer(&peer.ip().to_string());
        r
    })
}

/// 收一个载荷到 `<save_path>.part-<rnd>` 临时文件并校验尾随 SHA-256；
/// 哈希过了才换名（C# .part-<guid> 同策略，防半成品占名）。返回内容哈希。
async fn receive_payload<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    save_path: &Path,
    size: u64,
    display: &str,
    limiter: &mut Option<TokenBucket>,
    reporter: &CsReporter,
) -> Result<[u8; 32]> {
    use sha2::Digest;
    if let Some(r) = reporter {
        r.set_total(size);
    }
    // 半成品命名：`<原名>.<hex>.trft-part`（轮 UI-2 P2-1——旧命名 `.part-<hex>`
    // 不匹配任何孤儿清扫器，中断残件永久残留用户目录；现被三个
    // cleanup_part_orphans 同口径覆盖，7 天回收）。
    let mut temp_os = save_path.as_os_str().to_os_string();
    temp_os.push(format!(".{}.trft-part", random_hex(8)));
    let temp = PathBuf::from(temp_os);
    // 失败守卫（轮 UI-5 P0）：任何 Err 路径（断连/哈希失配/拷贝回退失败）都清掉
    // 内层半成品——成功时它已被 cs_publish 改名移走，守卫为空操作。
    let _part_guard = crate::transfer::receiver::PartGuard(temp.clone());
    // 磁盘预检（轮 UI-2 P2-2——对齐 v2 帧接收路径：宣大 size 的截断放大拦下）。
    if let Some(dir) = save_path.parent() {
        if !crate::transfer::receiver::space_ok(dir, size) {
            return Err(Error::Io(io::Error::new(io::ErrorKind::StorageFull, "磁盘可用空间不足")));
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp)?;
    let mut hasher = sha2::Sha256::new();
    let mut remaining = size;
    let mut buf = vec![0u8; CS_RECV_BUF];
    // 首块静默窗（轮 9 P1-4）：宣大 size 后不发体的 peer 不得占闸——首块
    // 30s；后续块保持无窗（限速 <68KB/s 的合法慢速兼容，30s 会误断）。
    let mut first_block = true;
    {
        use std::io::Write as _;
        while remaining > 0 {
            let n = buf.len().min(remaining as usize);
            if first_block {
                tokio::time::timeout(PRELUDE_IDLE, wire.read_exact(&mut buf[..n]))
                    .await
                    .map_err(|_| proto("传输体首块静默超时（30s）"))??;
                first_block = false;
            } else {
                wire.read_exact(&mut buf[..n]).await?;
            }
            if let Some(l) = limiter {
                l.acquire(n as u64).await;
            }
            hasher.update(&buf[..n]);
            f.write_all(&buf[..n])?;
            remaining -= n as u64;
            if let Some(r) = reporter {
                r.add(n as u64);
            }
        }
    }
    // 回执前落盘（与 0x02/0x03 及 v2 接收路径同纪律）：否则 ACK 只代表
    // 「进了页缓存」——掉电后对端已收到成功的文件可能变空/截断。
    f.sync_all()?;
    let mut got = [0u8; 32];
    wire.read_exact(&mut got).await?;
    let computed: [u8; 32] = hasher.finalize().into();
    if !ct_eq(&got, &computed) {
        // 半成品由 _part_guard 兜底清理（与所有 Err 路径同口径）。
        return Err(Error::Rejected(format!("{display}: SHA-256 校验失败")));
    }
    cs_publish(&temp, save_path).map_err(Error::Io)?;
    Ok(computed)
}

async fn handle_single_file<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    peer: SocketAddr,
    opts: &RecvOptions,
    save_dir: &Path,
    confirmed: &mut bool,
    limiter: &mut Option<TokenBucket>,
    hub: Option<&crate::progress::ProgressHub>,
) -> Result<u64> {
    let mut hdr = [0u8; 12];
    wire.read_exact(&mut hdr).await?;
    let size = i64::from_le_bytes(hdr[..8].try_into().expect("8B"));
    let name_len = i32::from_le_bytes(hdr[8..12].try_into().expect("4B"));
    if size < 0 || size as u64 > CS_MAX_TRANSFER || name_len <= 0 || name_len as usize > CS_MAX_NAME {
        return Err(proto("0x00 头非法"));
    }
    let mut name_buf = vec![0u8; name_len as usize];
    wire.read_exact(&mut name_buf).await?;
    let name = cs_safe_name(&String::from_utf8_lossy(&name_buf), "received_file");
    confirm_once(peer, opts, confirmed).await?;
    let reporter = register_recv(hub, peer, name.clone(), size as u64);
    let base = save_dir.join(&name);
    let save_path = cs_unique_save_path(save_dir, &name);
    let hash = receive_payload(wire, &save_path, size as u64, &name, limiter, &reporter).await?;
    // Skip 策略：与同名同长且同哈希的既有文件相同 → 丢弃新副本（C# SkipDuplicateFiles）。
    if opts.duplicate == DuplicatePolicy::Skip && save_path != base {
        let dup = std::fs::metadata(&base)
            .map(|m| m.len() == size as u64)
            .unwrap_or(false)
            && match tokio::task::spawn_blocking({
                let b = base.clone();
                move || crate::hash::sha256_file(&b)
            })
            .await
            {
                Ok(Ok(x)) => ct_eq(&x, &hash),
                _ => false,
            };
        if dup {
            let _ = std::fs::remove_file(&save_path);
            if let Some(r) = &reporter {
                r.finish();
            }
            // 跳过也要记一行（沿 v2 帧口径：detail=已存在（跳过），path=既有文件全路径）。
            record_recv(opts, peer, 0, 1, Instant::now(), "已存在（跳过）", &base);
            return Ok(0);
        }
    }
    if let Some(r) = &reporter {
        r.finish();
    }
    record_recv(opts, peer, size as u64, 1, Instant::now(), "直接发送", &save_path);
    Ok(size as u64)
}

async fn handle_folder<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    peer: SocketAddr,
    opts: &RecvOptions,
    save_dir: &Path,
    confirmed: &mut bool,
    limiter: &mut Option<TokenBucket>,
    hub: Option<&crate::progress::ProgressHub>,
) -> Result<(u64, u32)> {
    let mut hdr2 = [0u8; 2];
    wire.read_exact(&mut hdr2).await?;
    let folder_len = i16::from_le_bytes(hdr2);
    if folder_len <= 0 || folder_len as usize > CS_MAX_NAME {
        return Err(proto("0x01 目录名长度非法"));
    }
    let mut name_buf = vec![0u8; folder_len as usize];
    wire.read_exact(&mut name_buf).await?;
    let folder = cs_safe_name(&String::from_utf8_lossy(&name_buf), "received_folder");
    let mut hdr4 = [0u8; 4];
    wire.read_exact(&mut hdr4).await?;
    let file_count = i32::from_le_bytes(hdr4);
    if file_count <= 0 || file_count as usize > CS_MAX_FOLDER_FILES {
        return Err(proto("0x01 文件数非法"));
    }
    confirm_once(peer, opts, confirmed).await?;
    let reporter = register_recv(hub, peer, folder.clone(), 0);
    let folder_dir = cs_unique_save_path(save_dir, &folder);
    std::fs::create_dir_all(&folder_dir)?;
    let mut total = 0u64;
    // Skip 策略需要逐文件比对既有目录——收集 (rel, size, hash) 以便收尾归并。
    let mut received: Vec<(String, u64, [u8; 32])> = Vec::new();
    for _ in 0..file_count {
        let mut fh = [0u8; 10];
        wire.read_exact(&mut fh).await?;
        let size = i64::from_le_bytes(fh[..8].try_into().expect("8B"));
        let path_len = i16::from_le_bytes(fh[8..10].try_into().expect("2B"));
        if size < 0
            || size as u64 > CS_MAX_TRANSFER
            || path_len <= 0
            || path_len as usize > CS_MAX_NAME
        {
            return Err(proto("0x01 文件头非法"));
        }
        let mut pb = vec![0u8; path_len as usize];
        wire.read_exact(&mut pb).await?;
        let rel = cs_sanitize_rel(&String::from_utf8_lossy(&pb));
        let save_path = folder_dir.join(&rel);
        if let Some(parent) = save_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let display = format!("{folder}/{rel}");
        let hash =
            receive_payload(wire, &save_path, size as u64, &display, limiter, &reporter).await?;
        received.push((rel, size as u64, hash));
        total += size as u64;
        if let Some(r) = &reporter {
            r.add(1);
        }
    }
    // Skip 策略（目录级，对齐 v2 帧 0x01 语义）：重名根目录已存在时**复用**它，
    // 逐文件比对——一致即丢弃新副本；不全一致才把新副本并入既有目录（冲突改名）。
    // 绝不整目录改名为 lib_1（那正是 Skip 要避免的重复副本）。
    let base = save_dir.join(&folder);
    if opts.duplicate == DuplicatePolicy::Skip && folder_dir != base && base.is_dir() {
        let mut all_dup = true;
        let mut kept_bytes = 0u64;
        let mut kept_files = 0u32;
        for (rel, size, hash) in &received {
            let src = folder_dir.join(rel);
            let dest = base.join(rel);
            let dup = std::fs::metadata(&dest)
                .map(|m| m.len() == *size)
                .unwrap_or(false)
                && match tokio::task::spawn_blocking({
                    let d = dest.clone();
                    move || crate::hash::sha256_file(&d)
                })
                .await
                {
                    Ok(Ok(h)) => ct_eq(&h, hash),
                    _ => false,
                };
            if dup {
                let _ = std::fs::remove_file(&src);
                continue;
            }
            all_dup = false;
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            cs_publish(&src, &dest).map_err(Error::Io)?;
            kept_bytes += *size;
            kept_files += 1;
        }
        let _ = std::fs::remove_dir_all(&folder_dir);
        if let Some(r) = &reporter {
            r.finish();
        }
        if all_dup {
            // 整夹同内容副本：不落新副本、不记账（零传输的「已存在」）。
            return Ok((0, 0));
        }
        record_recv(
            opts,
            peer,
            kept_bytes,
            kept_files,
            Instant::now(),
            "整夹发送",
            &base,
        );
        return Ok((kept_bytes, kept_files));
    }
    if let Some(r) = &reporter {
        r.finish();
    }
    record_recv(opts, peer, total, file_count as u32, Instant::now(), "整夹发送", &folder_dir);
    Ok((total, file_count as u32))
}

#[allow(clippy::too_many_arguments)]
async fn handle_chunk<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    peer: SocketAddr,
    opts: &RecvOptions,
    state: &Arc<CsServerState>,
    save_dir: &Path,
    chunk_sessions: bool,
    confirmed: &mut bool,
    limiter: &mut Option<TokenBucket>,
    hub: Option<&crate::progress::ProgressHub>,
) -> Result<(bool, bool)> {
    let mut hdr = [0u8; 28];
    wire.read_exact(&mut hdr).await?;
    let total = i64::from_le_bytes(hdr[..8].try_into().expect("8B"));
    let offset = i64::from_le_bytes(hdr[8..16].try_into().expect("8B"));
    let chunk = i64::from_le_bytes(hdr[16..24].try_into().expect("8B"));
    let name_len = i32::from_le_bytes(hdr[24..28].try_into().expect("4B"));
    if total <= 0
        || total as u64 > CS_MAX_TRANSFER
        || offset < 0
        || chunk <= 0
        || offset > total - chunk
        || name_len <= 0
        || name_len as usize > CS_MAX_NAME
    {
        return Err(proto("0x02 头非法"));
    }
    let mut nb = vec![0u8; name_len as usize];
    wire.read_exact(&mut nb).await?;
    let name = cs_safe_name(&String::from_utf8_lossy(&nb), "received_file");
    let group_key: Option<String> = if chunk_sessions {
        let mut id = [0u8; 17];
        wire.read_exact(&mut id).await?;
        if id[0] == 1 {
            let g: [u8; 16] = id[1..].try_into().expect("16B");
            Some(guid_hex(&g))
        } else {
            None
        }
    } else {
        None
    };
    confirm_once(peer, opts, confirmed).await?;
    let reporter = register_recv(hub, peer, name.clone(), total as u64);
    let tracker_key = match &group_key {
        Some(g) => {
            // 组归属绑定（防外来 peer 写入他人组装——C# ChunkSessionPeers 同防线）。
            let ip = peer.ip().to_string();
            let mut owners = state.group_peers.lock().expect("组归属锁");
            match owners.get_mut(g) {
                Some((owner, ts)) if *owner != ip => {
                    return Err(Error::Rejected("分块组会话属于其他设备".into()));
                }
                Some((_, ts)) => {
                    *ts = Instant::now(); // 活跃刷新（TTL 清扫依据）
                }
                None => {
                    owners.insert(g.clone(), (ip, Instant::now()));
                }
            }
            format!("S|{g}")
        }
        None => format!("{}|{}", peer.ip(), name),
    };

    // 组装器（大小不符的遗留 tracker 重建——C# 同策略）。
    cs_sweep_stale(state); // 轮 UI-2 P2-1：入口惰性清扫（死 tracker/会话不再永驻）
    {
        let mut t = state.trackers.lock().expect("tracker 锁");
        let stale = match t.get(&tracker_key) {
            Some(tr) if tr.total == total as u64 => None,
            Some(_) => t.remove(&tracker_key),
            None => None,
        };
        if let Some(st) = stale {
            cs_release_declared(state, st.total); // 旧声明量随重建释放
            let _ = std::fs::remove_file(&st.save_path);
        }
        if !t.contains_key(&tracker_key) {
            // 轮 UI-4 F2/F3：declare 先于 create（被拒时不落盘）；组装器落盘改用
            // `.trft-part` 半成品名（旧最终名 + TTL 不敢删 = 时间维度绕过磁盘封顶；
            // 半成品名让 TTL 清扫可安全回收，完成时经 cs_publish 原子发布）。
            cs_declare(state, total as u64)?;
            let mut part_os = cs_unique_save_path(save_dir, &name).into_os_string();
            part_os.push(format!(".{}.trft-part", random_hex(8)));
            let tr = match CsChunkTracker::create(PathBuf::from(part_os), total as u64) {
                Ok(tr) => tr,
                Err(e) => {
                    cs_release_declared(state, total as u64);
                    return Err(Error::Io(e));
                }
            };
            t.insert(tracker_key.clone(), tr);
        }
    }

    // 写段 + 逐段哈希（C# HandleChunkedFile 同构）。
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    let mut remaining = chunk as u64;
    let mut write_off = offset as u64;
    let mut buf = vec![0u8; CS_RECV_BUF];
    while remaining > 0 {
        let n = buf.len().min(remaining as usize);
        wire.read_exact(&mut buf[..n]).await?;
        if let Some(l) = limiter {
            l.acquire(n as u64).await;
        }
        hasher.update(&buf[..n]);
        {
            let mut t = state.trackers.lock().expect("tracker 锁");
            match t.get_mut(&tracker_key) {
                Some(tr) => {
                    tr.write_data(write_off, &buf[..n])?;
                    if tr.ranges_count() > CS_MAX_CHUNK_RANGES {
                        return Err(Error::Rejected("分块覆盖区间数超限".into()));
                    }
                }
                None => {
                    // 组装器已被并发连接（同 key 不同 total）或 TTL 清扫摘除：
                    // **绝不能静默丢块后回 ACK 成功**（轮 UI-5 P1——此前该块
                    // 被跳过，本连接哈希只覆盖自己收到的字节仍然通过，对端收到
                    // 0x01 但文件永不发布）。整组重发是唯一安全方向。
                    return Err(Error::Rejected(
                        "分块组装器已被回收（请整组重发）".into(),
                    ));
                }
            }
        }
        write_off += n as u64;
        remaining -= n as u64;
        if let Some(r) = &reporter {
            r.add(n as u64);
        }
    }
    let mut got = [0u8; 32];
    wire.read_exact(&mut got).await?;
    let computed: [u8; 32] = hasher.finalize().into();
    if !ct_eq(&got, &computed) {
        let t = state.trackers.lock().expect("tracker 锁").remove(&tracker_key);
        if let Some(tr) = t {
            cs_release_declared(state, tr.total);
            let _ = std::fs::remove_file(&tr.save_path);
        }
        return Ok((false, false));
    }
    // 尾哈希通过 → 才把这整块的区间记入覆盖表（断连的块不留覆盖）。
    let complete = {
        let mut t = state.trackers.lock().expect("tracker 锁");
        match t.get_mut(&tracker_key) {
            Some(tr) => tr.commit_range(offset as u64, chunk as u64),
            None => {
                return Err(Error::Rejected(
                    "分块组装器已被回收（请整组重发）".into(),
                ))
            }
        }
    };
    if complete {
        let t = state
            .trackers
            .lock()
            .expect("tracker 锁")
            .remove(&tracker_key);
        if let Some(tr) = t {
            // 第 9 轮审查 P2-2：发布前把页缓存落盘。0x02 此前只保证目录项
            // （hard_link）与发布写透，掉电后可能「名字在、尾部为零」。
            if let Err(e) = tr.file.sync_all() {
                let _ = std::fs::remove_file(&tr.save_path);
                return Err(Error::Io(e));
            }
            cs_release_declared(state, tr.total);
            if let Some(g) = &group_key {
                state.group_peers.lock().expect("组归属锁").remove(g);
            }
            // 半成品 → 最终名原子发布（轮 UI-4 F3：hard_link fail-if-exists，
            // 冲突名重取；发布失败清半成品回滚——最终名上不留截断内容）。
            let final_path = match cs_publish(&tr.save_path, &cs_unique_save_path(save_dir, &name))
            {
                Ok(p) => p,
                Err(e) => {
                    let _ = std::fs::remove_file(&tr.save_path);
                    return Err(Error::Io(e));
                }
            };
            record_recv(
                opts,
                peer,
                total as u64,
                1,
                Instant::now(),
                "分块传输",
                &final_path,
            );
            if let Some(r) = &reporter {
                r.finish();
            }
        }
    }
    // (本块哈希核对通过, 本块是否补满组装并完成发布)
    Ok((true, complete))
}

impl CsChunkTracker {
    fn ranges_count(&self) -> usize {
        self.ranges.len()
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_resume<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    peer: SocketAddr,
    opts: &RecvOptions,
    state: &Arc<CsServerState>,
    save_dir: &Path,
    confirmed: &mut bool,
    limiter: &mut Option<TokenBucket>,
    hub: Option<&crate::progress::ProgressHub>,
) -> Result<bool> {
    // 头：sessionId(16) + totalSize(8) + resumeOffset(8) + nameLen(4)。
    let mut hdr = [0u8; 36];
    wire.read_exact(&mut hdr).await?;
    let sid: [u8; 16] = hdr[..16].try_into().expect("16B");
    let total = i64::from_le_bytes(hdr[16..24].try_into().expect("8B"));
    let client_off = i64::from_le_bytes(hdr[24..32].try_into().expect("8B"));
    let name_len = i32::from_le_bytes(hdr[32..36].try_into().expect("4B"));
    if total <= 0
        || total as u64 > CS_MAX_TRANSFER
        || client_off < 0
        || client_off > total
        || name_len <= 0
        || name_len as usize > CS_MAX_NAME
    {
        // 头非法：无 0x10 应答、无裸 ACK（连接按 EOF/超时失败——与 C# 同静默）。
        return Ok(false);
    }
    let mut nb = vec![0u8; name_len as usize];
    wire.read_exact(&mut nb).await?;
    let name = cs_safe_name(&String::from_utf8_lossy(&nb), "received_file");
    let mut flag = [0u8; 1];
    wire.read_exact(&mut flag).await?;
    let full_hash: Option<[u8; 32]> = if flag[0] == 1 {
        let mut h = [0u8; 32];
        wire.read_exact(&mut h).await?;
        Some(h)
    } else {
        None
    };
    confirm_once(peer, opts, confirmed).await?;
    let reporter = register_recv(hub, peer, name.clone(), total as u64);

    let key = guid_hex(&sid);
    // 单飞锁（轮 6 P1——同名 sid 两连接并发 append 会交错写坏文件；C# ResumeLocks
    // TryWait(0) 同防线）+ peer 绑定校验。锁随会话生命周期存续，完成时清理。
    // 轮 UI-2 P1-1：guard 必须绑定变量持有到函数尾——旧写法 `if
    // resume_gate.try_lock().is_err()` 里 Ok(guard) 是条件临时值，判定完即
    // drop，锁形同虚设（两连接同 sid 仍可并发 append 交错写坏文件）。
    cs_sweep_stale(state); // 轮 UI-2 P2-1：入口惰性清扫
    let resume_gate = {
        let mut gates = state.resume_gates.lock().expect("resume 门锁");
        gates.entry(key.clone()).or_default().clone()
    };
    let _resume_guard = resume_gate
        .try_lock()
        .map_err(|_| Error::Rejected("该续传会话正被另一连接使用".into()))?;
    let ip = peer.ip().to_string();
    // 会话解析：status 0 新传 / 1 续传 / 2 已完整（服务端权威 offset——客户端虚报不采信，
    // C# HandleResumableCore 同语义）。
    enum Session {
        New(PathBuf),
        Resume(PathBuf, u64),
        Done(PathBuf),
    }
    let session = {
        let mut rs = state.resume.lock().expect("resume 锁");
        // 先取值判定、再决定动作（避免在 get_mut 的借用下改表）。
        let existing = rs.get(&key).map(|st| {
            (
                st.total,
                st.received,
                st.verified,
                st.peer_ip.clone(),
                st.save_path.clone(),
                st.name.clone(),
                st.verified_hash,
            )
        });
        match existing {
            Some((_, _, _, eip, _, _, _)) if eip != ip => {
                return Err(Error::Rejected("续传会话属于其他设备".into()));
            }
            // 第 9 轮审查 P2-3：sid 由 (路径,大小,目标) 确定性派生、不含随机量，
            // 同 NAT 下另一台设备可能撞上同一 sid——文件名不同即拒绝续写他人会话
            // （C# HandleResumableCore 同样比对 FileName）。
            Some((_, _, _, _, _, ename, _)) if ename != name => {
                return Err(Error::Rejected("续传会话属于其他文件".into()));
            }
            Some((etotal, received, _, _, path, _, _))
                if etotal == total as u64 && received < total as u64 =>
            {
                // 磁盘事实优先（轮 UI-5 P1）：内存记账与实文件长度分叉时（外部
                // 截断/替换、上次部分写失败）作废重来——绝不带着错位续写。
                let disk = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                let mut from = received;
                if disk != received {
                    let _ = std::fs::File::create(&path); // 截断到 0
                    from = 0;
                }
                if let Some(st) = rs.get_mut(&key) {
                    st.received = from;
                    st.verified = false;
                    st.verified_hash = None;
                    st.touched = Instant::now(); // 活跃刷新（TTL 清扫依据）
                }
                Session::Resume(path, from)
            }
            Some((etotal, _, true, _, path, _, vhash)) if etotal == total as u64 => {
                // 已验证完成：再核一次磁盘长度（外部篡改/丢失即拒绝，不报成功）。
                let ok = std::fs::metadata(&path)
                    .map(|m| m.len() == total as u64)
                    .unwrap_or(false);
                if !ok {
                    // 只摘会话，**不删文件**：磁盘上的内容可能是用户后来替换的
                    // 正常文件（长度不同），删除即数据丢失。
                    if let Some(mut old) = rs.remove(&key) {
                        release_resume_declared(state, &mut old);
                    }
                    state.resume_gates.lock().expect("resume 门锁").remove(&key);
                    return Err(Error::Rejected("续传残件长度不符，需整组重发".into()));
                }
                // 第 9 轮审查 P1-3：只核长度的旧实现会让「同尺寸改内容后重发」
                // 被判为已完整（零传输、接收端保留旧内容）。客户端带整文件哈希
                // 时必须与验证完成时记录的一致。
                let hash_ok = match (full_hash.as_ref(), vhash.as_ref()) {
                    (Some(c), Some(v)) => ct_eq(c, v),
                    _ => true,
                };
                if hash_ok {
                    Session::Done(path)
                } else {
                    // 内容已变：作废旧会话（保留磁盘旧档），按新传处理。
                    if let Some(mut old) = rs.remove(&key) {
                        release_resume_declared(state, &mut old);
                    }
                    state.resume_gates.lock().expect("resume 门锁").remove(&key);
                    let save_path = cs_unique_save_path(save_dir, &name);
                    cs_declare(state, total as u64)?;
                    rs.insert(
                        key.clone(),
                        CsResumeState {
                            save_path: save_path.clone(),
                            total: total as u64,
                            received: 0,
                            name: name.clone(),
                            peer_ip: ip.clone(),
                            touched: Instant::now(),
                            verified: false,
                            verified_hash: None,
                            declared_held: true,
                        },
                    );
                    Session::New(save_path)
                }
            }
            _ => {
                // 旧会话（参数不同 / 体收满但未验证）一律作废：**先删残件再取唯一
                // 名**——否则未验证的 "name" 仍占名，新会话落到 name_1，旧残件
                // 永久留在用户目录（轮 UI-5 P1）。
                // 轮 UI-4 F1：旧声明量必须先释放，否则 declared_total 单调泄漏，
                // 远程几轮即可打满 64GiB 封顶令 UDT 槽位 0x02/0x03 全拒（持久 DoS）。
                if let Some(mut old) = rs.remove(&key) {
                    release_resume_declared(state, &mut old);
                    state.resume_gates.lock().expect("resume 门锁").remove(&key);
                    // **只删未验证的半成品**；已验证完成的是用户文件，换参数/重传
                    // 都不得删（否则同一 sid 换个 total 就能删掉已交付的文件）。
                    if !old.verified {
                        let _ = std::fs::remove_file(&old.save_path);
                    }
                }
                let save_path = cs_unique_save_path(save_dir, &name);
                // 声明总量记账（轮 UI-2 P2-2）：跨连接存活的断点会话纳入封顶。
                cs_declare(state, total as u64)?;
                rs.insert(
                    key.clone(),
                    CsResumeState {
                        save_path: save_path.clone(),
                        total: total as u64,
                        received: 0,
                        name: name.clone(),
                        peer_ip: ip.clone(),
                        touched: Instant::now(),
                        verified: false,
                        verified_hash: None,
                        declared_held: true,
                    },
                );
                Session::New(save_path)
            }
        }
    };
    match session {
        Session::Done(_path) => {
            // 已验证完成态：status 2 零传输（C# 语义）。不重复记账、不摘会话
            // ——重试收敛于成功；会话由 TTL 清扫释放声明量。
            if let Some(r) = &reporter {
                r.finish();
            }
            send_resume_response(wire, total, 2).await?;
            Ok(true)
        }
        Session::New(path) => {
            send_resume_response(wire, 0, 0).await?;
            receive_resume_body(
                wire, peer, opts, state, &key, &path, 0, total as u64, full_hash, limiter,
                &reporter,
            )
            .await
        }
        Session::Resume(path, from) => {
            send_resume_response(wire, from as i64, 1).await?;
            receive_resume_body(
                wire, peer, opts, state, &key, &path, from, total as u64, full_hash, limiter,
                &reporter,
            )
            .await
        }
    }
}

/// 0x10 应答：[0x10][offset i64][status u8]。
async fn send_resume_response<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    offset: i64,
    status: u8,
) -> Result<()> {
    let mut resp = vec![R_RESUME];
    resp.extend_from_slice(&offset.to_le_bytes());
    resp.push(status);
    wire.write_all(&resp).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn receive_resume_body<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    peer: SocketAddr,
    opts: &RecvOptions,
    state: &Arc<CsServerState>,
    key: &str,
    path: &Path,
    start: u64,
    total: u64,
    full_hash: Option<[u8; 32]>,
    limiter: &mut Option<TokenBucket>,
    reporter: &CsReporter,
) -> Result<bool> {
    use sha2::Digest;
    use std::io::{Seek as _, Write as _};
    // 磁盘预检（轮 UI-2 P2-2：追加段也占空间——与 v2 帧接收路径同口径）。
    if let Some(dir) = path.parent() {
        if !crate::transfer::receiver::space_ok(dir, total - start) {
            return Err(Error::Io(io::Error::new(io::ErrorKind::StorageFull, "磁盘可用空间不足")));
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.seek(std::io::SeekFrom::End(0))?;
    let mut hasher = sha2::Sha256::new();
    let mut remaining = total - start;
    let mut buf = vec![0u8; CS_RECV_BUF];
    // 首块静默窗（轮 UI-2 P2-3：0x10 应答后挂活不发体的 peer 不得占闸——
    // receive_payload 同款；后续块无窗兼容合法慢速限速）。
    let mut first_block = true;
    while remaining > 0 {
        // 部分读：中断前的到达字节必须立即记账（C# ReadSomeAsync 同构——
        // read_exact 会让不足一块的进度滞留 socket，续点回退）。
        let want = buf.len().min(remaining as usize);
        let n = if first_block {
            match tokio::time::timeout(PRELUDE_IDLE, wire.read_some(&mut buf[..want])).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(Error::Io(e)),
                Err(_) => return Err(proto("续传体首块静默超时（30s）")),
            }
        } else {
            wire.read_some(&mut buf[..want]).await?
        };
        first_block = false;
        if n == 0 {
            return Err(Error::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "对端中断")));
        }
        if let Some(l) = limiter {
            l.acquire(n as u64).await;
        }
        hasher.update(&buf[..n]);
        f.write_all(&buf[..n])?;
        remaining -= n as u64;
        {
            let mut rs = state.resume.lock().expect("resume 锁");
            if let Some(st) = rs.get_mut(key) {
                st.received += n as u64;
                st.touched = Instant::now(); // 活跃刷新（TTL 清扫依据）
            }
        }
        if let Some(r) = reporter {
            r.add(n as u64);
        }
    }
    // 发布前落盘（轮 UI-5 续 P2）：C# 方言 0x03 此前不 fsync——增量/全文件哈希
    // 都是从页缓存算出的，掉电后可能短文件而服务端已回 status 2。与 v2 同纪律。
    f.sync_all()?;
    let mut got = [0u8; 32];
    wire.read_exact(&mut got).await?;
    let computed: [u8; 32] = hasher.finalize().into();
    if !ct_eq(&got, &computed) {
        // 哈希失败：丢弃会话与半成品（重试从头）。
        let st = state.resume.lock().expect("resume 锁").remove(key);
        state.resume_gates.lock().expect("resume 门锁").remove(key);
        if let Some(mut st) = st {
            release_resume_declared(state, &mut st);
            let _ = std::fs::remove_file(&st.save_path);
        }
        return Ok(false);
    }
    // 收尾硬校验（轮 UI-5 P1，对齐 v2 resume.rs 轮 4 P0 纵深）：半成品长度必须
    // == 声明 total——append 位置由 EOF 决定，内存记账不得替代磁盘事实。
    let plen = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if plen != total {
        let st = state.resume.lock().expect("resume 锁").remove(key);
        state.resume_gates.lock().expect("resume 门锁").remove(key);
        if let Some(mut st) = st {
            release_resume_declared(state, &mut st);
            let _ = std::fs::remove_file(&st.save_path);
        }
        send_resume_response(wire, total as i64, 3).await?;
        return Ok(false);
    }
    // 全文件哈希核验（可选扩展——resume 的拼缝不在段哈希覆盖内）。
    if let Some(expect) = full_hash {
        // 读失败 = 报错并保留文件——绝不把「读不到」当「内容不符」去删档
        // （判错方向：杀软/共享冲突的瞬时读失败会误删刚校验通过的完整文件）。
        let p = path.to_path_buf();
        let actual = tokio::task::spawn_blocking(move || crate::hash::sha256_file(&p))
            .await
            .map_err(|e| proto(e.to_string()))??;
        if !ct_eq(&actual, &expect) {
            let st = state.resume.lock().expect("resume 锁").remove(key);
            state.resume_gates.lock().expect("resume 门锁").remove(key);
            if let Some(st) = st {
                cs_release_declared(state, st.total);
                let _ = std::fs::remove_file(&st.save_path);
            }
            send_resume_response(wire, total as i64, 3).await?;
            return Ok(false);
        }
    }
    // 成功：会话保留为「已验证完成」态（同 sid 重问回 status 2 零传输——C#
    // 协议语义），TTL 清扫时释放声明量；**统计只在此处记一次**（Done 重问
    // 不得重复入账）。
    {
        let mut rs = state.resume.lock().expect("resume 锁");
        if let Some(st) = rs.get_mut(key) {
            st.received = total;
            st.verified = true;
            // 记下客户端声明的整文件哈希：下次同 sid 重问时据此判「已完整」
            // 是否仍成立（P1-3）。无哈希（verifyFlag=0）时退回只核长度。
            st.verified_hash = full_hash;
            st.touched = Instant::now();
            // 完成即释放声明量（幂等；TTL 清扫不会再扣一次）——已验证会话在
            // TTL 窗口内不得继续占用 64 GiB 封顶额度（自查：否则大批量同步
            // 会在 30 分钟内把额度耗尽而误拒新传输）。
            release_resume_declared(state, st);
        }
    }
    state.resume_gates.lock().expect("resume 门锁").remove(key);
    record_recv(opts, peer, total, 1, Instant::now(), "续传传输", path);
    if let Some(r) = reporter {
        r.finish();
    }
    send_resume_response(wire, total as i64, 2).await?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn handle_folder_resume<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    peer: SocketAddr,
    opts: &RecvOptions,
    state: &Arc<CsServerState>,
    save_dir: &Path,
    per_file_skip: bool,
    confirmed: &mut bool,
    limiter: &mut Option<TokenBucket>,
    hub: Option<&crate::progress::ProgressHub>,
) -> Result<(bool, u64, u32)> {
    struct ManifestEntry {
        rel: String,
        size: u64,
        hash: [u8; 32],
    }
    // 头：sessionId(16) + folderNameLen(2) + folderName + fileCount(4) + totalBytes(8)。
    let mut head = [0u8; 18];
    wire.read_exact(&mut head).await?;
    let sid: [u8; 16] = head[..16].try_into().expect("16B");
    let folder_len = i16::from_le_bytes(head[16..18].try_into().expect("2B"));
    if folder_len <= 0 || folder_len as usize > CS_MAX_NAME {
        return Ok((false, 0, 0));
    }
    let mut nb = vec![0u8; folder_len as usize];
    wire.read_exact(&mut nb).await?;
    let folder = cs_safe_name(&String::from_utf8_lossy(&nb), "received_folder");
    let mut cnt = [0u8; 12];
    wire.read_exact(&mut cnt).await?;
    let file_count = i32::from_le_bytes(cnt[..4].try_into().expect("4B"));
    let total_bytes = i64::from_le_bytes(cnt[4..12].try_into().expect("8B"));
    if file_count <= 0
        || file_count as usize > CS_MAX_FOLDER_FILES
        || total_bytes < 0
        || total_bytes as u64 > CS_MAX_TRANSFER
    {
        return Ok((false, 0, 0));
    }
    // 容量提示封顶：file_count 上限 1,000,000（64 条并发连接下预分配可达数 GB）。
    // 合法清单逐项增长即可，提示只影响首次扩容次数。
    let mut manifest: Vec<ManifestEntry> = Vec::with_capacity((file_count as usize).min(1024));
    let mut manifest_total = 0u64;
    // 第 9 轮审查 P2-4：清单整表驻留且 total 无检查累加——1e6 × 4KB 路径可占
    // ~4GiB，16384 条 1PiB 还能让 u64 回绕、架空总长校验。加累计预算 + checked。
    let mut manifest_bytes: usize = 0;
    for _ in 0..file_count {
        let mut fh = [0u8; 10];
        wire.read_exact(&mut fh).await?;
        let size = i64::from_le_bytes(fh[..8].try_into().expect("8B"));
        let path_len = i16::from_le_bytes(fh[8..10].try_into().expect("2B"));
        if size < 0
            || size as u64 > CS_MAX_TRANSFER
            || path_len <= 0
            || path_len as usize > CS_MAX_NAME
        {
            return Ok((false, 0, 0));
        }
        let mut pb = vec![0u8; path_len as usize];
        wire.read_exact(&mut pb).await?;
        let mut h = [0u8; 32];
        wire.read_exact(&mut h).await?;
        manifest_bytes = match manifest_bytes.checked_add(pb.len()) {
            Some(n) if n <= CS_MANIFEST_MAX_BYTES => n,
            _ => return Ok((false, 0, 0)),
        };
        manifest_total = match manifest_total.checked_add(size as u64) {
            Some(n) if n <= CS_MAX_TRANSFER => n,
            _ => return Ok((false, 0, 0)),
        };
        manifest.push(ManifestEntry {
            rel: cs_sanitize_rel(&String::from_utf8_lossy(&pb)),
            size: size as u64,
            hash: h,
        });
    }
    if manifest_total != total_bytes as u64 {
        return Ok((false, 0, 0));
    }
    confirm_once(peer, opts, confirmed).await?;
    let reporter = register_recv(hub, peer, folder.clone(), total_bytes as u64);
    // 会话目录（确定性：<folder>.<guid8>——C# GetFolderSessionDir 同式，重复同步续用）。
    let dir = save_dir.join(format!("{folder}.{}", &guid_hex(&sid)[..8]));
    // 复用既有目录前先验包含性（junction/符号链接不得把落盘带出 save_dir）。
    ensure_contained(save_dir, &dir)?;
    std::fs::create_dir_all(&dir)?;
    ensure_contained(save_dir, &dir)?;
    // 续点扫描：首个不完整条目（C# 同构）。strict（SyncVerifyContent）不采信
    // 既有文件（缓存/盘上摘要），一律全量重收——与 v2 帧 0x04 的 strict 同口径
    // （规格 §3.3；「同步逐字节核对」不得被摘要缓存短路）。
    let mut resume_index = file_count;
    let mut resume_offset = 0i64;
    if opts.strict_verify {
        resume_index = 0;
    } else {
        for (i, e) in manifest.iter().enumerate() {
            let p = dir.join(&e.rel);
            if !p.exists() {
                resume_index = i as i32;
                resume_offset = 0;
                break;
            }
            let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            if len == e.size {
                if let Some(actual) = sync_hash_of(state, &p, e.size).await {
                    if ct_eq(&actual, &e.hash) {
                        continue;
                    }
                }
                resume_index = i as i32;
                resume_offset = 0;
                break;
            }
            // C# KnownComplete 守卫（移植时丢失，2026-11-23 双机测试暴露）：短于发送端
            // 但**已知完整**的文件是「该文件的上一个版本」，其字节不是待续传的前缀；
            // 只有当它从未被登记为完整摘要时，才可能是断点半成品（C# 注释同义：
            // 「bytes on disk belong to different content」）。
            if len > 0 && len < e.size && !known_complete(state, &p, len) {
                resume_index = i as i32;
                resume_offset = len as i64;
                break;
            }
            resume_index = i as i32;
            resume_offset = 0;
            break;
        }
    }
    let status: u8 = if resume_index >= file_count {
        2
    } else if resume_index > 0 || resume_offset > 0 {
        1
    } else {
        0
    };
    // 0x11 应答：[0x11][resumeIndex i64][resumeOffset i64][status u8]。
    let mut resp = vec![R_FOLDER_RESUME];
    resp.extend_from_slice(&(resume_index as i64).to_le_bytes());
    resp.extend_from_slice(&resume_offset.to_le_bytes());
    resp.push(status);
    wire.write_all(&resp).await?;
    if status == 2 {
        if let Some(r) = &reporter {
            r.finish();
        }
        record_recv(
            opts,
            peer,
            total_bytes as u64,
            file_count as u32,
            Instant::now(),
            "文件夹同步",
            &dir,
        );
        return Ok((true, total_bytes as u64, file_count as u32));
    }
    // 逐文件确认清单（0x0A bit0）：客户端声明剩余文件 → 服务端逐个回 0 跳过 / 1 需发送。
    let mut need: Option<Vec<bool>> = None;
    if per_file_skip && resume_index < file_count {
        let mut answers = Vec::with_capacity((file_count - resume_index) as usize);
        for i in resume_index..file_count {
            let e = &manifest[i as usize];
            let mut fh = [0u8; 10];
            wire.read_exact(&mut fh).await?;
            let size = i64::from_le_bytes(fh[..8].try_into().expect("8B"));
            let path_len = i16::from_le_bytes(fh[8..10].try_into().expect("2B"));
            if size != e.size as i64 || path_len <= 0 || path_len as usize > CS_MAX_NAME {
                return Ok((false, 0, 0));
            }
            let mut pb = vec![0u8; path_len as usize];
            wire.read_exact(&mut pb).await?;
            let mut h = [0u8; 32];
            wire.read_exact(&mut h).await?;
            let p = dir.join(cs_sanitize_rel(&String::from_utf8_lossy(&pb)));
            let identical = !opts.strict_verify
                && p.exists()
                && std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0) == e.size
                && sync_hash_of(state, &p, e.size)
                    .await
                    .map_or(false, |h| ct_eq(&h, &e.hash));
            answers.push(if identical { 0u8 } else { 1u8 });
        }
        wire.write_all(&answers).await?;
        need = Some(answers.into_iter().map(|a| a == 1).collect());
    }
    // 顺序收文件（从 resumeIndex 起，首个从 resumeOffset 续）。
    let mut files = 0u32;
    for i in resume_index..file_count {
        let idx = (i - resume_index) as usize;
        if let Some(n) = &need {
            if !n[idx] {
                if let Some(r) = &reporter {
                    r.add(manifest[i as usize].size);
                }
                continue;
            }
        }
        let e = &manifest[i as usize];
        let start: u64 = if i == resume_index {
            resume_offset as u64
        } else {
            0
        };
        let save_path = dir.join(&e.rel);
        if let Some(parent) = save_path.parent() {
            // 子目录同样可能是指向树外的链接：建目录前后各验一次。
            ensure_contained(save_dir, parent)?;
            std::fs::create_dir_all(parent)?;
            ensure_contained(save_dir, parent)?;
        }
        if start == 0 {
            // 外层暂存名同口径 `.trft-part` 后缀（轮 UI-2 P2-1：成功后 2069 行
            // rename 失败的残件也在清扫器覆盖内）。
            let mut temp_os = save_path.clone().into_os_string();
            temp_os.push(format!(".{}.trft-part", random_hex(8)));
            let temp = PathBuf::from(temp_os);
            let r = receive_payload(wire, &temp, e.size, &e.rel, limiter, &reporter).await;
            match r {
                Ok(_) => {
                    // 轮 UI-5 P0：同步替换 = 新文件整文件校验通过后**原子覆盖**。
                    // 发布失败时旧档保持原样（此前先 remove_file 旧档再发布，
                    // 任一步失败都会让用户上一版文件凭空消失）。
                    // F3（真机 B5）：发布前把数据落盘——0x04 此前只保证改名落盘
                    // （F2），断电后可出现「最终名在、内容不符」。与 0x02/0x03 同纪律。
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&temp)
                        .and_then(|f| f.sync_all())
                        .map_err(Error::Io)?;
                    cs_publish_replace(&temp, &save_path).map_err(Error::Io)?;
                }
                Err(_) => {
                    // 失败：**不触碰 save_path**（旧档原样保留）。内层半成品已由
                    // receive_payload 的守卫清理，外层 temp 从未创建；此处仅清理
                    // 可能存在的空壳。判错方向：宁可多传一次，不得丢既有文件。
                    let _ = std::fs::remove_file(&temp);
                    return Ok((false, 0, files));
                }
            }
        } else {
            // 增量续传：追加 + 增量哈希 + 全文件复核（C# HandleFolderResumableAsync 同构）。
            use sha2::Digest;
            use std::io::Write as _;
            // 磁盘预检 + 首块静默窗（轮 UI-2 P2-2/P2-3——与主路径同口径）。
            if let Some(dir) = save_path.parent() {
                if !crate::transfer::receiver::space_ok(dir, e.size - start) {
                    return Err(Error::Io(io::Error::new(io::ErrorKind::StorageFull, "磁盘可用空间不足")));
                }
            }
            let mut f = std::fs::OpenOptions::new().append(true).open(&save_path)?;
            let mut hasher = sha2::Sha256::new();
            let mut remaining = e.size - start;
            let mut buf = vec![0u8; CS_RECV_BUF];
            let mut first_block = true;
            while remaining > 0 {
                let n = buf.len().min(remaining as usize);
                if first_block {
                    tokio::time::timeout(PRELUDE_IDLE, wire.read_exact(&mut buf[..n]))
                        .await
                        .map_err(|_| proto("续传体首块静默超时（30s）"))??;
                    first_block = false;
                } else {
                    wire.read_exact(&mut buf[..n]).await?;
                }
                if let Some(l) = limiter {
                    l.acquire(n as u64).await;
                }
                hasher.update(&buf[..n]);
                f.write_all(&buf[..n])?;
                remaining -= n as u64;
                if let Some(r) = &reporter {
                    r.add(n as u64);
                }
            }
            // 第 9 轮审查 P2-2：追加数据先落盘——随后的整文件哈希是从页缓存
            // 算出来的，断电后会出现「已回成功但文件短尾」。与 start==0 同纪律。
            f.sync_all()?;
            let mut got = [0u8; 32];
            wire.read_exact(&mut got).await?;
            let computed: [u8; 32] = hasher.finalize().into();
            if !ct_eq(&got, &computed) {
                return Ok((false, 0, files));
            }
            // 第 9 轮审查 P1-4：读失败 = 保留文件并报错。旧实现 unwrap_or_default()
            // 会把「读不到」当「内容不符」，直接删掉用户既有文件。
            let p_owned = save_path.clone();
            let actual = tokio::task::spawn_blocking(move || crate::hash::sha256_file(&p_owned))
                .await
                .map_err(|e| Error::Io(io::Error::other(e.to_string())))??;
            if !ct_eq(&actual, &e.hash) {
                let _ = std::fs::remove_file(&save_path);
                return Ok((false, 0, files));
            }
        }
        // C# FileHashes.Store 同构：本轮落盘的版本登记为「已知完整」——下一轮续点
        // 判断据此区分「旧完整版本」与「断点半成品」（known_complete）。
        remember_sync_hash(state, &save_path, &e.hash);
        files += 1;
    }
    if let Some(r) = &reporter {
        r.finish();
    }
    record_recv(
        opts,
        peer,
        total_bytes as u64,
        files.max(1),
        Instant::now(),
        "文件夹同步",
        &dir,
    );
    Ok((true, total_bytes as u64, files))
}

async fn handle_text<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    peer: SocketAddr,
    opts: &RecvOptions,
) -> Result<u64> {
    let mut len_buf = [0u8; 4];
    wire.read_exact(&mut len_buf).await?;
    let len = i32::from_le_bytes(len_buf);
    if len < 0 || len as usize > CS_MAX_TEXT {
        return Err(Error::Rejected("文本超长".into()));
    }
    let mut buf = vec![0u8; len as usize];
    wire.read_exact(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf).to_string();
    if let Some(tx) = &opts.text_tx {
        let _ = tx.send(text);
    } else {
        eprintln!("[文本] {text}");
    }
    // 与主方言 0x06 同口径记账（无落盘路径——历史行不提供定位）。
    record_recv(
        opts,
        peer,
        len as u64,
        0,
        Instant::now(),
        "文本消息",
        Path::new(""),
    );
    Ok(len as u64)
}

/* ============ 客户端（v2 → C#） ============ */

/// 建连 + 认证栈（0x09/0x05 → 0x08；不探询能力——0x00/0x01/0x06 客户端用）。
pub async fn cs_connect_stack(
    addr: SocketAddr,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<CsWire<UdtStream>> {
    Ok(cs_connect_stack_full(addr, opts, 0).await?.0)
}

/// 建连 + 认证栈。`caps_req`：0x0A 能力探询请求位（0 = 不探询；0x01 = 0x04
/// 逐文件跳过清单）。返回 (线, 服务端能力位)。
pub async fn cs_connect_stack_full(
    addr: SocketAddr,
    opts: &crate::transfer::sender::SendOptions,
    caps_req: u8,
) -> Result<(CsWire<UdtStream>, u8)> {
    let stream = connect_udt(addr, opts.src_port).await?;
    cs_handshake(CsWire::new(stream), opts, caps_req).await
}

/// TCP 槽位的 C# 方言建连（互通改造：TCP 应用层与 UDT 同为 cswire）。
pub async fn cs_connect_tcp(
    addr: SocketAddr,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<CsWire<tokio::net::TcpStream>> {
    Ok(cs_connect_tcp_full(addr, opts, 0).await?.0)
}

/// 同 cs_connect_tcp，带 0x0A 能力探询位（0x01 = 0x04 逐文件跳过；0x02 = 0x02
/// 分块组会话 + 0x0B 覆盖查询）。返回 (线, 服务端能力位)。
pub async fn cs_connect_tcp_full(
    addr: SocketAddr,
    opts: &crate::transfer::sender::SendOptions,
    caps_req: u8,
) -> Result<(CsWire<tokio::net::TcpStream>, u8)> {
    // 与 v2 发送端同口径的调优：连接超时 10s、src_port 绑定、NODELAY、4MB 缓冲。
    let stream = crate::transfer::sender::connect(addr, opts.src_port).await?;
    cs_handshake(CsWire::new_tcp(stream), opts, caps_req).await
}

/// 已建连流上的 C# 认证栈（UDT/TCP 共用）。
pub async fn cs_handshake<S: AsyncRead + AsyncWrite + Unpin + Send>(
    mut wire: CsWire<S>,
    opts: &crate::transfer::sender::SendOptions,
    caps_req: u8,
) -> Result<(CsWire<S>, u8)> {
    let code = opts.pairing_code.clone().unwrap_or_default();
    if !code.is_empty() {
        if opts.encrypt {
            match cs_client_ecdh(&mut wire, &code).await? {
                CsEcdhOutcome::Encrypted => {}
                CsEcdhOutcome::Plaintext => {
                    eprintln!("[C# 方言] 对端未启用配对，明文继续");
                }
            }
        } else {
            cs_client_pairing(&mut wire, &code).await?;
        }
    }
    negotiate_tail(&mut wire, opts, caps_req).await?;
    let caps = wire.server_caps;
    Ok((wire, caps))
}

/// 认证后的压缩/能力协商尾段。
async fn negotiate_tail<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    opts: &crate::transfer::sender::SendOptions,
    caps_req: u8,
) -> Result<()> {
    if opts.compress {
        let mut pad = [0u8; 16];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut pad);
        let mut frame = vec![F_COMPRESS];
        frame.extend_from_slice(&pad);
        wire.write_all(&frame).await?;
        let mut resp = [0u8; 2];
        tokio::time::timeout(PRELUDE_TIMEOUT, wire.read_exact(&mut resp))
            .await
            .map_err(|_| proto("0x08 压缩应答超时"))?
            .map_err(Error::Io)?;
        if resp[0] == R_COMPRESS && resp[1] == 0 {
            wire.enable_compress();
        }
        // 其余状态：对端婉拒 → 明文继续（同连接）。
    }
    if caps_req != 0 {
        // 0x0A 能力探询（认证后；C# 客户端 AuthenticateAsync capabilities 同位）。
        wire.write_all(&[F_CAPS, caps_req]).await?;
        let mut resp = [0u8; 2];
        tokio::time::timeout(PRELUDE_TIMEOUT, wire.read_exact(&mut resp))
            .await
            .map_err(|_| proto("0x0A 能力应答超时"))?
            .map_err(Error::Io)?;
        if resp[0] != R_CAPS {
            return Err(proto("0x0A 能力应答类型不符"));
        }
        wire.server_caps = resp[1];
    }
    Ok(())
}

/// 结尾裸 ACK 读取（0x01 成功 / 0x00 拒绝 / EOF·超时 = 结果未知 → 失败）。
pub async fn cs_read_final_ack<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
) -> Result<()> {
    let mut ack = [0u8; 1];
    // TCP：判决经装饰器栈（C# ClientWire.ConfirmCompletionAsync 读 active 流）；
    // UDT：裸流带外 ACK（C# RunUdtTransfer udt_recv 直读 socket）。
    let read = async {
        if wire.ack_on_wire() {
            wire.read_exact(&mut ack).await
        } else {
            wire.raw_read_exact(&mut ack).await
        }
    };
    tokio::time::timeout(ACK_TIMEOUT, read)
        .await
        .map_err(|_| proto("等待对端完成确认超时（30s）"))?
        .map_err(Error::Io)?;
    match ack[0] {
        0x01 => Ok(()),
        0x00 => Err(Error::Rejected("被对端拒绝接收".into())),
        other => Err(proto(format!("对端确认字节异常: 0x{other:02X}"))),
    }
}

/// 发单文件（0x00）。返回传输字节数。
pub async fn cs_send_file<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    path: &Path,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<u64> {
    let raw = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| crate::error::config_err("路径没有合法 UTF-8 文件名"))?;
    let name = crate::protocol::frame::sanitize_name(raw)?;
    let meta = tokio::fs::metadata(path).await?;
    if !meta.is_file() {
        return Err(crate::error::config_err("路径不是普通文件"));
    }
    let size = meta.len();
    if size > CS_MAX_TRANSFER {
        return Err(crate::error::config_err("文件超过声明上限（1 PiB）"));
    }
    let reporter = opts.progress.as_ref();
    if let Some(r) = reporter {
        r.set_total(size);
    }

    // [0x00][size i64][nameLen i32][name]
    let mut header = Vec::with_capacity(1 + 12 + name.len());
    header.push(F_SINGLE);
    header.extend_from_slice(&(size as i64).to_le_bytes());
    header.extend_from_slice(&(name.len() as i32).to_le_bytes());
    header.extend_from_slice(name.as_bytes());
    wire.write_all(&header).await?;

    let mut f = tokio::fs::File::open(path).await?;
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    let mut lim = TokenBucket::new(opts.speed_limit_bps);
    let mut buf = vec![0u8; crate::transfer::CHUNK];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        lim.acquire(n as u64).await;
        hasher.update(&buf[..n]);
        wire.write_all(&buf[..n]).await?;
        if let Some(r) = &reporter {
            r.add(n as u64);
        }
    }
    let hash: [u8; 32] = hasher.finalize().into();
    wire.write_all(&hash).await?;
    cs_read_final_ack(wire).await?;
    if let Some(r) = &reporter {
        r.finish();
    }
    Ok(size)
}

/// 发目录（0x01，顺序逐文件）。返回 (字节数, 文件数)。
pub async fn cs_send_folder<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    path: &Path,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<(u64, u32)> {
    let raw = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| crate::error::config_err("路径没有合法 UTF-8 目录名"))?;
    let folder = crate::protocol::frame::sanitize_name(raw)?;
    // 递归清单（确定性排序）。
    let mut files: Vec<PathBuf> = Vec::new();
    fn walk(dir: &Path, exts: &[String], out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            let fname = e.file_name();
            let name = fname.to_string_lossy();
            // 本地缓存产物与半成品不是要发送的内容（v2 帧 collect_files 同口径——
            // 否则 0x04 二轮起把 .trft-hash-cache.txt 当文件传给对端）。
            if crate::hashcache::is_transient_name(&name) {
                continue;
            }
            // 用户配置的排除扩展名（与 v2 帧 collect_files 同口径）。
            if crate::extext::ext_excluded(&name, exts) {
                continue;
            }
            if p.is_dir() {
                walk(&p, exts, out);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
    walk(path, &opts.exclude_exts, &mut files);
    if files.is_empty() {
        return Err(crate::error::config_err("目录为空（C# 0x01 要求 fileCount ≥ 1）"));
    }
    if files.len() > CS_MAX_FOLDER_FILES {
        return Err(crate::error::config_err("目录文件数超上限"));
    }

    let reporter = opts.progress.as_ref();
    if let Some(r) = reporter {
        let total: u64 = files
            .iter()
            .map(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0))
            .sum();
        r.set_total(total);
    }

    // [0x01][folderNameLen i16][folderName][fileCount i32]
    let mut header = Vec::new();
    header.push(F_FOLDER);
    header.extend_from_slice(&(folder.len() as i16).to_le_bytes());
    header.extend_from_slice(folder.as_bytes());
    header.extend_from_slice(&(files.len() as i32).to_le_bytes());
    wire.write_all(&header).await?;

    let mut lim = TokenBucket::new(opts.speed_limit_bps);
    let mut total = 0u64;
    for p in &files {
        let rel_raw = p
            .strip_prefix(path)
            .map_err(|_| crate::error::config_err("相对路径解析失败"))?
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        let rel = cs_sanitize_rel(&rel_raw);
        let meta = std::fs::metadata(p)?;
        let size = meta.len();
        if size > CS_MAX_TRANSFER {
            return Err(crate::error::config_err("文件超过声明上限（1 PiB）"));
        }
        // [size i64][pathLen i16][relPath]
        let mut fh = Vec::with_capacity(10 + rel.len());
        fh.extend_from_slice(&(size as i64).to_le_bytes());
        fh.extend_from_slice(&(rel.len() as i16).to_le_bytes());
        fh.extend_from_slice(rel.as_bytes());
        wire.write_all(&fh).await?;

        let mut f = tokio::fs::File::open(p).await?;
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        let mut buf = vec![0u8; crate::transfer::CHUNK];
        loop {
            let n = f.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            lim.acquire(n as u64).await;
            hasher.update(&buf[..n]);
            wire.write_all(&buf[..n]).await?;
            if let Some(r) = &reporter {
                r.add(n as u64);
            }
        }
        let hash: [u8; 32] = hasher.finalize().into();
        wire.write_all(&hash).await?;
        total += size;
    }
    cs_read_final_ack(wire).await?;
    if let Some(r) = &reporter {
        r.finish();
    }
    Ok((total, files.len() as u32))
}

/// 发文本（0x06）。返回字节数。
pub async fn cs_send_text<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    text: &str,
) -> Result<u64> {
    let bytes = text.as_bytes();
    if bytes.len() > CS_MAX_TEXT {
        return Err(crate::error::config_err("文本超过 1MB 上限"));
    }
    let mut frame = Vec::with_capacity(1 + 4 + bytes.len());
    frame.push(F_TEXT);
    frame.extend_from_slice(&(bytes.len() as i32).to_le_bytes());
    frame.extend_from_slice(bytes);
    wire.write_all(&frame).await?;
    cs_read_final_ack(wire).await?;
    Ok(bytes.len() as u64)
}

/* ============ 客户端：0x03 续传 / 0x02 分块（TCP 槽位，互通改造） ============ */

/// 0x03 会话 GUID：稳定派生（同一文件 × 同一目标 → 同一会话），跨进程/重跑可续。
/// 公开给集成测试构造「中断后重连」的同一会话（生产路径由本模块内部调用）。
pub fn derive_resume_session_guid(path: &Path, size: u64, addr: SocketAddr) -> [u8; 16] {
    use sha1::Digest as _;
    let key = format!(
        "resume|{}|{}|{}|{}",
        path.to_string_lossy().to_lowercase(),
        size,
        addr.ip(),
        addr.port()
    );
    let h = sha1::Sha1::digest(key.as_bytes());
    h[..16].try_into().expect("SHA1 >= 16B")
}

/// 读 0x10 判决（10 字节：[0x10][offset i64][status u8]，长窗口）。EOF = 对端
/// 不认 0x03（旧对端/未启用）→ Unsupported（调用方回退 0x00 全量）。
/// 「对端不认识这帧」在 TCP 上的两种长相：优雅关闭（EOF）与 RST/Aborted/BrokenPipe
/// （对端一读到类型字节就断开、入站缓冲里还压着未读帧头——Linux/macOS 回 RST）。
/// 协商阶段两者都归 Unsupported，调用方才能降级；传输中段只当 IO 错误重试。
fn peer_closed(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}

async fn read_resume_response<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    what: &str,
    unsupported_on_close: bool,
) -> Result<(u64, u8)> {
    let mut resp = [0u8; 10];
    let r = tokio::time::timeout(LONG_READ_WINDOW, wire.read_exact(&mut resp)).await;
    match r {
        Ok(Ok(())) => {}
        Ok(Err(e)) if unsupported_on_close && peer_closed(&e) => {
            return Err(Error::Unsupported(format!(
                "对端未提供 0x03 续传判决（{what}）"
            )))
        }
        Ok(Err(e)) => return Err(Error::Io(e)),
        Err(_) => return Err(proto(format!("0x10 续传应答超时（300s，{what}）"))),
    }
    if resp[0] != R_RESUME {
        return Err(proto(format!("0x10 续传应答类型不符（{what}）")));
    }
    let off = i64::from_le_bytes(resp[1..9].try_into().expect("8B"));
    if off < 0 {
        return Err(proto("续传应答偏移非法"));
    }
    Ok((off as u64, resp[9]))
}

/// 单次 0x03 发送（已建连的线）。返回本次实际发送字节（服务端已有 = 0）。
/// claimed：整文件 SHA-256（调用方在建连之前算好——C# 同纪律）。
pub(crate) async fn cs_send_file_resume_on<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    addr: SocketAddr,
    path: &Path,
    claimed: [u8; 32],
    opts: &crate::transfer::sender::SendOptions,
) -> Result<u64> {
    let raw = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| crate::error::config_err("路径没有合法 UTF-8 文件名"))?;
    let name = crate::protocol::frame::sanitize_name(raw)?;
    let meta = tokio::fs::metadata(path).await?;
    if !meta.is_file() {
        return Err(crate::error::config_err("路径不是普通文件"));
    }
    let size = meta.len();
    if size == 0 {
        return Err(Error::Unsupported("空文件不走 0x03 续传".into()));
    }
    if size > CS_MAX_TRANSFER {
        return Err(crate::error::config_err("文件超过声明上限（1 PiB）"));
    }
    let sid = derive_resume_session_guid(path, size, addr);
    let reporter = opts.progress.as_ref();

    // 头：[0x03][sessionId 16][total i64][resumeOffset i64][nameLen i32][name]
    //     [verifyFlag 1][fullHash 32]。
    let mut header = Vec::with_capacity(1 + 16 + 8 + 8 + 4 + name.len() + 33);
    header.push(F_RESUME);
    header.extend_from_slice(&sid);
    header.extend_from_slice(&(size as i64).to_le_bytes());
    header.extend_from_slice(&0i64.to_le_bytes());
    header.extend_from_slice(&(name.len() as i32).to_le_bytes());
    header.extend_from_slice(name.as_bytes());
    header.push(1);
    header.extend_from_slice(&claimed);
    wire.write_all(&header).await?;

    let (server_off, status) = read_resume_response(wire, "协商", true).await?;
    match status {
        0 | 1 => {}
        2 => {
            // 服务端已持有完整文件（同 sid 重试收敛）：零传输成功。
            if let Some(r) = reporter {
                r.set_total(size);
                r.finish();
            }
            return Ok(0);
        }
        3 => {
            return Err(Error::Rejected(
                "服务端全文件校验失败（源文件已变化？需整文件重发）".into(),
            ))
        }
        _ => return Err(proto(format!("0x10 续传状态未知: {status}"))),
    }
    if server_off > size {
        return Err(proto(format!("续传偏移 {server_off} 超出文件大小 {size}")));
    }
    if let Some(r) = reporter {
        r.set_total(size);
    }

    // 从服务端权威偏移起发送 + 增量 SHA-256（服务端对续传文件按增量核对）。
    let mut f = tokio::fs::File::open(path).await?;
    use tokio::io::AsyncSeekExt as _;
    f.seek(std::io::SeekFrom::Start(server_off)).await?;
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    let mut lim = TokenBucket::new(opts.speed_limit_bps);
    let mut buf = vec![0u8; crate::transfer::CHUNK];
    let mut remaining = size - server_off;
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = f.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{name}: 源文件读取提前结束"),
            )));
        }
        lim.acquire(n as u64).await;
        hasher.update(&buf[..n]);
        wire.write_all(&buf[..n]).await?;
        if let Some(r) = reporter {
            r.add(n as u64);
        }
        remaining -= n as u64;
    }
    let inc: [u8; 32] = hasher.finalize().into();
    wire.write_all(&inc).await?;

    let (_, fin) = read_resume_response(wire, "终态", false).await?;
    match fin {
        2 => {
            if let Some(r) = reporter {
                r.finish();
            }
            Ok(size - server_off)
        }
        3 => Err(Error::Rejected(
            "服务端全文件校验失败（服务端已丢弃该文件）".into(),
        )),
        _ => Err(proto(format!("0x10 续传终态未知: {fin}"))),
    }
}

/// 0x03 的 TCP 单次尝试（建连 + 握手 + 发送）。
pub(crate) async fn cs_send_file_resume_tcp_once(
    addr: SocketAddr,
    path: &Path,
    claimed: [u8; 32],
    opts: &crate::transfer::sender::SendOptions,
) -> Result<u64> {
    let mut wire = cs_connect_tcp(addr, opts).await?;
    let n = cs_send_file_resume_on(&mut wire, addr, path, claimed, opts).await?;
    let _ = wire.shutdown().await;
    Ok(n)
}

/// 发一个 0x02 分块（已建连的线，能力位 0x02 已协商）。判决 = 服务端对 0x02
/// 写的 1 字节 ACK（Rust 服务端总发；C# 服务端不发 → EOF → Unsupported）。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cs_send_chunk_on<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    name: &str,
    path: &Path,
    offset: u64,
    len: u64,
    total: u64,
    group: Option<[u8; 16]>,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<()> {
    // 头：[0x02][total i64][offset i64][chunk i64][nameLen i32][name][flag 1 + gid 16]?
    let mut header = Vec::with_capacity(1 + 28 + name.len() + 17);
    header.push(F_CHUNK);
    header.extend_from_slice(&(total as i64).to_le_bytes());
    header.extend_from_slice(&(offset as i64).to_le_bytes());
    header.extend_from_slice(&(len as i64).to_le_bytes());
    header.extend_from_slice(&(name.len() as i32).to_le_bytes());
    header.extend_from_slice(name.as_bytes());
    if let Some(g) = group {
        header.push(1);
        header.extend_from_slice(&g);
    }
    wire.write_all(&header).await?;

    let mut f = tokio::fs::File::open(path).await?;
    use tokio::io::AsyncSeekExt as _;
    f.seek(std::io::SeekFrom::Start(offset)).await?;
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    let mut lim = TokenBucket::new(opts.speed_limit_bps);
    let mut buf = vec![0u8; crate::transfer::CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = f.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{name}: 源文件读取提前结束"),
            )));
        }
        lim.acquire(n as u64).await;
        hasher.update(&buf[..n]);
        wire.write_all(&buf[..n]).await?;
        if let Some(r) = &opts.progress {
            r.add(n as u64);
        }
        remaining -= n as u64;
    }
    let hash: [u8; 32] = hasher.finalize().into();
    wire.write_all(&hash).await?;

    // 判决：0x01 收下（含本块补满并已发布）/ 0x00 拒绝 / EOF = 对端不发判决。
    let mut ack = [0u8; 1];
    let read = async {
        if wire.ack_on_wire() {
            wire.read_exact(&mut ack).await
        } else {
            wire.raw_read_exact(&mut ack).await
        }
    };
    match tokio::time::timeout(ACK_TIMEOUT, read).await {
        Ok(Ok(())) => match ack[0] {
            0x01 => Ok(()),
            0x00 => Err(Error::Rejected("分块被对端拒绝（哈希或会话）".into())),
            other => Err(proto(format!("分块判决字节异常: 0x{other:02X}"))),
        },
        // EOF / 连接被重置都表示「对端处理后直接关、不发判决」（C# 服务端表现；
        // 关闭时可能有未读字节，Windows 上呈现为 RST 而非 FIN）。
        Ok(Err(e))
            if matches!(
                e.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
            ) =>
        {
            Err(Error::Unsupported(
                "对端不提供 0x02 分块判决（旧对端），需回退整文件发送".into(),
            ))
        }
        Ok(Err(e)) => Err(Error::Io(e)),
        Err(_) => Err(proto("分块判决超时（30s）")),
    }
}



/// 单块单连接发送（含 3 次网络重试；判决类错误不重试）。分块编排与探针共用。
#[allow(clippy::too_many_arguments)]
async fn send_chunk_conn_once(
    addr: SocketAddr,
    opts: &crate::transfer::sender::SendOptions,
    path: &Path,
    name: &str,
    range: (u64, u64),
    size: u64,
    gid: [u8; 16],
) -> Result<()> {
    let mut last: Option<Error> = None;
    for _ in 0..3 {
        let attempt = async {
            let (mut wire, caps) = cs_connect_tcp_full(addr, opts, 0x02).await?;
            if caps & 0x02 == 0 {
                return Err(Error::Unsupported(
                    "对端不支持 0x02 分块组会话（旧对端）".into(),
                ));
            }
            cs_send_chunk_on(&mut wire, name, path, range.0, range.1 - range.0, size, Some(gid), opts)
                .await?;
            let _ = wire.shutdown().await;
            Ok(())
        }
        .await;
        match attempt {
            Ok(()) => return Ok(()),
            // 判决类（旧对端/被拒/配置）不重试：重试只会重复同一结果。
            Err(e @ Error::Unsupported(_))
            | Err(e @ Error::Rejected(_))
            | Err(e @ Error::Config(_)) => return Err(e),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| proto("分块重试耗尽")))
}

/// 0x02 探针建连：要求服务端 caps bit1（组会话 + 逐块判决），否则 Unsupported。
async fn cs_connect_tcp_probe(
    addr: SocketAddr,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<CsWire<tokio::net::TcpStream>> {
    let (wire, caps) = cs_connect_tcp_full(addr, opts, 0x02).await?;
    if caps & 0x02 == 0 {
        return Err(Error::Unsupported(
            "对端不支持 0x02 分块组会话（旧对端）".into(),
        ));
    }
    Ok(wire)
}

/// TCP 槽位并行分块（C# 0x02：一连接一块 + 组会话 id）。每块等 Rust 服务端的
/// 1 字节判决；C# 服务端不发判决 → Unsupported（调用方回退整文件发送）。
pub async fn send_file_chunked_cs_tcp(
    addr: SocketAddr,
    path: &Path,
    opts: &crate::transfer::sender::SendOptions,
    connections: u8,
) -> Result<()> {
    let outcome = crate::progress::Outcome::new(opts.progress.clone());
    let raw = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| crate::error::config_err("路径没有合法 UTF-8 文件名"))?;
    let name = crate::protocol::frame::sanitize_name(raw)?;
    let meta = tokio::fs::metadata(path).await?;
    if !meta.is_file() {
        return Err(crate::error::config_err("路径不是普通文件"));
    }
    let size = meta.len();
    if size == 0 {
        return Err(crate::error::config_err(
            "分块传输不支持空文件（应改为直接发送）",
        ));
    }
    if size > CS_MAX_TRANSFER {
        return Err(crate::error::config_err("文件超过声明上限（1 PiB）"));
    }
    // 组 id 每次调用全新：源文件变化必须换组全量重发（v2 帧 0x02 同纪律）。
    let mut gid = [0u8; 16];
    {
        use rand_core::RngCore as _;
        rand_core::OsRng.fill_bytes(&mut gid);
    }
    let ranges = crate::transfer::chunked::split_ranges(size, connections.clamp(1, 8) as usize);
    let started = Instant::now();
    if let Some(r) = &opts.progress {
        r.set_total(size);
    }
    // 能力探针（实机教训）：C# 服务端对 0x02 不发判决，若先发真分块再回退，
    // 对端已建组装器占住最终名 → 0x03 回退落成 src_1.bin（重复文件）。
    // 用**非法头**（chunk=0）探判决能力：两侧都会在解析头时直接拒绝、不建组装器、
    // 不落盘；Rust 服务端回 1 字节 0x00，C# 服务端直接断连（EOF）。
    {
        let mut wire = cs_connect_tcp_probe(addr, opts).await?;
        let mut hdr = vec![0x02u8];
        hdr.extend_from_slice(&(size as i64).to_le_bytes());
        hdr.extend_from_slice(&0i64.to_le_bytes());
        hdr.extend_from_slice(&0i64.to_le_bytes()); // chunk = 0 → 非法头
        hdr.extend_from_slice(&1i32.to_le_bytes());
        hdr.push(b'x');
        wire.write_all(&hdr).await?;
        let mut ack = [0u8; 1];
        match tokio::time::timeout(ACK_TIMEOUT, wire.read_exact(&mut ack)).await {
            Ok(Ok(())) => { /* 有判决（本仓库服务端） */ }
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return Err(Error::Unsupported(
                    "对端不提供 0x02 分块判决（C# 服务端不发），改用整文件续传".into(),
                ))
            }
            Ok(Err(e)) => return Err(Error::Io(e)),
            Err(_) => return Err(proto("0x02 能力探针超时（30s）")),
        }
        let _ = wire.shutdown().await;
    }
    let mut set = tokio::task::JoinSet::new();
    for range in ranges {
        let opts2 = opts.clone();
        let path2 = path.to_path_buf();
        let name2 = name.clone();
        set.spawn(async move {
            send_chunk_conn_once(addr, &opts2, &path2, &name2, range, size, gid).await
        });
    }
    let mut results: Vec<Result<()>> = Vec::new();
    while let Some(joined) = set.join_next().await {
        results.push(joined.map_err(|e| proto(e.to_string())).and_then(|r| r));
    }
    if let Some(e) = results.iter().find_map(|r| match r {
        Err(Error::Unsupported(m)) => Some(Error::Unsupported(m.clone())),
        _ => None,
    }) {
        return Err(e);
    }
    if let Some(e) = results.iter().find_map(|r| match r {
        Err(Error::Rejected(m)) => Some(Error::Rejected(m.clone())),
        Err(Error::Config(m)) => Some(Error::Config(m.clone())),
        _ => None,
    }) {
        return Err(e);
    }
    if let Some(e) = results.iter().find_map(|r| match r {
        Err(Error::Io(e)) => Some(Error::Io(io::Error::new(e.kind(), e.to_string()))),
        Err(Error::Protocol(m)) => Some(proto(m.clone())),
        Err(Error::AuthRejected(m)) => Some(Error::AuthRejected(m.clone())),
        Err(Error::Crypto(m)) => Some(Error::Crypto(m.clone())),
        _ => None,
    }) {
        return Err(e);
    }
    outcome.finish();
    crate::transfer::sender::record_stats(
        opts,
        addr,
        size,
        1,
        started,
        &format!("分块传输×{connections}"),
        &name,
    );
    Ok(())
}

/* ============ 高层发送入口（sender.rs 的 Transport::Udt/Tcp 分支调用） ============ */

/// 0x00 发送体（已建连、已认证的线；UDT/TCP 共用）+ 发送侧统计。
pub(crate) async fn send_file_cs_on<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    addr: SocketAddr,
    path: &Path,
    opts: &crate::transfer::sender::SendOptions,
    started: Instant,
) -> Result<()> {
    let bytes = cs_send_file(wire, path, opts).await?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();
    crate::transfer::sender::record_stats(opts, addr, bytes, 1, started, "单文件", &name);
    Ok(())
}

/// UDT 槽位发单文件（建连 + 认证 + 0x00 + 统计）。
pub async fn send_file_cs(
    addr: SocketAddr,
    path: &Path,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<()> {
    let outcome = crate::progress::Outcome::new(opts.progress.clone());
    let started = Instant::now();
    let res = async {
        let mut wire = cs_connect_stack(addr, opts).await?;
        send_file_cs_on(&mut wire, addr, path, opts, started).await?;
        let _ = wire.shutdown().await;
        Ok(())
    }
    .await;
    if res.is_ok() {
        outcome.finish();
    }
    res
}

/// TCP 槽位发单文件（同一 C# 方言应用层；互通改造——TCP 与 UDT 共用 0x00）。
pub async fn send_file_cs_tcp(
    addr: SocketAddr,
    path: &Path,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<()> {
    let outcome = crate::progress::Outcome::new(opts.progress.clone());
    let started = Instant::now();
    let res = async {
        let mut wire = cs_connect_tcp(addr, opts).await?;
        send_file_cs_on(&mut wire, addr, path, opts, started).await?;
        let _ = wire.shutdown().await;
        Ok(())
    }
    .await;
    if res.is_ok() {
        outcome.finish();
    }
    res
}

/// C# DeriveSyncSession 同式：SHA1("sync|<folder>|<ip>|<port>|udt") 前 16B。
/// 与 C# CLI/GUI sync 的稳定会话互认（服务端会话目录 `<folder>.<guid8>` 一致）。
fn derive_sync_session_guid(folder: &str, ip: &str, port: u16) -> [u8; 16] {
    use sha1::Digest as _;
    let key = format!(
        "sync|{}|{}|{}|udt",
        folder.trim_end_matches(['\\', '/']).to_lowercase(),
        ip,
        port
    );
    let h = sha1::Sha1::digest(key.as_bytes());
    h[..16].try_into().expect("SHA1 >= 16B")
}

/// C# 方言 0x04 差量同步客户端（v2 → C#；C# SendFolderResumableAsync keepState
/// 同构）。`client_cache`：发送端摘要缓存（命中免算哈希，现算后回填——与 v2 帧
/// 0x04 同口径）。返回 (发送字节, 发送文件数；服务端已全有 = (0,0))。
pub(crate) struct CsSyncManifest {
    pub folder: String,
    pub entries: Vec<CsSyncEntry>,
    pub total: u64,
}

pub(crate) struct CsSyncEntry {
    pub rel: String,
    pub path: PathBuf,
    pub size: u64,
    pub hash: [u8; 32],
}

/// 清单构建（**建连前**调用——C# BuildFolderManifest 同款：哈希在连接后现算
/// 会撞服务端 30s 收超时）。命中发送端摘要缓存免算，现算后回填（纳秒粒度键，
/// 同 §7.31：秒粒度同秒同长改写 = 漏改）。
pub(crate) async fn build_sync_manifest(
    path: &Path,
    exclude_exts: &[String],
    client_cache: Option<&std::sync::Arc<tokio::sync::Mutex<crate::hashcache::HashCache>>>,
) -> Result<CsSyncManifest> {
    let raw = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| crate::error::config_err("路径没有合法 UTF-8 目录名"))?;
    let folder = crate::protocol::frame::sanitize_name(raw)?;
    // 递归清单（确定性排序，与 cs_send_folder 同款）。
    let mut files: Vec<PathBuf> = Vec::new();
    fn walk(dir: &Path, exts: &[String], out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            let fname = e.file_name();
            let name = fname.to_string_lossy();
            // 本地缓存产物与半成品不是要发送的内容（v2 帧 collect_files 同口径——
            // 否则 0x04 二轮起把 .trft-hash-cache.txt 当文件传给对端）。
            if crate::hashcache::is_transient_name(&name) {
                continue;
            }
            // 用户配置的排除扩展名（与 v2 帧 collect_files 同口径）。
            if crate::extext::ext_excluded(&name, exts) {
                continue;
            }
            if p.is_dir() {
                walk(&p, exts, out);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
    walk(path, exclude_exts, &mut files);
    if files.is_empty() {
        return Err(crate::error::config_err("目录为空（0x04 要求 fileCount >= 1）"));
    }
    if files.len() > CS_MAX_FOLDER_FILES {
        return Err(crate::error::config_err("目录文件数超上限"));
    }
    let mut entries = Vec::with_capacity(files.len());
    let mut total: u64 = 0;
    for p in &files {
        let rel_raw = p
            .strip_prefix(path)
            .map_err(|_| crate::error::config_err("相对路径解析失败"))?
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        let rel = cs_sanitize_rel(&rel_raw);
        let meta = tokio::fs::metadata(p).await?;
        let size = meta.len();
        if size > CS_MAX_TRANSFER {
            return Err(crate::error::config_err("文件超过声明上限（1 PiB）"));
        }
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let known = match client_cache {
            Some(c) => c.lock().await.get(&rel, size, mtime),
            None => None,
        };
        let hash = match known {
            Some(h) => h,
            None => {
                let h = crate::hash::sha256_file(p)?;
                if let Some(c) = client_cache {
                    c.lock().await.insert(&rel, size, mtime, h);
                }
                h
            }
        };
        total += size;
        entries.push(CsSyncEntry { rel, path: p.clone(), size, hash });
    }
    Ok(CsSyncManifest { folder, entries, total })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn cs_send_folder_sync<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    manifest: &CsSyncManifest,
    sid: [u8; 16],
    per_file_skip: bool,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<(u64, u32)> {
    let entries = &manifest.entries;
    let folder = &manifest.folder;
    let reporter = opts.progress.as_ref();
    // 头：[0x04][sessionId 16][folderNameLen i16][folderName][fileCount i32][totalBytes i64]
    let mut header = Vec::with_capacity(1 + 16 + 2 + folder.len() + 4 + 8);
    header.push(F_FOLDER_RESUME);
    header.extend_from_slice(&sid);
    header.extend_from_slice(&(folder.len() as i16).to_le_bytes());
    header.extend_from_slice(folder.as_bytes());
    header.extend_from_slice(&(entries.len() as i32).to_le_bytes());
    header.extend_from_slice(&(manifest.total as i64).to_le_bytes());
    wire.write_all(&header).await?;
    // 清单：每文件 [size i64][pathLen i16][relPath][fullHash 32]
    for e in entries.iter() {
        let mut m = Vec::with_capacity(10 + e.rel.len() + 32);
        m.extend_from_slice(&(e.size as i64).to_le_bytes());
        m.extend_from_slice(&(e.rel.len() as i16).to_le_bytes());
        m.extend_from_slice(e.rel.as_bytes());
        m.extend_from_slice(&e.hash);
        wire.write_all(&m).await?;
    }

    // 0x11 判决（长窗口）。对端不认 0x04 时可能优雅关闭（EOF），也可能在读到
    // 类型字节后直接断开（入站残留帧头 → Linux/macOS 回 RST）——两者同判
    // Unsupported，调用方才能给出「旧对端/未启用」的明确结论。
    let mut resp = [0u8; 18];
    match tokio::time::timeout(LONG_READ_WINDOW, wire.read_exact(&mut resp)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) if peer_closed(&e) => {
            return Err(Error::Unsupported(
                "对端不支持文件夹同步（0x04，旧对端或未启用）".into(),
            ))
        }
        Ok(Err(e)) => return Err(Error::Io(e)),
        Err(_) => return Err(proto("0x11 同步判决应答超时（300s）")),
    }
    if resp[0] == 0x00 {
        // 接收前确认未通过：服务端写判决字节后拒绝（C# C_RejectedByPeer 同判）。
        return Err(Error::Rejected("被对端拒绝接收（接收前确认未通过）".into()));
    }
    if resp[0] != R_FOLDER_RESUME {
        return Err(proto("同步判决应答类型不符"));
    }
    let resume_index = i64::from_le_bytes(resp[1..9].try_into().expect("8B"));
    let resume_offset = i64::from_le_bytes(resp[9..17].try_into().expect("8B"));
    let status = resp[17];
    if resume_index < 0
        || resume_index > entries.len() as i64
        || resume_offset < 0
        || resume_offset as u64
            > entries
                .get(resume_index as usize)
                .map(|e| e.size)
                .unwrap_or(0)
    {
        return Err(proto("同步判决续点非法"));
    }

    // 进度总量 = 差量（status 2 = 服务端已全有 → 零传输）。
    if let Some(r) = &reporter {
        let to_send: u64 = if status == 2 {
            0
        } else {
            entries
                .iter()
                .enumerate()
                .skip(resume_index as usize)
                .map(|(i, e)| {
                    if i == resume_index as usize {
                        e.size.saturating_sub(resume_offset as u64)
                    } else {
                        e.size
                    }
                })
                .sum()
        };
        r.set_total(to_send);
    }
    if status == 2 {
        // 服务端已持有全部文件（目录/哈希一致）——带外 ACK 后收工。
        cs_read_final_ack(wire).await?;
        if let Some(r) = &reporter {
            r.finish();
        }
        return Ok((0, 0));
    }

    // 逐文件跳过清单（0x0A bit0 协商成功且续点未到末尾）：声明剩余文件 →
    // 服务端逐个回 0 跳过 / 1 需发送（C# NegotiatePerFileSkipAsync 同构）。
    let mut need: Option<Vec<bool>> = None;
    if per_file_skip {
        for e in &entries[resume_index as usize..] {
            let mut m = Vec::with_capacity(10 + e.rel.len() + 32);
            m.extend_from_slice(&(e.size as i64).to_le_bytes());
            m.extend_from_slice(&(e.rel.len() as i16).to_le_bytes());
            m.extend_from_slice(e.rel.as_bytes());
            m.extend_from_slice(&e.hash);
            wire.write_all(&m).await?;
        }
        let n = entries.len() - resume_index as usize;
        let mut answers = vec![0u8; n];
        tokio::time::timeout(LONG_READ_WINDOW, wire.read_exact(&mut answers))
            .await
            .map_err(|_| proto("跳过清单应答超时（300s）"))?
            .map_err(Error::Io)?;
        need = Some(answers.iter().map(|&a| a == 1).collect());
    }

    // 顺序发（首个自 resumeOffset 续传；每段载荷尾随**增量**的 SHA-256——
    // 服务端对续传文件按增量哈希核对，C# SendFilePayload 同构）。
    let mut lim = TokenBucket::new(opts.speed_limit_bps);
    let mut sent_bytes = 0u64;
    let mut sent_files = 0u32;
    for (i, e) in entries.iter().enumerate().skip(resume_index as usize) {
        if let Some(n) = &need {
            if !n[i - resume_index as usize] {
                continue;
            }
        }
        let start = if i == resume_index as usize {
            resume_offset as u64
        } else {
            0
        };
        let send_size = e.size - start;
        let mut f = tokio::fs::File::open(&e.path).await?;
        use tokio::io::AsyncSeekExt as _;
        f.seek(std::io::SeekFrom::Start(start)).await?;
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        let mut buf = vec![0u8; crate::transfer::CHUNK];
        let mut left = send_size;
        while left > 0 {
            let want = buf.len().min(left as usize);
            let n = f.read(&mut buf[..want]).await?;
            if n == 0 {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("{}: 文件读取提前结束", e.rel),
                )));
            }
            lim.acquire(n as u64).await;
            hasher.update(&buf[..n]);
            wire.write_all(&buf[..n]).await?;
            if let Some(r) = &reporter {
                r.add(n as u64);
            }
            left -= n as u64;
        }
        let inc_hash: [u8; 32] = hasher.finalize().into();
        wire.write_all(&inc_hash).await?;
        sent_bytes += send_size;
        sent_files += 1;
    }
    // 带外 1B ACK（UDT 裸流——装饰器之外；C# RunUdtTransfer 同款）。
    cs_read_final_ack(wire).await?;
    if let Some(r) = &reporter {
        r.finish();
    }
    Ok((sent_bytes, sent_files))
}

/// 0x04 差量同步的公共尾段（清单 → 头/清单流 → 判决 → 差量发送 → 统计）。
#[allow(clippy::too_many_arguments)]
async fn folder_sync_cs_after_connect<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    addr: SocketAddr,
    path: &Path,
    manifest: &CsSyncManifest,
    caps: u8,
    opts: &crate::transfer::sender::SendOptions,
    started: Instant,
    name: &str,
) -> Result<()> {
    let per_file_skip = caps & 0x01 != 0;
    let sid = derive_sync_session_guid(&path.to_string_lossy(), &addr.ip().to_string(), addr.port());
    let (bytes, files) =
        cs_send_folder_sync(wire, manifest, sid, per_file_skip, opts).await?;
    let _ = wire.shutdown().await;
    crate::transfer::sender::record_stats(opts, addr, bytes, files, started, "文件夹同步", name);
    Ok(())
}

/// UDT 槽位差量同步（v2 → C# 0x04；会话 GUID 与 C# DeriveSyncSession 同式，
/// 同一 (folder, target) 的重复同步与 C# 客户端互相接力）。
pub async fn send_folder_sync_cs(
    addr: SocketAddr,
    path: &Path,
    opts: &crate::transfer::sender::SendOptions,
    client_cache: Option<&std::sync::Arc<tokio::sync::Mutex<crate::hashcache::HashCache>>>,
) -> Result<()> {
    let outcome = crate::progress::Outcome::new(opts.progress.clone());
    let started = Instant::now();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("folder")
        .to_string();
    let res = async {
        // 清单（全文件哈希）在**建连前**构建——C# BuildFolderManifest 同款：
        // 大目录建连后现算哈希会撞服务端 30s 收超时。
        let manifest = build_sync_manifest(path, &opts.exclude_exts, client_cache).await?;
        // 0x01 能力位（逐文件跳过清单）随认证栈协商。
        let (mut wire, caps) = cs_connect_stack_full(addr, opts, 0x01).await?;
        folder_sync_cs_after_connect(
            &mut wire, addr, path, &manifest, caps, opts, started, &name,
        )
        .await
    }
    .await;
    if res.is_ok() {
        outcome.finish();
    }
    res
}

/// TCP 槽位差量同步（0x04，C# 方言）——Tcp 与 Udt 同一应用层。
pub async fn send_folder_sync_cs_tcp(
    addr: SocketAddr,
    path: &Path,
    opts: &crate::transfer::sender::SendOptions,
    client_cache: Option<&std::sync::Arc<tokio::sync::Mutex<crate::hashcache::HashCache>>>,
) -> Result<()> {
    let outcome = crate::progress::Outcome::new(opts.progress.clone());
    let started = Instant::now();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("folder")
        .to_string();
    let res = async {
        let manifest = build_sync_manifest(path, &opts.exclude_exts, client_cache).await?;
        let (mut wire, caps) = cs_connect_tcp_full(addr, opts, 0x01).await?;
        folder_sync_cs_after_connect(
            &mut wire, addr, path, &manifest, caps, opts, started, &name,
        )
        .await
    }
    .await;
    if res.is_ok() {
        outcome.finish();
    }
    res
}

/// 0x01 发送体（已建连的线；UDT/TCP 共用）+ 发送侧统计。
pub(crate) async fn send_folder_cs_on<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    addr: SocketAddr,
    path: &Path,
    opts: &crate::transfer::sender::SendOptions,
    started: Instant,
) -> Result<()> {
    let (bytes, files) = cs_send_folder(wire, path, opts).await?;
    crate::transfer::sender::record_stats(
        opts,
        addr,
        bytes,
        files,
        started,
        "目录",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("目录"),
    );
    Ok(())
}

/// UDT 槽位发目录（建连 + 认证 + 0x01 + 统计）。
pub async fn send_folder_cs(
    addr: SocketAddr,
    path: &Path,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<()> {
    let outcome = crate::progress::Outcome::new(opts.progress.clone());
    let started = Instant::now();
    let res = async {
        let mut wire = cs_connect_stack(addr, opts).await?;
        send_folder_cs_on(&mut wire, addr, path, opts, started).await?;
        let _ = wire.shutdown().await;
        Ok(())
    }
    .await;
    if res.is_ok() {
        outcome.finish();
    }
    res
}

/// TCP 槽位发目录（0x01，C# 方言）。
pub async fn send_folder_cs_tcp(
    addr: SocketAddr,
    path: &Path,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<()> {
    let outcome = crate::progress::Outcome::new(opts.progress.clone());
    let started = Instant::now();
    let res = async {
        let mut wire = cs_connect_tcp(addr, opts).await?;
        send_folder_cs_on(&mut wire, addr, path, opts, started).await?;
        let _ = wire.shutdown().await;
        Ok(())
    }
    .await;
    if res.is_ok() {
        outcome.finish();
    }
    res
}

/// 0x06 发送体（已建连的线；UDT/TCP 共用）+ 发送侧统计。
pub(crate) async fn send_text_cs_on<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut CsWire<S>,
    addr: SocketAddr,
    text: &str,
    opts: &crate::transfer::sender::SendOptions,
    started: Instant,
) -> Result<()> {
    if let Some(r) = &opts.progress {
        r.set_total(text.len() as u64);
    }
    let n = cs_send_text(wire, text).await?;
    crate::transfer::sender::record_stats(opts, addr, n, 0, started, "文本消息", "<文本>");
    Ok(())
}

/// UDT 槽位发文本（建连 + 认证 + 0x06 + 统计）。
pub async fn send_text_cs(
    addr: SocketAddr,
    text: &str,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<()> {
    let started = Instant::now();
    let mut wire = cs_connect_stack(addr, opts).await?;
    send_text_cs_on(&mut wire, addr, text, opts, started).await?;
    let _ = wire.shutdown().await;
    Ok(())
}

/// TCP 槽位发文本（0x06，C# 方言）。
pub async fn send_text_cs_tcp(
    addr: SocketAddr,
    text: &str,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<()> {
    let started = Instant::now();
    let mut wire = cs_connect_tcp(addr, opts).await?;
    send_text_cs_on(&mut wire, addr, text, opts, started).await?;
    let _ = wire.shutdown().await;
    Ok(())
}

/* ============ 单测（已知答案向量 + 自洽） ============ */

#[cfg(test)]
mod tests {
    use super::*;

    /// 判别（2026-11-23，服务端重启场景）：`known_complete` 必须跨进程存活——
    /// 新 `CsServerState`（= 重启后的服务端）凭保存目录里的 journal 仍能认出
    /// 「上一轮写完的完整版本」，不会把变长旧档当断点半成品去拼接。
    /// 纯内存实现下第二次断言必红（TECH-STACK §7.64 残留项）。
    #[test]
    fn known_complete_survives_restart_via_journal() {
        let dir = tempfile::tempdir().unwrap();
        let done = dir.path().join("done.bin");
        std::fs::write(&done, b"alpha\n").unwrap();
        let hash = crate::hash::sha256_file(&done).unwrap();

        let st1 = Arc::new(CsServerState::with_journal(
            dir.path(),
            crate::hashcache::DEFAULT_TTL_DAYS,
        ));
        let size = std::fs::metadata(&done).unwrap().len();
        remember_sync_hash(&st1, &done, &hash);
        assert!(known_complete(&st1, &done, size), "当前进程必须认得刚写完的版本");

        // 重启：新状态、空内存缓存，只有落盘 journal。
        let st2 = Arc::new(CsServerState::with_journal(
            dir.path(),
            crate::hashcache::DEFAULT_TTL_DAYS,
        ));
        assert!(
            st2.sync_hashes.lock().unwrap().is_empty(),
            "前提：新状态的内存缓存必须是空的"
        );
        assert!(
            known_complete(&st2, &done, size),
            "落盘 journal 必须让重启后的服务端仍认出「已知完整」"
        );

        // 负例：从未登记过的短文件仍是断点半成品（不得一律当完整，否则续传失效）。
        let partial = dir.path().join("partial.bin");
        std::fs::write(&partial, b"half").unwrap();
        assert!(!known_complete(&st2, &partial, 4), "未登记文件不得判为已知完整");
        // 负例：同一路径换了长度即不认（键含 size——旧版本被改过）。
        assert!(!known_complete(&st2, &done, size + 9), "长度不符不得命中");
    }

    /// 轮 UI-5 续 5 判别：tracker/会话表必须有条数上限（declared_total 只封字节），
    /// 超出按 touched 最旧逐出；resume 只摘会话不删文件（可能是已验证交付）。
    #[test]
    fn session_tables_are_capped() {
        let dir = tempfile::tempdir().unwrap();
        let state = CsServerState::default();
        {
            let mut t = state.trackers.lock().unwrap();
            for i in 0..(CS_MAX_TRACKERS + 5) {
                let p = dir.path().join(format!("t{i}.part"));
                let mut tr = CsChunkTracker::create(p, 1).unwrap();
                tr.touched = Instant::now() - Duration::from_secs(i as u64);
                t.insert(format!("k{i}"), tr);
            }
        }
        {
            let mut rs = state.resume.lock().unwrap();
            for i in 0..(CS_MAX_RESUME_SESSIONS + 5) {
                rs.insert(
                    format!("s{i}"),
                    CsResumeState {
                        save_path: dir.path().join(format!("r{i}")),
                        total: 1,
                        received: 0,
                        name: "x".into(),
                        peer_ip: "1.1.1.1".into(),
                        touched: Instant::now() - Duration::from_secs(i as u64),
                        verified: false,
                        verified_hash: None,
                        declared_held: false,
                    },
                );
            }
        }
        cs_sweep_stale(&state);
        assert!(
            state.trackers.lock().unwrap().len() <= CS_MAX_TRACKERS,
            "tracker 表必须有上限"
        );
        assert!(
            state.resume.lock().unwrap().len() <= CS_MAX_RESUME_SESSIONS,
            "会话表必须有上限"
        );
    }

    /// 轮 UI-5 自查：会话声明量收尾必须幂等（完成释放后，TTL 清扫/参数变化/
    /// 失败删除不得重复扣减——否则 declared_total 下溢/额度错乱）。
    #[test]
    fn resume_declaration_release_is_idempotent() {
        use std::sync::atomic::Ordering;
        let state = CsServerState::default();
        cs_declare(&state, 1000).unwrap();
        assert_eq!(state.declared_total.load(Ordering::Relaxed), 1000);
        let mut st = CsResumeState {
            save_path: PathBuf::from("x.bin"),
            total: 1000,
            received: 1000,
            name: "x.bin".into(),
            peer_ip: "127.0.0.1".into(),
            touched: Instant::now(),
            verified: true,
            verified_hash: None,
            declared_held: true,
        };
        release_resume_declared(&state, &mut st);
        assert_eq!(state.declared_total.load(Ordering::Relaxed), 0, "完成即释放");
        release_resume_declared(&state, &mut st);
        assert_eq!(
            state.declared_total.load(Ordering::Relaxed),
            0,
            "重复收尾不得二次扣减"
        );
    }

    /// PBKDF2-HMAC-SHA1 已知答案。
    /// 向量 A：RFC 6070 c=4096（20B）。向量 B：Windows .NET Rfc2898DeriveBytes
    ///（= C# WireCrypto 同算法）与 OpenSSL hashlib 双源确认——C# 实机捕获固化。
    #[test]
    fn pbkdf2_sha1_known_answers() {
        let mut out = [0u8; 20];
        pbkdf2_sha1("password", b"salt", 4096, &mut out);
        assert_eq!(
            hex(&out),
            "4b007901b765489abead49d926f721d065a429c1",
            "RFC 6070 c=4096 向量"
        );
        let salt: Vec<u8> = (0u8..16).collect();
        let mut out2 = [0u8; 32];
        pbkdf2_sha1("246810", &salt, 50_000, &mut out2);
        assert_eq!(
            hex(&out2),
            "bd82392d8291890edd9fc949631f2ad5b791d8b82c97616be1d6a62a07f9e18b",
            ".NET Rfc2898DeriveBytes 实机向量（50000 迭代）"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// AES-256-CTR 计数器语义：大端 16B 递增 + 跨段持续。
    /// 密钥流向量由 Windows .NET（C# AesCtrTransform 同构：ECB 原语加密计数器块）实机生成。
    #[test]
    fn aes256_ctr_keystream_matches_dotnet() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x11, 0xf3, 0x52, 0xc0, 0x73, 0xb6, 0x10, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let mut w = CsEncWrite::new(key, [0u8; 32]);
        // 48 字节全零明文（单段）：密文 = 计数器 0/1/2 的密钥流。
        let wire = w.encrypt(&[0u8; 48]);
        let ks = hex(&wire[28..]);
        assert_eq!(
            ks,
            concat!(
                "683d07936efd8758a24266158f57ede1",
                "783e54564d01b52dc6e6236295d4c67d",
                "3cb63f69446a0270d4cb55f8bf7b3178"
            ),
            ".NET 实机密钥流（128 位大端计数递增）"
        );
    }

    /// CNG blob 编解码往返 + 魔数锁定（CngKeyBlobFormat.EccPublicBlob 解析要求）。
    #[test]
    fn cng_blob_roundtrip() {
        let x = [7u8; 32];
        let y = [9u8; 32];
        let blob = cng_public_blob(&x, &y);
        assert_eq!(blob.len(), ECDH_PUBLIC_BYTES);
        assert_eq!(&blob[..4], &CNG_ECDH_PUBLIC_P256_MAGIC_BYTES);
        assert_eq!(&blob[4..8], &32u32.to_le_bytes());
        assert_eq!(&blob[8..40], &x);
        assert_eq!(&blob[40..72], &y);
        assert_eq!(cng_parse_blob(&blob).unwrap(), (x, y));
        assert!(cng_parse_blob(&blob[..71]).is_none(), "长度不符必须拒绝");
        assert!(cng_parse_blob(&blob[..64]).is_none());
    }

    /// 0x09 密钥调度自洽：客户端/服务端对同一 (code, 公钥对, 共享材料)
    /// 推出相同 authKey/confirm/会话密钥，且 confirm 双向标签区分。
    #[test]
    fn key_schedule_symmetry() {
        use p256::ecdh::EphemeralSecret;
        let code = "246810";
        let client = EphemeralSecret::random(&mut rand_core::OsRng);
        let server = EphemeralSecret::random(&mut rand_core::OsRng);
        let cp = client.public_key().to_encoded_point(false);
        let sp = server.public_key().to_encoded_point(false);
        let mut cx = [0u8; 32];
        let mut cy = [0u8; 32];
        cx.copy_from_slice(cp.x().expect("X"));
        cy.copy_from_slice(cp.y().expect("Y"));
        let c_pub = cng_public_blob(&cx, &cy);
        let mut sx = [0u8; 32];
        let mut sy = [0u8; 32];
        sx.copy_from_slice(sp.x().expect("X"));
        sy.copy_from_slice(sp.y().expect("Y"));
        let s_pub = cng_public_blob(&sx, &sy);

        // 共享材料 = SHA256(X)：客户端用服务端公钥、服务端用客户端公钥 → 同一点。
        let peer_of_client = cng_blob_to_public_key(&s_pub).unwrap();
        let zc = client.diffie_hellman(&peer_of_client);
        let peer_of_server = cng_blob_to_public_key(&c_pub).unwrap();
        let zs = server.diffie_hellman(&peer_of_server);
        assert_eq!(zc.raw_secret_bytes(), zs.raw_secret_bytes(), "ECDH 共享点一致");
        let material: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(zc.raw_secret_bytes());
            h.finalize().into()
        };

        let ka = cs_derive_auth_key(code, &c_pub, &s_pub, &material);
        let kb = cs_derive_auth_key(code, &c_pub, &s_pub, &material);
        assert_eq!(ka, kb);
        let confirm_s = cs_confirm(&ka, "s2c-confirm", &c_pub, &s_pub);
        let confirm_c = cs_confirm(&ka, "c2s-confirm", &c_pub, &s_pub);
        assert_ne!(confirm_s, confirm_c, "双向标签必须产生不同 confirm");

        // 会话密钥四向互异。
        let c2s_enc = cs_session_key(&ka, "c2s-enc");
        let c2s_mac = cs_session_key(&ka, "c2s-mac");
        let s2c_enc = cs_session_key(&ka, "s2c-enc");
        let s2c_mac = cs_session_key(&ka, "s2c-mac");
        assert_ne!(c2s_enc, s2c_enc);
        assert_ne!(c2s_mac, s2c_mac);
        assert_ne!(c2s_enc, c2s_mac);

        // 段加解密往返（seq 绑定 + 跨段计数器持续——持久 Ctr 逐段解密拼回原文）。
        let mut ew = CsEncWrite::new(c2s_enc, c2s_mac);
        let plain: Vec<u8> = (0..ENC_SEGMENT_MAX + 1000).map(|i| (i % 251) as u8).collect();
        let wire = ew.encrypt(&plain);
        let mut ctr = Ctr128BE::<Aes256>::new(
            generic_array::GenericArray::from_slice(&c2s_enc),
            generic_array::GenericArray::from_slice(&[0u8; 16]),
        );
        let mut got = Vec::new();
        let mut off = 0usize;
        let mut expect_seq = 0i64;
        while off < wire.len() {
            let seq = i64::from_le_bytes(wire[off..off + 8].try_into().unwrap());
            let len = i32::from_le_bytes(wire[off + 8..off + 12].try_into().unwrap()) as usize;
            assert_eq!(seq, expect_seq, "段序号连续");
            let seg_end = off + 12 + 16 + len;
            let mac16 = &wire[off + 12..off + 28];
            let mut ct = wire[off + 28..seg_end].to_vec();
            let mut mac = <Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(&c2s_mac).unwrap();
            mac.update(&seq.to_le_bytes());
            mac.update(&(len as i32).to_le_bytes());
            mac.update(&ct);
            let expect = &mac.finalize().into_bytes()[..16];
            assert_eq!(expect, mac16, "MAC 逐段一致");
            ctr.apply_keystream(&mut ct);
            got.extend_from_slice(&ct);
            off = seg_end;
            expect_seq += 1;
        }
        assert_eq!(got, plain, "跨段计数器持续 → 拼回原文");
    }

    /// SafeName / SanitizeRelativePath 与 C# 语义对齐。
    #[test]
    fn sanitize_matches_csharp() {
        assert_eq!(cs_safe_name("a/b/c.txt", "f"), "c.txt");
        assert_eq!(cs_safe_name("name..", "f"), "name");
        assert_eq!(cs_safe_name("CON", "f"), "_CON");
        assert_eq!(cs_safe_name("com1.txt", "f"), "_com1.txt");
        assert_eq!(cs_safe_name("", "received_file"), "received_file");
        let win_path = String::from("a") + "\\" + "b" + "\\" + "c.txt";
        let joined = format!(
            "a{}b{}c.txt",
            std::path::MAIN_SEPARATOR,
            std::path::MAIN_SEPARATOR
        );
        assert_eq!(cs_sanitize_rel(&win_path), joined);
        assert_eq!(cs_sanitize_rel("/../x.txt"), format!("_{}x.txt", std::path::MAIN_SEPARATOR));
        assert_eq!(cs_sanitize_rel("a:b.txt"), "a_b.txt");
        assert_eq!(
            cs_unique_save_path(Path::new("/tmp"), "x.bin")
                .file_name()
                .unwrap(),
            "x.bin"
        );
    }

    /// 组装器落盘：乱序写 4 段 + 完整性判定（洞不得判完整）。
    #[test]
    fn chunk_tracker_writes_and_completeness() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.bin");
        let mut tr = CsChunkTracker::create(path.clone(), 400).unwrap();
        let seg: Vec<u8> = (0..100u32).map(|i| (i % 251) as u8).collect();
        // 乱序：第 3 段先到。写数据与登记覆盖分两步（尾哈希通过才 commit）。
        tr.write_data(200, &seg).unwrap();
        assert!(!tr.commit_range(200, 100));
        tr.write_data(300, &seg).unwrap();
        assert!(!tr.commit_range(300, 100));
        // 此时 ranges=[(200,299),(300,399)] —— 首段缺失，不得判完整。
        assert!(
            !(tr.ranges_exclusive().first().map(|r| r.0) == Some(0)
                && tr.ranges_exclusive().last().map(|r| r.1) == Some(400)),
            "有洞时不得满足 [0,total) 覆盖"
        );
        tr.write_data(0, &seg).unwrap();
        assert!(!tr.commit_range(0, 100));
        tr.write_data(100, &seg).unwrap();
        assert!(tr.commit_range(100, 100));
        drop(tr);
        let got = std::fs::read(&path).unwrap();
        assert_eq!(got.len(), 400);
        let want: Vec<u8> = (0..4)
            .flat_map(|_| seg.iter().map(move |b| *b))
            .collect();
        assert_eq!(got, want, "乱序写入必须逐字节一致");
    }

    /// 区间合并（0x02 组装 + 0x0B 覆盖查询的底座）。
    #[test]
    fn chunk_range_merge() {
        let mut r = Vec::new();
        CsChunkTracker::insert_range(&mut r, 10, 19);
        CsChunkTracker::insert_range(&mut r, 20, 29);
        assert_eq!(r, vec![(10, 29)], "相邻区间合并");
        CsChunkTracker::insert_range(&mut r, 0, 5);
        assert_eq!(r, vec![(0, 5), (10, 29)]);
        CsChunkTracker::insert_range(&mut r, 6, 9);
        assert_eq!(r, vec![(0, 29)], "补齐缺口后三段并一段");
        CsChunkTracker::insert_range(&mut r, 50, 60);
        CsChunkTracker::insert_range(&mut r, 100, 109);
        assert_eq!(r.len(), 3);
    }
}
