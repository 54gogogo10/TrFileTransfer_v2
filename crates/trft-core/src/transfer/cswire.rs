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
    confirm_once, conn_precheck, conn_settle, record_recv, resolve_save_dir, RecvOptions,
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
/// 单文件声明上限（C# MaxTransferSize = 1 PiB）。
pub const CS_MAX_TRANSFER: u64 = 1 << 50;
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
pub fn cs_safe_name(raw: &str, fallback: &str) -> String {
    let name = raw.rsplit(['\\', '/']).next().unwrap_or("");
    let mut name = if name.trim().is_empty() { fallback } else { name };
    name = name.trim_end_matches(['.', ' ']);
    if name.is_empty() {
        return fallback.to_string();
    }
    if is_reserved_name(name) {
        return format!("_{name}");
    }
    name.to_string()
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
        parts.push(seg);
    }
    if parts.is_empty() {
        return "_".into();
    }
    parts.join(std::path::MAIN_SEPARATOR_STR)
}

/// C# GetUniqueSavePath：`name` → `name_1.ext` → `name_2.ext` …
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
    let mut i = 1;
    loop {
        let cand = dir.join(format!("{stem}_{i}{ext}"));
        if !cand.exists() {
            return cand;
        }
        i += 1;
    }
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
}

impl<S: AsyncRead + AsyncWrite + Unpin> CsWire<S> {
    pub fn new(raw: S) -> Self {
        Self {
            raw,
            enc_r: None,
            enc_w: None,
            comp_r: None,
            comp_w: None,
            server_caps: 0,
        }
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
    wire.raw.read_exact(&mut buf).await?;
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
        opts.gate.lock().await.fail(&peer.ip());
        return Err(Error::AuthRejected("配对码校验失败".into()));
    }
    let mut confirm_c = [0u8; 32];
    wire.raw.read_exact(&mut confirm_c).await?;
    let expect_c = cs_confirm(&auth_key, "c2s-confirm", &c_pub, &s_pub);
    if !ct_eq(&expect_c, &confirm_c) {
        opts.gate.lock().await.success(&peer.ip());
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
    wire.raw.read_exact(&mut hash).await?;
    if opts.pairing_code.is_some() && opts.gate.lock().await.locked(&peer.ip()) {
        wire.raw_write(&[R_PAIRING, 1]).await?;
        return Err(Error::AuthRejected(format!(
            "{peer}: 配对失败次数过多，已临时锁定"
        )));
    }
    let status = if code.is_empty() {
        0u8
    } else if ct_eq(&hash, &sha256_code(code)) {
        0
    } else {
        1
    };
    wire.raw_write(&[R_PAIRING, status]).await?;
    if status == 1 {
        opts.gate.lock().await.fail(&peer.ip());
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
    /// 组会话归属（guid → 首个 peer IP）。
    pub group_peers: Mutex<HashMap<String, String>>,
}

/// C# ChunkTracker 等价物：预分配文件 + 区间合并覆盖。
pub struct CsChunkTracker {
    pub save_path: PathBuf,
    pub total: u64,
    file: std::fs::File,
    ranges: Vec<(u64, u64)>, // 闭区间，已合并升序
    pub received: u64,
}

impl CsChunkTracker {
    fn create(save_path: PathBuf, total: u64) -> io::Result<Self> {
        use std::io::Write;
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
        })
    }

    /// 写入一个偏移段；返回是否已完整覆盖 [0, total)。
    fn write_chunk(&mut self, off: u64, data: &[u8]) -> io::Result<bool> {
        use std::io::{Seek, SeekFrom, Write};
        self.file.seek(SeekFrom::Start(off))?;
        self.file.write_all(data)?;
        self.received += data.len() as u64;
        Self::insert_range(&mut self.ranges, off, off + data.len() as u64 - 1);
        // 完整 = 单一合并区间且恰覆盖 [0, total)（首尾判据会被中段洞骗过——
        // 轮 1 修复：ranges 已按升序不重叠维护，单区间即无洞）。
        Ok(self.ranges.len() == 1 && self.ranges[0] == (0, self.total - 1))
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
}

/* ============ 服务端连接处理 ============ */

#[derive(Default, Debug)]
pub struct CsOutcome {
    pub success: bool,
    pub is_chunked: bool,
    /// 0x03 的终态应答（0x10）即判决——不再发裸 ACK。
    pub has_own_final_response: bool,
    pub rejected: bool,
}

/// UDT 连接的 C# 方言入口（serve_udt_on 每连接调用；镜像 receiver::handle_conn 形状）。
pub(crate) async fn handle_conn_cs(
    stream: UdtStream,
    peer: SocketAddr,
    opts: &RecvOptions,
    served: Arc<AtomicU64>,
    state: Arc<CsServerState>,
) -> Result<()> {
    let _permit = conn_precheck(peer, opts).await?;
    let r = conn_cs_inner(stream, peer, opts, &state).await;
    // 限量模式计数口径与 TCP 同：只计成功处理的连接（被拒/失败不得消耗名额）。
    let handled = if r.is_ok() { 1 } else { 0 };
    conn_settle(&r, handled, peer, opts, &served).await;
    r
}

async fn conn_cs_inner(
    stream: UdtStream,
    peer: SocketAddr,
    opts: &RecvOptions,
    state: &Arc<CsServerState>,
) -> Result<()> {
    let mut wire = CsWire::new(stream);
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

    // 裸 ACK（UDT 特有：在装饰器之外）。0x03 自带终态应答，不发（与 C# 同）。
    let ack = if outcome.rejected {
        Some(0x00u8)
    } else if outcome.is_chunked || !outcome.has_own_final_response {
        Some(if outcome.success { 0x01 } else { 0x00 })
    } else {
        None
    };
    if let Some(b) = ack {
        let _ = wire.raw_write(&[b]).await;
    }
    let _ = wire.shutdown().await;
    res
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
    let mut prelude_frames = 0u32;
    let transfer_type = loop {
        let mut t = [0u8; 1];
        wire.read_exact(&mut t).await?;
        let t = t[0];
        match t {
            F_ECDH => {
                prelude_frames += 1;
                if prelude_frames > 8 {
                    return Err(proto("前奏帧数超限"));
                }
                let code_ref = opts.pairing_code.clone().unwrap_or_default();
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
                // 同 0x08：0x1A 应答必须经装饰器栈（此时可能已压缩+加密）。
                wire.write_all(&[R_CAPS, 0x03]).await?;
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
            let ok = handle_chunk(
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
            let key = format!("S|{}", guid_hex(&id));
            // 组归属校验（轮 6 P1，对齐 C# WireProtocol.cs:662-671 ChunkSessionPeers——
            // 此前任何认证过的 peer 可查询他人 group 的已收区间）。
            {
                let owners = state.group_peers.lock().expect("组归属锁");
                match owners.get(&key) {
                    Some(owner) if *owner != peer.ip().to_string() => {
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

/* ============ 帧处理器（服务端收） ============ */

type CsReporter = Option<crate::progress::Reporter>;

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
    let temp = save_path.with_extension(format!("part-{}", random_hex(8)));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp)?;
    let mut hasher = sha2::Sha256::new();
    let mut remaining = size;
    let mut buf = vec![0u8; 256 * 1024];
    {
        use std::io::Write as _;
        while remaining > 0 {
            let n = buf.len().min(remaining as usize);
            wire.read_exact(&mut buf[..n]).await?;
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
    let mut got = [0u8; 32];
    wire.read_exact(&mut got).await?;
    let computed: [u8; 32] = hasher.finalize().into();
    if !ct_eq(&got, &computed) {
        let _ = std::fs::remove_file(&temp);
        return Err(Error::Rejected(format!("{display}: SHA-256 校验失败")));
    }
    std::fs::rename(&temp, save_path)?;
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
    let reporter = hub.map(|h| h.register("recv", name.clone(), size as u64));
    let base = save_dir.join(&name);
    let save_path = cs_unique_save_path(save_dir, &name);
    let hash = receive_payload(wire, &save_path, size as u64, &name, limiter, &reporter).await?;
    // Skip 策略：与同名同长且同哈希的既有文件相同 → 丢弃新副本（C# SkipDuplicateFiles）。
    if opts.duplicate == DuplicatePolicy::Skip && save_path != base {
        let dup = std::fs::metadata(&base)
            .map(|m| m.len() == size as u64)
            .unwrap_or(false)
            && crate::hash::sha256_file(&base)
                .map(|x| ct_eq(&x, &hash))
                .unwrap_or(false);
        if dup {
            let _ = std::fs::remove_file(&save_path);
            if let Some(r) = &reporter {
                r.finish();
            }
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
    let reporter = hub.map(|h| h.register("recv", folder.clone(), 0));
    let folder_dir = cs_unique_save_path(save_dir, &folder);
    std::fs::create_dir_all(&folder_dir)?;
    let mut total = 0u64;
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
        receive_payload(wire, &save_path, size as u64, &display, limiter, &reporter).await?;
        total += size as u64;
        if let Some(r) = &reporter {
            r.add(1);
        }
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
) -> Result<bool> {
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
    let reporter = hub.map(|h| h.register("recv", name.clone(), total as u64));
    let tracker_key = match &group_key {
        Some(g) => {
            // 组归属绑定（防外来 peer 写入他人组装——C# ChunkSessionPeers 同防线）。
            let ip = peer.ip().to_string();
            let mut owners = state.group_peers.lock().expect("组归属锁");
            match owners.get(g) {
                Some(owner) if *owner != ip => {
                    return Err(Error::Rejected("分块组会话属于其他设备".into()));
                }
                Some(_) => {}
                None => {
                    owners.insert(g.clone(), ip);
                }
            }
            format!("S|{g}")
        }
        None => format!("{}|{}", peer.ip(), name),
    };

    // 组装器（大小不符的遗留 tracker 重建——C# 同策略）。
    {
        let mut t = state.trackers.lock().expect("tracker 锁");
        let stale = match t.get(&tracker_key) {
            Some(tr) if tr.total == total as u64 => None,
            Some(_) => t.remove(&tracker_key),
            None => None,
        };
        if let Some(st) = stale {
            let _ = std::fs::remove_file(&st.save_path);
        }
        if !t.contains_key(&tracker_key) {
            let save_path = cs_unique_save_path(save_dir, &name);
            let tr = CsChunkTracker::create(save_path, total as u64).map_err(Error::Io)?;
            t.insert(tracker_key.clone(), tr);
        }
    }

    // 写段 + 逐段哈希（C# HandleChunkedFile 同构）。
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    let mut remaining = chunk as u64;
    let mut write_off = offset as u64;
    let mut complete = false;
    let mut buf = vec![0u8; 256 * 1024];
    while remaining > 0 {
        let n = buf.len().min(remaining as usize);
        wire.read_exact(&mut buf[..n]).await?;
        if let Some(l) = limiter {
            l.acquire(n as u64).await;
        }
        hasher.update(&buf[..n]);
        {
            let mut t = state.trackers.lock().expect("tracker 锁");
            if let Some(tr) = t.get_mut(&tracker_key) {
                complete = tr.write_chunk(write_off, &buf[..n])?;
                if tr.ranges_count() > CS_MAX_CHUNK_RANGES {
                    return Err(Error::Rejected("分块覆盖区间数超限".into()));
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
            let _ = std::fs::remove_file(&tr.save_path);
        }
        return Ok(false);
    }
    if complete {
        let t = state
            .trackers
            .lock()
            .expect("tracker 锁")
            .remove(&tracker_key);
        if let Some(tr) = t {
            if let Some(g) = &group_key {
                state.group_peers.lock().expect("组归属锁").remove(g);
            }
            record_recv(
                opts,
                peer,
                total as u64,
                1,
                Instant::now(),
                "分块传输",
                &tr.save_path,
            );
            if let Some(r) = &reporter {
                r.finish();
            }
        }
    }
    Ok(true)
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
    let reporter = hub.map(|h| h.register("recv", name.clone(), total as u64));

    let key = guid_hex(&sid);
    // 单飞锁（轮 6 P1——同名 sid 两连接并发 append 会交错写坏文件；C# ResumeLocks
    // TryWait(0) 同防线）+ peer 绑定校验。锁随会话生命周期存续，完成时清理。
    let resume_gate = {
        let mut gates = state.resume_gates.lock().expect("resume 门锁");
        gates.entry(key.clone()).or_default().clone()
    };
    if resume_gate.try_lock().is_err() {
        return Err(Error::Rejected("该续传会话正被另一连接使用".into()));
    }
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
        match rs.get_mut(&key) {
            Some(st) if st.total == total as u64 && st.received < st.total => {
                if st.peer_ip != ip {
                    return Err(Error::Rejected("续传会话属于其他设备".into()));
                }
                Session::Resume(st.save_path.clone(), st.received)
            }
            Some(st) if st.total == total as u64 => Session::Done(st.save_path.clone()),
            _ => {
                let save_path = cs_unique_save_path(save_dir, &name);
                rs.insert(
                    key.clone(),
                    CsResumeState {
                        save_path,
                        total: total as u64,
                        received: 0,
                        name: name.clone(),
                        peer_ip: ip.clone(),
                    },
                );
                let p = rs.get(&key).expect("刚插入").save_path.clone();
                Session::New(p)
            }
        }
    };
    match session {
        Session::Done(path) => {
            record_recv(opts, peer, total as u64, 1, Instant::now(), "续传传输", &path);
            let st = state.resume.lock().expect("resume 锁").remove(&key);
            state.resume_gates.lock().expect("resume 门锁").remove(&key);
            drop(st);
            if let Some(r) = &reporter {
                r.finish();
            }
            send_resume_response(wire, total, 2).await?;
            return Ok(true);
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
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.seek(std::io::SeekFrom::End(0))?;
    let mut hasher = sha2::Sha256::new();
    let mut remaining = total - start;
    let mut buf = vec![0u8; 256 * 1024];
    while remaining > 0 {
        // 部分读：中断前的到达字节必须立即记账（C# ReadSomeAsync 同构——
        // read_exact 会让不足一块的进度滞留 socket，续点回退）。
        let want = buf.len().min(remaining as usize);
        let n = wire.read_some(&mut buf[..want]).await?;
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
            }
        }
        if let Some(r) = reporter {
            r.add(n as u64);
        }
    }
    let mut got = [0u8; 32];
    wire.read_exact(&mut got).await?;
    let computed: [u8; 32] = hasher.finalize().into();
    if !ct_eq(&got, &computed) {
        // 哈希失败：丢弃会话与半成品（重试从头）。
        let st = state.resume.lock().expect("resume 锁").remove(key);
        state.resume_gates.lock().expect("resume 门锁").remove(key);
        if let Some(st) = st {
            let _ = std::fs::remove_file(&st.save_path);
        }
        return Ok(false);
    }
    // 全文件哈希核验（可选扩展——resume 的拼缝不在段哈希覆盖内）。
    if let Some(expect) = full_hash {
        let actual = crate::hash::sha256_file(path).unwrap_or_default();
        if !ct_eq(&actual, &expect) {
            let st = state.resume.lock().expect("resume 锁").remove(key);
            state.resume_gates.lock().expect("resume 门锁").remove(key);
            if let Some(st) = st {
                let _ = std::fs::remove_file(&st.save_path);
            }
            send_resume_response(wire, total as i64, 3).await?;
            return Ok(false);
        }
    }
    let st = state.resume.lock().expect("resume 锁").remove(key);
    state.resume_gates.lock().expect("resume 门锁").remove(key);
    if let Some(st) = st {
        record_recv(opts, peer, total, 1, Instant::now(), "续传传输", &st.save_path);
    }
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
    let mut manifest: Vec<ManifestEntry> = Vec::with_capacity(file_count as usize);
    let mut manifest_total = 0u64;
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
        manifest_total += size as u64;
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
    let reporter = hub.map(|h| h.register("recv", folder.clone(), total_bytes as u64));
    // 会话目录（确定性：<folder>.<guid8>——C# GetFolderSessionDir 同式，重复同步续用）。
    let dir = save_dir.join(format!("{folder}.{}", &guid_hex(&sid)[..8]));
    std::fs::create_dir_all(&dir)?;
    // 续点扫描：首个不完整条目（C# 同构）。
    let mut resume_index = file_count;
    let mut resume_offset = 0i64;
    for (i, e) in manifest.iter().enumerate() {
        let p = dir.join(&e.rel);
        if !p.exists() {
            resume_index = i as i32;
            resume_offset = 0;
            break;
        }
        let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        if len == e.size {
            let actual = crate::hash::sha256_file(&p).unwrap_or_default();
            if ct_eq(&actual, &e.hash) {
                continue;
            }
            resume_index = i as i32;
            resume_offset = 0;
            break;
        }
        if len > 0 && len < e.size {
            resume_index = i as i32;
            resume_offset = len as i64;
            break;
        }
        resume_index = i as i32;
        resume_offset = 0;
        break;
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
            let identical = p.exists()
                && std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0) == e.size
                && crate::hash::sha256_file(&p)
                    .map(|x| ct_eq(&x, &e.hash))
                    .unwrap_or(false);
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
            std::fs::create_dir_all(parent)?;
        }
        if start == 0 {
            let temp = save_path.with_extension(format!("part-{}", random_hex(8)));
            let r = receive_payload(wire, &temp, e.size, &e.rel, limiter, &reporter).await;
            match r {
                Ok(_) => {
                    std::fs::rename(&temp, &save_path)?;
                }
                Err(_) => {
                    let _ = std::fs::remove_file(&temp);
                    return Ok((false, 0, files));
                }
            }
        } else {
            // 增量续传：追加 + 增量哈希 + 全文件复核（C# HandleFolderResumableAsync 同构）。
            use sha2::Digest;
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new().append(true).open(&save_path)?;
            let mut hasher = sha2::Sha256::new();
            let mut remaining = e.size - start;
            let mut buf = vec![0u8; 256 * 1024];
            while remaining > 0 {
                let n = buf.len().min(remaining as usize);
                wire.read_exact(&mut buf[..n]).await?;
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
            let mut got = [0u8; 32];
            wire.read_exact(&mut got).await?;
            let computed: [u8; 32] = hasher.finalize().into();
            if !ct_eq(&got, &computed) {
                return Ok((false, 0, files));
            }
            let actual = crate::hash::sha256_file(&save_path).unwrap_or_default();
            if !ct_eq(&actual, &e.hash) {
                let _ = std::fs::remove_file(&save_path);
                return Ok((false, 0, files));
            }
        }
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
    let mut wire = CsWire::new(stream);
    let code = opts.pairing_code.clone().unwrap_or_default();
    if !code.is_empty() {
        if opts.encrypt {
            match cs_client_ecdh(&mut wire, &code).await? {
                CsEcdhOutcome::Encrypted => {}
                CsEcdhOutcome::Plaintext => {
                    eprintln!("[UDT] 对端未启用配对，明文继续");
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
    tokio::time::timeout(ACK_TIMEOUT, wire.raw_read_exact(&mut ack))
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
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            // 本地摘要缓存产物不是要发送的内容（v2 帧 collect_files 同口径——
            // 否则 0x04 二轮起把 .trft-hash-cache.txt 当文件传给对端）。
            if crate::hashcache::is_cache_artifact(&e.file_name().to_string_lossy()) {
                continue;
            }
            if p.is_dir() {
                walk(&p, out);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
    walk(path, &mut files);
    if files.is_empty() {
        return Err(crate::error::config_err("目录为空（C# 0x01 要求 fileCount ≥ 1）"));
    }
    if files.len() > CS_MAX_FOLDER_FILES {
        return Err(crate::error::config_err("目录文件数超上限"));
    }

    let reporter = opts.progress.as_ref();

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

/* ============ 高层发送入口（sender.rs 的 Transport::Udt 分支调用） ============ */

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
        let bytes = cs_send_file(&mut wire, path, opts).await?;
        let _ = wire.shutdown().await;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        crate::transfer::sender::record_stats(opts, addr, bytes, 1, started, "单文件", &name);
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
    client_cache: Option<&std::sync::Arc<tokio::sync::Mutex<crate::hashcache::HashCache>>>,
) -> Result<CsSyncManifest> {
    let raw = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| crate::error::config_err("路径没有合法 UTF-8 目录名"))?;
    let folder = crate::protocol::frame::sanitize_name(raw)?;
    // 递归清单（确定性排序，与 cs_send_folder 同款）。
    let mut files: Vec<PathBuf> = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            // 本地摘要缓存产物不是要发送的内容（v2 帧 collect_files 同口径——
            // 否则 0x04 二轮起把 .trft-hash-cache.txt 当文件传给对端）。
            if crate::hashcache::is_cache_artifact(&e.file_name().to_string_lossy()) {
                continue;
            }
            if p.is_dir() {
                walk(&p, out);
            } else if p.is_file() {
                out.push(p);
            }
        }
    }
    walk(path, &mut files);
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

    // 0x11 判决（长窗口）。
    let mut resp = [0u8; 18];
    tokio::time::timeout(LONG_READ_WINDOW, wire.read_exact(&mut resp))
        .await
        .map_err(|_| proto("0x11 同步判决应答超时（300s）"))?
        .map_err(Error::Io)?;
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
        let manifest = build_sync_manifest(path, client_cache).await?;
        // 0x01 能力位（逐文件跳过清单）随认证栈协商。
        let (mut wire, caps) = cs_connect_stack_full(addr, opts, 0x01).await?;
        let per_file_skip = caps & 0x01 != 0;
        let sid =
            derive_sync_session_guid(&path.to_string_lossy(), &addr.ip().to_string(), addr.port());
        let (bytes, files) =
            cs_send_folder_sync(&mut wire, &manifest, sid, per_file_skip, opts).await?;
        let _ = wire.shutdown().await;
        crate::transfer::sender::record_stats(opts, addr, bytes, files, started, "文件夹同步", &name);
        Ok(())
    }
    .await;
    if res.is_ok() {
        outcome.finish();
    }
    res
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
        let (bytes, files) = cs_send_folder(&mut wire, path, opts).await?;
        let _ = wire.shutdown().await;
        crate::transfer::sender::record_stats(
            opts,
            addr,
            bytes,
            files,
            started,
            "目录",
            &path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("目录")
                .to_string(),
        );
        Ok(())
    }
    .await;
    if res.is_ok() {
        outcome.finish();
    }
    res
}

/// UDT 槽位发文本（建连 + 认证 + 0x06 + 统计）。
pub async fn send_text_cs(
    addr: SocketAddr,
    text: &str,
    opts: &crate::transfer::sender::SendOptions,
) -> Result<()> {
    let started = Instant::now();
    let mut wire = cs_connect_stack(addr, opts).await?;
    let n = cs_send_text(&mut wire, text).await?;
    let _ = wire.shutdown().await;
    crate::transfer::sender::record_stats(opts, addr, n, 0, started, "文本消息", "<文本>");
    Ok(())
}

/* ============ 单测（已知答案向量 + 自洽） ============ */

#[cfg(test)]
mod tests {
    use super::*;

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
        // 乱序：第 3 段先到。
        assert!(!tr.write_chunk(200, &seg).unwrap());
        assert!(!tr.write_chunk(300, &seg).unwrap());
        // 此时 ranges=[(200,299),(300,399)] —— 首段缺失，不得判完整。
        assert!(
            !(tr.ranges_exclusive().first().map(|r| r.0) == Some(0)
                && tr.ranges_exclusive().last().map(|r| r.1) == Some(400)),
            "有洞时不得满足 [0,total) 覆盖"
        );
        assert!(!tr.write_chunk(0, &seg).unwrap());
        assert!(tr.write_chunk(100, &seg).unwrap());
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
