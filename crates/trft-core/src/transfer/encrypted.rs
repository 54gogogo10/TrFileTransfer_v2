//! 0x09/0x19 加密装饰器（规格 §4.1：认证在前、装饰器包裹整个帧流）。
//!
//! 握手编排：
//! 1. 明文：客户端 `0x09 + 65B 公钥` → 服务端 `0x19 + 65B 公钥`，双方派生会话密钥；
//! 2. 加密通道内**双向 HMAC 确认**（规格 §4.1/§5.1 主动中间人防线）：
//!    客户端 `u8 flags + [32B 证明]` → 服务端校验 → 服务端 `u8 status + u8 flags + [32B 证明]`
//!    → 客户端校验。证明 = HMAC(通道确认密钥, cpub‖spub‖域分隔)，绑定双方公钥——
//!    盲接受型 MITM 无法伪造服务端证明，双臂中继因转写不同必然失配。
//! 3. 之后帧协议原样运行在 [`Encrypted`] 明文侧：线上 = `u32 密文段长 + seal(seq, 明文段)`。
//!
//! 机密性等级：无配对码时防被动窃听（ECDH 无认证）；配对码两侧配置时为
//! 双向认证。任一侧要求配对码而另一侧未配置 → fail-closed 拒绝。

use crate::crypto::handshake::{self, SessionKeys};
use crate::crypto::kdf::{ct_eq, derive_pairing_key, hmac_sha256};
use crate::error::{Error, Result, proto};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

pub const T_ENCRYPT: u8 = 0x09;
pub const T_ENCRYPT_OK: u8 = 0x19;
pub const PUBKEY_LEN: usize = 65;
/// 单段明文上限（规格 §6.1：加密分段 ≤256 KB）。
pub const SEGMENT_PLAIN: usize = 256 * 1024;
/// 线上信封长度上限 = 16B IV + 256KB 明文 + 16B tag。
pub const MAX_SEGMENT: usize = SEGMENT_PLAIN + 32;
pub const STATUS_OK: u8 = 0x01;
pub const STATUS_REJECT: u8 = 0x00;
const CONFIRM_DOMAIN: &[u8] = b"trft-enc-v2";

fn io_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Io(std::io::Error::other(e.to_string()))
}

/// 转写材料：绑定双方公钥——盲接受型 MITM 无法伪造服务端方向证明，
/// 双臂中继者两臂转写不同，证明必然失配。
fn transcript(client_pub: &[u8], server_pub: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(client_pub.len() + server_pub.len() + CONFIRM_DOMAIN.len());
    m.extend_from_slice(client_pub);
    m.extend_from_slice(server_pub);
    m.extend_from_slice(CONFIRM_DOMAIN);
    m
}

/// 通道内双向确认证明（密钥 = HKDF conf 分域展开，与加解密密钥分离）。
/// 关键：必须把 PBKDF2(配对码) 的派生钥混入——否则仅做 ECDH 的中间人
/// 自己就能派生 conf 密钥并伪造双向证明。配对码盐取转写哈希，两侧可独立重算。
fn k_code_of(code: &str, material: &[u8]) -> [u8; 32] {
    let salt = crate::hash::sha256(material);
    derive_pairing_key(code, &salt[..16])
}

fn confirm_proof(key: &[u8; 32], material: &[u8], k_code: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(material.len() + 32);
    data.extend_from_slice(material);
    data.extend_from_slice(k_code);
    hmac_sha256(key, &data)
}

/// 加密流装饰器：读 = 拉取密文段并解密；写 = 每次调用封一段。
/// 实现标准 AsyncRead/AsyncWrite，帧协议层无感知。
pub struct Encrypted<S> {
    inner: S,
    send: crate::crypto::cipher::SegmentCipher,
    send_seq: u64,
    recv: crate::crypto::cipher::SegmentCipher,
    recv_seq: u64,
    /// 已解密待消费的明文段。
    plain: Vec<u8>,
    plain_pos: usize,
    /// 半读状态：密文段缓冲与已读字节（必须跨 poll 持久化——Pending 不得丢进度）。
    sealed: Vec<u8>,
    sealed_pos: usize,
    /// 半写状态：(信封 = 4B 长度 + 密文段, 已写字节)。
    pending: Option<(Vec<u8>, usize)>,
    /// 待封段的剩余输入（多段写入跨 poll 的状态）。
    pending_in: Option<Vec<u8>>,
    header: [u8; 4],
    header_pos: usize,
}

impl<S> Encrypted<S> {
    pub fn new(inner: S, keys: SessionKeys, is_client: bool) -> Self {
        let (send, recv) = if is_client {
            (keys.c2s, keys.s2c)
        } else {
            (keys.s2c, keys.c2s)
        };
        Self {
            inner,
            send,
            send_seq: 0,
            recv,
            recv_seq: 0,
            plain: Vec::new(),
            plain_pos: 0,
            sealed: Vec::new(),
            sealed_pos: 0,
            pending: None,
            pending_in: None,
            header: [0; 4],
            header_pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Encrypted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let Self { inner, recv, recv_seq, plain, plain_pos, header, header_pos, sealed, sealed_pos, .. } = this;
        loop {
            // 1) 有已解密明文：直接供给。
            if *plain_pos < plain.len() {
                let n = out.remaining().min(plain.len() - *plain_pos);
                out.put_slice(&plain[*plain_pos..*plain_pos + n]);
                *plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            // 2) 长度头（4B）：补齐。
            while *header_pos < 4 {
                let mut rb = ReadBuf::new(&mut header[*header_pos..]);
                match Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            if *header_pos == 0 && sealed.is_empty() {
                                // 干净 EOF（信封边界），向上传递 0 字节读。
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "加密段长度头被截断",
                            )));
                        }
                        *header_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            // 3) 密文段：跨 poll 持久化缓冲，Pending 不得丢进度。
            if sealed.is_empty() {
                let len = u32::from_le_bytes(*header) as usize;
                if len < 32 || len > MAX_SEGMENT {
                    return Poll::Ready(Err(std::io::Error::other("加密段长度非法")));
                }
                *sealed = vec![0u8; len];
                *sealed_pos = 0;
            }
            while *sealed_pos < sealed.len() {
                let mut rb = ReadBuf::new(&mut sealed[*sealed_pos..]);
                match Pin::new(&mut *inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "加密段被截断",
                            )));
                        }
                        *sealed_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let pt = recv
                .open(*recv_seq, sealed)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            *recv_seq += 1;
            *header_pos = 0;
            // 段消费完毕：清空 sealed 回到「读新头」状态，否则下一次循环会用
            // 旧段长度继续读体，造成段错位（HMAC 失败）。
            *sealed_pos = 0;
            *sealed = Vec::new();
            *plain = pt;
            *plain_pos = 0;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Encrypted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let Self { inner, send, send_seq, pending, pending_in, .. } = this;
        // write_all 契约：Pending 后以同一 buf 重试。首次进入时把输入收进
        // 状态机，之后按 256KB 分段依次封段写出。
        if pending_in.is_none() && pending.is_none() {
            *pending_in = Some(buf.to_vec());
        }
        loop {
            // 1) 在途信封续写。
            if let Some((env, pos)) = pending.as_mut() {
                while *pos < env.len() {
                    match Pin::new(&mut *inner).poll_write(cx, &env[*pos..]) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::WriteZero,
                                "写加密信封失败",
                            )));
                        }
                        Poll::Ready(Ok(n)) => *pos += n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                *pending = None;
            }
            // 2) 从剩余输入封新段（≤256KB，规格 §6.1 分段上限）。
            match pending_in.as_mut() {
                Some(rest) if !rest.is_empty() => {
                    let take = rest.len().min(SEGMENT_PLAIN);
                    let chunk: Vec<u8> = rest.drain(..take).collect();
                    let sealed = send
                        .seal(*send_seq, &chunk)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    *send_seq += 1;
                    let mut env = Vec::with_capacity(4 + sealed.len());
                    env.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
                    env.extend_from_slice(&sealed);
                    let mut pos = 0usize;
                    while pos < env.len() {
                        match Pin::new(&mut *inner).poll_write(cx, &env[pos..]) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::WriteZero,
                                    "写加密信封失败",
                                )));
                            }
                            Poll::Ready(Ok(n)) => pos += n,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => {
                                *pending = Some((env, pos));
                                return Poll::Pending;
                            }
                        }
                    }
                }
                _ => {
                    *pending_in = None;
                    return Poll::Ready(Ok(buf.len()));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // 先补完半写信封，再委托底层。
        while let Some((env, pos)) = this.pending.as_mut() {
            match Pin::new(&mut this.inner).poll_write(cx, &env[*pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "写加密信封失败",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    *pos += n;
                    if *pos == env.len() {
                        this.pending = None;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while let Some((env, pos)) = this.pending.as_mut() {
            match Pin::new(&mut this.inner).poll_write(cx, &env[*pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "写加密信封失败",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    *pos += n;
                    if *pos == env.len() {
                        this.pending = None;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// 客户端握手并包装流（发送视角）。返回 (包装流, 是否完成双向配对认证)。
pub async fn client_wrap<S>(s: S, code: Option<&str>) -> Result<(Encrypted<S>, bool)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut s = s;
    let hs = handshake::new_handshake()?;
    let cpub = hs.public().to_vec();
    s.write_all(&[T_ENCRYPT]).await?;
    s.write_all(&cpub).await?;
    let t = crate::protocol::io::read_u8(&mut s).await?;
    if t != T_ENCRYPT_OK {
        return Err(proto(format!("对端不接受加密（0x{t:02X}）")));
    }
    let spub = crate::protocol::io::read_n(&mut s, PUBKEY_LEN).await?;
    let keys = hs.finish_client(&spub)?;
    let conf_c = keys.c2s_conf;
    let conf_s = keys.s2c_conf;
    let mut enc = Encrypted::new(s, keys, true);
    let material = transcript(&cpub, &spub);

    // —— 以下全部运行在加密通道内（规格 §4.1 双向 HMAC 确认）——
    // 0) 配对码派生（PBKDF2 50k 移出 async 线程；盐=转写哈希，两侧独立重算）。
    let k_code = match code {
        Some(c) => {
            let c = c.to_string();
            let material2 = material.clone();
            Some(
                tokio::task::spawn_blocking(move || k_code_of(&c, &material2))
                    .await
                    .map_err(|e| io_err(e))?,
            )
        }
        None => None,
    };
    // 1) 客户端证明。
    match &k_code {
        Some(k) => {
            let proof = confirm_proof(&conf_c, &material, k);
            enc.write_all(&[1]).await?;
            enc.write_all(&proof).await?;
        }
        None => enc.write_all(&[0]).await?,
    }
    // 2) 服务端结论 + 服务端证明（客户端必须能验证服务端持有配对码）。
    let st = crate::protocol::io::read_u8(&mut enc).await?;
    if st != STATUS_OK {
        return Err(Error::AuthRejected("对端拒绝加密握手（配对码不符）".into()));
    }
    let flags_s = crate::protocol::io::read_u8(&mut enc).await?;
    match (code, flags_s & 1 == 1) {
        (Some(_), false) => {
            // fail-closed：客户端要求配对码认证，对端未能证明自己持有配对码。
            return Err(Error::AuthRejected("对端未启用配对码，无法完成双向认证".into()));
        }
        (Some(_), true) => {
            let ps = crate::protocol::io::read_n(&mut enc, 32).await?;
            let expect = confirm_proof(&conf_s, &material, k_code.as_ref().unwrap());
            if !ct_eq(&ps, &expect) {
                return Err(Error::AuthRejected("服务端证明校验失败（疑似中间人）".into()));
            }
        }
        (None, _) => {}
    }
    let authed = code.is_some();
    Ok((enc, authed))
}

/// 服务端握手并包装流（首字节 0x09 已由调用方读走并验证）。
/// 返回 (包装流, 是否完成双向配对认证)。
pub async fn server_wrap<S>(s: S, code: Option<&str>) -> Result<(Encrypted<S>, bool)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut s = s;
    let cpub = crate::protocol::io::read_n(&mut s, PUBKEY_LEN).await?;
    let hs = handshake::new_handshake()?;
    let spub = hs.public().to_vec();
    s.write_all(&[T_ENCRYPT_OK]).await?;
    s.write_all(&spub).await?;
    let keys = hs.finish_server(&cpub)?;
    let conf_c = keys.c2s_conf;
    let conf_s = keys.s2c_conf;
    let mut enc = Encrypted::new(s, keys, false);
    let material = transcript(&cpub, &spub);

    // 1) 客户端证明校验（fail-closed：要求配对码而客户端未出示 → 拒绝）。
    let flags_c = crate::protocol::io::read_u8(&mut enc).await?;
    let mut authed = false;
    // 配对码存在时：PBKDF2 50k 移出 async 线程，k_code 双侧可独立重算。
    let k_code = match code {
        Some(c) => {
            let c = c.to_string();
            let material2 = material.clone();
            Some(
                tokio::task::spawn_blocking(move || k_code_of(&c, &material2))
                    .await
                    .map_err(|e| io_err(e))?,
            )
        }
        None => None,
    };
    match (code, flags_c & 1 == 1) {
        (Some(_), true) => {
            let proof = crate::protocol::io::read_n(&mut enc, 32).await?;
            let expect = confirm_proof(&conf_c, &material, k_code.as_ref().unwrap());
            if !ct_eq(&proof, &expect) {
                enc.write_all(&[STATUS_REJECT]).await?;
                return Err(Error::AuthRejected("客户端证明校验失败（配对码错误）".into()));
            }
            authed = true;
        }
        (Some(_), false) => {
            enc.write_all(&[STATUS_REJECT]).await?;
            return Err(Error::AuthRejected("客户端未出示加密握手证明".into()));
        }
        (None, true) => {
            // 服务端无码：无法验证客户端证明，宽容接受但不算已认证（规格 §4.1）。
            let _ = crate::protocol::io::read_n(&mut enc, 32).await?;
        }
        (None, false) => {}
    }
    // 2) 服务端结论 + 服务端证明（客户端有码时必须能验证服务端）。
    match (&k_code, code.is_some()) {
        (Some(k), true) => {
            let proof = confirm_proof(&conf_s, &material, k);
            enc.write_all(&[STATUS_OK, 1]).await?;
            enc.write_all(&proof).await?;
        }
        _ => {
            enc.write_all(&[STATUS_OK, 0]).await?;
        }
    }
    Ok((enc, authed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::handshake;
    use rand_core::RngCore;
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 底层 mock：每次 poll_write 先 Pending 一次、再只收 1 字节——强制
    /// poll_write 真正走 Pending→同 buf 重试路径。回归审查轮3 P1-1：
    /// 重试不得把同一段明文重复封段（审查轮7：原 mock 永不 Pending，无判别力）。
    struct Trickle {
        buf: Vec<u8>,
        pending: bool,
        woken: bool,
    }
    impl Trickle {
        fn new() -> Self {
            Self { buf: Vec::new(), pending: false, woken: false }
        }
    }
    impl tokio::io::AsyncWrite for Trickle {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.pending {
                this.pending = false;
                this.woken = true;
                let n = buf.len().min(1).max(1);
                this.buf.extend_from_slice(&buf[..n.min(buf.len())]);
                return Poll::Ready(Ok(n.min(buf.len())));
            }
            this.pending = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn write_pending_retry_does_not_duplicate_plaintext() {
        let a = handshake::new_handshake().unwrap();
        let b = handshake::new_handshake().unwrap();
        let ap = a.public().to_vec();
        let bp = b.public().to_vec();
        let ka = a.finish_client(&bp).unwrap();
        let kb = b.finish_server(&ap).unwrap();

        let mut enc = Encrypted::new(Trickle::new(), ka, true);
        let msg = "hello encrypted world, 重复封段检测".as_bytes();
        enc.write_all(msg).await.unwrap();
        enc.flush().await.unwrap();

        let bytes = std::mem::replace(&mut enc.inner, Trickle::new()).buf;
        // read_to_end + 长度精确断言：重复封段会让密文流翻倍——
        // read_exact(msg.len()) 掩盖重复（审查轮7），必须整流比对。
        let mut dec = Encrypted::new(Cursor::new(bytes), kb, false);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, msg, "Pending 重试不得产生重复封段");
    }

    #[tokio::test]
    async fn read_resumes_mid_segment_after_pending() {
        // 读侧跨 poll 状态持久化：mock 读端每次只给 1 字节且隔次 Pending——
        // 审查轮3 引入的 sealed/header 状态机必须无进度丢失（回退即 HMAC 红）。
        struct Dribble {
            data: Vec<u8>,
            pos: usize,
            toggle: bool,
        }
        impl tokio::io::AsyncRead for Dribble {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                out: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                let this = self.get_mut();
                if this.pos >= this.data.len() {
                    return Poll::Ready(Ok(()));
                }
                this.toggle = !this.toggle;
                if this.toggle {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let n = 1.min(out.remaining()).min(this.data.len() - this.pos);
                out.put_slice(&this.data[this.pos..this.pos + n]);
                this.pos += n;
                Poll::Ready(Ok(()))
            }
        }

        let a = handshake::new_handshake().unwrap();
        let b = handshake::new_handshake().unwrap();
        let ap = a.public().to_vec();
        let bp = b.public().to_vec();
        let ka = a.finish_client(&bp).unwrap();
        let kb = b.finish_server(&ap).unwrap();

        let mut data = vec![0u8; 300_000];
        rand_core::OsRng.fill_bytes(&mut data);
        let mut enc = Encrypted::new(Cursor::new(Vec::new()), ka, true);
        enc.write_all(&data).await.unwrap();
        let bytes = std::mem::replace(&mut enc.inner, Cursor::new(Vec::new())).into_inner();

        let mut dec = Encrypted::new(Dribble { data: bytes, pos: 0, toggle: false }, kb, false);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data, "隔次 Pending 的分段读必须无进度丢失");
    }

    #[tokio::test]
    async fn client_rejects_forged_server_proof() {
        // 审查轮7：删掉客户端对服务端证明的恒时校验，此测试必须变红。
        let (c_io, s_io) = tokio::io::duplex(64 * 1024);
        let fake = tokio::spawn(async move {
            let mut s = s_io;
            let mut hello = [0u8; 1 + 65];
            s.read_exact(&mut hello).await.unwrap();
            let hs = handshake::new_handshake().unwrap();
            let spub = hs.public().to_vec();
            s.write_all(&[T_ENCRYPT_OK]).await.unwrap();
            s.write_all(&spub).await.unwrap();
            let keys = hs.finish_server(&hello[1..]).unwrap();
            let mut enc = Encrypted::new(s, keys, false);
            let mut fl = [0u8; 1];
            enc.read_exact(&mut fl).await.unwrap();
            if fl[0] == 1 {
                let mut p = [0u8; 32];
                enc.read_exact(&mut p).await.unwrap();
            }
            // 伪造：声明有服务端证明，但内容是全零（攻击者无配对码）。
            enc.write_all(&[STATUS_OK, 1]).await.unwrap();
            enc.write_all(&[0u8; 32]).await.unwrap();
        });
        let r = client_wrap(c_io, Some("123456")).await;
        assert!(matches!(r, Err(Error::AuthRejected(_))), "伪造服务端证明必须被识破");
        fake.abort();
    }

    #[tokio::test]
    async fn wrong_pairing_code_rejected_both_sides() {
        // 审查轮7：删掉服务端对客户端证明的恒时校验，此测试必须变红。
        let (c_io, s_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut s = s_io;
            let mut first = [0u8; 1];
            s.read_exact(&mut first).await.unwrap();
            assert_eq!(first[0], T_ENCRYPT);
            server_wrap(s, Some("999999")).await
        });
        let r = client_wrap(c_io, Some("111111")).await;
        assert!(matches!(r, Err(Error::AuthRejected(_))), "错误配对码必须被拒绝");
        let sr = server.await.unwrap();
        assert!(matches!(sr, Err(Error::AuthRejected(_))), "服务端侧同样拒绝");
    }

    #[tokio::test]
    async fn encrypted_roundtrip_large_segments() {
        // 大段写→读回归（读侧跨 poll 状态持久化的正向覆盖）。
        let a = handshake::new_handshake().unwrap();
        let b = handshake::new_handshake().unwrap();
        let ap = a.public().to_vec();
        let bp = b.public().to_vec();
        let ka = a.finish_client(&bp).unwrap();
        let kb = b.finish_server(&ap).unwrap();

        let mut data = vec![0u8; 1024 * 1024 + 77];
        rand_core::OsRng.fill_bytes(&mut data);

        let mut enc = Encrypted::new(Cursor::new(Vec::new()), ka, true);
        enc.write_all(&data).await.unwrap();
        let bytes = std::mem::replace(&mut enc.inner, Cursor::new(Vec::new())).into_inner();

        let mut dec = Encrypted::new(Cursor::new(bytes), kb, false);
        let mut out = vec![0u8; data.len()];
        dec.read_exact(&mut out).await.unwrap();
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn mutual_confirmation_success() {
        let (c_io, s_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
        let mut s = s_io;
        let mut first = [0u8; 1];
        s.read_exact(&mut first).await.unwrap();
        assert_eq!(first[0], T_ENCRYPT);
        server_wrap(s, Some("999999")).await
    });
        let (enc, authed) = client_wrap(c_io, Some("999999")).await.unwrap();
        assert!(authed, "双侧配对码必须完成双向认证");
        let (_, s_authed) = server.await.unwrap().unwrap();
        assert!(s_authed, "服务端必须验证客户端证明");
        let _ = enc;
    }

    #[tokio::test]
    async fn blind_accept_mitm_detected() {
        // 伪造服务端：走完 0x09/0x19 并消费客户端证明，但不校验、也拿不出
        // 有效服务端证明——审查轮5 F2/轮6 P0-1：盲接受必须被客户端识破。
        let (c_io, s_io) = tokio::io::duplex(64 * 1024);
        let fake = tokio::spawn(async move {
            use p256::PublicKey;
            let mut s = s_io;
            let mut hello = [0u8; 1 + 65];
            s.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello[0], T_ENCRYPT);
            let hs = handshake::new_handshake().unwrap();
            let spub = hs.public().to_vec();
            s.write_all(&[T_ENCRYPT_OK]).await.unwrap();
            s.write_all(&spub).await.unwrap();
            let _peer = PublicKey::from_sec1_bytes(&hello[1..]).unwrap();
            let keys = hs.finish_server(&hello[1..]).unwrap();
            let mut enc = Encrypted::new(s, keys, false);
            let mut fl = [0u8; 1];
            enc.read_exact(&mut fl).await.unwrap();
            if fl[0] == 1 {
                let mut p = [0u8; 32];
                enc.read_exact(&mut p).await.unwrap();
                // 攻击者不做校验——这正是「盲接受」。
            }
            enc.write_all(&[STATUS_OK, 0]).await.unwrap();
        });
        let r = client_wrap(c_io, Some("123456")).await;
        assert!(
            matches!(r, Err(Error::AuthRejected(_))),
            "盲接受 MITM 必须被客户端识破"
        );
        fake.abort();
    }

    #[tokio::test]
    async fn config_mismatch_fails_closed() {
        // 客户端有码、服务端无码 → fail-closed（配置错误不可静默通过）。
        let (c_io, s_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
        let mut s = s_io;
        let mut first = [0u8; 1];
        s.read_exact(&mut first).await.unwrap();
        assert_eq!(first[0], T_ENCRYPT);
        server_wrap(s, None).await
    });
        let r = client_wrap(c_io, Some("123456")).await;
        assert!(matches!(r, Err(Error::AuthRejected(_))));
        let sr = server.await.unwrap();
        assert!(sr.is_ok(), "服务端无码 + 客户端有证明 = 宽容接受路径");
    }
}
