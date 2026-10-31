//! 发送端（TCP / QUIC 共用逻辑）：单文件 0x00（流式哈希 + 完成确认）、文本 0x06、配对 0x05、
//! 前导栈协商（0x0A 能力探询 + 0x08 压缩，WIRE-PROTOCOL.md §2）。
//! 失败必须上抛（规格 §7.1），不得把失败吞成成功。

use crate::crypto::kdf::{ct_eq, derive_pairing_key, pairing_proof, pairing_proof_bound, pairing_proof_s2c};
use crate::error::{Error, Result, config_err, proto};
use crate::hash::FileDigester;
use crate::limiter::TokenBucket;
use crate::protocol::frame::{
    CAP_COMPRESS, MAX_TRANSFER_SIZE, R_CAPABILITY, R_PAIRING_SALT, STATUS_OK, STATUS_REJECT,
    T_CAPABILITY, T_COMPRESS, T_COMPRESS_OK, T_PAIRING, T_PAIRING_BOUND, T_SINGLE_FILE, T_TEXT,
    sanitize_name,
};
use crate::protocol::io::{
    read_n, read_u8, write_all, write_str_u16, write_u32, write_u64, write_u8,
};
use crate::transfer::compress::Compressed;
use crate::transfer::encrypted;
use crate::transfer::quic::{QuicStream, connect_quic, connect_quic_full};
use crate::transfer::{BoxStream, CHUNK, Transport};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

#[derive(Debug, Clone)]
pub struct SendOptions {
    /// 配对码：两侧必须一致（规格 §4.1 0x05）。
    pub pairing_code: Option<String>,
    /// 发送限速（字节/秒，0=不限）。
    pub speed_limit_bps: u64,
    /// 源端口绑定；绑定失败属可重试错误（规格 §3.1）。仅 TCP。
    pub src_port: Option<u16>,
    /// 流式通道选择（TCP / QUIC）。
    pub transport: Transport,
    /// TCP 走 0x09 加密握手（规格 §5.1 被动窃听防线）；QUIC 由 TLS 承担。
    pub encrypt: bool,
    /// QUIC 服务端证书 SHA-256 指纹钉扎（可选；None = 信任任何自签证书）。
    pub quic_pin: Option<[u8; 32]>,
    /// 客户端期望压缩（0x08；库默认关——CLI/GUI 默认开，对旧对端自动降级明文）。
    pub compress: bool,
    /// QUIC 遇旧服务端（对 0x0D 回 0x00）时允许回退明文 0x05。**默认 false**
    /// （fail-closed，轮 2 F1：主动中间人可伪装旧服务端强制降级——0x05 无
    /// S→C 证明，盲接受型 MITM 可窃取载荷并令客户端假成功）。确需对接旧对端
    /// 时显式开启（CLI --allow-legacy-pair / GUI 配置），或改用 --pin（钉扎即绑定）。
    pub allow_legacy_pair: bool,
    /// 进度上报（规格 §3.1 100ms 节流；None = 不上报，CLI 路径零开销）。
    pub progress: Option<crate::progress::Reporter>,
    /// 传输统计（M5'：成功完成记账；None = 不记）。
    pub stats: Option<std::sync::Arc<crate::stats::StatsLog>>,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            pairing_code: None,
            speed_limit_bps: 0,
            src_port: None,
            transport: Transport::Tcp,
            encrypt: true,
            quic_pin: None,
            compress: false,
            allow_legacy_pair: false,
            progress: None,
            stats: None,
        }
    }
}

/// 成功完成的统计记账（仅成功——失败可见于进度终态/运行日志；TECH-STACK §7.10）。
pub(crate) fn record_stats(
    opts: &SendOptions,
    addr: SocketAddr,
    bytes: u64,
    files: u32,
    started: std::time::Instant,
    detail: &str,
    name: &str,
) {
    if let Some(s) = &opts.stats {
        s.record(
            crate::stats::Direction::Send,
            &addr.ip().to_string(),
            bytes,
            files,
            started.elapsed().as_secs(),
            detail,
            name,
        );
    }
}

/// 客户端前导栈协商计划（WIRE-PROTOCOL.md §2）。
#[derive(Debug, Clone, Copy, Default)]
pub struct StackPlan {
    /// 发 0x0A 能力探询：0x02/0x04 等大载荷扩展帧先探询，旧对端短路直返 Unsupported。
    pub probe_caps: bool,
    /// 期望压缩：需能力探询确认 CAP_COMPRESS 后才真正发 0x08（无探询不协商）。
    pub compress: bool,
}

/// 建连超时（轮 3 P3：对丢 SYN 的不可达地址挂 OS 默认时长——Windows ≈21s/Linux 可达 2min）。
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub(crate) async fn connect(addr: SocketAddr, src_port: Option<u16>) -> Result<TcpStream> {
    match src_port {
        None => Ok(tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await
            .map_err(|_| proto("连接超时（10s）"))??),
        Some(port) => {
            let local = SocketAddr::new(
                if addr.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                },
                port,
            );
            let sock = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
            sock.bind(local)?;
            Ok(tokio::time::timeout(CONNECT_TIMEOUT, sock.connect(addr))
                .await
                .map_err(|_| proto("连接超时（10s）"))??)
        }
    }
}

/// 配对握手（0x05）：服务端先发 16 字节盐，客户端回 HMAC 证明，服务端恒时比对。
pub(crate) async fn authenticate<S>(s: &mut S, code: Option<&str>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(code) = code {
        // 明文 0x05 门（协议 v2）：宣告 → 盐 → 证明 → 结论。
        write_u8(s, T_PAIRING).await?;
        let salt = read_n(s, 16).await?;
        let c = code.to_string();
        let salt2 = salt.clone();
        let k = tokio::task::spawn_blocking(move || derive_pairing_key(&c, &salt2))
            .await
            .map_err(|e| crate::error::proto(e.to_string()))?;
        let proof = pairing_proof(&k, &salt);
        write_all(s, &proof).await?;
        let st = read_u8(s).await?;
        if st != STATUS_OK {
            return Err(Error::AuthRejected("配对码被对端拒绝".into()));
        }
    }
    Ok(())
}

/// 旧服务端降级标记（嵌入 AuthRejected 消息，connect_quic_auth 判别回退用）。
const LEGACY_DOWNGRADE: &str = "PAIR-LEGACY-DOWNGRADE";

/// 0x0D 通道绑定配对（QUIC，M6'）：0x0D → 0x1D 盐 → 绑定证明 → 0x01/0x00。
/// 首字节非 0x1D = 旧服务端（对未知帧回 0x00）→ 判别为降级信号。
async fn authenticate_bound<S>(s: &mut S, code: &str, cert_fp: &[u8; 32]) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_u8(s, T_PAIRING_BOUND).await?;
    let first = read_u8(s).await?;
    if first != R_PAIRING_SALT {
        return Err(Error::AuthRejected(format!(
            "{LEGACY_DOWNGRADE}: 对端不支持通道绑定配对（旧版本）"
        )));
    }
    let salt = read_n(s, 16).await?;
    let c = code.to_string();
    let salt2 = salt.clone();
    let k = tokio::task::spawn_blocking(move || derive_pairing_key(&c, &salt2))
        .await
        .map_err(|e| crate::error::proto(e.to_string()))?;
    write_all(s, &pairing_proof_bound(&k, &salt, cert_fp)).await?;
    let st = read_u8(s).await?;
    if st != STATUS_OK {
        return Err(Error::AuthRejected("配对码被对端拒绝".into()));
    }
    // 双向确认（轮 2 P1）：验证服务端 S→C 证明——盲接受型假服务端（不知配对码）
    // 无法伪造 HMAC(K, s2c 域‖盐‖fp)，恒时校验失败即断。
    let s2c: [u8; 32] = read_n(s, 32).await?.try_into().expect("32 字节证明");
    if !ct_eq(&s2c, &pairing_proof_s2c(&k, &salt, cert_fp)) {
        return Err(Error::AuthRejected("服务端配对证明校验失败（疑似假服务端）".into()));
    }
    Ok(())
}

/// QUIC 建连 + 配对（通道绑定优先；旧服务端回退**默认拒绝**——轮 2 F1：
/// 单个未认证字节不足以区分「旧服务端」与「伪装旧服务端的主动中间人」，
/// MITM 对 0x0D 回 0x00 即可把客户端逼进无 S→C 证明的明文 0x05 腿内窃取
/// 载荷并令其假成功。TECH-STACK §7.11「回退只可能发生在旧服务端上」的前提
/// 不成立——须 `allow_legacy_pair` 显式放行（fail-closed，规格 §1.4））。
pub(crate) async fn connect_quic_auth(addr: SocketAddr, opts: &SendOptions) -> Result<QuicStream> {
    let (mut q, fp) = connect_quic_full(addr, opts.quic_pin).await?;
    if let Some(code) = opts.pairing_code.as_deref() {
        match authenticate_bound(&mut q, code, &fp).await {
            Ok(()) => {}
            Err(Error::AuthRejected(m)) if m.starts_with(LEGACY_DOWNGRADE) => {
                if !opts.allow_legacy_pair {
                    return Err(Error::AuthRejected(format!(
                        "{addr}: 对端不支持通道绑定配对（0x0D 被拒）——可能为旧版本，也可能是\
                         主动中间人降级攻击；确认对端后可用 --allow-legacy-pair 显式放行，\
                         或使用 --pin 钉扎（fail-closed）"
                    )));
                }
                eprintln!(
                    "[警告] 对端为旧版本（不支持通道绑定配对），按显式放行回退明文 0x05——该路径不防主动中间人"
                );
                let mut q2 = connect_quic(addr, opts.quic_pin).await?;
                authenticate(&mut q2, Some(code)).await?;
                return Ok(q2);
            }
            // 其余任何失败（读超时/EOF/证明失配/配对码错误）一律上抛：
            // 轮 2 修复——此前 if-let 只接 AuthRejected，超时等错误被静默吞掉后
            // 以 Ok(未认证流) 继续，沉默型假服务端可令客户端跳过配对直传（旁路）。
            Err(e) => return Err(e),
        }
    }
    Ok(q)
}

/// 建连 + 认证 + 能力探询 + 压缩协商，返回（帧层流, 对端能力位，未探询为 0）。
/// 认证在前、0x0A 次之、0x08 最后（规格 §4.1；压缩需能力确认，旧对端对 0x08 会直接断连）。
pub(crate) async fn connect_stack(
    addr: SocketAddr,
    opts: &SendOptions,
    plan: StackPlan,
) -> Result<(BoxStream, u8)> {
    let mut s: BoxStream = match opts.transport {
        Transport::Tcp => {
            let t = connect(addr, opts.src_port).await?;
            t.set_nodelay(true).ok();
            if opts.encrypt {
                // 0x09 加密握手；证明绑定公钥转写，认证在握手中完成。
                let (enc, _authed) = encrypted::client_wrap(t, opts.pairing_code.as_deref()).await?;
                Box::new(enc)
            } else {
                let mut t = t;
                authenticate(&mut t, opts.pairing_code.as_deref()).await?;
                Box::new(t)
            }
        }
        Transport::Quic => {
            // 配对已在 connect_quic_auth 内完成（含 0x0D 通道绑定/旧端回退）。
            let q = connect_quic_auth(addr, opts).await?;
            Box::new(q)
        }
    };
    let mut caps = 0u8;
    if plan.probe_caps {
        write_u8(&mut s, T_CAPABILITY).await?;
        let first = read_u8(&mut s).await?;
        if first != R_CAPABILITY {
            // 旧对端：对未知帧回 0x00 后断开 → 不支持扩展帧。
            return Err(Error::Unsupported("对端无能力协商（旧版本对端）".into()));
        }
        caps = read_u8(&mut s).await?;
    }
    if plan.compress && caps & CAP_COMPRESS != 0 {
        write_u8(&mut s, T_COMPRESS).await?;
        match read_u8(&mut s).await? {
            T_COMPRESS_OK => s = Box::new(Compressed::new(s)),
            STATUS_REJECT => {} // 服务端未启用：宽容降级，明文继续
            other => return Err(proto(format!("压缩协商应答异常: 0x{other:02X}"))),
        }
    }
    Ok((s, caps))
}

async fn stream_send_file<S>(s: &mut S, path: &Path, opts: &SendOptions) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
    if let Some(r) = &opts.progress {
        r.set_total(size);
    }

    write_u8(s, T_SINGLE_FILE).await?;
    write_str_u16(s, &name).await?;
    write_u64(s, size).await?;

    let mut f = tokio::fs::File::open(path).await?;
    let mut dig = FileDigester::new();
    let mut lim = TokenBucket::new(opts.speed_limit_bps);
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        // 所有分块（含最后一块）都必须过限速。
        lim.acquire(n as u64).await;
        dig.update(&buf[..n]);
        s.write_all(&buf[..n]).await?;
        if let Some(r) = &opts.progress {
            r.add(n as u64);
        }
    }
    s.write_all(&dig.finalize()).await?;

    // 完成确认：接收端权威，结果未知 ≠ 成功。
    let st = read_u8(s).await?;
    let _ = s.shutdown().await; // 干净收尾：让对端读到 EOF 而非连接重置
    if st != STATUS_OK {
        return Err(Error::Rejected("接收端拒绝（状态 0x00）".into()));
    }
    Ok(())
}

async fn stream_send_text<S>(s: &mut S, text: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bytes = text.as_bytes();
    if bytes.len() > crate::protocol::frame::MAX_TEXT_LEN {
        return Err(config_err("文本超过 1MB 上限"));
    }
    write_u8(s, T_TEXT).await?;
    write_u32(s, bytes.len() as u32).await?;
    write_all(s, bytes).await?;
    let st = read_u8(s).await?;
    let _ = s.shutdown().await;
    if st != STATUS_OK {
        return Err(Error::Rejected("对端拒绝文本（状态 0x00）".into()));
    }
    Ok(())
}

pub async fn send_file(addr: SocketAddr, path: &Path, opts: &SendOptions) -> Result<()> {
    let outcome = crate::progress::Outcome::new(opts.progress.clone());
    let res = match opts.transport {
        Transport::Tcp => {
            let s = connect(addr, opts.src_port).await?;
            s.set_nodelay(true).ok();
            if opts.encrypt {
                // 0x09 加密握手；证明绑定公钥转写，认证在握手中完成。
                let (mut enc, _authed) = encrypted::client_wrap(s, opts.pairing_code.as_deref()).await?;
                stream_send_file(&mut enc, path, opts).await
            } else {
                let mut s = s;
                authenticate(&mut s, opts.pairing_code.as_deref()).await?;
                stream_send_file(&mut s, path, opts).await
            }
        }
        Transport::Quic => {
            let mut s = connect_quic_auth(addr, opts).await?;
            stream_send_file(&mut s, path, opts).await
        }
    };
    if res.is_ok() {
        outcome.finish();
    }
    res
}

pub async fn send_text(addr: SocketAddr, text: &str, opts: &SendOptions) -> Result<()> {
    let started = std::time::Instant::now();
    let res = match opts.transport {
        Transport::Tcp => {
            let s = connect(addr, opts.src_port).await?;
            s.set_nodelay(true).ok();
            if opts.encrypt {
                let (mut enc, _authed) = encrypted::client_wrap(s, opts.pairing_code.as_deref()).await?;
                stream_send_text(&mut enc, text).await
            } else {
                let mut s = s;
                authenticate(&mut s, opts.pairing_code.as_deref()).await?;
                stream_send_text(&mut s, text).await
            }
        }
        Transport::Quic => {
            let mut s = connect_quic_auth(addr, opts).await?;
            stream_send_text(&mut s, text).await
        }
    };
    if res.is_ok() {
        record_stats(opts, addr, text.as_bytes().len() as u64, 0, started, "0x06 文本", "<文本>");
    }
    res
}
