//! QUIC 槽位（规格 §9.2「QUIC 替代 UDT」）：quinn + 运行时自签证书。
//! 传输加密由 TLS 1.3 承担；客户端跳过证书链校验（自签、无 CA 体系）。
//! 认证：0x0D 通道绑定配对（M6'）——证明混入「客户端所见服务器证书指纹」，
//! 双臂中继两腿证书必然不同 → 证明必败；新版服务端对 QUIC + 配对启用强制绑定
//! （明文 0x05 拒绝，客户端遇旧服务端自动回退并记警告——TECH-STACK §7.11）。

use crate::error::{Error, Result, proto};
use crate::transfer::receiver::{RecvOptions, handle_conn_quic};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;
use std::result::Result as SResult;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 自签证书的 SNI/SAN（客户端跳过校验，此名仅作握手标识）。
pub const QUIC_SNI: &str = "trft.local";

fn io_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Io(io::Error::other(e.to_string()))
}

/// 客户端 TLS 配置（自签模型：pin = Some 强制指纹钉扎；None = 信任任何自签证书）。
/// 公开供嵌入方与判别测试构造原始 QUIC 客户端（如 MITM 中继模拟）。
pub fn client_tls_config(pin: Option<[u8; 32]>) -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerify::new(pin))
        .with_no_client_auth()
}

/// 证书链校验策略：pin = Some 时强制 SHA-256 指纹匹配（TOFU/钉扎）；
/// None = 信任任何自签证书（信任模型由应用层配对码承担）。
#[derive(Debug)]
struct SkipServerVerify {
    provider: Arc<rustls::crypto::CryptoProvider>,
    pin: Option<[u8; 32]>,
}

impl SkipServerVerify {
    fn new(pin: Option<[u8; 32]>) -> Arc<Self> {
        Arc::new(Self { provider: Arc::new(rustls::crypto::ring::default_provider()), pin })
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerify {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> SResult<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(pin) = &self.pin {
            let fp = crate::hash::sha256(end_entity.as_ref());
            if !crate::crypto::kdf::ct_eq(&fp, pin) {
                return Err(rustls::Error::General("服务器证书指纹不匹配（钉扎校验失败）".into()));
            }
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> SResult<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> SResult<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// 双向 QUIC 流上的统一读写对象——帧协议与 TCP 完全一致。
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // quinn 的固有方法遮蔽了 trait 方法，必须全限定。
        <quinn::SendStream as AsyncWrite>::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// 创建 QUIC 服务端 endpoint（运行时生成自签证书）。
/// 返回 (endpoint, 证书指纹)：指纹供 0x0D 通道绑定配对校验（M6'）。
pub async fn server_endpoint(addr: SocketAddr) -> Result<(quinn::Endpoint, [u8; 32])> {
    let ck = rcgen::generate_simple_self_signed(vec![QUIC_SNI.to_string()])
        .map_err(|e| proto(format!("自签证书生成失败: {e}")))?;
    let cert: rustls::pki_types::CertificateDer<'static> = ck.cert.into();
    let fp = crate::hash::sha256(cert.as_ref());
    let key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .map_err(|e| proto(format!("服务端证书配置失败: {e}")))?;
    let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .map_err(|e| proto(format!("QUIC 服务端配置失败: {e}")))?;
    let cfg = quinn::ServerConfig::with_crypto(Arc::new(qsc));
    Ok((quinn::Endpoint::server(cfg, addr).map_err(io_err)?, fp))
}

pub async fn connect_quic(addr: SocketAddr, pin: Option<[u8; 32]>) -> Result<QuicStream> {
    Ok(connect_quic_full(addr, pin).await?.0)
}

/// 建连并返回 (流, 客户端所见服务器证书指纹)。
/// `--pin` 时 SkipServerVerify 已强制指纹匹配，此处提取值 = pin；
/// 无 pin 时指纹供 0x0D 通道绑定证明使用（M6'）。
pub async fn connect_quic_full(addr: SocketAddr, pin: Option<[u8; 32]>) -> Result<(QuicStream, [u8; 32])> {
    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls_config(pin))
        .map_err(|e| proto(format!("QUIC 客户端配置失败: {e}")))?;
    // 按目标地址族选择本地绑定（IPv6 不可达修复）。
    let local: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let mut endpoint = quinn::Endpoint::client(local).map_err(io_err)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(qcc)));
    let conn = endpoint
        .connect(addr, QUIC_SNI)
        .map_err(io_err)?
        .await
        .map_err(io_err)?;
    // 提取对端（服务器）证书链的端实体指纹（quinn 对 rustls 以 Vec<CertificateDer> 承载）。
    let fp = match conn.peer_identity().and_then(|id| id.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().ok()) {
        Some(certs) if !certs.is_empty() => crate::hash::sha256(certs[0].as_ref()),
        _ => return Err(proto("QUIC 握手未返回对端证书（通道绑定不可用）")),
    };
    let (send, recv) = conn.open_bi().await.map_err(io_err)?;
    let mut qs = QuicStream { send, recv };
    crate::protocol::io::write_all(&mut qs, &[crate::protocol::PROTO_VERSION]).await?;
    Ok((qs, fp))
}

pub async fn serve_quic(addr: SocketAddr, opts: RecvOptions) -> Result<()> {
    let (endpoint, fp) = server_endpoint(addr).await?;
    serve_quic_on(endpoint, fp, opts).await
}

pub async fn serve_quic_on(endpoint: quinn::Endpoint, cert_fp: [u8; 32], opts: RecvOptions) -> Result<()> {
    // 孤儿半成品清扫（轮 1：QUIC 此前缺席——与 TCP/UDP 同策略 7 天）。
    crate::transfer::receiver::cleanup_part_orphans(&opts.save_dir);
    crate::transfer::resume::cleanup_resume_orphans(&opts.save_dir);
    let served = Arc::new(AtomicU64::new(0));
    match opts.max_count {
        // 限量模式：串行，收满即停。
        Some(max) => loop {
            if served.load(Ordering::Relaxed) >= max {
                return Ok(());
            }
            let Some(incoming) = endpoint.accept().await else {
                return Err(proto("QUIC endpoint 已关闭"));
            };
            if let Err(e) = handle_incoming(incoming, &opts, served.clone(), cert_fp).await {
                eprintln!("[连接失败] {e}");
            }
        },
        // 常驻模式：JoinSet 与 TCP 对齐（endpoint 关闭时任务一并收尾）。
        None => {
            let mut set = tokio::task::JoinSet::new();
            loop {
                let Some(incoming) = endpoint.accept().await else {
                    while set.join_next().await.is_some() {}
                    return Err(proto("QUIC endpoint 已关闭"));
                };
                // 收割已完成任务（轮 5：完成条目驻留 ~190B/连接，随 accept 周期回收）。
                while set.try_join_next().is_some() {}
                let o = opts.clone();
                let c = served.clone();
                set.spawn(async move {
                    let _ = handle_incoming(incoming, &o, c, cert_fp).await;
                });
            }
        }
    }
}

async fn handle_incoming(
    incoming: quinn::Incoming,
    opts: &RecvOptions,
    served: Arc<AtomicU64>,
    cert_fp: [u8; 32],
) -> Result<()> {
    // IP 过滤先于握手（轮 2 P3：被拒源不得进入握手、不占任何资源）。
    if !crate::transfer::receiver::ip_allowed(
        incoming.remote_address().ip(),
        opts.ip_filter_mode,
        &opts.ip_filter_list,
    ) {
        return Err(crate::error::proto("被 IP 过滤规则拒绝"));
    }
    // 并发闸提前到 TLS 握手之前（每连接**一次**——轮 2 P3：此前 conn_precheck
    // 在闸已持的情况下再取一次，并发 64 实际减半）。
    let permit = crate::transfer::receiver::conn_permit(opts).await?;
    // 锁定门需要真实 peer（连接建立后立刻检查）。
    let conn = tokio::time::timeout(Duration::from_secs(30), incoming)
        .await
        .map_err(|_| proto("QUIC 握手超时"))?
        .map_err(io_err)?;
    let peer = conn.remote_address();
    crate::transfer::receiver::gate_check(peer, opts).await?;
    // 建流 30s 应用层超时：防「保活但零进度」占满 accept 槽。
    let (send, recv) = tokio::time::timeout(Duration::from_secs(30), conn.accept_bi())
        .await
        .map_err(|_| proto("QUIC 建流超时"))?
        .map_err(io_err)?;
    let mut qs = QuicStream { send, recv };
    // quinn 的流是懒打开：客户端必须先写一个版本字节，accept_bi 才能看到流。
    // 顺带充当协议版本校验（fail-closed）。
    let v = crate::protocol::io::read_u8(&mut qs).await?;
    if v != crate::protocol::PROTO_VERSION {
        return Err(proto(format!("协议版本不符: 0x{v:02X}")));
    }
    // 关键：QUIC 的 Connection drop 会隐式 close 并重置流——若在客户端读完
    // 完成确认之前关连接，状态字节会被吞掉（TCP 无此问题）。收尾排水在
    // 帧循环内部执行（always_drain=true，栈还活着时等对端发侧 FIN，5 秒兜底）。
    // 通道绑定：QUIC 槽位配对证明必须绑定本端证书指纹（明文 0x05 拒绝——§7.11）。
    // 闸许可自 handle_incoming 传入（已过滤/已持闸——不得重复获取）。
    handle_conn_quic(&mut qs, peer, opts, served, Some(cert_fp), permit).await
}
