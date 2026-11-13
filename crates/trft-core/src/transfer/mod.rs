//! TCP 传输（Rust 版线协议）：单文件 0x00、文件夹 0x01、文本 0x06、配对 0x05、
//! 分块 0x02/0x0B/0x0C、续传 0x03/0x04、压缩 0x08。QUIC/RUDP 槽位复用同一套帧协议。
//! 字节级布局见 docs/WIRE-PROTOCOL.md。

pub mod chunked;
pub mod compress;
pub mod encrypted;
pub mod folder;
pub mod quic;
pub mod receiver;
pub mod resume;
pub mod rudp;
pub mod sender;
/// UDT4 传输（真 UDT 协议；与原 C# 版 libudt 4.x 互通——TECH-STACK §7.30）。
pub mod udt;
pub mod udp;
/// C# 方言应用层（跑在 `transfer::udt` 之上；帧集与 C# 版 TCP 协议同构）。
pub mod cswire;

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 传输块大小：1 MiB（限速与进度节流的基准）。
pub const CHUNK: usize = 1 << 20;

/// 通配 IPv6（`::`）判定：唯一需要双栈的绑定地址（对齐原版「全部 IPv6」，
/// TECH-STACK §7.31）。具体 IPv6 地址只服务本族，无需双栈。
pub fn is_v6_wildcard(ip: std::net::IpAddr) -> bool {
    matches!(ip, std::net::IpAddr::V6(v6) if v6.is_unspecified())
}

/// TCP 监听 socket（socket2：通配 `::` 时关 only_v6 = **双栈**——Windows 默认
/// IPV6_V6ONLY=1，不关则 `::` 收不到 IPv4；选项必须 bind 前设置）。
pub fn std_tcp_listener(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
    if is_v6_wildcard(addr.ip()) {
        let _ = sock.set_only_v6(false); // 平台不支持仅损失双栈（fail-open 与原版一致）
    }
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    Ok(sock.into())
}

/// TCP 监听（tokio 封装，serve 入口用）。
pub async fn bind_tcp(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let l = std_tcp_listener(addr)?;
    l.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(l)
}

/// UDP 监听 socket（socket2：收缓冲 4MB 规格 §6.1；通配 `::` 时关 only_v6 = 双栈——
/// QUIC/RUDP/UDT/单向 UDP 共用）。
pub fn std_udp_listener(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    if is_v6_wildcard(addr.ip()) {
        let _ = sock.set_only_v6(false);
    }
    sock.bind(&addr.into())?;
    if let Err(e) = sock.set_recv_buffer_size(4 * 1024 * 1024) {
        eprintln!("[警告] UDP 收缓冲设置失败: {e}");
    }
    Ok(sock.into())
}

/// 流式传输通道（单向 UDP 不在此列——它走 `udp` 模块的无回传协议）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    /// 通用、防火墙友好。
    #[default]
    Tcp,
    /// QUIC（quinn，TLS 1.3 + 自签证书 + 0x0D 通道绑定）。
    Quic,
    /// RUDP 槽位（原生 Rust：UDP 之上的自研可靠有序字节流，`transfer::rudp`；
    /// 曾名「UDT」——因与 UDT4 重名更名，TECH-STACK §7.29）。
    /// 与 TCP 同帧协议，线格式为本仓库自定义（不与 UDT4/任何外部协议互通，规格 §4.3）。
    Rudp,
    /// UDT4 槽位（原生 Rust 复刻 libudt 4.x，`transfer::udt` + `transfer::cswire`
    /// C# 方言应用层）——全仓库唯一与原 C# 版互通的槽位（TECH-STACK §7.30）。
    Udt,
}

/// 统一读写 trait：客户端栈装箱用（Tcp / Encrypted<Tcp> / QuicStream / Compressed<…>）。
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// 装箱后的客户端帧层流。
pub type BoxStream = Box<dyn AsyncStream>;

/// 前导协商后的帧层流栈：压缩是唯一可选的外层装饰器（机密性由底层的
/// `Encrypted<TcpStream>` / QUIC TLS / 明文承担，见 WIRE-PROTOCOL.md §1）。
pub(crate) enum Framed<S> {
    Raw(S),
    Comp(compress::Compressed<S>),
}

impl<S: AsyncRead + Unpin> AsyncRead for Framed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Framed::Raw(s) => Pin::new(s).poll_read(cx, buf),
            Framed::Comp(c) => Pin::new(c).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Framed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Framed::Raw(s) => Pin::new(s).poll_write(cx, buf),
            Framed::Comp(c) => Pin::new(c).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Framed::Raw(s) => Pin::new(s).poll_flush(cx),
            Framed::Comp(c) => Pin::new(c).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Framed::Raw(s) => Pin::new(s).poll_shutdown(cx),
            Framed::Comp(c) => Pin::new(c).poll_shutdown(cx),
        }
    }
}
