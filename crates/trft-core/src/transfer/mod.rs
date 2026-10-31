//! TCP 传输（Rust 版线协议）：单文件 0x00、文件夹 0x01、文本 0x06、配对 0x05、
//! 分块 0x02/0x0B/0x0C、续传 0x03/0x04、压缩 0x08。QUIC 槽位复用同一套帧协议。
//! 字节级布局见 docs/WIRE-PROTOCOL.md。

pub mod chunked;
pub mod compress;
pub mod encrypted;
pub mod folder;
pub mod quic;
pub mod receiver;
pub mod resume;
pub mod sender;
pub mod udp;

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 传输块大小：1 MiB（限速与进度节流的基准）。
pub const CHUNK: usize = 1 << 20;

/// 流式传输通道（单向 UDP 不在此列——它走 `udp` 模块的无回传协议）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    /// 通用、防火墙友好。
    #[default]
    Tcp,
    /// 可靠 UDP 流槽位（QUIC 实现，规格书原 UDT 的替代）。
    Quic,
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
