//! 线协议（Rust 版 v2）。产品级语义沿用 PRODUCT-SPEC.md §4；字节级布局以本模块为权威，
//! 后续抽为 WIRE-PROTOCOL.md。所有多字节整数一律小端（LE）。

pub mod frame;
pub mod io;
pub mod udp;
pub mod udt;

/// 协议版本号（单向 UDP 公共头第 1 字节）。
pub const PROTO_VERSION: u8 = 2;
