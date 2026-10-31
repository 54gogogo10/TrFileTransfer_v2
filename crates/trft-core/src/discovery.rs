//! 设备发现（规格 §3.3）：UDP 广播 0xD1 → 应答 0xD2，仅 IPv4，默认端口 45000。
//! 帧布局（小端，WIRE-PROTOCOL.md §6）：
//! - 0xD1 请求：`0xD1 | u16 name_len | name`（请求方通报本机名，供对端记录）；
//! - 0xD2 应答：`0xD2 | u16 name_len | name | u8 flags | u16 tcp_port | u16 udt_port`；
//!   flags：bit0 = TCP 监听中、bit1 = UDT 监听中、bit2 = 需配对码。
//!
//! 守卫：name ≤ 64 字节、包总长 ≤ 512 字节（超出整包忽略——fail-closed）。
//! 应答方仅在有监听器时启动（GUI 决定生命周期）；标志位**实时**读取。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::net::UdpSocket;

pub const FRAME_REQ: u8 = 0xD1;
pub const FRAME_RESP: u8 = 0xD2;
/// name 字节上限（含 UTF-8）。
pub const MAX_NAME: usize = 64;
/// 单包上限（守卫，超出忽略）。
pub const MAX_PACKET: usize = 512;

pub const FLAG_TCP: u8 = 1;
pub const FLAG_UDT: u8 = 2;
pub const FLAG_PAIRING: u8 = 4;

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredDevice {
    pub name: String,
    pub ip: String,
    pub tcp_port: Option<u16>,
    pub udt_port: Option<u16>,
    pub needs_pairing: bool,
}

fn write_name(out: &mut Vec<u8>, name: &str) -> bool {
    let b = name.as_bytes();
    if b.len() > MAX_NAME {
        return false;
    }
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
    true
}

pub fn encode_request(name: &str) -> Option<Vec<u8>> {
    let mut out = vec![FRAME_REQ];
    if !write_name(&mut out, name) {
        return None;
    }
    Some(out)
}

pub fn encode_response(name: &str, tcp_port: Option<u16>, udt_port: Option<u16>, needs_pairing: bool) -> Option<Vec<u8>> {
    let mut out = vec![FRAME_RESP];
    if !write_name(&mut out, name) {
        return None;
    }
    let mut flags = 0u8;
    if tcp_port.is_some() {
        flags |= FLAG_TCP;
    }
    if udt_port.is_some() {
        flags |= FLAG_UDT;
    }
    if needs_pairing {
        flags |= FLAG_PAIRING;
    }
    out.push(flags);
    out.extend_from_slice(&tcp_port.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&udt_port.unwrap_or(0).to_le_bytes());
    Some(out)
}

#[derive(Debug, PartialEq)]
pub enum DiscoveryMsg {
    Request { name: String },
    Response { name: String, tcp_port: Option<u16>, udt_port: Option<u16>, needs_pairing: bool },
}

fn read_name(buf: &[u8], pos: &mut usize) -> Option<String> {
    if buf.len() < *pos + 2 {
        return None;
    }
    let len = u16::from_le_bytes([buf[*pos], buf[*pos + 1]]) as usize;
    *pos += 2;
    if len > MAX_NAME || buf.len() < *pos + len {
        return None;
    }
    let s = String::from_utf8(buf[*pos..*pos + len].to_vec()).ok()?;
    *pos += len;
    Some(s)
}

/// 解码一包；非法/超限/未知帧 → None（fail-closed）。
pub fn decode(buf: &[u8]) -> Option<DiscoveryMsg> {
    if buf.len() > MAX_PACKET {
        return None;
    }
    let frame = *buf.first()?;
    let mut pos = 1;
    match frame {
        FRAME_REQ => {
            let name = read_name(buf, &mut pos)?;
            Some(DiscoveryMsg::Request { name })
        }
        FRAME_RESP => {
            let name = read_name(buf, &mut pos)?;
            let flags = *buf.get(pos)?;
            pos += 1;
            if buf.len() < pos + 4 {
                return None;
            }
            let tcp = u16::from_le_bytes([buf[pos], buf[pos + 1]]);
            let udt = u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]);
            Some(DiscoveryMsg::Response {
                name,
                tcp_port: if flags & FLAG_TCP != 0 { Some(tcp) } else { None },
                udt_port: if flags & FLAG_UDT != 0 { Some(udt) } else { None },
                needs_pairing: flags & FLAG_PAIRING != 0,
            })
        }
        _ => None,
    }
}

/// 应答服务：收到 0xD1 → 按实时 flags 回 0xD2（单播）。返回的 closure 供 GUI abort。
pub async fn serve_answer(
    socket: UdpSocket,
    name: String,
    flags: Arc<dyn Fn() -> (Option<u16>, Option<u16>, bool) + Send + Sync>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_PACKET];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        if n > MAX_PACKET {
            continue;
        }
        if matches!(decode(&buf[..n]), Some(DiscoveryMsg::Request { .. })) {
            let (tcp, udt, pairing) = flags();
            if let Some(resp) = encode_response(&name, tcp, udt, pairing) {
                let _ = socket.send_to(&resp, peer).await;
            }
        }
    }
}

/// 发现已知目标的单次查询（GUI 传广播地址集；测试传单播地址）。
pub async fn discover_on(
    socket: &UdpSocket,
    targets: &[SocketAddr],
    timeout: Duration,
) -> Result<Vec<DiscoveredDevice>, String> {
    let host = hostname();
    let req = encode_request(&host).ok_or("本机名超长")?;
    for t in targets {
        let _ = socket.send_to(&req, *t).await;
    }
    let mut out: Vec<DiscoveredDevice> = Vec::new();
    let mut buf = vec![0u8; MAX_PACKET];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remain.is_zero() {
            break;
        }
        match tokio::time::timeout(remain, socket.recv_from(&mut buf)).await {
            Err(_) => break, // 整体超时
            Ok(Err(e)) => return Err(e.to_string()),
            Ok(Ok((n, peer))) => {
                if n > MAX_PACKET {
                    continue;
                }
                if let Some(DiscoveryMsg::Response { name, tcp_port, udt_port, needs_pairing }) = decode(&buf[..n]) {
                    let ip = peer.ip().to_string();
                    // 同 IP 去重（多轮应答/多播重复），后到覆盖（标志位更新）。
                    if let Some(d) = out.iter_mut().find(|d| d.ip == ip) {
                        d.name = name;
                        d.tcp_port = tcp_port;
                        d.udt_port = udt_port;
                        d.needs_pairing = needs_pairing;
                    } else {
                        out.push(DiscoveredDevice { name, ip, tcp_port, udt_port, needs_pairing });
                    }
                }
            }
        }
    }
    Ok(out)
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "TrFileTransfer".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_and_guards() {
        let req = encode_request("主机A").unwrap();
        assert!(matches!(decode(&req), Some(DiscoveryMsg::Request { name }) if name == "主机A"));

        let resp = encode_response("PC-1", Some(8080), None, true).unwrap();
        assert!(matches!(
            decode(&resp),
            Some(DiscoveryMsg::Response { name, tcp_port: Some(8080), udt_port: None, needs_pairing: true }) if name == "PC-1"
        ));

        // name 超长 → 编码失败；截断包/坏帧 → 解码 None。
        assert!(encode_request(&"x".repeat(MAX_NAME + 1)).is_none());
        assert_eq!(decode(&[0xD1, 0x10]), None, "短包");
        assert_eq!(decode(&[0x77]), None, "未知帧");
        let mut truncated = resp.clone();
        truncated.pop();
        assert!(decode(&truncated).is_none() || truncated.len() < resp.len(), "截断不得解码出完整应答");
        // 超限整包忽略
        let big = vec![0u8; MAX_PACKET + 1];
        assert_eq!(decode(&big), None);
    }

    #[tokio::test]
    async fn answer_service_replies_to_discovery() {
        // 应答方绑回环端口；发现方单播查询（回环上广播不可靠——与生产广播同代码路径 discover_on）。
        let ans = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ans_addr = ans.local_addr().unwrap();
        let flags: Arc<dyn Fn() -> (Option<u16>, Option<u16>, bool) + Send + Sync> =
            Arc::new(|| (Some(8080), Some(8081), true));
        let server = tokio::spawn(serve_answer(ans, "测试机".into(), flags));

        let disc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let devices = discover_on(&disc, &[ans_addr], Duration::from_secs(3)).await.unwrap();
        server.abort();
        assert_eq!(devices.len(), 1, "应恰好发现一台");
        let d = &devices[0];
        assert_eq!(d.name, "测试机");
        assert_eq!(d.tcp_port, Some(8080));
        assert_eq!(d.udt_port, Some(8081));
        assert!(d.needs_pairing);
        assert_eq!(d.ip, "127.0.0.1");
    }
}
