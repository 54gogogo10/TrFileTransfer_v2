//! 设备发现（规格 §3.3）：UDP 广播 0xD1 → 应答 0xD2，仅 IPv4，默认端口 45000。
//! 帧布局（小端，WIRE-PROTOCOL.md §6）：
//! - 0xD1 请求：`0xD1 | u16 name_len | name`（请求方通报本机名，供对端记录）；
//! - 0xD2 应答：`0xD2 | u16 name_len | name | u8 flags | u16 tcp_port | u16 quic_port [| u16 rudp_port]`；
//!   flags：bit0 = TCP 监听中、bit1 = QUIC 监听中、bit2 = 需配对码、bit3 = UDT 监听中。
//!
//! 兼容（UDT/QUIC 槽位拆分，TECH-STACK §7.28）：旧版应答尾部只有 tcp+udt（=QUIC）两个
//! 端口字段——旧解码器读新帧会把 quic_port 当「udt」位显示，语义与其一致（其 bit1 即
//! QUIC 槽位），天然向后兼容；新解码器对缺第三字段的旧帧回 `rudp_port = None`（该字段曾名 `udt_port`——更名批 §7.29）。
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
/// bit1：QUIC 槽位监听中（旧版本将此位显示为「UDT」——其 UDT 即本仓库的 QUIC 槽位）。
pub const FLAG_QUIC: u8 = 2;
pub const FLAG_PAIRING: u8 = 4;
/// bit3：RUDP 槽位（原生自研可靠 UDP 流；曾名 UDT，TECH-STACK §7.29）监听中。
pub const FLAG_RUDP: u8 = 8;
/// bit4：UDT4 槽位（真 UDT，与原 C# 版互通，TECH-STACK §7.30）监听中。
pub const FLAG_UDT: u8 = 16;

/// C# 版发现协议的 flags 位（DeviceDiscovery.cs：bit1=UDT bit2=配对）——
/// 裸 0xD1 探测的应答与 C# 响应解析共用。
pub const CS_FLAG_UDT: u8 = 2;
pub const CS_FLAG_PAIRING: u8 = 4;

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredDevice {
    pub name: String,
    pub ip: String,
    pub tcp_port: Option<u16>,
    pub quic_port: Option<u16>,
    pub rudp_port: Option<u16>,
    /// UDT4 槽位端口（bit4）；C# 设备（旧格式解析）仅填此字段。
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

pub fn encode_response(
    name: &str,
    tcp_port: Option<u16>,
    quic_port: Option<u16>,
    rudp_port: Option<u16>,
    needs_pairing: bool,
) -> Option<Vec<u8>> {
    encode_response_ext(name, tcp_port, quic_port, rudp_port, None, needs_pairing)
}

/// 扩展编码（UDT4 槽位追加第四端口字段，仿 bit3/rudp_port 先例）。
pub fn encode_response_ext(
    name: &str,
    tcp_port: Option<u16>,
    quic_port: Option<u16>,
    rudp_port: Option<u16>,
    udt_port: Option<u16>,
    needs_pairing: bool,
) -> Option<Vec<u8>> {
    let mut out = vec![FRAME_RESP];
    if !write_name(&mut out, name) {
        return None;
    }
    let mut flags = 0u8;
    if tcp_port.is_some() {
        flags |= FLAG_TCP;
    }
    if quic_port.is_some() {
        flags |= FLAG_QUIC;
    }
    if needs_pairing {
        flags |= FLAG_PAIRING;
    }
    if rudp_port.is_some() {
        flags |= FLAG_RUDP;
    }
    if udt_port.is_some() {
        flags |= FLAG_UDT;
    }
    out.push(flags);
    out.extend_from_slice(&tcp_port.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&quic_port.unwrap_or(0).to_le_bytes());
    // 第三端口字段仅在 RUDP 槽位启用时追加（旧对端解码器按固定尾部读取，
    // 多出的 2 字节其 `buf.len()` 检查不涉及——向后兼容布局见模块注释）。
    if rudp_port.is_some() {
        out.extend_from_slice(&rudp_port.unwrap_or(0).to_le_bytes());
    }
    // 第四端口字段同理仅在 UDT4 槽位启用时追加。
    if udt_port.is_some() {
        out.extend_from_slice(&udt_port.unwrap_or(0).to_le_bytes());
    }
    Some(out)
}

/// C# 版发现应答（DeviceDiscovery.cs BuildResponse 同构）：
/// `[0xD2][nameLen u8][name][port u16 大端][flags u8]`（bit1=UDT bit2=配对）。
/// 回给 C# 设备的探测应答——只报 UDT 槽位端口（C# 的 flags bit0=TCP 与端口
/// 单字段绑定，报 TCP 会把 C# 的 UDT 发送引到错误端口）。
pub fn encode_cs_response(name: &str, udt_port: u16, needs_pairing: bool) -> Option<Vec<u8>> {
    let name_bytes = name.as_bytes();
    if name_bytes.is_empty() || name_bytes.len() > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(5 + name_bytes.len());
    out.push(FRAME_RESP);
    out.push(name_bytes.len() as u8);
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(&udt_port.to_be_bytes());
    let mut flags = CS_FLAG_UDT;
    if needs_pairing {
        flags |= CS_FLAG_PAIRING;
    }
    out.push(flags);
    Some(out)
}

#[derive(Debug, PartialEq)]
pub enum DiscoveryMsg {
    Request {
        name: String,
    },
    Response {
        name: String,
        tcp_port: Option<u16>,
        quic_port: Option<u16>,
        rudp_port: Option<u16>,
        /// UDT4 槽位（bit4 或 C# 旧格式解析填充）。
        udt_port: Option<u16>,
        needs_pairing: bool,
    },
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
/// 0xD2 应答先按 v2 严格格式解析；失败后回退 C# 旧格式（`[0xD2][nameLen u8][name]
/// [port BE][flags]`，总长恰为 4+nameLen——v2 帧长度恒为 7/9+name，二者互斥，
/// 不存在误判面）。C# 帧解析结果仅填 `udt_port`（其 bit1 即 UDT 槽位）。
pub fn decode(buf: &[u8]) -> Option<DiscoveryMsg> {
    if buf.len() > MAX_PACKET {
        return None;
    }
    let frame = *buf.first()?;
    let mut pos = 1;
    match frame {
        FRAME_REQ => {
            // 裸 0xD1 单字节探测 = C# 版请求（无名字段）——本函数仍按 v2 解析，
            // C# 探测由 serve_answer 直接识别（长度 1 分支）。
            let name = read_name(buf, &mut pos)?;
            Some(DiscoveryMsg::Request { name })
        }
        FRAME_RESP => {
            if let Some(resp) = decode_v2_response(buf) {
                return Some(resp);
            }
            decode_cs_response(buf)
        }
        _ => None,
    }
}

fn decode_v2_response(buf: &[u8]) -> Option<DiscoveryMsg> {
    let mut pos = 1;
    let name = read_name(buf, &mut pos)?;
    let flags = *buf.get(pos)?;
    pos += 1;
    if buf.len() < pos + 4 {
        return None;
    }
    let tcp = u16::from_le_bytes([buf[pos], buf[pos + 1]]);
    let quic = u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]);
    pos += 4;
    // 第三端口字段可选（旧版应答无此字段）。
    let mut rudp = None;
    if flags & FLAG_RUDP != 0 {
        if buf.len() < pos + 2 {
            return None;
        }
        rudp = Some(u16::from_le_bytes([buf[pos], buf[pos + 1]]));
        pos += 2;
    }
    // 第四端口字段可选（UDT4 槽位，TECH-STACK §7.30）。
    let mut udt = None;
    if flags & FLAG_UDT != 0 {
        if buf.len() < pos + 2 {
            return None;
        }
        udt = Some(u16::from_le_bytes([buf[pos], buf[pos + 1]]));
    }
    Some(DiscoveryMsg::Response {
        name,
        tcp_port: if flags & FLAG_TCP != 0 {
            Some(tcp)
        } else {
            None
        },
        quic_port: if flags & FLAG_QUIC != 0 {
            Some(quic)
        } else {
            None
        },
        rudp_port: rudp,
        udt_port: udt,
        needs_pairing: flags & FLAG_PAIRING != 0,
    })
}

/// C# 旧格式 0xD2 解析（DeviceDiscovery.cs ParseResponse 同构）：
/// 总长恰为 5+nameLen（与 v2 帧长 8/10/12+name 互斥——无误判面）、port 大端。
fn decode_cs_response(buf: &[u8]) -> Option<DiscoveryMsg> {
    if buf.len() < 5 {
        return None;
    }
    let name_len = buf[1] as usize;
    if buf.len() != 5 + name_len {
        return None;
    }
    let name = String::from_utf8(buf[2..2 + name_len].to_vec()).ok()?;
    let port = u16::from_be_bytes([buf[2 + name_len], buf[3 + name_len]]);
    let flags = buf[4 + name_len];
    if port == 0 {
        return None;
    }
    Some(DiscoveryMsg::Response {
        name,
        tcp_port: None,
        quic_port: None,
        rudp_port: None,
        udt_port: if flags & CS_FLAG_UDT != 0 {
            Some(port)
        } else {
            None
        },
        needs_pairing: flags & CS_FLAG_PAIRING != 0,
    })
}

/// 实时 flags 闭包：(TCP 端口, QUIC 端口, RUDP 端口, UDT4 端口, 需配对)。
pub type DiscoveryFlagsFn =
    Arc<dyn Fn() -> (Option<u16>, Option<u16>, Option<u16>, Option<u16>, bool) + Send + Sync>;

/// 应答服务：收到 0xD1 → 按实时 flags 回 0xD2（单播）。
/// 双协议兼容（TECH-STACK §7.30）：
/// - 裸 `[0xD1]` 单字节探测 = C# 版请求 → 回 **C# 旧格式**应答（只报 UDT 端口）；
/// - 带 name 的 v2 探测 → 回 v2 格式（含全部槽位端口）。
pub async fn serve_answer(
    socket: UdpSocket,
    name: String,
    flags: DiscoveryFlagsFn,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_PACKET];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        if n > MAX_PACKET {
            continue;
        }
        if n == 1 && buf[0] == FRAME_REQ {
            // C# 探测（裸 0xD1）→ C# 格式应答。
            let (tcp, _quic, _rudp, udt, pairing) = flags();
            if let Some(udt_port) = udt {
                if let Some(resp) = encode_cs_response(&name, udt_port, pairing) {
                    let _ = socket.send_to(&resp, peer).await;
                }
            }
            let _ = tcp;
            continue;
        }
        if matches!(decode(&buf[..n]), Some(DiscoveryMsg::Request { .. })) {
            let (tcp, quic, rudp, udt, pairing) = flags();
            if let Some(resp) = encode_response_ext(&name, tcp, quic, rudp, udt, pairing) {
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
                if let Some(DiscoveryMsg::Response {
                    name,
                    tcp_port,
                    quic_port,
                    rudp_port,
                    udt_port,
                    needs_pairing,
                }) = decode(&buf[..n])
                {
                    let ip = peer.ip().to_string();
                    // 同 IP 去重（多轮应答/多播重复），后到覆盖（标志位更新）。
                    if let Some(d) = out.iter_mut().find(|d| d.ip == ip) {
                        d.name = name;
                        d.tcp_port = tcp_port;
                        d.quic_port = quic_port;
                        d.rudp_port = rudp_port;
                        d.udt_port = udt_port;
                        d.needs_pairing = needs_pairing;
                    } else {
                        out.push(DiscoveredDevice {
                            name,
                            ip,
                            tcp_port,
                            quic_port,
                            rudp_port,
                            udt_port,
                            needs_pairing,
                        });
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

        let resp =
            encode_response_ext("PC-1", Some(8080), Some(8081), Some(8082), Some(8083), true)
                .unwrap();
        assert!(matches!(
            decode(&resp),
            Some(DiscoveryMsg::Response {
                name,
                tcp_port: Some(8080),
                quic_port: Some(8081),
                rudp_port: Some(8082),
                udt_port: Some(8083),
                needs_pairing: true,
            }) if name == "PC-1"
        ));

        // name 超长 → 编码失败；截断包/坏帧 → 解码 None。
        assert!(encode_request(&"x".repeat(MAX_NAME + 1)).is_none());
        assert_eq!(decode(&[0xD1, 0x10]), None, "短包");
        assert_eq!(decode(&[0x77]), None, "未知帧");
        let mut truncated = resp.clone();
        truncated.pop();
        // 恒真式（X || truncated.len() < resp.len()）此前等于没断言——本轮 F9 收紧为
        // 真判别：尾部少一个字节必须解码失败。
        assert!(decode(&truncated).is_none(), "截断不得解码出完整应答");
        // 超限整包忽略
        let big = vec![0u8; MAX_PACKET + 1];
        assert_eq!(decode(&big), None);
    }

    /// 旧版应答（只有 tcp+udt 两端口、无 bit3）→ 新解码器 quic_port 命中、udt_port=None。
    #[test]
    fn legacy_response_without_udt_field_decodes() {
        let mut out = vec![FRAME_RESP];
        let name = b"old-pc";
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        out.push(FLAG_TCP | 2); // bit1 = 旧「UDT」= 本仓库 QUIC 槽位
        out.extend_from_slice(&8080u16.to_le_bytes());
        out.extend_from_slice(&8081u16.to_le_bytes());
        match decode(&out) {
            Some(DiscoveryMsg::Response {
                tcp_port,
                quic_port,
                rudp_port,
                ..
            }) => {
                assert_eq!(tcp_port, Some(8080));
                assert_eq!(quic_port, Some(8081), "旧 bit1 端口应归 QUIC 槽位");
                assert_eq!(rudp_port, None, "旧帧无 RUDP 槽位");
            }
            other => panic!("旧帧必须可解码: {other:?}"),
        }
    }

    /// C# 旧格式 0xD2（裸 nameLen u8 + 大端端口 + bit1=UDT）必须可解析且只落
    /// udt_port——v2 与 C# 帧长互斥（7/9+name vs 4+name），无误判面（TECH-STACK §7.30）。
    #[test]
    fn cs_response_parses_to_udt_port() {
        // DeviceDiscovery.cs BuildResponse("cs-box", 9090, tcp=false, udt=true, pairing=true)
        let mut out = vec![0xD2u8, 6];
        out.extend_from_slice(b"cs-box");
        out.extend_from_slice(&9090u16.to_be_bytes());
        out.push(CS_FLAG_UDT | CS_FLAG_PAIRING);
        match decode(&out) {
            Some(DiscoveryMsg::Response {
                name,
                tcp_port,
                quic_port,
                rudp_port,
                udt_port,
                needs_pairing,
            }) => {
                assert_eq!(name, "cs-box");
                assert_eq!(tcp_port, None);
                assert_eq!(quic_port, None);
                assert_eq!(rudp_port, None);
                assert_eq!(udt_port, Some(9090), "C# 设备端口必须落 UDT4 槽位");
                assert!(needs_pairing);
            }
            other => panic!("C# 帧必须可解码: {other:?}"),
        }
        // 端口为 0 的 C# 帧拒收（防伪造）。
        let mut zero = vec![0xD2u8, 2];
        zero.extend_from_slice(b"pc");
        zero.extend_from_slice(&0u16.to_be_bytes());
        zero.push(CS_FLAG_UDT);
        assert!(decode(&zero).is_none());
        // v2 帧绝不误判为 C# 格式（长度互斥兜底）。
        let v2 = encode_response("PC-1", Some(8080), None, None, false).unwrap();
        assert!(matches!(
            decode(&v2),
            Some(DiscoveryMsg::Response { tcp_port: Some(8080), .. })
        ));
    }

    /// 裸 0xD1（C# 探测）→ C# 格式应答（大端端口 + bit1=UDT）；v2 探测 → v2 格式应答。
    #[tokio::test]
    async fn answer_serves_both_probe_dialects() {
        use std::net::SocketAddr;
        let ans = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ans_addr: SocketAddr = ans.local_addr().unwrap();
        let flags: DiscoveryFlagsFn =
            Arc::new(|| (Some(8080), None, None, Some(9090), true));
        let server = tokio::spawn(serve_answer(ans, "cs-pc".into(), flags));

        // C# 探测：裸 0xD1 单字节。
        let cs = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        cs.send_to(&[0xD1u8], ans_addr).await.unwrap();
        let mut buf = vec![0u8; MAX_PACKET];
        let (_, _) = tokio::time::timeout(Duration::from_secs(3), cs.recv_from(&mut buf))
            .await
            .expect("C# 探测必须有应答")
            .unwrap();
        assert_eq!(buf[0], 0xD2);
        let name_len = buf[1] as usize;
        assert_eq!(&buf[2..2 + name_len], b"cs-pc");
        let port = u16::from_be_bytes([buf[2 + name_len], buf[3 + name_len]]);
        assert_eq!(port, 9090, "C# 应答报 UDT 端口");
        assert_eq!(buf[4 + name_len], CS_FLAG_UDT | CS_FLAG_PAIRING);

        // v2 探测（带名字）。
        let v2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        v2.send_to(&encode_request("probe").unwrap(), ans_addr)
            .await
            .unwrap();
        let (n2, _) = tokio::time::timeout(Duration::from_secs(3), v2.recv_from(&mut buf))
            .await
            .expect("v2 探测必须有应答")
            .unwrap();
        assert!(matches!(
            decode(&buf[..n2]),
            Some(DiscoveryMsg::Response { udt_port: Some(9090), needs_pairing: true, .. })
        ));
        server.abort();
    }

    #[tokio::test]
    async fn answer_service_replies_to_discovery() {
        // 应答方绑回环端口；发现方单播查询（回环上广播不可靠——与生产广播同代码路径 discover_on）。
        let ans = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ans_addr = ans.local_addr().unwrap();
        let flags: DiscoveryFlagsFn =
            Arc::new(|| (Some(8080), Some(8081), Some(8082), Some(8083), true));
        let server = tokio::spawn(serve_answer(ans, "测试机".into(), flags));

        let disc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let devices = discover_on(&disc, &[ans_addr], Duration::from_secs(3))
            .await
            .unwrap();
        server.abort();
        assert_eq!(devices.len(), 1, "应恰好发现一台");
        let d = &devices[0];
        assert_eq!(d.name, "测试机");
        assert_eq!(d.tcp_port, Some(8080));
        assert_eq!(d.quic_port, Some(8081));
        assert_eq!(d.rudp_port, Some(8082));
        assert_eq!(d.udt_port, Some(8083));
        assert!(d.needs_pairing);
        assert_eq!(d.ip, "127.0.0.1");
    }
}
