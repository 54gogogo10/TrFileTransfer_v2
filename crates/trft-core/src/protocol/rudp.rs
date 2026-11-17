//! RUDP 传输包格式（UDP 之上的自研可靠有序字节流；WIRE-PROTOCOL.md「RUDP 传输」节）。
//! 历史注记：本传输曾以「UDT」为名（原 C# 版槽位名）——因与 UDT4 协议重名且实现
//! 并非 UDT4，2026-11-12 更名 RUDP（TECH-STACK §7.29）；线格式与更名前完全一致。
//! 12 字节公共头（小端）：`magic "TU"(2B) | ver(1B) | type(1B) | conn_id(u32) | seq(u32) | payload_len(u16)`。
//!
//! 与单向 UDP（无回传链路）不同，UDT 是**双向可靠流**：DATA 靠 ACK/SACK 确认，
//! FIN/FIN_ACK 优雅收尾，RST 中止。seq 语义：DATA 包从 0 连续编号；ACK 携带
//! 「累积确认 = 期望的下一个 seq」+ SACK 区间；FIN 携带 DATA 总数（收满即回执）。

/// 公共头长度。
pub const RUDP_HEADER_LEN: usize = 12;
/// magic（"TU"——TrFileTransfer UDP-stream，与同端口的单向 UDP/其他流量区分的误收包过滤）。
pub const RUDP_MAGIC: [u8; 2] = [b'T', b'U'];
/// 默认单包载荷上限：1200B（+ UDP/IP 头 <1280B，规避 IPv4/IPv6 分片与隧道黑洞）。
pub const RUDP_PAYLOAD_MAX: usize = 1200;
/// MSS 协商上限（性能批 2026-11-14）：环回/内网大包——Windows/Linux 环回 UDP
/// 数据报上限 65507B，60000 留余量。非环回链路的提案仍为以太网友好的 1400B。
pub const RUDP_MSS_CEIL: usize = 60000;

/// 环回提案的实际取值。**macOS 的 `net.inet.udp.maxdgram` 默认仅 9216B**，
/// 超限 `sendto` 返回 EMSGSIZE（发送侧此前忽略该错误 → 数据包一个也发不出去，
/// 重传耗尽后报「重传超限（链路过差）」；CI 的 macOS 任务据此长期红）。
/// 保守取 8000（含 14B 包头仍 < 9216）。
#[cfg(target_os = "macos")]
pub const RUDP_MSS_LOOPBACK: usize = 8000;
#[cfg(not(target_os = "macos"))]
pub const RUDP_MSS_LOOPBACK: usize = RUDP_MSS_CEIL;
/// 单个数据报缓冲上限（含头 + 长度字段；协商 mss 无论如何不超过它）。
pub const RUDP_DATAGRAM_MAX: usize = RUDP_HEADER_LEN + 2 + RUDP_MSS_CEIL;

pub const U_P_HS: u8 = 0x01;
/// C→S 握手：payload = [nonce 16B] 或协商版 [nonce 16B | mss u16 LE]（客户端
/// 载荷上限提案；旧服务端只认 16B——客户端重发窗口自动降级为 16B 兼容）。
pub const U_P_HS_ACK: u8 = 0x02;
/// S→C：payload = [nonce 16B]（回显）或 [nonce 16B | mss u16 LE]（采纳的 mss）。
pub const U_P_DATA: u8 = 0x03;
pub const U_P_ACK: u8 = 0x04;
/// payload = cum(u32) + n(u8) + n × [start(u32) len(u8)]
pub const U_P_FIN: u8 = 0x05;
/// payload = DATA 总数(u32)——期望收到的最后 seq = total-1。
pub const U_P_FIN_ACK: u8 = 0x06;
pub const U_P_RST: u8 = 0x07;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdtHeader {
    pub kind: u8,
    pub conn: u32,
    pub seq: u32,
}

impl UdtHeader {
    pub fn to_bytes(self) -> [u8; RUDP_HEADER_LEN] {
        let mut b = [0u8; RUDP_HEADER_LEN];
        b[..2].copy_from_slice(&RUDP_MAGIC);
        b[2] = crate::protocol::PROTO_VERSION;
        b[3] = self.kind;
        b[4..8].copy_from_slice(&self.conn.to_le_bytes());
        b[8..12].copy_from_slice(&self.seq.to_le_bytes());
        b
    }

    /// 解码一包公共头；magic/版本不符或长度不足 → None（fail-closed，调用方整包忽略）。
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < RUDP_HEADER_LEN || buf[..2] != RUDP_MAGIC {
            return None;
        }
        if buf[2] != crate::protocol::PROTO_VERSION {
            return None;
        }
        Some(Self {
            kind: buf[3],
            conn: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            seq: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        })
    }
}

/// 编码一包：头 + 载荷（载荷超协商上限为错误——fail-closed，调用方分片；
/// 连接内更紧的 per-conn mss 由引擎侧把关）。
pub fn encode(kind: u8, conn: u32, seq: u32, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > RUDP_MSS_CEIL {
        return Err(format!(
            "UDT 载荷超限: {} > {RUDP_MSS_CEIL}",
            payload.len()
        ));
    }
    let mut out = Vec::with_capacity(RUDP_HEADER_LEN + payload.len());
    out.extend_from_slice(&UdtHeader { kind, conn, seq }.to_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// 解码一包：返回 (头, 载荷)。payload_len 声明与实际不符 / 超绝对上限 → None。
/// （per-conn 协商 mss 的收紧校验在引擎 `on_data`——decode 无连接上下文。）
pub fn decode(buf: &[u8]) -> Option<(UdtHeader, &[u8])> {
    if buf.len() < RUDP_HEADER_LEN + 2 {
        return None;
    }
    let h = UdtHeader::from_bytes(buf)?;
    let plen = u16::from_le_bytes([buf[RUDP_HEADER_LEN], buf[RUDP_HEADER_LEN + 1]]) as usize;
    if plen > RUDP_MSS_CEIL || buf.len() != RUDP_HEADER_LEN + 2 + plen {
        return None;
    }
    Some((h, &buf[RUDP_HEADER_LEN + 2..]))
}

/// 从 HS 载荷提取协商 mss：16B = 旧版（无协商 → 默认 1200）；18B = 协商版。
/// 其他长度 → None（非法 HS）。
pub fn hs_mss(payload: &[u8]) -> Option<usize> {
    match payload.len() {
        16 => Some(RUDP_PAYLOAD_MAX),
        18 => {
            let m = u16::from_le_bytes([payload[16], payload[17]]) as usize;
            Some(m.min(RUDP_MSS_CEIL).max(RUDP_PAYLOAD_MAX))
        }
        _ => None,
    }
}

/// 从 HS_ACK 载荷提取协商结果：`propose` = 本端提案（钳制采纳值不超过提案）。
/// 返回 None = 不是合法 HS_ACK 载荷。
pub fn hs_ack_mss(payload: &[u8], nonce: &[u8], propose: usize) -> Option<usize> {
    match payload.len() {
        16 if payload == nonce => Some(RUDP_PAYLOAD_MAX), // 旧服务端
        18 if payload[..16] == *nonce => {
            let m = u16::from_le_bytes([payload[16], payload[17]]) as usize;
            Some(m.min(propose).min(RUDP_MSS_CEIL).max(RUDP_PAYLOAD_MAX))
        }
        _ => None,
    }
}

/// 编码 ACK 载荷：累积确认 + SACK 区间列表（每区间 [start u32][len u8]，≤64 区间）。
pub fn encode_ack_payload(cum: u32, sacks: &[(u32, u8)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + sacks.len() * 5);
    out.extend_from_slice(&cum.to_le_bytes());
    let n = sacks.len().min(64);
    out.push(n as u8);
    for (start, len) in sacks.iter().take(n) {
        out.extend_from_slice(&start.to_le_bytes());
        out.push(*len);
    }
    out
}

/// 解码 ACK 载荷 → (累积确认, SACK 区间列表)。
pub fn decode_ack_payload(payload: &[u8]) -> Option<(u32, Vec<(u32, u8)>)> {
    if payload.len() < 5 {
        return None;
    }
    let cum = u32::from_le_bytes(payload[..4].try_into().unwrap());
    let n = payload[4] as usize;
    if payload.len() < 5 + n * 5 {
        return None;
    }
    let mut sacks = Vec::with_capacity(n);
    for i in 0..n {
        let o = 5 + i * 5;
        sacks.push((
            u32::from_le_bytes(payload[o..o + 4].try_into().unwrap()),
            payload[o + 4],
        ));
    }
    Some((cum, sacks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_roundtrip() {
        let payload = [7u8; 100];
        let pkt = encode(U_P_DATA, 0xDEADBEEF, 42, &payload).unwrap();
        let (h, pl) = decode(&pkt).unwrap();
        assert_eq!(
            h,
            UdtHeader {
                kind: U_P_DATA,
                conn: 0xDEADBEEF,
                seq: 42
            }
        );
        assert_eq!(pl, &payload);
    }

    #[test]
    fn rejects_short_and_bad_magic_and_bad_len() {
        assert!(decode(&[0u8; 8]).is_none(), "短包");
        let mut pkt = encode(U_P_DATA, 1, 1, &[0u8; 10]).unwrap();
        pkt[0] = b'X'; // 破坏 magic
        assert!(decode(&pkt).is_none());
        let mut pkt2 = encode(U_P_DATA, 1, 1, &[0u8; 10]).unwrap();
        pkt2[RUDP_HEADER_LEN] = 99; // 声明长度与实际不符
        assert!(decode(&pkt2).is_none());
        let big = vec![0u8; RUDP_MSS_CEIL + 1];
        assert!(encode(U_P_DATA, 1, 1, &big).is_err(), "超限载荷编码即失败");
    }

    #[test]
    fn mss_negotiation_helpers() {
        let nonce = [9u8; 16];
        // 旧版 HS：16B → 默认 1200；协商版 18B → 采纳并钳制到 [1200, CEIL]。
        assert_eq!(hs_mss(&nonce), Some(RUDP_PAYLOAD_MAX));
        let mut hs = nonce.to_vec();
        hs.extend_from_slice(&60000u16.to_le_bytes());
        assert_eq!(hs_mss(&hs), Some(60000));
        // 超提案/超上限/低于默认的提案均被钳制。
        let mut hs2 = nonce.to_vec();
        hs2.extend_from_slice(&(RUDP_MSS_CEIL as u16 + 1).to_le_bytes());
        assert_eq!(hs_mss(&hs2), Some(RUDP_MSS_CEIL));
        assert!(hs_mss(&nonce[..10]).is_none(), "非 16/18B 载荷非法");
        // HS_ACK：16B 旧服务端 → 1200；18B → min(采纳, 提案)。
        let mut ack = nonce.to_vec();
        ack.extend_from_slice(&1400u16.to_le_bytes());
        assert_eq!(hs_ack_mss(&ack, &nonce, 1400), Some(1400));
        assert_eq!(hs_ack_mss(&ack, &nonce, 1300), Some(1300), "不得超本端提案");
        assert_eq!(
            hs_ack_mss(&nonce, &nonce, 1400),
            Some(1200),
            "16B 旧应答 → 默认 mss"
        );
        let mut bad = nonce.to_vec();
        bad[0] ^= 1;
        assert!(hs_ack_mss(&bad, &nonce, 1400).is_none(), "nonce 不符");
    }

    #[test]
    fn rejects_wrong_version() {
        let mut pkt = encode(U_P_DATA, 1, 1, b"").unwrap();
        pkt[2] = crate::protocol::PROTO_VERSION + 1;
        assert!(decode(&pkt).is_none());
    }

    #[test]
    fn ack_payload_roundtrip() {
        let sacks = vec![(5u32, 3u8), (20, 1)];
        let p = encode_ack_payload(4, &sacks);
        assert_eq!(decode_ack_payload(&p).unwrap(), (4, sacks));
        // 截断 → None
        assert!(decode_ack_payload(&p[..p.len() - 1]).is_none());
        assert!(decode_ack_payload(&p[..3]).is_none());
    }
}
