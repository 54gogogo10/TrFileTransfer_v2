//! UDT 传输包格式（UDP 之上的可靠有序字节流；WIRE-PROTOCOL.md「UDT 传输」节）。
//! 12 字节公共头（小端）：`magic "TU"(2B) | ver(1B) | type(1B) | conn_id(u32) | seq(u32) | payload_len(u16)`。
//!
//! 与单向 UDP（无回传链路）不同，UDT 是**双向可靠流**：DATA 靠 ACK/SACK 确认，
//! FIN/FIN_ACK 优雅收尾，RST 中止。seq 语义：DATA 包从 0 连续编号；ACK 携带
//! 「累积确认 = 期望的下一个 seq」+ SACK 区间；FIN 携带 DATA 总数（收满即回执）。

/// 公共头长度。
pub const UDT_HEADER_LEN: usize = 12;
/// magic（"TU"——TrFileTransfer UDT，与非 UDT 流量同端口的误收包过滤）。
pub const UDT_MAGIC: [u8; 2] = [b'T', b'U'];
/// 单包载荷上限：1200B（+ UDP/IP 头 <1280B，规避 IPv4/IPv6 分片与隧道黑洞）。
pub const UDT_PAYLOAD_MAX: usize = 1200;
/// 单个数据报上限（含头）。
pub const UDT_DATAGRAM_MAX: usize = UDT_HEADER_LEN + UDT_PAYLOAD_MAX;

pub const U_P_HS: u8 = 0x01;
/// C→S 握手：payload = [nonce 16B]（版本在公共头 ver）。
pub const U_P_HS_ACK: u8 = 0x02;
/// S→C：payload = [nonce 16B]（回显）。
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
    pub fn to_bytes(self) -> [u8; UDT_HEADER_LEN] {
        let mut b = [0u8; UDT_HEADER_LEN];
        b[..2].copy_from_slice(&UDT_MAGIC);
        b[2] = crate::protocol::PROTO_VERSION;
        b[3] = self.kind;
        b[4..8].copy_from_slice(&self.conn.to_le_bytes());
        b[8..12].copy_from_slice(&self.seq.to_le_bytes());
        b
    }

    /// 解码一包公共头；magic/版本不符或长度不足 → None（fail-closed，调用方整包忽略）。
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < UDT_HEADER_LEN || buf[..2] != UDT_MAGIC {
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

/// 编码一包：头 + 载荷（载荷超上限截断为错误——fail-closed，调用方分片）。
pub fn encode(kind: u8, conn: u32, seq: u32, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > UDT_PAYLOAD_MAX {
        return Err(format!(
            "UDT 载荷超限: {} > {UDT_PAYLOAD_MAX}",
            payload.len()
        ));
    }
    let mut out = Vec::with_capacity(UDT_HEADER_LEN + payload.len());
    out.extend_from_slice(&UdtHeader { kind, conn, seq }.to_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// 解码一包：返回 (头, 载荷)。payload_len 声明与实际不符 / 超上限 → None。
pub fn decode(buf: &[u8]) -> Option<(UdtHeader, &[u8])> {
    if buf.len() < UDT_HEADER_LEN + 2 {
        return None;
    }
    let h = UdtHeader::from_bytes(buf)?;
    let plen = u16::from_le_bytes([buf[UDT_HEADER_LEN], buf[UDT_HEADER_LEN + 1]]) as usize;
    if plen > UDT_PAYLOAD_MAX || buf.len() != UDT_HEADER_LEN + 2 + plen {
        return None;
    }
    Some((h, &buf[UDT_HEADER_LEN + 2..]))
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
        pkt2[UDT_HEADER_LEN] = 99; // 声明长度与实际不符
        assert!(decode(&pkt2).is_none());
        let big = vec![0u8; UDT_PAYLOAD_MAX + 1];
        assert!(encode(U_P_DATA, 1, 1, &big).is_err(), "超限载荷编码即失败");
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
