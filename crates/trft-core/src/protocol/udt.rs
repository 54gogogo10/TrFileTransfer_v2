//! UDT4 传输线格式（UDT 槽位；WIRE-PROTOCOL.md「UDT4 传输」节）。
//!
//! 与本仓库自研 RUDP（`protocol::rudp`）完全独立的**另一套** UDP 可靠流：本模块逐字节
//! 复刻原 C# 版内嵌的 libudt 4.x（`D:\zcode\TrFileTransfer\udt-sdk\udt4\src`）线上格式，
//! 用于与其 UDT 槽位（`udt.dll` P/Invoke，SOCK_STREAM 字节流）互通——这是全仓库唯一
//! 承诺外部互通的传输（PRODUCT-SPEC §4.3）。
//!
//! 线上布局（`packet.h`/`channel.cpp`，头与控制载荷一律**大端**，数据载荷原样字节）：
//! ```text
//! 数据包: [0] = 0|seq(31bit)   [1] = ff|o|msgno(29bit)   [2] = timestamp(µs)   [3] = dst socket id
//! 控制包: [0] = 1|type(15bit)|extended(16bit) [1] = add.info  [2] = timestamp(µs)  [3] = dst socket id
//! ```
//! 握手（type 0）载荷 = CHandShake 48B = 12 个 i32 大端字（version/type/ISN/MSS/流窗/
//! req_type/id/cookie/peer_ip[4]）。ACK 载荷 = `[cum, rtt, rttvar, buf, (speed, bw)]`；
//! NAK 载荷 = 损失列表（单包 1 字，区间首字高位 1）。seq 空间 0..=0x7FFFFFFF 回绕。

/// 公共头长度（`CPacket::m_iPktHdrSize`）。
pub const UDT_HEADER_LEN: usize = 16;
/// 握手载荷长度（`CHandShake::m_iContentSize`）。
pub const UDT_HANDSHAKE_SIZE: usize = 48;
/// 默认 MSS（`core.cpp` `m_iMSS = 1500`；`m_iPktSize = MSS - 28`）。
pub const UDT_MSS: i32 = 1500;
/// 单包 UDP 载荷上限（= MSS − IP/UDP 头 28B）。
pub const UDT_PKT_SIZE: usize = (UDT_MSS as usize) - 28;
/// 单包数据载荷上限（= 包大小 − UDT 头 16B；libudt `m_iPayloadSize`）。
pub const UDT_PAYLOAD_MAX: usize = UDT_PKT_SIZE - UDT_HEADER_LEN;
/// 单个数据报上限（含头）。
pub const UDT_DGRAM_MAX: usize = UDT_PKT_SIZE;

/// UDT 协议版本（libudt 4.x）。
pub const UDT_VERSION: i32 = 4;
/// SOCK_STREAM（字节流模式——C# 侧唯一使用的模式）。
pub const UDT_SOCK_STREAM: i32 = 1;
/// 默认流窗（`m_iFlightFlagSize = 25600`）。
pub const UDT_FLIGHT_FLAG: i32 = 25600;
/// 默认收缓冲包数（`m_iRcvBufSize = 8192`；握手通告取 min(收缓冲, 流窗)）。
pub const UDT_RCV_BUF_PKTS: i32 = 8192;

pub const C_HANDSHAKE: u16 = 0;
pub const C_KEEPALIVE: u16 = 1;
pub const C_ACK: u16 = 2;
pub const C_NAK: u16 = 3;
pub const C_WARN: u16 = 4;
pub const C_SHUTDOWN: u16 = 5;
pub const C_ACK2: u16 = 6;
pub const C_DROP: u16 = 7;
pub const C_PEER_ERROR: u16 = 8;

/// 握手 req_type：1 = 请求（阶段一）、-1 = 响应/携带 cookie 的二次请求、-2 = rendezvous、
/// 1002 = 拒绝（版本/类型不符或服务端拒绝）。
pub const HS_REQ: i32 = 1;
pub const HS_RESP: i32 = -1;
pub const HS_REJECT: i32 = 1002;

/// seq 上限（`CSeqNo::m_iMaxSeqNo`；seq 空间 0..=MAX 回绕）。
pub const MAX_SEQ: i32 = 0x7FFF_FFFF;
/// seq 比较阈值（`m_iSeqNoTH`）。
const SEQ_TH: i64 = 0x3FFF_FFFF;
/// ACK 子序列号上限（`CAckNo::m_iMaxAckSeqNo`）。
pub const MAX_ACK: i32 = 0x7FFF_FFFF;
/// SYN 周期（`CUDT::m_iSYNInterval` µs = 10ms；ACK/NAK/EXP 计时基准）。
pub const SYN_US: u64 = 10_000;
/// light ACK 包数间隔（`m_iSelfClockInterval = 64`）。
pub const LIGHT_ACK_PKTS: i32 = 64;
/// msgNo 字段：边界位 11（solo，流模式接收端不解析 msgNo）。
pub const MSG_SOLO: u32 = 0xC000_0000;

/* ============ seq / ack 算术（libudt CSeqNo/CAckNo 语义） ============ */

/// `CSeqNo::seqcmp`：<0 / =0 / >0 表示 a 相对 b 的先后（回绕安全）。
pub fn seq_cmp(a: i32, b: i32) -> i32 {
    let d = (a as i64 - b as i64).abs();
    if d < SEQ_TH {
        a.wrapping_sub(b)
    } else {
        b.wrapping_sub(a)
    }
}

/// `CSeqNo::seqoff`：b 相对 a 的偏移量（回绕安全，可为负）。
pub fn seq_off(a: i32, b: i32) -> i32 {
    let d = (a as i64 - b as i64).abs();
    if d < SEQ_TH {
        b.wrapping_sub(a)
    } else if a < b {
        (b as i64 - a as i64 - MAX_SEQ as i64 - 1) as i32
    } else {
        (b as i64 - a as i64 + MAX_SEQ as i64 + 1) as i32
    }
}

/// `CSeqNo::seqlen`：a..=b 的含端长度。
pub fn seq_len(a: i32, b: i32) -> i32 {
    if a <= b {
        b - a + 1
    } else {
        b - a + MAX_SEQ + 2
    }
}

/// `CSeqNo::incseq`。
pub fn seq_inc(seq: i32) -> i32 {
    if seq == MAX_SEQ {
        0
    } else {
        seq + 1
    }
}

/// `CSeqNo::decseq`。
pub fn seq_dec(seq: i32) -> i32 {
    if seq == 0 {
        MAX_SEQ
    } else {
        seq - 1
    }
}

/// `CAckNo::incack`：ACK 子序列号 +1（0x7FFFFFFF 回绕到 0）。
pub fn ack_inc(ack: i32) -> i32 {
    if ack == MAX_ACK {
        0
    } else {
        ack + 1
    }
}

/* ============ 包编解码 ============ */

/// 解码后的一个 UDP 数据报。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pkt {
    /// 数据包（载荷原样字节；msg_no 含边界位）。
    Data {
        seq: i32,
        msg_no: u32,
        ts: u32,
        dst: u32,
        payload: Vec<u8>,
    },
    /// 控制包（载荷为大端 u32 字数组；`ext` 为 bit16..31 扩展类型）。
    Ctrl {
        ctype: u16,
        ext: u16,
        add: i32,
        ts: u32,
        dst: u32,
        words: Vec<u32>,
    },
}

impl Pkt {
    pub fn dst(&self) -> u32 {
        match self {
            Pkt::Data { dst, .. } => *dst,
            Pkt::Ctrl { dst, .. } => *dst,
        }
    }

    pub fn ts(&self) -> u32 {
        match self {
            Pkt::Data { ts, .. } => *ts,
            Pkt::Ctrl { ts, .. } => *ts,
        }
    }
}

/// 编码数据包（载荷超上限截断为错误——调用方负责分片到 ≤ `UDT_PAYLOAD_MAX`）。
pub fn encode_data(seq: i32, msg_no: u32, ts: u32, dst: u32, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > UDT_PAYLOAD_MAX {
        return Err(format!("UDT 数据载荷超限: {} > {UDT_PAYLOAD_MAX}", payload.len()));
    }
    let mut out = Vec::with_capacity(UDT_HEADER_LEN + payload.len());
    // 头一律大端（channel.cpp sendto 对 4 个头字 htonl）。
    out.extend_from_slice(&((seq as u32) & 0x7FFF_FFFF).to_be_bytes());
    out.extend_from_slice(&msg_no.to_be_bytes());
    out.extend_from_slice(&ts.to_be_bytes());
    out.extend_from_slice(&dst.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// 编码控制包（`words` 逐字大端；无载荷传空片——libudt 以 4 字节 pad 占位，长度不影响语义）。
pub fn encode_ctrl(ctype: u16, add: i32, ts: u32, dst: u32, words: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(UDT_HEADER_LEN + words.len() * 4);
    out.extend_from_slice(&(0x8000_0000u32 | ((ctype as u32) << 16)).to_be_bytes());
    out.extend_from_slice(&(add as u32).to_be_bytes());
    out.extend_from_slice(&ts.to_be_bytes());
    out.extend_from_slice(&dst.to_be_bytes());
    for w in words {
        out.extend_from_slice(&w.to_be_bytes());
    }
    out
}

/// 原地重写数据包 ts 字（头 word2，大端）——重传复用已编码包零再编码
/// （libudt packData 每次取包即刷新 ts，core.cpp 同语义）。
pub fn rewrite_ts(pkt: &mut [u8], ts: u32) {
    if pkt.len() >= 12 {
        pkt[8..12].copy_from_slice(&ts.to_be_bytes());
    }
}

/// 解码一个数据报；长度不足 16B / 数据载荷超限 → None（fail-closed 整包忽略）。
pub fn decode(buf: &[u8]) -> Option<Pkt> {
    if buf.len() < UDT_HEADER_LEN {
        return None;
    }
    let h = [
        u32::from_be_bytes(buf[0..4].try_into().ok()?),
        u32::from_be_bytes(buf[4..8].try_into().ok()?),
        u32::from_be_bytes(buf[8..12].try_into().ok()?),
        u32::from_be_bytes(buf[12..16].try_into().ok()?),
    ];
    let body = &buf[UDT_HEADER_LEN..];
    if h[0] & 0x8000_0000 != 0 {
        // 控制包：载荷按 4 字节字对齐（channel.cpp 按 getLength()/4 转换）。
        let n = body.len() / 4;
        let mut words = Vec::with_capacity(n);
        for i in 0..n {
            words.push(u32::from_be_bytes(body[i * 4..i * 4 + 4].try_into().ok()?));
        }
        Some(Pkt::Ctrl {
            ctype: ((h[0] >> 16) & 0x7FFF) as u16,
            ext: (h[0] & 0xFFFF) as u16,
            add: h[1] as i32,
            ts: h[2],
            dst: h[3],
            words,
        })
    } else {
        if body.len() > UDT_PAYLOAD_MAX {
            return None;
        }
        Some(Pkt::Data {
            seq: (h[0] & 0x7FFF_FFFF) as i32,
            msg_no: h[1],
            ts: h[2],
            dst: h[3],
            payload: body.to_vec(),
        })
    }
}

/* ============ 握手（CHandShake，48B = 12 个大端 i32） ============ */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Handshake {
    pub version: i32,
    pub sock_type: i32,
    pub isn: i32,
    pub mss: i32,
    pub flight_flag: i32,
    pub req_type: i32,
    pub id: i32,
    pub cookie: i32,
    /// 对端 UDP 地址（IPv4 用 word0；libudt CIPAddress::ntop 填充，回显用途）。
    pub peer_ip: [u32; 4],
}

impl Handshake {
    pub fn to_words(self) -> [u32; 12] {
        [
            self.version as u32,
            self.sock_type as u32,
            self.isn as u32,
            self.mss as u32,
            self.flight_flag as u32,
            self.req_type as u32,
            self.id as u32,
            self.cookie as u32,
            self.peer_ip[0],
            self.peer_ip[1],
            self.peer_ip[2],
            self.peer_ip[3],
        ]
    }

    /// 解码握手载荷；字数不足 12 → None（fail-closed）。
    pub fn from_words(words: &[u32]) -> Option<Self> {
        if words.len() < 12 {
            return None;
        }
        Some(Self {
            version: words[0] as i32,
            sock_type: words[1] as i32,
            isn: words[2] as i32,
            mss: words[3] as i32,
            flight_flag: words[4] as i32,
            req_type: words[5] as i32,
            id: words[6] as i32,
            cookie: words[7] as i32,
            peer_ip: [words[8], words[9], words[10], words[11]],
        })
    }

    pub fn encode_ctrl(self, ts: u32, dst: u32) -> Vec<u8> {
        encode_ctrl(C_HANDSHAKE, 0, ts, dst, &self.to_words())
    }
}

/* ============ NAK 损失列表编解码 ============ */

/// 编码 NAK 载荷：连续区间 [a..=b] 编码为 `(a | 0x80000000, b)` 两字，单包 1 字。
/// 区间数超出载荷上限时截断（调用方按周期再报）。
pub fn encode_loss(loss: &[i32]) -> Vec<u32> {
    // 输入须升序（调用方 BTreeSet/BTreeMap 产出）；合并连续段。
    // ≥2 包一律两字区间编码（对齐 libudt core.cpp:2424-2428 的 NAK 形态；
    // 单字与区间两种编码对端解码器均兼容——性能批 2026-11-14 逐字节保真对齐）。
    let mut out = Vec::new();
    let mut i = 0;
    while i < loss.len() {
        let start = loss[i];
        let mut end = start;
        while i + 1 < loss.len() && seq_off(end, loss[i + 1]) == 1 {
            i += 1;
            end = loss[i];
        }
        if end == start {
            out.push(start as u32);
        } else {
            out.push((start as u32) | 0x8000_0000);
            out.push(end as u32);
        }
        i += 1;
    }
    out
}

/// 解码 NAK 载荷 → 升序损失 seq 列表；非法区间（a>b / 超 0x7FFFFFFF）或展开规模超限
/// 整包拒绝 → None（fail-closed：伪造的巨型区间不得变成内存炸弹——流窗上限 25600，
/// 合理损失列表远小于此）。
pub const LOSS_DECODE_CAP: usize = 1 << 20;

pub fn decode_loss(words: &[u32]) -> Option<Vec<i32>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let w = words[i];
        if w & 0x8000_0000 != 0 {
            if i + 1 >= words.len() {
                return None;
            }
            let a = (w & 0x7FFF_FFFF) as i32;
            let b = words[i + 1] as i32;
            if seq_cmp(a, b) > 0 || b as u32 > MAX_SEQ as u32 {
                return None;
            }
            let n = seq_len(a, b);
            if n <= 0 || out.len() + n as usize > LOSS_DECODE_CAP {
                return None;
            }
            let mut s = a;
            for _ in 0..n {
                out.push(s);
                s = seq_inc(s);
            }
            i += 2;
        } else {
            out.push(w as i32);
            i += 1;
        }
    }
    Some(out)
}

/* ============ ACK 载荷 ============ */

/// ACK 载荷字数：轻量 ACK 1（仅 cum）；完整 ACK 4（cum/rtt/rttvar/buf）或 6（+speed/bw）。
pub const ACK_WORDS_FULL: usize = 4;
pub const ACK_WORDS_EXT: usize = 6;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_arithmetic_matches_libudt() {
        // 常规区间
        assert_eq!(seq_cmp(5, 7), -2);
        assert_eq!(seq_cmp(7, 5), 2);
        assert_eq!(seq_cmp(100, 100), 0);
        assert_eq!(seq_off(5, 7), 2);
        assert_eq!(seq_off(7, 5), -2);
        assert_eq!(seq_len(5, 7), 3);
        // 回绕：MAX → 0
        assert_eq!(seq_inc(MAX_SEQ), 0);
        assert_eq!(seq_dec(0), MAX_SEQ);
        assert_eq!(seq_off(MAX_SEQ, 0), 1);
        assert_eq!(seq_off(0, MAX_SEQ), -1);
        assert!(seq_cmp(MAX_SEQ, 0) < 0, "MAX 之后是 0（符号语义，幅值不作数）");
        assert!(seq_cmp(0, MAX_SEQ) > 0);
        assert_eq!(seq_len(MAX_SEQ, 1), 3, "MAX、0、1 三个 seq");
        assert_eq!(seq_off(MAX_SEQ, 3), 4, "MAX→0→1→2→3 前向距离 4");
        // 阈值边界（半周期歧义点，与 libudt C 代码逐位一致——符号即语义，幅值不作数）：
        let far = (SEQ_TH + 1) as i32; // 0x40000000
        assert_eq!(
            seq_off(0, far),
            -1073741824,
            "远分支：C 里 seq2-seq1-MAX-1 = -0x40000000（回绕向后的等距表述）"
        );
        assert!(seq_cmp(MAX_SEQ, 0) < 0, "远分支符号仍正确：MAX 先于 0");
        assert!(seq_cmp(0, MAX_SEQ) > 0, "远分支符号仍正确：0 后于 MAX");
        assert_eq!(ack_inc(MAX_ACK), 0);
        assert_eq!(ack_inc(0), 1);
    }

    #[test]
    fn data_packet_roundtrip() {
        let payload = vec![7u8; 100];
        let pkt = encode_data(42, MSG_SOLO | 1, 12345, 0xDEAD_BEEF, &payload).unwrap();
        match decode(&pkt).unwrap() {
            Pkt::Data {
                seq,
                msg_no,
                ts,
                dst,
                payload: p,
            } => {
                assert_eq!(seq, 42);
                assert_eq!(msg_no, MSG_SOLO | 1);
                assert_eq!(ts, 12345);
                assert_eq!(dst, 0xDEAD_BEEF);
                assert_eq!(p, payload);
            }
            other => panic!("应为数据包: {other:?}"),
        }
    }

    #[test]
    fn rejects_oversize_and_short() {
        let big = vec![0u8; UDT_PAYLOAD_MAX + 1];
        assert!(encode_data(1, 0, 0, 0, &big).is_err(), "超限编码即失败");
        assert!(decode(&[0u8; 8]).is_none(), "短包");
        let mut pkt = encode_data(1, 0, 0, 0, &[0u8; 10]).unwrap();
        pkt[0] = 0x80; // 数据包位被破坏成超限控制——仍可解码为控制
        assert!(decode(&pkt).is_some());
        // 数据载荷超上限（伪造成大包）→ None
        let oversized = vec![0u8; UDT_HEADER_LEN + UDT_PAYLOAD_MAX + 1];
        assert!(decode(&oversized).is_none());
    }

    #[test]
    fn ctrl_packet_roundtrip() {
        let words = [1u32, 2, 3, 0xFFFF_8000];
        let pkt = encode_ctrl(C_ACK, 7, 99, 0xABCD, &words);
        match decode(&pkt).unwrap() {
            Pkt::Ctrl {
                ctype,
                ext,
                add,
                ts,
                dst,
                words: w,
            } => {
                assert_eq!(ctype, C_ACK);
                assert_eq!(ext, 0);
                assert_eq!(add, 7);
                assert_eq!(ts, 99);
                assert_eq!(dst, 0xABCD);
                assert_eq!(w, words);
            }
            other => panic!("应为控制包: {other:?}"),
        }
    }

    #[test]
    fn handshake_roundtrip() {
        let hs = Handshake {
            version: UDT_VERSION,
            sock_type: UDT_SOCK_STREAM,
            isn: 123456789,
            mss: UDT_MSS,
            flight_flag: UDT_RCV_BUF_PKTS,
            req_type: HS_REQ,
            id: 0x1122_3344,
            cookie: -1,
            peer_ip: [0x0A00_0001, 0, 0, 0],
        };
        let pkt = hs.encode_ctrl(0, 0);
        assert_eq!(pkt.len(), UDT_HEADER_LEN + UDT_HANDSHAKE_SIZE);
        match decode(&pkt).unwrap() {
            Pkt::Ctrl { words, dst, .. } => {
                assert_eq!(dst, 0);
                assert_eq!(Handshake::from_words(&words).unwrap(), hs);
            }
            other => panic!("应为握手控制包: {other:?}"),
        }
        // 字数不足 → None
        assert!(Handshake::from_words(&[0u32; 11]).is_none());
        // 负数 cookie 的 i32 往返
        assert_eq!(Handshake::from_words(&hs.to_words()).unwrap().cookie, -1);
    }

    #[test]
    fn loss_codec_roundtrip_and_ranges() {
        // 单包损失
        assert_eq!(encode_loss(&[5]), vec![5]);
        assert_eq!(decode_loss(&encode_loss(&[5])).unwrap(), vec![5]);
        // 相邻两包：区间两字编码（对齐 libudt core.cpp:2424-2428——性能批修订）
        assert_eq!(encode_loss(&[5, 6]), vec![(5u32) | 0x8000_0000, 6]);
        assert_eq!(decode_loss(&encode_loss(&[5, 6])).unwrap(), vec![5, 6]);
        // 长区间：两字 + 高位标记
        let long: Vec<i32> = (10..=20).collect();
        let enc = encode_loss(&long);
        assert_eq!(enc.len(), 2);
        assert_eq!(enc[0], (10u32) | 0x8000_0000);
        assert_eq!(enc[1], 20);
        assert_eq!(decode_loss(&enc).unwrap(), long);
        // 混合：单 + 长区间
        let mixed: Vec<i32> = [3]
            .into_iter()
            .chain((100..=300).collect::<Vec<i32>>())
            .chain([500].into_iter())
            .collect();
        let dec = decode_loss(&encode_loss(&mixed)).unwrap();
        assert_eq!(dec, mixed);
        // 回绕区间
        let wrap: Vec<i32> = [MAX_SEQ, 0, 1].to_vec();
        let dec = decode_loss(&encode_loss(&wrap)).unwrap();
        assert_eq!(dec, wrap);
        // 非法：区间字缺第二字
        assert!(decode_loss(&[0x8000_0005]).is_none());
        // 非法：a > b
        assert!(decode_loss(&[0x8000_0005, 3]).is_none());
    }
}
