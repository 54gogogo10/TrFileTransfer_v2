//! 单向 UDP 帧：20 字节公共头（规格 §4.2），无回传链路、落盘即状态。
//! 布局: [0]=版本 [1]=帧类型 [2..10]=会话ID(LE) [10..18]=序号(LE) [18..20]=保留。

use crate::error::{Result, proto};
use crate::hash::sha256;

pub const UDP_HEADER_LEN: usize = 20;
pub const U_F_START: u8 = 0x01;
pub const U_F_DATA: u8 = 0x02;
pub const U_F_END: u8 = 0x03;
pub const U_F_PARITY: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    pub frame: u8,
    pub session: u64,
    pub seq: u64,
}

impl UdpHeader {
    pub fn to_bytes(self) -> [u8; UDP_HEADER_LEN] {
        let mut b = [0u8; UDP_HEADER_LEN];
        b[0] = crate::protocol::PROTO_VERSION;
        b[1] = self.frame;
        b[2..10].copy_from_slice(&self.session.to_le_bytes());
        b[10..18].copy_from_slice(&self.seq.to_le_bytes());
        b
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < UDP_HEADER_LEN {
            return Err(proto("UDP 包短于 20 字节公共头"));
        }
        if buf[0] != crate::protocol::PROTO_VERSION {
            return Err(proto(format!("未知协议版本 0x{:02X}", buf[0])));
        }
        Ok(Self {
            frame: buf[1],
            session: u64::from_le_bytes(buf[2..10].try_into().unwrap()),
            seq: u64::from_le_bytes(buf[10..18].try_into().unwrap()),
        })
    }
}

/// 会话 ID 由 (文件名, 大小, mtime) 确定性派生——重发即重试，接收方跨重启续收（规格 §4.2）。
pub fn session_id(name: &str, size: u64, mtime_secs: u64) -> u64 {
    let mut material = Vec::with_capacity(name.len() + 16);
    material.extend_from_slice(name.as_bytes());
    material.extend_from_slice(&size.to_le_bytes());
    material.extend_from_slice(&mtime_secs.to_le_bytes());
    let h = sha256(&material);
    u64::from_le_bytes(h[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = UdpHeader { frame: U_F_DATA, session: 0x1122334455667788, seq: 42 };
        let b = h.to_bytes();
        assert_eq!(b.len(), 20);
        assert_eq!(UdpHeader::from_bytes(&b).unwrap(), h);
    }

    #[test]
    fn rejects_wrong_version_and_short() {
        let mut b = UdpHeader { frame: U_F_START, session: 1, seq: 1 }.to_bytes();
        b[0] = 9;
        assert!(UdpHeader::from_bytes(&b).is_err());
        assert!(UdpHeader::from_bytes(&b[..10]).is_err());
    }

    #[test]
    fn session_id_is_deterministic() {
        let a = session_id("照片.jpg", 12345, 1_700_000_000);
        let b = session_id("照片.jpg", 12345, 1_700_000_000);
        let c = session_id("照片.jpg", 12346, 1_700_000_000);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
