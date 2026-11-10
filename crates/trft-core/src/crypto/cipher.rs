//! 段加密器：AES-256-CTR + 截断 HMAC（16B）+ 段序绑定。
//! 规格 §5.1：等长段重排/交换立即校验失败 → tag 输入绑定 seq。

use crate::error::{crypto, Result};
use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use generic_array::GenericArray;
use hmac::Mac;
use rand_core::{OsRng, RngCore};

pub const IV_LEN: usize = 16;
pub const SEGMENT_MAC_LEN: usize = 16;
const SEAL_OVERHEAD: usize = IV_LEN + SEGMENT_MAC_LEN;

pub struct SegmentCipher {
    aes_key: [u8; 32],
    mac_key: [u8; 32],
}

impl SegmentCipher {
    pub fn new(aes_key: [u8; 32], mac_key: [u8; 32]) -> Self {
        Self { aes_key, mac_key }
    }

    /// 加密一段：返回 iv(16) || ct || tag(16)。
    pub fn seal(&self, seq: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut iv = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv);
        let mut ct = plaintext.to_vec();
        Self::crypt(&self.aes_key, &iv, &mut ct);
        let tag = self.tag(seq, &iv, &ct);
        let mut out = Vec::with_capacity(SEAL_OVERHEAD + ct.len());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// 解密一段；HMAC 先行恒时校验，篡改/乱序/截断一律失败。
    pub fn open(&self, seq: u64, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < SEAL_OVERHEAD {
            return Err(crypto("密文段过短"));
        }
        let iv: [u8; IV_LEN] = sealed[..IV_LEN].try_into().unwrap();
        let ct = &sealed[IV_LEN..sealed.len() - SEGMENT_MAC_LEN];
        let tag = &sealed[sealed.len() - SEGMENT_MAC_LEN..];
        let expect = self.tag(seq, &iv, ct);
        if !crate::crypto::kdf::ct_eq(tag, &expect) {
            return Err(crypto("HMAC 校验失败（篡改、截断或段序错乱）"));
        }
        let mut pt = ct.to_vec();
        Self::crypt(&self.aes_key, &iv, &mut pt);
        Ok(pt)
    }

    fn crypt(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
        let mut c =
            Ctr128BE::<Aes256>::new(GenericArray::from_slice(key), GenericArray::from_slice(iv));
        c.apply_keystream(data);
    }

    fn tag(&self, seq: u64, iv: &[u8], ct: &[u8]) -> [u8; SEGMENT_MAC_LEN] {
        let mut mac = <crate::crypto::kdf::HmacSha256 as hmac::Mac>::new_from_slice(&self.mac_key)
            .expect("HMAC 接受任意长度密钥");
        mac.update(&seq.to_le_bytes());
        mac.update(iv);
        mac.update(ct);
        let t = mac.finalize().into_bytes();
        let mut out = [0u8; SEGMENT_MAC_LEN];
        out.copy_from_slice(&t[..SEGMENT_MAC_LEN]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> SegmentCipher {
        SegmentCipher::new([7u8; 32], [9u8; 32])
    }

    #[test]
    fn roundtrip() {
        let c = cipher();
        let msg = "你好, TrFileTransfer!".as_bytes();
        let sealed = c.seal(1, msg).unwrap();
        assert_eq!(c.open(1, &sealed).unwrap(), msg);
    }

    #[test]
    fn empty_segment_roundtrip() {
        let c = cipher();
        let sealed = c.seal(5, b"").unwrap();
        assert_eq!(c.open(5, &sealed).unwrap(), b"");
    }

    #[test]
    fn tamper_detected() {
        let c = cipher();
        let mut sealed = c.seal(1, b"payload").unwrap();
        sealed[IV_LEN] ^= 1;
        assert!(c.open(1, &sealed).is_err());
    }

    #[test]
    fn sequence_reorder_detected() {
        let c = cipher();
        let sealed_a = c.seal(1, b"aaaa").unwrap();
        let sealed_b = c.seal(2, b"bbbb").unwrap();
        // 等长段交换后 seq 绑定校验必然失败。
        assert!(c.open(2, &sealed_a).is_err());
        assert!(c.open(1, &sealed_b).is_err());
    }

    #[test]
    fn truncation_detected() {
        let c = cipher();
        let sealed = c.seal(1, b"payload").unwrap();
        assert!(c.open(1, &sealed[..sealed.len() - 1]).is_err());
    }
}
