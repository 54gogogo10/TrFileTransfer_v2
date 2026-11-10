//! 配对码 KDF 与 HMAC / 恒时比较原语。

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub type HmacSha256 = Hmac<Sha256>;

/// 规格 §4.1/§6.1：PBKDF2-HMAC-SHA256，50,000 轮。
pub const PBKDF2_ROUNDS: u32 = 50_000;

/// 由配对码 + 盐派生 32 字节密钥。
pub fn derive_pairing_key(code: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(code.as_bytes(), salt, PBKDF2_ROUNDS, &mut out);
    out
}

/// 配对证明 = HMAC-SHA256(K, salt || 域分隔)。域分隔防跨协议重放。
pub fn pairing_proof(k: &[u8; 32], salt: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(salt.len() + 16);
    data.extend_from_slice(salt);
    data.extend_from_slice(b"trft-pair-v2");
    hmac_sha256(k, &data)
}

/// 通道绑定配对证明（M6'，QUIC 槽位）：HMAC(K, domain ‖ salt ‖ 服务器证书指纹)。
/// 指纹取「客户端实际所见服务器证书」——双臂中继两腿证书必然不同 → 证明必败；
/// 域分隔防与明文 0x05 证明交叉重放。
pub fn pairing_proof_bound(k: &[u8; 32], salt: &[u8], cert_fp: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(salt.len() + 64);
    data.extend_from_slice(b"trft-pair-bind-v1");
    data.extend_from_slice(salt);
    data.extend_from_slice(cert_fp);
    hmac_sha256(k, &data)
}

/// 服务端→客户端方向证明（轮 2 P1：0x0D 双向确认——服务端也证明自己持有码，
/// 封死「盲接受型假服务端」窃取；域分隔防与 C→S 证明交叉重放）。
pub fn pairing_proof_s2c(k: &[u8; 32], salt: &[u8], cert_fp: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(salt.len() + 64);
    data.extend_from_slice(b"trft-pair-bind-s2c-v1");
    data.extend_from_slice(salt);
    data.extend_from_slice(cert_fp);
    hmac_sha256(k, &data)
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// 恒时比较（规格 §4.1 0x05：恒时比较）。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        crate::hash::hex(b)
    }

    // PBKDF2-HMAC-SHA256 标准测试向量（公开向量集）。
    // 50k 轮无官方向量，用低轮数独立调用验证实现正确性。
    #[test]
    fn pbkdf2_known_vectors() {
        let mut out = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"password", b"salt", 1, &mut out);
        assert_eq!(
            hex(&out),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        pbkdf2::pbkdf2_hmac::<Sha256>(b"password", b"salt", 4096, &mut out);
        assert_eq!(
            hex(&out),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    #[test]
    fn pairing_proof_is_deterministic_and_key_dependent() {
        let k1 = derive_pairing_key("123456", b"saaaaaaaaaaaa");
        let k2 = derive_pairing_key("654321", b"saaaaaaaaaaaa");
        assert_ne!(
            pairing_proof(&k1, b"saaaaaaaaaaaa"),
            pairing_proof(&k2, b"saaaaaaaaaaaa")
        );
        assert_eq!(
            pairing_proof(&k1, b"saaaaaaaaaaaa"),
            pairing_proof(&k1, b"saaaaaaaaaaaa")
        );
    }

    /// M6'：绑定证明与明文证明域分隔；指纹/盐/密钥任一变化即变化。
    #[test]
    fn pairing_proof_bound_is_domain_separated() {
        let k = derive_pairing_key("123456", b"saaaaaaaaaaaa");
        let salt = b"saaaaaaaaaaaa";
        let fp_a = [1u8; 32];
        let fp_b = [2u8; 32];
        assert_ne!(
            pairing_proof_bound(&k, salt, &fp_a),
            pairing_proof(&k, salt),
            "域分隔"
        );
        assert_ne!(
            pairing_proof_bound(&k, salt, &fp_a),
            pairing_proof_bound(&k, salt, &fp_b)
        );
        assert_eq!(
            pairing_proof_bound(&k, salt, &fp_a),
            pairing_proof_bound(&k, salt, &fp_a)
        );
        let k2 = derive_pairing_key("654321", salt);
        assert_ne!(
            pairing_proof_bound(&k, salt, &fp_a),
            pairing_proof_bound(&k2, salt, &fp_a)
        );
        // S→C 方向证明与 C→S 域分隔。
        assert_ne!(
            pairing_proof_s2c(&k, salt, &fp_a),
            pairing_proof_bound(&k, salt, &fp_a)
        );
        assert_ne!(
            pairing_proof_s2c(&k, salt, &fp_a),
            pairing_proof_s2c(&k, salt, &fp_b)
        );
    }

    #[test]
    fn hmac_ct_eq() {
        let m = hmac_sha256(b"k", b"data");
        assert!(ct_eq(&m, &m));
        assert!(!ct_eq(&m, &[0u8; 32]));
        assert!(!ct_eq(&m, &m[..31]));
    }
}
