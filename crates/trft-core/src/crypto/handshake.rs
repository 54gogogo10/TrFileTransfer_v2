//! ECDH 认证握手（规格 §4.1 0x09 / §5.1）：临时 P-256，会话密钥只来自共享秘密 Z，
//! HKDF 按 c2s/s2c 方向分离派生（防反射）。本模块提供可测试的密钥派生原语，
//! 线上编排在传输里程碑接入。

use crate::crypto::cipher::SegmentCipher;
use crate::error::{Result, crypto};
use crate::hash::sha256;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use rand_core::OsRng;
use sha2::Sha256;

/// 会话密钥对：c2s / s2c 方向分离，防反射攻击；conf = 通道内双向确认密钥。
pub struct SessionKeys {
    pub c2s: SegmentCipher,
    pub s2c: SegmentCipher,
    pub c2s_conf: [u8; 32],
    pub s2c_conf: [u8; 32],
}

impl SessionKeys {
    pub fn client_view(&self) -> (&SegmentCipher, &SegmentCipher) {
        (&self.c2s, &self.s2c)
    }

    pub fn server_view(&self) -> (&SegmentCipher, &SegmentCipher) {
        (&self.s2c, &self.c2s)
    }
}

/// 一次未完成的握手：持有己方临时私钥与公钥（SEC1 未压缩 65 字节）。
pub struct Handshake {
    secret: EphemeralSecret,
    my_pub: Vec<u8>,
}

pub fn new_handshake() -> Result<Handshake> {
    let secret = EphemeralSecret::random(&mut OsRng);
    let my_pub = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
    Ok(Handshake { secret, my_pub })
}

impl Handshake {
    pub fn public(&self) -> &[u8] {
        &self.my_pub
    }

    /// 客户端收尾：输入服务端公钥，得到会话密钥。
    pub fn finish_client(self, server_pub: &[u8]) -> Result<SessionKeys> {
        let my = self.my_pub.clone();
        let peer = parse_pub(server_pub)?;
        let z = self.secret.diffie_hellman(&peer);
        derive_session(z.raw_secret_bytes().as_slice(), &my, server_pub)
    }

    /// 服务端收尾：输入客户端公钥，得到会话密钥。
    pub fn finish_server(self, client_pub: &[u8]) -> Result<SessionKeys> {
        let my = self.my_pub.clone();
        let peer = parse_pub(client_pub)?;
        let z = self.secret.diffie_hellman(&peer);
        derive_session(z.raw_secret_bytes().as_slice(), client_pub, &my)
    }
}

fn parse_pub(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(bytes).map_err(|_| crypto("对端公钥非法（SEC1 解析失败）"))
}

fn derive_session(z: &[u8], client_pub: &[u8], server_pub: &[u8]) -> Result<SessionKeys> {
    // 盐绑定双方公钥：把身份钉进密钥材料。
    let mut salt_material = Vec::with_capacity(client_pub.len() + server_pub.len());
    salt_material.extend_from_slice(client_pub);
    salt_material.extend_from_slice(server_pub);
    let hk = Hkdf::<Sha256>::new(Some(&sha256(&salt_material)), z);
    let mut ka = [0u8; 32];
    let mut kma = [0u8; 32];
    let mut kb = [0u8; 32];
    let mut kmb = [0u8; 32];
    let mut kca = [0u8; 32];
    let mut kcb = [0u8; 32];
    hk.expand(b"trft-v2 c2s aes", &mut ka).map_err(|e| crypto(e.to_string()))?;
    hk.expand(b"trft-v2 c2s mac", &mut kma).map_err(|e| crypto(e.to_string()))?;
    hk.expand(b"trft-v2 s2c aes", &mut kb).map_err(|e| crypto(e.to_string()))?;
    hk.expand(b"trft-v2 s2c mac", &mut kmb).map_err(|e| crypto(e.to_string()))?;
    hk.expand(b"trft-v2 c2s conf", &mut kca).map_err(|e| crypto(e.to_string()))?;
    hk.expand(b"trft-v2 s2c conf", &mut kcb).map_err(|e| crypto(e.to_string()))?;
    Ok(SessionKeys {
        c2s: SegmentCipher::new(ka, kma),
        s2c: SegmentCipher::new(kb, kmb),
        c2s_conf: kca,
        s2c_conf: kcb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_same_keys() {
        let a = new_handshake().unwrap();
        let b = new_handshake().unwrap();
        let ap = a.public().to_vec();
        let bp = b.public().to_vec();
        let ka = a.finish_client(&bp).unwrap();
        let kb = b.finish_server(&ap).unwrap();
        // 客户端用 c2s 发，服务端用 c2s 收。
        let sealed = ka.c2s.seal(1, b"hello").unwrap();
        assert_eq!(kb.c2s.open(1, &sealed).unwrap(), b"hello");
        let sealed = kb.s2c.seal(2, b"world").unwrap();
        assert_eq!(ka.s2c.open(2, &sealed).unwrap(), b"world");
    }

    #[test]
    fn direction_binding() {
        let a = new_handshake().unwrap();
        let b = new_handshake().unwrap();
        let ap = a.public().to_vec();
        let bp = b.public().to_vec();
        let ka = a.finish_client(&bp).unwrap();
        let kb = b.finish_server(&ap).unwrap();
        // 用错方向（c2s 密文走 s2c 解）必须失败。
        let sealed = ka.c2s.seal(1, b"x").unwrap();
        assert!(kb.s2c.open(1, &sealed).is_err());
    }

    #[test]
    fn rejects_garbage_pubkey() {
        let a = new_handshake().unwrap();
        assert!(a.finish_client(&[0u8; 65]).is_err());
    }
}
