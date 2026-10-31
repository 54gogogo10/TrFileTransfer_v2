//! 加密与认证原语（规格 §4.1/§5.1）：PBKDF2(50k)、AES-CTR + 截断 HMAC、
//! ECDH P-256 握手、恒时比较。全部使用经审计的 RustCrypto 实现，不手搓算法。

pub mod cipher;
pub mod handshake;
pub mod kdf;

pub use kdf::{derive_pairing_key, pairing_proof};
