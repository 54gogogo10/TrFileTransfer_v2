//! SHA-256 流式摘要（规格 §3.1：每个文件必须带 SHA-256 并在接收端重算比对）。

use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

use crate::error::Result;

pub const HASH_LEN: usize = 32;

pub fn sha256(data: &[u8]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// 流式摘要器：边传输边算，避免为求和把整个文件读进内存。
pub struct FileDigester {
    hasher: Sha256,
    written: u64,
}

impl FileDigester {
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            written: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.written += data.len() as u64;
    }

    pub fn written(&self) -> u64 {
        self.written
    }

    pub fn finalize(self) -> [u8; HASH_LEN] {
        self.hasher.finalize().into()
    }
}

impl Default for FileDigester {
    fn default() -> Self {
        Self::new()
    }
}

/// 对整文件求 SHA-256（1 MiB 步长流式读取）。
pub fn sha256_file(path: &Path) -> Result<[u8; HASH_LEN]> {
    let mut f = std::fs::File::open(path)?;
    let mut dig = FileDigester::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dig.update(&buf[..n]);
    }
    Ok(dig.finalize())
}

/// 小写十六进制（与规格 §10.2 `.sha256` 边车格式一致）。
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_abc() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn file_digester_matches_whole_hash() {
        let data = b"hello trft";
        let mut d = FileDigester::new();
        d.update(&data[..4]);
        d.update(&data[4..]);
        assert_eq!(d.written(), data.len() as u64);
        assert_eq!(d.finalize(), sha256(data));
    }
}
