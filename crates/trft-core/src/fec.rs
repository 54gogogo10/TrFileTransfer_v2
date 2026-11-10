//! Reed-Solomon 前向纠错（规格 §3.1 单向 UDP：多轮重发 + RS 前向纠错）。
//! 基于 reed-solomon-erasure（Galois 8）。

use crate::error::{proto, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

pub const FEC_DATA_SHARDS: usize = 4;
pub const FEC_PARITY_SHARDS: usize = 2;

pub struct FecCodec {
    rs: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
}

impl FecCodec {
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        if data_shards == 0 || parity_shards == 0 {
            return Err(proto("FEC 数据/校验分片数必须 ≥ 1"));
        }
        if data_shards + parity_shards > 255 {
            return Err(proto("FEC 总分片数不得超过 255"));
        }
        Ok(Self {
            rs: ReedSolomon::new(data_shards, parity_shards).map_err(|e| proto(e.to_string()))?,
            data_shards,
            parity_shards,
        })
    }

    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }

    /// 输入恰好 data_shards 个等长数据分片，返回 data+parity 全部分片（parity 槽位补零后由库覆写）。
    pub fn encode_group(&self, mut shards: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        if shards.len() != self.data_shards {
            return Err(proto(format!(
                "编码需要恰好 {} 个数据分片",
                self.data_shards
            )));
        }
        let len = shards[0].len();
        if shards.iter().any(|s| s.len() != len) {
            return Err(proto("数据分片必须等长"));
        }
        for _ in 0..self.parity_shards {
            shards.push(vec![0u8; len]);
        }
        self.rs
            .encode(&mut shards)
            .map_err(|e| proto(e.to_string()))?;
        Ok(shards)
    }

    /// 缺失分片用 None 占位；可恢复则原地补齐（全部变 Some）。
    pub fn try_reconstruct(
        &self,
        mut shards: Vec<Option<Vec<u8>>>,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        if shards.len() != self.data_shards + self.parity_shards {
            return Err(proto("分片数与编解码器配置不符"));
        }
        self.rs
            .reconstruct(&mut shards)
            .map_err(|e| proto(e.to_string()))?;
        Ok(shards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard(n: u8, len: usize) -> Vec<u8> {
        vec![n; len]
    }

    #[test]
    fn encode_then_reconstruct_with_loss() {
        let f = FecCodec::new(4, 2).unwrap();
        let len = 1024;
        let original: Vec<Vec<u8>> =
            vec![shard(1, len), shard(2, len), shard(3, len), shard(4, len)];
        let shards = f.encode_group(original.clone()).unwrap();
        assert_eq!(shards.len(), 6);
        // 丢 2 个分片（= parity 上限）仍可恢复。
        let mut recv: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        recv[1] = None;
        recv[4] = None;
        let rec = f.try_reconstruct(recv).unwrap();
        let rec: Vec<Vec<u8>> = rec.into_iter().map(|s| s.unwrap()).collect();
        assert_eq!(&rec[..4], &original[..]);
    }

    #[test]
    fn too_many_losses_unrecoverable() {
        let f = FecCodec::new(4, 2).unwrap();
        let original: Vec<Vec<u8>> = vec![shard(1, 8), shard(2, 8), shard(3, 8), shard(4, 8)];
        let shards = f.encode_group(original).unwrap();
        let mut recv: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        recv[0] = None;
        recv[1] = None;
        recv[2] = None;
        assert!(f.try_reconstruct(recv).is_err());
    }

    #[test]
    fn rejects_bad_config() {
        assert!(FecCodec::new(0, 2).is_err());
        assert!(FecCodec::new(128, 128).is_err());
    }
}
