//! FEC 吞吐基准（TECH-STACK §7.2 登记项：reed-solomon-erasure 纯 Rust 参考实现
//! 的发布阶段基准——不达标再评估 C 绑定）。
//!
//! 运行（不入常规套件）：
//!   cargo test -p trft-core --test fec_bench -- --ignored --nocapture
//!
//! 判读口径：单向 UDP 每组 = 4 数据片 × 1400B ≈ 5.6KB；吞吐按「数据字节数/秒」
//! 计（编码含校验片生成，重建含擦除恢复）。LAN 1 Gbps ≈ 125 MB/s，链路侧还有
//! 400ms 轮间间隔与重发叠加——引擎吞吐达到该量级一个数量级以上即不构成瓶颈。

use std::time::Instant;
use trft_core::fec::{FecCodec, FEC_DATA_SHARDS, FEC_PARITY_SHARDS};

const GROUPS: usize = 20_000; // 20k 组 × 5.6KB ≈ 112 MB 数据量
const SHARD: usize = 1400;

#[test]
#[ignore = "吞吐基准：手动运行（cargo test -p trft-core --test fec_bench -- --ignored --nocapture）"]
fn fec_throughput_encode_and_reconstruct() {
    let codec = FecCodec::new(FEC_DATA_SHARDS, FEC_PARITY_SHARDS).unwrap();
    let mut rng = 0x12345678u32;

    let mk_group = |seed: &mut u32| -> Vec<Vec<u8>> {
        (0..FEC_DATA_SHARDS)
            .map(|_| {
                (0..SHARD)
                    .map(|_| {
                        *seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                        (*seed >> 24) as u8
                    })
                    .collect::<Vec<u8>>()
            })
            .collect()
    };

    // 预热（分配/页错误不进统计）。
    for _ in 0..200 {
        let g = mk_group(&mut rng);
        codec.encode_group(g.clone()).unwrap();
    }

    // 编码：数据字节 / 秒。
    let t0 = Instant::now();
    for _ in 0..GROUPS {
        let g = mk_group(&mut rng);
        let shards = codec.encode_group(g).unwrap();
        assert_eq!(shards.len(), FEC_DATA_SHARDS + FEC_PARITY_SHARDS);
    }
    let enc = t0.elapsed();

    // 重建：丢 1 片（最常见场景）——None 占位（与引擎擦除语义一致）。
    let t1 = Instant::now();
    for _ in 0..GROUPS {
        let g = mk_group(&mut rng);
        let mut shards: Vec<Option<Vec<u8>>> =
            codec.encode_group(g).unwrap().into_iter().map(Some).collect();
        let last = shards.len() - 1;
        shards[last] = None; // 擦除一片
        let rec = codec.try_reconstruct(shards).unwrap();
        assert!(rec.iter().all(|s| s.is_some()), "≤parity 擦除必须可恢复");
    }
    let dec = t1.elapsed();

    let data_mb = (GROUPS * FEC_DATA_SHARDS * SHARD) as f64 / 1e6;
    let enc_mb = data_mb / enc.as_secs_f64();
    let dec_mb = data_mb / dec.as_secs_f64();
    println!(
        "FEC 吞吐（4+2 × 1400B 组）：编码 {enc_mb:.0} MB/s（{enc:?}）｜重建 {dec_mb:.0} MB/s（{dec:?}）｜数据量 {data_mb:.0} MB"
    );
    // 判别下界：低于 50 MB/s 即评估 C 绑定（1Gbps 链路 125MB/s 的 40%）。
    assert!(enc_mb > 50.0, "FEC 编码吞吐过低: {enc_mb:.0} MB/s");
    assert!(dec_mb > 50.0, "FEC 重建吞吐过低: {dec_mb:.0} MB/s");
}
