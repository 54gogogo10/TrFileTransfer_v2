//! 限速接线判别（审查轮 7 登记的测试计划项）。
//!
//! 判别逻辑：限速器的单测只证明「桶本身会睡」，不证明「传输路径真的把每个分块
//! （含最后一块）都过了一遍桶」。本套件用真实回环传输的时间下界判别接线：
//! 若任何分块绕过限速器，传输会显著快于下界 → 测试变红。
//! 规格 §3.1：发送侧 SpeedLimit、接收侧 RecvSpeedLimit（流控反压）、所有分块含最后一块。

mod common;

use common::{ephemeral_listener, opts, opts_resident, random_file, wait_server};
use std::time::Instant;
use trft_core::hash::sha256_file;
use trft_core::transfer::chunked::send_file_chunked;
use trft_core::transfer::receiver::serve_on;
use trft_core::transfer::sender::{send_file, SendOptions};

const RATE: u64 = 96 * 1024; // 96 KB/s
const SIZE: usize = 384 * 1024; // 桶初始满 96KB + 3s 排空 = 时间下界的来源
const LOWER: std::time::Duration = std::time::Duration::from_millis(2700);
const UPPER: std::time::Duration = std::time::Duration::from_secs(12);

#[tokio::test]
async fn send_side_limit_wired_every_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let (src, data) = random_file(dir.path(), "lim.bin", SIZE);
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, opts(out.clone(), None, 1)));

    let o = SendOptions {
        speed_limit_bps: RATE,
        ..Default::default()
    };
    let t0 = Instant::now();
    send_file(addr, &src, &o).await.unwrap();
    let el = t0.elapsed();
    wait_server(server).await;

    assert!(
        el >= LOWER,
        "发送限速未接线或被绕过: {el:?}（下界 {LOWER:?}）"
    );
    assert!(el < UPPER, "发送限速过慢: {el:?}");
    assert_eq!(
        sha256_file(&out.join("lim.bin")).unwrap(),
        sha256_file(&src).unwrap()
    );
    common::assert_no_leftovers(&out);
    let _ = data;
}

#[tokio::test]
async fn recv_side_limit_wired_every_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "rlim.bin", SIZE);
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let mut o = opts(out.clone(), None, 1);
    o.recv_limit_bps = RATE; // 接收限速：靠流控反压发送方（规格 §3.1）
    let server = tokio::spawn(serve_on(listener, o));

    let t0 = Instant::now();
    send_file(addr, &src, &SendOptions::default())
        .await
        .unwrap();
    let el = t0.elapsed();
    wait_server(server).await;

    assert!(
        el >= LOWER,
        "接收限速未接线或被绕过: {el:?}（下界 {LOWER:?}）"
    );
    assert!(el < UPPER, "接收限速过慢: {el:?}");
    assert_eq!(
        sha256_file(&out.join("rlim.bin")).unwrap(),
        sha256_file(&src).unwrap()
    );
    common::assert_no_leftovers(&out);
}

#[tokio::test]
async fn chunked_path_limit_wired() {
    // 0x02 分块路径（2 条并行连接）：限速语义为**每连接一桶**（规格 §3.2「按面板限速」
    // 的独立客户端口径），N 路聚合上限 = N × SpeedLimit。
    // 判别下界：每连接 192KB（桶初始满 96KB + 96KB @96KB/s ≈ 1s）→ 传输 ≥ 0.9s；
    // 任何分块绕过限速器都会在 <0.3s 内完成 → 测试变红。
    const CHUNKED_LOWER: std::time::Duration = std::time::Duration::from_millis(900);
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "chunk.bin", SIZE);
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, opts_resident(out.clone(), None)));

    let o = SendOptions {
        speed_limit_bps: RATE,
        ..Default::default()
    };
    let t0 = Instant::now();
    send_file_chunked(addr, &src, &o, 2).await.unwrap();
    let el = t0.elapsed();
    server.abort();

    assert!(el >= CHUNKED_LOWER, "0x02 分块路径限速未接线: {el:?}");
    assert!(el < UPPER, "0x02 分块路径限速过慢: {el:?}");
    assert_eq!(
        sha256_file(&out.join("chunk.bin")).unwrap(),
        sha256_file(&src).unwrap()
    );
    common::assert_no_leftovers(&out);
}
