//! 0x02 并行分块专项 e2e。
//!
//! 既有覆盖的缺口：分块此前只有单元状态机（split/complement/merge/end）与
//! limits 套件顺带覆盖——无「多分块边界 + 真实传输 + 完整送达」的专项成功路径。
//! 回退语义 interop 已测「会回退」，本套件补「回退后完整送达」。

mod common;

use common::{ephemeral_listener, opts_resident, random_file, wait_server};

use trft_core::error::Error;
use trft_core::hash::sha256_file;
use trft_core::transfer::chunked::send_file_chunked;
use trft_core::transfer::receiver::serve_on;
use trft_core::transfer::resume::send_file_auto;
use trft_core::transfer::sender::SendOptions;

/// 8 MiB = 多个 2 MiB 级分块边界 + 大于套件现有 3 MiB 上限。
const SIZE: usize = 8 * 1024 * 1024;

#[tokio::test]
async fn chunked_roundtrip_multi_chunk_chinese_name() {
    let dir = tempfile::tempdir().unwrap();
    let (src, data) = random_file(dir.path(), "大文件_分块测试_8MiB.bin", SIZE);
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, opts_resident(out.clone(), None)));

    send_file_chunked(addr, &src, &SendOptions::default(), 4).await.unwrap();
    server.abort();

    assert_eq!(
        sha256_file(&out.join("大文件_分块测试_8MiB.bin")).unwrap(),
        sha256_file(&src).unwrap(),
        "多分块 round-trip 必须逐字节保真"
    );
    common::assert_no_leftovers(&out);
    let _ = data;
}

#[tokio::test]
async fn chunked_full_stack_pairing_compress() {
    // 分块 × 配对码 × 压缩同时启用（全栈组合；接收端常驻受理多连接）。
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "stacked.bin", 3 * 1024 * 1024);
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, opts_resident(out.clone(), Some("654321"))));

    let o = SendOptions {
        pairing_code: Some("654321".into()),
        compress: true,
        ..Default::default()
    };
    send_file_chunked(addr, &src, &o, 3).await.unwrap();
    server.abort();

    assert_eq!(sha256_file(&out.join("stacked.bin")).unwrap(), sha256_file(&src).unwrap());
    common::assert_no_leftovers(&out);
}

/// 回归（GUI 实机测试发现）：`--count 1` 与 0x02 并行分块组合。
/// 修复前接收端把首条连接的 INCOMPLETE（0x02）判决也计入 --count，收到第一个
/// 分片就退出 → 发送端被 RST、落盘只剩 .trft-part（CLI 与 GUI 均实测复现）。
#[tokio::test]
async fn chunked_with_count_one_receives_full_file() {
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "count1.bin", 4 * 1024 * 1024);
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let mut o = opts_resident(out.clone(), None);
    o.max_count = Some(1); // 限量模式：串行受理，收满 1 次「真实完成」即退
    let server = tokio::spawn(serve_on(listener, o));

    send_file_chunked(addr, &src, &SendOptions::default(), 4)
        .await
        .expect("分块发送必须成功（接收端不得在中途退出）");
    wait_server(server).await;

    assert_eq!(
        sha256_file(&out.join("count1.bin")).unwrap(),
        sha256_file(&src).unwrap(),
        "4 路分块 + --count 1 必须完整送达"
    );
    common::assert_no_leftovers(&out);
}

#[tokio::test]
async fn chunked_fallback_completes_against_old_peer() {
    // 规格 §3.2 AutoRetry：0x02 对旧对端 Unsupported → 调用方回退 0x03（自动降级
    // 0x00 全量）→ 必须完整送达。interop 测「会报 Unsupported」，这里测回退链路终点。
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "fb.bin", 512 * 1024);
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, trft_core::transfer::receiver::RecvOptions {
        save_dir: out.clone(),
        duplicate: trft_core::config::DuplicatePolicy::Rename,
        enable_chunked: false,
        enable_resume: false,
        compress: false,
        ..Default::default()
    }));

    let r = send_file_chunked(addr, &src, &SendOptions::default(), 4).await;
    assert!(
        matches!(r, Err(Error::Unsupported(_))),
        "旧对端必须显式 Unsupported，实际 {r:?}"
    );
    // 回退：send_file_auto 首选 0x03，对端无续传能力自动降级 0x00 全量。
    send_file_auto(addr, &src, &SendOptions::default()).await.unwrap();
    server.abort();

    assert_eq!(sha256_file(&out.join("fb.bin")).unwrap(), sha256_file(&src).unwrap());
    common::assert_no_leftovers(&out);
}
