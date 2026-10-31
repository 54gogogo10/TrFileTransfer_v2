//! 0x01 文件夹传输端到端测试：嵌套目录、中文名、根目录冲突改名。

mod common;

use common::{ephemeral_listener, opts};
use rand_core::{OsRng, RngCore};
use std::time::Duration;
use tokio::time::timeout;
use trft_core::config::DuplicatePolicy;
use trft_core::hash::sha256_file;
use trft_core::transfer::folder::send_folder;
use trft_core::transfer::receiver::{RecvOptions, serve_on};
use trft_core::transfer::sender::SendOptions;

fn make_file(path: &std::path::Path, len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    OsRng.fill_bytes(&mut data);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, &data).unwrap();
    data
}

#[tokio::test]
async fn folder_roundtrip_nested_and_root_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("proj");
    make_file(&src.join("docs").join("说明.txt"), 4096);
    make_file(&src.join("图纸 v2").join("最终 render.png"), 100_000);
    make_file(&src.join("顶层.bin"), 777);
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, opts(out.clone(), None, 1)));
    send_folder(addr, &src, &SendOptions::default()).await.unwrap();
    timeout(Duration::from_secs(10), server).await.unwrap().unwrap().unwrap();

    let base = out.join("proj");
    for rel in ["docs/说明.txt", "图纸 v2/最终 render.png", "顶层.bin"] {
        assert_eq!(
            sha256_file(&base.join(rel)).unwrap(),
            sha256_file(&src.join(rel)).unwrap(),
            "{rel} 内容应一致"
        );
    }

    // 第二次发送 → 根目录冲突 → proj_1
    let (listener2, addr2) = ephemeral_listener().await;
    let server2 = tokio::spawn(serve_on(listener2, opts(out.clone(), None, 1)));
    send_folder(addr2, &src, &SendOptions::default()).await.unwrap();
    timeout(Duration::from_secs(10), server2).await.unwrap().unwrap().unwrap();
    assert!(out.join("proj_1").join("docs").join("说明.txt").exists());
}

#[tokio::test]
async fn folder_skip_drops_identical_copy() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("lib");
    make_file(&src.join("same.bin"), 2048);
    let out = dir.path().join("out");

    // skip 模式接收两次：第二次同内容副本应被丢弃，不产生 _1。
    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(
        listener,
        RecvOptions {
            save_dir: out.clone(),
            duplicate: DuplicatePolicy::Skip,
            max_count: Some(2),
            ..Default::default()
        },
    ));
    send_folder(addr, &src, &SendOptions::default()).await.unwrap();
    send_folder(addr, &src, &SendOptions::default()).await.unwrap();
    timeout(Duration::from_secs(10), server).await.unwrap().unwrap().unwrap();

    assert!(out.join("lib").join("same.bin").exists());
    assert!(!out.join("lib_1").join("same.bin").exists(), "同内容副本应被丢弃（不产生 lib_1）");
}
