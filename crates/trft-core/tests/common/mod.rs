//! e2e 公共辅助（审查轮 7 P3 登记：跨测试文件归并，消除四处复制）。

#![allow(dead_code)]

use rand_core::{OsRng, RngCore};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::timeout;
use trft_core::config::DuplicatePolicy;
use trft_core::transfer::receiver::RecvOptions;

/// 空闲端口监听（规格 §10.1：端口经空闲探测）。
pub async fn ephemeral_listener() -> (TcpListener, std::net::SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}

/// 标准接收选项：max_count 收满即停（限量模式串行——测试判定的确定性基础）。
pub fn opts(save: std::path::PathBuf, code: Option<&str>, count: u64) -> RecvOptions {
    RecvOptions {
        save_dir: save,
        pairing_code: code.map(String::from),
        duplicate: DuplicatePolicy::Rename,
        max_count: Some(count),
        ..Default::default()
    }
}

/// 常驻接收选项（多连接路径——0x02 并行分块、互通矩阵——必须并发受理）。
pub fn opts_resident(save: std::path::PathBuf, code: Option<&str>) -> RecvOptions {
    RecvOptions {
        save_dir: save,
        pairing_code: code.map(String::from),
        duplicate: DuplicatePolicy::Rename,
        max_count: None,
        ..Default::default()
    }
}

/// 随机内容临时文件。
pub fn random_file(dir: &std::path::Path, name: &str, len: usize) -> (std::path::PathBuf, Vec<u8>) {
    let mut data = vec![0u8; len];
    OsRng.fill_bytes(&mut data);
    let p = dir.join(name);
    std::fs::write(&p, &data).unwrap();
    (p, data)
}

/// 等待限量接收器按预期收尾（10s 兜底以失败形式呈现死锁）。
pub async fn wait_server(server: tokio::task::JoinHandle<Result<(), trft_core::error::Error>>) {
    timeout(Duration::from_secs(10), server)
        .await
        .unwrap_or_else(|_| panic!("接收器 10s 内未收尾（疑似死锁）"))
        .unwrap()
        .unwrap();
}

/// 断言目录内无 .trft-part / .trft-resume 残留（假成功防护的落盘不变量）。
pub fn assert_no_leftovers(dir: &std::path::Path) {
    let leftover: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.ends_with(".trft-part") || n.ends_with(".trft-resume") || n.ends_with(".meta")
        })
        .collect();
    assert!(
        leftover.is_empty(),
        "残留: {:?}",
        leftover.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );
}
