//! 自互通矩阵 e2e 化（审查轮 8 发布检查单：以自互通矩阵替代 C# 互通矩阵）。
//!
//! 矩阵口径：客户端特性 × 服务端特性 → 预期行为。旧对端用 RecvOptions
//! 的 enable_chunked / enable_resume / compress = false 模拟（服务端对未知帧
//! 的处理与旧版本完全一致：回 0x00 后断开）。
//!
//! | 客户端 \ 服务端 | 新版（全特性） | 旧版（无扩展帧） |
//! |---|---|---|
//! | send_file_auto (0x03) | 断点续传 | 自动降级 0x00 全量 |
//! | send_file_chunked (0x02) | 覆盖判完成 | Unsupported（调用方回退） |
//! | sync (0x04) | 差量位图 | Unsupported（显式报错） |
//! | compress=on | 0x08 协商成功 | 协商被拒 → 明文继续 |
//! | compress=off | 明文 | 明文 |

mod common;

use common::{ephemeral_listener, opts, opts_resident, random_file};
use rand_core::{OsRng, RngCore};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use trft_core::hash::sha256_file;
use trft_core::protocol::frame::{
    CAP_CHUNKED, CAP_COMPRESS, CAP_COVERAGE, CAP_RESUME_FILE, CAP_RESUME_FOLDER, R_CAPABILITY,
    T_CAPABILITY, T_CHUNKED,
};
use trft_core::protocol::io::{read_u8, write_all, write_str_u16, write_u32, write_u64, write_u8};
use trft_core::transfer::chunked::send_file_chunked;
use trft_core::transfer::receiver::RecvOptions;
use trft_core::transfer::resume::send_file_auto;
use trft_core::transfer::resume::send_folder_resume;
use trft_core::transfer::sender::SendOptions;

fn old_server_opts(save: std::path::PathBuf) -> RecvOptions {
    // 「旧对端」模拟：关闭全部扩展特性（未知帧 fail-closed 行为与旧版本一致）。
    RecvOptions {
        save_dir: save,
        duplicate: trft_core::config::DuplicatePolicy::Rename,
        max_count: Some(1),
        enable_chunked: false,
        enable_resume: false,
        compress: false,
        ..Default::default()
    }
}

fn new_client_opts() -> SendOptions {
    SendOptions {
        compress: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn matrix_new_client_vs_old_server_falls_back_to_00() {
    let dir = tempfile::tempdir().unwrap();
    let (src, data) = random_file(dir.path(), "m.bin", 512 * 1024);
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(trft_core::transfer::receiver::serve_on(
        listener,
        old_server_opts(out.clone()),
    ));

    // 规格 §3.2：0x03 首选 → 旧对端 → 自动降级 0x00 → 成功。
    send_file_auto(addr, &src, &new_client_opts())
        .await
        .unwrap();
    common::wait_server(server).await;
    assert_eq!(
        sha256_file(&out.join("m.bin")).unwrap(),
        sha256_file(&src).unwrap()
    );
    let _ = data;
}

#[tokio::test]
async fn matrix_chunked_vs_old_server_is_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "c.bin", 256 * 1024);
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(trft_core::transfer::receiver::serve_on(
        listener,
        old_server_opts(out.clone()),
    ));

    let r = send_file_chunked(addr, &src, &new_client_opts(), 4).await;
    assert!(
        matches!(r, Err(trft_core::error::Error::Unsupported(_))),
        "旧对端必须显式 Unsupported（调用方据此回退），实际 {r:?}"
    );
    server.abort();
}

#[tokio::test]
async fn matrix_sync_vs_old_server_is_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("srcdir");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a.txt"), b"A").unwrap();
    std::fs::write(root.join("sub/b.txt"), b"B").unwrap();
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(trft_core::transfer::receiver::serve_on(
        listener,
        old_server_opts(out.clone()),
    ));

    let r = send_folder_resume(addr, &root, &new_client_opts(), 42, None).await;
    assert!(
        matches!(r, Err(trft_core::error::Error::Unsupported(_))),
        "同步对旧对端必须显式报错（不做静默语义降级），实际 {r:?}"
    );
    server.abort();
}

#[tokio::test]
async fn matrix_compress_on_vs_off_still_transfers() {
    let dir = tempfile::tempdir().unwrap();
    // 可压缩数据：0x08 被拒后必须以明文继续（宽容降级，规格 §1.4）。
    let mut data = Vec::new();
    for i in 0..40_000u32 {
        data.extend_from_slice(format!("row-{i}-padpadpad\n").as_bytes());
    }
    let src = dir.path().join("comp.txt");
    std::fs::write(&src, &data).unwrap();
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    // 服务端关闭压缩（其余特性保留）。
    let o = RecvOptions {
        compress: false,
        ..opts_resident(out.clone(), None)
    };
    let server = tokio::spawn(trft_core::transfer::receiver::serve_on(listener, o));

    send_file_auto(addr, &src, &new_client_opts())
        .await
        .unwrap();
    server.abort();
    assert_eq!(
        sha256_file(&out.join("comp.txt")).unwrap(),
        sha256_file(&src).unwrap()
    );
}

#[tokio::test]
async fn matrix_compress_full_stack_roundtrip() {
    // 压缩 ↔ 压缩（全特性栈：探询 + 0x08 协商 + 0x03 续传）。
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "z.bin", 300 * 1024);
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(trft_core::transfer::receiver::serve_on(
        listener,
        opts(out.clone(), None, 1),
    ));

    send_file_auto(addr, &src, &new_client_opts())
        .await
        .unwrap();
    common::wait_server(server).await;
    assert_eq!(
        sha256_file(&out.join("z.bin")).unwrap(),
        sha256_file(&src).unwrap()
    );
    common::assert_no_leftovers(&out);
}

#[tokio::test]
async fn capability_frame_reports_feature_bits() {
    // 0x0A/0x1A：全开服务端 → 5 个能力位；受限服务端 → 位随选项收敛。
    async fn probe(addr: std::net::SocketAddr) -> u8 {
        let mut s = TcpStream::connect(addr).await.unwrap();
        write_u8(&mut s, T_CAPABILITY).await.unwrap();
        assert_eq!(read_u8(&mut s).await.unwrap(), R_CAPABILITY);
        read_u8(&mut s).await.unwrap()
    }

    let dir = tempfile::tempdir().unwrap();
    let (l1, a1) = ephemeral_listener().await;
    let s1 = tokio::spawn(trft_core::transfer::receiver::serve_on(
        l1,
        opts_resident(dir.path().join("o1"), None),
    ));
    assert_eq!(
        probe(a1).await,
        CAP_CHUNKED | CAP_COVERAGE | CAP_RESUME_FILE | CAP_RESUME_FOLDER | CAP_COMPRESS,
        "全开服务端必须广播全部能力位"
    );

    let (l2, a2) = ephemeral_listener().await;
    let s2 = tokio::spawn(trft_core::transfer::receiver::serve_on(
        l2,
        RecvOptions {
            compress: false,
            enable_chunked: false,
            ..opts_resident(dir.path().join("o2"), None)
        },
    ));
    assert_eq!(
        probe(a2).await,
        CAP_RESUME_FILE | CAP_RESUME_FOLDER,
        "位必须随选项收敛"
    );
    s1.abort();
    s2.abort();
}

#[tokio::test]
async fn resume_survives_interrupted_transfer() {
    // 0x03 跨连接续传：半途掐断 → 重新 send_file_auto → 服务端权威偏移接续 → 完整。
    let dir = tempfile::tempdir().unwrap();
    let (src, data) = random_file(dir.path(), "big.bin", 2 * 1024 * 1024);
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    let (l1, a1) = ephemeral_listener().await;
    let s1 = tokio::spawn(trft_core::transfer::receiver::serve_on(
        l1,
        opts_resident(out.clone(), None),
    ));

    // 手工发送 0x03 头 + 一半载荷后掐断（模拟瞬断）。
    let name = "big.bin";
    {
        let mut s = TcpStream::connect(a1).await.unwrap();
        write_u8(&mut s, trft_core::protocol::frame::T_RESUME_FILE)
            .await
            .unwrap();
        write_str_u16(&mut s, name).await.unwrap();
        write_u64(&mut s, data.len() as u64).await.unwrap();
        write_u64(&mut s, 0).await.unwrap();
        write_u8(&mut s, 1).await.unwrap();
        write_all(&mut s, &sha256_file(&src).unwrap())
            .await
            .unwrap();
        // 协商应答。
        assert_eq!(
            read_u8(&mut s).await.unwrap(),
            trft_core::protocol::frame::R_RESUME_NEGO
        );
        assert_eq!(read_u8(&mut s).await.unwrap(), 0x01);
        let off = {
            let mut b = [0u8; 8];
            s.read_exact(&mut b).await.unwrap();
            u64::from_le_bytes(b)
        };
        assert_eq!(off, 0, "首次协商从 0 开始");
        s.write_all(&data[..data.len() / 2]).await.unwrap();
        // 半途掐断：不发尾哈希直接 drop。
        drop(s);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    // 半成品在盘上（重启/重连可恢复），但最终名不存在。
    assert!(!out.join(name).exists());

    // 重连 → 服务端从半成品长度接续。
    send_file_auto(a1, &src, &new_client_opts()).await.unwrap();
    s1.abort();
    assert_eq!(
        sha256_file(&out.join(name)).unwrap(),
        sha256_file(&src).unwrap()
    );
    common::assert_no_leftovers(&out);
}

#[tokio::test]
async fn coverage_query_reports_written_ranges() {
    // 0x0B：手工发送部分块 → 新连接查询 → 合并区间精确反映已写盘范围（落盘即状态）。
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    let (l1, a1) = ephemeral_listener().await;
    let s1 = tokio::spawn(trft_core::transfer::receiver::serve_on(
        l1,
        opts_resident(out.clone(), None),
    ));

    let name = "cov.bin";
    let total: u64 = 3 * 1024 * 1024;
    let mut gid = [0u8; 16];
    OsRng.fill_bytes(&mut gid);
    {
        let mut s = TcpStream::connect(a1).await.unwrap();
        // 块 0（[0,1MiB)）与块 2（[2MiB,3MiB)）——中间留洞。
        for off in [0u64, 2 * 1024 * 1024] {
            write_u8(&mut s, T_CHUNKED).await.unwrap();
            write_all(&mut s, &gid).await.unwrap();
            write_u64(&mut s, off).await.unwrap();
            write_u64(&mut s, total).await.unwrap();
            write_str_u16(&mut s, name).await.unwrap();
            write_u32(&mut s, 1024 * 1024).await.unwrap();
            let payload = vec![0xABu8; 1024 * 1024];
            write_all(&mut s, &payload).await.unwrap();
        }
        drop(s); // 不发 0x0C：连接结束但会话保留（覆盖查询的前提）
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 查询覆盖率。
    let mut s = TcpStream::connect(a1).await.unwrap();
    write_u8(&mut s, trft_core::protocol::frame::T_COVERAGE_QUERY)
        .await
        .unwrap();
    write_all(&mut s, &gid).await.unwrap();
    assert_eq!(read_u8(&mut s).await.unwrap(), 0x01, "会话必须存活");
    let n = {
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await.unwrap();
        u32::from_le_bytes(b)
    };
    assert_eq!(n, 2, "两个不连续区间");
    let mut ranges = Vec::new();
    for _ in 0..n {
        let mut b = [0u8; 16];
        s.read_exact(&mut b).await.unwrap();
        let off = u64::from_le_bytes(b[..8].try_into().unwrap());
        let len = u64::from_le_bytes(b[8..].try_into().unwrap());
        ranges.push((off, len));
    }
    assert_eq!(
        ranges,
        vec![(0, 1024 * 1024), (2 * 1024 * 1024, 1024 * 1024)]
    );
    s1.abort();
}
