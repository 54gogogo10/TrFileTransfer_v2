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
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use trft_core::hash::{sha256, sha256_file};
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
    // 0x0A/0x1A（C# 方言）：bit0 = 0x04 逐文件跳过清单，bit1 = 0x02 组会话 + 0x0B。
    // 默认全开 = 0x03（与 C# 服务端同）；关闭特性时位随选项收敛。
    async fn probe(addr: std::net::SocketAddr) -> u8 {
        use tokio::io::AsyncWriteExt;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&[0x0Au8, 0x03]).await.unwrap();
        let mut resp = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut s, &mut resp)
            .await
            .unwrap();
        assert_eq!(resp[0], 0x1A);
        resp[1]
    }

    let dir = tempfile::tempdir().unwrap();
    let (l1, a1) = ephemeral_listener().await;
    let s1 = tokio::spawn(trft_core::transfer::receiver::serve_on(
        l1,
        opts_resident(dir.path().join("o1"), None),
    ));
    assert_eq!(probe(a1).await, 0x03, "全开服务端必须广播 bit0|bit1");

    let (l2, a2) = ephemeral_listener().await;
    let s2 = tokio::spawn(trft_core::transfer::receiver::serve_on(
        l2,
        RecvOptions {
            enable_chunked: false,
            ..opts_resident(dir.path().join("o2"), None)
        },
    ));
    assert_eq!(probe(a2).await, 0x01, "位必须随选项收敛");
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

    // 手工发送 0x03 头（C# 方言：sid 与 send_file_auto 同派生）+ 一半载荷后掐断。
    let name = "big.bin";
    let full = sha256_file(&src).unwrap();
    let sid = trft_core::transfer::cswire::derive_resume_session_guid(&src, data.len() as u64, a1);
    {
        use tokio::io::AsyncWriteExt;
        let mut s = TcpStream::connect(a1).await.unwrap();
        // [0x03][sid 16][total i64][offset i64][nameLen i32][name][flag 1][fullHash 32]
        let mut hdr = vec![0x03u8];
        hdr.extend_from_slice(&sid);
        hdr.extend_from_slice(&(data.len() as i64).to_le_bytes());
        hdr.extend_from_slice(&0i64.to_le_bytes());
        hdr.extend_from_slice(&(name.len() as i32).to_le_bytes());
        hdr.extend_from_slice(name.as_bytes());
        hdr.push(1);
        hdr.extend_from_slice(&full);
        s.write_all(&hdr).await.unwrap();
        // 0x10 协商应答：[0x10][offset i64][status u8]。
        let mut resp = [0u8; 10];
        s.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], 0x10);
        assert_eq!(resp[9], 0x00, "首次协商 status 0");
        let off = i64::from_le_bytes(resp[1..9].try_into().unwrap());
        assert_eq!(off, 0, "首次协商从 0 开始");
        s.write_all(&data[..data.len() / 2]).await.unwrap();
        // 半途掐断：不发尾哈希直接 drop。
        drop(s);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    // C# 方言 0x03 直接写最终名（无 .trft-part）：半成品在盘上，长度短于声明。
    let partial = std::fs::metadata(out.join(name)).map(|m| m.len()).unwrap_or(0);
    assert!(
        partial > 0 && partial < data.len() as u64,
        "半成品应已落盘且短于声明（实际 {partial}）"
    );

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
    // 0x0A 协商 bit1（组会话 + 0x0B）——未协商时服务端不认块头里的组 id。
    async fn connect_neg(addr: std::net::SocketAddr) -> TcpStream {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&[0x0Au8, 0x02]).await.unwrap();
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x1A, 0x03]);
        s
    }
    {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        // 块 0（[0,1MiB)）与块 2（[2MiB,3MiB)）——中间留洞；每块一条连接
        // （C# 方言一个连接只承载一个分块），尾随自身哈希。
        for off in [0u64, 2 * 1024 * 1024] {
            let payload = vec![0xABu8; 1024 * 1024];
            let mut s = connect_neg(a1).await;
            let mut hdr = vec![0x02u8];
            hdr.extend_from_slice(&(total as i64).to_le_bytes());
            hdr.extend_from_slice(&(off as i64).to_le_bytes());
            hdr.extend_from_slice(&(payload.len() as i64).to_le_bytes());
            hdr.extend_from_slice(&(name.len() as i32).to_le_bytes());
            hdr.extend_from_slice(name.as_bytes());
            hdr.push(1);
            hdr.extend_from_slice(&gid);
            s.write_all(&hdr).await.unwrap();
            s.write_all(&payload).await.unwrap();
            s.write_all(&sha256(&payload)).await.unwrap();
            // 服务端逐块判决（Rust 服务端对 0x02 写 1 字节 ACK）。
            let mut ack = [0u8; 1];
            s.read_exact(&mut ack).await.unwrap();
            assert_eq!(ack[0], 0x01, "分块必须被收下");
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 查询覆盖率：[0x1B][count i32][start i64][end i64]…
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut s = connect_neg(a1).await;
    s.write_all(&[0x0Bu8]).await.unwrap();
    s.write_all(&gid).await.unwrap();
    let mut head = [0u8; 5];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x1B, "覆盖应答类型");
    let n = i32::from_le_bytes(head[1..5].try_into().unwrap());
    assert_eq!(n, 2, "两个不连续区间");
    let mut ranges = Vec::new();
    for _ in 0..n {
        let mut b = [0u8; 16];
        s.read_exact(&mut b).await.unwrap();
        let start = i64::from_le_bytes(b[..8].try_into().unwrap());
        let end = i64::from_le_bytes(b[8..].try_into().unwrap());
        ranges.push((start, end));
    }
    assert_eq!(
        ranges,
        vec![(0, 1024 * 1024), (2 * 1024 * 1024, 3 * 1024 * 1024)]
    );
    s1.abort();
}
