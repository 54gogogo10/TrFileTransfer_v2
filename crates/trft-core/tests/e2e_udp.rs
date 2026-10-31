//! 单向 UDP 端到端测试：真实 socket 回环，多轮重发 + FEC 全链路。

use rand_core::{OsRng, RngCore};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use trft_core::hash::sha256_file;
use trft_core::transfer::udp::{UdpRecvOptions, UdpSendOptions, send_file_udp, serve_udp_on};
use trft_core::transfer::udp::UdpEvent;

#[tokio::test]
async fn udp_single_file_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let mut data = vec![0u8; 50_000];
    OsRng.fill_bytes(&mut data);
    let src = dir.path().join("u.bin");
    std::fs::write(&src, &data).unwrap();
    let out = dir.path().join("out");

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let server = tokio::spawn(serve_udp_on(socket, UdpRecvOptions { save_dir: out.clone(), ..Default::default() }, Some(tx)));

    // 发送在后台：接收器先完成（落盘即状态），发送器才退出。
    let send_path = src.clone();
    let sender = tokio::spawn(async move {
        send_file_udp(addr, &send_path, &UdpSendOptions { passes: 2, fec: true, fec_parity: 2, speed_limit_bps: 0, ..Default::default() }).await
    });

    // 事件流里先有 Started/Progress，循环等到 Completed 为止。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv()).await.unwrap().unwrap();
        if matches!(ev, UdpEvent::Completed { .. }) {
            break;
        }
    }
    sender.await.unwrap().unwrap();
    server.abort();

    let dest = out.join("u.bin");
    assert_eq!(sha256_file(&dest).unwrap(), sha256_file(&src).unwrap());
}

/// UDP 收侧进度接线 + 节流判别（M4'）：逐包 UdpEvent::Progress 经 100ms 节流后
/// 事件数必须远小于数据包数（50KB ≈ 42 DATA/轮，无节流接线本测试必红），
/// 终态 done == size。文件取小值防回环 blast 丢包（与既有测试同纪律）。
#[tokio::test]
async fn udp_progress_throttled_and_final_exact() {
    use trft_core::progress::ProgressEvent;

    let dir = tempfile::tempdir().unwrap();
    let mut data = vec![0u8; 50_000];
    OsRng.fill_bytes(&mut data);
    let src = dir.path().join("throttle.bin");
    std::fs::write(&src, &data).unwrap();
    let out = dir.path().join("out");

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (ptx, mut prx) = mpsc::unbounded_channel();
    let hub = trft_core::progress::ProgressHub::new(ptx);
    let server = tokio::spawn(serve_udp_on(
        socket,
        UdpRecvOptions { save_dir: out.clone(), progress: Some(hub), ..Default::default() },
        Some(tx),
    ));

    let send_path = src.clone();
    let sender = tokio::spawn(async move {
        send_file_udp(
            addr,
            &send_path,
            &UdpSendOptions { passes: 2, fec: true, fec_parity: 2, speed_limit_bps: 0, ..Default::default() },
        )
        .await
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv()).await.unwrap().unwrap();
        if matches!(ev, UdpEvent::Completed { .. }) {
            break;
        }
    }
    sender.await.unwrap().unwrap();
    server.abort();

    let mut evs: Vec<ProgressEvent> = Vec::new();
    while let Ok(ev) = prx.try_recv() {
        evs.push(ev);
    }
    assert!(!evs.is_empty(), "收侧无进度事件（接线缺失）");
    assert!(
        evs.len() < 30,
        "节流失效：50KB 两轮回环不应产生 {} 个进度事件",
        evs.len()
    );
    let last = evs.last().unwrap();
    assert_eq!(last.state, "done", "终态必为 done: {:?}", &evs[evs.len().saturating_sub(5)..]);
    assert_eq!(last.done, data.len() as u64, "终态字节数必须等于文件大小");
    assert_eq!(last.total, data.len() as u64, "收侧总量 = 文件大小（按轮加权是发侧口径）");
}

/// 轮 4 P1 判别：一个超长数据报（Windows WSAEMSGSIZE）不得杀死整个接收器。
/// 修复前 recv_from 错误直接 `?` 上抛——LAN 任意主机 1 包 = UDP 接收永久不可用。
/// 去掉 10040 容错（改回直接传播）本测试必红（服务器退出 → 后续传输超时）。
#[tokio::test]
async fn oversized_datagram_does_not_kill_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let mut data = vec![0u8; 3000];
    OsRng.fill_bytes(&mut data);
    let src = dir.path().join("after.bin");
    std::fs::write(&src, &data).unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let server = tokio::spawn(serve_udp_on(
        sock,
        UdpRecvOptions { save_dir: out.clone(), ..Default::default() },
        None,
    ));

    // 1) 发一个 3001 字节垃圾包（> 2048 缓冲）。
    let junk_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let junk = vec![0xEE; 3001];
    junk_sock.send_to(&junk, addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 2) 服务器必须仍活着并正常收完整文件。
    let opts = UdpSendOptions::default();
    send_file_udp(addr, &src, &opts).await.unwrap();
    // 多轮重发给引擎留收敛时间。
    for _ in 0..20 {
        if out.join("after.bin").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        out.join("after.bin").exists(),
        "超长垃圾包之后服务器必须仍能接收（kill-switch 红线）"
    );
    assert_eq!(std::fs::read(out.join("after.bin")).unwrap(), data);
    server.abort();
}
