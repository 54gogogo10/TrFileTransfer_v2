//! UDT 槽位端到端测试（原生可靠 UDP 流）：真实 socket 握手 + 与 TCP 一致的帧协议。
//! 丢包/乱序/重传路径由 `transfer::udt` 引擎单测覆盖（对偶注入）；本文件验证
//! 线上集成：握手、配对门、单文件 SHA-256 一致、文本帧、0x09 加密路径。

mod common;

use common::{opts, random_file, wait_server};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use trft_core::hash::sha256_file;
use trft_core::transfer::sender::SendOptions;
use trft_core::transfer::udt::serve_udt_on;
use trft_core::transfer::Transport;

/// 空闲 UDP 端口绑定（UDT 服务端入口；IPv4 回环）。
async fn ephemeral_udp() -> (UdpSocket, std::net::SocketAddr) {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    (s, a)
}

#[tokio::test]
async fn udt_single_file_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let (src, _data) = random_file(dir.path(), "u.bin", 1_000_000 + 123);
    let out = dir.path().join("out");

    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, opts(out.clone(), None, 1)));

    let send_opts = SendOptions {
        transport: Transport::Udt,
        ..Default::default()
    };
    trft_core::transfer::sender::send_file(addr, &src, &send_opts)
        .await
        .unwrap();
    wait_server(server).await;
    assert_eq!(
        sha256_file(&out.join("u.bin")).unwrap(),
        sha256_file(&src).unwrap()
    );
    common::assert_no_leftovers(&out);
}

#[tokio::test]
async fn udt_pairing_required_and_wrong_code_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "secret.txt", 128);
    let out = dir.path().join("out");

    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, opts(out.clone(), Some("246810"), 1)));

    // 无码 → 拒绝。
    let no_code = SendOptions {
        transport: Transport::Udt,
        ..Default::default()
    };
    assert!(
        trft_core::transfer::sender::send_file(addr, &src, &no_code)
            .await
            .is_err(),
        "无配对码必须失败"
    );
    // 错码 → 拒绝。
    let wrong = SendOptions {
        transport: Transport::Udt,
        pairing_code: Some("111111".into()),
        ..Default::default()
    };
    assert!(
        trft_core::transfer::sender::send_file(addr, &src, &wrong)
            .await
            .is_err(),
        "错误配对码必须失败"
    );
    // 对码 → 成功。
    let right = SendOptions {
        transport: Transport::Udt,
        pairing_code: Some("246810".into()),
        ..Default::default()
    };
    trft_core::transfer::sender::send_file(addr, &src, &right)
        .await
        .unwrap();
    wait_server(server).await;
    assert_eq!(
        sha256_file(&out.join("secret.txt")).unwrap(),
        sha256_file(&src).unwrap()
    );
}

#[tokio::test]
async fn udt_text_frame_and_encrypted_path() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    // encrypt = true（默认）→ 0x09 加密握手（与 TCP 同口径，证明 UDT 之上加密栈可用）。
    let server = tokio::spawn(serve_udt_on(sock, common::opts(out.clone(), None, 2)));

    let opts_enc = SendOptions {
        transport: Transport::Udt,
        ..Default::default()
    };
    trft_core::transfer::sender::send_text(addr, "udt 文本消息 ✅", &opts_enc)
        .await
        .unwrap();

    // 文件走加密路径（encrypt 默认 true）。
    let (src, data) = random_file(dir.path(), "enc.bin", 300_000);
    trft_core::transfer::sender::send_file(addr, &src, &opts_enc)
        .await
        .unwrap();
    wait_server(server).await;
    let got = std::fs::read(out.join("enc.bin")).unwrap();
    assert_eq!(got, data, "0x09 加密路径传输必须逐字节一致");
}

/// 版本不符：HS 公共头版本字节由 pw::decode 拒绝 → 客户端 30s 握手超时太慢，
/// 这里直发假版本包验证服务端整包忽略（fail-closed 不崩不收）。
#[tokio::test]
async fn udt_rejects_wrong_version_handshake() {
    use trft_core::protocol::udt as pw;
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, opts(out, None, 1)));

    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut pkt = pw::encode(pw::U_P_HS, 42, 0, &[0u8; 16]).unwrap();
    pkt[2] = trft_core::protocol::PROTO_VERSION + 1; // 伪版本
    s.send_to(&pkt, addr).await.unwrap();
    // 正常版本 HS（同 conn）：应答 HS_ACK = 服务端存活且版本门在位。
    let good = pw::encode(pw::U_P_HS, 43, 0, &[7u8; 16]).unwrap();
    s.send_to(&good, addr).await.unwrap();
    let mut buf = vec![0u8; 2048];
    let (n, _) = timeout(Duration::from_secs(5), s.recv_from(&mut buf))
        .await
        .expect("应收到 HS_ACK")
        .unwrap();
    let (h, _) = pw::decode(&buf[..n]).unwrap();
    assert_eq!(h.kind, pw::U_P_HS_ACK);
    assert_eq!(h.conn, 43);
    server.abort();
}
