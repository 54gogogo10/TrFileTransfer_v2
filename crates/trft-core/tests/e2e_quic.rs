//! QUIC 槽位端到端测试：自签 + 跳校验 + 应用层配对码，帧协议与 TCP 一致。

mod common;

use common::opts;
use rand_core::{OsRng, RngCore};
use std::time::Duration;
use tokio::time::timeout;
use trft_core::hash::sha256_file;
use trft_core::transfer::Transport;
use trft_core::transfer::quic::{server_endpoint, serve_quic_on};
use trft_core::transfer::sender::SendOptions;

#[tokio::test]
async fn quic_single_file_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let mut data = vec![0u8; 1_000_000 + 123];
    OsRng.fill_bytes(&mut data);
    let src = dir.path().join("q.bin");
    std::fs::write(&src, &data).unwrap();
    let out = dir.path().join("out");

    let (endpoint, cert_fp) = server_endpoint("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = endpoint.local_addr().unwrap();
    let server = tokio::spawn(serve_quic_on(endpoint, cert_fp, opts(out.clone(), None, 1)));

    let mut send_opts = SendOptions::default();
    send_opts.transport = Transport::Quic;
    trft_core::transfer::sender::send_file(addr, &src, &send_opts).await.unwrap();
    timeout(Duration::from_secs(15), server).await.unwrap().unwrap().unwrap();

    assert_eq!(
        sha256_file(&out.join("q.bin")).unwrap(),
        sha256_file(&src).unwrap()
    );
}

#[tokio::test]
async fn quic_pairing_required() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("secret.txt");
    std::fs::write(&src, b"secret over quic").unwrap();
    let out = dir.path().join("out");

    let (endpoint, cert_fp) = server_endpoint("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = endpoint.local_addr().unwrap();
    let server = tokio::spawn(serve_quic_on(endpoint, cert_fp, opts(out.clone(), Some("987654"), 1)));

    // 无码 → 拒绝。
    let no_code = SendOptions { transport: Transport::Quic, ..Default::default() };
    let r = trft_core::transfer::sender::send_file(addr, &src, &no_code).await;
    assert!(r.is_err(), "无配对码必须失败");

    // 有码 → 成功。
    let with_code = SendOptions {
        transport: Transport::Quic,
        pairing_code: Some("987654".into()),
        ..Default::default()
    };
    trft_core::transfer::sender::send_file(addr, &src, &with_code).await.unwrap();
    timeout(Duration::from_secs(15), server).await.unwrap().unwrap().unwrap();
    assert!(out.join("secret.txt").exists());
}

/// M6' 判别（TECH-STACK §7.11）：**双臂中继必败**。
/// MITM 对客户端出示自己的证书、对服务端另开一条腿并逐字节转发——
/// 0x0D 证明绑定「客户端所见服务器证书指纹」，两腿指纹必然不同 → 服务端拒绝。
/// 去掉绑定接线（回退明文 0x05 直通）本测试必红（中继成功即假成功红线）。
#[tokio::test]
async fn mitm_dual_arm_relay_rejected_by_channel_binding() {
    use std::sync::Arc;

    // 真实服务端：配对码 987654（限量 1——拒绝路径不计数，收尾由 abort 兜底）。
    let (ep, real_fp) = server_endpoint("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let real_addr = ep.local_addr().unwrap();
    let out = tempfile::tempdir().unwrap().path().join("out-real");
    let server = tokio::spawn(serve_quic_on(
        ep,
        real_fp,
        common::opts(out.clone(), Some("987654"), 1),
    ));

    // MITM：自签 endpoint（客户端看到的是 MITM 证书，不是真实服务端证书）。
    let (mitm_ep, _mfp) = server_endpoint("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let mitm_addr = mitm_ep.local_addr().unwrap();
    let relay = tokio::spawn(async move {
        // 上行客户端配置（无 pin——模拟无钉扎的真实受害者）。
        let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(
            trft_core::transfer::quic::client_tls_config(None),
        )
        .unwrap();
        let mut up_ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        up_ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(qcc)));
        while let Some(inc) = mitm_ep.accept().await {
            // 每连接一个任务（并发中继——不因单腿阻塞后续连接）。
            let up_ep2 = up_ep.clone();
            tokio::spawn(async move {
                eprintln!("[MITM] 下游连接进入");
                let Ok(down) = inc.await else { return };
                let Ok((cs, cr)) = down.accept_bi().await else { return };
                eprintln!("[MITM] 下游流建立");
                // 第二腿：连接真实服务端（MITM 是这里的客户端）。
                let Ok(up_conn) = up_ep2.connect(real_addr, "trft.local").unwrap().await else {
                    eprintln!("[MITM] 上游连接失败");
                    return;
                };
                eprintln!("[MITM] 上游连接建立");
                let Ok((us, ur)) = up_conn.open_bi().await else { return };
                eprintln!("[MITM] 上游流建立——开始转发");
                let (mut cs, mut cr) = (cs, cr);
                let (mut us, mut ur) = (us, ur);
                // 双臂逐字节转发（含 0x0D 证明——但两腿证书指纹不同，证明必败）。
                tokio::spawn(async move {
                    let n = tokio::io::copy(&mut cr, &mut us).await;
                    eprintln!("[MITM] C→S 转发结束: {n:?}");
                });
                tokio::spawn(async move {
                    let n = tokio::io::copy(&mut ur, &mut cs).await;
                    eprintln!("[MITM] S→C 转发结束: {n:?}");
                });
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("victim.bin");
    std::fs::write(&src, b"victim payload").unwrap();
    let victim = SendOptions {
        transport: Transport::Quic,
        pairing_code: Some("987654".into()),
        ..Default::default()
    };
    let r = trft_core::transfer::sender::send_file(mitm_addr, &src, &victim).await;
    assert!(r.is_err(), "双臂中继必须被通道绑定拒绝");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!out.join("victim.bin").exists(), "中继不得造成任何落盘");
    assert!(!out.join("victim.bin.trft-resume").exists());
    server.abort();
    relay.abort();
}

/// 轮 2 P1 判别：**盲接受型假服务端必败**——假服务端不知配对码，无法伪造
/// S→C 证明（HMAC(K, s2c 域‖盐‖fp)）；客户端恒时校验失败即断。
/// 去掉 s2c 校验（只查状态字节）本测试必红（假成功窃取红线）。
#[tokio::test]
async fn blind_accept_fake_server_rejected_by_s2c_proof() {
    use trft_core::protocol::io::{read_n, read_u8, write_all, write_u8};
    use trft_core::protocol::{frame::R_PAIRING_SALT, frame::T_PAIRING_BOUND};

    // 假服务端：自签证书，不知道配对码——走完 0x0D 流程并「盲接受」。
    let (ep, _fp) = server_endpoint("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = ep.local_addr().unwrap();
    let server = tokio::spawn(async move {
        use trft_core::protocol::io::{read_str_u16, read_u64};
        let conn = ep.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let _ = read_u8(&mut recv).await.unwrap(); // 版本字节
        let t = read_u8(&mut recv).await.unwrap();
        assert_eq!(t, T_PAIRING_BOUND, "测试前提：客户端应走 0x0D");
        write_u8(&mut send, R_PAIRING_SALT).await.unwrap();
        write_all(&mut send, &[7u8; 16]).await.unwrap();
        let _proof = read_n(&mut recv, 32).await.unwrap();
        // 盲接受：不知码也回 OK + 32B 垃圾证明。
        write_u8(&mut send, 0x01).await.unwrap();
        write_all(&mut send, &[0u8; 32]).await.unwrap();
        // 像真接收器一样照单全收文件帧（0x00 + 名 + 大小 + 载荷 + 哈希）并回 OK——
        // 偷数据型假服务端模型；无 s2c 校验时 send_file 将假成功（判别基线）。
        // s2c 生效时客户端在校验处断开——读失败即优雅退出（不得 panic）。
        let Ok(frame) = read_u8(&mut recv).await else { return };
        if frame != 0x00 {
            return;
        }
        let Ok(_name) = read_str_u16(&mut recv).await else { return };
        let Ok(size) = read_u64(&mut recv).await else { return };
        let mut left = size;
        let mut buf = vec![0u8; 4096];
        while left > 0 {
            let want = std::cmp::min(4096, left) as usize;
            if recv.read_exact(&mut buf[..want]).await.is_err() {
                return;
            }
            left -= want as u64;
        }
        if read_n(&mut recv, 32).await.is_err() {
            return;
        }
        let _ = write_u8(&mut send, 0x01).await;
        // 优雅收尾：FIN 交付状态字节 + 保持连接（quinn 关闭会丢弃未读流数据）。
        let _ = send.finish();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    });

    let opts = SendOptions {
        transport: Transport::Quic,
        pairing_code: Some("987654".into()),
        ..Default::default()
    };
    // authenticate_bound 为私有——经 send_file 走全流程；假服务端不会收文件，
    // 客户端应在 s2c 校验处失败（任何 Err 均可，关键是不得成功）。
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("v.bin");
    std::fs::write(&src, b"victim").unwrap();
    let r = trft_core::transfer::sender::send_file(addr, &src, &opts).await;
    assert!(r.is_err(), "盲接受型假服务端必须被 S→C 证明拒绝");
    timeout(Duration::from_secs(10), server).await.unwrap().unwrap();
}
