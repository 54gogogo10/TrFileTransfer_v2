//! UDT4 槽位端到端测试：真实 UDP socket 两段式握手 + C# 方言应用层。
//! 丢包/乱序/重传路径由 `transfer::udt` 引擎单测覆盖（对偶注入）；本文件验证
//! 线上集成：握手、配对门、单文件 SHA-256 一致、文本帧、0x09 加密路径、
//! 0x02 并发分块、0x03 断点续传——并含一个测试内手写的 C# 方言客户端，
//! 钉住「C# 客户端 → v2 服务端」方向的线格式（TECH-STACK §7.30）。

mod common;

use common::{opts, random_file, wait_server};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use trft_core::hash::sha256_file;
use trft_core::transfer::cswire::CsWire;
use trft_core::transfer::sender::SendOptions;
use trft_core::transfer::Transport;

/// 空闲 UDP 端口绑定（UDT 服务端入口；IPv4 回环）。
/// 收缓冲 4MB **镜像生产口径**（serve_udt 同款）：发端批量泵在一个调度片内
/// 可 blast 数百 KB，OS 默认 ~64KB 缓冲会丢包（批量化后实机暴露——0x03 续传
/// e2e 首收 77/183 包）。
async fn ephemeral_udp() -> (UdpSocket, std::net::SocketAddr) {
    use socket2::{Domain, Socket as S2Socket, Type};
    let dom = Domain::IPV4;
    let sock = S2Socket::new(dom, Type::DGRAM, None).unwrap();
    sock.bind(&"127.0.0.1:0"
        .parse::<std::net::SocketAddr>()
        .unwrap()
        .into())
    .unwrap();
    if let Err(e) = sock.set_recv_buffer_size(4 * 1024 * 1024) {
        eprintln!("[测试] UDP 收缓冲设置失败: {e}");
    }
    sock.set_nonblocking(true).unwrap();
    let std_sock: std::net::UdpSocket = sock.into();
    let s = UdpSocket::from_std(std_sock).unwrap();
    let a = s.local_addr().unwrap();
    (s, a)
}

fn udt_opts() -> SendOptions {
    SendOptions {
        transport: Transport::Udt,
        ..Default::default()
    }
}

/* ============ v2 客户端 → v2 服务端（复用 send_* 入口的 UDT 分支） ============ */

#[tokio::test]
async fn udt_single_file_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let (src, data) = random_file(dir.path(), "u.bin", 1_000_000 + 123);
    let out = dir.path().join("out");

    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, opts(out.clone(), None, 1)));

    trft_core::transfer::sender::send_file(addr, &src, &udt_opts())
        .await
        .unwrap();
    wait_server(server).await;
    assert_eq!(
        sha256_file(&out.join("u.bin")).unwrap(),
        sha256_file(&src).unwrap()
    );
    let _ = data;
    common::assert_no_leftovers(&out);
}

#[tokio::test]
async fn udt_pairing_required_and_wrong_code_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "secret.txt", 4096);
    let out = dir.path().join("out");

    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, opts(out.clone(), Some("246810"), 1)));

    // 无码 → 拒绝（服务端要求配对，客户端跳过认证 → 0x15/1 + NACK）。
    let no_code = udt_opts();
    assert!(
        trft_core::transfer::sender::send_file(addr, &src, &no_code)
            .await
            .is_err(),
        "无配对码必须失败"
    );
    // 错码 → 0x09 握手 status 1 拒绝。
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
    // 对码 → 0x09 加密路径成功。
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
async fn udt_text_and_folder() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, opts(out.clone(), None, 3)));

    trft_core::transfer::sender::send_text(addr, "udt 文本消息 ✅", &udt_opts())
        .await
        .unwrap();

    // 文件夹（C# 方言 0x01：递归 + 相对路径）。
    let root = dir.path().join("送检目录");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    let (a, a_data) = random_file(&root, "a.txt", 50_000);
    let (b, b_data) = random_file(&root.join("sub"), "b.bin", 200_000);
    trft_core::transfer::folder::send_folder_auto(addr, &root, &udt_opts())
        .await
        .unwrap();

    // 文本再来一条（max_count=3 的第 3 帧）。
    trft_core::transfer::sender::send_text(addr, "第二条", &udt_opts())
        .await
        .unwrap();
    wait_server(server).await;

    assert_eq!(
        sha256_file(&out.join("送检目录").join("a.txt")).unwrap(),
        sha256_file(&a).unwrap()
    );
    assert_eq!(
        sha256_file(&out.join("送检目录").join("sub").join("b.bin")).unwrap(),
        sha256_file(&b).unwrap()
    );
    let _ = (a_data, b_data);
    common::assert_no_leftovers(&out);
}

/* ============ C# 方言客户端 → v2 服务端（测试内手写客户端钉线格式） ============ */

/// 用 cswire 客户端原语直连 v2 UDT 服务端：0x00 单文件 + 裸 ACK 读判决。
#[tokio::test]
async fn cs_dialect_client_sends_single_file() {
    use trft_core::transfer::cswire::cs_send_file;

    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "cs.bin", 300_000);
    let out = dir.path().join("out");
    let stats_path = dir.path().join("stats.log");
    let (sock, addr) = ephemeral_udp().await;
    let mut ro = opts(out.clone(), None, 1);
    ro.stats = Some(std::sync::Arc::new(trft_core::stats::StatsLog::new(stats_path.clone())));
    let server = tokio::spawn(serve_udt_on(sock, ro));

    // 直连（无认证栈——服务端未配配对码）。
    let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
    let mut wire = CsWire::new(stream);
    cs_send_file(&mut wire, &src, &SendOptions::default()).await.unwrap();
    let _ = wire.shutdown().await;

    wait_server(server).await;
    assert_eq!(
        sha256_file(&out.join("cs.bin")).unwrap(),
        sha256_file(&src).unwrap()
    );
    // C# 方言分支的记账判别：detail 用规范文案，path 记最终落盘全路径（§7.31）。
    let rows = trft_core::stats::StatsLog::new(stats_path).load();
    assert_eq!(rows.len(), 1, "一次成功接收恰好一行");
    assert_eq!(rows[0].detail, "直接发送", "C# 方言行不得把文件名当 detail");
    assert_eq!(
        rows[0].path,
        out.join("cs.bin").display().to_string(),
        "C# 方言行必须记最终落盘全路径（历史定位用）"
    );
}

/// 0x02 并发分块（C# GUI 默认形态：0x0A bit1 能力 + 组会话 + 4 连接各发一段）。
/// 服务端经组内范围合并组装；完整后以裸 ACK 0x01 逐连接判决。
#[tokio::test]
async fn cs_dialect_chunked_group_assembles_file() {
    use sha2::Digest;
    use trft_core::transfer::cswire::{cs_read_final_ack, F_CAPS, F_CHUNK, R_CAPS};

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, common::opts_resident(out.clone(), None)));

    // 测试载荷：4 段 × 200KB。
    let total: u64 = 4 * 200_000;
    let payload: Vec<u8> = (0..total as usize).map(|i| (i % 251) as u8).collect();
    let src = dir.path().join("chunked.bin");
    std::fs::write(&src, &payload).unwrap();
    let group_id: [u8; 16] = [0x42; 16];
    let chunk: u64 = 200_000;
    let concurrency = 4usize;

    // 每连接：0x0A 能力（bit1）→ 0x02 分块段 → 裸 ACK。
    let mut handles = Vec::new();
    for i in 0..concurrency {
        let addr = addr;
        let payload = payload.clone();
        let group_id = group_id;
        handles.push(tokio::spawn(async move {
            let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
            let mut wire = CsWire::new(stream);
            // 能力帧：[0x0A][0x02] → [0x1A][0x03]。
            wire.raw_write(&[F_CAPS, 0x02]).await.unwrap();
            let mut resp = [0u8; 2];
            wire.raw.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp[0], R_CAPS, "能力应答");
            assert_eq!(resp[1] & 0x02, 0x02, "bit1 必须被确认");

            // 0x02 头：[totalSize i64][chunkOffset i64][chunkSize i64][nameLen i32][name]
            //          [groupFlag u8=1][groupId 16B] + 数据 + [sha256 32]。
            let name = "chunked.bin";
            let off = (i as u64) * chunk;
            let seg = &payload[off as usize..(off + chunk) as usize];
            let mut hasher = sha2::Sha256::new();
            hasher.update(seg);
            let seg_hash: [u8; 32] = hasher.finalize().into();
            let mut header = Vec::with_capacity(29 + 16 + 12 + name.len());
            header.push(F_CHUNK);
            header.extend_from_slice(&(total as i64).to_le_bytes());
            header.extend_from_slice(&(off as i64).to_le_bytes());
            header.extend_from_slice(&(chunk as i64).to_le_bytes());
            header.extend_from_slice(&(name.len() as i32).to_le_bytes());
            header.extend_from_slice(name.as_bytes());
            header.push(1);
            header.extend_from_slice(&group_id);
            wire.write_all(&header).await.unwrap();
            wire.write_all(seg).await.unwrap();
            wire.write_all(&seg_hash).await.unwrap();
            cs_read_final_ack(&mut wire).await.unwrap();
            let _ = wire.shutdown().await;
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    server.abort();

    // 组装完成：整文件逐字节一致。
    assert_eq!(
        sha256_file(&out.join("chunked.bin")).unwrap(),
        sha256_file(&src).unwrap()
    );
}

/// 0x03 断点续传：首连发一半断开 → 服务端会话保留 → 二连从服务端权威 offset 续传
/// → 尾哈希通过 → 0x10/2 终态。
#[tokio::test]
async fn cs_dialect_resume_0x03_continues() {
    use sha2::Digest;
    use trft_core::transfer::cswire::{F_RESUME, R_RESUME};

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, common::opts_resident(out.clone(), None)));

    let total: usize = 500_000;
    let payload: Vec<u8> = (0..total).map(|i| (i % 241) as u8).collect();
    let full_hash: [u8; 32] = {
        let mut h = sha2::Sha256::new();
        h.update(&payload);
        h.finalize().into()
    };
    let name = "resume.bin";
    let session: [u8; 16] = [0x77; 16];
    let half = (total / 2) as u64;

    // 连接一：声明 total + 发送前一半（未发尾哈希即断开——模拟中断）。
    {
        let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
        let mut wire = CsWire::new(stream);
        let mut header = Vec::new();
        header.push(F_RESUME);
        header.extend_from_slice(&session);
        header.extend_from_slice(&(total as i64).to_le_bytes());
        header.extend_from_slice(&(0i64).to_le_bytes());
        header.extend_from_slice(&(name.len() as i32).to_le_bytes());
        header.extend_from_slice(name.as_bytes());
        header.push(1); // verifyFlag=1（附全文件哈希）
        header.extend_from_slice(&full_hash);
        wire.write_all(&header).await.unwrap();
        let mut resp = [0u8; 10];
        wire.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], R_RESUME);
        assert_eq!(resp[9], 0, "新会话 status 0");
        let from = i64::from_le_bytes(resp[1..9].try_into().unwrap());
        assert_eq!(from, 0);
        wire.write_all(&payload[..half as usize]).await.unwrap();
        // 不发尾哈希：直接 drop（SHUTDOWN）——模拟发送端中断。
        drop(wire);
    }
    // 服务端处理第一条连接（半成品落盘）。
    tokio::time::sleep(Duration::from_millis(400)).await;

    // 连接二：同会话续传 → 服务端应答 status 1 + offset=half → 补发余下 + 尾哈希 → 0x10/2。
    {
        let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
        let mut wire = CsWire::new(stream);
        let mut header = Vec::new();
        header.push(F_RESUME);
        header.extend_from_slice(&session);
        header.extend_from_slice(&(total as i64).to_le_bytes());
        header.extend_from_slice(&(half as i64).to_le_bytes());
        header.extend_from_slice(&(name.len() as i32).to_le_bytes());
        header.extend_from_slice(name.as_bytes());
        header.push(1);
        header.extend_from_slice(&full_hash);
        wire.write_all(&header).await.unwrap();
        let mut resp = [0u8; 10];
        wire.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], R_RESUME);
        let from = i64::from_le_bytes(resp[1..9].try_into().unwrap());
        assert_eq!(from, half as i64, "服务端权威续点");
        assert_eq!(resp[9], 1, "status 1 = 续传");
        wire.write_all(&payload[half as usize..]).await.unwrap();
        // C# 0x03 尾哈希 = 增量哈希（本次连接发送的字节）——非全文件哈希。
        let increment_hash: [u8; 32] = {
            let mut h = sha2::Sha256::new();
            h.update(&payload[half as usize..]);
            h.finalize().into()
        };
        wire.write_all(&increment_hash).await.unwrap();
        let mut fin = [0u8; 10];
        wire.read_exact(&mut fin).await.unwrap();
        assert_eq!(fin[0], R_RESUME);
        assert_eq!(fin[9], 2, "终态 status 2");
        let _ = wire.shutdown().await;
    }
    server.abort();
    assert_eq!(
        sha256_file(&out.join("resume.bin")).unwrap(),
        full_hash
    );
}

/// 判别（轮 6 P0）：**加密栈**下 0x03 续传体跨 256KB 加密段边界。
/// `read_some` 在段间 pending 耗尽时旧实现直接 `raw.read` 穿透装饰器把
/// 密文当应用字节写盘——第二连接补发体 >256KB（首个加密段边界）后必炸
/// （增量哈希失配）。无加密/小文件测试掩盖了它。去修复必红。
#[tokio::test]
async fn cs_dialect_resume_encrypted_crosses_segment_boundary() {
    use sha2::Digest;
    use trft_core::transfer::cswire::{F_RESUME, R_RESUME};

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, common::opts_resident(out.clone(), Some("135790"))));

    let total: usize = 600_000;
    let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let full_hash: [u8; 32] = {
        let mut h = sha2::Sha256::new();
        h.update(&payload);
        h.finalize().into()
    };
    let name = "res_enc.bin";
    let session: [u8; 16] = [0x88; 16];
    let half = (total / 2) as u64; // 300KB > 256KB 首段界

    let client_opts = SendOptions {
        transport: Transport::Udt,
        pairing_code: Some("135790".into()),
        encrypt: true,
        ..Default::default()
    };
    // 连接一：加密声明 + 发前一半，断开。
    {
        let (mut wire, _) =
            trft_core::transfer::cswire::cs_connect_stack_full(addr, &client_opts, 0)
                .await
                .unwrap();
        assert!(wire.encrypted(), "前奏必须建立加密层");
        let mut header = Vec::new();
        header.push(F_RESUME);
        header.extend_from_slice(&session);
        header.extend_from_slice(&(total as i64).to_le_bytes());
        header.extend_from_slice(&(0i64).to_le_bytes());
        header.extend_from_slice(&(name.len() as i32).to_le_bytes());
        header.extend_from_slice(name.as_bytes());
        header.push(0); // verifyFlag=0
        wire.write_all(&header).await.unwrap();
        let mut resp = [0u8; 10];
        wire.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], R_RESUME);
        assert_eq!(resp[9], 0);
        wire.write_all(&payload[..half as usize]).await.unwrap();
        drop(wire); // 不发尾哈希——模拟中断
    }
    tokio::time::sleep(Duration::from_millis(400)).await;

    // 连接二：加密续传——补发体 300KB **跨段**。
    {
        let (mut wire, _) =
            trft_core::transfer::cswire::cs_connect_stack_full(addr, &client_opts, 0)
                .await
                .unwrap();
        let mut header = Vec::new();
        header.push(F_RESUME);
        header.extend_from_slice(&session);
        header.extend_from_slice(&(total as i64).to_le_bytes());
        header.extend_from_slice(&(half as i64).to_le_bytes());
        header.extend_from_slice(&(name.len() as i32).to_le_bytes());
        header.extend_from_slice(name.as_bytes());
        header.push(0);
        wire.write_all(&header).await.unwrap();
        let mut resp = [0u8; 10];
        wire.read_exact(&mut resp).await.unwrap();
        let from = i64::from_le_bytes(resp[1..9].try_into().unwrap());
        assert_eq!(from, half as i64, "服务端权威续点");
        assert_eq!(resp[9], 1, "status 1 = 续传");
        wire.write_all(&payload[half as usize..]).await.unwrap();
        let increment_hash: [u8; 32] = {
            let mut h = sha2::Sha256::new();
            h.update(&payload[half as usize..]);
            h.finalize().into()
        };
        wire.write_all(&increment_hash).await.unwrap();
        let mut fin = [0u8; 10];
        wire.read_exact(&mut fin).await.unwrap();
        assert_eq!(fin[0], R_RESUME);
        assert_eq!(fin[9], 2, "终态 status 2（跨段哈希必须通过）");
        let _ = wire.shutdown().await;
    }
    // 服务端处理完第二条连接（落盘即状态——abort 前给处理时间，与明文 resume 同口径）。
    tokio::time::sleep(Duration::from_millis(400)).await;
    server.abort();
    assert_eq!(
        sha256_file(&out.join(name)).unwrap(),
        full_hash,
        "加密续传跨段后必须逐字节一致"
    );
}

/* ============ 版本门（握手层 fail-closed） ============ */

/// 服务端对版本/类型不符的握手回 1002 拒绝（libudt listen 语义）。
#[tokio::test]
async fn udt_rejects_wrong_version_handshake() {
    use trft_core::protocol::udt as pw;

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, opts(out, None, 1)));

    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // 伪版本握手请求（req_type=1, cookie=0）。
    let bad = pw::Handshake {
        version: pw::UDT_VERSION + 1,
        sock_type: pw::UDT_SOCK_STREAM,
        isn: 42,
        mss: pw::UDT_MSS,
        flight_flag: pw::UDT_RCV_BUF_PKTS,
        req_type: pw::HS_REQ,
        id: 0x1122,
        cookie: 0,
        peer_ip: [0, 0, 0, 0],
    };
    // 阶段一（cookie 挑战）不会拒版本——直接跳到阶段二（带 cookie 的 -1 请求；
    // cookie 需匹配服务端签发值，这里先拿挑战）。
    s.send_to(&bad.encode_ctrl(0, 0), addr).await.unwrap();
    let mut buf = vec![0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), s.recv_from(&mut buf))
        .await
        .expect("应收到 cookie 挑战")
        .unwrap();
    let challenge = pw::decode(&buf[..n]).unwrap();
    let cookie = match &challenge {
        pw::Pkt::Ctrl { words, .. } => {
            pw::Handshake::from_words(words).expect("握手字数").cookie
        }
        other => panic!("应为握手控制包: {other:?}"),
    };
    // 阶段二：带 challenge cookie + 伪版本 → 1002。
    let req2 = pw::Handshake { req_type: pw::HS_RESP, cookie, ..bad };
    s.send_to(&req2.encode_ctrl(0, 0), addr).await.unwrap();
    let (n2, _) = tokio::time::timeout(Duration::from_secs(5), s.recv_from(&mut buf))
        .await
        .expect("应收到 1002 拒绝")
        .unwrap();
    let resp = pw::decode(&buf[..n2]).unwrap();
    match resp {
        pw::Pkt::Ctrl { words, .. } => {
            let hs = pw::Handshake::from_words(&words).expect("握手字数");
            assert_eq!(hs.req_type, pw::HS_REJECT, "版本不符必须 1002 拒绝");
        }
        other => panic!("应为握手控制包: {other:?}"),
    }
    server.abort();
}

use trft_core::transfer::udt::serve_udt_on;

/// §7.31 判别：C# 方言 **加密+压缩** 全栈回环——0x08 提议在 0x09 之后到达时，
/// 服务端 0x18 应答必须经加密装饰器返回（实机 F2 排障：裸写被 C# 段格式卡死
/// 到 8s 响应窗超时 → 对端回退明文；服务端应答改走 write_all 后本测为绿）。
#[tokio::test]
async fn cs_dialect_encrypted_compressed_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "enc.bin", 100_000);
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, opts(out.clone(), Some("135790"), 1)));

    let o = SendOptions {
        transport: Transport::Udt,
        pairing_code: Some("135790".into()),
        compress: true,
        ..Default::default()
    };
    trft_core::transfer::sender::send_file(addr, &src, &o)
        .await
        .unwrap();
    wait_server(server).await;
    assert_eq!(
        sha256_file(&out.join("enc.bin")).unwrap(),
        sha256_file(&src).unwrap()
    );
}

/* ============ 0x04 差量同步客户端（TECH-STACK §7.31） ============ */

fn sync_cache(dir: &std::path::Path) -> std::sync::Arc<tokio::sync::Mutex<trft_core::hashcache::HashCache>> {
    std::sync::Arc::new(tokio::sync::Mutex::new(trft_core::hashcache::HashCache::load(
        &dir.join("cache.txt"),
        7,
    )))
}

/// 判别：UDT 槽位 0x04 同步客户端对 C# 方言服务端——首轮全量落盘；
/// 改一个文件后二轮只补差异（服务端逐文件哈希核对，其余跳过）。
/// 退回 §7.30 的 Unsupported 短路（或 0x11/跳过清单接线错误）本测必红。
#[tokio::test]
async fn cs_dialect_sync_incremental_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("lib");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a.bin"), vec![1u8; 50_000]).unwrap();
    std::fs::write(root.join("sub/b.txt"), b"hello sync").unwrap();
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, common::opts_resident(out.clone(), None)));

    let cache = sync_cache(dir.path());
    trft_core::transfer::cswire::send_folder_sync_cs(addr, &root, &udt_opts(), Some(&cache))
        .await
        .unwrap();

    // 服务端会话目录 = out/<folder>.<guid8>（确定性派生——重复同步续用）。
    let session_dir = std::fs::read_dir(&out)
        .unwrap()
        .find_map(|e| {
            let n = e.unwrap().file_name().to_string_lossy().to_string();
            n.starts_with("lib.").then(|| out.join(n))
        })
        .expect("服务端必须建立 <folder>.<guid8> 会话目录");
    assert_eq!(
        std::fs::read(session_dir.join("a.bin")).unwrap(),
        vec![1u8; 50_000]
    );
    assert_eq!(std::fs::read(session_dir.join("sub/b.txt")).unwrap(), b"hello sync");

    // 改一个文件 + 新增一个 → 二轮同步只补差异（跳过清单逐文件核对）。
    std::fs::write(root.join("a.bin"), vec![2u8; 50_000]).unwrap();
    std::fs::write(root.join("new.bin"), b"added").unwrap();
    trft_core::transfer::cswire::send_folder_sync_cs(addr, &root, &udt_opts(), Some(&cache))
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(session_dir.join("a.bin")).unwrap(),
        vec![2u8; 50_000],
        "被改文件必须重新同步"
    );
    assert_eq!(std::fs::read(session_dir.join("new.bin")).unwrap(), b"added");
    assert_eq!(
        std::fs::read(session_dir.join("sub/b.txt")).unwrap(),
        b"hello sync",
        "未变文件必须跳过（哈希一致）"
    );
    server.abort();
}
