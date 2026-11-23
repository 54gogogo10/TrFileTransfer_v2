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
        let payload = payload.clone();
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

/// 判别（2026-11-23 双机测试抓到）：首轮落盘后把某文件**改大**，二轮同步必须整文件
/// 替换成功。旧实现把「变长的旧版本」当作断点前缀去追加（C# KnownComplete 守卫在
/// 移植时丢失）→ 拼接后尾哈希不符 → 服务端删旧档 + 回拒绝，同步失败一次且目标
/// 目录丢该文件（重试才自愈）。去掉修复本测必红。
#[tokio::test]
async fn cs_dialect_sync_replaces_file_that_grew() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("lib");
    std::fs::create_dir_all(&root).unwrap();
    // 旧版本不得是新版本的前缀——这正是「旧完整文件被误当断点」的判别场景
    // （若新内容只是旧内容的追加，拼接碰巧正确，测不出缺陷）。
    std::fs::write(root.join("log.txt"), b"alpha\n").unwrap();
    std::fs::write(root.join("keep.bin"), vec![7u8; 4096]).unwrap();
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, common::opts_resident(out.clone(), None)));

    let cache = sync_cache(dir.path());
    trft_core::transfer::cswire::send_folder_sync_cs(addr, &root, &udt_opts(), Some(&cache))
        .await
        .unwrap();
    let session_dir = std::fs::read_dir(&out)
        .unwrap()
        .find_map(|e| {
            let n = e.unwrap().file_name().to_string_lossy().to_string();
            n.starts_with("lib.").then(|| out.join(n))
        })
        .expect("服务端必须建立 <folder>.<guid8> 会话目录");
    assert_eq!(
        std::fs::read(session_dir.join("log.txt")).unwrap(),
        b"alpha\n"
    );

    // 改写为更长的不同内容（"文件变长"是最常见的变更形态：配置/文本/导出）。
    std::fs::write(root.join("log.txt"), b"beta version two\n").unwrap();
    let r =
        trft_core::transfer::cswire::send_folder_sync_cs(addr, &root, &udt_opts(), Some(&cache))
            .await;
    assert!(
        r.is_ok(),
        "文件变长后二轮同步必须成功（旧实现：按旧长度续传 → 拼接 → 哈希不符 → 删档 + 拒绝）: {r:?}"
    );
    assert_eq!(
        std::fs::read(session_dir.join("log.txt")).unwrap(),
        b"beta version two\n",
        "变长文件必须整文件替换（不得拼接成半旧半新）"
    );
    assert_eq!(
        std::fs::read(session_dir.join("keep.bin")).unwrap(),
        vec![7u8; 4096],
        "未变文件保持原样"
    );
    server.abort();
}

/* ============ 轮 UI-5 判别：C# 方言层的假成功/数据丢失防线 ============ */

/// 0x04 清单头：[0x04][sid 16][folderLen i16][folder][count i32][totalBytes i64]。
fn cs_folder_head(sid: &[u8; 16], folder: &str, count: i32, total: u64) -> Vec<u8> {
    use trft_core::transfer::cswire::F_FOLDER_RESUME;
    let mut v = Vec::new();
    v.push(F_FOLDER_RESUME);
    v.extend_from_slice(sid);
    v.extend_from_slice(&(folder.len() as i16).to_le_bytes());
    v.extend_from_slice(folder.as_bytes());
    v.extend_from_slice(&count.to_le_bytes());
    v.extend_from_slice(&(total as i64).to_le_bytes());
    v
}

/// 0x04 清单项：[size i64][pathLen i16][path][sha256 32]。
fn cs_folder_entry(rel: &str, size: u64, hash: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(size as i64).to_le_bytes());
    v.extend_from_slice(&(rel.len() as i16).to_le_bytes());
    v.extend_from_slice(rel.as_bytes());
    v.extend_from_slice(hash);
    v
}

fn sha256_of(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// 轮 UI-5 P0 判别：0x04 同步更新某文件中途失败（断连/哈希失配）时，**接收方
/// 既有文件必须原样保留**——旧实现 Err 分支先 remove_file(save_path) 再发布一个
/// 从未创建的 temp，净效果是用户上一版文件凭空消失。同时钉住成功路径：校验通过
/// 的新版本必须原子替换（不得留下 name_1 副本）。
#[tokio::test]
async fn cs_sync_failure_preserves_existing_file_and_success_replaces() {
    use trft_core::transfer::cswire::{CsWire, R_FOLDER_RESUME};

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, common::opts_resident(out.clone(), None)));

    let sid: [u8; 16] = [0x33; 16];
    let folder = "lib";
    let old: Vec<u8> = (0..100u32).map(|i| (i % 7) as u8).collect();
    let new: Vec<u8> = (0..50u32).map(|i| (i % 11) as u8).collect();
    let new_hash = sha256_of(&new);

    // 第 0 轮：建立会话目录（<folder>.<guid8>）并确认目录名。
    {
        let seed = b"seed".to_vec();
        let seed_hash = sha256_of(&seed);
        let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
        let mut wire = CsWire::new(stream);
        let mut req = cs_folder_head(&sid, folder, 1, seed.len() as u64);
        req.extend_from_slice(&cs_folder_entry("seed.bin", seed.len() as u64, &seed_hash));
        wire.write_all(&req).await.unwrap();
        let mut resp = [0u8; 18];
        wire.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], R_FOLDER_RESUME, "0x04 必须有 0x11 应答");
        assert_eq!(resp[17], 0, "空目录必须 status 0（需发送）");
        wire.write_all(&seed).await.unwrap();
        wire.write_all(&seed_hash).await.unwrap();
        let _ = wire.shutdown().await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let session_dir = std::fs::read_dir(&out)
        .unwrap()
        .find_map(|e| {
            let n = e.unwrap().file_name().to_string_lossy().to_string();
            n.starts_with("lib.").then(|| out.join(n))
        })
        .expect("服务端必须建立 <folder>.<guid8> 会话目录");
    // 既有「上一版」文件：比新版更长 → 服务端判定须全量替换（start == 0）。
    std::fs::write(session_dir.join("a.bin"), &old).unwrap();

    // 第 1 轮：新版本发到一半断连 —— 既有文件必须原样保留。
    {
        let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
        let mut wire = CsWire::new(stream);
        let mut req = cs_folder_head(&sid, folder, 1, new.len() as u64);
        req.extend_from_slice(&cs_folder_entry("a.bin", new.len() as u64, &new_hash));
        wire.write_all(&req).await.unwrap();
        let mut resp = [0u8; 18];
        wire.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[17], 0, "内容不同必须要求全量发送");
        wire.write_all(&new[..20]).await.unwrap();
        drop(wire); // 断连：余下字节与尾哈希都不发
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        std::fs::read(session_dir.join("a.bin")).unwrap(),
        old,
        "同步失败不得删除/改写接收方既有文件（轮 UI-5 P0 判别）"
    );

    // 第 2 轮：完整发送 + 尾哈希 → 原子替换为新版，且不留 _1 副本。
    {
        let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
        let mut wire = CsWire::new(stream);
        let mut req = cs_folder_head(&sid, folder, 1, new.len() as u64);
        req.extend_from_slice(&cs_folder_entry("a.bin", new.len() as u64, &new_hash));
        wire.write_all(&req).await.unwrap();
        let mut resp = [0u8; 18];
        wire.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[17], 0);
        wire.write_all(&new).await.unwrap();
        wire.write_all(&new_hash).await.unwrap();
        // 读连接级 ACK 作为「服务端处理完毕」的同步点（否则 abort 可能
        // 抢在发布之前，测试变成时序竞态）。
        trft_core::transfer::cswire::cs_read_final_ack(&mut wire)
            .await
            .unwrap();
        let _ = wire.shutdown().await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    server.abort();
    assert_eq!(
        std::fs::read(session_dir.join("a.bin")).unwrap(),
        new,
        "校验通过的新版本必须原子替换既有文件"
    );
    assert!(
        !session_dir.join("a_1.bin").exists(),
        "同步替换不得产生 _1 副本"
    );
}

/// 轮 UI-5 P1 判别：0x03 体收满但**尾哈希前断连**时，会话不得被当作
/// 「已完整」——旧实现把 received 推到 total 就保留会话，下一连接直接回
/// status 2（零校验假成功）。修复后必须 status 0 + offset 0 整组重传；
/// 重传校验通过后 status 2，且再次重问仍回 2（C# 语义保留）。
#[tokio::test]
async fn cs_resume_body_without_tail_hash_is_not_reported_complete() {
    use trft_core::transfer::cswire::{CsWire, F_RESUME, R_RESUME};

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, common::opts_resident(out.clone(), None)));

    let total = 120_000usize;
    let payload: Vec<u8> = (0..total).map(|i| (i % 239) as u8).collect();
    let full_hash = sha256_of(&payload);
    let name = "taildrop.bin";
    let sid: [u8; 16] = [0x5a; 16];

    let mut header = vec![F_RESUME];
    header.extend_from_slice(&sid);
    header.extend_from_slice(&(total as i64).to_le_bytes());
    header.extend_from_slice(&0i64.to_le_bytes());
    header.extend_from_slice(&(name.len() as i32).to_le_bytes());
    header.extend_from_slice(name.as_bytes());
    header.push(1); // verifyFlag=1
    header.extend_from_slice(&full_hash);

    // 连接一：发完全部体，但不发尾哈希即断开。
    {
        let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
        let mut wire = CsWire::new(stream);
        wire.write_all(&header).await.unwrap();
        let mut resp = [0u8; 10];
        wire.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[9], 0, "新会话 status 0");
        wire.write_all(&payload).await.unwrap();
        drop(wire);
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 连接二：体已收满但未验证 —— 必须整组重传（status 0 / offset 0）。
    {
        let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
        let mut wire = CsWire::new(stream);
        wire.write_all(&header).await.unwrap();
        let mut resp = [0u8; 10];
        wire.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], R_RESUME);
        assert_eq!(resp[9], 0, "未验证完成的会话不得回 status 2（假成功）");
        let from = i64::from_le_bytes(resp[1..9].try_into().unwrap());
        assert_eq!(from, 0, "未验证的残件必须从 0 重传");
        wire.write_all(&payload).await.unwrap();
        wire.write_all(&full_hash).await.unwrap(); // 本次连接的增量哈希 = 全文件
        let mut fin = [0u8; 10];
        wire.read_exact(&mut fin).await.unwrap();
        assert_eq!(fin[9], 2, "完整校验后 status 2");
        let _ = wire.shutdown().await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 连接三：已验证完成 → status 2 零传输（C#「已完整」语义保留）。
    {
        let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
        let mut wire = CsWire::new(stream);
        wire.write_all(&header).await.unwrap();
        let mut resp = [0u8; 10];
        wire.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[9], 2, "已验证完成的重问必须回 status 2");
        let off = i64::from_le_bytes(resp[1..9].try_into().unwrap());
        assert_eq!(off, total as i64);
        let _ = wire.shutdown().await;
    }
    server.abort();
    assert_eq!(sha256_file(&out.join(name)).unwrap(), full_hash);
}

/// 轮 UI-5 回归：已验证完成（文件已交付）的 0x03 会话，不得因「同 sid 换 total」
/// 而被当作残件删除——那是用户文件，不是半成品。
#[tokio::test]
async fn cs_resume_verified_file_survives_param_change() {
    use trft_core::transfer::cswire::{CsWire, F_RESUME};

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, common::opts_resident(out.clone(), None)));

    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 241) as u8).collect();
    let hash = sha256_of(&payload);
    let name = "delivered.bin";
    let sid: [u8; 16] = [0x6b; 16];
    let total = payload.len() as i64;

    let mut header = vec![F_RESUME];
    header.extend_from_slice(&sid);
    header.extend_from_slice(&total.to_le_bytes());
    header.extend_from_slice(&0i64.to_le_bytes());
    header.extend_from_slice(&(name.len() as i32).to_le_bytes());
    header.extend_from_slice(name.as_bytes());
    header.push(1);
    header.extend_from_slice(&hash);

    // 完整传输 → status 2，文件交付。
    {
        let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
        let mut wire = CsWire::new(stream);
        wire.write_all(&header).await.unwrap();
        let mut resp = [0u8; 10];
        wire.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[9], 0, "新会话 status 0");
        wire.write_all(&payload).await.unwrap();
        wire.write_all(&hash).await.unwrap();
        let mut fin = [0u8; 10];
        wire.read_exact(&mut fin).await.unwrap();
        assert_eq!(fin[9], 2, "终态 status 2");
        let _ = wire.shutdown().await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(std::fs::read(out.join(name)).unwrap(), payload);

    // 同 sid、不同 total：旧会话作废，但已交付文件必须保留。
    {
        let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
        let mut wire = CsWire::new(stream);
        let mut h2 = vec![F_RESUME];
        h2.extend_from_slice(&sid);
        h2.extend_from_slice(&(total + 1).to_le_bytes());
        h2.extend_from_slice(&0i64.to_le_bytes());
        h2.extend_from_slice(&(name.len() as i32).to_le_bytes());
        h2.extend_from_slice(name.as_bytes());
        h2.push(0); // verifyFlag=0
        wire.write_all(&h2).await.unwrap();
        let mut resp = [0u8; 10];
        wire.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[9], 0, "参数变化必须开新会话");
        drop(wire);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        std::fs::read(out.join(name)).unwrap(),
        payload,
        "已验证交付的文件不得因同 sid 换参数而被删除"
    );
    server.abort();
}

/// 轮 UI-5 续 3 P2 判别：0x04 会复用既有会话目录——save_dir 内预置的 junction
/// 不得把对端可控相对路径写到保存目录之外。修复前服务端会沿 junction 落盘。
#[cfg(windows)]
#[tokio::test]
async fn cs_sync_rejects_junction_escape() {
    use trft_core::transfer::cswire::CsWire;

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let (sock, addr) = ephemeral_udp().await;
    let server = tokio::spawn(serve_udt_on(sock, common::opts_resident(out.clone(), None)));

    let sid: [u8; 16] = [0x77; 16];
    let seed = b"seed".to_vec();
    let seed_hash = sha256_of(&seed);
    // 第 0 轮：正常建出会话目录。
    {
        let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
        let mut wire = CsWire::new(stream);
        let mut req = cs_folder_head(&sid, "lib", 1, seed.len() as u64);
        req.extend_from_slice(&cs_folder_entry("seed.bin", seed.len() as u64, &seed_hash));
        wire.write_all(&req).await.unwrap();
        let mut resp = [0u8; 18];
        wire.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], trft_core::transfer::cswire::R_FOLDER_RESUME);
        wire.write_all(&seed).await.unwrap();
        wire.write_all(&seed_hash).await.unwrap();
        let _ = wire.shutdown().await;
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    let session_dir = std::fs::read_dir(&out)
        .unwrap()
        .find_map(|e| {
            let n = e.unwrap().file_name().to_string_lossy().to_string();
            n.starts_with("lib.").then(|| out.join(n))
        })
        .expect("会话目录必须已建立");
    // 换成指向树外的 junction（普通用户可创建）。
    std::fs::remove_dir_all(&session_dir).unwrap();
    let ok = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&session_dir)
        .arg(&outside)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "测试环境必须支持创建 junction");

    // 第 1 轮：同一 sid 再同步 —— 服务端必须在落盘前拒绝。
    {
        let evil = b"escaped".to_vec();
        let evil_hash = sha256_of(&evil);
        let stream = trft_core::transfer::udt::connect_udt(addr, None).await.unwrap();
        let mut wire = CsWire::new(stream);
        let mut req = cs_folder_head(&sid, "lib", 1, evil.len() as u64);
        req.extend_from_slice(&cs_folder_entry("evil.txt", evil.len() as u64, &evil_hash));
        wire.write_all(&req).await.unwrap();
        let mut resp = [0u8; 18];
        let r = tokio::time::timeout(Duration::from_secs(5), wire.read_exact(&mut resp)).await;
        assert!(
            r.is_err() || r.unwrap().is_err(),
            "树外 junction 必须被拒绝（不得回 0x11 正常应答）"
        );
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !outside.join("evil.txt").exists(),
        "不得透过 junction 写出保存目录"
    );
    server.abort();
}
