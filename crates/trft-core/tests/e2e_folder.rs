//! 0x01 文件夹传输端到端测试：嵌套目录、中文名、根目录冲突改名。

mod common;

use common::{ephemeral_listener, opts};
use rand_core::{OsRng, RngCore};
use std::time::Duration;
use tokio::time::timeout;
use trft_core::config::DuplicatePolicy;
use trft_core::hash::sha256_file;
use trft_core::transfer::folder::send_folder;
use trft_core::transfer::receiver::{serve_on, RecvOptions};
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
    send_folder(addr, &src, &SendOptions::default())
        .await
        .unwrap();
    timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

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
    send_folder(addr2, &src, &SendOptions::default())
        .await
        .unwrap();
    timeout(Duration::from_secs(10), server2)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
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
    send_folder(addr, &src, &SendOptions::default())
        .await
        .unwrap();
    send_folder(addr, &src, &SendOptions::default())
        .await
        .unwrap();
    timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert!(out.join("lib").join("same.bin").exists());
    assert!(
        !out.join("lib_1").join("same.bin").exists(),
        "同内容副本应被丢弃（不产生 lib_1）"
    );
}

/// 轮 1 F3 判别：0x01 文件夹发送必须遵循 opts.encrypt——服务端关加密
/// （0x09 首帧必拒）+ 客户端开加密 → 发送必须失败。修复前 send_folder 直连
/// 明文（忽略 encrypt）→ 发送假性成功，本测试必红。
#[tokio::test]
async fn folder_send_honors_encrypt_option() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("sec");
    make_file(&src.join("secret.bin"), 1024);
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(
        listener,
        RecvOptions {
            save_dir: out.clone(),
            encrypt: false, // 服务端拒绝 0x09 升级
            max_count: Some(1),
            ..Default::default()
        },
    ));
    // 客户端默认 encrypt=true → 必须走 0x09 → 被服务端拒绝 → 发送失败。
    let r = send_folder(addr, &src, &SendOptions::default()).await;
    assert!(
        r.is_err(),
        "服务端拒绝 0x09 时，开加密的文件夹发送必须失败（不得静默明文降级）"
    );
    // 服务端不得收到任何文件。
    let _ = server.abort();
    assert!(
        !out.join("sec").join("secret.bin").exists(),
        "明文降级路径不得落盘"
    );
    common::assert_no_leftovers(&out);
}

/// 轮 1 F5 判别：0x06 载荷非法（声明超 1MB）必须收到**拒绝字节**而非 EOF——
/// 修复前服务端直接 `?` 断连，客户端只见「连接中断」（违反「处理后必回」）。
#[tokio::test]
async fn oversize_text_gets_reject_byte_not_eof() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, opts(out.clone(), None, 1)));
    // 手工裸帧（合法 send_text 客户端会在本地就拦截超限文本，测不到服务端路径）。
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(&[0x06]).await.unwrap(); // T_TEXT
    sock.write_all(&((1024 * 1024 + 1) as u32).to_le_bytes())
        .await
        .unwrap(); // 声明超限
    sock.flush().await.unwrap();
    let mut b = [0u8; 1];
    let n = timeout(Duration::from_secs(5), sock.read(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 1, "必须收到拒绝字节而非直接 EOF");
    assert_eq!(b[0], 0x00, "超限文本应答拒绝字节 0x00");
    let _ = server.abort();
}

/// 轮 6 P2-5 判别：文件夹 0x01 失败后必须自动转 0x04 差量续传收敛
/// （规格 §3.2 AutoRetry「文件夹失败后转 0x04」——此前失败永远从零重发，
/// 即直接报错）。测试编排：前置代理对第 1 条连接读 100 字节即掐断
/// （模拟传输中断），其后连接全量转发到真实接收器。
#[tokio::test]
async fn folder_send_falls_back_to_resume_after_failure() {
    use tokio::io::AsyncReadExt as _;
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("proj");
    make_file(&src.join("a.bin"), 8192);
    make_file(&src.join("b.bin"), 4096);
    let out = dir.path().join("out");

    // 真实接收器（常驻）。
    let (backend, b_addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(backend, common::opts_resident(out.clone(), None)));

    // 前置代理：第 1 条连接掐断，其后双向转发。
    let (front, f_addr) = ephemeral_listener().await;
    let proxy = tokio::spawn(async move {
        let mut conn_no = 0u32;
        loop {
            let Ok((mut c, _)) = front.accept().await else {
                return;
            };
            conn_no += 1;
            if conn_no == 1 {
                // 模拟传输中断：读一小段后丢弃连接。
                let mut b = [0u8; 100];
                let _ = c.read(&mut b).await;
                drop(c);
                continue;
            }
            let up = match tokio::net::TcpStream::connect(b_addr).await {
                Ok(u) => u,
                Err(_) => return,
            };
            let (mut cr, mut cw) = c.into_split();
            let (mut ur, mut uw) = up.into_split();
            let t1 = tokio::spawn(async move {
                let _ = tokio::io::copy(&mut cr, &mut uw).await;
            });
            let t2 = tokio::spawn(async move {
                let _ = tokio::io::copy(&mut ur, &mut cw).await;
            });
            let _ = t1.await;
            let _ = t2.await;
        }
    });

    let opts = SendOptions::default();
    trft_core::transfer::folder::send_folder_auto(f_addr, &src, &opts)
        .await
        .expect("0x01 中断后必须经 0x04 差量续传收敛（规格 §3.2 AutoRetry）");
    assert!(out.join("proj").join("a.bin").exists(), "文件 a 必须落盘");
    assert!(out.join("proj").join("b.bin").exists(), "文件 b 必须落盘");
    common::assert_no_leftovers(&out);
    server.abort();
    proxy.abort();
}
