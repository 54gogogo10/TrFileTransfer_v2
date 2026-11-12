//! 跨进程集成：真实 `trft recv` / `trft send` 子进程全链路。
//!
//! 既有 cli_exit_codes 只测错误路径的退出码；此处覆盖「参数解析 → 监听 →
//! 0x03 断点续传发送 → 落盘 → 收满自退」的真实二进制进程间链路。

use std::process::{Command, Stdio};
use std::time::Duration;

fn trft() -> Command {
    Command::new(env!("CARGO_BIN_EXE_trft"))
}

/// 空闲 TCP 端口（绑定即关——与接收器真实绑定间存在极小竞窗，core e2e 同口径）。
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn recv_send_roundtrip_via_real_processes() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    // 1 MiB + 777（非整块尾）确定性内容（LCG 填充，避免引随机依赖）。
    let src = dir.path().join("cli 传输 测试.bin");
    let mut data = vec![0u8; 1024 * 1024 + 777];
    let mut x: u32 = 0x1234_5678;
    for b in data.iter_mut() {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    std::fs::write(&src, &data).unwrap();

    let port = free_port().to_string();

    // 接收端：收满 1 个文件自退（--count 1）。
    let mut recv = trft()
        .args([
            "recv",
            "--port",
            &port,
            "--out",
            out.to_str().unwrap(),
            "--count",
            "1",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn recv");

    // 轮询发送直到成功（接收器绑定就绪前 send 会连接失败，成功即止）。
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut sent_ok = false;
    while std::time::Instant::now() < deadline {
        let st = trft()
            .args([
                "send",
                "--ip",
                "127.0.0.1",
                "--port",
                &port,
                "--file",
                src.to_str().unwrap(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .status();
        if matches!(st, Ok(s) if s.success()) {
            sent_ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    assert!(sent_ok, "send 20s 内未成功（接收器未就绪或传输失败）");

    let rx = recv.wait().expect("wait recv");
    assert!(
        rx.success(),
        "recv 必须以 0 退出（--count 1 收满即退），实际 {rx}"
    );
    assert_eq!(
        std::fs::read(out.join("cli 传输 测试.bin")).unwrap(),
        data,
        "跨进程传输必须逐字节保真"
    );
}

/// UDT4 槽位跨进程链路（TECH-STACK §7.30）：`trft recv --proto udt` × `trft send
/// --proto udt` 真实子进程；空闲 UDP 端口 + 收满自退 + SHA-256 级逐字节保真。
#[test]
fn recv_send_roundtrip_via_udt_processes() {
    use std::net::UdpSocket;

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();

    // 256 KiB + 33 确定性内容（LCG 填充）。
    let src = dir.path().join("udt-cli.bin");
    let mut data = vec![0u8; 256 * 1024 + 33];
    let mut x: u32 = 0x1234_5678u32.wrapping_add(0x0BAD_F00D);
    for b in data.iter_mut() {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    std::fs::write(&src, &data).unwrap();

    let port = {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    }
    .to_string();

    let mut recv = trft()
        .args([
            "recv",
            "--proto",
            "udt",
            "--port",
            &port,
            "--out",
            out.to_str().unwrap(),
            "--count",
            "1",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn recv");

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut sent_ok = false;
    while std::time::Instant::now() < deadline {
        let st = trft()
            .args([
                "send",
                "--proto",
                "udt",
                "--ip",
                "127.0.0.1",
                "--port",
                &port,
                "--file",
                src.to_str().unwrap(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .status();
        if matches!(st, Ok(s) if s.success()) {
            sent_ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    assert!(sent_ok, "UDT send 20s 内未成功（握手/引擎故障）");

    let rx = recv.wait().expect("wait recv");
    assert!(rx.success(), "UDT recv 必须以 0 退出，实际 {rx}");
    assert_eq!(
        std::fs::read(out.join("udt-cli.bin")).unwrap(),
        data,
        "UDT 跨进程传输必须逐字节保真"
    );
}
