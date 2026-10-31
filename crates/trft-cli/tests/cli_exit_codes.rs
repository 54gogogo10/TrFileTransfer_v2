//! CLI 层测试：退出码契约（规格 §3.6：0=成功，1=错误，2=用法）与
//! verify 的摘要缓存比对语义（审查轮7：CLI 层零测试缺口）。

use std::process::Command;
use std::time::Duration;

fn trft() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_trft"));
    c.current_dir(std::env::temp_dir());
    c
}

fn output(cmd: &mut Command) -> (i32, String, String) {
    let out = cmd.output().expect("子进程启动失败");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn usage_errors_exit_2() {
    // 配对码格式非法。
    let (code, _, _) = output(
        trft().args(["send", "--ip", "127.0.0.1", "--port", "1", "--file", "x", "--code", "12ab"]),
    );
    assert_eq!(code, 2, "非法配对码必须是用法错误（退出码 2）");
    // --passes 越界。
    let (code, _, _) = output(
        trft().args([
            "send",
            "--ip",
            "127.0.0.1",
            "--port",
            "1",
            "--file",
            "x",
            "--proto",
            "udp",
            "--passes",
            "9",
        ]),
    );
    assert_eq!(code, 2, "--passes 越界必须是用法错误");
    // --count 0。
    let (code, _, _) = output(trft().args(["recv", "--port", "1", "--count", "0"]));
    assert_eq!(code, 2, "--count 0 必须是用法错误");
    // 缺 --file/--text/--folder。
    let (code, _, _) = output(trft().args(["send", "--ip", "127.0.0.1", "--port", "1"]));
    assert_eq!(code, 2, "缺发送目标必须是用法错误");
    // clap 层（未知参数）也是 2。
    let (code, _, _) = output(trft().args(["send", "--nonsense"]));
    assert_eq!(code, 2, "clap 用法错误退出码 2");
}

#[test]
fn sync_unimplemented_exits_1() {
    let (code, _, stderr) = output(
        trft().args(["sync", "--folder", ".", "--ip", "127.0.0.1", "--port", "1"]),
    );
    assert_eq!(code, 1, "未实现的运行时错误退出码 1");
    assert!(stderr.contains("错误"), "应有错误信息: {stderr}");
}

#[test]
fn verify_detects_tampering_exit_1() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("doc.txt");
    std::fs::write(&f, b"original content").unwrap();

    // 第一次 verify：建立缓存基线 → 0。
    let (code, stdout, _) = output(trft().args(["verify", "--dir", dir.path().to_str().unwrap()]));
    assert_eq!(code, 0, "首次 verify（全为新记录）应成功: {stdout}");
    assert!(stdout.contains("新记录 1"), "应记录 1 个新条目: {stdout}");

    // 按原 mtime 篡改内容（绕过「大小+mtime 变化=未命中」的重新记录路径）。
    let old_mtime = std::fs::metadata(&f).unwrap().modified().unwrap();
    std::fs::write(&f, b"tampered content").unwrap();
    let f2 = std::fs::File::options().write(true).open(&f).unwrap();
    f2.set_modified(old_mtime).unwrap();
    drop(f2);

    // 第二次 verify：缓存命中但哈希不一致 → 退出码 1 + 指出文件。
    let (code, _, stderr) = output(trft().args(["verify", "--dir", dir.path().to_str().unwrap()]));
    assert_eq!(code, 1, "篡改必须退出码 1: {stderr}");
    assert!(stderr.contains("doc.txt"), "必须指出不一致文件: {stderr}");
}

#[test]
fn verify_all_fresh_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
    std::fs::write(dir.path().join("b.txt"), b"bbb").unwrap();
    let (code, stdout, _) = output(trft().args(["verify", "--dir", dir.path().to_str().unwrap()]));
    assert_eq!(code, 0);
    assert!(stdout.contains("新记录 2"));
    // 二次全命中。
    let (code, stdout, _) = output(trft().args(["verify", "--dir", dir.path().to_str().unwrap()]));
    assert_eq!(code, 0);
    assert!(stdout.contains("缓存核对 2"), "{stdout}");
}

#[test]
fn verify_missing_dir_exits_1() {
    let (code, _, stderr) = output(trft().args(["verify", "--dir", "Z:/definitely/not/exist"]));
    assert_eq!(code, 1);
    assert!(stderr.contains("目录不存在"));
}

// 保持 Duration 引用（避免未来在超时断言处重复导入告警）。
#[allow(dead_code)]
fn _t() -> Duration {
    Duration::from_secs(1)
}

#[test]
fn bad_target_ip_is_usage_error() {
    // 轮 5 P2：目标地址非法属参数格式错误 → 退出码 2（此前误归运行错误 1）。
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_trft"))
        .args(["send", "--ip", "not-an-ip", "--port", "8080", "--file", "x"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "坏 IP 必须退出 2");
}
