//! M5' 接收选项判别 e2e：ConfirmReceive 三态（§3.3）、PerDeviceFolder 落点、
//! AutoArchive 叠加、0x04 缓存键一致性、UDP 目录解析。
//! 判别纪律：去掉对应接线（如 confirm 钩子 / resolve 目录）任一断言必红。

mod common;

use common::{ephemeral_listener, random_file, wait_server};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use trft_core::config::{ConfirmMode, DuplicatePolicy};
use trft_core::devices::{DeviceStore, DeviceInfo};
use trft_core::transfer::receiver::{ConfirmRequest, RecvOptions, serve_on};
use trft_core::transfer::resume::{send_file_auto, send_folder_resume, stable_session_id};
use trft_core::transfer::sender::{SendOptions, send_file};

fn dev(ip: &str, name: &str) -> DeviceInfo {
    DeviceInfo {
        name: name.into(),
        ip: ip.into(),
        port: 8080,
        proto: "tcp".into(),
        needs_pairing: false,
        last_seen: 0,
        source: trft_core::devices::DeviceSource::Transfer,
    }
}

fn confirm_channel() -> (
    mpsc::UnboundedSender<ConfirmRequest>,
    Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ConfirmRequest>>>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    (tx, Arc::new(tokio::sync::Mutex::new(rx)))
}

fn recv_base(save: std::path::PathBuf) -> RecvOptions {
    RecvOptions {
        save_dir: save,
        duplicate: DuplicatePolicy::Rename,
        max_count: Some(1),
        confirm_timeout: Duration::from_millis(300),
        ..Default::default()
    }
}

/// 回答下一个确认请求。
async fn answer_next(rx: &Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ConfirmRequest>>>, allow: bool) {
    let mut g = rx.lock().await;
    let req = timeout(Duration::from_secs(5), g.recv()).await.unwrap().expect("应有确认请求");
    let _ = req.reply.send(allow);
}

/// 并发应答者：确认请求到达即应答（发送端阻塞在载荷写，应答必须并发进行）。
fn spawn_answerer(
    rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ConfirmRequest>>>,
    allow: bool,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        answer_next(&rx, allow).await;
    })
}

/// 并发丢弃者：收到确认请求即整体丢弃（reply 随之关闭 = 无应答拒绝）。
fn spawn_dropper(
    rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ConfirmRequest>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut g = rx.lock().await;
        if let Some(req) = g.recv().await {
            drop(req); // 不应答
        }
    })
}

/// 拒绝路径收尾：限量模式对 handled=0 的连接不计数（既有语义），不等待
/// serve 收尾——给足处理时间后 abort，判定落在「发送失败 + 不落盘」上。
async fn settle_rejected(server: tokio::task::JoinHandle<Result<(), trft_core::error::Error>>) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    server.abort();
}

// ============ ConfirmReceive 三态 ============

#[tokio::test]
async fn confirm_all_accepts_after_reply() {
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "ok.bin", 4096);
    let out = dir.path().join("out");
    let (ctx, crx) = confirm_channel();
    let mut ro = recv_base(out.clone());
    ro.confirm_mode = ConfirmMode::All;
    ro.confirm_tx = Some(ctx);
    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, ro));
    let answerer = spawn_answerer(crx.clone(), true);

    send_file(addr, &src, &SendOptions::default()).await.unwrap();
    timeout(Duration::from_secs(5), answerer).await.unwrap().unwrap();
    wait_server(server).await;
    assert!(out.join("ok.bin").exists(), "确认通过后必须落盘");
}

#[tokio::test]
async fn confirm_all_rejects_denial_and_silence() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    // 拒绝应答：fail-closed 不落盘。
    {
        let (src, _) = random_file(dir.path(), "no.bin", 2048);
        let (ctx, crx) = confirm_channel();
        let mut ro = recv_base(out.clone());
        ro.confirm_mode = ConfirmMode::All;
        ro.confirm_tx = Some(ctx);
        let (listener, addr) = ephemeral_listener().await;
        let server = tokio::spawn(serve_on(listener, ro));
        let answerer = spawn_answerer(crx.clone(), false);
        let r = send_file(addr, &src, &SendOptions::default()).await;
        timeout(Duration::from_secs(5), answerer).await.unwrap().unwrap();
        assert!(r.is_err(), "拒绝应答必须使发送失败");
        settle_rejected(server).await;
        assert!(!out.join("no.bin").exists(), "拒绝后不得落盘");
    }
    // 无应答（应答端直接丢弃请求）= 拒绝（规格 §3.3）。
    {
        let (src, _) = random_file(dir.path(), "silent.bin", 2048);
        let (ctx, crx) = confirm_channel();
        let mut ro = recv_base(out.clone());
        ro.confirm_mode = ConfirmMode::All;
        ro.confirm_tx = Some(ctx);
        let (listener, addr) = ephemeral_listener().await;
        let server = tokio::spawn(serve_on(listener, ro));
        let dropper = spawn_dropper(crx.clone());
        let r = send_file(addr, &src, &SendOptions::default()).await;
        timeout(Duration::from_secs(5), dropper).await.unwrap().unwrap();
        assert!(r.is_err(), "无应答必须判拒绝（fail-closed）");
        settle_rejected(server).await;
        assert!(!out.join("silent.bin").exists());
    }
}

#[tokio::test]
async fn confirm_all_without_channel_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "nc.bin", 2048);
    let out = dir.path().join("out");
    let mut ro = recv_base(out.clone());
    ro.confirm_mode = ConfirmMode::All; // 要求确认但未注入通道
    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, ro));
    assert!(
        send_file(addr, &src, &SendOptions::default()).await.is_err(),
        "mode≠off 而通道缺省必须拒绝（fail-closed）"
    );
    settle_rejected(server).await;
    assert!(!out.join("nc.bin").exists());
}

#[tokio::test]
async fn confirm_unknown_passes_known_device_without_dialog() {
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "known.bin", 2048);
    let out = dir.path().join("out");
    let store = Arc::new(DeviceStore::in_memory());
    store.upsert(dev("127.0.0.1", "本机测试"));
    let (ctx, crx) = confirm_channel();
    let mut ro = recv_base(out.clone());
    ro.confirm_mode = ConfirmMode::Unknown;
    ro.confirm_tx = Some(ctx);
    ro.devices = Some(store);
    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, ro));
    send_file(addr, &src, &SendOptions::default()).await.unwrap();
    wait_server(server).await;
    assert!(out.join("known.bin").exists());
    assert!(
        crx.lock().await.try_recv().is_err(),
        "已知设备不得弹确认（规格 §3.3 unknown 语义）"
    );
}

#[tokio::test]
async fn confirm_same_ip_remembered_within_window() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (ctx, crx) = confirm_channel();
    let mut ro = recv_base(out.clone());
    ro.confirm_mode = ConfirmMode::All;
    ro.confirm_tx = Some(ctx);
    // 两轮共享同一 RecvOptions（Clone 共享 confirm_seen——与生产 GUI 单例同口径）。
    for i in 0..2 {
        let (src, _) = random_file(dir.path(), &format!("w{i}.bin"), 1024);
        let (listener, addr) = ephemeral_listener().await;
        let server = tokio::spawn(serve_on(listener, ro.clone()));
        if i == 0 {
            let answerer = spawn_answerer(crx.clone(), true);
            send_file(addr, &src, &SendOptions::default()).await.unwrap();
            timeout(Duration::from_secs(5), answerer).await.unwrap().unwrap();
        } else {
            // 窗口内第二次：不挂应答者——窗口失效（重弹确认）则 send_file 必失败。
            send_file(addr, &src, &SendOptions::default()).await.unwrap();
        }
        wait_server(server).await;
    }
    assert!(
        crx.lock().await.try_recv().is_err(),
        "同 IP 10 分钟内第二次传输不得重复弹窗"
    );
    assert!(out.join("w0.bin").exists() && out.join("w1.bin").exists());
}

// ============ PerDeviceFolder / AutoArchive ============

#[tokio::test]
async fn per_device_folder_routes_by_remembered_name() {
    let dir = tempfile::tempdir().unwrap();
    let (src, data) = random_file(dir.path(), "routed.bin", 4096);
    let out = dir.path().join("out");
    let store = Arc::new(DeviceStore::in_memory());
    store.upsert(dev("127.0.0.1", "设备甲"));
    let mut ro = recv_base(out.clone());
    ro.per_device_folder = true;
    ro.devices = Some(store);
    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, ro));
    send_file(addr, &src, &SendOptions::default()).await.unwrap();
    wait_server(server).await;

    let today = trft_core::transfer::receiver::today_component();
    let dest = out.join("设备甲").join("routed.bin");
    assert!(dest.exists(), "已知设备按记忆名分目录");
    assert_eq!(std::fs::read(&dest).unwrap(), data);
    assert!(!out.join("routed.bin").exists(), "根目录不得出现副本");
    let _ = today;
}

#[tokio::test]
async fn per_device_unknown_falls_back_to_ip() {
    let dir = tempfile::tempdir().unwrap();
    let (src, _) = random_file(dir.path(), "anon.bin", 2048);
    let out = dir.path().join("out");
    let mut ro = recv_base(out.clone());
    ro.per_device_folder = true; // 无 DeviceStore
    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, ro));
    send_file(addr, &src, &SendOptions::default()).await.unwrap();
    wait_server(server).await;
    assert!(
        out.join("127.0.0.1").join("anon.bin").exists(),
        "未知设备回退 IP 目录"
    );
}

#[tokio::test]
async fn auto_archive_alone_and_combined_ordering() {
    let dir = tempfile::tempdir().unwrap();
    let today = trft_core::transfer::receiver::today_component();
    // 仅归档：<save>/<日期>/。
    {
        let (src, _) = random_file(dir.path(), "arch.bin", 2048);
        let out = dir.path().join("out1");
        let mut ro = recv_base(out.clone());
        ro.auto_archive = true;
        let (listener, addr) = ephemeral_listener().await;
        let server = tokio::spawn(serve_on(listener, ro));
        send_file(addr, &src, &SendOptions::default()).await.unwrap();
        wait_server(server).await;
        assert!(out.join(&today).join("arch.bin").exists(), "仅归档：<日期>/ 一层");
        assert_eq!(
            out.join(&today).read_dir().unwrap().count(),
            1,
            "仅归档时日期下不得再有设备层"
        );
    }
    // 叠加：<save>/<设备>/<日期>/（用户拍板顺序）。
    {
        let (src, _) = random_file(dir.path(), "both.bin", 2048);
        let out = dir.path().join("out2");
        let store = Arc::new(DeviceStore::in_memory());
        store.upsert(dev("127.0.0.1", "设备乙"));
        let mut ro = recv_base(out.clone());
        ro.per_device_folder = true;
        ro.auto_archive = true;
        ro.devices = Some(store);
        let (listener, addr) = ephemeral_listener().await;
        let server = tokio::spawn(serve_on(listener, ro));
        send_file(addr, &src, &SendOptions::default()).await.unwrap();
        wait_server(server).await;
        assert!(
            out.join("设备乙").join(&today).join("both.bin").exists(),
            "叠加顺序必须是 <设备>/<日期>/"
        );
    }
}

/// 0x04 同步在分目录下的缓存键一致性：二次同步必须全跳过（键口径错位即红）。
#[tokio::test]
async fn sync_per_device_bitmap_skip_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let src_root = dir.path().join("proj");
    std::fs::create_dir_all(&src_root).unwrap();
    random_file(&src_root, "a.txt", 2048);
    let out = dir.path().join("out");
    let store = Arc::new(DeviceStore::in_memory());
    store.upsert(dev("127.0.0.1", "同步机"));
    let make_ro = |cache: bool| {
        let mut ro = RecvOptions {
            save_dir: out.clone(),
            duplicate: DuplicatePolicy::Rename,
            per_device_folder: true,
            devices: Some(store.clone()),
            max_count: Some(1),
            ..Default::default()
        };
        if cache {
            ro.hash_cache = Some(Arc::new(tokio::sync::Mutex::new(
                trft_core::hashcache::HashCache::load(
                    &trft_core::hashcache::cache_file_for(&out),
                    7,
                ),
            )));
        }
        ro
    };

    // 发送端缓存：首跑传输中免费回填，次跑清单携带哈希 → 服务端位图判跳过。
    let cache = Arc::new(tokio::sync::Mutex::new(trft_core::hashcache::HashCache::load(
        &trft_core::hashcache::cache_file_for(&src_root),
        7,
    )));

    // 第一次同步（清单无哈希 → 全发；发送端缓存回填）。
    let (l1, a1) = ephemeral_listener().await;
    let s1 = tokio::spawn(serve_on(l1, make_ro(false)));
    send_folder_resume(a1, &src_root, &SendOptions::default(), stable_session_id(&src_root, "t"), Some(&cache))
        .await
        .unwrap();
    timeout(Duration::from_secs(10), s1).await.unwrap().unwrap().unwrap();
    assert!(
        out.join("同步机").join("proj").join("a.txt").exists(),
        "分目录下 0x04 根目录落点"
    );

    // 第二次同步（清单携带缓存哈希 → 位图全跳过，总传输量 0）。
    let (stx, mut srx) = mpsc::unbounded_channel();
    let shub = trft_core::progress::ProgressHub::new(stx);
    let sopts = SendOptions { progress: Some(shub.register("send", "sync2", 0)), ..Default::default() };
    let (l2, a2) = ephemeral_listener().await;
    let s2 = tokio::spawn(serve_on(l2, make_ro(true)));
    send_folder_resume(a2, &src_root, &sopts, stable_session_id(&src_root, "t"), Some(&cache))
        .await
        .unwrap();
    timeout(Duration::from_secs(10), s2).await.unwrap().unwrap().unwrap();
    let sent: u64 = std::iter::from_fn(|| srx.try_recv().ok())
        .filter_map(|ev| if ev.state == "done" { Some(ev.done) } else { None })
        .last()
        .unwrap_or(0);
    assert_eq!(sent, 0, "分目录下二次同步必须全跳过（缓存键与落盘键同口径）");
}

/// 轮 1 P1 判别：0x03 冲突改名后缓存键必须跟最终路径——
/// 投毒时「同尺寸不同内容重发」被静默 skip（假成功红线）；修复后必须真收成 same_2.bin。
#[tokio::test]
async fn resume_conflict_no_cache_poisoning() {
    use trft_core::hashcache::{cache_file_for, HashCache};
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let cache_path = cache_file_for(&out);
    let old = vec![7u8; 100];
    let new = vec![9u8; 100]; // 同尺寸不同内容
    std::fs::write(out.join("same.bin"), &old).unwrap();

    let make_ro = || {
        RecvOptions {
            save_dir: out.clone(),
            // Skip 口径：0x03 的缓存 skip 判定只在 Skip 模式下运行——投毒在此咬人。
            duplicate: DuplicatePolicy::Skip,
            max_count: Some(1),
            hash_cache: Some(Arc::new(tokio::sync::Mutex::new(HashCache::load(
                &cache_path,
                7,
            )))),
            ..Default::default()
        }
    };

    // 第一次：发 new 内容（与磁盘旧文件同尺寸；源文件名必须同为 same.bin 才冲突）。
    let f1 = dir.path().join("same.bin");
    std::fs::write(&f1, &new).unwrap();
    let (l1, a1) = common::ephemeral_listener().await;
    let s1 = tokio::spawn(serve_on(l1, make_ro()));
    send_file_auto(a1, &f1, &SendOptions::default()).await.unwrap();
    timeout(Duration::from_secs(10), s1).await.unwrap().unwrap().unwrap();
    assert!(out.join("same_1.bin").exists());
    assert_eq!(std::fs::read(out.join("same.bin")).unwrap(), old, "旧文件不得被覆盖");

    // 第二次：再发同一 new 内容 → skip 判定若命中投毒条目会零传输（假成功）。
    let (l2, a2) = common::ephemeral_listener().await;
    let s2 = tokio::spawn(serve_on(l2, make_ro()));
    send_file_auto(a2, &f1, &SendOptions::default()).await.unwrap();
    timeout(Duration::from_secs(10), s2).await.unwrap().unwrap().unwrap();

    // 修复后：磁盘 same.bin 仍是旧内容 → 不得判 skip → 必须真收 → same_2.bin。
    assert!(
        out.join("same_2.bin").exists(),
        "同尺寸不同内容重发不得被缓存误判 skip（缓存投毒红线）"
    );
    assert_eq!(std::fs::read(out.join("same_2.bin")).unwrap(), new);
}

/// 轮 4 P0 判别：0x03 偏移权威 = 服务端磁盘事实。
/// 连接 1：声明 size=100、declared=0，只发 5 字节即断开（半成品+meta 保留）；
/// 连接 2：declared=99 放大声明——服务端必须回 offset=5（磁盘事实），
/// 修复前 max(声明,实际) 回 99：1MiB 级输入即可绕过磁盘预检写满整盘。
#[tokio::test]
async fn resume_offset_authority_is_server_disk() {
    use trft_core::hash::sha256;
    use trft_core::protocol::frame::{R_RESUME_NEGO, STATUS_OK, T_RESUME_FILE};
    use trft_core::protocol::io::{read_u8, read_u64, write_all, write_str_u16, write_u64, write_u8};

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let data = vec![42u8; 100];
    let claimed = sha256(&data);

    // 连接 1：只发 5 字节载荷即断开。
    {
        let (listener, addr) = ephemeral_listener().await;
        let server = tokio::spawn(serve_on(listener, recv_base(out.clone())));
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        write_u8(&mut s, T_RESUME_FILE).await.unwrap();
        write_str_u16(&mut s, "poc.bin").await.unwrap();
        write_u64(&mut s, 100).await.unwrap();
        write_u64(&mut s, 0).await.unwrap(); // declared=0
        write_u8(&mut s, 1).await.unwrap();
        write_all(&mut s, &claimed).await.unwrap();
        // 读协商应答后只发 5 字节。
        let first = read_u8(&mut s).await.unwrap();
        assert_eq!(first, R_RESUME_NEGO);
        let st = read_u8(&mut s).await.unwrap();
        let off = read_u64(&mut s).await.unwrap();
        assert_eq!((st, off), (STATUS_OK, 0), "全新会话应从 0 起");
        write_all(&mut s, &data[..5]).await.unwrap();
        drop(s); // 掐断——半成品保留（续传语义）
        tokio::time::sleep(Duration::from_millis(200)).await;
        server.abort();
    }
    // 半成品保留为 0 字节（载荷按整块读取，短传即全无）——正是 PoC 场景：
    // 0 字节半成品 + meta 合法，客户端随后声明巨大 offset。
    let part = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .find(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n.ends_with(".trft-resume") && !n.ends_with(".meta")
        })
        .expect("半成品应保留");
    assert_eq!(part.metadata().unwrap().len(), 0);

    // 连接 2：declared=99 放大声明。
    {
        let (listener, addr) = ephemeral_listener().await;
        let server = tokio::spawn(serve_on(listener, recv_base(out.clone())));
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        write_u8(&mut s, T_RESUME_FILE).await.unwrap();
        write_str_u16(&mut s, "poc.bin").await.unwrap();
        write_u64(&mut s, 100).await.unwrap();
        write_u64(&mut s, 99).await.unwrap(); // 放大声明
        write_u8(&mut s, 1).await.unwrap();
        write_all(&mut s, &claimed).await.unwrap();
        let first = read_u8(&mut s).await.unwrap();
        assert_eq!(first, R_RESUME_NEGO);
        let st = read_u8(&mut s).await.unwrap();
        let off = read_u64(&mut s).await.unwrap();
        assert_eq!(
            (st, off),
            (STATUS_OK, 0),
            "偏移权威必须是磁盘事实（0），客户端声明（99）不得生效"
        );
        server.abort();
    }
}
