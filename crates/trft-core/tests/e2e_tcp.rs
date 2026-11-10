//! TCP 传输端到端测试：真实监听 + 真实发送（规格 §10.1 端到端集成风格）。

mod common;

use common::{ephemeral_listener, opts};
use rand_core::{OsRng, RngCore};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use trft_core::config::DuplicatePolicy;
use trft_core::error::Error;
use trft_core::hash::sha256_file;
use trft_core::transfer::receiver::{serve_on, RecvOptions};
use trft_core::transfer::sender::{send_file, send_text, SendOptions};

#[tokio::test]
async fn single_file_roundtrip_with_chinese_name() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("源文件 测试.bin");
    let mut data = vec![0u8; 3 * 1024 * 1024 + 777];
    OsRng.fill_bytes(&mut data);
    std::fs::write(&src, &data).unwrap();
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, opts(out.clone(), None, 1)));

    send_file(addr, &src, &SendOptions::default())
        .await
        .unwrap();
    timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let dest = out.join("源文件 测试.bin");
    assert_eq!(sha256_file(&dest).unwrap(), sha256_file(&src).unwrap());
    // 半成品已原子改名，目录里不残留任何 .trft-part（审查轮7：改为目录扫描）。
    let leftover: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".trft-part"))
        .collect();
    assert!(
        leftover.is_empty(),
        "残留: {:?}",
        leftover.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn pairing_success_and_missing_code_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("secret.txt");
    std::fs::write(&src, b"top secret").unwrap();
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, opts(out.clone(), Some("123456"), 1)));

    // 正确配对码 → 成功。
    let ok = SendOptions {
        pairing_code: Some("123456".into()),
        ..Default::default()
    };
    send_file(addr, &src, &ok).await.unwrap();

    // 无配对码 → 拒绝（fail-closed）；发送端必须见到错误。
    let r = send_file(addr, &src, &SendOptions::default()).await;
    assert!(matches!(r, Err(Error::Rejected(_)) | Err(Error::Io(_))));

    timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(out.join("secret.txt").exists());
}

#[tokio::test]
async fn text_roundtrip_then_second_file() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (tx, mut rx) = mpsc::unbounded_channel();

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(
        listener,
        RecvOptions {
            text_tx: Some(tx),
            ..opts(out.clone(), None, 2)
        },
    ));

    send_text(addr, "你好，局域网", &SendOptions::default())
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap(), "你好，局域网");

    let src = dir.path().join("b.bin");
    std::fs::write(&src, vec![1u8; 4096]).unwrap();
    send_file(addr, &src, &SendOptions::default())
        .await
        .unwrap();

    timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(out.join("b.bin").exists());
}

#[tokio::test]
async fn concurrent_same_name_no_crosswrite() {
    // 修复验证（审查轮1 P1-1）：并发同名 0x00 必须双双成功且内容互不污染。
    let dir = tempfile::tempdir().unwrap();
    // 两个同名源（不同目录、不同内容）：并发发送同名 img.jpg。
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let a = dir_a.path().join("img.jpg");
    let b = dir_b.path().join("img.jpg");
    let mut da = vec![1u8; 300_000];
    let mut db = vec![2u8; 300_000];
    OsRng.fill_bytes(&mut da);
    OsRng.fill_bytes(&mut db);
    std::fs::write(&a, &da).unwrap();
    std::fs::write(&b, &db).unwrap();
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(
        listener,
        RecvOptions {
            save_dir: out.clone(),
            max_count: None,
            ..opts(out.clone(), None, 1)
        },
    ));

    // 直接并发两个发送任务。
    let (a1, b1) = (a.clone(), b.clone());
    let f1 = tokio::spawn(async move { send_file(addr, &a1, &SendOptions::default()).await });
    let f2 = tokio::spawn(async move { send_file(addr, &b1, &SendOptions::default()).await });
    f1.await.unwrap().unwrap();
    f2.await.unwrap().unwrap();

    timeout(Duration::from_secs(5), async {
        loop {
            if out.join("img.jpg").exists() && out.join("img_1.jpg").exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();

    let h1 = sha256_file(&out.join("img.jpg")).unwrap();
    let h2 = sha256_file(&out.join("img_1.jpg")).unwrap();
    let ha = sha256_file(&a).unwrap();
    let hb = sha256_file(&b).unwrap();
    // 两份落盘文件必须各自与某个源完全一致（不出现混合内容）。
    assert!(
        (h1 == ha && h2 == hb) || (h1 == hb && h2 == ha),
        "并发同名不得产生混合内容"
    );
    server.abort();
}

#[tokio::test]
async fn pairing_lockout_after_ten_failures() {
    // 修复验证（审查轮2 P1）：配对失败 10 次 → IP 锁定，正确配对码也被拒。
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("s.txt");
    std::fs::write(&src, b"x").unwrap();
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, opts(out.clone(), Some("123456"), 1)));

    let wrong = SendOptions {
        pairing_code: Some("000000".into()),
        ..Default::default()
    };
    for i in 0..10 {
        let r = send_file(addr, &src, &wrong).await;
        assert!(r.is_err(), "第 {} 次错误配对码应失败", i + 1);
    }
    // 锁定生效：正确配对码同样被拒（fail-closed）。
    let correct = SendOptions {
        pairing_code: Some("123456".into()),
        ..Default::default()
    };
    let r = send_file(addr, &src, &correct).await;
    assert!(r.is_err(), "锁定期间正确配对码也应被拒");
    server.abort();
}

/// 手工构造明文 0x00 帧（绕过 sender），用于哈希不一致与明文组合测试。
async fn raw_send_file_broken_hash(
    addr: std::net::SocketAddr,
    name: &str,
    payload: &[u8],
    code: Option<&str>,
) -> Result<u8, Box<dyn std::error::Error>> {
    use trft_core::protocol::frame::{sanitize_name, T_SINGLE_FILE};
    use trft_core::protocol::io::{read_n, read_u8, write_all, write_str_u16, write_u64, write_u8};

    let mut s = tokio::net::TcpStream::connect(addr).await?;
    if let Some(code) = code {
        // 明文 0x05 门（协议 v2）：宣告 → 盐 → 证明。
        write_u8(&mut s, trft_core::protocol::frame::T_PAIRING).await?;
        let salt = read_n(&mut s, 16).await?;
        let k = trft_core::crypto::kdf::derive_pairing_key(code, &salt);
        let proof = trft_core::crypto::kdf::pairing_proof(&k, &salt);
        write_all(&mut s, &proof).await?;
        let st = read_u8(&mut s).await?;
        assert_eq!(st, trft_core::protocol::frame::STATUS_OK);
    }
    let name = sanitize_name(name)?;
    write_u8(&mut s, T_SINGLE_FILE).await?;
    write_str_u16(&mut s, &name).await?;
    write_u64(&mut s, payload.len() as u64).await?;
    write_all(&mut s, payload).await?;
    // 故意写错误哈希。
    write_all(&mut s, &trft_core::hash::sha256(b"wrong")).await?;
    let st = read_u8(&mut s).await?;
    Ok(st)
}

#[tokio::test]
async fn hash_mismatch_rejected_and_no_residue() {
    // 审查轮7：SHA-256 不一致 fail-closed 全链路（TCP 侧）——
    // 去掉接收端哈希比对本测试必须变红。
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, opts(out.clone(), None, 1)));

    let st = raw_send_file_broken_hash(addr, "bad.bin", b"payload bytes", None)
        .await
        .unwrap();
    assert_eq!(
        st,
        trft_core::protocol::frame::STATUS_REJECT,
        "坏哈希必须被拒绝"
    );
    server.abort(); // 错误连接不计入 served，直接收尾
    assert!(!out.join("bad.bin").exists(), "不得落盘");
    let leftover: Vec<_> = std::fs::read_dir(&out).unwrap().flatten().collect();
    assert!(leftover.is_empty(), "不得残留半成品");
}

#[tokio::test]
async fn plaintext_pairing_roundtrip_and_deterministic_reject() {
    // 审查轮8 F-1：明文 0x05 双码全链路 + 无码对有码的确定性拒绝（无 1/256 假成功）。
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("p.txt");
    std::fs::write(&src, b"plain text pairing").unwrap();
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(
        listener,
        RecvOptions {
            save_dir: out.clone(),
            pairing_code: Some("654321".into()),
            encrypt: false,
            max_count: Some(2),
            ..opts(out.clone(), Some("654321"), 2)
        },
    ));

    // 双码明文 → 成功。
    let ok = SendOptions {
        pairing_code: Some("654321".into()),
        encrypt: false,
        ..Default::default()
    };
    send_file(addr, &src, &ok).await.unwrap();

    // 无码明文 → 确定性拒绝（读到的状态字节必须是 0x00，而非随机的盐字节）。
    let st = raw_send_file_broken_hash(addr, "x.bin", b"zz", None)
        .await
        .unwrap();
    assert_eq!(
        st,
        trft_core::protocol::frame::STATUS_REJECT,
        "无码必须确定性拒绝"
    );

    server.abort();
    assert!(out.join("p.txt").exists());
}

#[tokio::test]
async fn empty_file_roundtrip() {
    // 审查轮7：0 字节文件路径（recv_single 跳过循环、空摘要、直接发布）。
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("empty.bin");
    std::fs::write(&src, b"").unwrap();
    let out = dir.path().join("out");

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(listener, opts(out.clone(), None, 1)));
    send_file(addr, &src, &SendOptions::default())
        .await
        .unwrap();
    timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(out.join("empty.bin").exists());
    assert_eq!(std::fs::read(out.join("empty.bin")).unwrap(), b"");
}

#[tokio::test]
async fn ipv6_loopback_roundtrip() {
    // 审查轮7：IPv6 双栈（::1 监听 + 发送）。
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("v6.bin");
    std::fs::write(&src, b"ipv6 payload").unwrap();
    let out = dir.path().join("out");

    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(serve_on(listener, opts(out.clone(), None, 1)));
    send_file(addr, &src, &SendOptions::default())
        .await
        .unwrap();
    timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(out.join("v6.bin").exists());
}

#[tokio::test]
async fn skip_modified_dest_keeps_renamed_copy() {
    // 审查轮7：Skip 且 dest 内容不同 → 必须改名保留新副本（不静默丢）。
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("a.txt");
    std::fs::write(&src, b"version-2").unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("a.txt"), b"version-1").unwrap();

    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(
        listener,
        RecvOptions {
            save_dir: out.clone(),
            duplicate: DuplicatePolicy::Skip,
            max_count: Some(1),
            ..opts(out.clone(), None, 1)
        },
    ));
    send_file(addr, &src, &SendOptions::default())
        .await
        .unwrap();
    timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), b"version-1");
    assert_eq!(std::fs::read(out.join("a_1.txt")).unwrap(), b"version-2");
}

/// 进度接线判别（M4'，规格 §3.1 100ms 节流）：0x00 收发两侧均有事件、
/// 终态 done == total。去掉任一侧接线本测试必红（无事件即失败）。
#[tokio::test]
async fn progress_events_wired_on_send_and_recv() {
    let dir = tempfile::tempdir().unwrap();
    let mut data = vec![0u8; 2 * 1024 * 1024 + 555]; // 跨多个 1MiB CHUNK
    OsRng.fill_bytes(&mut data);
    let src = dir.path().join("prog.bin");
    std::fs::write(&src, &data).unwrap();
    let out = dir.path().join("out");

    let (send_tx, mut send_rx) = mpsc::unbounded_channel();
    let (recv_tx, mut recv_rx) = mpsc::unbounded_channel();
    let send_hub = trft_core::progress::ProgressHub::new(send_tx);
    let recv_hub = trft_core::progress::ProgressHub::new(recv_tx);

    let (listener, addr) = ephemeral_listener().await;
    let mut ropts = opts(out.clone(), None, 1);
    ropts.progress = Some(recv_hub);
    let server = tokio::spawn(serve_on(listener, ropts));

    let mut sopts = SendOptions::default();
    sopts.progress = Some(send_hub.register("send", "prog.bin", 0));
    send_file(addr, &src, &sopts).await.unwrap();
    timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let total = data.len() as u64;
    let collect = |rx: &mut mpsc::UnboundedReceiver<trft_core::progress::ProgressEvent>| {
        let mut evs = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            evs.push(ev);
        }
        evs
    };

    let sevs = collect(&mut send_rx);
    assert!(!sevs.is_empty(), "发送侧无进度事件（接线缺失）");
    assert!(
        sevs.iter().any(|e| e.state == "running" && e.done > 0),
        "发送侧应有运行态事件: {sevs:?}"
    );
    let last = sevs.last().unwrap();
    assert_eq!(last.state, "done", "发送侧终态必为 done: {sevs:?}");
    assert_eq!(last.done, total, "发送侧终态字节数必须等于文件大小");
    assert_eq!(last.total, total);
    for w in sevs.windows(2) {
        assert!(w[1].done >= w[0].done, "done 必须单调不减: {sevs:?}");
    }

    let revs = collect(&mut recv_rx);
    assert!(!revs.is_empty(), "接收侧无进度事件（接线缺失）");
    let last = revs.last().unwrap();
    assert_eq!(last.state, "done", "接收侧终态必为 done: {revs:?}");
    assert_eq!(last.done, total, "接收侧终态字节数必须等于文件大小");
    assert_eq!(last.kind, "recv");
    // A5 对齐（原版 v2.15 DeviceDisplay.NameFor 接收侧）：接收事件必须携带对端 IP
    //（回环测试即 127.0.0.1）——UI 据此显示已知设备名徽标。
    assert!(
        revs.iter().all(|e| e.peer.as_deref() == Some("127.0.0.1")),
        "接收事件 peer 必须全为对端 IP: {:?}",
        revs.iter().map(|e| e.peer.clone()).collect::<Vec<_>>()
    );
}

/// SyncVerifyContent strict 判别（规格 §3.3）：二次同步默认位图全跳过（进度总量 0）；
/// strict 开启后接收侧完全绕过摘要缓存 → 全量重传（进度总量 == 文件总大小）。
/// 去掉 strict 旁路（回退 skip 判定）本测试必红。
#[tokio::test]
async fn sync_strict_verify_bypasses_digest_cache() {
    use trft_core::transfer::resume::{send_folder_resume, stable_session_id};

    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("a.bin"), vec![7u8; 300 * 1024]).unwrap();
    std::fs::write(src.join("b.bin"), vec![9u8; 200 * 1024]).unwrap();
    let out = dir.path().join("out");
    let full: u64 = 300 * 1024 + 200 * 1024;

    // 发送端缓存（正常路径免费携带哈希）。
    let cache = std::sync::Arc::new(tokio::sync::Mutex::new(
        trft_core::hashcache::HashCache::load(
            &trft_core::hashcache::cache_file_for(&src),
            trft_core::hashcache::DEFAULT_TTL_DAYS,
        ),
    ));

    let run_sync = |strict: bool| {
        let src = src.clone();
        let out = out.clone();
        let cache = cache.clone();
        async move {
            let (listener, addr) = ephemeral_listener().await;
            let (ptx, _prx) = mpsc::unbounded_channel();
            let hub = trft_core::progress::ProgressHub::new(ptx);
            let mut ropts = opts(out.clone(), None, 1);
            ropts.hash_cache = Some(std::sync::Arc::new(tokio::sync::Mutex::new(
                trft_core::hashcache::HashCache::load(
                    &trft_core::hashcache::cache_file_for(&out),
                    trft_core::hashcache::DEFAULT_TTL_DAYS,
                ),
            )));
            ropts.progress = Some(hub);
            ropts.strict_verify = strict;
            let server = tokio::spawn(serve_on(listener, ropts));

            let (stx, mut srx) = mpsc::unbounded_channel();
            let shub = trft_core::progress::ProgressHub::new(stx);
            let reporter = shub.register("send", "sync", 0);
            let sopts = SendOptions {
                progress: Some(reporter),
                ..Default::default()
            };
            let session = stable_session_id(&src, "sync-strict-test");
            send_folder_resume(addr, &src, &sopts, session, Some(&cache))
                .await
                .unwrap();
            timeout(Duration::from_secs(10), server)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            // 排空事件，取发送侧最后一个 running/done 的 total（= 位图差量汇总）。
            let mut total = 0u64;
            while let Ok(ev) = srx.try_recv() {
                if ev.total > 0 || ev.state == "done" {
                    total = ev.total;
                }
            }
            total
        }
    };

    // 首次：全量（总量 = 文件总大小）。
    assert_eq!(run_sync(false).await, full, "首同步必须全量");
    // 二次（非 strict）：位图差分全跳过 → 总量 0。
    assert_eq!(run_sync(false).await, 0, "二次同步应全跳过（缓存命中）");
    // 三次（strict）：绕过缓存 → 全量重传。
    assert_eq!(
        run_sync(true).await,
        full,
        "strict 必须绕过摘要缓存全量重传"
    );
}

/// IP 过滤判别（规格 §3.3）：deny 含对端 → 拒绝；allow 不含对端 → 拒绝；
/// allow 命中 → 放行。去掉 conn_precheck 的过滤钩子本测试必红。
#[tokio::test]
async fn ip_filter_blocks_and_allows() {
    use std::sync::Arc as StdArc;
    use tokio::sync::Mutex as TokioMutex;
    use trft_core::hashcache::{cache_file_for, HashCache, DEFAULT_TTL_DAYS};
    use trft_core::transfer::receiver::serve_on;

    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("f.bin");
    std::fs::write(&src, vec![1u8; 4096]).unwrap();

    let mk_opts = |mode: trft_core::config::FilterMode, list: Vec<String>| {
        let out = dir.path().join(format!(
            "out-{}-{}",
            mode == trft_core::config::FilterMode::Deny,
            list.len()
        ));
        RecvOptions {
            save_dir: out,
            ip_filter_mode: mode,
            ip_filter_list: list,
            hash_cache: Some(StdArc::new(TokioMutex::new(HashCache::load(
                &cache_file_for(&dir.path().join("c")),
                DEFAULT_TTL_DAYS,
            )))),
            ..Default::default()
        }
    };

    // deny 含回环 → 发送失败（接收器以错误退出属预期，不 unwrap 其结果）
    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(
        listener,
        mk_opts(
            trft_core::config::FilterMode::Deny,
            vec!["127.0.0.1".into()],
        ),
    ));
    let r = send_file(addr, &src, &SendOptions::default()).await;
    server.abort();
    assert!(r.is_err(), "deny 命中对端必须拒绝");

    // allow 不含回环 → 发送失败
    let (listener, addr) = ephemeral_listener().await;
    let server = tokio::spawn(serve_on(
        listener,
        mk_opts(
            trft_core::config::FilterMode::Allow,
            vec!["10.0.0.0/8".into()],
        ),
    ));
    let r = send_file(addr, &src, &SendOptions::default()).await;
    server.abort();
    assert!(r.is_err(), "allow 未命中必须拒绝");

    // allow 命中（CIDR）→ 成功且内容一致
    let (listener, addr) = ephemeral_listener().await;
    let o = mk_opts(
        trft_core::config::FilterMode::Allow,
        vec!["127.0.0.0/8".into()],
    );
    let out_path = o.save_dir.clone();
    let server = tokio::spawn(serve_on(listener, o));
    send_file(addr, &src, &SendOptions::default())
        .await
        .unwrap();
    server.abort();
    assert!(out_path.join("f.bin").is_file(), "allow 命中必须成功接收");
}
