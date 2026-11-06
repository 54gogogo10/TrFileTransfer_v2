//! 监控模式（规格 §3.2）：监控「落料」目录，文件就绪即自动发出。
//!
//! 可靠性口径（TECH-STACK §7.10，用户拍板「绝对可靠」）：
//! - **周期全量扫描是唯一事实来源**（不丢事件）；目录事件侦听（notify）仅作
//!   **提前扫描触发器**——事件不承载任何判定；事件层初始化失败自动退化为
//!   纯轮询，功能零损失。
//! - **拷贝完成判定 = 双重门**：独占打开成功（Windows share-none）+ 500ms
//!   大小/mtime 稳定窗——半截文件与「0 字节占位后填充」不得发出。
//! - 队列语义：未就绪文件**后移一位**（队首让给下一个文件，本文件下一轮
//!   重试，不阻塞队首）；已消失文件直接丢弃；未就绪/失败日志按文件节流
//!   （首报立即、后续 60 秒一次）；成功后移入「已发送文件/」（重名追加序号）。

use crate::error::{Error, Result, config_err};
use crate::transfer::resume::send_file_auto;
use crate::transfer::sender::SendOptions;
use crate::transfer::udp::{send_file_udp, UdpSendOptions};
use crate::transfer::Transport;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

/// 「已发送文件/」目录名（规格 §3.2 字面）。
pub const SENT_DIR: &str = "已发送文件";
/// 默认轮询间隔（扫描为唯一事实来源；事件仅加速）。
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// 拷贝完成稳定窗（规格 §3.2：500ms 大小稳定）。
pub const STABLE_WINDOW: Duration = Duration::from_millis(500);
/// 未就绪/失败日志按文件节流（首报立即、后续 60 秒一次——规格 §3.2）。
const LOG_THROTTLE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, serde::Serialize)]
pub enum MonitorEvent {
    Queued { name: String, queue_len: usize },
    NotReady { name: String },
    Dropped { name: String },
    Sending { name: String },
    Sent { name: String, to: String },
    Failed { name: String, error: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorProto {
    Tcp,
    Quic,
    Udp,
}

pub struct MonitorConfig {
    pub watch_dir: PathBuf,
    pub addr: SocketAddr,
    pub proto: MonitorProto,
    /// 流式发送选项（Tcp/Quic；Udp 模式忽略）。
    pub send_opts: SendOptions,
    /// 单向 UDP 选项（Udp 模式必填）。
    pub udp_opts: UdpSendOptions,
    pub poll_interval: Duration,
    pub stable_window: Duration,
    /// 事件出口（GUI 面板；None = 仅日志）。
    pub events: Option<mpsc::UnboundedSender<MonitorEvent>>,
    /// 停止信号（true = 停）。
    pub stop: watch::Receiver<bool>,
}

impl MonitorConfig {
    pub fn new(watch_dir: PathBuf, addr: SocketAddr, proto: MonitorProto, stop: watch::Receiver<bool>) -> Self {
        Self {
            watch_dir,
            addr,
            proto,
            send_opts: SendOptions { transport: Transport::Tcp, ..Default::default() },
            udp_opts: UdpSendOptions::default(),
            poll_interval: POLL_INTERVAL,
            stable_window: STABLE_WINDOW,
            events: None,
            stop,
        }
    }

    fn emit(&self, ev: MonitorEvent) {
        if let Some(tx) = &self.events {
            let _ = tx.send(ev);
        }
    }
}

/// 入口：启动全量扫描 + 主循环。返回前保证停止信号已消费（GUI abort 亦可）。
pub async fn run_monitor(cfg: MonitorConfig) -> Result<()> {
    if !cfg.watch_dir.is_dir() {
        return Err(config_err(format!("监控目录不存在: {}", cfg.watch_dir.display())));
    }
    // 事件加速器：任何 FS 事件 → 提前触发一次扫描（失败 = 纯轮询，零损失）。
    use notify::Watcher;
    let (tick_tx, mut tick_rx) = mpsc::unbounded_channel::<()>();
    let _watcher = notify::recommended_watcher(move |_| {
        let _ = tick_tx.send(());
    })
    .map(|mut w| {
        w.watch(&cfg.watch_dir, notify::RecursiveMode::NonRecursive).ok();
        w
    })
    .map_err(|e| eprintln!("[监控] 事件侦听不可用（纯轮询模式）: {e}"))
    .ok();

    let mut queue: VecDeque<PathBuf> = VecDeque::new();
    let mut queued: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    // 已发送待归档（轮 5 P1）：发送成功但移入「已发送文件/」失败——
    // 不得重发（无限重传放大），仅重试归档。
    let mut pending_archive: Vec<PathBuf> = Vec::new();
    let mut throttle: HashMap<String, Instant> = HashMap::new();
    let mut mut_stop = cfg.stop.clone();

    // 启动全量扫描（规格 §3.2）。
    for f in scan_dir(&cfg.watch_dir) {
        queued.insert(f.clone());
        queue.push_back(f);
    }
    for q in &queue {
        cfg.emit(MonitorEvent::Queued { name: file_name(q), queue_len: queue.len() });
    }

    loop {
        // 等待：事件 tick / 轮询间隔 / 停止（三者任一）。
        tokio::select! {
            _ = tokio::time::sleep(cfg.poll_interval) => {}
            _ = tick_rx.recv() => {}
            // changed() 就绪 = 有新变更或通道已关闭——协议上两者都是停止
            // （发送端只发 true）。直接退出；不得再查 has_changed()
            //（changed() 已把变更标记为已读 → 恒 false → 永不退出）。
            _ = mut_stop.changed() => {
                break;
            }
        }
        // 排空积压 tick（事件风暴防自旋：一轮只触发一次扫描）。
        while tick_rx.try_recv().is_ok() {}

        // 扫描新文件（唯一事实来源）：入队去重（已发送/已消失的不再出现）。
        for f in scan_dir(&cfg.watch_dir) {
            if queued.insert(f.clone()) {
                cfg.emit(MonitorEvent::Queued { name: file_name(&f), queue_len: queue.len() + 1 });
                queue.push_back(f);
            }
        }
        // 待归档重试（每轮一次；事件经节流通道，规格 §3.2）。
        pending_archive.retain(|p| {
            match move_to_sent(&cfg.watch_dir, p) {
                Ok(dest) => {
                    queued.remove(p);
                    cfg.emit(MonitorEvent::Sent { name: file_name(p), to: dest.display().to_string() });
                    false
                }
                Err(e) => {
                    let n = file_name(p);
                    throttled_log(&mut throttle, &n, || {
                        cfg.emit(MonitorEvent::Failed { name: n.clone(), error: format!("归档失败: {e}") });
                    });
                    true
                }
            }
        });

        let Some(front) = queue.front().cloned() else {
            continue; // 空队列：回到等待
        };
        let name = file_name(&front);

        // 已消失文件直接丢弃（规格 §3.2）。
        if !front.is_file() {
            queue.pop_front();
            queued.remove(&front);
            cfg.emit(MonitorEvent::Dropped { name });
            continue;
        }

        // 拷贝完成判定（双重门；阻塞窗在 blocking 池）。
        // check_path 已由 scan_dir 拼好（= watch_dir 下的完整路径），**不得**再
        // join 一次 watch_dir——相对监控目录会被拼成 "drop/drop/a.bin"，
        // metadata 恒失败 → 文件永远判不就绪（本轮 F2）。
        let window = cfg.stable_window;
        let check_path = front.clone();
        let ready = tokio::task::spawn_blocking(move || copy_complete(&check_path, window))
            .await
            .unwrap_or(false);
        if !ready {
            // 后移一位：队首让给下一个文件，本文件下一轮重试（规格 §3.2）。
            if queue.len() > 1 {
                queue.swap(0, 1);
            }
            throttled_log(&mut throttle, &name, || {
                cfg.emit(MonitorEvent::NotReady { name: name.clone() });
            });
            // 未就绪重查无意义（至少隔一个稳定窗）——按轮询节律等下一拍；
            // select 停止信号（轮 3 P3：此前 stop 最坏延迟 poll+窗口 ≈1.6s）。
            tokio::select! {
                _ = tokio::time::sleep(cfg.poll_interval) => {}
                _ = mut_stop.changed() => {
                    return Ok(());
                }
            }
            continue;
        }

        cfg.emit(MonitorEvent::Sending { name: name.clone() });
        let res = match cfg.proto {
            MonitorProto::Udp => send_file_udp(cfg.addr, &front, &cfg.udp_opts).await,
            MonitorProto::Tcp => {
                let mut o = cfg.send_opts.clone();
                o.transport = Transport::Tcp;
                send_file_auto(cfg.addr, &front, &o).await
            }
            MonitorProto::Quic => {
                let mut o = cfg.send_opts.clone();
                o.transport = Transport::Quic;
                send_file_auto(cfg.addr, &front, &o).await
            }
        };
        match res {
            Ok(()) => {
                queue.pop_front();
                match move_to_sent(&cfg.watch_dir, &front) {
                    Ok(dest) => {
                        queued.remove(&front);
                        eprintln!("[监控] 已发送并归档 {name} → {}", dest.display());
                        cfg.emit(MonitorEvent::Sent { name, to: dest.display().to_string() });
                    }
                    // 归档失败（轮 5 P1）：文件已成功送达对端——绝不重发；
                    // 留在 queued 集合（扫描不再重复入队），转入待归档重试。
                    Err(e) => {
                        pending_archive.push(front);
                        throttled_log(&mut throttle, &name, || {
                            cfg.emit(MonitorEvent::Failed { name: name.clone(), error: format!("归档失败: {e}") });
                        });
                        eprintln!("[监控] 归档失败（转入待归档重试）{name}: {e}");
                    }
                }
            }
            Err(e) => {
                // 失败不阻断队列：移到队尾（他人先行），按文件节流上报。
                queue.pop_front();
                queue.push_back(front.clone());
                throttled_log(&mut throttle, &name, || {
                    cfg.emit(MonitorEvent::Failed { name: name.clone(), error: e.to_string() });
                });
                eprintln!("[监控] 发送失败 {name}: {e}");
            }
        }
    }
    Ok(())
}

/// 顶层文件扫描（跳过子目录 / 「已发送文件」/ 摘要缓存元数据；排序确定性）。
fn scan_dir(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let sent = dir.join(SENT_DIR);
    let mut out: Vec<PathBuf> = rd
        .flatten()
        .filter(|e| {
            let p = e.path();
            p.is_file()
                && p != sent
                && !crate::hashcache::is_cache_artifact(&e.file_name().to_string_lossy())
        })
        .map(|e| e.path())
        .collect();
    out.sort();
    out
}

/// 拷贝完成双重门：独占打开（Windows share-none；其他平台尽力写句柄）
/// + 稳定窗内大小与 mtime 双不变。调用方置于 blocking 池（内含 sleep）。
pub fn copy_complete(path: &Path, window: Duration) -> bool {
    let Ok(m1) = std::fs::metadata(path) else { return false };
    if !m1.is_file() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // share_mode(0)：写方仍持有句柄时打开必败——独占探测（规格 §3.2）。
        if std::fs::OpenOptions::new().read(true).share_mode(0).open(path).is_err() {
            return false;
        }
    }
    #[cfg(not(windows))]
    {
        if std::fs::OpenOptions::new().append(true).open(path).is_err() {
            return false;
        }
    }
    std::thread::sleep(window);
    let Ok(m2) = std::fs::metadata(path) else { return false };
    m1.len() == m2.len() && m1.modified().ok() == m2.modified().ok()
}

/// 成功后移入「已发送文件/」（重名追加序号，规格 §3.2）。
pub fn move_to_sent(watch_dir: &Path, path: &Path) -> std::io::Result<PathBuf> {
    let sent = watch_dir.join(SENT_DIR);
    std::fs::create_dir_all(&sent)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::other("文件名非 UTF-8"))?;
    let p = Path::new(name);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = p.extension().and_then(|s| s.to_str()).map(|e| format!(".{e}")).unwrap_or_default();
    let mut dest = sent.join(name);
    if dest.exists() {
        let mut found = None;
        for i in 1..10000u32 {
            let cand = sent.join(format!("{stem}_{i}{ext}"));
            if !cand.exists() {
                found = Some(cand);
                break;
            }
        }
        // 耗尽不回退原名（轮 4 P3-7：回退会在 Windows 上静默替换已归档文件）。
        dest = found.ok_or_else(|| std::io::Error::other("已发送目录冲突名耗尽"))?;
    }
    std::fs::rename(path, &dest)?;
    Ok(dest)
}

fn file_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
}

/// 按文件节流：首报立即、后续 LOG_THROTTLE 内静默（规格 §3.2）。
fn throttled_log(map: &mut HashMap<String, Instant>, name: &str, f: impl FnOnce()) {
    let now = Instant::now();
    let due = map.get(name).is_none_or(|t| now.duration_since(*t) >= LOG_THROTTLE);
    if due {
        map.insert(name.to_string(), now);
        // 容量防线：1 小时未再出现的文件条目可清。
        map.retain(|_, t| now.duration_since(*t) < Duration::from_secs(3600));
        f();
    }
}

/// 便捷构造：错误归一（GUI 命令层用）。
pub fn describe_error(e: &Error) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_complete_rejects_growing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("grow.bin");
        std::fs::write(&p, vec![0u8; 100]).unwrap();
        // 模拟半截文件：检查期间仍在增长 → 稳定窗判不变。
        // 确定性关键：写点间隔（200ms）< 稳定窗（300ms）——任意相隔一个稳定窗的
        // 两次采样必跨至少一个写点、看到不同大小 → 必判不稳，无调度竞态
        // （旧版单次写点 100ms 处存在真时钟 flaky：首次采样若被调度延迟跨过写点，
        // 两次采样同大小 → 误判稳定 → 假红）。
        let dir2 = dir.path().to_path_buf();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            std::fs::write(dir2.join("grow.bin"), vec![0u8; 500]).unwrap();
            std::thread::sleep(Duration::from_millis(200));
            std::fs::write(dir2.join("grow.bin"), vec![0u8; 1000]).unwrap();
        });
        assert!(!copy_complete(&p, Duration::from_millis(300)), "增长中的文件不得判就绪");
        writer.join().unwrap();
        // 稳定后判就绪（写者已结束，无并发）。
        assert!(copy_complete(&p, Duration::from_millis(50)), "稳定文件必须判就绪");
    }

    #[test]
    fn move_to_sent_appends_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("x.bin");
        std::fs::write(&a, b"1").unwrap();
        let d1 = move_to_sent(dir.path(), &a).unwrap();
        assert_eq!(d1, dir.path().join(SENT_DIR).join("x.bin"));
        let b = dir.path().join("x.bin");
        std::fs::write(&b, b"2").unwrap();
        let d2 = move_to_sent(dir.path(), &b).unwrap();
        assert_eq!(d2, dir.path().join(SENT_DIR).join("x_1.bin"), "重名追加序号");
        assert!(!b.exists(), "移走后原位不得残留");
    }

    #[test]
    fn scan_skips_sent_dir_and_subdirs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.bin"), b"1").unwrap();
        let sent = dir.path().join(SENT_DIR);
        std::fs::create_dir_all(&sent).unwrap();
        std::fs::write(sent.join("b.bin"), b"2").unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub").join("c.bin"), b"3").unwrap();
        let found = scan_dir(dir.path());
        assert_eq!(found, vec![dir.path().join("a.bin")], "仅顶层文件入扫描");
    }

    #[tokio::test]
    async fn monitor_sends_ready_file_and_archives() {
        // 端到端：监控目录 → 文件就绪 → 自动发送到本地接收器 → 移入已发送。
        use crate::transfer::receiver::{serve_on, RecvOptions};
        let dir = tempfile::tempdir().unwrap();
        let watch = dir.path().join("drop");
        std::fs::create_dir_all(&watch).unwrap();
        let out = dir.path().join("out");
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let server = tokio::spawn(serve_on(l, RecvOptions { save_dir: out.clone(), max_count: Some(1), ..Default::default() }));

        // 预置半截文件（稳定窗内会被补完——此处直接放完整文件）。
        let src = watch.join("auto.bin");
        std::fs::write(&src, b"monitor me").unwrap();

        let (stx, srx) = watch::channel(false);
        let (etx, mut erx) = mpsc::unbounded_channel();
        let mut cfg = MonitorConfig::new(watch.clone(), addr, MonitorProto::Tcp, srx);
        cfg.events = Some(etx);
        cfg.stable_window = Duration::from_millis(100);
        cfg.poll_interval = Duration::from_millis(100);
        let h = tokio::spawn(run_monitor(cfg));

        // 等待发送完成（事件或落盘判定，5s 兜底）。
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if out.join("auto.bin").exists() {
                break;
            }
            if let Ok(ev) = erx.try_recv() {
                if matches!(ev, MonitorEvent::Failed { .. }) {
                    h.abort();
                    panic!("监控发送失败: {ev:?}");
                }
            }
            assert!(Instant::now() < deadline, "监控 5s 内未完成发送");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(std::fs::read(out.join("auto.bin")).unwrap(), b"monitor me");
        // 归档（rename 到「已发送文件/」）发生在**发送侧返回之后**，而上面的等待
        // 条件是接收侧落盘——两者之间存在窗口（实跑曾偶发红）。此处等到归档为止，
        // 保留断言强度而不是放宽判据。
        let archived = watch.join(SENT_DIR).join("auto.bin");
        let archive_deadline = Instant::now() + Duration::from_secs(5);
        while !archived.exists() {
            assert!(Instant::now() < archive_deadline, "成功后必须移入「已发送文件/」");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = stx.send(true);
        let _ = h.await;
        server.abort();
    }
}
