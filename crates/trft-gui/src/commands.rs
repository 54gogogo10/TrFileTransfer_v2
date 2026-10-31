//! Tauri 命令层：UI 只做参数收集与事件消费，全部逻辑复用 trft-core（规格 §3.6
//! 「复用 GUI 同一逻辑层」反向成立——GUI 与 CLI 调同一批 core 入口，行为一致）。

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use serde::Deserialize;
use tauri::{Emitter, Manager};
use tokio::sync::mpsc;
use trft_core::error::config_err;
use trft_core::config::Config;
use trft_core::hashcache::{cache_file_for, HashCache, DEFAULT_TTL_DAYS};
use trft_core::transfer::chunked::{send_file_chunked, ChunkTracker};
use trft_core::transfer::folder::send_folder;
use trft_core::transfer::receiver::{serve_on, RecvOptions};
use trft_core::transfer::resume::{send_file_auto, send_folder_resume, stable_session_id};
use trft_core::transfer::sender::SendOptions;
use trft_core::transfer::udp::{send_file_udp, serve_udp_on, UdpRecvOptions, UdpSendOptions};
use trft_core::transfer::Transport;
use trft_core::monitor::MonitorProto;

use crate::state::{forward_progress, AppState, HttpHandle, Proto, ReceiverHandle, TaskHandle};

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// 静默启动子进程（Windows CREATE_NO_WINDOW，不闪控制台）。
fn spawn_hidden(mut c: std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = c.creation_flags(0x0800_0000).spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = c.spawn();
    }
}

/// 防睡眠（规格 §3.7）：传输/接收器/共享运行期间 SetThreadExecutionState 引用钳制。
/// 计数从状态**派生**而非加减配对——任务 abort（取消）路径不可能泄漏。
fn update_awake(app: &tauri::AppHandle) {
    let st = app.state::<AppState>();
    let active = {
        let receivers = st.receivers.lock().expect("接收器锁").len();
        let tasks = st.tasks.lock().expect("任务锁").len();
        let http = st.http.lock().expect("http 锁").is_some() as usize;
        let monitor = st.monitor_handle.lock().expect("监控锁").is_some() as usize;
        receivers + tasks + http + monitor
    };
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Power::{
            SetThreadExecutionState, ES_CONTINUOUS, ES_SYSTEM_REQUIRED,
        };
        let mode = if active > 0 { ES_CONTINUOUS | ES_SYSTEM_REQUIRED } else { ES_CONTINUOUS };
        SetThreadExecutionState(mode);
    }
    #[cfg(not(windows))]
    let _ = active;
}

fn addr_of(ip: &str, port: u16) -> Result<SocketAddr, String> {
    if ip.contains(':') {
        format!("[{ip}]:{port}").parse::<SocketAddr>().map_err(|e| e.to_string())
    } else {
        format!("{ip}:{port}").parse::<SocketAddr>().map_err(|e| e.to_string())
    }
}

/// 校验配对码（4–12 位数字，规格 §3.7 输入校验）。
fn validate_code(code: &Option<String>) -> Result<(), String> {
    if let Some(c) = code {
        let n = c.chars().count();
        if !(4..=12).contains(&n) || !c.chars().all(|ch| ch.is_ascii_digit()) {
            return Err("配对码必须是 4–12 位数字".into());
        }
    }
    Ok(())
}

fn parse_pin(pin: &Option<String>) -> Result<Option<[u8; 32]>, String> {
    match pin {
        None => Ok(None),
        Some(h) if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) => {
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(err)?;
            }
            Ok(Some(out))
        }
        Some(_) => Err("QUIC 指纹需要 64 位十六进制".into()),
    }
}


// ============ 应用状态 / 配置 ============

#[tauri::command]
pub fn get_app_state(app: tauri::AppHandle) -> serde_json::Value {
    let st = app.state::<AppState>();
    let cfg = st.cfg.lock().expect("配置锁").clone();
    let running: Vec<serde_json::Value> = st
        .receivers
        .lock()
        .expect("接收器锁")
        .values()
        .map(|r| serde_json::json!({ "proto": r.proto, "port": r.port, "bound": r.bound }))
        .collect();
    let http_running = st.http.lock().expect("http 锁").is_some();
    serde_json::json!({
        "config": cfg,
        "version": env!("CARGO_PKG_VERSION"),
        "receivers": running,
        "httpRunning": http_running,
        "addresses": list_addresses_inner(),
    })
}

#[tauri::command]
pub fn save_config(app: tauri::AppHandle, config: Config) -> Result<(), String> {
    config.validate().map_err(err)?;
    let st = app.state::<AppState>();
    *st.cfg.lock().expect("配置锁") = config;
    st.save_config()
}

fn list_addresses_inner() -> Vec<String> {
    // 二维码面向手机浏览器（局域网 IPv4）；v6 链路本地地址对扫码场景无意义。
    let mut out = Vec::new();
    if let Ok(addrs) = if_addrs::get_if_addrs() {
        for a in addrs {
            if let std::net::IpAddr::V4(v4) = a.ip() {
                if !v4.is_loopback() {
                    out.push(v4.to_string());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[tauri::command]
pub fn list_addresses() -> Vec<String> {
    list_addresses_inner()
}

// ============ 发送 ============

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendRequest {
    /// "file" | "folder" | "text" | "udpfile"
    pub kind: String,
    pub path: Option<String>,
    pub text: Option<String>,
    pub ip: String,
    pub port: u16,
    pub proto: Proto,
    pub code: Option<String>,
    pub limit: Option<u64>,
    pub chunks: Option<u8>,
    pub nocompress: bool,
    pub noencrypt: bool,
    pub passes: Option<u32>,
    pub fec_parity: Option<u8>,
    pub nofec: bool,
    pub pin: Option<String>,
}

impl SendRequest {
    fn display_name(&self) -> String {
        match (&self.path, &self.text) {
            (Some(p), _) => PathBuf::from(p)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| p.clone()),
            (_, Some(t)) => {
                let head: String = t.chars().take(24).collect();
                format!("文本: {head}")
            }
            _ => "发送".into(),
        }
    }

    fn addr(&self) -> Result<SocketAddr, String> {
        addr_of(&self.ip, self.port)
    }

    fn stream_opts(
        &self,
        reporter: Option<trft_core::progress::Reporter>,
        compress_default: bool,
        stats: Option<Arc<trft_core::stats::StatsLog>>,
    ) -> Result<SendOptions, String> {
        validate_code(&self.code)?;
        let transport = match self.proto {
            Proto::Tcp | Proto::Udp => Transport::Tcp,
            Proto::Udt => Transport::Quic,
        };
        if self.proto != Proto::Udt && self.pin.is_some() {
            return Err("指纹钉扎仅用于 UDT(QUIC)".into());
        }
        Ok(SendOptions {
            pairing_code: self.code.clone(),
            speed_limit_bps: self.limit.unwrap_or(0).min(10_000_000) * 1024,
            src_port: None,
            transport,
            encrypt: !self.noencrypt,
            compress: !self.nocompress && compress_default,
            quic_pin: parse_pin(&self.pin)?,
            // GUI 无旧对端放行开关：0x0D 降级一律 fail-closed（轮 2 F1；
            // 需对接旧 QUIC 对端时用 CLI --allow-legacy-pair 或 --pin）。
            allow_legacy_pair: false,
            progress: reporter,
            stats,
        })
    }
}

/// 任务收尾（轮 3 P1）：先置 settled 再摘表——spawn/insert 时序竞态下，
/// 父任务注册后的补偿检查（`register_task` 返回值）保证幽灵句柄必被回收。
fn finish_task(app: &tauri::AppHandle, id: u64) {
    let st = app.state::<AppState>();
    st.tasks.lock().expect("任务锁").remove(&id);
    st.task_progress.lock().expect("映射锁").remove(&id);
    update_awake(app);
}

/// 发送任务公共收尾：终态事件 + 已知设备记忆（规格 §3.3）+ 可选系统通知。
async fn settle_send(
    app: tauri::AppHandle,
    id: u64,
    name: String,
    res: Result<(), trft_core::error::Error>,
    peer: Option<(String, u16, &'static str, bool)>,
) {
    let notify = {
        let st = app.state::<AppState>();
        st.tasks.lock().expect("任务锁").remove(&id);
        st.task_progress.lock().expect("映射锁").remove(&id);
        let cfg = st.cfg.lock().expect("配置锁");
        cfg.notify_enabled
    };
    update_awake(&app);
    let ok = res.is_ok();
    update_awake(&app);
    if ok {
        if let Some((ip, port, proto, needs_pairing)) = peer {
            // 规格 §3.3：传输成功记入已知设备（core DeviceStore 写穿持久化）。
            app.state::<AppState>().devices.upsert(DeviceInfo {
                name: String::new(),
                ip,
                port,
                proto: proto.into(),
                needs_pairing,
                last_seen: 0,
                source: trft_core::devices::DeviceSource::Transfer,
            });
        }
    }
    let _ = app.emit(
        "trft://task",
        serde_json::json!({ "id": id, "ok": ok, "error": res.as_ref().err().map(|e| e.to_string()) }),
    );
    if notify {
        use tauri_plugin_notification::NotificationExt;
        let n = app.notification().builder().title(format!("TrFileTransfer — {name}"));
        let _ = if ok {
            n.body("传输完成").show()
        } else {
            n.body(format!("失败: {}", res.err().map(|e| e.to_string()).unwrap_or_default())).show()
        };
    }
}

#[tauri::command]
pub async fn send_start(app: tauri::AppHandle, req: SendRequest) -> Result<u64, String> {
    let name = req.display_name();
    let (ptx, prx) = mpsc::unbounded_channel();
    forward_progress(app.clone(), prx);
    let hub = {
        let st = app.state::<AppState>();
        let base = st.next_hub.fetch_add(1, Ordering::SeqCst) * 1_000_000;
        trft_core::progress::ProgressHub::with_id_base(ptx, base)
    };
    // UDP 无暂停/继续语义（规格 §3.2）——kind 区分让前端不绑暂停按钮。
    let send_kind = if req.kind == "udpfile" { "udp-send" } else { "send" };
    let reporter = hub.register(send_kind, name.clone(), 0);
    let progress_id = reporter.id();

    let (compress_default, udp_cfg, send_stats) = {
        let st = app.state::<AppState>();
        let cfg = st.cfg.lock().expect("配置锁").clone();
        (true, (cfg.udp_passes, cfg.udp_fec, cfg.udp_fec_parity), st.stats.clone())
    };
    let addr = req.addr()?;
    let id = {
        let st = app.state::<AppState>();
        st.alloc_task_id()
    };
    let app2 = app.clone();
    let name2 = name.clone();
    let settled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let settled2 = settled.clone();
    let handle = tauri::async_runtime::spawn(async move {
        let res = match req.kind.as_str() {
            "file" => {
                let path = PathBuf::from(req.path.clone().unwrap_or_default());
                let opts = req.stream_opts(Some(reporter), compress_default, Some(send_stats.clone()));
                match opts {
                    // 拖放多选把目录按 file 入队（前端拿不到 is_dir）——自动路由整夹发送。
                    Ok(o) if path.is_dir() => send_folder(addr, &path, &o).await,
                    Ok(o) => send_file_auto(addr, &path, &o).await,
                    Err(e) => Err(config_err(e)),
                }
            }
            "folder" => {
                let path = PathBuf::from(req.path.clone().unwrap_or_default());
                let opts = req.stream_opts(Some(reporter), compress_default, Some(send_stats.clone()));
                match opts {
                    Ok(o) => send_folder(addr, &path, &o).await,
                    Err(e) => Err(config_err(e)),
                }
            }
            "text" => {
                let text = req.text.clone().unwrap_or_default();
                let opts = req.stream_opts(None, compress_default, Some(send_stats.clone()));
                match opts {
                    Ok(o) => trft_core::transfer::sender::send_text(addr, &text, &o).await,
                    Err(e) => Err(config_err(e)),
                }
            }
            "udpfile" => {
                let path = PathBuf::from(req.path.clone().unwrap_or_default());
                if req.code.is_some() {
                    Err(config_err("单向 UDP 不支持配对码/加密（规格 §3.1）"))
                } else {
                    let opts = UdpSendOptions {
                        passes: req.passes.unwrap_or(udp_cfg.0).clamp(1, 5),
                        fec: !req.nofec && udp_cfg.1,
                        fec_parity: req.fec_parity.unwrap_or(udp_cfg.2).clamp(1, 8),
                        speed_limit_bps: req.limit.unwrap_or(0).min(10_000_000) * 1024,
                        progress: Some(reporter),
                        stats: Some(send_stats.clone()),
                    };
                    send_file_udp(addr, &path, &opts).await
                }
            }
            other => Err(config_err(format!("未知发送类型: {other}"))),
        };
        let peer_proto = if req.proto == Proto::Udt { "udt" } else { "tcp" };
        let peer = Some((req.ip.clone(), req.port, peer_proto, req.code.is_some()));
        settle_send(app2, id, name2, res, peer).await;
        settled2.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let st = app.state::<AppState>();
    st.tasks.lock().expect("任务锁").insert(
        id,
        TaskHandle { handle },
    );
    st.task_progress.lock().expect("映射锁").insert(id, progress_id);
    // 子任务先于注册收尾的补偿摘除（轮 3 P1-1）；task_progress 先插——
    // 快速完成窗口中子 settle 摘的是尚不存在的映射，父再插即泄漏（轮 7 P3）。
    if settled.load(std::sync::atomic::Ordering::SeqCst) {
        finish_task(&app, id);
    }
    update_awake(&app);
    let _ = app.emit("trft://task-start", serde_json::json!({ "id": id, "progressId": progress_id }));
    Ok(id)
}

/// 0x02 并行分块（Unsupported 自动回退 0x03 续传——规格 §3.6）。
#[tauri::command]
pub async fn send_chunked_start(app: tauri::AppHandle, req: SendRequest) -> Result<u64, String> {
    let connections = req.chunks.unwrap_or(2).clamp(1, 8);
    let name = req.display_name();
    let (ptx, prx) = mpsc::unbounded_channel();
    forward_progress(app.clone(), prx);
    let hub = {
        let st = app.state::<AppState>();
        let base = st.next_hub.fetch_add(1, Ordering::SeqCst) * 1_000_000;
        trft_core::progress::ProgressHub::with_id_base(ptx, base)
    };
    let addr = req.addr()?;
    let send_stats = app.state::<AppState>().stats.clone();
    let base = req.stream_opts(None, true, Some(send_stats.clone()))?;
    let path = PathBuf::from(req.path.clone().ok_or("缺少文件路径")?);
    let id = {
        let st = app.state::<AppState>();
        st.alloc_task_id()
    };
    let app2 = app.clone();
    let name2 = name.clone();
    let name3 = name.clone();
    let settled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let settled2 = settled.clone();
    // 首卡（0x02）Reporter 在 spawn 前注册：任务↔进度卡绑定需要它的 ID。
    let first_reporter = hub.register("send", &name, 0);
    let first_progress_id = first_reporter.id();
    let handle = tauri::async_runtime::spawn(async move {
        // 0x02 与回退 0x03 是两张进度卡：各注册一个 Reporter（同一事件通道）。
        let mut chunked_opts = base.clone();
        chunked_opts.progress = Some(first_reporter);
        let res = match send_file_chunked(addr, &path, &chunked_opts, connections).await {
            Err(trft_core::error::Error::Unsupported(m)) => {
                let _ = app2.emit("trft://log", serde_json::json!({ "level": "warn", "message": m }));
                let mut auto_opts = base;
                auto_opts.progress = Some(hub.register("send", name3, 0));
                send_file_auto(addr, &path, &auto_opts).await
            }
            other => other,
        };
        let peer_proto = if req.proto == Proto::Udt { "udt" } else { "tcp" };
        let peer = Some((req.ip.clone(), req.port, peer_proto, req.code.is_some()));
        settle_send(app2, id, name2, res, peer).await;
        settled2.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let st = app.state::<AppState>();
    st.tasks.lock().expect("任务锁").insert(
        id,
        TaskHandle { handle },
    );
    st.task_progress.lock().expect("映射锁").insert(id, first_progress_id);
    if settled.load(std::sync::atomic::Ordering::SeqCst) {
        finish_task(&app, id);
    }
    update_awake(&app);
    let _ = app.emit("trft://task-start", serde_json::json!({ "id": id, "progressId": first_progress_id }));
    Ok(id)
}

#[tauri::command]
pub fn send_cancel(app: tauri::AppHandle, id: u64) {
    let t = {
        let st = app.state::<AppState>();
        let mut g = st.tasks.lock().expect("任务锁");
        g.remove(&id)
    };
    if let Some(t) = t {
        t.handle.abort();
        // 补发终态事件（轮 7 P2）：abort 掐断的 future 不会走 settle_send——
        // 群发汇总（groupPending）依赖 trft://task 收敛。
        let _ = app.emit(
            "trft://task",
            serde_json::json!({ "id": id, "ok": false, "error": "已取消" }),
        );
    }
    let st = app.state::<AppState>();
    st.task_progress.lock().expect("映射锁").remove(&id);
    update_awake(&app);
}

/// 队列串行发送（规格 §3.2：串行批量执行；失败不阻断后续——逐项上报）。
/// `after_done`：无/关机/休眠/执行命令（执行前确认在前端弹窗完成）。
#[tauri::command]
pub async fn send_queue(
    app: tauri::AppHandle,
    items: Vec<SendRequest>,
    after_done: Option<String>,
    after_command: Option<String>,
) -> Result<u64, String> {
    let _queue_label = format!("队列 ×{}", items.len());
    let id = {
        let st = app.state::<AppState>();
        st.alloc_task_id()
    };
    let app2 = app.clone();
    let settled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let settled2 = settled.clone();
    let handle = tauri::async_runtime::spawn(async move {
        let mut ok_n = 0u32;
        for (i, item) in items.into_iter().enumerate() {
            let label = format!("队列 {}/{}", i + 1, item.display_name());
            let sub = run_single_send(app2.clone(), item).await;
            if sub.is_ok() {
                ok_n += 1;
            }
            let _ = app2.emit(
                "trft://log",
                serde_json::json!({ "level": if sub.is_ok() { "ok" } else { "err" }, "message": label }),
            );
        }
        let _ = app2.emit(
            "trft://task",
            serde_json::json!({ "id": id, "ok": ok_n > 0, "summary": format!("{ok_n} 完成") }),
        );
        // 自摘除（轮 3 P1-2：queue 任务此前永驻 tasks 表——防睡眠计数泄漏）。
        finish_task(&app2, id);
        settled2.store(true, std::sync::atomic::Ordering::SeqCst);
        // 完成后动作（确认弹窗已在队列启动前完成——规格 §3.2）。
        match after_done.as_deref() {
            Some("shutdown") => {
                let mut c = std::process::Command::new("cmd");
                c.args(["/C", "shutdown", "/s", "/t", "60"]);
                spawn_hidden(c);
                let _ = app2.emit("trft://log", serde_json::json!({ "level": "warn", "message": "系统将在 60 秒后关机（shutdown /a 可取消）" }));
            }
            Some("sleep") => {
                let mut c = std::process::Command::new("rundll32.exe");
                c.args(["powrprof.dll,SetSuspendState", "0,1,0"]);
                spawn_hidden(c);
            }
            Some("command") => {
                if let Some(cmd) = after_command.filter(|c| !c.trim().is_empty()) {
                    let mut c = std::process::Command::new("cmd");
                    c.args(["/C", cmd.trim()]);
                    spawn_hidden(c);
                }
            }
            _ => {}
        }
    });
    let st = app.state::<AppState>();
    st.tasks.lock().expect("任务锁").insert(
        id,
        TaskHandle { handle },
    );
    if settled.load(std::sync::atomic::Ordering::SeqCst) {
        finish_task(&app, id);
    }
    update_awake(&app);
    Ok(id)
}

async fn run_single_send(app: tauri::AppHandle, req: SendRequest) -> Result<(), String> {
    let app2 = app.clone();
    match send_start(app, req).await {
        Ok(id) => {
            // 等待该任务终态（轮询注册表足够——任务完成即自我移除）。
            loop {
                {
                    let st = app2.state::<AppState>();
                    if !st.tasks.lock().expect("任务锁").contains_key(&id) {
                        return Ok(());
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
        }
        Err(e) => Err(e),
    }
}

// ============ 同步（0x04） ============

#[tauri::command]
pub async fn sync_start(
    app: tauri::AppHandle,
    folder: String,
    ip: String,
    port: u16,
    proto: Proto,
    code: Option<String>,
    limit: Option<u64>,
    nocompress: bool,
) -> Result<u64, String> {
    if proto == Proto::Udp {
        return Err("单向 UDP 不支持文件夹同步（仅单文件，规格 §3.6）".into());
    }
    validate_code(&code)?;
    let path = PathBuf::from(&folder);
    if !path.is_dir() {
        return Err(format!("路径不是目录: {folder}"));
    }
    let addr = addr_of(&ip, port)?;
    let name = path
        .file_name()
        .map(|n| format!("同步: {}", n.to_string_lossy()))
        .unwrap_or_else(|| format!("同步: {folder}"));
    let (ptx, prx) = mpsc::unbounded_channel();
    forward_progress(app.clone(), prx);
    let hub = {
        let st = app.state::<AppState>();
        let base = st.next_hub.fetch_add(1, Ordering::SeqCst) * 1_000_000;
        trft_core::progress::ProgressHub::with_id_base(ptx, base)
    };
    let reporter = hub.register("send", name.clone(), 0);
    let progress_id = reporter.id();

    let opts = SendOptions {
        transport: if proto == Proto::Udt { Transport::Quic } else { Transport::Tcp },
        pairing_code: code.clone(),
        speed_limit_bps: limit.unwrap_or(0).min(10_000_000) * 1024,
        compress: !nocompress,
        progress: Some(reporter),
        stats: Some(app.state::<AppState>().stats.clone()),
        ..Default::default()
    };
    // 稳定会话 ID：与 CLI sync 互相接力（规格 §3.2）。
    let session = stable_session_id(&path, &format!("{ip}:{port}"));
    // SyncVerifyContent（strict，规格 §3.3）：双侧生效 → 发送侧不携带缓存哈希。
    let strict = app.state::<AppState>().config().sync_verify_content;
    let cache = if strict {
        None
    } else {
        Some(Arc::new(tokio::sync::Mutex::new(HashCache::load(
            &cache_file_for(&path),
            DEFAULT_TTL_DAYS,
        ))))
    };
    let id = {
        let st = app.state::<AppState>();
        st.alloc_task_id()
    };
    let app2 = app.clone();
    let name2 = name.clone();
    let settled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let settled2 = settled.clone();
    let handle = tauri::async_runtime::spawn(async move {
        let res = send_folder_resume(addr, &path, &opts, session, cache.as_ref()).await;
        let peer = Some((ip.to_string(), port, if proto == Proto::Udt { "udt" } else { "tcp" }, code.is_some()));
        settle_send(app2, id, name2, res, peer).await;
        settled2.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let st = app.state::<AppState>();
    st.tasks.lock().expect("任务锁").insert(
        id,
        TaskHandle { handle },
    );
    st.task_progress.lock().expect("映射锁").insert(id, progress_id);
    if settled.load(std::sync::atomic::Ordering::SeqCst) {
        finish_task(&app, id);
    }
    update_awake(&app);
    let _ = app.emit("trft://task-start", serde_json::json!({ "id": id, "progressId": progress_id }));
    Ok(id)
}

// ============ 接收器 ============

/// 解析绑定地址列表（规格 §3.3：族通配 + 具体网卡，每地址一个监听器；去重）。
fn parse_bind_addrs(addrs: Option<Vec<String>>) -> Result<Vec<std::net::IpAddr>, String> {
    let list = addrs.unwrap_or_else(|| vec!["0.0.0.0".into()]);
    if list.is_empty() {
        return Err("未选择任何监听地址".into());
    }
    let mut out = Vec::new();
    for a in list {
        let ip: std::net::IpAddr = a.parse().map_err(|_| format!("非法绑定地址: {a}"))?;
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    Ok(out)
}

/// UDP 监听（与 trft-core::serve_udp 同口径：4MB 收缓冲，规格 §6.1），
/// 绑定在调用侧完成以支持逐地址失败上报。
async fn bind_udp(addr: SocketAddr) -> Result<tokio::net::UdpSocket, String> {
    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, None)
        .map_err(|e| e.to_string())?;
    sock.set_nonblocking(true).map_err(|e| e.to_string())?;
    sock.bind(&addr.into()).map_err(|e| format!("{} 绑定失败: {e}", addr))?;
    if let Err(e) = sock.set_recv_buffer_size(4 * 1024 * 1024) {
        eprintln!("[警告] UDP 收缓冲设置失败: {e}");
    }
    let std_sock: std::net::UdpSocket = sock.into();
    tokio::net::UdpSocket::from_std(std_sock).map_err(|e| e.to_string())
}

/// 自 `port+1` 起探测同传输的下一个可用端口（≤ +10）。
fn next_free_port(proto: Proto, ip: std::net::IpAddr, port: u16) -> Option<u16> {
    for p in (port + 1)..=(port.saturating_add(10).min(65535)) {
        let addr = SocketAddr::new(ip, p);
        let free = match proto {
            Proto::Udp => std::net::UdpSocket::bind(addr).is_ok(),
            // UDT(QUIC) 走 UDP 传输（轮 7 P3：此前误用 TCP 探测）。
            Proto::Udt => std::net::UdpSocket::bind(addr).is_ok(),
            Proto::Tcp => std::net::TcpListener::bind(addr).is_ok(),
        };
        if free {
            return Some(p);
        }
    }
    None
}

#[tauri::command]
pub async fn recv_start(
    app: tauri::AppHandle,
    proto: Proto,
    port: u16,
    save_dir: Option<String>,
    addrs: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    {
        let st = app.state::<AppState>();
        let mut g = st.receivers.lock().expect("接收器锁");
        if g.contains_key(&proto) {
            return Err(format!("{} 接收器已在运行", proto.label()));
        }
        // 占位（轮 3 P3-6）：检查与 insert 之间隔着逐地址 bind await——并发启动
        // 会让后者覆盖前者的句柄，前者成为无法停止的孤儿监听器。失败路径回滚。
        g.insert(
            proto,
            ReceiverHandle { proto, port, bound: vec![], handles: vec![] },
        );
    }
    let cfg = app.state::<AppState>().config();
    let dir = match save_dir {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => match proto {
            Proto::Tcp => cfg.save_dir_tcp.clone(),
            Proto::Udt => cfg.save_dir_quic.clone(),
            Proto::Udp => cfg.save_dir_udp.clone(),
        },
    };
    let _ = std::fs::create_dir_all(&dir);
    let bind_list = match parse_bind_addrs(addrs) {
        Ok(l) => l,
        Err(e) => {
            app.state::<AppState>()
                .receivers
                .lock()
                .expect("接收器锁")
                .remove(&proto);
            return Err(e);
        }
    };

    let (ptx, prx) = mpsc::unbounded_channel();
    forward_progress(app.clone(), prx);
    let hub = {
        let st = app.state::<AppState>();
        let base = st.next_hub.fetch_add(1, Ordering::SeqCst) * 1_000_000;
        trft_core::progress::ProgressHub::with_id_base(ptx, base)
    };

    let app2 = app.clone();
    let mut handles = Vec::new();
    let mut bound = Vec::new();
    let mut failed: Vec<(SocketAddr, String)> = Vec::new();

    // 状态/资源只建一份：多监听器经 Clone 共享（gate/并发闸/分块会话表/缓存/事件通道）。
    // M5'：设备记忆/确认钩子/分目录/归档/统计统一注入（TECH-STACK §7.10）。
    let shared = match proto {
        Proto::Udp => None,
        _ => {
            let cache = Arc::new(tokio::sync::Mutex::new(HashCache::load(
                &cache_file_for(&dir),
                cfg.hash_cache_days,
            )));
            let (ttx, mut trx) = mpsc::unbounded_channel::<String>();
            let app3 = app.clone();
            tauri::async_runtime::spawn(async move {
                while let Some(t) = trx.recv().await {
                    text_history_append(&t); // 规格 §3.2：历史落盘 200 条
                    let _ = app3.emit("trft://text", &t);
                }
            });
            let mut tracker = ChunkTracker::default();
            tracker.progress = Some(hub.clone());
            // 接收前确认（规格 §3.3）：mode ≠ off 时起应答消费任务 → 前端弹窗。
            let mut confirm_tx = None;
            if cfg.confirm_receive != trft_core::config::ConfirmMode::Off {
                let (ctx, mut crx) = mpsc::unbounded_channel::<trft_core::transfer::receiver::ConfirmRequest>();
                let appc = app.clone();
                tauri::async_runtime::spawn(async move {
                    while let Some(req) = crx.recv().await {
                        let id = appc
                            .state::<AppState>()
                            .next_confirm
                            .fetch_add(1, Ordering::SeqCst);
                        appc.state::<AppState>()
                            .pending_confirms
                            .lock()
                            .expect("确认锁")
                            .insert(id, req.reply);
                        // 看门狗（轮 3 P2-4）：core 30s 超时判拒绝后无反向通知——
                        // GUI 表项无人清理会永久泄漏（可被循环制造）。
                        let appw = appc.clone();
                        tauri::async_runtime::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_secs(31)).await;
                            let _ = appw
                                .state::<AppState>()
                                .pending_confirms
                                .lock()
                                .expect("确认锁")
                                .remove(&id);
                        });
                        let _ = appc.emit(
                            "trft://confirm",
                            serde_json::json!({ "id": id, "device": req.device, "peer": req.peer.to_string() }),
                        );
                    }
                });
                confirm_tx = Some(ctx);
            }
            let st = app.state::<AppState>();
            Some(RecvOptions {
                save_dir: dir.clone(),
                pairing_code: cfg.pairing_code.clone(),
                recv_limit_bps: cfg.recv_speed_limit.min(10_000_000) * 1024,
                duplicate: cfg.duplicate_files,
                text_tx: Some(ttx),
                hash_cache: Some(cache),
                progress: Some(hub.clone()),
                strict_verify: cfg.sync_verify_content,
                ip_filter_mode: cfg.ip_filter_mode,
                ip_filter_list: cfg.ip_filter_list.clone(),
                chunk_sessions: Arc::new(tracker),
                devices: Some(st.devices.clone()),
                per_device_folder: cfg.per_device_folder,
                auto_archive: cfg.auto_archive,
                confirm_mode: cfg.confirm_receive,
                confirm_tx,
                confirm_seen: st.confirm_seen.clone(),
                stats: Some(st.stats.clone()),
                ..Default::default()
            })
        }
    };

    for ip in bind_list {
        let addr = SocketAddr::new(ip, port);
        match proto {
            Proto::Tcp => match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    let o = shared.as_ref().expect("TCP 选项已建").clone();
                    let a2 = app2.clone();
                    handles.push(tauri::async_runtime::spawn(async move {
                        if let Err(e) = serve_on(listener, o).await {
                            let _ = a2.emit("trft://log", serde_json::json!({ "level": "err", "message": format!("TCP 接收器退出: {e}") }));
                        }
                    }));
                    bound.push(addr.to_string());
                }
                Err(e) => failed.push((addr, e.to_string())),
            },
            Proto::Udt => match trft_core::transfer::quic::server_endpoint(addr).await {
                Ok((endpoint, cert_fp)) => {
                    let o = shared.as_ref().expect("QUIC 选项已建").clone();
                    let a2 = app2.clone();
                    handles.push(tauri::async_runtime::spawn(async move {
                        if let Err(e) = trft_core::transfer::quic::serve_quic_on(endpoint, cert_fp, o).await {
                            let _ = a2.emit("trft://log", serde_json::json!({ "level": "err", "message": format!("QUIC 接收器退出: {e}") }));
                        }
                    }));
                    bound.push(addr.to_string());
                }
                Err(e) => failed.push((addr, e.to_string())),
            },
            Proto::Udp => match bind_udp(addr).await {
                Ok(socket) => {
                    let st = app.state::<AppState>();
                    let o = UdpRecvOptions {
                        save_dir: dir.clone(),
                        progress: Some(hub.clone()),
                        ip_filter_mode: cfg.ip_filter_mode,
                        ip_filter_list: cfg.ip_filter_list.clone(),
                        devices: Some(st.devices.clone()),
                        per_device_folder: cfg.per_device_folder,
                        auto_archive: cfg.auto_archive,
                        stats: Some(st.stats.clone()),
                    };
                    let a2 = app2.clone();
                    handles.push(tauri::async_runtime::spawn(async move {
                        if let Err(e) = serve_udp_on(socket, o, None).await {
                            let _ = a2.emit("trft://log", serde_json::json!({ "level": "err", "message": format!("UDP 接收器退出: {e}") }));
                        }
                    }));
                    bound.push(addr.to_string());
                }
                Err(e) => failed.push((addr, e.to_string())),
            },
        }
    }

    if bound.is_empty() {
        let detail = failed
            .iter()
            .map(|(a, e)| format!("{a}: {e}"))
            .collect::<Vec<_>>()
            .join("；");
        // 规格 §3.3：全部被外部占用时保留「换下一可用端口」提议。
        let first_ip = failed.first().map(|(a, _)| a.ip());
        let suggestion = match first_ip {
            Some(ip) if port < 65535 => next_free_port(proto, ip, port)
                .map(|p| format!("（建议换用端口 {p}）"))
                .unwrap_or_default(),
            _ => String::new(),
        };
        app.state::<AppState>()
            .receivers
            .lock()
            .expect("接收器锁")
            .remove(&proto);
        return Err(format!("{} 监听器全部绑定失败 —— {}{}", proto.label(), detail, suggestion));
    }

    let st = app.state::<AppState>();
    st.receivers.lock().expect("接收器锁").insert(
        proto,
        ReceiverHandle { proto, port, bound: bound.clone(), handles },
    );
    update_awake(&app);
    update_discovery_answer(&app);
    // 规格 §3.7：首次成功启动服务器展示一次 netsh 放行命令。
    if !cfg.firewall_hinted {
        let hint_port = bound.first().and_then(|b| b.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()));
        let _ = app.emit(
            "trft://firewall-hint",
            serde_json::json!({
                "command": format!("netsh advfirewall firewall add rule name=\"TrFileTransfer\" dir=in action=allow protocol=TCP localport={}", hint_port.unwrap_or(cfg.server_port_tcp)),
                "port": hint_port.unwrap_or(cfg.server_port_tcp),
            }),
        );
        st.cfg.lock().expect("配置锁").firewall_hinted = true;
        let _ = st.save_config();
    }
    let _ = app.emit(
        "trft://log",
        serde_json::json!({ "level": "ok", "message": format!("{} 接收器启动 :{port} ← {}", proto.label(), bound.join(", ")) }),
    );
    Ok(serde_json::json!({
        "proto": proto,
        "port": port,
        "dir": dir.to_string_lossy(),
        "bound": bound,
        "failed": failed.iter().map(|(a, e)| serde_json::json!({ "addr": a.to_string(), "error": e })).collect::<Vec<_>>(),
    }))
}

#[tauri::command]
pub fn recv_stop(app: tauri::AppHandle, proto: Proto) -> Result<(), String> {
    let r = {
        let st = app.state::<AppState>();
        let mut g = st.receivers.lock().expect("接收器锁");
        g.remove(&proto)
    };
    if let Some(r) = r {
        for h in r.handles {
            h.abort();
        }
        update_awake(&app);
        update_discovery_answer(&app);
        let _ = app.emit("trft://log", serde_json::json!({ "level": "ok", "message": format!("{} 接收器已停止", proto.label()) }));
        Ok(())
    } else {
        Err(format!("{} 接收器未在运行", proto.label()))
    }
}

// ============ HTTP 共享 + 二维码（规格 §3.4） ============

#[tauri::command]
pub async fn http_start(
    app: tauri::AppHandle,
    port: Option<u16>,
    dir: Option<String>,
) -> Result<serde_json::Value, String> {
    {
        let st = app.state::<AppState>();
        if st.http.lock().expect("http 锁").is_some() {
            return Err("共享已在运行".into());
        }
    }
    let cfg = app.state::<AppState>().config();
    let port = port.unwrap_or(cfg.http_port).clamp(1, 65535);
    // 规格 §3.4：共享所选保存目录（GUI 无标签页，用下拉三选一）。
    let dir = match dir {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => cfg.save_dir_tcp.clone(),
    };
    let _ = std::fs::create_dir_all(&dir);
    // `?t=` 令牌派生密钥（轮 6 P2-4）：每安装随机 32B，持久化 config——
    // 泄漏只作废令牌（换密钥），不回传低熵配对码。守卫不跨 await。
    let secret = {
        let st = app.state::<AppState>();
        let mut st_cfg = st.cfg.lock().expect("配置锁");
        if st_cfg.token_secret.is_none() {
            st_cfg.token_secret = Some(trft_core::config::new_token_secret());
            let _ = st_cfg.save(&app.state::<AppState>().cfg_path);
        }
        let mut secret = [0u8; 32];
        if let Some(h) = &st_cfg.token_secret {
            for i in 0..32 {
                secret[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap_or(0);
            }
        }
        secret
    };
    let token = cfg.pairing_code.as_ref().map(|c| trft_server::token_for(&secret, c));
    let auth = cfg.pairing_code.clone().map(|pairing_code| trft_server::AuthConfig { pairing_code });
    let state = Arc::new(trft_server::WebState::with_token_secret(dir.clone(), auth, secret));
    let router = trft_server::build_router(state);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .map_err(|e| format!("端口 {port} 绑定失败: {e}"))?;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let app2 = app.clone();
    let _handle = tauri::async_runtime::spawn(async move {
        let _ = axum_like_serve(listener, router, rx).await;
        let _ = app2.emit("trft://log", serde_json::json!({ "level": "ok", "message": "HTTP 共享已停止" }));
    });
    {
        let st = app.state::<AppState>();
        st.http.lock().expect("http 锁").replace(HttpHandle { port, shutdown: tx });
    }
    update_awake(&app);
    let _ = app.emit("trft://log", serde_json::json!({ "level": "ok", "message": format!("HTTP 共享启动 :{port}") }));
    Ok(serde_json::json!({ "port": port, "token": token, "dir": dir.to_string_lossy() }))
}

/// 带头读超时的共享 serve + graceful shutdown（轮 2 P1：与 trft-server main 同口径，
/// 规格 §6.1 头读超时 15s）。
async fn axum_like_serve(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    tokio::select! {
        r = trft_server::serve_with_header_timeout(listener, router) => r,
        _ = async {
            let _ = shutdown.await;
        } => Ok(()),
    }
}

#[tauri::command]
pub fn http_stop(app: tauri::AppHandle) -> Result<(), String> {
    let st = app.state::<AppState>();
    let mut g = st.http.lock().expect("http 锁");
    if let Some(h) = g.take() {
        let port = h.port;
        let _ = h.shutdown.send(());
        drop(g);
        update_awake(&app);
        let _ = app.emit("trft://log", serde_json::json!({ "level": "ok", "message": format!("HTTP 共享已停止（端口 {port}）") }));
        Ok(())
    } else {
        Err("共享未在运行".into())
    }
}

/// QR 码 SVG（模块矩阵自拼，qrcode 仅编码核零依赖）。
#[tauri::command]
pub fn qr_svg(text: String) -> Result<String, String> {
    use qrcode::{Color, EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).map_err(err)?;
    let w = code.width();
    let colors = code.to_colors();
    let mut svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {w}" width="220" height="220" shape-rendering="crispEdges"><rect width="{w}" height="{w}" fill="#ffffff"/>"##
    );
    for (i, c) in colors.iter().enumerate() {
        if *c == Color::Dark {
            let x = i % w;
            let y = i / w;
            svg.push_str(&format!(r##"<rect x="{x}" y="{y}" width="1" height="1" fill="#111827"/>"##));
        }
    }
    svg.push_str("</svg>");
    Ok(svg)
}

// ============ 文件库校验（规格 §3.5：聚合全部已配置保存目录） ============

#[tauri::command]
pub fn verify_start(app: tauri::AppHandle) -> Result<u64, String> {
    {
        let st = app.state::<AppState>();
        if st.verify_stop.swap(false, Ordering::Relaxed) {
            // 清残留标志
        }
    }
    let cfg = app.state::<AppState>().config();
    // 去重 + 仅存在的根（规格 §3.5）。
    let mut roots: Vec<PathBuf> = Vec::new();
    for d in [cfg.save_dir_tcp, cfg.save_dir_quic, cfg.save_dir_udp] {
        if d.is_dir() && !roots.contains(&d) {
            roots.push(d);
        }
    }
    if roots.is_empty() {
        return Err("没有已配置且存在的保存目录".into());
    }
    let id = {
        let st = app.state::<AppState>();
        st.alloc_task_id()
    };
    let app2 = app.clone();
    let stop_flag = {
        let st = app.state::<AppState>();
        st.verify_stop.clone()
    };
    let settled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let settled2 = settled.clone();
    let handle = tauri::async_runtime::spawn(async move {
        let mut agg = trft_core::scrub::VerifyReport::default();
        let mut seen: HashSet<String> = HashSet::new();
        'outer: for root in roots {
            let cache_path = cache_file_for(&root);
            let mut cache = HashCache::load(&cache_path, cfg.hash_cache_days);
            let key = root.to_string_lossy().to_lowercase();
            if !seen.insert(key) {
                continue;
            }
            let (vtx, mut vrx) = mpsc::unbounded_channel::<(u64, u64)>();
            let appv = app2.clone();
            tauri::async_runtime::spawn(async move {
                while let Some((done, total)) = vrx.recv().await {
                    let _ = appv.emit("trft://verify", serde_json::json!({ "done": done, "total": total }));
                }
            });
            let mut prog = move |done: u64, total: u64| {
                let _ = vtx.send((done, total));
            };
            let root2 = root.clone();
            let stop2 = stop_flag.clone();
            let res = tauri::async_runtime::spawn_blocking(move || {
                trft_core::scrub::verify_dir(&root2, &mut cache, Some(&stop2), Some(&mut prog))
            })
            .await;
            match res {
                Ok(mut r) => {
                    let dir_label = root.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    for m in &mut r.mismatches {
                        *m = format!("{dir_label}/{m}");
                    }
                    let _ = app2.emit("trft://log", serde_json::json!({ "level": "ok", "message": format!("校验 {}: {} 文件", dir_label, r.scanned) }));
                    agg.scanned += r.scanned;
                    agg.bytes += r.bytes;
                    agg.hit += r.hit;
                    agg.fresh += r.fresh;
                    agg.unreadable += r.unreadable;
                    agg.mismatches.extend(r.mismatches);
                }
                Err(e) => {
                    let _ = app2.emit("trft://log", serde_json::json!({ "level": "err", "message": format!("校验任务失败: {e}") }));
                    break 'outer;
                }
            }
        }
        let _ = app2.emit("trft://verify-result", &agg);
        // 自摘除（轮 3 P1-2）。
        finish_task(&app2, id);
        settled2.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let st = app.state::<AppState>();
    st.tasks.lock().expect("任务锁").insert(
        id,
        TaskHandle { handle },
    );
    if settled.load(std::sync::atomic::Ordering::SeqCst) {
        finish_task(&app, id);
    }
    update_awake(&app);
    Ok(id)
}

#[tauri::command]
pub fn verify_stop(app: tauri::AppHandle) {
    let st = app.state::<AppState>();
    st.verify_stop.store(true, Ordering::Relaxed);
}

// ============ 更新（ed25519 清单，与 CLI update 同引擎） ============

#[tauri::command]
pub async fn update_check(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let url = manifest_url(&app)?;
    let pubkey = trft_core::update::embedded_pubkey().map_err(err)?;
    let m = trft_core::update::fetch_manifest(&url, &pubkey).await.map_err(err)?;
    let current = env!("CARGO_PKG_VERSION");
    let has = trft_core::update::version_gt(&m.version, current);
    Ok(serde_json::json!({ "hasUpdate": has, "current": current, "version": m.version, "url": m.url }))
}

#[tauri::command]
pub async fn update_install(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let url = manifest_url(&app)?;
    let pubkey = trft_core::update::embedded_pubkey().map_err(err)?;
    let work = trft_core::config::app_data_dir().join("updates");
    let current = env!("CARGO_PKG_VERSION");
    match trft_core::update::run_update(&url, &pubkey, current, &work).await {
        Ok(Some(bak)) => {
            let _ = std::fs::remove_file(&bak);
            Ok(serde_json::json!({ "installed": true }))
        }
        Ok(None) => Ok(serde_json::json!({ "installed": false, "reason": "已是最新版本" })),
        Err(e) => Err(err(e)),
    }
}

fn manifest_url(app: &tauri::AppHandle) -> Result<String, String> {
    app.state::<AppState>()
        .config()
        .update_url
        .ok_or_else(|| "未配置更新源（设置 → UpdateUrl）".to_string())
}

// ============ 桌面集成 ============

#[tauri::command]
pub fn open_path(path: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&path)
            .spawn()
            .map_err(err)?;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("xdg-open").arg(&path).spawn().map_err(err)?;
        Ok(())
    }
}

/// 开机自启（HKCU Run 键，无需管理员——规格 §3.7）。
#[tauri::command]
pub fn autostart_set(enable: bool) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let run = hkcu
            .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_SET_VALUE)
            .map_err(err)?;
        if enable {
            let exe = std::env::current_exe().map_err(err)?;
            run.set_value("TrFileTransfer", &format!("\"{}\"", exe.display())).map_err(err)?;
        } else {
            let _ = run.delete_value("TrFileTransfer");
        }
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = enable;
        Err("当前平台不支持".into())
    }
}

#[tauri::command]
pub fn autostart_get() -> bool {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run")
            .and_then(|k| k.get_value::<String, _>("TrFileTransfer"))
            .is_ok()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

// ============ 设备记忆与发现（规格 §3.3：0xD1/0xD2；M5' 存储下沉 core） ============

pub use trft_core::devices::DeviceInfo;

fn now_secs() -> u64 {
    trft_core::devices::now_secs()
}

#[tauri::command]
pub fn devices_load(app: tauri::AppHandle) -> Vec<DeviceInfo> {
    app.state::<AppState>().devices.snapshot()
}

#[tauri::command]
pub fn devices_record(app: tauri::AppHandle, devices: Vec<DeviceInfo>) -> Result<(), String> {
    let store = app.state::<AppState>().devices.clone();
    for mut d in devices {
        d.source = trft_core::devices::DeviceSource::User; // 前端手工记录
        store.upsert(d);
    }
    Ok(())
}

#[tauri::command]
pub fn devices_remove(app: tauri::AppHandle, ip: String) -> Result<(), String> {
    app.state::<AppState>().devices.remove(&ip).map_err(err)
}

#[tauri::command]
pub fn devices_clear(app: tauri::AppHandle) -> Result<(), String> {
    app.state::<AppState>().devices.clear().map_err(err)
}

// ============ 接收前确认应答（规格 §3.3；前端弹窗回调） ============

#[tauri::command]
pub fn confirm_reply(app: tauri::AppHandle, id: u64, allow: bool) -> Result<(), String> {
    let reply = app
        .state::<AppState>()
        .pending_confirms
        .lock()
        .expect("确认锁")
        .remove(&id);
    match reply {
        Some(tx) => {
            let _ = tx.send(allow);
            Ok(())
        }
        None => Err("确认请求不存在或已超时".into()),
    }
}

// ============ 传输统计与历史（规格 §3.3；M5'） ============

#[tauri::command]
pub fn stats_summary(app: tauri::AppHandle) -> serde_json::Value {
    let st = app.state::<AppState>();
    let records = st.stats.load();
    let now = trft_core::devices::now_secs();
    let summary = trft_core::stats::summarize(&records, now, trft_core::stats::today_start_unix());
    serde_json::to_value(&summary).unwrap_or(serde_json::json!({}))
}

/// 历史明细（按时间倒序，最近 `limit` 条；direction: "all"|"S"|"R"）。
#[tauri::command]
pub fn stats_records(app: tauri::AppHandle, direction: String, limit: usize) -> Vec<serde_json::Value> {
    let st = app.state::<AppState>();
    let mut records = st.stats.load();
    records.reverse(); // 最新在前
    records
        .into_iter()
        .filter(|r| match direction.as_str() {
            "S" => r.dir == trft_core::stats::Direction::Send,
            "R" => r.dir == trft_core::stats::Direction::Recv,
            _ => true,
        })
        .take(limit.clamp(1, 5000))
        .map(|r| {
            serde_json::json!({
                "time": r.time,
                "dir": if r.dir == trft_core::stats::Direction::Send { "S" } else { "R" },
                "peer": r.peer,
                "bytes": r.bytes,
                "files": r.files,
                "secs": r.secs,
                "detail": r.detail,
                "path": r.path,
            })
        })
        .collect()
}

/// CSV 导出（UTF-8 BOM；保存到前端给定的绝对路径）。
#[tauri::command]
pub fn stats_export_csv(app: tauri::AppHandle, path: String) -> Result<String, String> {
    let st = app.state::<AppState>();
    let records = st.stats.load();
    let csv = trft_core::stats::export_csv(&records);
    std::fs::write(&path, csv.as_bytes()).map_err(err)?;
    Ok(path)
}

#[tauri::command]
pub fn stats_clear(app: tauri::AppHandle) -> Result<(), String> {
    let path = trft_core::stats::stats_path();
    if path.exists() {
        trft_core::config::atomic_write(&path, b"").map_err(err)?;
    }
    let _ = app.state::<AppState>().stats.load();
    Ok(())
}

// ============ 监控模式（规格 §3.2；M5'） ============

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorRequest {
    pub watch_dir: String,
    pub ip: String,
    pub port: u16,
    pub proto: Proto,
    pub code: Option<String>,
    pub limit: Option<u64>,
    pub passes: Option<u32>,
    pub fec_parity: Option<u8>,
    pub nofec: bool,
}

#[tauri::command]
pub async fn monitor_start(app: tauri::AppHandle, req: MonitorRequest) -> Result<(), String> {
    {
        let st = app.state::<AppState>();
        if st.monitor_handle.lock().expect("监控锁").is_some() {
            return Err("监控已在运行".into());
        }
    }
    if !PathBuf::from(&req.watch_dir).is_dir() {
        return Err(format!("监控目录不存在: {}", req.watch_dir));
    }
    if req.proto == Proto::Udp && req.code.is_some() {
        return Err("单向 UDP 不支持配对码/加密（规格 §3.1）".into());
    }
    validate_code(&req.code)?;
    let addr = addr_of(&req.ip, req.port)?;
    let cfg = app.state::<AppState>().config();
    let stats = app.state::<AppState>().stats.clone();

    let core_proto = match req.proto {
        Proto::Tcp => MonitorProto::Tcp,
        Proto::Udt => MonitorProto::Quic,
        Proto::Udp => MonitorProto::Udp,
    };
    let (stx, srx) = tokio::sync::watch::channel(false);
    let (etx, mut erx) = mpsc::unbounded_channel::<trft_core::monitor::MonitorEvent>();
    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        // 监控事件 → 前端（trft://monitor）。
        use tauri::Emitter;
        while let Some(ev) = erx.recv().await {
            let _ = app2.emit("trft://monitor", &ev);
        }
    });

    let mut mcfg = trft_core::monitor::MonitorConfig::new(
        PathBuf::from(&req.watch_dir),
        addr,
        core_proto,
        srx,
    );
    mcfg.send_opts = SendOptions {
        pairing_code: req.code.clone(),
        speed_limit_bps: req.limit.unwrap_or(0).min(10_000_000) * 1024,
        encrypt: true,
        compress: true,
        stats: Some(stats.clone()),
        ..Default::default()
    };
    mcfg.udp_opts = UdpSendOptions {
        passes: req.passes.unwrap_or(cfg.udp_passes).clamp(1, 5),
        fec: !req.nofec && cfg.udp_fec,
        fec_parity: req.fec_parity.unwrap_or(cfg.udp_fec_parity).clamp(1, 8),
        speed_limit_bps: req.limit.unwrap_or(0).min(10_000_000) * 1024,
        progress: None,
        stats: Some(stats),
    };
    mcfg.events = Some(etx);

    let a3 = app.clone();
    let handle = tauri::async_runtime::spawn(async move {
        // run_monitor 启动即败（目录竞删等）——上报并清理句柄槽（轮 5 P3）。
        if let Err(e) = trft_core::monitor::run_monitor(mcfg).await {
            let _ = a3.emit("trft://log", serde_json::json!({ "level": "err", "message": format!("监控退出: {e}") }));
            let st = a3.state::<AppState>();
            *st.monitor_stop.lock().expect("监控锁") = None;
            *st.monitor_handle.lock().expect("监控锁") = None;
        }
    });
    let st = app.state::<AppState>();
    *st.monitor_stop.lock().expect("监控锁") = Some(stx);
    *st.monitor_handle.lock().expect("监控锁") = Some(handle);
    let _ = app.emit("trft://log", serde_json::json!({ "level": "ok", "message": format!("监控启动 {} → {}:{}", req.watch_dir, req.ip, req.port) }));
    update_awake(&app);
    Ok(())
}

#[tauri::command]
pub async fn monitor_stop(app: tauri::AppHandle) -> Result<(), String> {
    // 守卫不跨 await：先摘出句柄再等待（future 必须 Send）。
    let tx = {
        let st = app.state::<AppState>();
        let mut g = st.monitor_stop.lock().expect("监控锁");
        g.take()
    };
    if let Some(tx) = tx {
        let _ = tx.send(true);
    }
    let h = {
        let st = app.state::<AppState>();
        let mut g = st.monitor_handle.lock().expect("监控锁");
        g.take()
    };
    if let Some(h) = h {
        // 给循环最多 2s 自然退出（abort 兜底——半成品由孤儿清扫兜底口径不变）。
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), h).await;
    }
    let _ = app.emit("trft://log", serde_json::json!({ "level": "ok", "message": "监控已停止" }));
    update_awake(&app);
    Ok(())
}

#[tauri::command]
pub fn monitor_status(app: tauri::AppHandle) -> bool {
    app.state::<AppState>()
        .monitor_handle
        .lock()
        .expect("监控锁")
        .is_some()
}

#[tauri::command]
pub async fn discover_devices(app: tauri::AppHandle) -> Result<Vec<DeviceInfo>, String> {
    let cfg = app.state::<AppState>().config();
    // 广播目标：各 IPv4 网卡广播地址 + 受限广播（规格 §3.3 仅 IPv4）。
    let mut targets: Vec<SocketAddr> = vec!["255.255.255.255:0".parse().unwrap()];
    if let Ok(addrs) = if_addrs::get_if_addrs() {
        for a in addrs {
            if let if_addrs::IfAddr::V4(v4) = a.addr {
                if let Some(bcast) = v4.broadcast {
                    if !bcast.is_loopback() && !bcast.is_unspecified() {
                        targets.push(SocketAddr::new(std::net::IpAddr::V4(bcast), cfg.discovery_port));
                    }
                }
            }
        }
    }
    let targets: Vec<SocketAddr> = targets
        .into_iter()
        .map(|t| SocketAddr::new(t.ip(), cfg.discovery_port))
        .collect();
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.map_err(err)?;
    sock.set_broadcast(true).map_err(err)?;
    let found = trft_core::discovery::discover_on(&sock, &targets, std::time::Duration::from_millis(1500))
        .await
        .map_err(err)?;
    // 发现结果并入设备记忆（core DeviceStore）。
    let store = app.state::<AppState>().devices.clone();
    let devices: Vec<DeviceInfo> = found
        .into_iter()
        .map(|d| DeviceInfo {
            name: d.name,
            ip: d.ip,
            port: d.tcp_port.or(d.udt_port).unwrap_or(cfg.discovery_port),
            proto: if d.tcp_port.is_some() { "tcp".into() } else { "udt".into() },
            needs_pairing: d.needs_pairing,
            last_seen: now_secs(),
            source: trft_core::devices::DeviceSource::Discovery,
        })
        .collect();
    for d in devices.clone() {
        store.upsert(d);
    }
    Ok(devices)
}

/// 有 TCP/UDT 监听器时确保发现应答服务在跑；没有则停掉。flags 实时读取。
fn update_discovery_answer(app: &tauri::AppHandle) {
    let st = app.state::<AppState>();
    let any_stream = st
        .receivers
        .lock()
        .expect("接收器锁")
        .keys()
        .any(|p| matches!(p, Proto::Tcp | Proto::Udt));
    let mut slot = st.discovery_answer.lock().expect("应答锁");
    if any_stream && slot.is_none() {
        let cfg = st.config();
        let app_flags = app.clone();
        let app_spawn = app.clone();
        let flags: std::sync::Arc<dyn Fn() -> (Option<u16>, Option<u16>, bool) + Send + Sync> =
            std::sync::Arc::new(move || {
                let st2 = app_flags.state::<AppState>();
                let map = st2.receivers.lock().expect("接收器锁");
                let tcp = map.get(&Proto::Tcp).map(|r| r.port);
                let udt = map.get(&Proto::Udt).map(|r| r.port);
                let pairing = st2.config().pairing_code.is_some();
                (tcp, udt, pairing)
            });
        let name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "TrFileTransfer".into());
        *slot = Some(tauri::async_runtime::spawn(async move {
            let app2 = app_spawn;
            let bind = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), cfg.discovery_port);
            match tokio::net::UdpSocket::bind(bind).await {
                Ok(sock) => {
                    let _ = trft_core::discovery::serve_answer(sock, name, flags).await;
                }
                Err(e) => {
                    let _ = tauri::Emitter::emit(&app2, "trft://log", serde_json::json!({ "level": "warn", "message": format!("发现应答端口 {} 占用: {e}", cfg.discovery_port) }));
                }
            }
        }));
    } else if !any_stream && slot.is_some() {
        if let Some(h) = slot.take() {
            h.abort();
        }
    }
}

// ============ 文本历史（规格 §3.2：历史落盘 200 条重启不丢） ============

fn text_history_path() -> PathBuf {
    trft_core::config::app_data_dir().join("text-history.txt")
}

/// 追加一条（时间戳	文本）；超过 200 条重写保留末 200。
pub fn text_history_append(text: &str) {
    let path = text_history_path();
    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .map(|t| t.lines().rev().map(String::from).collect())
        .unwrap_or_default();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let one_line = text.replace('\n', " ").replace('\r', " ");
    lines.push(format!("{stamp}	{one_line}"));
    let keep: Vec<String> = if lines.len() > 200 { lines[lines.len() - 200..].to_vec() } else { lines };
    let mut out = String::new();
    for l in keep.iter().rev() {
        out.push_str(l);
        out.push('\n');
    }
    let _ = trft_core::config::atomic_write(&path, out.as_bytes());
}

#[tauri::command]
pub fn text_history_load() -> Vec<serde_json::Value> {
    std::fs::read_to_string(text_history_path())
        .map(|t| {
            t.lines()
                .rev()
                .filter_map(|l| l.split_once('\t'))
                .map(|(stamp, text)| serde_json::json!({ "time": stamp, "text": text }))
                .collect()
        })
        .unwrap_or_default()
}

#[tauri::command]
pub fn text_history_clear() -> Result<(), String> {
    trft_core::config::atomic_write(&text_history_path(), b"").map_err(err)
}

// ============ 发送队列持久化（规格 §3.2：queue.txt，`|` 分隔，上限 500 项） ============

#[derive(serde::Deserialize)]
pub struct QueueItem {
    pub kind: String,
    pub path: String,
}

fn queue_path() -> PathBuf {
    trft_core::config::app_data_dir().join("queue.txt")
}

#[tauri::command]
pub fn queue_load() -> Vec<serde_json::Value> {
    let Ok(text) = std::fs::read_to_string(queue_path()) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        // 与 queue_save 同分隔符 `|`（轮 7 P1：此前按 tab 分割——保存的行
        // 不含 tab，恢复恒为空，持久化形同虚设）。
        .filter_map(|l| l.split_once('|'))
        .map(|(kind, path)| serde_json::json!({ "kind": kind, "path": path }))
        .take(500)
        .collect()
}

#[tauri::command]
pub fn queue_save(items: Vec<QueueItem>) -> Result<(), String> {
    if items.len() > 500 {
        return Err("队列上限 500 项（规格 §3.2）".into());
    }
    let mut out = String::new();
    for it in items {
        if it.path.contains('|') {
            continue; // `|` 为分隔符（Windows 文件名本身不含 |，防御性跳过）
        }
        out.push_str(&format!("{}|{}
", it.kind, it.path));
    }
    trft_core::config::atomic_write(&queue_path(), out.as_bytes()).map_err(err)
}

/// 供托盘/主窗口保存配置（关窗时调用）。
pub fn save_now(app: &tauri::AppHandle) {
    let st = app.state::<AppState>();
    let _ = st.save_config();
}
