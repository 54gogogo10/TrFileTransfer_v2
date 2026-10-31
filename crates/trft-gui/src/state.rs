//! GUI 全局状态：配置、接收器/共享/任务句柄、进度事件出口。
//! 事件通道纪律：core 侧 `ProgressHub` 只认 `UnboundedSender<ProgressEvent>`，
//! GUI 为每条长活链路（接收器）与每个发送任务各建一条通道 + 转发任务。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use trft_core::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udt,
    Udp,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udt => "UDT(QUIC)",
            Proto::Udp => "UDP",
        }
    }
}

/// 运行中的接收器（abort = 停止；半成品由孤儿清扫兜底）。
/// 多地址绑定（规格 §3.3：每勾选地址一个监听器）→ 每地址一个任务句柄。
pub struct ReceiverHandle {
    pub proto: Proto,
    pub port: u16,
    /// 实际绑定成功的地址。
    pub bound: Vec<String>,
    pub handles: Vec<tauri::async_runtime::JoinHandle<()>>,
}

/// HTTP 共享句柄（graceful shutdown）。
pub struct HttpHandle {
    pub port: u16,
    pub shutdown: tokio::sync::oneshot::Sender<()>,
}

/// 发送/校验任务（cancel = abort）。
pub struct TaskHandle {
    pub handle: tauri::async_runtime::JoinHandle<()>,
}

pub struct AppState {
    pub cfg: Mutex<Config>,
    pub cfg_path: PathBuf,
    pub receivers: Mutex<HashMap<Proto, ReceiverHandle>>,
    pub http: Mutex<Option<HttpHandle>>,
    pub tasks: Mutex<HashMap<u64, TaskHandle>>,
    /// 任务 ID → 进度事件 ID（UI 卡片挂暂停/继续按钮用；任务收尾即移除）。
    pub task_progress: Mutex<HashMap<u64, u64>>,
    pub next_task: AtomicU64,
    /// 校验中途停止标志（规格 §3.5；Arc 供任务闭包克隆）。
    pub verify_stop: Arc<AtomicBool>,
    /// 设备发现应答服务（有 TCP/UDT 监听器时运行；0xD1→0xD2）。
    pub discovery_answer: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    /// 设备记忆（M5'：core 共享实例——接收器确认/分目录解析与 GUI 同源）。
    pub devices: Arc<trft_core::devices::DeviceStore>,
    /// 传输统计（M5'：stats.log；GUI/CLI 同一文件）。
    pub stats: Arc<trft_core::stats::StatsLog>,
    /// 接收前确认：请求 ID → 应答通道（前端 confirm_reply 消费）。
    pub pending_confirms: Mutex<HashMap<u64, tokio::sync::oneshot::Sender<bool>>>,
    pub next_confirm: AtomicU64,
    /// 进度 Hub 全局基址分配（×1_000_000——轮 7 P1：Hub 内 ID 从 1 递增，并发 Hub 串台）。
    pub next_hub: AtomicU64,
    /// 同 IP 确认免重复窗口（规格 §3.3；跨协议共享——App 级一份）。
    pub confirm_seen: Arc<tokio::sync::Mutex<HashMap<std::net::IpAddr, std::time::Instant>>>,
    /// 监控模式（M5'：单实例；stop 信号 + 任务句柄）。
    pub monitor_stop: Mutex<Option<tokio::sync::watch::Sender<bool>>>,
    pub monitor_handle: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}

impl AppState {
    pub fn new(cfg: Config, cfg_path: PathBuf) -> Self {
        Self {
            cfg: Mutex::new(cfg),
            cfg_path,
            receivers: Mutex::new(HashMap::new()),
            http: Mutex::new(None),
            tasks: Mutex::new(HashMap::new()),
            task_progress: Mutex::new(HashMap::new()),
            next_task: AtomicU64::new(1),
            verify_stop: Arc::new(AtomicBool::new(false)),
            discovery_answer: Mutex::new(None),
            devices: Arc::new(trft_core::devices::DeviceStore::load(
                trft_core::devices::devices_path(),
            )),
            stats: Arc::new(trft_core::stats::StatsLog::default_log()),
            pending_confirms: Mutex::new(HashMap::new()),
            next_confirm: AtomicU64::new(1),
            next_hub: AtomicU64::new(1),
            confirm_seen: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            monitor_stop: Mutex::new(None),
            monitor_handle: Mutex::new(None),
        }
    }

    pub fn alloc_task_id(&self) -> u64 {
        self.next_task.fetch_add(1, Ordering::Relaxed)
    }

    /// 配置快照（命令层统一入口，避免守卫顺序问题）。
    pub fn config(&self) -> Config {
        self.cfg.lock().expect("配置锁").clone()
    }

    pub fn save_config(&self) -> Result<(), String> {
        let cfg = self.config();
        cfg.save(&self.cfg_path).map_err(|e| e.to_string())
    }
}

/// 进度事件转发：core 通道 → 前端事件（通道关闭即转发任务自然结束）。
pub fn forward_progress(app: tauri::AppHandle, mut rx: tokio::sync::mpsc::UnboundedReceiver<trft_core::progress::ProgressEvent>) {
    use tauri::Emitter;
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let _ = app.emit("trft://progress", &ev);
            if ev.kind == "recv" && (ev.state == "done" || ev.state == "failed") {
                // 最近接收视图直接消费进度终态，这里补一条日志事件便于历史区展示。
                let _ = app.emit(
                    "trft://log",
                    serde_json::json!({ "level": if ev.state == "done" { "ok" } else { "err" }, "message": ev.name }),
                );
            }
        }
    });
}
