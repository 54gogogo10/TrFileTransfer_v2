//! 进度事件（规格 §3.1：节流 100ms，GUI/CLI 共用；§1.4 分层纪律——节流器在 core，
//! UI 只消费事件）。设计点：
//!
//! - 热路径零分配：`Reporter::add` 仅做一次原子加 + 一次无竞争 Mutex 时间戳检查；
//! - 不派生后台任务：节流靠「距上次发送 ≥100ms 才发」的惰性检查，随 Reporter 析构自然停止；
//! - 终态必达：`finish`/`fail` 绕过节流立即发送，且此后 `add` 一律忽略
//!   （分块多连接共享同一 Reporter 时，迟到块不得污染终态）；
//! - `total = 0` 表示总量未知（0x01 清单流式发送等场景），UI 显示不定进度。

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::mpsc::UnboundedSender;
// 用 tokio 时钟而非 std：生产环境语义一致，判别测试可随暂停时钟确定性推进。
use tokio::time::Instant;

/// 进度节流间隔（规格 §3.1）。
pub const THROTTLE: std::time::Duration = std::time::Duration::from_millis(100);

/// 进度事件（serde 直出 JSON，GUI/Tauri 事件通道共用同一结构）。
#[derive(Debug, Clone, Serialize)]
pub struct ProgressEvent {
    /// 单调递增的传输 ID（Hub 内唯一）。
    pub id: u64,
    /// `"send"` / `"recv"`。
    pub kind: &'static str,
    /// 文件名或文本摘要（UI 卡片标题）。
    pub name: String,
    /// 已完成字节数。
    pub done: u64,
    /// 总字节数；0 = 未知（不定进度）。
    pub total: u64,
    /// `"running"` / `"done"` / `"failed"`。
    pub state: &'static str,
    /// 对端 IP（接收端 = 来源，发送端 = 目标；None = 未上报）。UI 据此显示
    /// 已知设备名徽标（对齐原版 v2.15 DeviceDisplay.NameFor 的接收侧）。
    pub peer: Option<String>,
}

const STATE_RUNNING: u8 = 0;
const STATE_DONE: u8 = 1;
const STATE_FAILED: u8 = 2;

/// 终态守卫：`finish` 显式成功；其余任何路径（含 `?` 早退与 panic）Drop 即上报失败——
/// 判错方向：失败必须可见，不得静默消失。
pub struct Outcome {
    rep: Option<Reporter>,
    settled: bool,
}

impl Outcome {
    pub fn new(rep: Option<Reporter>) -> Self {
        Self {
            rep,
            settled: false,
        }
    }

    pub fn finish(mut self) {
        self.settled = true;
        if let Some(r) = &self.rep {
            r.finish();
        }
    }
}

impl Drop for Outcome {
    fn drop(&mut self) {
        if !self.settled {
            if let Some(r) = &self.rep {
                r.fail();
            }
        }
    }
}

#[derive(Debug)]
struct Shared {
    id: u64,
    kind: &'static str,
    name: String,
    /// 对端 IP（set_peer 一次写入；连接建立后紧随 register，无热路径竞争）。
    peer: Mutex<Option<String>>,
    total: AtomicU64,
    done: AtomicU64,
    state: AtomicU8,
    /// 上次节流发送时刻；None = 尚未发过（首次 add 立即发）。
    last: Mutex<Option<Instant>>,
}

/// 进度上报句柄（Clone 共享同一计数；多连接分块发送各自持一份）。
#[derive(Clone, Debug)]
pub struct Reporter {
    sh: Arc<Shared>,
    tx: UnboundedSender<ProgressEvent>,
}

impl Reporter {
    fn snapshot(sh: &Shared, state: &'static str) -> ProgressEvent {
        ProgressEvent {
            id: sh.id,
            kind: sh.kind,
            name: sh.name.clone(),
            done: sh.done.load(Ordering::Relaxed),
            total: sh.total.load(Ordering::Relaxed),
            state,
            peer: sh.peer.lock().expect("进度对端锁").clone(),
        }
    }

    /// 完成量增加 `n` 字节（终态后忽略）。首次调用立即发送，其后按 100ms 节流。
    pub fn add(&self, n: u64) {
        if n == 0 || self.sh.state.load(Ordering::Relaxed) != STATE_RUNNING {
            return;
        }
        self.sh.done.fetch_add(n, Ordering::Relaxed);
        let mut last = self.sh.last.lock().expect("进度时间戳锁");
        let due = match *last {
            None => true, // 首报立即，保证短传输至少有一个运行态事件
            Some(t) => t.elapsed() >= THROTTLE,
        };
        if due {
            *last = Some(Instant::now());
            drop(last);
            let _ = self.tx.send(Self::snapshot(&self.sh, "running"));
        }
    }

    /// 上报对端 IP（register 后紧随调用一次；重复调用以首值为准——
    /// 分块多连接共享 Reporter 时，迟到连接不得改写初始归属）。
    pub fn set_peer(&self, ip: &str) {
        let mut p = self.sh.peer.lock().expect("进度对端锁");
        if p.is_none() {
            *p = Some(ip.to_string());
        }
    }

    /// 修正总量（0x04 差量清单汇总后、0x02 协商大小后调用）。
    pub fn set_total(&self, total: u64) {
        self.sh.total.store(total, Ordering::Relaxed);
    }

    /// 本传输的事件 ID（UI 把任务按钮绑定到对应进度卡用）。
    pub fn id(&self) -> u64 {
        self.sh.id
    }

    /// 终态：成功。绕过节流立即发送，此后 add 忽略。
    pub fn finish(&self) {
        self.sh.state.store(STATE_DONE, Ordering::Relaxed);
        let _ = self.tx.send(Self::snapshot(&self.sh, "done"));
    }

    /// 终态：失败。绕过节流立即发送，此后 add 忽略。
    pub fn fail(&self) {
        self.sh.state.store(STATE_FAILED, Ordering::Relaxed);
        let _ = self.tx.send(Self::snapshot(&self.sh, "failed"));
    }

    /// 条件终态：仅当仍在 running 时置失败。「会话逐出」等放弃路径用——
    /// 已完成（done）的传输不得被翻转为 failed（轮 3 F1）。
    pub fn fail_if_running(&self) {
        if self.sh.state.load(Ordering::Relaxed) == STATE_RUNNING {
            self.fail();
        }
    }
}

/// 进度事件出口 + ID 分配器（Clone 供多处持有）。
#[derive(Clone, Debug)]
pub struct ProgressHub {
    next: Arc<AtomicU64>,
    tx: UnboundedSender<ProgressEvent>,
}

impl ProgressHub {
    pub fn new(tx: UnboundedSender<ProgressEvent>) -> Self {
        Self {
            next: Arc::new(AtomicU64::new(1)),
            tx,
        }
    }

    /// 带 ID 基址的 Hub（GUI 专用：每个 Hub 一个全局唯一基址——
    /// 前端以 progressId 为全局键，Hub 内从 1 递增会让并发 Hub 互相串台）。
    pub fn with_id_base(tx: UnboundedSender<ProgressEvent>, base: u64) -> Self {
        Self {
            next: Arc::new(AtomicU64::new(base)),
            tx,
        }
    }

    /// 注册一个传输：分配 ID 并返回 Reporter。`total` 传 0 表示未知。
    pub fn register(&self, kind: &'static str, name: impl Into<String>, total: u64) -> Reporter {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        Reporter {
            sh: Arc::new(Shared {
                id,
                kind,
                name: name.into(),
                peer: Mutex::new(None),
                total: AtomicU64::new(total),
                done: AtomicU64::new(0),
                state: AtomicU8::new(STATE_RUNNING),
                last: Mutex::new(None),
            }),
            tx: self.tx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::unbounded_channel;

    #[tokio::test(start_paused = true)]
    async fn throttles_to_100ms_but_first_and_final_always_emitted() {
        let (tx, mut rx) = unbounded_channel();
        let hub = ProgressHub::new(tx);
        let r = hub.register("send", "a.bin", 10_000);

        // 首报立即 + 999 次快速 add 全被节流吞掉（暂停时钟下不到期）。
        r.add(1);
        for _ in 0..999 {
            r.add(1);
        }
        let mut got = 0;
        while rx.try_recv().is_ok() {
            got += 1;
        }
        assert_eq!(got, 1, "节流期 1000 次 add 只能发 1 个事件");

        // 推进时钟 100ms → 下一次 add 解禁。
        tokio::time::advance(THROTTLE).await;
        r.add(1);
        let ev = rx.try_recv().expect("解禁后应有事件");
        assert_eq!(ev.done, 1001);
        assert_eq!(ev.total, 10_000);
        assert!(rx.try_recv().is_err());

        // 终态绕过节流必达（距上次 <100ms 也发）。
        r.finish();
        let ev = rx.try_recv().expect("终态必达");
        assert_eq!(ev.state, "done");
        assert_eq!(ev.done, 1001);
        assert!(rx.try_recv().is_err());

        // 终态后 add 忽略（分块多连接迟到块不污染终态）。
        r.add(1);
        assert!(rx.try_recv().is_err(), "终态后不得再有事件");
    }

    #[tokio::test(start_paused = true)]
    async fn fail_is_terminal_and_hub_ids_are_unique() {
        let (tx, mut rx) = unbounded_channel();
        let hub = ProgressHub::new(tx);
        let r1 = hub.register("recv", "x", 0);
        let r2 = hub.register("send", "y", 0);
        assert_ne!(r1.sh.id, r2.sh.id, "Hub 内 ID 必须唯一");

        r1.fail();
        let ev = rx.try_recv().expect("fail 必达");
        assert_eq!(ev.state, "failed");
        r1.add(5);
        assert!(rx.try_recv().is_err(), "fail 后 add 必须忽略");
    }

    #[tokio::test(start_paused = true)]
    async fn zero_total_is_indeterminate_but_still_reported() {
        let (tx, mut rx) = unbounded_channel();
        let hub = ProgressHub::new(tx);
        let r = hub.register("send", "流式", 0);
        r.add(4096);
        let ev = rx.try_recv().expect("未知总量也要报运行态");
        assert_eq!(ev.total, 0);
        assert_eq!(ev.done, 4096);
        assert_eq!(ev.name, "流式");
    }

    #[tokio::test]
    async fn peer_set_once_flows_into_events() {
        let (tx, mut rx) = unbounded_channel();
        let hub = ProgressHub::new(tx);
        let r = hub.register("recv", "p.bin", 100);
        r.set_peer("192.168.1.20");
        r.set_peer("10.0.0.1"); // 首值锁定：分块多连接迟到者不得改写归属
        r.add(1);
        let ev = rx.try_recv().expect("运行态事件");
        assert_eq!(
            ev.peer.as_deref(),
            Some("192.168.1.20"),
            "对端 IP 必须进事件且取首值"
        );
        r.finish();
        let fin = rx.try_recv().expect("终态事件");
        assert_eq!(fin.peer.as_deref(), Some("192.168.1.20"));
        assert!(rx.try_recv().is_err(), "set_peer 本身不得产生事件");
    }
}
