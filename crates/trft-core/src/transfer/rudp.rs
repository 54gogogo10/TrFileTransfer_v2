//! RUDP 槽位（原生 Rust 实现）：UDP 之上的自研可靠有序字节流，帧协议与 TCP 完全一致
//! （规格 §4.3：与 UDT4/C# 不做包级互通，线格式见 WIRE-PROTOCOL.md「RUDP 传输」）。
//! 历史注记：曾以「UDT」为名——因与 UDT4 协议重名且实现并非 UDT4，2026-11-12 更名
//! RUDP（TECH-STACK §7.29）；本次更名只改命名，线格式/行为与更名前零差异。
//!
//! 结构（对齐 `udp.rs` 的「引擎与 socket 解耦」纪律）：
//! - `RudpConn`：连接状态机（发送窗口/重传/RTT 估计 + 接收重排/确认），纯逻辑，
//!   经 `mpsc` 出入包，可绕过 socket 直接构造对偶做丢包注入单测；
//! - `RudpStream`：`AsyncRead + AsyncWrite`，帧层零改动复用（0x05 配对、0x09 加密、
//!   分块/续传/文件夹/限速/进度全部继承 TCP 路径）；
//! - 客户端 `connect_rudp`（HS 握手 + 定时重发），服务端 `serve_rudp_on`（单 socket
//!   按 conn_id 多路分解 → `receiver::handle_conn_quic` 复用入口：闸/锁/统计同口径）。
//!
//! 与 UDT4 的语义差异（TECH-STACK §3 登记）：固定窗口（64×1200B）无拥塞控制、
//! 立即逐包 ACK + SACK、RTO 按 RFC 6298 简化 EWMA（200ms–3s）、30s 空闲超时
//! （对齐原版 UDT_RCVTIMEO/UDT_SNDTIMEO）。

use crate::error::{proto, Error, Result};
use crate::protocol::rudp as pw;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{watch, Semaphore};

/// 在途包窗口（双向）：1024 包 × 协商 mss（环回 60000 → 高带宽；LAN 1400 →
/// 1.4MB/RTT 50ms ≈ 28MB/s——旧值 256 在真实 RTT 链路上把吞吐钉在 6MB/s）。
const RUDP_WINDOW: usize = 1024;
/// 乱序重排缓冲上限（字节——超出丢弃等重传；包数上限退居次席，mss 大时防
/// 重排内存无界：60000B mss × 无限包数曾在环回突发下放大到数十 MB/连接）。
const RUDP_PENDING_CAP_PKTS: usize = 4 * RUDP_WINDOW;
const RUDP_PENDING_CAP_BYTES: usize = 2 * 1024 * 1024;
/// 重传扫描节拍。
const RUDP_TICK: Duration = Duration::from_millis(25);
/// 快速重传最小间隔（SACK 空洞触发的立即重发限频——与扫描节拍同拍）。
const RUDP_FAST_RETX_MIN: Duration = RUDP_TICK;
/// RTO 下限/上限/初值（ms）。
/// 单次唤醒的批量上限（泵排空/驱动处理/出包发送共用——每批一次让出，
/// 去掉逐包调度开销；§7.28「批量收发/ACK 合批」）。
const RUDP_BATCH_CAP: usize = 512;
/// 读侧单次 poll 的聚合上限（把逐块唤醒拼成大块）。
const RUDP_READ_AGG: usize = 256 * 1024;
/// 按序待读缓冲上限（块数，轮 10 P1-3——≥2× 窗口；满即「投不进则不确认」，
/// 对端重传背压，读者消化后 ACK 恢复）。
const RUDP_DATA_CAP: usize = 2 * 1024;
const RUDP_RTO_MIN_MS: u64 = 50;
const RUDP_RTO_MAX_MS: u64 = 3000;
const RUDP_RTO_INIT_MS: u64 = 400;
/// 非环回链路的 MSS 提案（以太网 1500 − IP/UDP 头 − 余量）。
const RUDP_MSS_LAN: usize = 1400;
/// 单包重传上限（超过判链路过差，断连——不无限重传放大）。
const RUDP_RETRIES_MAX: u32 = 12;
/// 空闲超时（对齐原版 UDT_RCVTIMEO/UDT_SNDTIMEO = 30 秒）。
const RUDP_IDLE: Duration = Duration::from_secs(30);
/// 握手超时（原版 WaitForConnectionReady 30×200ms 同口径上限）。
const RUDP_HS_TIMEOUT: Duration = Duration::from_secs(30);
/// 握手重发间隔。
const RUDP_HS_RESEND: Duration = Duration::from_millis(300);
/// FIN 等待 FIN_ACK 的兜底（超时按尽力收尾放行，与 TCP `let _ = shutdown()` 同口径）。
const RUDP_FIN_WAIT: Duration = Duration::from_secs(5);
/// 服务端连接表上限。
const RUDP_CONN_CAP: usize = 256;

type Pkt = (u8, u32, Vec<u8>); // (kind, seq, payload)

/// 已编码出包（Arc 共享：首发与重传零再编码零再拷贝——重传只是克隆指针）。
type WirePkt = Arc<[u8]>;
/// 出口通道元素。
type OutPkt = (SocketAddr, WirePkt);

/// 序号回绕算术（u32 模 2^32 距离 <2^31 为「在前」）：多 TB 传输（4.29G 包 ×
/// mss）必回绕，朴素整数比较在回绕点把新周期包判为旧包——接收端永久缺包、
/// 发送端重传超限断连。全部序比较统一走这对助手。
#[inline]
fn seq_ge(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) < 0x8000_0000
}
#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    !seq_ge(a, b)
}
#[inline]
fn seq_gt(a: u32, b: u32) -> bool {
    a != b && seq_ge(a, b)
}

#[derive(Debug, Clone)]
struct InFlight {
    /// 已编码完整数据报（头+载荷）——首发即编码，重传只克隆 Arc。
    pkt: WirePkt,
    first_send: Instant,
    last_send: Instant,
    retries: u32,
    /// RTO/快速重发过后置位：其 ACK 采样不代表真实 RTT（Karn 修正，防 RTO
    /// 正反馈膨胀到上限——大传输爬行的共因）。
    retransmitted: bool,
}

#[derive(Debug)]
struct SendSide {
    inflight: HashMap<u32, InFlight>,
    next_seq: u32,
    /// 本连接协商 mss（发送分片上限）。
    mss: usize,
    srtt_ms: f64,
    rttvar_ms: f64,
    rto: Duration,
    shutdown_req: bool,
    fin_sent_at: Option<Instant>,
    /// 快速重传限频基准（SACK 空洞触发的立即重发至多每拍一次）。
    last_fast_retx: Instant,
    /// 最近一次累计确认推进时刻（轮 10——「重传超限」断连的判据改为
    /// **无进展时长**：背压丢弃不是丢包，读者消化后 ACK 推进即复位）。
    last_progress: Instant,
}

impl SendSide {
    fn new(mss: usize) -> Self {
        Self {
            inflight: HashMap::new(),
            next_seq: 0,
            mss,
            srtt_ms: 0.0,
            rttvar_ms: 0.0,
            rto: Duration::from_millis(RUDP_RTO_INIT_MS),
            shutdown_req: false,
            fin_sent_at: None,
            last_fast_retx: Instant::now(),
            last_progress: Instant::now(),
        }
    }

    /// RFC 6298 简化 EWMA：srtt = 7/8 s + 1/8 x；rttvar = 3/4 v + 1/4 |x−s|。
    /// （重传包的采样偏大 → RTO 偏保守，方向安全。）
    /// **背压滞留守卫（轮 10）**：ACK 语义 = 投递确认，慢读者场景样本含
    /// 对端缓冲滞留（秒级）——采了会把 RTO 推到 3s 上限，恢复每轮 3s
    /// （10MB 慢读者恢复 66s 实测）。样本显著高于当前 srtt（>4×+200ms）
    /// 判为滞留不采；真 RTT 激增按低估方向偏差（过度重传无害）。
    fn rto_update(&mut self, sample_ms: f64) {
        if self.srtt_ms > 0.0 && sample_ms > self.srtt_ms * 4.0 + 200.0 {
            return;
        }
        if self.srtt_ms <= 0.0 {
            self.srtt_ms = sample_ms;
        } else {
            self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * (sample_ms - self.srtt_ms).abs();
            self.srtt_ms = 0.875 * self.srtt_ms + 0.125 * sample_ms;
        }
        let rto = self.srtt_ms + 4.0 * self.rttvar_ms;
        self.rto = Duration::from_millis((rto as u64).clamp(RUDP_RTO_MIN_MS, RUDP_RTO_MAX_MS));
    }
}

#[derive(Debug)]
struct RecvSide {
    expected: u32,
    pending: HashMap<u32, Vec<u8>>,
    /// 重排缓存字节数（与包数上限共同把关——mss 协商大包时防内存放大）。
    pending_bytes: usize,
    /// 本连接协商 mss（超限 DATA 丢弃——垃圾/攻击面收口）。
    mss: usize,
    remote_fin: Option<u32>,
    eof_seen: bool,
}

impl RecvSide {
    fn new(mss: usize) -> Self {
        Self {
            expected: 0,
            pending: HashMap::new(),
            pending_bytes: 0,
            mss,
            remote_fin: None,
            eof_seen: false,
        }
    }

    /// ACK 载荷用 SACK 区间（pending 键合并连续段，≤64 段）。
    /// 排序以 `expected` 为原点按回绕距离——回绕点两侧的朴素排序会交错出错。
    fn sack_ranges(&self) -> Vec<(u32, u8)> {
        let mut keys: Vec<u32> = self.pending.keys().copied().collect();
        let origin = self.expected;
        keys.sort_unstable_by_key(|k| k.wrapping_sub(origin));
        let mut out = Vec::new();
        let mut i = 0;
        while i < keys.len() && out.len() < 64 {
            let start = keys[i];
            let mut len = 1u8;
            while i + 1 < keys.len()
                && keys[i + 1] == keys[i].wrapping_add(1)
                && u32::from(len) < u32::from(u8::MAX)
            {
                i += 1;
                len += 1;
            }
            out.push((start, len));
            i += 1;
        }
        out
    }
}

/// 已编码出包出口类型（socket 发送任务消费；共享注入点见 `build_conn`）。
type OutTx = Mutex<Option<UnboundedSender<OutPkt>>>;

/// 连接状态机（收发双侧共享；驱动任务与 `RudpStream` 各持 Arc）。
pub(crate) struct RudpConn {
    conn: u32,
    peer: SocketAddr,
    send: Mutex<SendSide>,
    recv: Mutex<RecvSide>,
    /// 窗口信号量：每排队一个 DATA 消耗 1，ACK 确认归还 1；close 兜底全量归还。
    window: Arc<Semaphore>,
    /// 已编码出包出口（socket 发送任务消费；close 时摘除）。
    out_tx: OutTx,
    /// 有序载荷出口（读侧 poll_recv 消费；EOF/错误时摘除关闭 → 读侧见 EOF）。
    /// **有界**（轮 10 P1-3：unbounded 下慢读者内存无界增长——TCP 是内核缓冲
    /// 满→窗口收缩→写端阻塞，此处等价语义 =「投不进则不确认」，重传背压）。
    data_tx: Mutex<Option<tokio::sync::mpsc::Sender<Vec<u8>>>>,
    /// FIN 已被对端确认（scan 停止重发 FIN 的依据）。
    fin_flag: AtomicBool,
    /// FIN_ACK 唤醒通道（poll_shutdown 的 waker 挂在 Receiver 上——常驻注册，
    /// 不受 Notified future 逐 poll 重建注销影响；close 时摘除 → 读侧视为尽力收尾）。
    fin_tx: Mutex<Option<UnboundedSender<()>>>,
    /// 连接级错误（RST/超时/重传超限；None = 未出错）。
    err_tx: watch::Sender<Option<String>>,
    /// 与 err_tx 同对（**必须持有接收端**——无接收者时 send 失败且不存值，
    /// error() 会把 RST/超时误读为干净 EOF，违反「结果未知 ≠ 成功」）。
    err_rx: watch::Receiver<Option<String>>,
    last_rx: Mutex<Instant>,
    closed: AtomicBool,
}

impl RudpConn {
    fn outbound(&self, pkt: WirePkt) {
        let tx = self.out_tx.lock().expect("出包锁").clone();
        if let Some(tx) = tx {
            let _ = tx.send((self.peer, pkt));
        }
    }

    fn send_ack(&self, recv: &RecvSide) {
        let payload = pw::encode_ack_payload(recv.expected, &recv.sack_ranges());
        if let Ok(p) = pw::encode(pw::U_P_ACK, self.conn, 0, &payload) {
            let pkt: WirePkt = p.into();
            self.outbound(pkt);
        }
    }

    fn send_fin(&self, total: u32) {
        if let Ok(p) = pw::encode(pw::U_P_FIN, self.conn, 0, &total.to_le_bytes()) {
            let pkt: WirePkt = p.into();
            self.outbound(pkt);
        }
    }

    fn send_rst(&self, reason: &str) {
        let mut payload = reason.as_bytes().to_vec();
        payload.truncate(200);
        if let Ok(p) = pw::encode(pw::U_P_RST, self.conn, 0, &payload) {
            let pkt: WirePkt = p.into();
            self.outbound(pkt);
        }
    }

    /// 连接收尾：置错误标志（若有）、摘除出口（读侧见 EOF/错误）、归还窗口（唤醒写侧）。
    fn close(&self, err: Option<String>) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(e) = err {
            let _ = self.err_tx.send(Some(e));
        }
        self.fin_flag.store(true, Ordering::SeqCst); // 停 FIN 重发
        let _ = self.data_tx.lock().expect("数据锁").take();
        let _ = self.out_tx.lock().expect("出包锁").take();
        // 摘除 FIN_ACK 通道：poll_shutdown 的 poll_recv 见 None → 尽力收尾放行。
        let _ = self.fin_tx.lock().expect("fin 锁").take();
        self.window.add_permits(RUDP_WINDOW);
    }

    fn error(&self) -> Option<String> {
        self.err_rx.borrow().clone()
    }

    /// 处理一入包（驱动任务调用）。返回 true = 接收侧状态已推进（Gap/Deliver，
    /// cum/SACK 变化）→ 批末需合并 ACK；Dup（状态不变）与其他控制帧 = false。
    /// HS/HS_ACK 只属于握手阶段，驱动期忽略。
    fn handle_packet(&self, kind: u8, seq: u32, payload: &[u8]) -> bool {
        let ack_needed = match kind {
            pw::U_P_DATA => self.on_data(seq, payload),
            pw::U_P_ACK => {
                self.on_ack(payload);
                false
            }
            pw::U_P_FIN => {
                // FIN 载荷 = DATA 总数（seq 头字段弃用）。
                let total = if payload.len() >= 4 {
                    u32::from_le_bytes(payload[..4].try_into().expect("4 字节"))
                } else {
                    seq
                };
                self.on_fin(total);
                false // on_fin 的缺口路径已自行即席 ACK（收满判据依赖它）
            }
            pw::U_P_FIN_ACK => {
                self.fin_flag.store(true, Ordering::SeqCst);
                // 唤醒 poll_shutdown：waker 挂在 fin_rx（Receiver）上，经 channel
                // 投递即 wake——不依赖 Notified future 的跨 poll 存活。
                if let Some(tx) = self.fin_tx.lock().expect("fin 锁").clone() {
                    let _ = tx.send(());
                }
                false
            }
            pw::U_P_RST => {
                let reason = String::from_utf8(payload.to_vec()).unwrap_or_default();
                let msg = if reason.is_empty() {
                    "连接被对端中止".into()
                } else {
                    reason
                };
                self.close(Some(msg));
                false
            }
            _ => false,
        };
        *self.last_rx.lock().expect("活性锁") = Instant::now();
        ack_needed
    }

    /// 批末合并 ACK（驱动任务调用；一批内 cum/SACK 只发一次——ACK 合批）。
    fn flush_ack(&self) {
        let r = self.recv.lock().expect("接收锁");
        self.send_ack(&r);
    }

    /// 背压续投（轮 10 P1-3）：读者消费后把 pending 连续段补投进有界缓冲。
    /// on_data 的链投递只在收包时触发——对端关闭（FIN 已到）后丢弃重传源
    /// 消失，此处是唯一能把回填块送出的通道；EOF 收满判定也在此收口。
    fn pump_pending(&self) {
        let tx_slot = self.data_tx.lock().expect("数据锁").clone();
        let Some(tx) = tx_slot else { return }; // 已 EOF/关闭
        let eof_now = {
            let mut r = self.recv.lock().expect("接收锁");
            let mut eof_now = false;
            loop {
                let exp = r.expected;
                let Some(p) = r.pending.remove(&exp) else {
                    break;
                };
                r.pending_bytes = r.pending_bytes.saturating_sub(p.len());
                match tx.try_send(p) {
                    Ok(()) => {
                        r.expected = exp.wrapping_add(1);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(p)) => {
                        // 满（慢读者）：回填原位，等下次消费后再试。
                        r.pending_bytes += p.len();
                        r.pending.insert(exp, p);
                        break;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(p)) => {
                        // 收尾中：回填（close 幂等兜底会归还窗口）。
                        r.pending_bytes += p.len();
                        r.pending.insert(exp, p);
                        break;
                    }
                }
            }
            if let Some(total) = r.remote_fin {
                if seq_ge(r.expected, total) && !r.eof_seen {
                    r.eof_seen = true;
                    eof_now = true;
                }
            }
            eof_now
        };
        if eof_now {
            let _ = self.data_tx.lock().expect("数据锁").take();
            self.send_fin_ack();
        }
    }

    fn on_data(&self, seq: u32, payload: &[u8]) -> bool {
        // 单次加锁完成状态变更与判定；出包一律放锁外（std Mutex 不可重入）。
        enum Action {
            Dup,   // 重复包（ACK 丢失）→ 状态不变（批末 ACK 与上次同型，省略）
            Gap,   // 乱序 → 已入缓存，ACK 告知空洞
            Eof,   // FIN 收满 → 关读侧（EOF）
            Plain, // 投递/背压推进已完成（含部分推进）→ 批末 ACK
        }
        let action = {
            let mut r = self.recv.lock().expect("接收锁");
            if payload.len() > r.mss {
                return false; // 超协商 mss → 杂包丢弃（不 ACK——发送端不会发这种包）
            }
            if seq_lt(seq, r.expected) {
                Action::Dup
            } else if seq == r.expected {
                // ---- 背压投递（轮 10 P1-3）----
                // 链 = 本块 + pending 里的连续段。逐块 try_send 进**有界**读缓冲；
                // 满即停：未投递块回填 pending、expected 只推进到最后已投递块——
                // 「投不进则不确认」，对端重传背压，读者消化后 ACK 恢复（等价
                // TCP 内核缓冲满→窗口收缩→写端阻塞，用户态闭环版）。
                let tx_slot = self.data_tx.lock().expect("数据锁").clone();
                let mut chain: Vec<(u32, Vec<u8>)> = vec![(seq, payload.to_vec())];
                let mut nxt = seq.wrapping_add(1);
                while let Some(p) = r.pending.remove(&nxt) {
                    r.pending_bytes = r.pending_bytes.saturating_sub(p.len());
                    chain.push((nxt, p));
                    nxt = nxt.wrapping_add(1);
                }
                let mut delivered = 0usize;
                if let Some(tx) = tx_slot.as_ref() {
                    for (_, chunk) in &chain {
                        match tx.try_send(chunk.clone()) {
                            Ok(()) => delivered += 1,
                            Err(_) => break, // Full（慢读者背压）/ Closed（收尾中）
                        }
                    }
                }
                // 回填纪律（轮 10 P1-3 二次修正）：**本批新块（chain[0]）投递
                // 失败一律丢弃不回填**——回填 + SACK 确认会让写端 inflight 移除
                // 该块且无人重传（永久丢字节）；丢弃则写端 RTO 重传自然重试。
                // chain[1..] 是原本就在 pending 的乱序块——必须回填（它们的
                // SACK 确认早已发出，丢弃即真丢），由后续 in-order 投递时的
                // chain 收集带出（本函数顶部的 remove 循环）。
                for (k, chunk) in &chain[delivered.max(1)..] {
                    r.pending_bytes += chunk.len();
                    r.pending.insert(*k, chunk.clone());
                }
                if delivered > 0 {
                    let last = chain[delivered - 1].0;
                    r.expected = last.wrapping_add(1);
                }
                let eof_now = match r.remote_fin {
                    Some(total) => seq_ge(r.expected, total) && !r.eof_seen,
                    None => false,
                };
                if eof_now {
                    r.eof_seen = true;
                }
                if eof_now {
                    Action::Eof
                } else {
                    // 部分推进也算「状态已变」——批末 ACK 释放对端窗口（含
                    // 背压场景：投了几块就确认几块，窗口不因满缓冲而僵死）。
                    if delivered > 0 { Action::Plain } else { Action::Gap }
                }
            } else {
                // 乱序：入缓存（包数/字节双上限，超出丢弃等发送端重传）。
                // contains_key 先查：重传的回填块同键覆盖不得双计字节。
                if !r.pending.contains_key(&seq)
                    && r.pending.len() < RUDP_PENDING_CAP_PKTS
                    && r.pending_bytes + payload.len() <= RUDP_PENDING_CAP_BYTES
                {
                    r.pending_bytes += payload.len();
                    r.pending.insert(seq, payload.to_vec());
                }
                Action::Gap
            }
        };
        match action {
            Action::Eof => {
                // 先关读侧（EOF 可见）再回 FIN_ACK。
                let _ = self.data_tx.lock().expect("数据锁").take();
                self.send_fin_ack();
                true
            }
            _ => true, // Dup/Gap/Plain 状态均已变更（或同型）→ 批末合并 ACK
        }
    }

    fn send_fin_ack(&self) {
        if let Ok(p) = pw::encode(pw::U_P_FIN_ACK, self.conn, 0, &[]) {
            let pkt: WirePkt = p.into();
            self.outbound(pkt);
        }
    }

    fn on_ack(&self, payload: &[u8]) {
        let Some((cum, sacks)) = pw::decode_ack_payload(payload) else {
            return;
        };
        let now = Instant::now();
        let released: usize;
        // 快速重传候选：SACK 首区间之前的空洞（接收端已见其后的包——洞内
        // 在途包大概率丢失）。限频每拍一次，避免重复 ACK 洪泛放大。
        let mut retx: Vec<WirePkt> = Vec::new();
        {
            let mut s = self.send.lock().expect("发送锁");
            if seq_gt(cum, s.next_seq) {
                return; // 非法/超前 ACK（fail-closed 忽略）
            }
            // RTT 采样：取 cum-1 号包的首次发送时刻。Karn 修正：RTO 重发过的
            // 包不采样（重传样本 ≈ 前次 RTO，正反馈把 RTO 推到上限——大传输
            // 爬行的共因之一）。
            if cum != s.next_seq {
                if let Some(inf) = s.inflight.get(&cum.wrapping_sub(1)) {
                    if !inf.retransmitted {
                        let sample = inf.first_send.elapsed().as_secs_f64() * 1000.0;
                        s.rto_update(sample.max(0.1));
                    }
                }
            }
            let before = s.inflight.len();
            s.inflight.retain(|&k, _| !seq_lt(k, cum));
            for (start, len) in &sacks {
                let mut k = *start;
                for _ in 0..*len {
                    s.inflight.remove(&k);
                    k = k.wrapping_add(1);
                }
            }
            released = before - s.inflight.len();
            if released > 0 {
                s.last_progress = now; // 任何确认推进 = 链路有进展（背压丢弃不复位）
            }
            if !sacks.is_empty() && now.duration_since(s.last_fast_retx) >= RUDP_FAST_RETX_MIN {
                // 空洞 = [cum, 首个 SACK 起点)：全部在途包立即重发（受窗口界）。
                let hole_end = sacks
                    .iter()
                    .map(|(st, _)| *st)
                    .min_by_key(|st| st.wrapping_sub(cum))
                    .expect("sacks 非空");
                if seq_lt(cum, hole_end) {
                    s.last_fast_retx = now;
                    let hole: Vec<u32> = s
                        .inflight
                        .keys()
                        .copied()
                        .filter(|k| seq_lt(*k, hole_end))
                        .collect();
                    for k in hole {
                        if let Some(inf) = s.inflight.get_mut(&k) {
                            inf.retransmitted = true;
                            inf.last_send = now;
                            retx.push(inf.pkt.clone());
                        }
                    }
                }
            }
        }
        if released > 0 {
            self.window.add_permits(released);
        }
        for p in retx {
            self.outbound(p);
        }
    }

    fn on_fin(&self, total: u32) {
        // FIN 可重到（发送端 RTO 重发；首个 FIN_ACK 丢失后必须幂等重发，
        // 否则对端 shutdown 等 RUDP_FIN_WAIT——真机丢包下必踩）。
        let (finish_now, ack_fin) = {
            let mut r = self.recv.lock().expect("接收锁");
            // 重复 FIN 一致；total 取回绕序更靠后的一方（防御性）。
            r.remote_fin = Some(
                r.remote_fin
                    .map_or(total, |t| if seq_ge(total, t) { total } else { t }),
            );
            let complete = seq_ge(r.expected, total) && r.pending.is_empty();
            let finish_now = complete && !r.eof_seen; // 首次达成 → 关读侧（EOF 一次性）
            if finish_now {
                r.eof_seen = true;
            }
            (finish_now, complete)
        };
        if finish_now {
            let _ = self.data_tx.lock().expect("数据锁").take();
        }
        if ack_fin {
            self.send_fin_ack();
        } else {
            // 有空洞：ACK 告知缺口，收满后由 on_data/on_fin 触发 EOF。
            let r = self.recv.lock().expect("接收锁");
            self.send_ack(&r);
            drop(r);
            // FIN 已宣告别再发——立即尝试排空 pending（data_tx 有空间时直接推进）。
            self.pump_pending();
        }
    }

    /// 重传扫描（驱动节拍调用）：RTO 到期重发、FIN 重发、空闲超时、重传上限。
    fn scan(&self) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let now = Instant::now();
        if now.duration_since(*self.last_rx.lock().expect("活性锁")) > RUDP_IDLE {
            self.close(Some("连接超时（30s 无数据）".into()));
            return;
        }
        let mut resend: Vec<WirePkt> = Vec::new();
        let mut resend_fin = false;
        let abort = {
            let mut s = self.send.lock().expect("发送锁");
            let rto = s.rto;
            let mut due: Vec<(std::time::Instant, WirePkt)> = Vec::new();
            for inf in s.inflight.values_mut() {
                if now.duration_since(inf.last_send) >= rto {
                    inf.retries += 1;
                    inf.retransmitted = true;
                    inf.last_send = now;
                    if inf.retries > RUDP_RETRIES_MAX {
                        continue; // 轮 10：超限块跳过不断批（其余到期块照常重发）
                    }
                    due.push((inf.last_send, inf.pkt.clone()));
                }
            }
            // 重发限流（轮 10）：背压场景丢弃块每 RTO 到期——全量重发 = 洪水
            //（实测每块重传 129 轮、恢复 66s）。每轮最旧优先取 64 块；无损场景
            // RTO 到期罕见不受影响；真丢包恢复 1000 块 = 16 轮 × 25ms = 400ms。
            due.sort_by(|a, b| a.0.cmp(&b.0));
            resend.extend(due.into_iter().map(|(_, p)| p).take(64));
            let too_lossy = s.inflight.values().any(|i| i.retries > RUDP_RETRIES_MAX)
                // 轮 10：**无进展**超 (MAX+1)×RTO 才真断——背压场景下丢弃块的
                // 重传计数会累积，但读者消化后 ACK 推进即复位 last_progress；
                // 真丢包链路无 ACK 推进 → 原 12 次语义保持。
                && now.duration_since(s.last_progress)
                    >= rto.mul_f64((RUDP_RETRIES_MAX + 1) as f64);
            // FIN 重发只在未被对端确认时进行（fin_flag 置位即停）。
            if !too_lossy
                && s.shutdown_req
                && !self.fin_flag.load(Ordering::SeqCst)
                && s.fin_sent_at.is_some_and(|t| now.duration_since(t) >= rto)
            {
                s.fin_sent_at = Some(now);
                resend_fin = true;
            }
            too_lossy
        };
        if abort {
            self.close(Some("重传超限（链路过差）".into()));
            return;
        }
        for pkt in resend {
            self.outbound(pkt);
        }
        if resend_fin {
            let total = self.send.lock().expect("发送锁").next_seq;
            self.send_fin(total);
        }
    }
}

impl std::fmt::Debug for RudpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RudpConn")
            .field("conn", &self.conn)
            .field("peer", &self.peer)
            .finish()
    }
}

/// 可靠流句柄（帧层读写对象；同一连接在本端仅一个实例）。
pub struct RudpStream {
    conn: Arc<RudpConn>,
    data_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    /// FIN_ACK 唤醒通道（waker 常驻注册在 Receiver 上；None 消息 = 关闭兜底放行）。
    fin_rx: UnboundedReceiver<()>,
    /// poll_write 的窗口许可等待（每次 poll 重建；就绪后置 None）。
    acquire: Option<
        Pin<Box<dyn std::future::Future<Output = tokio::sync::OwnedSemaphorePermit> + Send>>,
    >,
    /// poll_recv 取出但超出本次读缓冲的残余（`read_pos` 光标——消费只推进，
    /// 耗尽才清零，避免每次读 drain 整段 memmove）。
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl RudpStream {
    /// 按序待读缓冲的当前块数（轮 10 P1-3 观测口；≤ `RUDP_DATA_CAP`——
    /// 背压上限的直接证据）。
    pub fn buffered_chunks(&self) -> usize {
        self.data_rx.len()
    }

    /// 等价 TCP 的 shutdown：发 FIN 并等 FIN_ACK（RUDP_FIN_WAIT 兜底放行）。
    fn do_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        {
            let mut s = this.conn.send.lock().expect("发送锁");
            if !s.shutdown_req {
                s.shutdown_req = true;
                s.fin_sent_at = Some(Instant::now());
                let total = s.next_seq;
                drop(s);
                this.conn.send_fin(total);
            }
        }
        if this.conn.fin_flag.load(Ordering::SeqCst) {
            return Poll::Ready(Ok(()));
        }
        // 兜底基准 = max(FIN 发出, 对端最后活跃) + FIN_WAIT——对端还活着
        //（缺口 ACK 在来、重传在恢复）时不得提前放弃：背压大流量场景下
        // 读者消化 5s+ 是常态（轮 10）；对端真失联 → 静默 5s 放行（原语义）。
        let deadline = {
            let last_rsp = *this.conn.last_rx.lock().expect("活性锁");
            this.conn
                .send
                .lock()
                .expect("发送锁")
                .fin_sent_at
                .map(|t| t.max(last_rsp) + RUDP_FIN_WAIT)
        };
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(())); // 尽力收尾（对端失联等）
        }
        // FIN_ACK 经 channel 投递（FIN_ACK 处理注释）：poll_recv 注册的 waker
        // 随 Receiver 常驻存活，不受「future 逐 poll 重建、drop 即注销」影响。
        // 通道被摘（close）→ None → 尽力收尾放行。
        match Pin::new(&mut this.fin_rx).poll_recv(cx) {
            Poll::Ready(Some(())) | Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for RudpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 先清残余（光标推进，耗尽即清零——避免 drain 的整段 memmove），再从队列补包。
        loop {
            if self.read_pos < self.read_buf.len() {
                let n = (self.read_buf.len() - self.read_pos).min(buf.remaining());
                if n == 0 {
                    return Poll::Pending; // 0 长读缓冲：不消费数据
                }
                buf.put_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
                self.read_pos += n;
                if self.read_pos == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
                // 背压续投（轮 10 P1-3）：消费释放容量后补投 pending 连续段
                //（对端已关闭场景下这是唯一投递通道；多数时候空链零开销）。
                self.conn.pump_pending();
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.data_rx).poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.read_buf = chunk;
                    self.read_pos = 0;
                    // 聚合积压（§7.28「应用写聚合」）：逐块唤醒的开销在大流量
                    // 下占主导；单次 poll 拼到上限再切片。
                    while self.read_buf.len() < RUDP_READ_AGG {
                        match self.data_rx.try_recv() {
                            Ok(c) => self.read_buf.extend_from_slice(&c),
                            Err(_) => break,
                        }
                    }
                }
                Poll::Ready(None) => {
                    if let Some(e) = self.conn.error() {
                        return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)));
                    }
                    return Poll::Ready(Ok(())); // EOF
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for RudpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(e) = self.conn.error() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)));
        }
        let mss = {
            let s = self.conn.send.lock().expect("发送锁");
            if s.shutdown_req {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "写端已关闭")));
            }
            s.mss
        };
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // 窗口信号量（批量快速路径）：一次 acquire_many 发完窗口允许的整批
        // ——每批一次锁一次让出；仅窗口满时走单许可慢路径（等 ACK 归还唤醒）。
        let want = buf.len().div_ceil(mss).min(RUDP_WINDOW) as u32;
        let sem = self.conn.window.clone();
        let permits = match sem.clone().try_acquire_many_owned(want) {
            Ok(p) => p,
            Err(_) => {
                if self.acquire.is_none() {
                    let sem = sem.clone();
                    self.acquire = Some(Box::pin(async move {
                        // 等一个许可即可：下一轮 poll_write 走批量快速路径补齐。
                        sem.acquire_owned()
                            .await
                            .expect("窗口信号量永不 close（close 用 add_permits 唤醒等待者）")
                    }));
                }
                let mut fut = self.acquire.take().expect("已插入");
                match fut.as_mut().poll(cx) {
                    Poll::Ready(p) => p,
                    Poll::Pending => {
                        self.acquire = Some(fut);
                        return Poll::Pending;
                    }
                }
            }
        };
        permits.forget(); // 配额由 ACK 归还（add_permits）；close 兜底全量归还
        let mut pkts: Vec<WirePkt> = Vec::new();
        let mut sent = 0usize;
        {
            let mut s = self.conn.send.lock().expect("发送锁");
            let now = Instant::now();
            let mut off = 0usize;
            while off < buf.len() {
                let end = (off + s.mss).min(buf.len());
                let seq = s.next_seq;
                s.next_seq = seq.wrapping_add(1);
                match pw::encode(pw::U_P_DATA, self.conn.conn, seq, &buf[off..end]) {
                    Ok(p) => {
                        let pkt: WirePkt = p.into();
                        s.inflight.insert(
                            seq,
                            InFlight {
                                pkt: pkt.clone(),
                                first_send: now,
                                last_send: now,
                                retries: 0,
                                retransmitted: false,
                            },
                        );
                        pkts.push(pkt);
                    }
                    Err(_) => break, // 不可能（mss ≤ CEIL 已在协商钳制）；防御
                }
                sent = end;
                off = end;
            }
        }
        if sent == 0 {
            // 编码全败（防御路径）：归还刚扣的许可，报错。
            self.conn.window.add_permits(want as usize);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RUDP 编码失败",
            )));
        }
        for p in pkts {
            self.conn.outbound(p);
        }
        Poll::Ready(Ok(sent))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(())) // 出包即时编码投递，无应用层缓冲
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.do_shutdown(cx)
    }
}

impl Drop for RudpStream {
    fn drop(&mut self) {
        if self.conn.closed.load(Ordering::SeqCst) {
            return;
        }
        // 未走 FIN 且未收到对端 FIN（异常退出/提前 drop）→ RST 通知对端立即收场，
        // 免得对端空等 30s 空闲超时。
        let clean = self.conn.send.lock().expect("发送锁").shutdown_req
            || self.conn.recv.lock().expect("接收锁").eof_seen;
        if clean {
            self.conn.close(None);
        } else {
            self.conn.send_rst("连接被本端中止");
            self.conn.close(Some("连接被本端中止".into()));
        }
    }
}

/// `build_conn` 返回：(状态机, 流, 入包通道发送端, 出包通道接收端, 驱动句柄)。
/// 入包通道发送端：客户端交给 socket 泵；服务端交给 demux；测试交给对偶注入。
/// 出包通道接收端：`shared_out = None` 时创建本连接专属通道（客户端/测试）；
/// 服务端注入共享出口后为 None（省掉每连接一跳 forward 任务——批量性能批）。
type BuiltConn = (
    Arc<RudpConn>,
    RudpStream,
    UnboundedSender<Pkt>,
    Option<UnboundedReceiver<OutPkt>>,
    tokio::task::JoinHandle<()>,
);

/// 连接装配：状态机 + 流句柄 + 驱动任务（就地起）。`mss` = 握手协商载荷上限。
fn build_conn(conn: u32, peer: SocketAddr, mss: usize, shared_out: Option<UnboundedSender<OutPkt>>) -> BuiltConn {
    let (out_tx, out_rx) = match shared_out {
        Some(tx) => (tx, None),
        None => {
            let (tx, rx) = unbounded_channel::<OutPkt>();
            (tx, Some(rx))
        }
    };
    let (data_tx, data_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(RUDP_DATA_CAP);
    let (in_tx, in_rx) = unbounded_channel::<Pkt>();
    let (fin_tx, fin_rx) = unbounded_channel::<()>();
    let (err_tx, err_rx) = watch::channel(None);
    let internal = Arc::new(RudpConn {
        conn,
        peer,
        send: Mutex::new(SendSide::new(mss)),
        recv: Mutex::new(RecvSide::new(mss)),
        window: Arc::new(Semaphore::new(RUDP_WINDOW)),
        out_tx: Mutex::new(Some(out_tx)),
        data_tx: Mutex::new(Some(data_tx)),
        fin_flag: AtomicBool::new(false),
        fin_tx: Mutex::new(Some(fin_tx)),
        err_tx,
        err_rx,
        last_rx: Mutex::new(Instant::now()),
        closed: AtomicBool::new(false),
    });
    let stream = RudpStream {
        conn: internal.clone(),
        data_rx,
        fin_rx,
        acquire: None,
        read_buf: Vec::new(),
        read_pos: 0,
    };
    let driver = tokio::spawn(run_driver(internal.clone(), in_rx));
    (internal, stream, in_tx, out_rx, driver)
}

/// 驱动任务：入包处理 + 节拍扫描；连接关闭或入口关闭后退出并做连接级收尾。
async fn run_driver(conn: Arc<RudpConn>, mut in_rx: UnboundedReceiver<Pkt>) {
    let mut ticker = tokio::time::interval(RUDP_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if conn.closed.load(Ordering::SeqCst) {
            break;
        }
        // 批量排空（§7.28「ACK 合批」）：一批包共用一次让出与一个合并 ACK。
        // 修复 P0：连续投递（常态路径）此前不发 ACK，发送端窗口灌满后只能等
        // RTO 重传命中 Dup 才释放窗口——每窗口轮次烧一次 RTO，大传输爬行。
        let mut ack_needed = false;
        let mut n = 0usize;
        while n < RUDP_BATCH_CAP {
            match in_rx.try_recv() {
                Ok((kind, seq, payload)) => {
                    ack_needed |= conn.handle_packet(kind, seq, &payload);
                    n += 1;
                }
                Err(_) => break,
            }
        }
        if n == 0 {
            // 无积压：等一个包或节拍（scan 分支继续循环，不得当作入口关闭）。
            enum Wait {
                Pkt,
                Tick,
                Closed,
            }
            let ev = tokio::select! {
                pkt = in_rx.recv() => match pkt {
                    Some((kind, seq, payload)) => {
                        ack_needed = conn.handle_packet(kind, seq, &payload);
                        Wait::Pkt
                    }
                    None => Wait::Closed, // 入口关闭（泵/服务端摘表）
                },
                _ = ticker.tick() => {
                    conn.scan();
                    Wait::Tick
                }
            };
            if matches!(ev, Wait::Closed) {
                break;
            }
        }
        if ack_needed {
            conn.flush_ack();
        }
        // 协作让出（传输饥饿防线）：入包有积压时 recv 恒 Ready，不让出会饿死
        // 对端泵/写端（current-thread runtime 上必现）——每批让出一次。
        tokio::task::yield_now().await;
    }
    // 收尾口径（「结果未知 ≠ 成功」）：入口关闭且本端从未走正常收尾
    // （shutdown_req / 已见对端 FIN / FIN 已确认）→ 泵/服务端先死于 socket
    // 错误，读侧必须见错误；任一正常收尾迹象（含对端 FIN 已到、数据尚在
    // 缓冲待读——慢读者场景）→ 干净 EOF。
    if conn.closed.load(Ordering::SeqCst) {
        conn.close(None);
    } else {
        let clean = conn.send.lock().expect("发送锁").shutdown_req
            || conn.recv.lock().expect("接收锁").eof_seen
            || conn.fin_flag.load(Ordering::SeqCst);
        if clean {
            conn.close(None);
        } else {
            conn.close(Some("传输通道异常中断".into()));
        }
    }
}

fn local_bind_addr(addr: SocketAddr, src_port: Option<u16>) -> SocketAddr {
    let ip: IpAddr = if addr.is_ipv4() {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    };
    SocketAddr::new(ip, src_port.unwrap_or(0))
}

fn random_bytes(n: usize) -> Vec<u8> {
    use rand_core::RngCore;
    let mut v = vec![0u8; n];
    rand_core::OsRng.fill_bytes(&mut v);
    v
}

fn random_u32() -> u32 {
    let v = random_bytes(4);
    u32::from_le_bytes(v.try_into().expect("4 字节"))
}

/* ============ 客户端 ============ */

/// 建立到 `addr` 的 RUDP 连接（HS 握手 + 定时重发；30s 超时）。
/// 首发协商版 HS（nonce + mss 提案：环回 60000 / 其余 1400），重发窗口
/// 自动降级为旧版 16B HS——旧服务端只认 16B，新服务端两种都认。
/// `src_port`：可选本地端口绑定（与 TCP/QUIC `--srcport` 同口径）。
pub async fn connect_rudp(addr: SocketAddr, src_port: Option<u16>) -> Result<RudpStream> {
    let socket = UdpSocket::bind(local_bind_addr(addr, src_port))
        .await
        .map_err(Error::Io)?;
    let conn_id = random_u32();
    let nonce = random_bytes(16);
    let propose: usize = if addr.ip().is_loopback() {
        pw::RUDP_MSS_CEIL
    } else {
        RUDP_MSS_LAN
    };
    let mut hs_new = nonce.clone();
    hs_new.extend_from_slice(&(propose as u16).to_le_bytes());
    let hs_new = pw::encode(pw::U_P_HS, conn_id, 0, &hs_new).map_err(proto)?;
    let hs_old = pw::encode(pw::U_P_HS, conn_id, 0, &nonce).map_err(proto)?;
    let deadline = Instant::now() + RUDP_HS_TIMEOUT;
    let mut buf = vec![0u8; pw::RUDP_DATAGRAM_MAX + 64];
    let mut first_round = true;
    let mss;
    loop {
        if Instant::now() >= deadline {
            return Err(proto("RUDP 握手超时（30s）"));
        }
        // 首轮发协商版；重发窗口降级旧版（旧服务端对 18B 载荷静默忽略）。
        let _ = socket.send_to(if first_round { &hs_new } else { &hs_old }, addr).await;
        let remain = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remain.min(RUDP_HS_RESEND), socket.recv_from(&mut buf)).await {
            Err(_) => {
                first_round = false; // 重发窗口到点 → 降级重发
                continue;
            }
            Ok(Err(e)) => return Err(Error::Io(e)),
            Ok(Ok((n, src))) => {
                if src != addr {
                    continue; // 非对端来源，忽略
                }
                match pw::decode(&buf[..n]) {
                    Some((h, payload)) if h.conn == conn_id => match h.kind {
                        pw::U_P_HS_ACK => {
                            if let Some(m) = pw::hs_ack_mss(payload, &nonce, propose) {
                                mss = m;
                                break;
                            }
                        }
                        pw::U_P_RST => {
                            let reason = String::from_utf8_lossy(payload);
                            return Err(proto(if reason.is_empty() {
                                "RUDP 连接被对端拒绝".into()
                            } else {
                                format!("RUDP 连接被对端拒绝: {reason}")
                            }));
                        }
                        _ => continue,
                    },
                    _ => continue, // 坏包/版本不符/其他连接 → 忽略
                }
            }
        }
    }
    let (internal, stream, in_tx, out_rx, driver) = build_conn(conn_id, addr, mss, None);
    // socket 共享（tokio UdpSocket 无 Clone——Arc 承载；方法均取 &self）。
    let socket = Arc::new(socket);
    // socket 泵：入包 → 驱动（连接关闭即退）。
    let pump_conn = internal.clone();
    let pump_sock = socket.clone();
    let pump_in = in_tx;
    tokio::spawn(async move {
        let mut b = vec![0u8; pw::RUDP_DATAGRAM_MAX + 64];
        // 连续非 WouldBlock 错误计数（socket 坏死后 try_recv 立即返回错误——
        // 不设限会以满 CPU 自旋到批上限；64 次仍错即退泵，由驱动收尾报错）。
        let mut hard_errs = 0u32;
        loop {
            if pump_conn.closed.load(Ordering::SeqCst) {
                break;
            }
            // 批量排空积压（§7.28「批量收发」）：非阻塞 try 到 WouldBlock/上限。
            let mut n = 0usize;
            while n < RUDP_BATCH_CAP {
                match pump_sock.try_recv_from(&mut b) {
                    Ok((len, src)) => {
                        hard_errs = 0;
                        if src == pump_conn.peer {
                            if let Some((h, payload)) = pw::decode(&b[..len]) {
                                if h.conn == pump_conn.conn {
                                    let _ = pump_in.send((h.kind, h.seq, payload.to_vec()));
                                }
                            }
                        }
                        n += 1;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        hard_errs = 0;
                        break;
                    }
                    // EMSGSIZE 等杂包：丢弃本包继续（与 serve_udp 同口径——超长
                    // 垃圾包不得杀死泵）；但持续性错误须退泵防自旋。
                    Err(_) => {
                        n += 1;
                        hard_errs += 1;
                        if hard_errs > 64 {
                            return; // 泵退 → 入口关闭 → 驱动按异常中断收尾
                        }
                        continue;
                    }
                }
            }
            if n > 0 {
                // 协作让出（传输饥饿防线，与 demux/driver 同口径）。
                tokio::task::yield_now().await;
                continue;
            }
            tokio::select! {
                r = pump_sock.recv_from(&mut b) => match r {
                    Ok((len, src)) => {
                        if src == pump_conn.peer {
                            if let Some((h, payload)) = pw::decode(&b[..len]) {
                                if h.conn == pump_conn.conn {
                                    let _ = pump_in.send((h.kind, h.seq, payload.to_vec()));
                                }
                            }
                        }
                        tokio::task::yield_now().await;
                    }
                    Err(_) => break,
                },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
    });
    // 出包任务：驱动编码包 → socket（批量排空，每批一次让出）。
    let send_sock = socket;
    let mut out_rx = out_rx.expect("客户端连接持专属出包通道");
    tokio::spawn(async move {
        loop {
            let Some((dst, pkt)) = out_rx.recv().await else {
                break;
            };
            if send_sock.send_to(&pkt, dst).await.is_err() {
                break;
            }
            let mut n = 1usize;
            while n < RUDP_BATCH_CAP {
                match out_rx.try_recv() {
                    Ok((dst, pkt)) => {
                        if send_sock.send_to(&pkt, dst).await.is_err() {
                            return;
                        }
                        n += 1;
                    }
                    Err(_) => break,
                }
            }
            // 协作让出（传输饥饿防线）。
            tokio::task::yield_now().await;
        }
    });
    // 驱动句柄 detached：泵在连接关闭后退出 → in_tx drop → 驱动自然收尾。
    drop(driver);
    Ok(stream)
}

/* ============ 服务端 ============ */

struct ConnEntry {
    peer: SocketAddr,
    in_tx: UnboundedSender<Pkt>,
    /// 握手协商 mss（重复 HS 幂等重 ACK 需带协商值——客户端降级重发时以首答为准）。
    mss: u16,
}

fn rst_pkt(conn: u32, reason: &str) -> Option<Vec<u8>> {
    pw::encode(pw::U_P_RST, conn, 0, reason.as_bytes()).ok()
}

/// 监听并服务 RUDP 连接（收缓冲 4MB，对齐 `serve_udp` 口径；通配 `::` 双栈——
/// TECH-STACK §7.31）。
pub async fn serve_rudp(
    addr: SocketAddr,
    opts: crate::transfer::receiver::RecvOptions,
) -> Result<()> {
    let std_sock = crate::transfer::std_udp_listener(addr).map_err(Error::Io)?;
    std_sock.set_nonblocking(true).map_err(Error::Io)?;
    let socket = UdpSocket::from_std(std_sock).map_err(Error::Io)?;
    serve_rudp_on(socket, opts).await
}

/// demux 循环共享上下文（廉价 Arc/引用——单次构建全循环复用，逐包零克隆）。
struct DemuxCtx<'a> {
    socket: Arc<UdpSocket>,
    out_tx: UnboundedSender<OutPkt>,
    conns: Arc<Mutex<HashMap<u32, ConnEntry>>>,
    opts: &'a crate::transfer::receiver::RecvOptions,
    served: Arc<std::sync::atomic::AtomicU64>,
    ended: Arc<tokio::sync::Notify>,
    stop_tx: watch::Sender<bool>,
}

/// 处理一个入包（HS 控制面 / 数据面路由）。
/// 返回 Ok(true) = 接收器应优雅停止（限量收满）；Err = socket 致命错误。
async fn demux_one(
    ctx: &DemuxCtx<'_>,
    finished: &mut tokio::task::JoinSet<()>,
    pkt: &[u8],
    src: SocketAddr,
) -> Result<bool> {
    use crate::transfer::receiver::{gate_check, handle_conn, ip_allowed};
    let Some((h, payload)) = pw::decode(pkt) else {
        return Ok(false);
    };
    let opts = ctx.opts;
    if h.kind == pw::U_P_HS {
        // 版本校验已由 pw::decode 承担（ver 不符整包忽略）；载荷 16B 旧版 /
        // 18B 协商版（nonce + mss 提案，钳制到 [1200, CEIL]）。
        let Some(mss) = pw::hs_mss(payload) else {
            return Ok(false);
        };
        // IP 过滤先于握手（对齐 quic.rs：被拒源不进任何状态机）。
        if !ip_allowed(src.ip(), opts.ip_filter_mode, &opts.ip_filter_list) {
            if let Some(rst) = rst_pkt(h.conn, "被 IP 过滤规则拒绝") {
                let _ = ctx.socket.send_to(&rst, src).await;
            }
            return Ok(false);
        }
        // 锁定门（配对失败次数过多）。
        if gate_check(src, opts).await.is_err() {
            if let Some(rst) = rst_pkt(h.conn, "配对失败次数过多，已临时锁定") {
                let _ = ctx.socket.send_to(&rst, src).await;
            }
            return Ok(false);
        }
        // 限量模式（--count）：串行——等现有连接结束再接受新 HS；收满即停。
        if let Some(max) = opts.max_count {
            loop {
                let empty = ctx.conns.lock().expect("连接表锁").is_empty();
                if empty {
                    break;
                }
                // 轮询兜底防 missed-notify 死锁（串行模式专属，100ms 粒度足够）。
                let _ = tokio::time::timeout(Duration::from_millis(100), ctx.ended.notified()).await;
            }
            if ctx.served.load(Ordering::Relaxed) >= max {
                return Ok(true);
            }
        }
        // 重复 HS 判别与表容量检查（短锁域；await 一律在锁外——future 须 Send，
        // 且不得让数据面路由阻塞在握手锁上）。
        enum HsRoute {
            Dup(u16),
            Ignore,
            CapFull,
            Proceed,
        }
        let route = {
            let t = ctx.conns.lock().expect("连接表锁");
            match t.get(&h.conn) {
                Some(e) if e.peer == src => HsRoute::Dup(e.mss),
                Some(_) => HsRoute::Ignore, // conn 冲突（他端占用）→ 忽略
                None if t.len() >= RUDP_CONN_CAP => HsRoute::CapFull,
                None => HsRoute::Proceed,
            }
        };
        // HS_ACK 载荷与入 HS 同形：18B 协商版带采纳 mss，16B 旧版纯 nonce 回显。
        let ack_payload: Vec<u8> = if payload.len() == 18 {
            let mut p = payload[..16].to_vec();
            p.extend_from_slice(&(mss as u16).to_le_bytes());
            p
        } else {
            payload.to_vec()
        };
        match route {
            HsRoute::Dup(neg) => {
                // 重复 HS（客户端重发）→ 幂等重发 HS_ACK（带建连时的协商值）。
                let mut p = payload[..16].to_vec();
                if neg > pw::RUDP_PAYLOAD_MAX as u16 {
                    p.extend_from_slice(&neg.to_le_bytes());
                }
                if let Ok(ack) = pw::encode(pw::U_P_HS_ACK, h.conn, 0, &p) {
                    let _ = ctx.socket.send_to(&ack, src).await;
                }
                return Ok(false);
            }
            HsRoute::Ignore => return Ok(false),
            HsRoute::CapFull => {
                if let Some(rst) = rst_pkt(h.conn, "连接数已达上限") {
                    let _ = ctx.socket.send_to(&rst, src).await;
                }
                return Ok(false);
            }
            HsRoute::Proceed => {}
        }
        // 并发闸不在此获取：复用 `handle_conn`（TCP 入口）——0x09 加密分支与
        // conn_precheck（IP 过滤 + 30s 闸上限）都在其内，与 TCP 语义完全一致
        // （QUIC 入口跳过 0x09——其机密性由 TLS 承担，RUDP 无 TLS 不得复用）。
        // 建连接并登记（短锁域，无 await；共享出口直连——省一跳 forward 任务）。
        let (internal, stream, in_tx, _out_rx, driver) =
            build_conn(h.conn, src, mss, Some(ctx.out_tx.clone()));
        let _ = internal; // Arc 由 stream/驱动持有
        {
            let mut t = ctx.conns.lock().expect("连接表锁");
            t.insert(
                h.conn,
                ConnEntry {
                    peer: src,
                    in_tx,
                    mss: mss as u16,
                },
            );
        }
        // HS_ACK（回显 nonce + 采纳 mss）。
        if let Ok(ack) = pw::encode(pw::U_P_HS_ACK, h.conn, 0, &ack_payload) {
            let _ = ctx.socket.send_to(&ack, src).await;
        }
        let o2 = opts.clone();
        let served2 = ctx.served.clone();
        let conns2 = ctx.conns.clone();
        let ended2 = ctx.ended.clone();
        let stop2 = ctx.stop_tx.clone();
        let serial_max = opts.max_count;
        // 监督任务：帧循环（0x05 配对/0x09 加密/0x0A 能力/0x08 压缩/
        // 分块/续传全继承 TCP）→ 驱动退出后摘表；限量模式收满即发停止信号。
        finished.spawn(async move {
            let _ = handle_conn(stream, src, &o2, served2.clone()).await;
            let _ = driver.await;
            conns2.lock().expect("连接表锁").remove(&h.conn);
            ended2.notify_waiters();
            // 限量模式：收满即停（demux 正阻塞在 recv_from，无人再发包时
            // 需此信号主动唤醒退出——对齐 serve_quic_on 串行语义）。
            if let Some(max) = serial_max {
                if served2.load(Ordering::Relaxed) >= max {
                    let _ = stop2.send(true);
                }
            }
        });
        return Ok(false);
    }
    // 数据面：按 conn_id 路由（peer 校验防串线；死连接残包/伪造 → 丢弃）。
    let t = ctx.conns.lock().expect("连接表锁");
    if let Some(e) = t.get(&h.conn) {
        if e.peer == src {
            let _ = e.in_tx.send((h.kind, h.seq, payload.to_vec()));
        }
    }
    Ok(false)
}

/// 在既有 UDP socket 上服务 RUDP 连接（GUI 复用 `bind_udp` 的逐地址绑定/失败上报）。
pub async fn serve_rudp_on(
    socket: UdpSocket,
    opts: crate::transfer::receiver::RecvOptions,
) -> Result<()> {
    use crate::transfer::receiver::cleanup_part_orphans;
    // 孤儿半成品清扫（与 TCP/QUIC/UDP 同策略 7 天）。
    cleanup_part_orphans(&opts.save_dir);
    crate::transfer::resume::cleanup_resume_orphans(&opts.save_dir);

    let served = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (out_tx, mut out_rx) = unbounded_channel::<OutPkt>();
    // 出包任务：所有连接的编码包统一经此 socket 发出（Arc 共享，方法均取 &self）。
    let socket = Arc::new(socket);
    let send_sock = socket.clone();
    tokio::spawn(async move {
        loop {
            let Some((dst, pkt)) = out_rx.recv().await else {
                break;
            };
            if send_sock.send_to(&pkt, dst).await.is_err() {
                break;
            }
            let mut n = 1usize;
            while n < RUDP_BATCH_CAP {
                match out_rx.try_recv() {
                    Ok((dst, pkt)) => {
                        if send_sock.send_to(&pkt, dst).await.is_err() {
                            return;
                        }
                        n += 1;
                    }
                    Err(_) => break,
                }
            }
            // 协作让出（传输饥饿防线）。
            tokio::task::yield_now().await;
        }
    });

    let conns: Arc<Mutex<HashMap<u32, ConnEntry>>> = Arc::new(Mutex::new(HashMap::new()));
    let ended = Arc::new(tokio::sync::Notify::new());
    let mut finished = tokio::task::JoinSet::new();
    // 限量模式「收满即停」信号（demux 阻塞在 recv_from，无人再发包时需主动唤醒）。
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let ctx = DemuxCtx {
        socket: socket.clone(),
        out_tx,
        conns: conns.clone(),
        opts: &opts,
        served: served.clone(),
        ended: ended.clone(),
        stop_tx,
    };
    let mut buf = vec![0u8; pw::RUDP_DATAGRAM_MAX + 64];
    loop {
        // 收割已结束的连接监督任务（摘表已在任务内完成）。
        while finished.try_join_next().is_some() {}
        // 协作让出（传输饥饿防线）：recv_from 在有积压时同步返回 Ready，
        // 循环不 await 会让 current-thread runtime 上的泵/驱动/写端全部饿死。
        tokio::task::yield_now().await;
        let (mut len, mut src) = tokio::select! {
            r = socket.recv_from(&mut buf) => match r {
                Ok(x) => x,
                Err(e) => {
                    // EMSGSIZE（Windows 10040）等杂包不致接收器退出（与 serve_udp 同口径）。
                    if e.raw_os_error() == Some(10040) {
                        continue;
                    }
                    return Err(Error::Io(e));
                }
            },
            _ = stop_rx.changed() => return Ok(()),
        };
        // 批量排空积压（性能批 2026-11-14：此前服务端每包一次阻塞 recv +
        // 一次让出 + 一次全局表锁——与客户端泵的批量口径对齐，每批一次让出；
        // 批内错误一律断批，持久错误由下一轮阻塞 recv 呈报）。
        let mut m = 0usize;
        loop {
            if demux_one(&ctx, &mut finished, &buf[..len], src).await? {
                return Ok(());
            }
            m += 1;
            if m >= RUDP_BATCH_CAP {
                break;
            }
            match socket.try_recv_from(&mut buf) {
                Ok((l, s)) => {
                    len = l;
                    src = s;
                }
                Err(_) => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 绕过 socket 的对偶装配：两条连接的出入包直接经转发任务对接。
    /// `lossy = true` 时按确定性伪随机序列丢弃约 25% 的包（重传路径注入）。
    async fn pair(lossy: bool) -> (RudpStream, RudpStream) {
        let peer_c: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let peer_s: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let (c_conn, cs, c_in, c_out, c_drv) = build_conn(1, peer_s, pw::RUDP_PAYLOAD_MAX, None);
        let (s_conn, ss, s_in, s_out, s_drv) = build_conn(1, peer_c, pw::RUDP_PAYLOAD_MAX, None);
        let mut c_out = c_out.expect("对偶连接持专属出包通道");
        let mut s_out = s_out.expect("对偶连接持专属出包通道");
        // 两个独立种子的 xorshift64（确定性丢包注入，两侧互不干扰）。
        let mut seed1 = 0x1234_5678_9ABC_DEF0u64;
        let mut seed2 = 0x0FED_CBA9_8765_4321u64;
        tokio::spawn(async move {
            while let Some((_dst, pkt)) = c_out.recv().await {
                seed1 ^= seed1 << 13;
                seed1 ^= seed1 >> 7;
                seed1 ^= seed1 << 17;
                if lossy && seed1.is_multiple_of(4) {
                    continue;
                }
                if let Some((h, pl)) = pw::decode(&pkt) {
                    let _ = s_in.send((h.kind, h.seq, pl.to_vec()));
                }
            }
        });
        tokio::spawn(async move {
            while let Some((_dst, pkt)) = s_out.recv().await {
                seed2 ^= seed2 << 13;
                seed2 ^= seed2 >> 7;
                seed2 ^= seed2 << 17;
                if lossy && seed2.is_multiple_of(4) {
                    continue;
                }
                if let Some((h, pl)) = pw::decode(&pkt) {
                    let _ = c_in.send((h.kind, h.seq, pl.to_vec()));
                }
            }
        });
        // 驱动句柄 detached（与生产一致）；Arc 由驱动持有。
        drop((c_conn, s_conn, c_drv, s_drv));
        (cs, ss)
    }

    /// 无损：双向 + 顺序 + FIN/EOF 收尾。
    #[tokio::test]
    async fn stream_roundtrip_bidirectional_clean_close() {
        let (mut c, mut s) = pair(false).await;
        // 客户端 → 服务端（跨窗口：8KB < 64×1200=76.8KB？用 200KB 强制多窗口轮转）。
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        c.write_all(&payload).await.unwrap();
        c.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "大载荷必须逐字节一致（含乱序重排）");
        // 服务端 → 客户端（帧层状态字节的双向语义）。
        s.write_all(b"OK").await.unwrap();
        let mut back = [0u8; 2];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"OK");
        // FIN 收尾：客户端 shutdown → 服务端读到 EOF。
        c.shutdown().await.unwrap();
        let mut eof = Vec::new();
        let n = s.read_to_end(&mut eof).await.unwrap();
        assert_eq!(n, 0, "FIN 后服务端必须见 EOF");
    }

    /// 判别（TECH-STACK §7.31 性能批）：连续投递必须经批末合并 ACK 实时释放
    /// 发送窗口。退回「常态不发 ACK」的旧行为时，4MB（≈13 个窗口轮次）只能靠
    /// RTO 重传命中 Dup 才释放窗口（每轮 ≥RTO=400ms，且重传采样把 RTO 推向
    /// 3s 上限）——完成时间爆表。新行为为纯内存通道流转，<3s 恒真。
    #[tokio::test]
    async fn in_order_delivery_releases_window_via_batched_ack() {
        let (mut c, mut s) = pair(false).await;
        let payload: Vec<u8> = (0..4_000_000u32).map(|i| (i % 199) as u8).collect();
        let t0 = std::time::Instant::now();
        c.write_all(&payload).await.unwrap();
        c.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "大流量必须逐字节一致");
        let elapsed = t0.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "4MB 传输耗时 {elapsed:?}——窗口未被合并 ACK 实时释放（旧行为 ≥13×RTO）"
        );
        c.shutdown().await.unwrap();
    }

    /// 判别（TECH-STACK §7.31 性能批）：FIN_ACK 必须对重到的 FIN 幂等重发。
    /// 丢弃首个 FIN_ACK（真机丢包常态）后，旧行为下后续 FIN 走缺口 ACK 分支
    /// → 发送端 shutdown 等 RUDP_FIN_WAIT(5s) 兜底；新行为立刻重发 FIN_ACK。
    #[tokio::test]
    async fn fin_ack_is_idempotent_after_first_loss() {
        let peer_c: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let peer_s: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let (_c_conn, mut cs, c_in, c_out, _c_drv) =
            build_conn(1, peer_s, pw::RUDP_PAYLOAD_MAX, None);
        let (_s_conn, mut ss, s_in, s_out, _s_drv) =
            build_conn(1, peer_c, pw::RUDP_PAYLOAD_MAX, None);
        let mut c_out = c_out.expect("对偶连接持专属出包通道");
        let mut s_out = s_out.expect("对偶连接持专属出包通道");
        // c_out → s_in 无损；s_out → c_in 丢弃**首个** FIN_ACK。
        tokio::spawn(async move {
            while let Some((_dst, pkt)) = c_out.recv().await {
                if let Some((h, pl)) = pw::decode(&pkt) {
                    let _ = s_in.send((h.kind, h.seq, pl.to_vec()));
                }
            }
        });
        let mut fin_ack_dropped = false;
        tokio::spawn(async move {
            while let Some((_dst, pkt)) = s_out.recv().await {
                if let Some((h, pl)) = pw::decode(&pkt) {
                    if h.kind == pw::U_P_FIN_ACK && !fin_ack_dropped {
                        fin_ack_dropped = true;
                        continue; // 模拟首个 FIN_ACK 丢包
                    }
                    let _ = c_in.send((h.kind, h.seq, pl.to_vec()));
                }
            }
        });
        drop((_c_conn, _s_conn, _c_drv, _s_drv));
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 197) as u8).collect();
        cs.write_all(&payload).await.unwrap();
        cs.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        ss.read_exact(&mut got).await.unwrap();
        // 旧行为：首个 FIN_ACK 被丢 → 后续 FIN 只回缺口 ACK → shutdown 等 5s 兜底。
        tokio::time::timeout(std::time::Duration::from_secs(2), cs.shutdown())
            .await
            .expect("FIN_ACK 幂等重发后 shutdown 必须即时完成（旧行为等 5s 兜底）")
            .unwrap();
    }

    /// 25% 丢包注入：重传 + SACK 必须恢复出完整流（乱序重排）。
    #[tokio::test]
    async fn loss_recovery_reassembles_stream() {
        let (mut c, mut s) = pair(true).await;
        let payload: Vec<u8> = (0..60_000u32).map(|i| (i % 241) as u8).collect();
        c.write_all(&payload).await.unwrap();
        c.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "丢包后必须经重传恢复逐字节一致");
        c.shutdown().await.unwrap();
        let mut sink = Vec::new();
        assert_eq!(
            s.read_to_end(&mut sink).await.unwrap(),
            0,
            "丢包链路同样必须干净收尾"
        );
    }

    /// 异常中止：客户端提前 drop → RST → 服务端读侧报 ConnectionReset。
    #[tokio::test]
    async fn rst_propagates_to_peer_read() {
        let (c, mut s) = pair(false).await;
        {
            let mut c = c;
            c.write_all(b"partial").await.unwrap();
            // 提前 drop（未 shutdown）→ Drop 发 RST。
        }
        let mut sink = Vec::new();
        let r = s.read_to_end(&mut sink).await;
        assert!(r.is_err(), "RST 后读必须报错而非假成功（结果未知 ≠ 成功）");
    }

    /// 重复 DATA（ACK 丢失场景）与 FIN 收满：直接向驱动注入包做行为判别。
    #[tokio::test]
    async fn duplicate_data_delivered_once_and_fin_eof() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (_conn, mut stream, in_tx, _out, _drv) = build_conn(7, peer, pw::RUDP_PAYLOAD_MAX, None);
        in_tx.send((pw::U_P_DATA, 0, b"he".to_vec())).unwrap();
        in_tx.send((pw::U_P_DATA, 1, b"llo".to_vec())).unwrap();
        in_tx.send((pw::U_P_DATA, 0, b"he".to_vec())).unwrap(); // 重复（ACK 丢失后重传）
                                                                // FIN：total=2 → expected 已到 2 且无空洞 → EOF。
        in_tx
            .send((pw::U_P_FIN, 0, 2u32.to_le_bytes().to_vec()))
            .unwrap();
        let mut got = [0u8; 5];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello", "重复 seq=0 不得重复投递");
        let mut sink = Vec::new();
        assert_eq!(
            stream.read_to_end(&mut sink).await.unwrap(),
            0,
            "收满 FIN 总数必须见 EOF"
        );
    }

    /// 判别（性能批 2026-11-14）：序号回绕。朴素整数比较在 u32 回绕点（4.29G
    /// 包 ≈ 5TB@1200B）把新周期包判为旧包——接收端永久缺包、重传超限断连；
    /// 回绕算术必须跨点续传。两侧 ISN 手工拨到 u32::MAX-5 附近强行跨点。
    #[tokio::test]
    async fn seq_wraparound_survives_crossing() {
        let peer_c: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let peer_s: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let (c_conn, mut cs, c_in, c_out, _c_drv) =
            build_conn(1, peer_s, pw::RUDP_PAYLOAD_MAX, None);
        let (s_conn, mut ss, s_in, s_out, _s_drv) =
            build_conn(1, peer_c, pw::RUDP_PAYLOAD_MAX, None);
        let mut c_out = c_out.expect("出包通道");
        let mut s_out = s_out.expect("出包通道");
        // 拨 ISN：发送端 next_seq 与接收端 expected 同步置于回绕点前 5 包。
        c_conn.send.lock().unwrap().next_seq = u32::MAX - 5;
        s_conn.recv.lock().unwrap().expected = u32::MAX - 5;
        tokio::spawn(async move {
            while let Some((_dst, pkt)) = c_out.recv().await {
                if let Some((h, pl)) = pw::decode(&pkt) {
                    let _ = s_in.send((h.kind, h.seq, pl.to_vec()));
                }
            }
        });
        tokio::spawn(async move {
            while let Some((_dst, pkt)) = s_out.recv().await {
                if let Some((h, pl)) = pw::decode(&pkt) {
                    let _ = c_in.send((h.kind, h.seq, pl.to_vec()));
                }
            }
        });
        // 30KB ≈ 26 包（1200B/包）——必跨回绕点。
        let payload: Vec<u8> = (0..30_000u32).map(|i| (i % 253) as u8).collect();
        cs.write_all(&payload).await.unwrap();
        cs.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        ss.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "回绕点两侧必须逐字节一致");
        cs.shutdown().await.unwrap();
        let mut sink = Vec::new();
        assert_eq!(ss.read_to_end(&mut sink).await.unwrap(), 0, "跨回绕收尾干净");
    }

    /// 判别（性能批 2026-11-14）：SACK 空洞触发快速重传。定向丢 1 个数据包，
    /// 旧行为只能等 RTO（初始 400ms）；SACK 快速重传在首个含空洞的 ACK 后
    /// 立即补发。25KB 数据 + 慢速消费确保窗口未满（区分快速重传与 RTO 路径），
    /// 总时限收紧到 250ms 判别（RTO_MIN=50ms 也兜不住持续丢 1 包的旧行为——
    /// 丢包在窗口中段时旧路径需整窗 RTO）。
    #[tokio::test]
    async fn sack_hole_triggers_fast_retransmit() {
        let peer_c: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let peer_s: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let (c_conn, mut cs, c_in, c_out, _c_drv) =
            build_conn(1, peer_s, pw::RUDP_PAYLOAD_MAX, None);
        let (_s_conn, mut ss, s_in, s_out, _s_drv) =
            build_conn(1, peer_c, pw::RUDP_PAYLOAD_MAX, None);
        let mut c_out = c_out.expect("出包通道");
        let mut s_out = s_out.expect("出包通道");
        // RTO 钉在最大值：任何依赖 RTO 的恢复路径都在 3s 开外——判别只认快速重传。
        c_conn.send.lock().unwrap().rto = Duration::from_millis(RUDP_RTO_MAX_MS);
        tokio::spawn(async move {
            let mut dropped = false;
            while let Some((_dst, pkt)) = c_out.recv().await {
                if let Some((h, _)) = pw::decode(&pkt) {
                    // 丢第 3 个 DATA 包（一次）。
                    if h.kind == pw::U_P_DATA && h.seq == 3 && !dropped {
                        dropped = true;
                        continue;
                    }
                }
                if let Some((h, pl)) = pw::decode(&pkt) {
                    let _ = s_in.send((h.kind, h.seq, pl.to_vec()));
                }
            }
        });
        tokio::spawn(async move {
            while let Some((_dst, pkt)) = s_out.recv().await {
                if let Some((h, pl)) = pw::decode(&pkt) {
                    let _ = c_in.send((h.kind, h.seq, pl.to_vec()));
                }
            }
        });
        let payload: Vec<u8> = (0..25_000u32).map(|i| (i % 249) as u8).collect();
        let t0 = std::time::Instant::now();
        cs.write_all(&payload).await.unwrap();
        cs.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        ss.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "丢 1 包必须恢复出完整流");
        assert!(
            t0.elapsed() < Duration::from_millis(250),
            "恢复耗时 {:?}——SACK 快速重传未生效（RTO 已钉 3s）",
            t0.elapsed()
        );
    }

    /// 判别（轮 10 P1-3）：读侧背压。写 10MB（8740 块，远超窗口+读缓冲+
    /// 乱序缓存的总吸收量），读侧延迟 300ms——期间接收侧按序待读缓冲必须
    /// 钳在 `RUDP_DATA_CAP`（unbounded 旧行为会无界涨到全量 8740 块）；
    /// 随后全速读完，逐字节一致（背压不得丢字节——丢弃重传/乱序回填/SACK
    /// 的交织路径全覆盖）。
    #[tokio::test]
    async fn slow_reader_backpressure_bounds_memory() {
        let (mut c, mut s) = pair(false).await;
        let payload: Vec<u8> = (0..10_000_000u32).map(|i| (i % 199) as u8).collect();
        let total = payload.len();
        let writer = {
            let data = payload.clone();
            tokio::spawn(async move {
                c.write_all(&data).await.unwrap();
                c.flush().await.unwrap();
                // 干净收尾（未 shutdown 的 drop = RST 异常中止——会打断慢读者）。
                c.shutdown().await.unwrap();
            })
        };
        // 读侧延迟期间采样：缓冲必须恒 ≤ CAP（背压上限；unbounded 会涨过 CAP）。
        let mut peak = 0usize;
        for _ in 0..30 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            peak = peak.max(s.buffered_chunks());
        }
        assert!(
            peak <= RUDP_DATA_CAP,
            "按序待读缓冲峰值 {peak} 超 CAP {RUDP_DATA_CAP}——背压失效（unbounded 旧行为）"
        );
        let mut got = vec![0u8; total];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "背压恢复后必须逐字节一致");
        writer.await.unwrap();
        s.shutdown().await.unwrap();
    }

    /// MSS 协商回退判别：伪旧服务端对 18B 协商 HS 静默忽略、只应答 16B 旧 HS——
    /// 客户端必须在重发窗口降级并连通；新服务端（真 serve_rudp_on）对协商 HS
    /// 回 18B ACK 且大包传输成功。
    #[tokio::test]
    async fn mss_negotiation_new_server_and_legacy_fallback() {
        use crate::transfer::receiver::RecvOptions;
        // —— 新服务端：协商建立 + 大包（>1200B）传输 ——
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let std_sock = crate::transfer::std_udp_listener(addr).unwrap();
        std_sock.set_nonblocking(true).unwrap();
        let port = std_sock.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let sock = UdpSocket::from_std(std_sock).unwrap();
            let mut o = RecvOptions::default();
            o.save_dir = std::env::temp_dir().join("trft-rudp-mss-test");
            let _ = std::fs::create_dir_all(&o.save_dir);
            serve_rudp_on(sock, o).await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let s = connect_rudp(format!("127.0.0.1:{port}").parse().unwrap(), None)
            .await
            .expect("协商握手必须成功");
        assert_eq!(
            s.conn.send.lock().unwrap().mss,
            pw::RUDP_MSS_CEIL,
            "环回新服务端必须协商到最大 mss"
        );
        drop(s);
        srv.abort();

        // —— 伪旧服务端：只应答 16B HS，忽略 18B ——
        let old = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old_port = old.local_addr().unwrap().port();
        let old_task = tokio::spawn(async move {
            let mut b = vec![0u8; pw::RUDP_DATAGRAM_MAX + 64];
            loop {
                let Ok((n, src)) = old.recv_from(&mut b).await else {
                    return;
                };
                let Some((h, payload)) = pw::decode(&b[..n]) else {
                    continue;
                };
                if h.kind == pw::U_P_HS {
                    if payload.len() != 16 {
                        continue; // 旧服务端对协商版 HS 静默忽略
                    }
                    if let Ok(ack) = pw::encode(pw::U_P_HS_ACK, h.conn, 0, payload) {
                        let _ = old.send_to(&ack, src).await;
                    }
                }
            }
        });
        let t0 = std::time::Instant::now();
        let s2 = connect_rudp(format!("127.0.0.1:{old_port}").parse().unwrap(), None)
            .await
            .expect("降级重发后必须连通旧服务端");
        assert!(
            s2.conn.send.lock().unwrap().mss == pw::RUDP_PAYLOAD_MAX,
            "旧服务端连接必须回落默认 mss"
        );
        assert!(
            t0.elapsed() >= RUDP_HS_RESEND,
            "降级应发生在首个重发窗口（实际 {:?}）",
            t0.elapsed()
        );
        old_task.abort();
    }
}
