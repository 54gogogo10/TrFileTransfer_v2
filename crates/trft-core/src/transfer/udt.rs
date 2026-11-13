//! UDT4 传输槽位（原生 Rust 实现，与原 C# 版 libudt 4.x `SOCK_STREAM` 字节级互通）。
//! 结构对齐 `transfer::rudp` 的「引擎与 socket 解耦」纪律：
//! - `UdtConn`：连接状态机（发送窗口/重传/拥塞近似 + 接收重排/ACK/NAK 生成），纯逻辑，
//!   经 mpsc 出入包，可绕过 socket 直接构造对偶做丢包注入单测；
//! - `UdtStream`：`AsyncRead + AsyncWrite` 字节流（C# 方言应用层跑在其上）；
//! - 客户端 `connect_udt`（两段式握手：cookie 挑战 → 带证二次请求），服务端 `serve_udt_on`
//!   （单 socket 按 dst socket id 多路分解——libudt 的 accept 连接共享监听端口，与 RUDP 的
//!   每连接独立 socket 不同）。
//!
//! 线格式与定时器以 vendored libudt 4.x 为权威（`protocol::udt` 与模块注释）；
//! 拥塞控制为 UDT4 默认 CC（慢启动倍增 + 丢包 0.875 收缩）的可用近似——互通正确性
//! 由 ACK/NAK/流窗承担，吞吐不作为验收口径（TECH-STACK §7.30）。

use crate::error::{proto, Error, Result};
use crate::protocol::udt as pw;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{watch, Notify};

/// 发送侧拥塞窗初值（UDT4 慢启动起点）。
const CWND_INIT: f64 = 16.0;
/// 接收重排缓冲上限（对端 libudt 收缓冲默认 8192 包；本地对等取同值）。
const REORDER_CAP: usize = 8192;

/// 连接本地 µs 时钟（Instant 单调；探测/到达窗与 SYN 节流共用）。
fn now_us_since(epoch: &Instant) -> u64 {
    epoch.elapsed().as_micros() as u64
}

/// 中位数（libudt nth_element 同效；不改原序——拷贝小窗排序）。
fn median_of(win: &[u32; 16]) -> u32 {
    let mut c = *win;
    c.sort_unstable();
    c[8]
}

/// 重传兜底扫描节流（NAK 触发即发，不受此限）。
const RETRANS_MIN_INTERVAL: Duration = Duration::from_millis(50);
/// 驱动节拍（libudt ACK/EXP 检查粒度 = SYN 10ms）。
const TICK: Duration = Duration::from_millis(10);
/// EXP 基准（libudt：count×(RTT+4RTTVar)+SYN，下限 count×300ms；RTT 初值 = 10×SYN）。
const RTT_INIT_US: i64 = 100_000;
const RTTVAR_INIT_US: i64 = 50_000;
/// EXP 计数超限且 5s 无响应 → 判连路失效。
const EXP_LIMIT: u32 = 16;
/// keepalive 兜底周期。
const KEEPALIVE_EVERY: Duration = Duration::from_secs(15);
/// SHUTDOWN 重发上限与间隔（libudt 只发一次；丢失靠对端 EXP 兜底——限次增强收尾确定性）。
const SHUTDOWN_RESENDS: u32 = 3;
const SHUTDOWN_RESEND_EVERY: Duration = Duration::from_millis(500);
/// 连接空闲硬超时（30s 无任何对端包——对齐 RUDP/原版 UDT_RCVTIMEO 口径）。
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// 握手总超时与重发间隔（libudt 250ms 请求节奏，TTL 3s×10 口径）。
const HS_TIMEOUT: Duration = Duration::from_secs(30);
const HS_RESEND: Duration = Duration::from_millis(250);
/// 服务端连接表上限（对齐 RUDP_CONN_CAP）。
const UDT_CONN_CAP: usize = 256;
/// ACK 窗口容量（libudt CACKWindow(1024)）。
const ACK_WINDOW_CAP: usize = 1024;

#[derive(Debug)]
struct SendState {
    /// 未被累积确认的包（front = incseq(last_ack) 的数据）。
    pkts: VecDeque<Vec<u8>>,
    /// 累积确认基准 seq（初始 = 本端 ISN）。
    last_ack: i32,
    /// 最后分配的 seq（初始 = ISN-1）。
    next_seq: i32,
    /// 重传列表（升序去重）。
    loss: BTreeSet<i32>,
    /// 对端通告流窗（握手 + ACK 载荷 word3 持续刷新；light ACK 反向递减）。
    flow_window: i32,
    /// 拥塞窗（慢启动近似）。
    cwnd: f64,
    in_slow_start: bool,
    shutdown_req: bool,
    shutdown_resends: u32,
}

impl SendState {
    fn new(isn: i32, flow_window: i32) -> Self {
        Self {
            pkts: VecDeque::new(),
            last_ack: isn,
            next_seq: pw::seq_dec(isn),
            loss: BTreeSet::new(),
            flow_window,
            cwnd: CWND_INIT,
            in_slow_start: true,
            shutdown_req: false,
            shutdown_resends: 0,
        }
    }

    fn window(&self) -> usize {
        (self.flow_window.min(self.cwnd as i32)).max(0) as usize
    }
}

#[derive(Debug)]
struct RecvState {
    /// 累积确认基准（= 期望的下一个 seq；初始 = 对端 ISN）。
    expected: i32,
    /// 已见最高 seq（初始 = ISN-1）。
    curr: i32,
    /// 缺失 seq（(expected, curr] 内未收到的；升序）。
    loss: BTreeSet<i32>,
    /// 乱序缓存。
    pending: HashMap<i32, Vec<u8>>,
    peer_shutdown: bool,
    // -- ACK 发送状态 --
    ack_no: i32,
    /// ACK 子序列号 → (发送时刻, 该 ACK 的 cum)。
    ack_window: HashMap<i32, (Instant, i32)>,
    last_ack_sent: i32,
    /// 对端 ACK2 已确认到的 ACK cum（防重复 ACK）。
    last_ack_ack: i32,
    last_ack_time: Instant,
    /// 本端 RTT 估计（ACK2 采样；喂 ACK 载荷 word1/2 与 EXP）。
    rtt_us: i64,
    rttvar_us: i64,
    /// 不规则包（写批次末段）到达 → 立即 ACK。
    ack_immediate: bool,
    /// light ACK 计数（每 64 包一个）。
    pkt_count: i32,
    light_count: i32,
    /// 最近一次 **6 词** ACK 时刻（libudt m_ullLastAckTime：word4/5 的 SYN 节流
    /// 与重复 ACK 守卫共用——只在 6 词分支刷新）。
    last_full_us: u64,
    /// 包到达间隔窗（µs，16 槽，中位数滤波——libudt CPktTimeWindow 同款，
    /// 喂 ACK word4 接收速率；UDT4 互通必需，缺失时 libudt CC 退出慢启动后
    /// `cwnd = RcvRate/1e6×(RTT+RC)+16` 恒钉 16 包 → 发送端 750 pkt/s 塌陷）。
    pkt_win: [u32; 16],
    pkt_ptr: usize,
    last_arr_us: u64,
    /// 探测对间隔窗（µs，16 槽——seq&0xF==0/1 成对到达测链路容量，喂 word5）。
    probe_win: [u32; 16],
    probe_ptr: usize,
    probe_time_us: u64,
    /// µs 时钟基准（连接建立时刻；Instant 单调）。
    epoch: Instant,
}

impl RecvState {
    fn new(peer_isn: i32) -> Self {
        Self {
            expected: peer_isn,
            curr: pw::seq_dec(peer_isn),
            loss: BTreeSet::new(),
            pending: HashMap::new(),
            peer_shutdown: false,
            ack_no: 0,
            ack_window: HashMap::new(),
            last_ack_sent: peer_isn,
            last_ack_ack: peer_isn,
            last_ack_time: Instant::now(),
            rtt_us: RTT_INIT_US,
            rttvar_us: RTTVAR_INIT_US,
            ack_immediate: false,
            pkt_count: 0,
            light_count: 1,
            last_full_us: 0,
            pkt_win: [1_000_000; 16],
            pkt_ptr: 0,
            last_arr_us: 0,
            probe_win: [1_000; 16],
            probe_ptr: 0,
            probe_time_us: 0,
            epoch: Instant::now(),
        }
    }

    /// 包到达记账（libudt CPktTimeWindow::onPktArrival 同款；每个 DATA 到达调用）。
    fn on_pkt_arrival(&mut self, now_us: u64, seq: i32) {
        let interval = (now_us - self.last_arr_us).min(u32::MAX as u64) as u32;
        self.pkt_win[self.pkt_ptr] = interval;
        self.pkt_ptr = (self.pkt_ptr + 1) % 16;
        self.last_arr_us = now_us;
        // 探测对：seq 低 4 位 0/1 成对（libudt processData 同判）。
        if seq & 0xF == 0 {
            self.probe_time_us = now_us;
        } else if seq & 0xF == 1 && self.probe_time_us > 0 {
            let gap = (now_us - self.probe_time_us).min(u32::MAX as u64) as u32;
            self.probe_win[self.probe_ptr] = gap;
            self.probe_ptr = (self.probe_ptr + 1) % 16;
        }
    }

    /// 接收速率估计（包/秒；中位数滤波，样本不足半窗回 0——libudt getPktRcvSpeed）。
    fn pkt_rcv_speed(&self) -> u32 {
        let median = median_of(&self.pkt_win);
        let (mut count, mut sum) = (0u32, 0u64);
        for &v in &self.pkt_win {
            if v < median * 8 && v > median / 8 {
                count += 1;
                sum += v as u64;
            }
        }
        if count > 8 {
            (1_000_000.0 / (sum as f64 / count as f64)).ceil() as u32
        } else {
            0
        }
    }

    /// 链路带宽估计（包/秒；探测对中位数滤波——libudt getBandwidth）。
    fn bandwidth(&self) -> u32 {
        let median = median_of(&self.probe_win);
        let (mut count, mut sum) = (1u32, median as u64);
        for &v in &self.probe_win {
            if v < median * 8 && v > median / 8 {
                count += 1;
                sum += v as u64;
            }
        }
        (1_000_000.0 / (sum as f64 / count as f64)).ceil() as u32
    }

    /// ACK cum：无损失 = curr+1；有损失 = 首个缺失 seq（libudt sendCtrl(2) 语义）。
    fn ack_cum(&self) -> i32 {
        if self.loss.is_empty() {
            pw::seq_inc(self.curr)
        } else {
            *self.loss.iter().next().expect("非空")
        }
    }

    /// 可用接收缓冲（包数，下限 2 防 deadlock——libudt 同语义）。
    fn avail_buf(&self) -> i32 {
        ((REORDER_CAP - self.pending.len()) as i32).max(2)
    }

    /// ACK2 采样 → RTT EWMA（libudt：var=3/4v+1/4|x-rtt|，rtt=7/8rtt+1/8x）。
    fn rtt_sample(&mut self, x_us: i64) {
        let diff = (x_us - self.rtt_us).abs();
        self.rttvar_us = (3 * self.rttvar_us + diff) / 4;
        self.rtt_us = ((7 * self.rtt_us + x_us) / 8).max(1);
    }
}

/// 连接状态机（收发双侧共享；驱动任务与 `UdtStream` 各持 Arc）。
pub(crate) struct UdtConn {
    my_id: u32,
    peer_id: u32,
    peer: SocketAddr,
    start: Instant,
    send: Mutex<SendState>,
    recv: Mutex<RecvState>,
    /// 已编码出包出口（socket 泵/转发消费；close 摘除）。
    out_tx: Mutex<Option<UnboundedSender<Vec<u8>>>>,
    /// 有序载荷出口（读侧消费；EOF/错误摘除 → 读侧见 EOF）。
    data_tx: Mutex<Option<UnboundedSender<Vec<u8>>>>,
    /// 写侧窗口等待（notify_waiters 唤醒已注册等待者；写侧「先注册后查窗」的顺序
    /// 保证开窗通知不丢——错过的一次由后续 SYN 周期 ACK 的通知兜底，停顿 ≤10ms）。
    window_notify: Arc<Notify>,
    /// 连接级错误。
    err_tx: watch::Sender<Option<String>>,
    err_rx: watch::Receiver<Option<String>>,
    /// 服务端握手响应（幂等重发；客户端 None）。
    hs_resp: Mutex<Option<Vec<u8>>>,
    last_rsp: Mutex<Instant>,
    exp_count: AtomicU32,
    last_loss_send: Mutex<Instant>,
    last_keepalive: Mutex<Instant>,
    last_shutdown_send: Mutex<Instant>,
    last_ack2: Mutex<(i32, Instant)>,
    closed: AtomicBool,
}

impl UdtConn {
    fn ts(&self) -> u32 {
        self.start.elapsed().as_micros() as u32
    }

    fn outbound(&self, pkt: Vec<u8>) {
        if let Some(tx) = self.out_tx.lock().expect("出包锁").clone() {
            let _ = tx.send(pkt);
        }
    }

    fn send_ctrl(&self, ctype: u16, add: i32, words: &[u32]) {
        let pkt = pw::encode_ctrl(ctype, add, self.ts(), self.peer_id, words);
        self.outbound(pkt);
    }

    fn send_data_pkt(&self, seq: i32, data: &[u8]) {
        let msg_no = pw::MSG_SOLO | (seq as u32 & 0x1FFF_FFFF);
        if let Ok(pkt) = pw::encode_data(seq, msg_no, self.ts(), self.peer_id, data) {
            self.outbound(pkt);
        }
    }

    fn notify_window(&self) {
        self.window_notify.notify_waiters();
    }

    fn close(&self, err: Option<String>) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(e) = err {
            let _ = self.err_tx.send(Some(e));
        }
        let _ = self.data_tx.lock().expect("数据锁").take();
        let _ = self.out_tx.lock().expect("出包锁").take();
        self.notify_window(); // 唤醒可能停在窗口上的写侧（随后写侧见错误）
    }

    fn error(&self) -> Option<String> {
        self.err_rx.borrow().clone()
    }

    /* ---------- 入包处理（驱动任务调用） ---------- */

    fn handle_packet(self: &Arc<Self>, pkt: pw::Pkt) {
        match pkt {
            pw::Pkt::Data { seq, payload, .. } => self.on_data(seq, &payload),
            pw::Pkt::Ctrl {
                ctype, add, words, ..
            } => match ctype {
                pw::C_ACK => self.on_ack(add, &words),
                pw::C_NAK => self.on_nak(&words),
                pw::C_ACK2 => self.on_ack2(add),
                pw::C_KEEPALIVE => {}
                pw::C_SHUTDOWN => self.on_shutdown(),
                pw::C_HANDSHAKE => {
                    // 已建立连接上对端重发的握手请求 → 幂等重发响应
                    //（libudt processCtrl case 0：req_type > 0 时重发 initdata）。
                    if let Some(resp) = self.hs_resp.lock().expect("握手锁").clone() {
                        self.outbound(resp);
                    }
                }
                pw::C_WARN | pw::C_DROP | pw::C_PEER_ERROR => {}
                _ => {}
            },
        }
        *self.last_rsp.lock().expect("活性锁") = Instant::now();
        self.exp_count.store(1, Ordering::Relaxed);
    }

    /* ---------- 发送方向 ---------- */

    /// 从写侧入队新数据（窗口允许范围内尽量多包）。返回消费的字节数（0 = 窗口满）。
    fn enqueue(&self, buf: &[u8]) -> usize {
        let mut jobs: Vec<(i32, Vec<u8>)> = Vec::new();
        let consumed = {
            let mut s = self.send.lock().expect("发送锁");
            let win = s.window();
            if win == 0 || s.pkts.len() >= win {
                return 0;
            }
            let budget = win - s.pkts.len();
            let mut consumed = 0usize;
            for _ in 0..budget {
                if consumed >= buf.len() {
                    break;
                }
                let n = (buf.len() - consumed).min(pw::UDT_PAYLOAD_MAX);
                let seq = pw::seq_inc(s.next_seq);
                s.next_seq = seq;
                s.pkts.push_back(buf[consumed..consumed + n].to_vec());
                jobs.push((seq, buf[consumed..consumed + n].to_vec()));
                consumed += n;
            }
            consumed
        };
        for (seq, data) in jobs {
            self.send_data_pkt(seq, &data);
        }
        consumed
    }

    /// 重传损失列表（NAK 触发即发 + 周期兜底）。`force = false` 时受节流约束。
    fn retransmit_loss(&self, force: bool) {
        let now = Instant::now();
        {
            let mut last = self.last_loss_send.lock().expect("重传锁");
            if !force && now.duration_since(*last) < RETRANS_MIN_INTERVAL {
                return;
            }
            *last = now;
        }
        // 单次锁内取全部 (seq, data)（无 await 交错，索引不会失效）。
        // 索引语义：pkts.front 的 seq == last_ack（libudt readData(offset) 同构，
        // offset = seqoff(sndLastDataAck, seq)）。
        let jobs: Vec<(i32, Vec<u8>)> = {
            let s = self.send.lock().expect("发送锁");
            s.loss
                .iter()
                .filter_map(|seq| {
                    let idx = pw::seq_off(s.last_ack, *seq);
                    if idx >= 0 {
                        s.pkts.get(idx as usize).map(|d| (*seq, d.clone()))
                    } else {
                        None
                    }
                })
                .collect()
        };
        for (seq, data) in jobs {
            self.send_data_pkt(seq, &data);
        }
    }

    fn on_ack(self: &Arc<Self>, add: i32, words: &[u32]) {
        if words.is_empty() {
            return;
        }
        let mut opened = false;
        let mut send_ack2 = false;
        {
            let mut s = self.send.lock().expect("发送锁");
            if words.len() == 1 {
                // 轻量 ACK：仅 cum，流窗反向递减（libudt 语义）。
                let cum = words[0] as i32;
                if pw::seq_cmp(cum, s.last_ack) >= 0 {
                    let off = pw::seq_off(s.last_ack, cum);
                    if off > 0 {
                        s.flow_window -= off;
                        for _ in 0..off {
                            s.pkts.pop_front();
                        }
                        s.last_ack = cum;
                        s.loss.retain(|x| pw::seq_cmp(*x, cum) >= 0);
                        opened = true;
                    }
                }
            } else {
                let cum = words[0] as i32;
                if pw::seq_cmp(cum, pw::seq_inc(s.next_seq)) > 0 {
                    // 超前 ACK（攻击或 bug）→ 断连（libudt 同语义）。
                    drop(s);
                    self.close(Some("ACK 越界（对端状态异常）".into()));
                    return;
                }
                if pw::seq_cmp(cum, s.last_ack) >= 0 {
                    if words.len() >= 4 {
                        s.flow_window = words[3] as i32;
                    }
                    let off = pw::seq_off(s.last_ack, cum);
                    if off > 0 {
                        for _ in 0..off {
                            s.pkts.pop_front();
                        }
                        s.last_ack = cum;
                        s.loss.retain(|x| pw::seq_cmp(*x, cum) >= 0);
                        opened = true;
                    }
                }
                // CC onACK（近似 UDT4 CUDTCC）：慢启动倍增 / 拥塞避免 +1/cwnd。
                if s.in_slow_start {
                    s.cwnd = (s.cwnd * 2.0).min(s.flow_window.max(CWND_INIT as i32) as f64);
                } else {
                    s.cwnd += 1.0 / s.cwnd.max(1.0);
                }
            }
            let now = Instant::now();
            let mut lk = self.last_ack2.lock().expect("ack2 锁");
            if now.duration_since(lk.1) > Duration::from_micros(pw::SYN_US) || add == lk.0 {
                send_ack2 = true;
                *lk = (add, now);
            }
        }
        if send_ack2 {
            self.send_ctrl(pw::C_ACK2, add, &[]);
        }
        if opened {
            self.notify_window();
        }
    }

    fn on_nak(self: &Arc<Self>, words: &[u32]) {
        let Some(loss_list) = pw::decode_loss(words) else {
            return;
        };
        {
            let mut s = self.send.lock().expect("发送锁");
            for seq in loss_list {
                if pw::seq_cmp(seq, s.last_ack) >= 0 && pw::seq_cmp(seq, s.next_seq) <= 0 {
                    s.loss.insert(seq);
                }
            }
            // CC onLoss：慢启动退出 + 0.875 收缩（近似 CUDTCC）。
            if s.in_slow_start {
                s.in_slow_start = false;
            }
            s.cwnd = (s.cwnd * 0.875).max(CWND_INIT);
        }
        self.retransmit_loss(true);
    }

    fn on_ack2(&self, add: i32) {
        let mut r = self.recv.lock().expect("接收锁");
        if let Some((sent_at, ack_cum)) = r.ack_window.remove(&add) {
            let x_us = sent_at.elapsed().as_micros() as i64;
            if x_us > 0 {
                r.rtt_sample(x_us);
            }
            if pw::seq_cmp(ack_cum, r.last_ack_ack) > 0 {
                r.last_ack_ack = ack_cum;
            }
        }
    }

    /* ---------- 接收方向 ---------- */

    fn on_data(self: &Arc<Self>, seq: i32, payload: &[u8]) {
        // 到达速率/探测对记账（libudt processData：每个到达先记时再处理）。
        {
            let mut r = self.recv.lock().expect("接收锁");
            let now_us = now_us_since(&r.epoch);
            r.on_pkt_arrival(now_us, seq);
        }
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut nak_words: Option<Vec<u32>> = None;
        let mut eof_now = false;
        {
            let mut r = self.recv.lock().expect("接收锁");
            if seq == r.expected {
                out.push(payload.to_vec());
                r.expected = pw::seq_inc(r.expected);
                r.loss.remove(&seq);
            } else if pw::seq_cmp(seq, r.expected) < 0 {
                // 重复包（ACK 丢失后重传）——出损失表即可，不重复投递。
                r.loss.remove(&seq);
            } else {
                // 乱序（seq > expected）。
                if !r.pending.contains_key(&seq) {
                    if r.pending.len() >= REORDER_CAP {
                        // 缓冲满：丢弃（保持缺失状态，发送端经 NAK/EXP 重传）。
                        r.pkt_count += 1;
                        if payload.len() != pw::UDT_PAYLOAD_MAX {
                            r.ack_immediate = true;
                        }
                        return;
                    }
                    r.pending.insert(seq, payload.to_vec());
                }
                r.loss.remove(&seq);
                if pw::seq_cmp(seq, r.curr) > 0 {
                    // 抬高水位：补记缺口，稍后即席 NAK（libudt processData 语义）。
                    let mut s = pw::seq_inc(r.curr);
                    while pw::seq_cmp(s, seq) < 0 {
                        r.loss.insert(s);
                        s = pw::seq_inc(s);
                    }
                    r.curr = seq;
                    nak_words = Some(pw::encode_loss(&r.loss.iter().copied().collect::<Vec<_>>()));
                }
            }
            // 通用收敛（含补齐缺口后 newly-contiguous 的立即投递）。
            loop {
                let exp = r.expected;
                let Some(p) = r.pending.remove(&exp) else {
                    break;
                };
                r.loss.remove(&exp);
                out.push(p);
                r.expected = pw::seq_inc(exp);
            }
            // 最高已见 seq 无条件更新（libudt processData 2442：seqcmp(seq, curr) > 0
            // 即抬 curr——顺序到达同样要抬，否则 ACK cum 永远停在 ISN，发送端窗口卡死）。
            if pw::seq_cmp(seq, r.curr) > 0 {
                r.curr = seq;
            }
            r.pkt_count += 1;
            if payload.len() != pw::UDT_PAYLOAD_MAX {
                r.ack_immediate = true;
            }
            if r.peer_shutdown && r.loss.is_empty() && r.pending.is_empty() {
                eof_now = true;
            }
        }
        if let Some(words) = nak_words {
            self.send_ctrl(pw::C_NAK, 0, &words);
        }
        if !out.is_empty() {
            let tx = self.data_tx.lock().expect("数据锁").clone();
            if let Some(tx) = tx {
                for chunk in out {
                    let _ = tx.send(chunk);
                }
            }
        }
        if eof_now {
            let _ = self.data_tx.lock().expect("数据锁").take();
        }
    }

    fn on_shutdown(self: &Arc<Self>) {
        let drained = {
            let mut r = self.recv.lock().expect("接收锁");
            r.peer_shutdown = true;
            r.loss.is_empty() && r.pending.is_empty()
        };
        if drained {
            let _ = self.data_tx.lock().expect("数据锁").take();
        }
    }

    /* ---------- 驱动扫描 ---------- */

    /// ACK 发送（接收方向）：SYN 周期 + 即席标记 + light ACK（libudt checkTimers 语义）。
    fn send_ack_scan(&self) {
        let now = Instant::now();
        let mut light: Option<i32> = None;
        {
            let mut r = self.recv.lock().expect("接收锁");
            let cum = r.ack_cum();
            if pw::seq_cmp(cum, r.last_ack_ack) > 0 {
                // 完整 ACK 判定：cum 推进 / 即席标记 / 重复 ACK 的 RTT 节流。
                let should_send = if pw::seq_cmp(cum, r.last_ack_sent) > 0 || r.ack_immediate {
                    r.ack_immediate = false;
                    r.last_ack_sent = cum;
                    true
                } else if cum == r.last_ack_sent {
                    let guard = (r.rtt_us + 4 * r.rttvar_us) as u64;
                    now.duration_since(r.last_ack_time).as_micros() as u64 >= guard
                } else {
                    false // 回退的 cum（乱序 NAK 基准）——保持既有 last_ack_sent
                };
                if should_send && pw::seq_cmp(r.last_ack_sent, r.last_ack_ack) > 0 {
                    let ack_no = pw::ack_inc(r.ack_no);
                    r.ack_no = ack_no;
                    if r.ack_window.len() >= ACK_WINDOW_CAP {
                        // 窗口满：丢最旧（libudt 环形窗口同效）。
                        let oldest = r
                            .ack_window
                            .iter()
                            .min_by_key(|(_, (t, _))| *t)
                            .map(|(k, _)| *k);
                        if let Some(k) = oldest {
                            r.ack_window.remove(&k);
                        }
                    }
                    let last = r.last_ack_sent;
                    r.ack_window.insert(ack_no, (now, last));
                    // libudt checkTimers ACK 分支：距上次 6 词 ACK > SYN → 附带
                    // word4/5（接收速率/带宽估计）成 24B；否则 16B。libudt 发送端
                    // CC 退出慢启动后 `cwnd = RcvRate/1e6×(RTT+RC)+16`——缺 word4
                    // 时 cwnd 恒 16 包，C# 发送端塌陷到 ~750 pkt/s（实机 80MB 1MB/s
                    // vs C#↔C# 63MB/s，TECH-STACK §7.31）。
                    let now_us = now_us_since(&r.epoch);
                    let six = now_us - r.last_full_us > pw::SYN_US as u64;
                    if six {
                        r.last_full_us = now_us;
                    }
                    let mut words = [
                        last as u32,
                        r.rtt_us as u32,
                        r.rttvar_us as u32,
                        r.avail_buf() as u32,
                        0,
                        0,
                    ];
                    if six {
                        words[4] = r.pkt_rcv_speed();
                        words[5] = r.bandwidth();
                    }
                    // 线上保真：非 6 词节拍发 16B（4 词）——libudt 同款。
                    let out_words: &[u32] = if six { &words } else { &words[..4] };
                    self.send_ctrl(pw::C_ACK, ack_no, out_words);
                    r.last_ack_time = now;
                    r.pkt_count = 0;
                    r.light_count = 1;
                } else if r.pkt_count >= pw::LIGHT_ACK_PKTS * r.light_count {
                    // 轻量 ACK：add=0、单字 cum（libudt sendCtrl(2,…,4) 线上形态）。
                    light = Some(cum);
                    r.light_count += 1;
                    r.pkt_count = 0;
                } else {
                    r.ack_immediate = false;
                }
            } else if r.pkt_count >= pw::LIGHT_ACK_PKTS * r.light_count {
                light = Some(cum);
                r.light_count += 1;
                r.pkt_count = 0;
            }
        }
        if let Some(cum) = light {
            self.send_ctrl(pw::C_ACK, 0, &[cum as u32]);
        }
    }

    /// EXP / 重传兜底 / keepalive / shutdown 重发（libudt checkTimers EXP 分支语义）。
    fn exp_scan(&self) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let now = Instant::now();
        if now.duration_since(*self.last_rsp.lock().expect("活性锁")) > IDLE_TIMEOUT {
            self.close(Some("连接超时（30s 无对端数据）".into()));
            return;
        }
        let (rtt_us, rttvar_us) = {
            let r = self.recv.lock().expect("接收锁");
            (r.rtt_us, r.rttvar_us)
        };
        let count = self.exp_count.load(Ordering::Relaxed) as i64;
        let exp_int_us: u128 = ((count * (rtt_us + 4 * rttvar_us) + pw::SYN_US as i64) as u64)
            .max((count * 300_000) as u64) as u128;
        let since_rsp = now
            .duration_since(*self.last_rsp.lock().expect("活性锁"))
            .as_micros() as u128;
        if since_rsp < exp_int_us {
            return;
        }
        if self.exp_count.load(Ordering::Relaxed) > EXP_LIMIT && since_rsp > 5_000_000 {
            self.close(Some("连接超时（对端持续无响应）".into()));
            return;
        }
        let has_unacked = {
            let mut s = self.send.lock().expect("发送锁");
            let unacked = !s.pkts.is_empty();
            if unacked && s.loss.is_empty() {
                // 全部未确认包入重传列表（libudt checkTimers EXP 分支语义）。
                // 未确认区间 = [last_ack ..= next_seq]（front.seq == last_ack，
                // 与 pop/重传索引模型一致）。
                let mut seq = s.last_ack;
                while pw::seq_cmp(seq, s.next_seq) <= 0 {
                    s.loss.insert(seq);
                    seq = pw::seq_inc(seq);
                }
            }
            if unacked {
                s.cwnd = CWND_INIT; // onTimeout：重置拥塞窗（近似 CUDTCC）
                s.in_slow_start = true;
            }
            unacked
        };
        if has_unacked {
            self.retransmit_loss(true);
        } else {
            self.send_ctrl(pw::C_KEEPALIVE, 0, &[]);
            *self.last_keepalive.lock().expect("心跳锁") = now;
        }
        self.exp_count.fetch_add(1, Ordering::Relaxed);
        *self.last_rsp.lock().expect("活性锁") = now;
    }

    fn housekeeping_scan(&self) {
        let now = Instant::now();
        // loss 兜底重传（NAK 已即发；此处周期重发未确认的损失包）。
        let loss_nonempty = self.send.lock().expect("发送锁").loss.len() > 0;
        if loss_nonempty {
            self.retransmit_loss(false);
        }
        // shutdown 限次重发（500ms 间隔）。
        let should_resend = {
            let s = self.send.lock().expect("发送锁");
            s.shutdown_req && s.shutdown_resends < SHUTDOWN_RESENDS
        };
        if should_resend
            && self
                .last_shutdown_send
                .lock()
                .expect("shutdown 锁")
                .elapsed()
                >= SHUTDOWN_RESEND_EVERY
        {
            {
                let mut s = self.send.lock().expect("发送锁");
                s.shutdown_resends += 1;
            }
            *self.last_shutdown_send.lock().expect("shutdown 锁") = now;
            self.send_ctrl(pw::C_SHUTDOWN, 0, &[]);
        }
        // keepalive 兜底（静默期心跳）。
        if self
            .last_keepalive
            .lock()
            .expect("心跳锁")
            .elapsed()
            > KEEPALIVE_EVERY
        {
            self.send_ctrl(pw::C_KEEPALIVE, 0, &[]);
            *self.last_keepalive.lock().expect("心跳锁") = now;
        }
    }
}

impl fmt::Debug for UdtConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdtConn")
            .field("my_id", &self.my_id)
            .field("peer_id", &self.peer_id)
            .field("peer", &self.peer)
            .finish()
    }
}

/// 可靠流句柄（C# 方言应用层读写对象；同一连接本端仅一个实例）。
pub struct UdtStream {
    conn: Arc<UdtConn>,
    data_rx: UnboundedReceiver<Vec<u8>>,
    read_buf: Vec<u8>,
    /// 窗口等待 future（每次等待期注册 waker；wake 后置 None 重建）。
    window_fut: Option<Pin<Box<dyn std::future::Future<Output = ()> + Send>>>,
}

impl UdtStream {
    fn request_shutdown(&self) {
        let mut s = self.conn.send.lock().expect("发送锁");
        if !s.shutdown_req {
            s.shutdown_req = true;
            s.shutdown_resends = 1; // 立即发一次，驱动限次补发
            drop(s);
            *self.conn.last_shutdown_send.lock().expect("shutdown 锁") = Instant::now();
            self.conn.send_ctrl(pw::C_SHUTDOWN, 0, &[]);
        }
    }
}

impl AsyncRead for UdtStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                if n == 0 {
                    return Poll::Pending;
                }
                buf.put_slice(&self.read_buf[..n]);
                self.read_buf.drain(..n);
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.data_rx).poll_recv(cx) {
                Poll::Ready(Some(chunk)) => self.read_buf = chunk,
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

impl AsyncWrite for UdtStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(e) = self.conn.error() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)));
        }
        if self.conn.send.lock().expect("发送锁").shutdown_req {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "写端已关闭")));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            let n = self.conn.enqueue(buf);
            if n > 0 {
                return Poll::Ready(Ok(n));
            }
            // 窗口满：先注册 waker 再返回 Pending（notify_waiters 只唤醒已注册者；
            // 注册前发生的一次通知若对应开窗，下一轮 enqueue 即成功，否则由后续
            // ACK 周期通知兜底）。
            if self.window_fut.is_none() {
                let notify = Arc::clone(&self.conn.window_notify);
                self.window_fut = Some(Box::pin(async move { notify.notified().await }));
            }
            let fut = self.window_fut.as_mut().expect("已插入");
            match fut.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    self.window_fut = None;
                    continue;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.request_shutdown();
        Poll::Ready(Ok(()))
    }
}

impl Drop for UdtStream {
    fn drop(&mut self) {
        if self.conn.closed.load(Ordering::SeqCst) {
            return;
        }
        let clean = {
            self.conn.send.lock().expect("发送锁").shutdown_req
        } || {
            self.conn.recv.lock().expect("接收锁").peer_shutdown
        };
        if !clean {
            self.request_shutdown();
        }
        self.conn.close(None);
    }
}

/// `build_conn` 返回：(状态机, 流, 入包通道发送端, 出包通道接收端, 驱动句柄)。
pub(crate) type BuiltConn = (
    Arc<UdtConn>,
    UdtStream,
    UnboundedSender<pw::Pkt>,
    UnboundedReceiver<Vec<u8>>,
    tokio::task::JoinHandle<()>,
);

/// 连接装配。`isn`：本端发送起始 seq；`peer_isn`：对端发送起始 seq（服务端 = 客户端
/// ISN 回显，两端同值——libudt 非 rendezvous 语义）；`flow_window`：对端通告的流窗。
pub(crate) fn build_conn(
    my_id: u32,
    peer_id: u32,
    peer: SocketAddr,
    isn: i32,
    peer_isn: i32,
    flow_window: i32,
    hs_resp: Option<Vec<u8>>,
) -> BuiltConn {
    let (out_tx, out_rx) = unbounded_channel::<Vec<u8>>();
    let (data_tx, data_rx) = unbounded_channel::<Vec<u8>>();
    let (in_tx, in_rx) = unbounded_channel::<pw::Pkt>();
    let (err_tx, err_rx) = watch::channel(None);
    let conn = Arc::new(UdtConn {
        my_id,
        peer_id,
        peer,
        start: Instant::now(),
        send: Mutex::new(SendState::new(isn, flow_window)),
        recv: Mutex::new(RecvState::new(peer_isn)),
        out_tx: Mutex::new(Some(out_tx)),
        data_tx: Mutex::new(Some(data_tx)),
        window_notify: Arc::new(Notify::new()),
        err_tx,
        err_rx,
        hs_resp: Mutex::new(hs_resp),
        last_rsp: Mutex::new(Instant::now()),
        exp_count: AtomicU32::new(1),
        last_loss_send: Mutex::new(Instant::now()),
        last_keepalive: Mutex::new(Instant::now()),
        last_shutdown_send: Mutex::new(Instant::now()),
        last_ack2: Mutex::new((-1, Instant::now() - Duration::from_secs(10))),
        closed: AtomicBool::new(false),
    });
    let stream = UdtStream {
        conn: conn.clone(),
        data_rx,
        read_buf: Vec::new(),
        window_fut: None,
    };
    let driver = tokio::spawn(run_driver(conn.clone(), in_rx));
    (conn, stream, in_tx, out_rx, driver)
}

/// 驱动任务：入包处理 + 10ms 节拍扫描。
async fn run_driver(conn: Arc<UdtConn>, mut in_rx: UnboundedReceiver<pw::Pkt>) {
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if conn.closed.load(Ordering::SeqCst) {
            break;
        }
        tokio::select! {
            pkt = in_rx.recv() => match pkt {
                Some(p) => {
                    conn.handle_packet(p);
                    tokio::task::yield_now().await;
                }
                None => break,
            },
            _ = ticker.tick() => {
                conn.send_ack_scan();
                conn.exp_scan();
                conn.housekeeping_scan();
            }
        }
    }
    conn.close(None);
}

fn random_bytes(n: usize) -> Vec<u8> {
    use rand_core::RngCore;
    let mut v = vec![0u8; n];
    rand_core::OsRng.fill_bytes(&mut v);
    v
}

fn random_u32_nonzero() -> u32 {
    loop {
        let v = u32::from_le_bytes(random_bytes(4).try_into().expect("4 字节"));
        if v != 0 {
            return v;
        }
    }
}

/// 随机 ISN（libudt：rand × MaxSeq，落 0..=MAX_SEQ）。
fn random_isn() -> i32 {
    let v = u64::from(u32::from_le_bytes(random_bytes(4).try_into().expect("4 字节")));
    (v % (pw::MAX_SEQ as u64 + 1)) as i32
}

/// 对端地址的 peer_ip 四字（握手回显字段；IPv4 用 word0 承载）。
fn peer_ip_words(addr: SocketAddr) -> [u32; 4] {
    match addr.ip() {
        IpAddr::V4(v4) => [u32::from(v4), 0, 0, 0],
        IpAddr::V6(v6) => {
            let o = v6.octets();
            [
                u32::from_be_bytes([o[0], o[1], o[2], o[3]]),
                u32::from_be_bytes([o[4], o[5], o[6], o[7]]),
                u32::from_be_bytes([o[8], o[9], o[10], o[11]]),
                u32::from_be_bytes([o[12], o[13], o[14], o[15]]),
            ]
        }
    }
}

/* ============ 客户端 ============ */

/// 建立到 `addr` 的 UDT4 连接（两段式握手：cookie 挑战 → 带证二次请求；30s 超时）。
/// `src_port`：可选本地端口绑定（与 TCP/QUIC/RUDP `--srcport` 同口径）。
pub async fn connect_udt(addr: SocketAddr, src_port: Option<u16>) -> Result<UdtStream> {
    let local = SocketAddr::new(
        if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        },
        src_port.unwrap_or(0),
    );
    let socket = UdpSocket::bind(local).await.map_err(Error::Io)?;
    let my_id = random_u32_nonzero();
    let isn = random_isn();
    let mut req = pw::Handshake {
        version: pw::UDT_VERSION,
        sock_type: pw::UDT_SOCK_STREAM,
        isn,
        mss: pw::UDT_MSS,
        flight_flag: pw::UDT_RCV_BUF_PKTS.min(pw::UDT_FLIGHT_FLAG),
        req_type: pw::HS_REQ,
        id: my_id as i32,
        cookie: 0,
        peer_ip: peer_ip_words(addr),
    };
    let mut buf = vec![0u8; pw::UDT_DGRAM_MAX + 64];
    let deadline = Instant::now() + HS_TIMEOUT;
    let mut last_send = Instant::now() - HS_RESEND;
    let peer_id;
    let peer_flight;
    loop {
        if Instant::now() >= deadline {
            return Err(proto("UDT 握手超时（30s）"));
        }
        if last_send.elapsed() >= HS_RESEND {
            let pkt = req.encode_ctrl(0, 0); // 握手请求 dst = 0（libudt 连接请求口径）
            socket.send_to(&pkt, addr).await.map_err(Error::Io)?;
            last_send = Instant::now();
        }
        let remain = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remain.min(HS_RESEND), socket.recv_from(&mut buf)).await {
            Err(_) => continue, // 重发窗口到点
            Ok(Err(e)) => return Err(Error::Io(e)),
            Ok(Ok((n, src))) => {
                if src != addr {
                    continue;
                }
                match pw::decode(&buf[..n]) {
                    Some(pw::Pkt::Ctrl {
                        ctype: pw::C_HANDSHAKE,
                        words,
                        dst,
                        ..
                    }) if dst == my_id || dst == 0 => {
                        let Some(hs) = pw::Handshake::from_words(&words) else {
                            continue;
                        };
                        if hs.req_type == pw::HS_REQ {
                            // 阶段一应答：cookie 挑战 → 带证二次请求（立即发，不等 250ms）。
                            req.cookie = hs.cookie;
                            req.req_type = pw::HS_RESP;
                            let pkt = req.encode_ctrl(0, 0);
                            socket.send_to(&pkt, addr).await.map_err(Error::Io)?;
                            last_send = Instant::now();
                            continue;
                        }
                        if hs.req_type == pw::HS_RESP {
                            // 安全校验：响应 ISN 必须回显本端 ISN（libudt security check）。
                            if hs.isn != isn {
                                return Err(proto("UDT 握手安全校验失败（ISN 不回显）"));
                            }
                            peer_id = hs.id as u32;
                            peer_flight = hs.flight_flag;
                            break;
                        }
                        if hs.req_type == pw::HS_REJECT {
                            return Err(proto("UDT 连接被对端拒绝（版本/类型不符或策略拒绝）"));
                        }
                    }
                    _ => continue, // 非握手/其他 dst → 忽略
                }
            }
        }
    }
    // 服务端以客户端 ISN 作为自己的发送 ISN（libudt acceptAndRespond 回显）。
    let (_conn, stream, in_tx, mut out_rx, driver) =
        build_conn(my_id, peer_id, addr, isn, isn, peer_flight.max(2), None);
    let socket = Arc::new(socket);
    // 入包泵：全部（含握手重发响应）交给驱动。
    let pump_sock = socket.clone();
    let pump_in = in_tx;
    let pump_my = my_id;
    tokio::spawn(async move {
        let mut b = vec![0u8; pw::UDT_DGRAM_MAX + 64];
        loop {
            tokio::select! {
                r = pump_sock.recv_from(&mut b) => match r {
                    Ok((n, src)) => {
                        if src == addr {
                            if let Some(p) = pw::decode(&b[..n]) {
                                if p.dst() == pump_my {
                                    let _ = pump_in.send(p);
                                }
                            }
                        }
                        tokio::task::yield_now().await;
                    }
                    Err(e) => {
                        // Windows ICMP 毒化（10054）按瞬态继续；其余错误短暂退避。
                        if e.raw_os_error() != Some(10054) {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        tokio::task::yield_now().await;
                    }
                },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
    });
    // 出包泵。send 失败（ICMP 毒化瞬态）重试而非退出——通道关闭才是退出条件。
    let send_sock = socket;
    tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            if send_sock.send_to(&pkt, addr).await.is_err() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            tokio::task::yield_now().await;
        }
    });
    drop(driver); // detached：泵随连接关闭退出 → in_tx drop → 驱动收尾
    Ok(stream)
}

/* ============ 服务端 ============ */

struct ConnEntry {
    peer: SocketAddr,
    in_tx: UnboundedSender<pw::Pkt>,
    /// 建连时的握手响应（重复握手幂等重发）。
    hs_resp: Vec<u8>,
}

/// 监听并服务 UDT 连接（收缓冲 4MB，对齐 `serve_rudp` 口径；通配 `::` 双栈——
/// TECH-STACK §7.31）。
pub async fn serve_udt(
    addr: SocketAddr,
    opts: crate::transfer::receiver::RecvOptions,
) -> Result<()> {
    let std_sock = crate::transfer::std_udp_listener(addr).map_err(Error::Io)?;
    std_sock.set_nonblocking(true).map_err(Error::Io)?;
    let socket = UdpSocket::from_std(std_sock).map_err(Error::Io)?;
    serve_udt_on(socket, opts).await
}

/// 在既有 UDP socket 上服务 UDT 连接（GUI 复用 `bind_udp` 的逐地址绑定）。
/// 连接处理委托 `cswire::handle_conn_cs`（C# 方言应用层）。
pub async fn serve_udt_on(
    socket: UdpSocket,
    opts: crate::transfer::receiver::RecvOptions,
) -> Result<()> {
    use crate::transfer::receiver::{cleanup_part_orphans, ip_allowed};
    cleanup_part_orphans(&opts.save_dir);
    crate::transfer::resume::cleanup_resume_orphans(&opts.save_dir);

    let listener_id = random_u32_nonzero();
    let served = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let socket = Arc::new(socket);
    // C# 方言跨连接状态（分块组装/断点会话/组归属）——serve 级共享。
    let cs_state = Arc::new(crate::transfer::cswire::CsServerState::default());
    // 连接表：my_id → 入口；peer_id → my_id（重复握手幂等路由）。
    let conns: Arc<Mutex<HashMap<u32, ConnEntry>>> = Arc::new(Mutex::new(HashMap::new()));
    let by_peer: Arc<Mutex<HashMap<u32, u32>>> = Arc::new(Mutex::new(HashMap::new()));
    // SYN cookie 表（客户端 IP → (cookie, 签发时刻)；2 分钟刷新）。
    let cookies: Arc<Mutex<HashMap<IpAddr, (i32, Instant)>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let ended = Arc::new(tokio::sync::Notify::new());
    let mut finished = tokio::task::JoinSet::new();
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let mut buf = vec![0u8; pw::UDT_DGRAM_MAX + 64];

    loop {
        while finished.try_join_next().is_some() {}
        tokio::task::yield_now().await;
        let (n, src) = tokio::select! {
            r = socket.recv_from(&mut buf) => match r {
                Ok(x) => x,
                Err(e) => {
                    let code = e.raw_os_error();
                    if code == Some(10040) {
                        continue; // EMSGSIZE 杂包（Windows 10040）
                    }
                    if code == Some(10054) {
                        // Windows UDP 的 ICMP port-unreachable 毒化：向已关端口发包后
                        // 下一次 recv 报 WSAECONNRESET——瞬态，继续服务（C# 版
                        // DeviceDiscovery.cs 同款问题的同款对策）。
                        continue;
                    }
                    return Err(Error::Io(e));
                }
            },
            _ = stop_rx.changed() => return Ok(()),
        };
        let Some(pkt) = pw::decode(&buf[..n]) else {
            continue;
        };
        let opts = opts.clone();

        // 握手处理（dst = 0 或 listener id；已建立连接的握手重发走数据面路由）。
        let hs_route = if let pw::Pkt::Ctrl {
            ctype: pw::C_HANDSHAKE,
            ref words,
            dst,
            ..
        } = pkt
        {
            if dst == 0 || dst == listener_id {
                pw::Handshake::from_words(words).map(|hs| hs)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(hs) = hs_route {
            if hs.req_type == pw::HS_REQ {
                // 阶段一：回 cookie 挑战（回显请求 + cookie 字段，req_type 仍为 1）。
                let cookie = {
                    let mut m = cookies.lock().expect("cookie 锁");
                    let now = Instant::now();
                    m.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(120));
                    if m.len() > 4096 {
                        m.clear();
                    }
                    let e = m.entry(src.ip()).or_insert_with(|| {
                        (
                            i32::from_le_bytes(random_bytes(4).try_into().expect("4 字节")),
                            now,
                        )
                    });
                    e.1 = now;
                    e.0
                };
                let resp = pw::Handshake { cookie, ..hs };
                let _ = socket.send_to(&resp.encode_ctrl(0, hs.id as u32), src).await;
                continue;
            }
            if hs.req_type == pw::HS_RESP {
                // 阶段二：cookie 校验（无签发记录/不匹配 → 静默，防伪造源）。
                let cookie_ok = cookies
                    .lock()
                    .expect("cookie 锁")
                    .get(&src.ip())
                    .is_some_and(|(c, _)| *c == hs.cookie);
                if !cookie_ok {
                    continue;
                }
                // 版本/类型/IP 过滤门（libudt listen：不符 → 1002 拒绝）。
                if hs.version != pw::UDT_VERSION
                    || hs.sock_type != pw::UDT_SOCK_STREAM
                    || !ip_allowed(src.ip(), opts.ip_filter_mode, &opts.ip_filter_list)
                {
                    let peer_id = hs.id;
                    let resp = pw::Handshake {
                        req_type: pw::HS_REJECT,
                        ..hs
                    };
                    let _ = socket
                        .send_to(&resp.encode_ctrl(0, peer_id as u32), src)
                        .await;
                    continue;
                }
                // 重复握手（客户端未收到响应而重发）→ 幂等重发该连接的响应。
                let dup = {
                    let my_id = by_peer
                        .lock()
                        .expect("peer 表锁")
                        .get(&(hs.id as u32))
                        .copied();
                    my_id.and_then(|id| {
                        conns
                            .lock()
                            .expect("连接表锁")
                            .get(&id)
                            .filter(|e| e.peer == src)
                            .map(|e| e.hs_resp.clone())
                    })
                };
                if let Some(resp) = dup {
                    let _ = socket.send_to(&resp, src).await;
                    continue;
                }
                // 限量模式（--count）：串行——等现有连接结束；收满即停。
                if let Some(max) = opts.max_count {
                    loop {
                        let empty = conns.lock().expect("连接表锁").is_empty();
                        if empty {
                            break;
                        }
                        let _ =
                            tokio::time::timeout(Duration::from_millis(100), ended.notified()).await;
                    }
                    if served.load(std::sync::atomic::Ordering::Relaxed) >= max {
                        return Ok(());
                    }
                }
                // 表容量。
                if conns.lock().expect("连接表锁").len() >= UDT_CONN_CAP {
                    let peer_id = hs.id;
                    let resp = pw::Handshake {
                        req_type: pw::HS_REJECT,
                        ..hs
                    };
                    let _ = socket
                        .send_to(&resp.encode_ctrl(0, peer_id as u32), src)
                        .await;
                    continue;
                }
                // 建连：服务端发送 ISN = 客户端 ISN（libudt acceptAndRespond 回显语义）。
                let my_id = random_u32_nonzero();
                let mss = hs.mss.min(pw::UDT_MSS);
                let hs_resp = pw::Handshake {
                    version: pw::UDT_VERSION,
                    sock_type: pw::UDT_SOCK_STREAM,
                    isn: hs.isn,
                    mss,
                    flight_flag: pw::UDT_RCV_BUF_PKTS.min(pw::UDT_FLIGHT_FLAG),
                    req_type: pw::HS_RESP,
                    id: my_id as i32,
                    cookie: hs.cookie,
                    peer_ip: peer_ip_words(src),
                }
                .encode_ctrl(0, hs.id as u32);
                let (_c, stream, in_tx, out_rx_c, driver) = build_conn(
                    my_id,
                    hs.id as u32,
                    src,
                    hs.isn,
                    hs.isn,
                    hs.flight_flag.max(2),
                    Some(hs_resp.clone()),
                );
                {
                    let mut t = conns.lock().expect("连接表锁");
                    t.insert(
                        my_id,
                        ConnEntry {
                            peer: src,
                            in_tx,
                            hs_resp: hs_resp.clone(),
                        },
                    );
                    by_peer
                        .lock()
                        .expect("peer 表锁")
                        .insert(hs.id as u32, my_id);
                }
                // 连接出包 → 共享 socket（逐连接转发任务）。send 失败（ICMP 毒化
                // 瞬态/对端已关）不得终止泵——通道关闭才是退出条件。
                let fwd_sock = Arc::clone(&socket);
                let fwd_peer = src;
                tokio::spawn(async move {
                    let mut rx = out_rx_c;
                    while let Some(p) = rx.recv().await {
                        if fwd_sock.send_to(&p, fwd_peer).await.is_err() {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        tokio::task::yield_now().await;
                    }
                });
                // 立即发出握手响应（libudt：新连接响应由 accept 侧发出）。
                let _ = socket.send_to(&hs_resp, src).await;
                let o2 = opts.clone();
                let served2 = served.clone();
                let conns2 = conns.clone();
                let by_peer2 = by_peer.clone();
                let ended2 = ended.clone();
                let stop2 = stop_tx.clone();
                let serial_max = opts.max_count;
                let peer_id_cs = hs.id as u32;
                let cs_state2 = Arc::clone(&cs_state);
                finished.spawn(async move {
                    let _ = crate::transfer::cswire::handle_conn_cs(
                        stream,
                        src,
                        &o2,
                        served2.clone(),
                        cs_state2,
                    )
                    .await;
                    let _ = driver.await;
                    conns2.lock().expect("连接表锁").remove(&my_id);
                    by_peer2.lock().expect("peer 表锁").remove(&peer_id_cs);
                    ended2.notify_waiters();
                    if let Some(max) = serial_max {
                        if served2.load(std::sync::atomic::Ordering::Relaxed) >= max {
                            let _ = stop2.send(true);
                        }
                    }
                });
                continue;
            }
            continue;
        }

        // 数据面：按 dst socket id 路由（peer 校验防串线）。
        let entry = conns
            .lock()
            .expect("连接表锁")
            .get(&pkt.dst())
            .map(|e| (e.peer, e.in_tx.clone()));
        if let Some((peer, in_tx)) = entry {
            if peer == src {
                let _ = in_tx.send(pkt);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 绕过 socket 的对偶装配：两条连接的出入包直接经转发任务对接（可选确定性丢包）。
    /// 握手已完成状态：两端 ISN 同值（libudt 语义）、流窗 64。
    async fn pair(lossy: bool) -> (UdtStream, UdtStream) {
        let peer_c: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let peer_s: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let isn = 123456;
        let (c_conn, cs, c_in, mut c_out, c_drv) =
            build_conn(100, 200, peer_s, isn, isn, 64, None);
        let (s_conn, ss, s_in, mut s_out, s_drv) =
            build_conn(200, 100, peer_c, isn, isn, 64, None);
        let mut seed1 = 0x1234_5678_9ABC_DEF0u64;
        let mut seed2 = 0x0FED_CBA9_8765_4321u64;
        tokio::spawn(async move {
            while let Some(pkt) = c_out.recv().await {
                seed1 ^= seed1 << 13;
                seed1 ^= seed1 >> 7;
                seed1 ^= seed1 << 17;
                if lossy && seed1.is_multiple_of(4) {
                    continue;
                }
                // 出包是已编码字节 → 解码后注入对端驱动（对偶免 socket）。
                if let Some(p) = pw::decode(&pkt) {
                    let _ = s_in.send(p);
                }
            }
        });
        tokio::spawn(async move {
            while let Some(pkt) = s_out.recv().await {
                seed2 ^= seed2 << 13;
                seed2 ^= seed2 >> 7;
                seed2 ^= seed2 << 17;
                if lossy && seed2.is_multiple_of(4) {
                    continue;
                }
                if let Some(p) = pw::decode(&pkt) {
                    let _ = c_in.send(p);
                }
            }
        });
        drop((c_conn, s_conn, c_drv, s_drv));
        (cs, ss)
    }

    /// 无损：双向 + 顺序 + SHUTDOWN→EOF 收尾。
    #[tokio::test]
    async fn stream_roundtrip_bidirectional_clean_close() {
        let (mut c, mut s) = pair(false).await;
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        // 超时护栏：窗口/ACK 链路卡死时以失败形式呈现，而非挂起整个测试进程。
        tokio::time::timeout(Duration::from_secs(10), async {
            c.write_all(&payload).await.unwrap();
            c.flush().await.unwrap();
        })
        .await
        .expect("write_all 10s 未完成（窗口/ACK 链路卡死）");
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got))
            .await
            .expect("read_exact 10s 未完成（ACK 链路卡死）")
            .unwrap();
        assert_eq!(got, payload, "大载荷必须逐字节一致（含乱序重排）");
        s.write_all(b"OK").await.unwrap();
        let mut back = [0u8; 2];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"OK");
        c.shutdown().await.unwrap();
        let mut eof = Vec::new();
        let n = s.read_to_end(&mut eof).await.unwrap();
        assert_eq!(n, 0, "SHUTDOWN 后服务端必须见 EOF");
    }

    /// 25% 丢包注入：NAK 重传 + 乱序重排必须恢复完整流。
    #[tokio::test]
    async fn loss_recovery_reassembles_stream() {
        let (mut c, mut s) = pair(true).await;
        let payload: Vec<u8> = (0..60_000u32).map(|i| (i % 241) as u8).collect();
        tokio::time::timeout(Duration::from_secs(20), async {
            c.write_all(&payload).await.unwrap();
            c.flush().await.unwrap();
        })
        .await
        .expect("lossy write_all 20s 未完成（窗口/ACK 链路卡死）");
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(20), s.read_exact(&mut got))
            .await
            .expect("lossy read_exact 20s 未完成（重传链路卡死）")
            .unwrap();
        assert_eq!(got, payload, "丢包后必须经 NAK 重传恢复逐字节一致");
        c.shutdown().await.unwrap();
        let mut sink = Vec::new();
        assert_eq!(
            s.read_to_end(&mut sink).await.unwrap(),
            0,
            "丢包链路同样必须干净收尾"
        );
    }

    /// 异常中止：客户端提前 drop → SHUTDOWN → 服务端读出已交付部分后见 EOF。
    #[tokio::test]
    async fn abrupt_drop_yields_eof_not_hang() {
        let (c, mut s) = pair(false).await;
        {
            let mut c = c;
            c.write_all(b"partial").await.unwrap();
        }
        let mut sink = Vec::new();
        let n = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut sink))
            .await
            .expect("5s 内必须收尾")
            .unwrap();
        assert_eq!(n, 7, "drop 发 SHUTDOWN → 读出已交付部分后见 EOF（\"partial\"=7B）");
    }

    /// 重复 DATA（ACK 丢失场景）：同 seq 不得重复投递；乱序+补齐收敛。
    #[tokio::test]
    async fn duplicate_data_delivered_once_and_reorder() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let isn = 777;
        let (_conn, mut stream, in_tx, _out, _drv) = build_conn(1, 2, peer, isn, isn, 64, None);
        let seq0 = isn;
        let seq1 = pw::seq_inc(seq0);
        let seq2 = pw::seq_inc(seq1);
        let mk = |seq: i32, payload: &[u8]| pw::Pkt::Data {
            seq,
            msg_no: 0,
            ts: 0,
            dst: 1,
            payload: payload.to_vec(),
        };
        in_tx.send(mk(seq0, b"he")).unwrap();
        in_tx.send(mk(seq2, b"!")).unwrap(); // 乱序（缺口 seq1）
        in_tx.send(mk(seq1, b"ll")).unwrap(); // 补齐
        in_tx.send(mk(seq1, b"ll")).unwrap(); // 重复
        let mut got = [0u8; 5];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hell!", "乱序重排 + 重复去重");
    }

    /// 超前 ACK 必须断连（libudt attack/bug 防线）。
    #[tokio::test]
    async fn oversized_ack_breaks_connection() {
        let peer: SocketAddr = "127.0.0.1:11".parse().unwrap();
        let isn = 42;
        let (conn, mut stream, in_tx, _out, _drv) = build_conn(1, 2, peer, isn, isn, 64, None);
        // next_seq = isn-1 → 合法 ACK 上限 = isn。发 isn+10（超前）→ 断连。
        in_tx
            .send(pw::Pkt::Ctrl {
                ctype: pw::C_ACK,
                ext: 0,
                add: 0,
                ts: 0,
                dst: 1,
                words: vec![(isn + 10) as u32, 0, 0, 64],
            })
            .unwrap();
        let mut buf = [0u8; 8];
        let r = stream.read(&mut buf).await;
        assert!(r.is_err(), "超前 ACK 必须报 ConnectionReset");
        assert!(conn.error().is_some());
    }

    /// 窗口约束：流窗 3 时写 8 包必须被窗口限流（未被 ACK 放行前不得完成）。
    #[tokio::test]
    async fn write_blocks_on_flow_window() {
        let peer: SocketAddr = "127.0.0.1:13".parse().unwrap();
        let isn = 5;
        let (_conn, stream, _in_tx, mut out, _drv) = build_conn(1, 2, peer, isn, isn, 3, None);
        let big = vec![7u8; 8 * pw::UDT_PAYLOAD_MAX];
        let mut stream = stream;
        let handle = tokio::spawn(async move {
            stream.write_all(&big).await.unwrap();
            stream.flush().await.unwrap();
        });
        // 窗口 3 → 先发 3 个包，其余等 ACK。200ms 内不得完成。
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !handle.is_finished(),
            "8 包 > 流窗 3：写必须在窗口上阻塞（未被 ACK 前不得完成）"
        );
        // 前三个包已出（拉取确认计数后丢弃）。
        let mut seen = 0;
        while tokio::time::timeout(Duration::from_millis(50), out.recv())
            .await
            .unwrap()
            .is_some()
        {
            seen += 1;
            if seen >= 3 {
                break;
            }
        }
        assert_eq!(seen, 3, "窗口 3 → 恰 3 个数据包出队");
        handle.abort();
    }
}
