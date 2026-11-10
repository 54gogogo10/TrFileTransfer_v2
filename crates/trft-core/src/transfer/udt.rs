//! UDT 槽位（原生 Rust 实现）：UDP 之上的可靠有序字节流，帧协议与 TCP 完全一致
//! （规格 §4.3：与 UDT4/C# 不做包级互通，线格式见 WIRE-PROTOCOL.md「UDT 传输」）。
//!
//! 结构（对齐 `udp.rs` 的「引擎与 socket 解耦」纪律）：
//! - `UdtConn`：连接状态机（发送窗口/重传/RTT 估计 + 接收重排/确认），纯逻辑，
//!   经 `mpsc` 出入包，可绕过 socket 直接构造对偶做丢包注入单测；
//! - `UdtStream`：`AsyncRead + AsyncWrite`，帧层零改动复用（0x05 配对、0x09 加密、
//!   分块/续传/文件夹/限速/进度全部继承 TCP 路径）；
//! - 客户端 `connect_udt`（HS 握手 + 定时重发），服务端 `serve_udt_on`（单 socket
//!   按 conn_id 多路分解 → `receiver::handle_conn_quic` 复用入口：闸/锁/统计同口径）。
//!
//! 与 UDT4 的语义差异（TECH-STACK §3 登记）：固定窗口（64×1200B）无拥塞控制、
//! 立即逐包 ACK + SACK、RTO 按 RFC 6298 简化 EWMA（200ms–3s）、30s 空闲超时
//! （对齐原版 UDT_RCVTIMEO/UDT_SNDTIMEO）。

use crate::error::{proto, Error, Result};
use crate::protocol::udt as pw;
use std::collections::{HashMap, HashSet, VecDeque};
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

/// 在途包窗口（双向，256×1200B ≈ 300KB——RTT 50ms 时吞吐上限 ≈6MB/s）。
const UDT_WINDOW: usize = 256;
/// 乱序重排缓冲上限（超出丢弃，等发送端重传）。
const UDT_PENDING_CAP: usize = 4 * UDT_WINDOW;
/// 重传扫描节拍。
const UDT_TICK: Duration = Duration::from_millis(25);
/// RTO 下限/上限/初值（ms）。
const UDT_RTO_MIN_MS: u64 = 200;
const UDT_RTO_MAX_MS: u64 = 3000;
const UDT_RTO_INIT_MS: u64 = 400;
/// 单包重传上限（超过判链路过差，断连——不无限重传放大）。
const UDT_RETRIES_MAX: u32 = 12;
/// 空闲超时（对齐原版 UDT_RCVTIMEO/UDT_SNDTIMEO = 30 秒）。
const UDT_IDLE: Duration = Duration::from_secs(30);
/// 握手超时（原版 WaitForConnectionReady 30×200ms 同口径上限）。
const UDT_HS_TIMEOUT: Duration = Duration::from_secs(30);
/// 握手重发间隔。
const UDT_HS_RESEND: Duration = Duration::from_millis(300);
/// FIN 等待 FIN_ACK 的兜底（超时按尽力收尾放行，与 TCP `let _ = shutdown()` 同口径）。
const UDT_FIN_WAIT: Duration = Duration::from_secs(5);
/// 服务端连接表上限。
const UDT_CONN_CAP: usize = 256;

type Pkt = (u8, u32, Vec<u8>); // (kind, seq, payload)

#[derive(Debug, Clone)]
struct InFlight {
    data: Vec<u8>,
    first_send: Instant,
    last_send: Instant,
    retries: u32,
}

#[derive(Debug)]
struct SendSide {
    inflight: HashMap<u32, InFlight>,
    next_seq: u32,
    sacked: HashSet<u32>,
    srtt_ms: f64,
    rttvar_ms: f64,
    rto: Duration,
    shutdown_req: bool,
    fin_sent_at: Option<Instant>,
}

impl SendSide {
    fn new() -> Self {
        Self {
            inflight: HashMap::new(),
            next_seq: 0,
            sacked: HashSet::new(),
            srtt_ms: 0.0,
            rttvar_ms: 0.0,
            rto: Duration::from_millis(UDT_RTO_INIT_MS),
            shutdown_req: false,
            fin_sent_at: None,
        }
    }

    /// RFC 6298 简化 EWMA：srtt = 7/8 s + 1/8 x；rttvar = 3/4 v + 1/4 |x−s|。
    /// （重传包的采样偏大 → RTO 偏保守，方向安全。）
    fn rto_update(&mut self, sample_ms: f64) {
        if self.srtt_ms <= 0.0 {
            self.srtt_ms = sample_ms;
        } else {
            self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * (sample_ms - self.srtt_ms).abs();
            self.srtt_ms = 0.875 * self.srtt_ms + 0.125 * sample_ms;
        }
        let rto = self.srtt_ms + 4.0 * self.rttvar_ms;
        self.rto = Duration::from_millis((rto as u64).clamp(UDT_RTO_MIN_MS, UDT_RTO_MAX_MS));
    }
}

#[derive(Debug)]
struct RecvSide {
    expected: u32,
    pending: HashMap<u32, Vec<u8>>,
    remote_fin: Option<u32>,
    eof_seen: bool,
}

impl RecvSide {
    fn new() -> Self {
        Self {
            expected: 0,
            pending: HashMap::new(),
            remote_fin: None,
            eof_seen: false,
        }
    }

    /// 从乱序缓存收敛连续段到输出（调用方持锁）。
    fn drain_contiguous(&mut self, out: &mut VecDeque<Vec<u8>>) {
        while let Some(p) = self.pending.remove(&self.expected) {
            out.push_back(p);
            self.expected += 1;
        }
    }

    /// ACK 载荷用 SACK 区间（pending 键合并连续段，≤64 段）。
    fn sack_ranges(&self) -> Vec<(u32, u8)> {
        let mut keys: Vec<u32> = self.pending.keys().copied().collect();
        keys.sort_unstable();
        let mut out = Vec::new();
        let mut i = 0;
        while i < keys.len() && out.len() < 64 {
            let start = keys[i];
            let mut len = 1u8;
            while i + 1 < keys.len()
                && keys[i + 1] == keys[i] + 1
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

/// 已编码出包出口类型（socket 发送任务消费）。
type OutTx = Mutex<Option<UnboundedSender<(SocketAddr, Vec<u8>)>>>;

/// 连接状态机（收发双侧共享；驱动任务与 `UdtStream` 各持 Arc）。
pub(crate) struct UdtConn {
    conn: u32,
    peer: SocketAddr,
    send: Mutex<SendSide>,
    recv: Mutex<RecvSide>,
    /// 窗口信号量：每排队一个 DATA 消耗 1，ACK 确认归还 1；close 兜底全量归还。
    window: Arc<Semaphore>,
    /// 已编码出包出口（socket 发送任务消费；close 时摘除）。
    out_tx: OutTx,
    /// 有序载荷出口（读侧 poll_recv 消费；EOF/错误时摘除关闭 → 读侧见 EOF）。
    data_tx: Mutex<Option<UnboundedSender<Vec<u8>>>>,
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

impl UdtConn {
    fn outbound(&self, pkt: Vec<u8>) {
        let tx = self.out_tx.lock().expect("出包锁").clone();
        if let Some(tx) = tx {
            let _ = tx.send((self.peer, pkt));
        }
    }

    fn send_data(&self, seq: u32, data: &[u8]) {
        if let Ok(p) = pw::encode(pw::U_P_DATA, self.conn, seq, data) {
            self.outbound(p);
        }
    }

    fn send_ack(&self, recv: &RecvSide) {
        let payload = pw::encode_ack_payload(recv.expected, &recv.sack_ranges());
        if let Ok(p) = pw::encode(pw::U_P_ACK, self.conn, 0, &payload) {
            self.outbound(p);
        }
    }

    fn send_fin(&self, total: u32) {
        if let Ok(p) = pw::encode(pw::U_P_FIN, self.conn, 0, &total.to_le_bytes()) {
            self.outbound(p);
        }
    }

    fn send_rst(&self, reason: &str) {
        let mut payload = reason.as_bytes().to_vec();
        payload.truncate(200);
        if let Ok(p) = pw::encode(pw::U_P_RST, self.conn, 0, &payload) {
            self.outbound(p);
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
        self.window.add_permits(UDT_WINDOW);
    }

    fn error(&self) -> Option<String> {
        self.err_rx.borrow().clone()
    }

    /// 处理一入包（驱动任务调用）。HS/HS_ACK 只属于握手阶段，驱动期忽略。
    fn handle_packet(self: &Arc<Self>, kind: u8, seq: u32, payload: &[u8]) {
        match kind {
            pw::U_P_DATA => self.on_data(seq, payload),
            pw::U_P_ACK => self.on_ack(payload),
            pw::U_P_FIN => {
                // FIN 载荷 = DATA 总数（seq 头字段弃用）。
                let total = if payload.len() >= 4 {
                    u32::from_le_bytes(payload[..4].try_into().expect("4 字节"))
                } else {
                    seq
                };
                self.on_fin(total);
            }
            pw::U_P_FIN_ACK => {
                self.fin_flag.store(true, Ordering::SeqCst);
                // 唤醒 poll_shutdown：waker 挂在 fin_rx（Receiver）上，经 channel
                // 投递即 wake——不依赖 Notified future 的跨 poll 存活。
                if let Some(tx) = self.fin_tx.lock().expect("fin 锁").clone() {
                    let _ = tx.send(());
                }
            }
            pw::U_P_RST => {
                let reason = String::from_utf8(payload.to_vec()).unwrap_or_default();
                let msg = if reason.is_empty() {
                    "连接被对端中止".into()
                } else {
                    reason
                };
                self.close(Some(msg));
            }
            _ => {}
        }
        *self.last_rx.lock().expect("活性锁") = Instant::now();
    }

    fn on_data(self: &Arc<Self>, seq: u32, payload: &[u8]) {
        // 单次加锁完成状态变更与判定；出包/投递一律放锁外（std Mutex 不可重入）。
        enum Action {
            Dup,           // 重复包（ACK 丢失）→ 重发当前 ACK
            Gap,           // 乱序 → 已入缓存，ACK 告知空洞
            Deliver(bool), // 连续段就绪 → 投递读侧；bool = FIN 达成（EOF）
        }
        let mut out = VecDeque::new();
        let action = {
            let mut r = self.recv.lock().expect("接收锁");
            if seq < r.expected {
                Action::Dup
            } else if seq == r.expected {
                out.push_back(payload.to_vec());
                r.expected += 1;
                r.drain_contiguous(&mut out);
                let eof_now = match r.remote_fin {
                    Some(total) => r.expected >= total && !r.eof_seen,
                    None => false,
                };
                if eof_now {
                    r.eof_seen = true;
                }
                Action::Deliver(eof_now)
            } else {
                // 乱序：入缓存（超限丢弃，等发送端重传）。
                if r.pending.len() < UDT_PENDING_CAP {
                    r.pending.insert(seq, payload.to_vec());
                }
                Action::Gap
            }
        };
        match action {
            Action::Dup | Action::Gap => {
                let r = self.recv.lock().expect("接收锁");
                self.send_ack(&r);
            }
            Action::Deliver(eof_now) => {
                let tx = self.data_tx.lock().expect("数据锁").clone();
                if let Some(tx) = tx {
                    for chunk in out {
                        let _ = tx.send(chunk);
                    }
                }
                if eof_now {
                    // 先关读侧（EOF 可见）再回 FIN_ACK。
                    let _ = self.data_tx.lock().expect("数据锁").take();
                    self.send_fin_ack();
                }
            }
        }
    }

    fn send_fin_ack(&self) {
        if let Ok(p) = pw::encode(pw::U_P_FIN_ACK, self.conn, 0, &[]) {
            self.outbound(p);
        }
    }

    fn on_ack(self: &Arc<Self>, payload: &[u8]) {
        let Some((cum, sacks)) = pw::decode_ack_payload(payload) else {
            return;
        };
        let mut released = 0usize;
        {
            let mut s = self.send.lock().expect("发送锁");
            if cum > s.next_seq {
                return; // 非法/超前 ACK（fail-closed 忽略）
            }
            // RTT 采样：取 cum-1 号包的首次发送时刻（重传包采样偏大 → RTO 偏保守）。
            if cum > 0 {
                if let Some(inf) = s.inflight.get(&(cum - 1)) {
                    let sample = inf.first_send.elapsed().as_secs_f64() * 1000.0;
                    s.rto_update(sample.max(0.1));
                }
            }
            for k in s.inflight.keys().copied().collect::<Vec<_>>() {
                if k < cum && s.inflight.remove(&k).is_some() {
                    released += 1;
                }
            }
            for (start, len) in sacks {
                for k in start..start.saturating_add(u32::from(len)) {
                    if s.inflight.remove(&k).is_some() {
                        released += 1;
                    }
                }
            }
            s.sacked.retain(|k| *k >= cum);
        }
        if released > 0 {
            self.window.add_permits(released);
        }
    }

    fn on_fin(self: &Arc<Self>, total: u32) {
        let (finish, got_gap) = {
            let mut r = self.recv.lock().expect("接收锁");
            // 取更小的 total（重复 FIN 一致；防御性取 min）。
            r.remote_fin = Some(r.remote_fin.map_or(total, |t| t.min(total)));
            let finish = r.expected >= total && r.pending.is_empty() && !r.eof_seen;
            (finish, !finish)
        };
        if finish {
            let _ = self.data_tx.lock().expect("数据锁").take();
            {
                let mut r = self.recv.lock().expect("接收锁");
                r.eof_seen = true;
            }
            self.send_fin_ack();
        } else if got_gap {
            // 有空洞：ACK 告知缺口，收满后由 on_data 触发 EOF。
            let r = self.recv.lock().expect("接收锁");
            self.send_ack(&r);
        }
    }

    /// 重传扫描（驱动节拍调用）：RTO 到期重发、FIN 重发、空闲超时、重传上限。
    fn scan(&self) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let now = Instant::now();
        if now.duration_since(*self.last_rx.lock().expect("活性锁")) > UDT_IDLE {
            self.close(Some("连接超时（30s 无数据）".into()));
            return;
        }
        let mut resend: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut resend_fin = false;
        let abort = {
            let mut s = self.send.lock().expect("发送锁");
            let rto = s.rto;
            for (seq, inf) in s.inflight.iter_mut() {
                if now.duration_since(inf.last_send) >= rto {
                    inf.retries += 1;
                    inf.last_send = now;
                    if inf.retries > UDT_RETRIES_MAX {
                        break;
                    }
                    resend.push((*seq, inf.data.clone()));
                }
            }
            let too_lossy = s.inflight.values().any(|i| i.retries > UDT_RETRIES_MAX);
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
        for (seq, data) in resend {
            self.send_data(seq, &data);
        }
        if resend_fin {
            let total = self.send.lock().expect("发送锁").next_seq;
            self.send_fin(total);
        }
    }
}

impl std::fmt::Debug for UdtConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdtConn")
            .field("conn", &self.conn)
            .field("peer", &self.peer)
            .finish()
    }
}

/// 可靠流句柄（帧层读写对象；同一连接在本端仅一个实例）。
pub struct UdtStream {
    conn: Arc<UdtConn>,
    data_rx: UnboundedReceiver<Vec<u8>>,
    /// FIN_ACK 唤醒通道（waker 常驻注册在 Receiver 上；None 消息 = 关闭兜底放行）。
    fin_rx: UnboundedReceiver<()>,
    /// poll_write 的窗口许可等待（每次 poll 重建；就绪后置 None）。
    acquire: Option<
        Pin<Box<dyn std::future::Future<Output = tokio::sync::OwnedSemaphorePermit> + Send>>,
    >,
    /// poll_recv 取出但超出本次读缓冲的残余（读侧临时缓冲，下一次读先清它）。
    read_buf: Vec<u8>,
}

impl UdtStream {
    /// 等价 TCP 的 shutdown：发 FIN 并等 FIN_ACK（UDT_FIN_WAIT 兜底放行）。
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
        let deadline = this
            .conn
            .send
            .lock()
            .expect("发送锁")
            .fin_sent_at
            .map(|t| t + UDT_FIN_WAIT);
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

impl AsyncRead for UdtStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 先清残余（可能超出本次缓冲的部分留待下次），再从队列补包。
        loop {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                if n == 0 {
                    return Poll::Pending; // 0 长读缓冲：不消费数据
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
        // 窗口信号量：拿不到许可 = 在途满 → Pending（ACK 确认/close 兜底唤醒）。
        if self.acquire.is_none() {
            let sem = self.conn.window.clone();
            self.acquire = Some(Box::pin(async move {
                sem.acquire_owned()
                    .await
                    .expect("窗口信号量永不 close（close 用 add_permits 唤醒等待者）")
            }));
        }
        let mut fut = self.acquire.take().expect("已插入");
        let permit = match fut.as_mut().poll(cx) {
            Poll::Ready(p) => p,
            Poll::Pending => {
                self.acquire = Some(fut);
                return Poll::Pending;
            }
        };
        permit.forget(); // 配额由 ACK 归还（add_permits）；close 兜底全量归还
        let data = buf[..buf.len().min(pw::UDT_PAYLOAD_MAX)].to_vec();
        let seq;
        {
            let mut s = self.conn.send.lock().expect("发送锁");
            seq = s.next_seq;
            s.next_seq += 1;
            let now = Instant::now();
            s.inflight.insert(
                seq,
                InFlight {
                    data: data.clone(),
                    first_send: now,
                    last_send: now,
                    retries: 0,
                },
            );
        }
        self.conn.send_data(seq, &data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(())) // 出包即时编码投递，无应用层缓冲
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.do_shutdown(cx)
    }
}

impl Drop for UdtStream {
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
type BuiltConn = (
    Arc<UdtConn>,
    UdtStream,
    UnboundedSender<Pkt>,
    UnboundedReceiver<(SocketAddr, Vec<u8>)>,
    tokio::task::JoinHandle<()>,
);

/// 连接装配：状态机 + 流句柄 + 驱动任务（就地起）。
fn build_conn(conn: u32, peer: SocketAddr) -> BuiltConn {
    let (out_tx, out_rx) = unbounded_channel::<(SocketAddr, Vec<u8>)>();
    let (data_tx, data_rx) = unbounded_channel::<Vec<u8>>();
    let (in_tx, in_rx) = unbounded_channel::<Pkt>();
    let (fin_tx, fin_rx) = unbounded_channel::<()>();
    let (err_tx, err_rx) = watch::channel(None);
    let internal = Arc::new(UdtConn {
        conn,
        peer,
        send: Mutex::new(SendSide::new()),
        recv: Mutex::new(RecvSide::new()),
        window: Arc::new(Semaphore::new(UDT_WINDOW)),
        out_tx: Mutex::new(Some(out_tx)),
        data_tx: Mutex::new(Some(data_tx)),
        fin_flag: AtomicBool::new(false),
        fin_tx: Mutex::new(Some(fin_tx)),
        err_tx,
        err_rx,
        last_rx: Mutex::new(Instant::now()),
        closed: AtomicBool::new(false),
    });
    let stream = UdtStream {
        conn: internal.clone(),
        data_rx,
        fin_rx,
        acquire: None,
        read_buf: Vec::new(),
    };
    let driver = tokio::spawn(run_driver(internal.clone(), in_rx));
    (internal, stream, in_tx, out_rx, driver)
}

/// 驱动任务：入包处理 + 节拍扫描；连接关闭或入口关闭后退出并做连接级收尾。
async fn run_driver(conn: Arc<UdtConn>, mut in_rx: UnboundedReceiver<Pkt>) {
    let mut ticker = tokio::time::interval(UDT_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if conn.closed.load(Ordering::SeqCst) {
            break;
        }
        tokio::select! {
            pkt = in_rx.recv() => match pkt {
                Some((kind, seq, payload)) => {
                    conn.handle_packet(kind, seq, &payload);
                    // 协作让出（传输饥饿防线）：入包有积压时 recv 恒 Ready，
                    // 不让出会饿死对端泵/写端（current-thread runtime 上必现）。
                    tokio::task::yield_now().await;
                }
                None => break, // 入口关闭（泵/服务端摘表）
            },
            _ = ticker.tick() => conn.scan(),
        }
    }
    conn.close(None);
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

/// 建立到 `addr` 的 UDT 连接（HS 握手 + 定时重发；30s 超时）。
/// `src_port`：可选本地端口绑定（与 TCP/QUIC `--srcport` 同口径）。
pub async fn connect_udt(addr: SocketAddr, src_port: Option<u16>) -> Result<UdtStream> {
    let socket = UdpSocket::bind(local_bind_addr(addr, src_port))
        .await
        .map_err(Error::Io)?;
    let conn_id = random_u32();
    let nonce = random_bytes(16);
    let hs = pw::encode(pw::U_P_HS, conn_id, 0, &nonce).map_err(proto)?;
    let deadline = Instant::now() + UDT_HS_TIMEOUT;
    let mut buf = vec![0u8; pw::UDT_DATAGRAM_MAX + 64];
    loop {
        if Instant::now() >= deadline {
            return Err(proto("UDT 握手超时（30s）"));
        }
        let _ = socket.send_to(&hs, addr).await;
        let remain = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remain.min(UDT_HS_RESEND), socket.recv_from(&mut buf)).await {
            Err(_) => continue, // 重发窗口到点 → 再发 HS
            Ok(Err(e)) => return Err(Error::Io(e)),
            Ok(Ok((n, src))) => {
                if src != addr {
                    continue; // 非对端来源，忽略
                }
                match pw::decode(&buf[..n]) {
                    Some((h, payload)) if h.conn == conn_id => match h.kind {
                        pw::U_P_HS_ACK if payload == nonce => break,
                        pw::U_P_RST => {
                            let reason = String::from_utf8_lossy(payload);
                            return Err(proto(if reason.is_empty() {
                                "UDT 连接被对端拒绝".into()
                            } else {
                                format!("UDT 连接被对端拒绝: {reason}")
                            }));
                        }
                        _ => continue,
                    },
                    _ => continue, // 坏包/版本不符/其他连接 → 忽略
                }
            }
        }
    }
    let (internal, stream, in_tx, mut out_rx, driver) = build_conn(conn_id, addr);
    // socket 共享（tokio UdpSocket 无 Clone——Arc 承载；方法均取 &self）。
    let socket = Arc::new(socket);
    // socket 泵：入包 → 驱动（连接关闭即退）。
    let pump_conn = internal.clone();
    let pump_sock = socket.clone();
    let pump_in = in_tx;
    tokio::spawn(async move {
        let mut b = vec![0u8; pw::UDT_DATAGRAM_MAX + 64];
        loop {
            if pump_conn.closed.load(Ordering::SeqCst) {
                break;
            }
            tokio::select! {
                r = pump_sock.recv_from(&mut b) => match r {
                    Ok((n, src)) => {
                        if src == pump_conn.peer {
                            if let Some((h, payload)) = pw::decode(&b[..n]) {
                                if h.conn == pump_conn.conn {
                                    let _ = pump_in.send((h.kind, h.seq, payload.to_vec()));
                                }
                            }
                        }
                        // 协作让出（传输饥饿防线，与 demux/driver 同口径）。
                        tokio::task::yield_now().await;
                    }
                    Err(_) => break,
                },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
        }
    });
    // 出包任务：驱动编码包 → socket。
    let send_sock = socket;
    tokio::spawn(async move {
        while let Some((dst, pkt)) = out_rx.recv().await {
            if send_sock.send_to(&pkt, dst).await.is_err() {
                break;
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
}

fn rst_pkt(conn: u32, reason: &str) -> Option<Vec<u8>> {
    pw::encode(pw::U_P_RST, conn, 0, reason.as_bytes()).ok()
}

/// 监听并服务 UDT 连接（socket2 收缓冲 4MB，对齐 `serve_udp` 口径）。
pub async fn serve_udt(
    addr: SocketAddr,
    opts: crate::transfer::receiver::RecvOptions,
) -> Result<()> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, None).map_err(Error::Io)?;
    sock.set_nonblocking(true).map_err(Error::Io)?;
    sock.bind(&addr.into()).map_err(Error::Io)?;
    if let Err(e) = sock.set_recv_buffer_size(4 * 1024 * 1024) {
        eprintln!("[警告] UDT 收缓冲设置失败: {e}");
    }
    let std_sock: std::net::UdpSocket = sock.into();
    let socket = UdpSocket::from_std(std_sock).map_err(Error::Io)?;
    serve_udt_on(socket, opts).await
}

/// 在既有 UDP socket 上服务 UDT 连接（GUI 复用 `bind_udp` 的逐地址绑定/失败上报）。
pub async fn serve_udt_on(
    socket: UdpSocket,
    opts: crate::transfer::receiver::RecvOptions,
) -> Result<()> {
    use crate::transfer::receiver::{cleanup_part_orphans, gate_check, handle_conn, ip_allowed};
    // 孤儿半成品清扫（与 TCP/QUIC/UDP 同策略 7 天）。
    cleanup_part_orphans(&opts.save_dir);
    crate::transfer::resume::cleanup_resume_orphans(&opts.save_dir);

    let served = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (out_tx, mut out_rx) = unbounded_channel::<(SocketAddr, Vec<u8>)>();
    // 出包任务：所有连接的编码包统一经此 socket 发出（Arc 共享，方法均取 &self）。
    let socket = Arc::new(socket);
    let send_sock = socket.clone();
    tokio::spawn(async move {
        while let Some((dst, pkt)) = out_rx.recv().await {
            if send_sock.send_to(&pkt, dst).await.is_err() {
                break;
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
    let mut buf = vec![0u8; pw::UDT_DATAGRAM_MAX + 64];
    loop {
        // 收割已结束的连接监督任务（摘表已在任务内完成）。
        while finished.try_join_next().is_some() {}
        // 协作让出（传输饥饿防线）：recv_from 在有积压时同步返回 Ready，
        // 循环不 await 会让 current-thread runtime 上的泵/驱动/写端全部饿死。
        tokio::task::yield_now().await;
        let (n, src) = tokio::select! {
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
        let Some((h, payload)) = pw::decode(&buf[..n]) else {
            continue;
        };
        let opts = opts.clone();
        if h.kind == pw::U_P_HS {
            // 版本校验已由 pw::decode 承担（ver 不符整包忽略）；HS 载荷 = 16B nonce。
            if payload.len() != 16 {
                continue;
            }
            // IP 过滤先于握手（对齐 quic.rs：被拒源不进任何状态机）。
            if !ip_allowed(src.ip(), opts.ip_filter_mode, &opts.ip_filter_list) {
                if let Some(rst) = rst_pkt(h.conn, "被 IP 过滤规则拒绝") {
                    let _ = socket.send_to(&rst, src).await;
                }
                continue;
            }
            // 锁定门（配对失败次数过多）。
            if gate_check(src, &opts).await.is_err() {
                if let Some(rst) = rst_pkt(h.conn, "配对失败次数过多，已临时锁定") {
                    let _ = socket.send_to(&rst, src).await;
                }
                continue;
            }
            // 限量模式（--count）：串行——等现有连接结束再接受新 HS；收满即停。
            if let Some(max) = opts.max_count {
                loop {
                    let empty = conns.lock().expect("连接表锁").is_empty();
                    if empty {
                        break;
                    }
                    // 轮询兜底防 missed-notify 死锁（串行模式专属，100ms 粒度足够）。
                    let _ =
                        tokio::time::timeout(Duration::from_millis(100), ended.notified()).await;
                }
                if served.load(Ordering::Relaxed) >= max {
                    return Ok(());
                }
            }
            // 重复 HS 判别与表容量检查（短锁域；await 一律在锁外——future 须 Send，
            // 且不得让数据面路由阻塞在握手锁上）。
            enum HsRoute {
                Dup,
                Ignore,
                CapFull,
                Proceed,
            }
            let route = {
                let t = conns.lock().expect("连接表锁");
                match t.get(&h.conn) {
                    Some(e) if e.peer == src => HsRoute::Dup,
                    Some(_) => HsRoute::Ignore, // conn 冲突（他端占用）→ 忽略
                    None if t.len() >= UDT_CONN_CAP => HsRoute::CapFull,
                    None => HsRoute::Proceed,
                }
            };
            match route {
                HsRoute::Dup => {
                    // 重复 HS（客户端重发）→ 幂等重发 HS_ACK。
                    if let Ok(ack) = pw::encode(pw::U_P_HS_ACK, h.conn, 0, payload) {
                        let _ = socket.send_to(&ack, src).await;
                    }
                    continue;
                }
                HsRoute::Ignore => continue,
                HsRoute::CapFull => {
                    if let Some(rst) = rst_pkt(h.conn, "连接数已达上限") {
                        let _ = socket.send_to(&rst, src).await;
                    }
                    continue;
                }
                HsRoute::Proceed => {}
            }
            // 并发闸不在此获取：复用 `handle_conn`（TCP 入口）——0x09 加密分支与
            // conn_precheck（IP 过滤 + 30s 闸上限）都在其内，与 TCP 语义完全一致
            // （QUIC 入口跳过 0x09——其机密性由 TLS 承担，UDT 无 TLS 不得复用）。
            // 建连接并登记（短锁域，无 await）。
            let (internal, stream, in_tx, out_rx, driver) = build_conn(h.conn, src);
            let _ = internal; // Arc 由 stream/驱动持有
            {
                let mut t = conns.lock().expect("连接表锁");
                t.insert(h.conn, ConnEntry { peer: src, in_tx });
            }
            // HS_ACK（回显 nonce）。
            if let Ok(ack) = pw::encode(pw::U_P_HS_ACK, h.conn, 0, payload) {
                let _ = socket.send_to(&ack, src).await;
            }
            // 连接出包 → 共享 socket 发送通道。
            let out_fwd = out_tx.clone();
            tokio::spawn(async move {
                let mut rx = out_rx;
                while let Some((dst, pkt)) = rx.recv().await {
                    let _ = out_fwd.send((dst, pkt));
                    // 协作让出（传输饥饿防线）。
                    tokio::task::yield_now().await;
                }
            });
            let o2 = opts.clone();
            let served2 = served.clone();
            let conns2 = conns.clone();
            let ended2 = ended.clone();
            let stop2 = stop_tx.clone();
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
            continue;
        }
        // 数据面：按 conn_id 路由（peer 校验防串线；死连接残包/伪造 → 丢弃）。
        let t = conns.lock().expect("连接表锁");
        if let Some(e) = t.get(&h.conn) {
            if e.peer == src {
                let _ = e.in_tx.send((h.kind, h.seq, payload.to_vec()));
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
    async fn pair(lossy: bool) -> (UdtStream, UdtStream) {
        let peer_c: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let peer_s: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let (c_conn, cs, c_in, mut c_out, c_drv) = build_conn(1, peer_s);
        let (s_conn, ss, s_in, mut s_out, s_drv) = build_conn(1, peer_c);
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
        let (_conn, mut stream, in_tx, _out, _drv) = build_conn(7, peer);
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
}
