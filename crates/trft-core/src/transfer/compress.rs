//! 0x08/0x18 分段 deflate 压缩装饰器（规格 §4.1：装饰器顺序 encrypt(compress(plain))，
//! 压缩在内层、加密在外层；仅认证后协商）。
//!
//! 段格式（docs/WIRE-PROTOCOL.md §4）：`u32 rawLen + u32 wireLen + u8 mode + payload`。
//! - mode 0：原样零膨胀直传；mode 1：deflate（解压必须恰好产出 rawLen 字节）。
//! - 写前采样 ≤64KB，压后 ≤30% 才压整段（规格 §6.2）；段长 <64B 一律直传（最小压缩段）。
//! - 读侧防线：rawLen > 64MiB 拒绝；解压输出以 rawLen 为硬上限（炸弹守卫）。

use std::io::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 压缩段明文上限（规格 §6.1：压缩段长上限 64 MB）。
pub const MAX_SEGMENT: usize = 64 * 1024 * 1024;
/// 最小压缩段：低于此长度直传（规格 §6.1）。
pub const MIN_SEGMENT: usize = 64;
/// 采样窗口（规格 §6.2：≤64KB 试压）。
pub const SAMPLE_LEN: usize = 64 * 1024;
/// 采样压比阈值：压后 ≤30% 才压整段（规格 §6.2，依据内部实测保守取值）。
pub const SAMPLE_RATIO_NUM: usize = 30;
const SAMPLE_RATIO_DEN: usize = 100;

const MODE_RAW: u8 = 0;
const MODE_DEFLATE: u8 = 1;

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// 一次性 deflate（fast 级，规格 §6.2）。
pub(crate) fn deflate(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut enc = flate2::write::DeflateEncoder::new(
        Vec::with_capacity(input.len() / 2),
        flate2::Compression::fast(),
    );
    enc.write_all(input)?;
    enc.finish()
}

/// 一次性 inflate，硬上限 `limit` 字节：超出即判炸弹/损坏（不按需扩容）。
/// 用 `Take(limit+1)` 读取：多出 1 字节即可区分「恰好 limit」与「超限」。
pub(crate) fn inflate(input: &[u8], limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut decoder = flate2::read::DeflateDecoder::new(input);
    let mut out = Vec::new();
    (&mut decoder)
        .take(limit as u64 + 1)
        .read_to_end(&mut out)?;
    if out.len() > limit {
        return Err(std::io::Error::other("解压超出声明长度（疑似压缩炸弹）"));
    }
    // 流必须干净结束：正常结尾返回 EOF；截断/超限在上方已分别报错。
    let mut probe = [0u8; 1];
    match decoder.read(&mut probe) {
        Ok(0) => Ok(out),
        Ok(_) => Err(std::io::Error::other("解压超出声明长度（疑似压缩炸弹）")),
        Err(e) => Err(e),
    }
}

/// 压缩装饰器：读 = 拉取一段并解压；写 = 每次调用封一段（采样决定 mode）。
pub struct Compressed<S> {
    inner: S,
    /// 已解压待消费明文。
    plain: Vec<u8>,
    plain_pos: usize,
    /// 半读状态：段头（4B rawLen + 4B wireLen + 1B mode）、段体缓冲与进度（跨 poll 持久化）。
    header: [u8; 9],
    header_pos: usize,
    body: Vec<u8>,
    /// 当前段剩余载荷字节数（轮 4 P2 增量读）。
    wire_left: u64,
    body_pos: usize,
    /// 半写状态：(线上帧 = 4B rawLen + 1B mode + payload, 已写字节)。
    pending: Option<(Vec<u8>, usize)>,
    /// 跨 poll 的剩余输入（大 buffer 多段写出）。
    pending_in: Option<Vec<u8>>,
}

impl<S> Compressed<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            plain: Vec::new(),
            plain_pos: 0,
            header: [0; 9],
            header_pos: 0,
            body: Vec::new(),
            body_pos: 0,
            wire_left: 0,
            pending: None,
            pending_in: None,
        }
    }

    /// 决定一段的线上形态（采样策略，规格 §6.2）。
    fn build_frame(input: &[u8]) -> std::io::Result<Vec<u8>> {
        let raw_len = input.len();
        let mode = if raw_len < MIN_SEGMENT {
            MODE_RAW
        } else {
            let sample_len = raw_len.min(SAMPLE_LEN);
            let sample = deflate(&input[..sample_len])?;
            if sample.len() * SAMPLE_RATIO_DEN <= sample_len * SAMPLE_RATIO_NUM {
                MODE_DEFLATE
            } else {
                MODE_RAW
            }
        };
        let payload = if mode == MODE_DEFLATE {
            deflate(input)?
        } else {
            input.to_vec()
        };
        let mut frame = Vec::with_capacity(9 + payload.len());
        frame.extend_from_slice(&(raw_len as u32).to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.push(mode);
        frame.extend_from_slice(&payload);
        Ok(frame)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Compressed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1) 有已解压明文：直接供给。
            if this.plain_pos < this.plain.len() {
                let n = out.remaining().min(this.plain.len() - this.plain_pos);
                out.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            // 2) 段头（9B）：跨 poll 补齐。
            while this.header_pos < 9 {
                let mut rb = ReadBuf::new(&mut this.header[this.header_pos..]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            if this.header_pos == 0 && this.body.is_empty() {
                                return Poll::Ready(Ok(())); // 干净 EOF（信封边界）
                            }
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "压缩段头被截断",
                            )));
                        }
                        this.header_pos += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            // 3) 段体：跨 poll 补齐。
            if this.body.is_empty() {
                let raw_len =
                    u32::from_le_bytes(this.header[..4].try_into().expect("4 字节长度头")) as usize;
                let wire_len =
                    u32::from_le_bytes(this.header[4..8].try_into().expect("4 字节载荷长度头"))
                        as usize;
                if raw_len > MAX_SEGMENT || wire_len > MAX_SEGMENT {
                    return Poll::Ready(Err(io_err(format!(
                        "压缩段长度超限（raw={raw_len}, wire={wire_len}）"
                    ))));
                }
                // 增量缓冲（轮 4 P2）：此前声明即全额预分配——9 字节段头
                // 悬持 64MB×并发（慢速读取至超时）。64KB 起步随读增长。
                this.body = Vec::with_capacity(wire_len.min(64 * 1024).max(1));
                this.wire_left = wire_len as u64;
                this.body_pos = 0;
            }
            // 增量读段载荷（读到 wire_len 为止）。
            while this.wire_left > 0 {
                let want = std::cmp::min(this.wire_left, 64 * 1024) as usize;
                let mut chunk = vec![0u8; want];
                let mut rb = ReadBuf::new(&mut chunk);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "压缩段被截断",
                            )));
                        }
                        this.body.extend_from_slice(&rb.filled()[..n]);
                        this.wire_left -= n as u64;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            // 4) 解压：mode 校验 + 硬上限 + 精确性校验。
            let mode = this.header[8];
            let raw_len = u32::from_le_bytes(this.header[..4].try_into().expect("4B")) as usize;
            let wire_len = u32::from_le_bytes(this.header[4..8].try_into().expect("4B")) as usize;
            let plain = match mode {
                MODE_RAW => {
                    if wire_len != raw_len {
                        return Poll::Ready(Err(io_err(format!(
                            "mode=0 段载荷 {wire_len} 与声明 {raw_len} 不一致"
                        ))));
                    }
                    std::mem::take(&mut this.body)
                }
                MODE_DEFLATE => inflate(&this.body, raw_len).map_err(io_err)?,
                _ => return Poll::Ready(Err(io_err("压缩数据无法识别"))),
            };
            if plain.len() != raw_len {
                return Poll::Ready(Err(io_err(format!(
                    "解压长度 {}/声明 {raw_len} 不一致",
                    plain.len()
                ))));
            }
            this.header_pos = 0;
            this.body = Vec::new();
            this.body_pos = 0;
            this.plain = plain;
            this.plain_pos = 0;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Compressed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() && this.pending.is_none() && this.pending_in.is_none() {
            return Poll::Ready(Ok(0));
        }
        // write_all 契约：Pending 后以同一 buf 重试——首次进入才收编输入。
        if this.pending_in.is_none() && this.pending.is_none() {
            this.pending_in = Some(buf.to_vec());
        }
        loop {
            // 1) 在途帧续写。
            if let Some((frame, pos)) = this.pending.as_mut() {
                while *pos < frame.len() {
                    match Pin::new(&mut this.inner).poll_write(cx, &frame[*pos..]) {
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::WriteZero,
                                "写压缩帧失败",
                            )));
                        }
                        Poll::Ready(Ok(n)) => *pos += n,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                this.pending = None;
            }
            // 2) 封新段（≤64MB，超出切多段）。
            match this.pending_in.as_mut() {
                Some(rest) if !rest.is_empty() => {
                    let take = rest.len().min(MAX_SEGMENT);
                    let seg: Vec<u8> = rest.drain(..take).collect();
                    let frame = Self::build_frame(&seg)?;
                    let mut pos = 0usize;
                    while pos < frame.len() {
                        match Pin::new(&mut this.inner).poll_write(cx, &frame[pos..]) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::WriteZero,
                                    "写压缩帧失败",
                                )));
                            }
                            Poll::Ready(Ok(n)) => pos += n,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => {
                                this.pending = Some((frame, pos));
                                return Poll::Pending;
                            }
                        }
                    }
                }
                _ => {
                    this.pending_in = None;
                    return Poll::Ready(Ok(buf.len()));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while let Some((frame, pos)) = this.pending.as_mut() {
            match Pin::new(&mut this.inner).poll_write(cx, &frame[*pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "写压缩帧失败",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    *pos += n;
                    if *pos == frame.len() {
                        this.pending = None;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while let Some((frame, pos)) = this.pending.as_mut() {
            match Pin::new(&mut this.inner).poll_write(cx, &frame[*pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "写压缩帧失败",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    *pos += n;
                    if *pos == frame.len() {
                        this.pending = None;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn compressible_roundtrip() {
        let mut data = Vec::new();
        for i in 0..200_000u32 {
            data.extend_from_slice(format!("line-{i}\n").as_bytes());
        }
        let mut enc = Compressed::new(std::io::Cursor::new(Vec::new()));
        enc.write_all(&data).await.unwrap();
        let bytes =
            std::mem::replace(&mut enc.inner, std::io::Cursor::new(Vec::new())).into_inner();
        // 可压缩内容必须真的被压（线上显著小于明文）。
        assert!(
            bytes.len() < data.len() / 2,
            "deflate 未生效: {} vs {}",
            bytes.len(),
            data.len()
        );
        let mut dec = Compressed::new(std::io::Cursor::new(bytes));
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn incompressible_goes_raw() {
        let mut data = vec![0u8; 300_000];
        OsRng.fill_bytes(&mut data);
        let mut enc = Compressed::new(std::io::Cursor::new(Vec::new()));
        enc.write_all(&data).await.unwrap();
        let bytes =
            std::mem::replace(&mut enc.inner, std::io::Cursor::new(Vec::new())).into_inner();
        // 零膨胀直传：线上 = 明文 + 每段 9B 头。
        assert_eq!(bytes.len(), data.len() + 9, "不可压缩数据必须零膨胀直传");
        let mut dec = Compressed::new(std::io::Cursor::new(bytes));
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn small_segment_goes_raw() {
        // < 64B 最小压缩段：即使可压缩也直传。
        let data = b"000000000000000000000000000000000000000000000000".to_vec(); // 48B 可压缩
        assert!(data.len() < MIN_SEGMENT);
        let mut enc = Compressed::new(std::io::Cursor::new(Vec::new()));
        enc.write_all(&data).await.unwrap();
        let bytes =
            std::mem::replace(&mut enc.inner, std::io::Cursor::new(Vec::new())).into_inner();
        assert_eq!(bytes.len(), data.len() + 9, "小段必须零膨胀直传（9B 段头）");
    }

    #[tokio::test]
    async fn large_write_spans_multiple_segments() {
        // 70MB 输入 → 2 段（64MB + 6MB）。内存受限环境跑不动 70MB×2 份拷贝，
        // 改用 1.5 段边界：64MiB+1024。
        let seg = 64 * 1024 * 1024;
        let mut data = vec![0u8; seg + 1024];
        OsRng.fill_bytes(&mut data);
        let mut enc = Compressed::new(std::io::Cursor::new(Vec::new()));
        enc.write_all(&data).await.unwrap();
        let bytes =
            std::mem::replace(&mut enc.inner, std::io::Cursor::new(Vec::new())).into_inner();
        // 两段全 raw：明文 + 2×9B 头。
        assert_eq!(bytes.len(), data.len() + 18);
        let mut dec = Compressed::new(std::io::Cursor::new(bytes));
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn compressed_bomb_rejected() {
        // 手工构造 mode=1 + 小 rawLen 声明 + 大 deflate 流 → 解压超出即错。
        let big = vec![7u8; 300_000];
        let deflated = deflate(&big).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&1000u32.to_le_bytes()); // 声明 1000B
        frame.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
        frame.push(MODE_DEFLATE);
        frame.extend_from_slice(&deflated);
        let mut dec = Compressed::new(std::io::Cursor::new(frame));
        let mut out = Vec::new();
        let r = dec.read_to_end(&mut out).await;
        assert!(r.is_err(), "压缩炸弹必须被硬上限拒绝");
    }

    #[tokio::test]
    async fn truncated_segment_errors() {
        let data = vec![1u8; 1000];
        let mut enc = Compressed::new(std::io::Cursor::new(Vec::new()));
        enc.write_all(&data).await.unwrap();
        let mut bytes =
            std::mem::replace(&mut enc.inner, std::io::Cursor::new(Vec::new())).into_inner();
        bytes.truncate(bytes.len() - 10);
        let mut dec = Compressed::new(std::io::Cursor::new(bytes));
        let mut out = Vec::new();
        assert!(
            dec.read_to_end(&mut out).await.is_err(),
            "截断段必须报错而非静默短读"
        );
    }
}
