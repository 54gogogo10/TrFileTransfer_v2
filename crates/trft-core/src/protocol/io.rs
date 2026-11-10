//! 异步读写原语：多字节整数一律小端；
//! 控制帧读 30s 超时、载荷读 5min 超时（规格 §6.1：普通读超时 30 秒，长任务读窗口 5 分钟）。

use crate::error::{proto, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 普通读超时（帧头/控制字段）。
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// 长任务读窗口（大文件载荷，允许吞吐静默）。
pub const LONG_READ_TIMEOUT: Duration = Duration::from_secs(300);

async fn read_exact_t<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut [u8],
    dur: Duration,
) -> Result<()> {
    match tokio::time::timeout(dur, r.read_exact(buf)).await {
        Ok(res) => {
            res?;
            Ok(())
        }
        Err(_) => Err(proto(format!("读超时（{dur:?}）"))),
    }
}

pub async fn read_u8<R: AsyncRead + Unpin>(r: &mut R) -> Result<u8> {
    let mut b = [0u8; 1];
    read_exact_t(r, &mut b, READ_TIMEOUT).await?;
    Ok(b[0])
}

/// 长任务窗口的单字节读：服务端应答前可能做全文件哈希（0x03 skip 判定 /
/// 0x04 位图核对——冷缓存下静默可达数分钟，规格 §6.1 长任务读窗口）。
pub async fn read_u8_long<R: AsyncRead + Unpin>(r: &mut R) -> Result<u8> {
    let mut b = [0u8; 1];
    read_exact_t(r, &mut b, LONG_READ_TIMEOUT).await?;
    Ok(b[0])
}

pub async fn read_n<R: AsyncRead + Unpin>(r: &mut R, n: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    read_exact_t(r, &mut v, READ_TIMEOUT).await?;
    Ok(v)
}

/// 载荷读：允许更长的吞吐静默窗口。
pub async fn read_n_long<R: AsyncRead + Unpin>(r: &mut R, n: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; n];
    read_exact_t(r, &mut v, LONG_READ_TIMEOUT).await?;
    Ok(v)
}

pub async fn read_u16<R: AsyncRead + Unpin>(r: &mut R) -> Result<u16> {
    let v = read_n(r, 2).await?;
    Ok(u16::from_le_bytes([v[0], v[1]]))
}

pub async fn read_u32<R: AsyncRead + Unpin>(r: &mut R) -> Result<u32> {
    let v = read_n(r, 4).await?;
    Ok(u32::from_le_bytes(v.try_into().unwrap()))
}

pub async fn read_u64<R: AsyncRead + Unpin>(r: &mut R) -> Result<u64> {
    let v = read_n(r, 8).await?;
    Ok(u64::from_le_bytes(v.try_into().unwrap()))
}

/// 载荷块读入调用方缓冲（不分配新内存）。
pub async fn read_exact_long<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    read_exact_t(r, buf, LONG_READ_TIMEOUT).await
}

pub async fn write_u8<W: AsyncWrite + Unpin>(w: &mut W, v: u8) -> Result<()> {
    w.write_all(&[v]).await?;
    Ok(())
}

pub async fn write_all<W: AsyncWrite + Unpin>(w: &mut W, v: &[u8]) -> Result<()> {
    w.write_all(v).await?;
    Ok(())
}

pub async fn write_u16<W: AsyncWrite + Unpin>(w: &mut W, v: u16) -> Result<()> {
    w.write_all(&v.to_le_bytes()).await?;
    Ok(())
}

pub async fn write_u32<W: AsyncWrite + Unpin>(w: &mut W, v: u32) -> Result<()> {
    w.write_all(&v.to_le_bytes()).await?;
    Ok(())
}

pub async fn write_u64<W: AsyncWrite + Unpin>(w: &mut W, v: u64) -> Result<()> {
    w.write_all(&v.to_le_bytes()).await?;
    Ok(())
}

pub async fn write_str_u16<W: AsyncWrite + Unpin>(w: &mut W, s: &str) -> Result<()> {
    let b = s.as_bytes();
    // 静默截断会导致线框架失步，必须显式失败。
    if b.len() > u16::MAX as usize {
        return Err(crate::error::proto(format!(
            "字符串超长（{} 字节 > 65535）",
            b.len()
        )));
    }
    write_u16(w, b.len() as u16).await?;
    w.write_all(b).await?;
    Ok(())
}

pub async fn read_str_u16<R: AsyncRead + Unpin>(r: &mut R) -> Result<String> {
    let len = read_u16(r).await? as usize;
    let bytes = read_n(r, len).await?;
    String::from_utf8(bytes).map_err(|_| proto("字符串不是合法 UTF-8"))
}
