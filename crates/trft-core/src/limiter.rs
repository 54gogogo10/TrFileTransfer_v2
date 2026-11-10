//! 令牌桶限速（规格 §3.1：发送/接收限速 KB/s，0=不限；所有分块含最后一块都必须过限速）。

use std::time::{Duration, Instant};
use tokio::time::sleep;

pub struct TokenBucket {
    rate_bps: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// bytes_per_sec = 0 表示不限速。
    pub fn new(bytes_per_sec: u64) -> Self {
        let rate = bytes_per_sec as f64;
        Self {
            rate_bps: rate,
            capacity: rate.max(1.0),
            tokens: rate.max(1.0),
            last: Instant::now(),
        }
    }

    pub fn unlimited(&self) -> bool {
        self.rate_bps <= 0.0
    }

    /// 渐进授予：请求大于桶容量也能在限速约束下分次放行，绝不死等。
    pub async fn acquire(&mut self, mut n: u64) {
        if self.unlimited() || n == 0 {
            return;
        }
        while n > 0 {
            let now = Instant::now();
            let dt = now.duration_since(self.last).as_secs_f64();
            self.last = now;
            self.tokens = (self.tokens + dt * self.rate_bps).min(self.capacity);
            let grant = self.tokens.min(n as f64) as u64;
            if grant > 0 {
                self.tokens -= grant as f64;
                n -= grant;
            }
            if n > 0 {
                let wait = if self.tokens < 1.0 {
                    // 桶空：等出 1 字节的时间即可继续推进。
                    (1.0 / self.rate_bps).clamp(0.001, 0.25)
                } else {
                    ((n as f64 - self.tokens) / self.rate_bps).clamp(0.001, 0.25)
                };
                sleep(Duration::from_secs_f64(wait)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn limits_throughput() {
        // 1 MB/s 取 2 MB：桶初始满先放 1 MB，剩余约等 1 秒。
        let mut b = TokenBucket::new(1_000_000);
        let t0 = Instant::now();
        // timeout 包裹：潜在死锁以失败形式呈现，不挂 CI（审查轮7）。
        tokio::time::timeout(Duration::from_secs(10), b.acquire(2_000_000))
            .await
            .expect("限速器死锁");
        let el = t0.elapsed();
        assert!(el >= Duration::from_millis(800), "限速未生效: {el:?}");
        assert!(el < Duration::from_secs(6), "限速过慢: {el:?}");
    }

    #[tokio::test]
    async fn request_larger_than_capacity_terminates() {
        // 64 KB/s 取 4 MB（远超桶容量）：必须按速率渐进放行，约 64s？——
        // 不行，太久；改用 1 MB/s 取 4 MB ≈ 3 秒。
        let mut b = TokenBucket::new(1_000_000);
        let t0 = Instant::now();
        b.acquire(4_000_000).await;
        let el = t0.elapsed();
        assert!(
            el >= Duration::from_millis(2_800),
            "超容量请求未按速率放行: {el:?}"
        );
        assert!(el < Duration::from_secs(8), "超容量请求过慢: {el:?}");
    }

    #[tokio::test]
    async fn unlimited_is_instant() {
        let mut b = TokenBucket::new(0);
        let t0 = Instant::now();
        b.acquire(u64::MAX >> 1).await;
        assert!(t0.elapsed() < Duration::from_millis(100));
    }
}
