//! 追加式摘要缓存（规格 §3.1：键 = 路径+大小+mtime；FNV-1a 行校验坏行丢弃；
//! TTL 过期按未命中；**追加写 + 8MB 日志重写收敛 + 两代分代淘汰**；
//! 不可写时静默退化为内存缓存）。
//!
//! 行格式：`fnv1a_hex|hash_hex|size|mtime|path_fnv`——路径以 FNV 键存储，
//! 含 `|` 的路径不入缓存。装载时后行覆盖前行（追加日志天然去重）。

use crate::error::Result;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const DEFAULT_TTL_DAYS: u32 = 7;
/// 日志重写阈值（规格 §3.1/§6.1：8MB）。
pub const REWRITE_THRESHOLD: u64 = 8 * 1024 * 1024;
/// degraded（不可写→纯内存）模式的条目数防线（轮 5 P2-1）：可写路径经
/// 8MB 重写 + 两代淘汰收敛；degraded 下无日志可触发收敛，按条目数封顶
/// （≈ 可写路径两代窗口的量级，130B/条 → 上限 ≈ 26MB 内存）。
pub const DEGRADED_MAP_CAP: usize = 200_000;

/// FNV-1a 64 位行校验。
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Default)]
pub struct HashCache {
    map: HashMap<(u64, u64, u64), ([u8; 32], u32)>, // (path_fnv, size, mtime) → (hash, 代数)
    /// 追加句柄（懒开；写失败 → degraded=true 静默退化为内存缓存）。
    log_path: Option<PathBuf>,
    log: Option<std::fs::File>,
    log_size: u64,
    degraded: bool,
    gen: u32,
    rewrite_threshold: u64,
    appended: AtomicU64,
}

impl HashCache {
    /// 加载：坏行丢弃（fail-open，规格 §3.1「不可写时静默退化」同源语义）；
    /// TTL 过期条目按未命中处理（0 = 永不过期）。
    pub fn load(path: &Path, ttl_days: u32) -> Self {
        let mut map = HashMap::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            let now = now_secs();
            let ttl_secs = (ttl_days as u64).saturating_mul(24 * 3600);
            for line in text.lines() {
                let Some(first) = line.find('|') else {
                    continue;
                };
                let (sum_hex, rest) = line.split_at(first);
                let Ok(sum) = u64::from_str_radix(sum_hex, 16) else {
                    continue;
                };
                if sum != fnv1a(rest[1..].as_bytes()) {
                    continue; // 坏行丢弃（校验体不含首个分隔符）
                }
                let parts: Vec<&str> = rest[1..].splitn(4, '|').collect();
                if parts.len() != 4 {
                    continue;
                }
                let (Ok(h), Ok(size), Ok(mtime), Ok(pf)) = (
                    decode_hash(parts[0]),
                    parts[1].parse::<u64>(),
                    parts[2].parse::<u64>(),
                    u64::from_str_radix(parts[3], 16),
                ) else {
                    continue;
                };
                if ttl_secs > 0 && now.saturating_sub(mtime) > ttl_secs {
                    continue; // TTL 过期按未命中
                }
                map.insert((pf, size, mtime), (h, 0));
            }
        }
        let log_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        Self {
            map,
            log_path: Some(path.to_path_buf()),
            log: None,
            log_size,
            degraded: false,
            gen: 0,
            rewrite_threshold: REWRITE_THRESHOLD,
            appended: AtomicU64::new(0),
        }
    }

    /// 测试钩子：注入重写阈值（真实配置恒为 8MB）。
    #[cfg(test)]
    fn with_rewrite_threshold(mut self, bytes: u64) -> Self {
        self.rewrite_threshold = bytes;
        self
    }

    pub fn get(&self, path: &str, size: u64, mtime: u64) -> Option<[u8; 32]> {
        self.map
            .get(&(fnv1a(path.as_bytes()), size, mtime))
            .map(|(h, _)| *h)
    }

    /// 插入：内存立即生效；持久化走追加日志（FNV 行校验），写失败静默退化为内存缓存。
    /// 超过重写阈值（默认 8MB）时先收敛再追加；代数盖章在收敛之后（本条属于新一代）。
    /// degraded（不可写）模式下无日志可触发分代收敛（gen 恒不前进，两代淘汰
    /// 不可用）——按**条目数硬封顶**，满则整体清空重建（轮 5 P2-1：此前
    /// degraded 下 map 无界增长，PoC 实证 200 万条 +260MB 零收敛；判错方向 =
    /// 清空后多算一次哈希，与既有语义一致；清空每 CAP 次插入一次，摊还 O(1)）。
    pub fn insert(&mut self, path: &str, size: u64, mtime: u64, hash: [u8; 32]) {
        if path.contains('|') {
            return; // 格式冲突，放弃缓存该条目（判错方向：多算一次）
        }
        self.append_line(path, size, mtime, hash); // 可能触发重写（gen+1）
        if self.degraded && self.map.len() >= DEGRADED_MAP_CAP {
            self.map.clear();
        }
        self.map
            .insert((fnv1a(path.as_bytes()), size, mtime), (hash, self.gen));
    }

    fn append_line(&mut self, path: &str, size: u64, mtime: u64, hash: [u8; 32]) {
        if self.degraded || self.log_path.is_none() {
            return;
        }
        if self.log_size >= self.rewrite_threshold {
            if self.rewrite().is_err() {
                self.degraded = true;
                return;
            }
        }
        if self.log.is_none() {
            // 追加模式打开（无则创建）；目录不可写 → 永久退化（规格 §3.1）。
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.log_path.as_ref().unwrap())
            {
                Ok(f) => self.log = Some(f),
                Err(_) => {
                    self.degraded = true;
                    return;
                }
            }
        }
        let inner = format!(
            "{}|{size}|{mtime}|{:016x}",
            crate::hash::hex(&hash),
            fnv1a(path.as_bytes())
        );
        let line = format!("{:016x}|{inner}\n", fnv1a(inner.as_bytes()));
        let f = self.log.as_mut().unwrap();
        match f.write_all(line.as_bytes()).and_then(|_| f.flush()) {
            Ok(()) => {
                self.log_size += line.len() as u64;
                self.appended.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.degraded = true; // 静默退化：内存缓存继续工作
                self.log = None;
            }
        }
    }

    /// 全量重写收敛：代数 +1，淘汰两代未被复验的条目（分代淘汰），
    /// 原子换入新日志（.tmp → .bak → 主文件），日志尺寸归零重计。
    pub fn rewrite(&mut self) -> Result<()> {
        self.gen = self.gen.wrapping_add(1);
        let keep_from = self.gen.saturating_sub(2); // 保留当前与上一代
        self.map.retain(|_, (_, g)| *g >= keep_from);
        // 先关追加句柄再换入（Windows 上打开句柄会锁住 persist 目标）。
        self.log = None;
        if let Some(p) = self.log_path.clone() {
            self.save(&p)?;
        }
        self.log_size = 0; // 下次追加按新文件重开（append 模式定位到尾部）
        Ok(())
    }

    /// 兼容入口（= 立即重写收敛）：verify CLI 收尾落盘用。
    /// 先关追加句柄再换入——Windows 上打开句柄会锁住 persist 目标（与 rewrite 同纪律；
    /// 缺此步则 insert 过的缓存 save 恒失败，M4' 实测修复）。
    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.log = None;
        let mut out = String::with_capacity(self.map.len() * 96);
        for ((pf, size, mtime), (h, _)) in &self.map {
            let body = format!("{}|{size}|{mtime}|{:016x}", crate::hash::hex(h), pf);
            out.push_str(&format!("{:016x}|{body}\n", fnv1a(body.as_bytes())));
        }
        crate::config::atomic_write(path, out.as_bytes())
    }

    pub fn degraded(&self) -> bool {
        self.degraded
    }

    pub fn appended_count(&self) -> u64 {
        self.appended.load(Ordering::Relaxed)
    }
}

fn decode_hash(hex: &str) -> std::result::Result<[u8; 32], ()> {
    let mut out = [0u8; 32];
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(());
    }
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(out)
}

/// 目录级缓存文件名（内部元数据；文件夹收集/verify 均按此排除）。
pub const CACHE_FILE_NAME: &str = ".trft-hash-cache.txt";
/// 原子换入产生的 `.bak` 镜像（config::write_atomic 同族产物）——扫描/清单同样必须排除。
pub const CACHE_BAK_NAME: &str = ".trft-hash-cache.bak";

/// 缓存族文件判定（主文件 + .bak 镜像）。
pub fn is_cache_artifact(name: &str) -> bool {
    name == CACHE_FILE_NAME || name == CACHE_BAK_NAME
}

/// 便捷入口：确保目录级缓存文件名。
pub fn cache_file_for(dir: &Path) -> std::path::PathBuf {
    dir.join(CACHE_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry_line(path: &str, size: u64, mtime: u64, h: &[u8; 32]) -> String {
        let pf = fnv1a(path.as_bytes());
        let inner = format!("{}|{size}|{mtime}|{:016x}", crate::hash::hex(h), pf);
        format!("{:016x}|{inner}", fnv1a(inner.as_bytes()))
    }

    #[test]
    fn roundtrip_and_bad_line_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.txt");
        let h = crate::hash::sha256(b"data");
        let mut body = entry_line("a.bin", 10, 100, &h);
        body.push('\n');
        body.push_str("deadbeef|garbage line\n"); // 坏校验 → 丢弃
        body.push_str("not a line\n");
        std::fs::write(&p, &body).unwrap();

        let c = HashCache::load(&p, 0);
        assert_eq!(c.get("a.bin", 10, 100), Some(h));
        assert_eq!(c.get("a.bin", 10, 101), None);
    }

    #[test]
    fn ttl_expiry_misses() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.txt");
        let h = crate::hash::sha256(b"x");
        let old = now_secs() - 8 * 24 * 3600;
        std::fs::write(&p, entry_line("old.bin", 1, old, &h)).unwrap();
        assert_eq!(HashCache::load(&p, 7).get("old.bin", 1, old), None);
        assert_eq!(HashCache::load(&p, 0).get("old.bin", 1, old), Some(h));
    }

    #[test]
    fn tamper_detected_via_cache() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.txt");
        let h = crate::hash::sha256(b"original");
        let now = now_secs();
        std::fs::write(&p, entry_line("f.txt", 9, now, &h)).unwrap();
        let c = HashCache::load(&p, 7);
        let actual = crate::hash::sha256(b"tampered!");
        assert_ne!(
            actual,
            c.get("f.txt", 9, now).unwrap(),
            "篡改必须被比对发现"
        );
    }

    #[test]
    fn append_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.txt");
        let h = crate::hash::sha256(b"payload");
        let mut c = HashCache::load(&p, 0);
        c.insert("x/y.bin", 42, 777, h);
        assert_eq!(c.appended_count(), 1, "insert 必须走追加日志");
        // 重开进程：追加行即状态（无需显式 save）。
        let c2 = HashCache::load(&p, 0);
        assert_eq!(c2.get("x/y.bin", 42, 777), Some(h));
    }

    #[test]
    fn append_log_naturally_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.txt");
        let h1 = crate::hash::sha256(b"v1");
        let h2 = crate::hash::sha256(b"v2");
        let mut c = HashCache::load(&p, 0);
        c.insert("f", 5, 1, h1);
        c.insert("f", 5, 1, h2); // 同键更新：后行覆盖前行
        let c2 = HashCache::load(&p, 0);
        assert_eq!(c2.get("f", 5, 1), Some(h2));
    }

    #[test]
    fn rewrite_at_threshold_and_two_generation_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cache.txt");
        let ha = crate::hash::sha256(b"a");
        let hb = crate::hash::sha256(b"b");
        let mut c = HashCache::load(&p, 0).with_rewrite_threshold(64);
        c.insert("a", 1, 1, ha); // 第 0 代
        let size_before = std::fs::metadata(&p).unwrap().len();
        assert!(size_before >= 64, "阈值触发前日志已超限: {size_before}");
        c.insert("b", 2, 2, hb); // 触发重写：gen=1，两代窗口保留 a
        assert_eq!(c.get("a", 1, 1), Some(ha), "上一代条目必须保留");
        assert_eq!(c.get("b", 2, 2), Some(hb));
        // 再两次重写（不再触碰 a）→ a 被分代淘汰（两代未复验）。
        c.rewrite().unwrap(); // gen=2
        c.rewrite().unwrap(); // gen=3 → 保留 >= 1
        assert_eq!(c.get("a", 1, 1), None, "两代未复验的条目必须被分代淘汰");
        assert_eq!(c.get("b", 2, 2), Some(hb), "持续复验的条目必须保留");
        let len_after = std::fs::metadata(&p).unwrap().len();
        assert!(len_after < size_before + 128, "重写后日志必须收敛");
    }

    #[test]
    fn unwritable_dir_degrades_to_memory() {
        // 只读目录（Windows 上用不存在的父目录模拟不可写）→ 静默退化，内存仍可用。
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("no-such-subdir").join("cache.txt");
        let h = crate::hash::sha256(b"mem");
        let mut c = HashCache::load(&p, 0);
        c.insert("k", 1, 1, h);
        assert!(c.degraded(), "不可写必须标记退化");
        assert_eq!(c.get("k", 1, 1), Some(h), "内存缓存必须继续工作");
    }

    /// 轮 5 P2-1 判别：degraded（纯内存）模式下 map 必须**有界**——
    /// 修复前唯一收敛路径（8MB 日志重写）不可达，200 万条 PoC 实证 +260MB
    /// 零收敛；修复后条目数硬封顶（满则清空重建）。
    #[test]
    fn degraded_mode_map_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("no-such-subdir").join("cache.txt");
        let mut c = HashCache::load(&p, 0);
        c.insert("probe", 0, 0, [0u8; 32]);
        assert!(c.degraded(), "前提自检：该路径必须处于 degraded");
        // 灌 2× 上限条目——最早条目必须已被清空（修复前全部驻留，首条可查）。
        let cap = DEGRADED_MAP_CAP as u64;
        for i in 0..(cap * 2) {
            c.insert(&format!("f{i}"), i, i, [1u8; 32]);
        }
        assert_eq!(
            c.get("f0", 0, 0),
            None,
            "degraded 下达上限后最早的条目必须被清出（否则 map 无界）"
        );
        // 最后一次清空发生在临近末尾——最末条目必然在表内。
        let last = cap * 2 - 1;
        assert!(
            c.get(&format!("f{last}"), last, last).is_some(),
            "最近的条目应可用"
        );
    }
}
