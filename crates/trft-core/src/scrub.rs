//! 文件库校验引擎（规格 §3.5「scrub」）：逐文件重算 SHA-256 与摘要缓存比对。
//! CLI `verify --dir` 与 GUI「校验」共用同一实现（§3.6 复用同一逻辑层——行为必须一致）。
//!
//! 判别口径与 PRODUCT-SPEC §3.5 一致：
//! - 四类结论：一致（hit 且哈希相同）/ 不一致（hit 且哈希不同）/ 无记录（fresh）/ 无法读取；
//! - 无记录不算失败；发现不一致由调用方决定退出码（CLI = 1）；
//! - 缓存按自身规则作答（TTL 过期 → 无记录；strict 由调用方绕行——本引擎不读 strict）；
//! - 摘要缓存文件自身（`.trft-hash-cache.txt`）不入扫描。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::hashcache::HashCache;

/// 校验结论汇总（字段与 CLI 输出口径一一对应）。
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct VerifyReport {
    /// 扫描文件数（含无法读取）。
    pub scanned: u64,
    /// 扫描总字节。
    pub bytes: u64,
    /// 缓存命中并比对（含不一致）。
    pub hit: u64,
    /// 无缓存记录（已回填新摘要）。
    pub fresh: u64,
    /// 目录/文件无法读取数。
    pub unreadable: u64,
    /// 与缓存不一致的相对路径（'/' 分隔）。
    pub mismatches: Vec<String>,
}

impl VerifyReport {
    pub fn is_consistent(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// 目录递归深度上限（与 `cleanup_part_orphans` 的 6 不同：校验要覆盖深目录树，
/// 只作为**防环**兜底——配合"不进入链接目录"一起封死 junction 环导致的栈溢出）。
const MAX_SCAN_DEPTH: u32 = 32;

/// 收集待校验文件（先全量走一遍：GUI 进度条需要总数；不可读目录计一次 unreadable）。
/// 本轮 F8：此前用 `p.is_dir()`（跟随链接）且无深度上限——目录联接成环时
/// `collect` 无限递归直到栈溢出。现改为 `file_type()` 不跟随链接：真目录才递归，
/// 链接按"指向文件则校验、指向目录则跳过"处理。
fn collect(
    root: &Path,
    depth: u32,
    visited: &mut std::collections::HashSet<PathBuf>,
    out: &mut Vec<PathBuf>,
    unreadable: &mut u64,
) {
    if depth > MAX_SCAN_DEPTH {
        *unreadable += 1;
        return;
    }
    // 目录环（junction 回指祖先）第二道防线：按真实路径去重，已走过的目录不再进入。
    if let Ok(canon) = std::fs::canonicalize(root) {
        if !visited.insert(canon) {
            return;
        }
    }
    let Ok(rd) = std::fs::read_dir(root) else {
        *unreadable += 1;
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(ft) = e.file_type() else {
            *unreadable += 1;
            continue;
        };
        if ft.is_symlink() {
            // 链接不进入递归（目录联接环的唯一入口）；指向文件的链接仍需校验。
            match std::fs::metadata(&p) {
                Ok(m) if m.is_dir() => continue,
                Ok(_) => out.push(p),
                Err(_) => *unreadable += 1,
            }
            continue;
        }
        if ft.is_dir() {
            collect(&p, depth + 1, visited, out, unreadable);
        } else if !e
            .file_name()
            .to_str()
            .map(crate::hashcache::is_cache_artifact)
            .unwrap_or(false)
        {
            out.push(p);
        }
    }
}

/// 校验一个目录树。`stop` 置真即中途停止（返回已完成部分，spec §3.5 可中途停止）；
/// `progress(files_done, files_total)` 逐文件回调（GUI 进度条；CLI 传 None）。
/// 新摘要回填进 `cache`（调用方负责落盘）。
pub fn verify_dir(
    dir: &Path,
    cache: &mut HashCache,
    stop: Option<&AtomicBool>,
    mut progress: Option<&mut dyn FnMut(u64, u64)>,
) -> VerifyReport {
    let mut report = VerifyReport::default();
    let mut files = Vec::new();
    let mut visited = std::collections::HashSet::new();
    collect(dir, 0, &mut visited, &mut files, &mut report.unreadable);
    let total = files.len() as u64;

    // 排序保证确定性（目录枚举顺序不定）。
    files.sort();
    for (i, p) in files.iter().enumerate() {
        if let Some(flag) = stop {
            if flag.load(Ordering::Relaxed) {
                break;
            }
        }
        if let Some(cb) = progress.as_mut() {
            cb(i as u64, total);
        }
        let Ok(meta) = std::fs::metadata(p) else {
            report.unreadable += 1;
            continue;
        };
        let Ok(rel) = p.strip_prefix(dir) else {
            report.unreadable += 1;
            continue;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let size = meta.len();
        report.scanned += 1;
        report.bytes += size;
        match crate::hash::sha256_file(p) {
            Ok(actual) => match cache.get(&rel, size, mtime) {
                Some(expected) => {
                    report.hit += 1;
                    if actual != expected {
                        report.mismatches.push(rel);
                    }
                }
                None => {
                    report.fresh += 1;
                    cache.insert(&rel, size, mtime, actual);
                }
            },
            Err(_) => report.unreadable += 1,
        }
    }
    if let Some(cb) = progress.as_mut() {
        cb(total, total);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashcache::{cache_file_for, DEFAULT_TTL_DAYS};

    #[test]
    fn verify_detects_tamper_and_fresh_and_excludes_cache_file() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        std::fs::write(&a, b"alpha").unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let b = sub.join("b.bin");
        std::fs::write(&b, [1u8; 4096]).unwrap();

        let cache_path = cache_file_for(dir.path());
        let mut cache = HashCache::load(&cache_path, DEFAULT_TTL_DAYS);
        let r1 = verify_dir(dir.path(), &mut cache, None, None);
        assert_eq!(r1.scanned, 2, "缓存文件自身不入扫描");
        assert_eq!(r1.fresh, 2, "首扫全为新记录");
        assert!(r1.is_consistent());
        cache.save(&cache_path).unwrap();

        // 篡改后重扫：hit=2、1 条不一致。改写需同长度并恢复 mtime——
        // 缓存键含 (size, mtime)，任一变化按设计判「无记录」（定时刷新语义）。
        let orig_mtime = std::fs::metadata(&a).unwrap().modified().unwrap();
        std::fs::write(&a, b"alphb").unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&a).unwrap();
        f.set_modified(orig_mtime).unwrap();
        let mut cache2 = HashCache::load(&cache_path, DEFAULT_TTL_DAYS);
        let r2 = verify_dir(dir.path(), &mut cache2, None, None);
        assert_eq!(r2.hit, 2);
        assert_eq!(r2.fresh, 0);
        assert_eq!(r2.mismatches, vec!["a.txt".to_string()], "不一致必须点名");
    }

    /// 本轮 F8 判别：目录联接（junction）回指祖先时不得无限递归。
    /// 修复前 `p.is_dir()` 跟随链接 + 无深度上限 → 栈溢出（测试进程直接崩）。
    /// 环境不支持 junction（非 NTFS / 权限不足）时跳过，不误报。
    #[test]
    fn junction_cycle_does_not_recurse_forever() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        #[cfg(windows)]
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(sub.join("loop"))
            .arg(dir.path())
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        #[cfg(not(windows))]
        let made = false;
        if !made {
            return; // 环境不支持目录联接
        }
        let cache_path = cache_file_for(dir.path());
        let mut cache = HashCache::load(&cache_path, 0);
        let r = verify_dir(dir.path(), &mut cache, None, None);
        assert_eq!(r.scanned, 1, "联接环不得重复扫描（只应有 a.txt 一个文件）");
    }

    #[test]
    fn stop_flag_halts_midway() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10 {
            std::fs::write(dir.path().join(format!("f{i}.txt")), [i; 512]).unwrap();
        }
        let cache_path = cache_file_for(dir.path());
        let mut cache = HashCache::load(&cache_path, DEFAULT_TTL_DAYS);
        let stop = AtomicBool::new(true); // 直接置停：扫描应为 0（或极少）且不 panic
        let r = verify_dir(dir.path(), &mut cache, Some(&stop), None);
        assert_eq!(r.scanned, 0, "已停标志下不得继续扫描");
        assert!(r.is_consistent());
    }
}
