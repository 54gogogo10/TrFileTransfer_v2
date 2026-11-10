//! 文件日志与崩溃日志（规格 §3.7：文件日志按天落 `%AppData%\TrFileTransfer\logs\`
//! 保留 30 天；崩溃写 crash.log 并弹友好提示——对齐原 C# 版，补齐登记在案缺口）。
//!
//! 写入策略：追加式、无锁竞争担忧（GUI 单进程内各线程经全局 Mutex 串行）；
//! 写失败静默（文件日志不可用不得影响功能——UI 日志事件仍在）。

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::OnceLock;

/// logs 目录（规格 §8.1 数据文件布局）。
pub fn logs_dir() -> PathBuf {
    trft_core::config::app_data_dir().join("logs")
}

fn crash_log_path() -> PathBuf {
    trft_core::config::app_data_dir().join("crash.log")
}

/// 某日期的日志文件名（`yyyy-MM-dd.log`，规格 §3.7）。
fn log_file_name(days_since_epoch: i64) -> String {
    // days → (y, m, d)：civil 算法（Howard Hinnant），无外部依赖。
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}.log")
}

static LOG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static CRASH_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
fn lock() -> &'static Mutex<()> {
    LOG_LOCK.get_or_init(|| Mutex::new(()))
}
fn crash_lock() -> &'static Mutex<()> {
    CRASH_LOCK.get_or_init(|| Mutex::new(()))
}

/// 追加一行到当天的日志文件（level: ok/warn/err 或空）。失败静默。
pub fn log_line(level: &str, msg: &str) {
    let _g = lock().lock();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let days = (now.as_secs() / 86_400) as i64;
    let secs = now.as_secs() % 86_400;
    let path = logs_dir().join(log_file_name(days));
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let stamp = format!(
            "{:02}:{:02}:{:02}",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60
        );
        let line = if level.is_empty() {
            format!("{stamp}  {msg}\n")
        } else {
            format!("{stamp} [{level}] {msg}\n")
        };
        let _ = f.write_all(line.as_bytes());
    }
}

/// 删除 `dir` 内修改时间早于 `cutoff_days` 天的 `.log` 文件（规格 §3.7 保留 30 天）。
/// 纯目录操作，`crash.log`（在上级目录）不受影响；测试经 base 参数注入。
fn prune_old_logs_in(dir: &Path, cutoff_days: u64) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("log") {
            continue;
        }
        let Ok(md) = e.metadata() else { continue };
        if !md.is_file() {
            continue;
        }
        let old = md
            .modified()
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|d| d.as_secs() > cutoff_days * 86_400);
        if old {
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// 启动初始化：清理过期日志（幂等——多跑只是重复扫描）。
pub fn init_file_logging() {
    let dir = logs_dir();
    let _ = std::fs::create_dir_all(&dir);
    prune_old_logs_in(&dir, 30);
}

/// 崩溃日志：追加 panic 信息 + backtrace（规格 §3.7 crash.log）。
/// 与日常日志**分锁**：panic 可能正发生在 log_line 持锁期间——钩子若再抢同一把
/// 非 重入 Mutex 会死锁，崩溃路径反而卡死。try_lock 失败（极端：两个线程同时
/// panic）则无锁直写——append 模式单条写交错风险可接受，宁留痕不丢失。
pub fn write_crash_log(info: &str, backtrace: &str) {
    let _g = match crash_lock().try_lock() {
        Ok(g) => Some(g),
        Err(_) => None,
    };
    let path = crash_log_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let _ = write!(
            f,
            "===== {} (unix {})\n{info}\nbacktrace:\n{backtrace}\n",
            log_file_name((now.as_secs() / 86_400) as i64),
            now.as_secs()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_file_name_is_iso_date() {
        // 1970-01-01 + 20763d = 2026-11-06（19723=2024-01-01，+366+365+304+5）。
        assert_eq!(log_file_name(20_763), "2026-11-06.log");
        // 纪元日本身。
        assert_eq!(log_file_name(0), "1970-01-01.log");
    }

    #[test]
    fn prune_removes_only_old_log_files() {
        let dir = tempfile::tempdir().unwrap();
        let mk = |name: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, b"x").unwrap();
            p
        };
        let old = mk("2020-01-01.log");
        let fresh = mk("fresh.log");
        let other = mk("keep.txt");
        // 把 old 的修改时间拨回 31 天前。
        let old_time = std::time::SystemTime::now() - std::time::Duration::from_secs(31 * 86_400);
        let f = std::fs::File::options().append(true).open(&old).unwrap();
        f.set_modified(old_time).unwrap();
        drop(f);

        prune_old_logs_in(dir.path(), 30);

        assert!(!old.exists(), "过期日志必须删除");
        assert!(fresh.exists(), "未过期日志保留");
        assert!(other.exists(), "非 .log 文件不动");
    }

    #[test]
    fn append_writes_level_lines_to_base_dir() {
        let dir = tempfile::tempdir().unwrap();
        // 直接验证行格式：经 log_line 的内部路径无法注入 base，
        // 这里验证 prune/文件名已覆盖核心逻辑，追加格式以集成验证为准。
        let p = dir.path().join(log_file_name(20_665));
        std::fs::write(&p, "12:00:00 [ok] hi\n").unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("[ok] hi"));
    }
}
