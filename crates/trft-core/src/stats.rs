//! 传输统计（规格 §3.3/§8.1）：stats.log 追加式落盘、>2MB 重写保留末 5000 行
//! （与摘要缓存同纪律）、今日/7 天/累计聚合 + 按设备明细、CSV 导出（UTF-8 BOM）。
//!
//! 记录点：core 完成/失败路径接线（TECH-STACK §7.10）——仅记**成功完成的传输**
//! （失败可见于运行日志/进度终态，不重复入账）；GUI 与 CLI 共享同一 stats.log。
//! 格式：`时间|S/R|IP|字节|文件数|秒|Detail|Path`；6 字段旧行照读（Detail/Path 补空）。

use std::io::Write;
use std::path::{Path, PathBuf};

/// 重写阈值与保留行数（规格 §8.1：>2MB 重写留 5000）。
pub const REWRITE_THRESHOLD: u64 = 2 * 1024 * 1024;
pub const REWRITE_KEEP: usize = 5000;

pub fn stats_path() -> PathBuf {
    crate::config::app_data_dir().join("stats.log")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Send,
    Recv,
}

impl Direction {
    fn tag(self) -> &'static str {
        match self {
            Direction::Send => "S",
            Direction::Recv => "R",
        }
    }
    fn from_tag(t: &str) -> Option<Self> {
        match t {
            "S" => Some(Direction::Send),
            "R" => Some(Direction::Recv),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StatRecord {
    /// Unix 秒。
    pub time: u64,
    pub dir: Direction,
    /// 对端（IP 或 IP:端口）。
    pub peer: String,
    pub bytes: u64,
    pub files: u32,
    pub secs: u64,
    /// 模式说明（用户可见文案，如 "续传传输" / "UDP×2轮"；不得写帧码）。
    pub detail: String,
    /// 文件/文件夹名（文本传输为 `<文本>`）。
    pub path: String,
}

/// 追加式统计日志（每条一开一写一关：跨进程/跨线程并发安全，统计永不阻断传输）。
#[derive(Debug, Clone)]
pub struct StatsLog {
    path: PathBuf,
}

impl StatsLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// 默认路径实例（`%AppData%\TrFileTransfer\stats.log`）。
    pub fn default_log() -> Self {
        Self::new(stats_path())
    }

    pub fn record(
        &self,
        dir: Direction,
        peer: &str,
        bytes: u64,
        files: u32,
        secs: u64,
        detail: &str,
        path: &str,
    ) {
        let time = crate::devices::now_secs();
        let line = format!(
            "{time}|{}|{peer}|{bytes}|{files}|{secs}|{}|{}\n",
            dir.tag(),
            detail.replace('|', " "),
            path.replace('|', " "),
        );
        let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        else {
            return; // 统计不可写 = 静默退化（不阻断传输）
        };
        let _ = f.write_all(line.as_bytes());
        drop(f);
        self.maybe_rewrite();
    }

    /// 阈值重写：>2MB 保留末 5000 行（原子换入；并发重写串行化无害，
    /// 最坏「丢一行并发期新增统计」——统计口径非账务，可接受，轮 3 P3 修正注释）。
    fn maybe_rewrite(&self) {
        let Ok(md) = std::fs::metadata(&self.path) else {
            return;
        };
        if md.len() <= REWRITE_THRESHOLD {
            return;
        }
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return;
        };
        let keep: Vec<&str> = text.lines().collect::<Vec<_>>();
        let start = keep.len().saturating_sub(REWRITE_KEEP);
        let mut out = String::new();
        for l in &keep[start..] {
            out.push_str(l);
            out.push('\n');
        }
        let _ = crate::config::atomic_write(&self.path, out.as_bytes());
    }

    /// 全量读取（坏行丢弃——与摘要缓存同口径）。
    pub fn load(&self) -> Vec<StatRecord> {
        parse_stats_file(&self.path)
    }
}

/// 行解析：现格式（Unix 秒）；**C# 旧 8 字段行照读**（时间列 = "yyyy-MM-dd HH:mm:ss"
/// 本地时间字符串、秒列可带小数）；6 字段旧行照读（Detail/Path 补空）。
/// 时间解析失败 → time=0（仅进累计桶，不进今日/7 天——判错方向是多读不是漏报）。
pub fn parse_line(line: &str) -> Option<StatRecord> {
    let parts: Vec<&str> = line.trim_end().split('|').collect();
    if parts.len() < 6 {
        return None;
    }
    let time = parse_time_col(parts[0]).unwrap_or(0);
    let dir = Direction::from_tag(parts[1])?;
    let peer = parts[2].to_string();
    let bytes = parts[3].parse().ok()?;
    let files = parts[4].parse().ok()?;
    // 秒列兼容小数（旧版 "0.0"）。
    let secs = parts[5]
        .parse::<u64>()
        .or_else(|_| parts[5].parse::<f64>().map(|f| f as u64))
        .ok()?;
    let (detail, path) = match parts.len() {
        6 => (String::new(), String::new()),
        _ => (normalize_detail(parts[6]), parts[7..].join("|")),
    };
    Some(StatRecord {
        time,
        dir,
        peer,
        bytes,
        files,
        secs,
        detail,
        path,
    })
}

/// 历史记录里的传输方式文案归一：
/// 旧版本把线协议帧码写进了 stats.log（"0x03 续传" 等），用户可见历史里不该出现。
/// 读入时统一映射成现在的说法，旧日志随下一次重写自然收敛（不改写用户文件）。
fn normalize_detail(detail: &str) -> String {
    let d = detail.trim();
    if d.is_empty() {
        return String::new();
    }
    let mapped = if d == "0x00" {
        "直接发送"
    } else if d.starts_with("0x00 skip") {
        "已存在（跳过）"
    } else if d.starts_with("0x00 空文件") {
        "空文件"
    } else if d.starts_with("0x01 文件夹") {
        "整夹发送"
    } else if d.starts_with("0x02 分块（补发）") {
        "分块传输（补发）"
    } else if let Some(rest) = d.strip_prefix("0x02 分块×") {
        return format!("分块传输×{rest}");
    } else if d.starts_with("0x02 分块") {
        "分块传输"
    } else if d.starts_with("0x03 skip") {
        "已存在（跳过）"
    } else if d.starts_with("0x03 续传") {
        "续传传输"
    } else if d.starts_with("0x03→0x00") {
        "续传不可用，改为直接发送"
    } else if d.starts_with("0x04 同步") {
        "文件夹同步"
    } else if d.starts_with("0x06 文本") {
        "文本消息"
    } else {
        return detail.to_string();
    };
    mapped.to_string()
}

/// 时间列：Unix 秒 或 C# 旧格式本地时间字符串（"yyyy-MM-dd HH:mm:ss"，手解析——
/// 不引 time 的 macros/parsing 特性，依赖保持最小）。
fn parse_time_col(s: &str) -> Option<u64> {
    if let Ok(v) = s.parse::<u64>() {
        return Some(v);
    }
    let mut it = s.split(|c| c == '-' || c == ' ' || c == ':');
    let (y, mo, d, h, mi, se) = (
        it.next()?.parse::<i32>().ok()?,
        it.next()?.parse::<u8>().ok()?,
        it.next()?.parse::<u8>().ok()?,
        it.next()?.parse::<u8>().ok()?,
        it.next()?.parse::<u8>().ok()?,
        it.next()?.parse::<u8>().ok()?,
    );
    if it.next().is_some() {
        return None;
    }
    let date = time::Date::from_calendar_date(y, time::Month::try_from(mo).ok()?, d).ok()?;
    let t = time::Time::from_hms(h, mi, se).ok()?;
    let dt = date.with_time(t);
    // 按本地偏移转 Unix；获取失败回退 UTC（仅影响旧行聚合桶划分）。
    let off = time::OffsetDateTime::now_local()
        .map(|n| n.offset())
        .unwrap_or(time::UtcOffset::UTC);
    Some(dt.assume_offset(off).unix_timestamp().max(0) as u64)
}

pub fn parse_stats_file(path: &Path) -> Vec<StatRecord> {
    std::fs::read_to_string(path)
        .map(|t| t.lines().filter_map(parse_line).collect())
        .unwrap_or_default()
}

// ============ 聚合（规格 §3.3：今日/7 天/累计 + 按设备明细） ============

#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct Aggregate {
    pub count: u64,
    pub bytes: u64,
    pub files: u64,
    pub secs: u64,
}

impl Aggregate {
    fn add(&mut self, r: &StatRecord) {
        self.count += 1;
        self.bytes += r.bytes;
        self.files += r.files as u64;
        self.secs += r.secs;
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct StatsSummary {
    pub today: Aggregate,
    pub week: Aggregate,
    pub total: Aggregate,
    /// 按对端明细（count 降序，前 50）。
    pub by_device: Vec<DeviceAgg>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceAgg {
    pub peer: String,
    #[serde(flatten)]
    pub agg: Aggregate,
}

/// 今日边界（本地时区 00:00；失败回退 UTC——仅影响统计桶划分）。
/// GUI/CLI 调 `summarize` 时注入。
pub fn today_start_unix() -> u64 {
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let midnight = now.date().midnight();
    midnight.assume_utc().unix_timestamp().max(0) as u64
}

/// 聚合快照。`now` 由调用方注入（可测）；`today_start` 同理可传 0 跳过今日桶。
pub fn summarize(records: &[StatRecord], now: u64, today_start: u64) -> StatsSummary {
    let week_from = now.saturating_sub(7 * 24 * 3600);
    let mut s = StatsSummary::default();
    let mut devs: std::collections::HashMap<String, Aggregate> = std::collections::HashMap::new();
    for r in records {
        s.total.add(r);
        if r.time >= today_start {
            s.today.add(r);
        }
        if r.time >= week_from {
            s.week.add(r);
        }
        devs.entry(r.peer.clone()).or_default().add(r);
    }
    let mut list: Vec<DeviceAgg> = devs
        .into_iter()
        .map(|(peer, agg)| DeviceAgg { peer, agg })
        .collect();
    list.sort_by(|a, b| b.agg.count.cmp(&a.agg.count).then(a.peer.cmp(&b.peer)));
    list.truncate(50);
    s.by_device = list;
    s
}

/// CSV 导出（UTF-8 BOM + 表头；RFC 4180 引号转义）。调用方写入文件。
pub fn export_csv(records: &[StatRecord]) -> String {
    /// RFC 4180 转义 + 公式注入防线（本轮 F4）：`path`/`detail` 含对端可控的
    /// 文件名，以 `= + - @`（及制表/回车）开头时 Excel/LibreOffice 会当公式求值
    /// ——前置单引号强制按文本解析（DDE/外链公式的经典入口）。
    fn esc(s: &str) -> String {
        let formula_trigger = matches!(s.chars().next(), Some('=' | '+' | '-' | '@' | '\t' | '\r'));
        let body = if formula_trigger {
            format!("'{s}")
        } else {
            s.to_string()
        };
        if body.contains(',') || body.contains('"') || body.contains('\n') || body.contains('\r') {
            format!("\"{}\"", body.replace('"', "\"\""))
        } else {
            body
        }
    }
    let mut out = String::from("\u{feff}时间,方向,IP,字节,文件数,秒,Detail,Path\n");
    for r in records {
        let d = match r.dir {
            Direction::Send => "S",
            Direction::Recv => "R",
        };
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            r.time,
            d,
            esc(&r.peer),
            r.bytes,
            r.files,
            r.secs,
            esc(&r.detail),
            esc(&r.path),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(time: u64, dir: Direction, peer: &str, bytes: u64) -> StatRecord {
        StatRecord {
            time,
            dir,
            peer: peer.into(),
            bytes,
            files: 1,
            secs: 1,
            detail: "直接发送".into(),
            path: "a.bin".into(),
        }
    }

    #[test]
    fn line_roundtrip_and_legacy_six_fields() {
        let r = rec(1700000000, Direction::Send, "192.168.1.5", 12345);
        // 旧格式行里的帧码在解析时归一成用户文案（见 normalize_detail）。
        let line = format!("{}|S|192.168.1.5|12345|1|1|0x00|a.bin", r.time);
        let p = parse_line(&line).unwrap();
        assert_eq!(p.bytes, 12345);
        assert_eq!(p.detail, "直接发送", "旧帧码必须归一（历史里不显示 0xNN）");
        // 旧 6 字段行照读。
        let old = "1700000001|R|10.0.0.2|7|1|0";
        let p2 = parse_line(old).unwrap();
        assert_eq!(p2.dir, Direction::Recv);
        assert_eq!(p2.detail, "");
        assert!(parse_line("bad|line").is_none(), "坏行丢弃");
    }

    /// 实机冒烟抓到的兼容缺口：C# 旧版 8 字段行（时间 = 本地时间字符串、秒带小数）
    /// 必须照读（规格 §8.1）；实机上已存在此类 stats.log。
    #[test]
    fn legacy_csharp_eight_field_lines_parse() {
        let line = "2026-10-30 21:14:43|R|127.0.0.1|23|1|0.0|hello.txt|C:\\Temp\\hello.txt";
        let p = parse_line(line).unwrap_or_else(|| panic!("C# 旧格式行必须照读"));
        assert_eq!(p.bytes, 23);
        assert_eq!(p.secs, 0, "小数秒截断");
        assert_eq!(p.detail, "hello.txt");
        assert_eq!(p.path, "C:\\Temp\\hello.txt");
        assert!(p.time > 1_700_000_000, "时间列应转成 Unix 秒（本地时区）");
        // 时间列损坏时按 0 兜底（仅进累计桶——判错方向是多读不是漏报）。
        let bad_time = "not-a-date|R|127.0.0.1|23|1|0.0|d|p";
        assert_eq!(parse_line(bad_time).unwrap().time, 0);
    }

    #[test]
    fn append_load_and_rewrite_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("stats.log");
        let log = StatsLog::new(p.clone());
        for i in 0..100 {
            log.record(Direction::Recv, "10.0.0.1", i, 1, 1, "直接发送", "f.bin");
        }
        assert_eq!(log.load().len(), 100);
        // 压到阈值之上（6000 × ≈420B ≈ 2.5MB > 2MB）→ 重写保留末 5000。
        let big_line = format!("1|S|1.1.1.1|1|1|1|{}|y\n", "x".repeat(400));
        let big: String = big_line.repeat(6000);
        std::fs::write(&p, big).unwrap();
        log.record(Direction::Recv, "10.0.0.1", 5, 1, 1, "直接发送", "f.bin");
        let after = std::fs::read_to_string(&p).unwrap();
        let n = after.lines().count();
        assert!(n <= REWRITE_KEEP + 1, "重写后必须收敛（实际 {n} 行）");
        assert_eq!(log.load().last().unwrap().bytes, 5, "最新一条必须保留");
    }

    #[test]
    fn summarize_buckets_and_devices() {
        let now: u64 = 30 * 24 * 3600;
        let today_start = now - 3600;
        let rs = vec![
            rec(now - 10, Direction::Send, "1.1.1.1", 100), // 今日
            rec(now - 3 * 24 * 3600, Direction::Recv, "2.2.2.2", 200), // 本周
            rec(now - 20 * 24 * 3600, Direction::Send, "1.1.1.1", 400), // 仅累计
        ];
        let s = summarize(&rs, now, today_start);
        assert_eq!(s.today.count, 1);
        assert_eq!(s.today.bytes, 100);
        assert_eq!(s.week.count, 2);
        assert_eq!(s.total.count, 3);
        assert_eq!(s.total.bytes, 700);
        assert_eq!(s.by_device.len(), 2);
        assert_eq!(s.by_device[0].peer, "1.1.1.1", "按 count 降序");
    }

    /// 兼容归一：旧 stats.log 写的是帧码，读入时换成用户可读文案，
    /// 且幂等（新文案原样保留）、不篡改未知文案。
    #[test]
    fn legacy_protocol_labels_are_normalized_on_load() {
        let d = |line: &str| parse_line(line).unwrap().detail;
        assert_eq!(
            d("1700000000|S|127.0.0.1|1|1|1|0x03 续传|a.bin"),
            "续传传输"
        );
        assert_eq!(
            d("1700000000|R|127.0.0.1|1|1|1|0x00 skip|a.bin"),
            "已存在（跳过）"
        );
        assert_eq!(
            d("1700000000|S|127.0.0.1|1|1|1|0x02 分块×4|a.bin"),
            "分块传输×4"
        );
        assert_eq!(
            d("1700000000|S|127.0.0.1|1|1|1|0x04 同步|a.bin"),
            "文件夹同步"
        );
        assert_eq!(
            d("1700000000|S|127.0.0.1|1|1|1|0x06 文本|<文本>"),
            "文本消息"
        );
        assert_eq!(
            d("1700000000|S|127.0.0.1|1|1|1|续传传输|a.bin"),
            "续传传输",
            "幂等"
        );
        assert_eq!(
            d("1700000000|S|127.0.0.1|1|1|1|UDP×2轮|a.bin"),
            "UDP×2轮",
            "不篡改未知文案"
        );
    }

    #[test]
    fn csv_quotes_and_bom() {
        let mut r = rec(1, Direction::Send, "1.1.1.1", 2);
        r.path = "a,b\"c".into();
        let csv = export_csv(&[r]);
        assert!(csv.starts_with('\u{feff}'));
        assert!(csv.contains("\"a,b\"\"c\""), "RFC 4180 转义");
    }

    /// 本轮 F4 判别：对端可控的文件名以公式前缀开头时，导出必须强制文本。
    /// 修复前 `=cmd|'/c calc'!A0` 原样落盘 → Excel 打开即求值。
    #[test]
    fn csv_neutralizes_formula_prefixes() {
        for evil in ["=cmd|'/c calc'!A0", "+1+1", "-1+1", "@SUM(1,2)", "\tx"] {
            let mut r = rec(1, Direction::Recv, "1.1.1.1", 2);
            r.path = evil.into();
            let csv = export_csv(&[r]);
            let last = csv.lines().last().unwrap();
            assert!(
                last.ends_with(&format!(",'{evil}")) || last.ends_with(&format!(",\"'{evil}\"")),
                "公式前缀必须前置单引号（实际: {last}）"
            );
        }
        // 正常文件名不得被加引号（避免污染既有格式）。
        let r = rec(1, Direction::Recv, "1.1.1.1", 2);
        assert!(export_csv(&[r]).lines().last().unwrap().ends_with(",a.bin"));
    }
}
