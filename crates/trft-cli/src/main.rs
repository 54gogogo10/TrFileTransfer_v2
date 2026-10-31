//! TrFileTransfer v2 命令行界面。
//! 退出码（规格 §3.6）：0=成功，1=错误，2=用法（clap 用法错误自动退出码 2）。
//!
//! 发送语义（规格 §3.2 AutoRetry）：`send --file` 首选 0x03 断点续传（失败退避重试 3 次、
//! 旧对端自动降级 0x00）；`--chunks 1-8` 走 0x02 并行分块；`--nocompress` 关闭 0x08 压缩
//! 协商（默认开，旧对端自动降级明文）。`sync` 走 0x04 文件夹同步（稳定会话 ID）。

use clap::{Parser, ValueEnum};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use trft_core::config::DuplicatePolicy;
use trft_core::hashcache::{HashCache, cache_file_for};
use trft_core::transfer::Transport;
use trft_core::transfer::folder::send_folder;
use trft_core::transfer::quic::serve_quic;
use trft_core::transfer::receiver::{self, RecvOptions};
use trft_core::transfer::resume::{send_file_auto, send_folder_resume, stable_session_id};
use trft_core::transfer::chunked::send_file_chunked;
use trft_core::transfer::sender::{SendOptions, send_text};
use trft_core::transfer::udp::{UdpRecvOptions, UdpSendOptions, send_file_udp, serve_udp};

#[derive(Parser)]
#[command(name = "trft", version, about = "局域网点对点文件传输（TrFileTransfer v2）")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Proto {
    /// 通用、防火墙友好
    Tcp,
    /// 可靠 UDP 流（QUIC 槽位）
    Udt,
    /// 单向 UDP + FEC（仅单文件，无配对码/加密）
    Udp,
}

#[derive(clap::Subcommand)]
enum Cmd {
    /// 发送单文件、文件夹或文本（单文件首选 0x03 断点续传，自动重试 + 降级）
    Send {
        #[arg(long)]
        ip: String,
        #[arg(long)]
        port: u16,
        #[arg(long, conflicts_with_all = ["text", "folder"])]
        file: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["file", "text"])]
        folder: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["file", "folder"])]
        text: Option<String>,
        #[arg(long, value_enum, default_value = "tcp")]
        proto: Proto,
        #[arg(long)]
        code: Option<String>,
        /// 发送限速 KB/s（0=不限）
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        srcport: Option<u16>,
        /// 0x02 并行分块连接数 1–8（省略 = 0x03 自动续传，规格 §3.2）
        #[arg(long)]
        chunks: Option<u8>,
        /// 单向 UDP：重发轮数 1–5（默认 2）
        #[arg(long)]
        passes: Option<u32>,
        /// 单向 UDP：FEC 校验分片 1–8（默认 2）
        #[arg(long = "fec-parity")]
        fec_parity: Option<u8>,
        /// 单向 UDP：关闭 FEC
        #[arg(long)]
        nofec: bool,
        /// 关闭 TCP 0x09 加密（默认开启；QUIC 由 TLS 承担）
        #[arg(long)]
        noencrypt: bool,
        /// 关闭 0x08 压缩协商（默认开；旧对端自动降级明文）
        #[arg(long)]
        nocompress: bool,
        /// QUIC 证书 SHA-256 指纹钉扎（64 位 hex；手动指定，不自动记录；
        /// 无 --pin 时 --udt 不防主动中间人）
        #[arg(long = "pin")]
        quic_pin: Option<String>,
    },
    /// 无人值守接收
    Recv {
        #[arg(long)]
        port: u16,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "tcp")]
        proto: Proto,
        #[arg(long)]
        code: Option<String>,
        /// 收满 N 个成功帧数后退出（仅 tcp/udt）
        #[arg(long)]
        count: Option<u64>,
        /// 拒绝 TCP 0x09 加密升级（默认接受）
        #[arg(long)]
        noencrypt: bool,
    },
    /// 文件夹同步（0x04 差量同步：只传差异、保留服务端已删除文件；稳定会话 ID 可接力）
    Sync {
        #[arg(long)]
        folder: PathBuf,
        #[arg(long)]
        ip: String,
        #[arg(long)]
        port: u16,
        #[arg(long, value_enum, default_value = "tcp")]
        proto: Proto,
        #[arg(long)]
        code: Option<String>,
        /// 发送限速 KB/s（0=不限）
        #[arg(long)]
        limit: Option<u64>,
        /// 关闭 0x08 压缩协商（默认开）
        #[arg(long)]
        nocompress: bool,
    },
    /// 文件库校验（重算 SHA-256；发现不一致退出码 1）
    Verify {
        #[arg(long)]
        dir: PathBuf,
    },
    /// 自更新（ed25519 签名清单；更新源强制 https，规格 §5.1）
    Update {
        /// 清单 URL（key=value + ed25519 签名；缺省读配置 UpdateUrl）
        #[arg(long)]
        url: Option<String>,
        /// 仅检查（不下载不换入）
        #[arg(long)]
        check: bool,
        /// 换入成功后重启进程
        #[arg(long)]
        restart: bool,
    },
}

fn addr_of(ip: &str, port: u16) -> Result<SocketAddr, String> {
    if ip.contains(':') {
        format!("[{ip}]:{port}").parse::<SocketAddr>().map_err(|e| e.to_string())
    } else {
        format!("{ip}:{port}").parse::<SocketAddr>().map_err(|e| e.to_string())
    }
}

fn validate_code(code: &Option<String>) -> Result<(), String> {
    if let Some(c) = code {
        let n = c.chars().count();
        if !(4..=12).contains(&n) || !c.chars().all(|ch| ch.is_ascii_digit()) {
            return Err("配对码必须是 4–12 位数字".into());
        }
    }
    Ok(())
}

fn parse_pin(pin: &Option<String>) -> Result<Option<[u8; 32]>, String> {
    match pin {
        None => Ok(None),
        Some(h) => {
            if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("--pin 需要 64 位十六进制（SHA-256 指纹）".into());
            }
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap();
            }
            Ok(Some(out))
        }
    }
}

fn transport_of(p: Proto) -> Transport {
    match p {
        Proto::Tcp => Transport::Tcp,
        Proto::Udt => Transport::Quic,
        Proto::Udp => Transport::Tcp, // 不会走到：UDP 分支单独处理
    }
}

fn stream_opts(
    code: Option<String>,
    limit: Option<u64>,
    srcport: Option<u16>,
    p: Proto,
    encrypt: bool,
    compress: bool,
    pin: Option<[u8; 32]>,
) -> SendOptions {
    SendOptions {
        pairing_code: code,
        speed_limit_bps: limit.unwrap_or(0).min(10_000_000) * 1024,
        src_port: srcport,
        transport: transport_of(p),
        encrypt,
        compress,
        quic_pin: pin,
        progress: None,
        // 规格 §3.3 stats.log：CLI 与 GUI 共享同一统计（TECH-STACK §7.10）。
        stats: Some(std::sync::Arc::new(trft_core::stats::StatsLog::default_log())),
    }
}

fn udp_opts(passes: Option<u32>, fec_parity: Option<u8>, nofec: bool, limit: Option<u64>) -> UdpSendOptions {
    UdpSendOptions {
        passes: passes.unwrap_or(2).clamp(1, 5),
        fec: !nofec,
        fec_parity: fec_parity.unwrap_or(2).clamp(1, 8),
        speed_limit_bps: limit.unwrap_or(0).min(10_000_000) * 1024,
        progress: None,
        stats: Some(std::sync::Arc::new(trft_core::stats::StatsLog::default_log())),
    }
}

fn fail(msg: &str) -> i32 {
    eprintln!("错误: {msg}");
    1
}

/// 用法类错误（参数格式/互斥约束/越界）统一退出码 2（规格 §3.6）。
fn usage_fail(msg: &str) -> i32 {
    eprintln!("用法错误: {msg}");
    2
}

#[tokio::main]
async fn main() {
    std::process::exit(run().await);
}

async fn run() -> i32 {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Send { ip, port, file, folder, text, proto, code, limit, srcport, chunks, passes, fec_parity, nofec, noencrypt, nocompress, quic_pin } => {
            if let Err(e) = validate_code(&code) {
                return usage_fail(&e);
            }
            if proto != Proto::Udt && quic_pin.is_some() {
                return usage_fail("--pin 仅用于 --proto udt");
            }
            if let Some(n) = chunks {
                if !(1..=8).contains(&n) {
                    return usage_fail("--chunks 取值 1–8");
                }
            }
            let pin = match parse_pin(&quic_pin) {
                Ok(v) => v,
                Err(e) => return usage_fail(&e),
            };
            if let Some(p) = passes {
                if !(1..=5).contains(&p) {
                    return usage_fail("--passes 取值 1–5");
                }
            }
            if let Some(fp) = fec_parity {
                if !(1..=8).contains(&fp) {
                    return usage_fail("--fec-parity 取值 1–8");
                }
            }
            let addr = match addr_of(&ip, port) {
                Ok(a) => a,
                Err(e) => return usage_fail(&format!("目标地址非法: {e}")),
            };
            if proto == Proto::Udp {
                if code.is_some() {
                    return usage_fail("单向 UDP 无握手通道，不支持配对码/加密（规格 §3.1，帮助须明示）");
                }
                if folder.is_some() {
                    return usage_fail("单向 UDP 仅支持单文件（规格 §3.6）");
                }
                if text.is_some() {
                    return usage_fail("单向 UDP 不支持文本帧");
                }
                if nocompress {
                    return usage_fail("单向 UDP 不支持压缩协商（无握手通道）");
                }
                let Some(f) = file else {
                    return usage_fail("send 需要 --file（单向 UDP）");
                };
                let o = udp_opts(passes, fec_parity, nofec, limit);
                return match send_file_udp(addr, &f, &o).await {
                    Ok(()) => 0,
                    Err(e) => fail(&format!("发送失败: {e}")),
                };
            }
            let opts = stream_opts(code, limit, srcport, proto, !noencrypt, !nocompress, pin);
            let r = match (folder, file, text) {
                (Some(f), _, _) => send_folder(addr, &f, &opts).await,
                // 规格 §3.2 AutoRetry：单文件首选 0x03（含降级 0x00）；--chunks 走 0x02。
                (_, Some(f), _) if chunks.is_some() => {
                    let n = chunks.unwrap();
                    match send_file_chunked(addr, &f, &opts, n).await {
                        Ok(()) => Ok(()),
                        Err(trft_core::error::Error::Unsupported(m)) => {
                            eprintln!("提示: {m}，回退自动续传（0x03→0x00）");
                            send_file_auto(addr, &f, &opts).await
                        }
                        Err(e) => Err(e),
                    }
                }
                (_, Some(f), _) => send_file_auto(addr, &f, &opts).await,
                (_, _, Some(t)) => send_text(addr, &t, &opts).await,
                _ => return usage_fail("send 需要 --file 或 --text 或 --folder"),
            };
            match r {
                Ok(()) => {
                    println!("完成");
                    0
                }
                Err(e) => fail(&format!("发送失败: {e}")),
            }
        }
        Cmd::Recv { port, out, proto, code, count, noencrypt } => {
            if let Err(e) = validate_code(&code) {
                return usage_fail(&e);
            }
            if count == Some(0) {
                return usage_fail("--count 至少为 1");
            }
            let save =
                out.unwrap_or_else(|| std::env::current_dir().unwrap_or_default().join("trft-received"));
            let addr = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port);
            match proto {
                Proto::Udp => {
                    if code.is_some() {
                        return usage_fail("单向 UDP 无握手通道，不支持配对码/加密（规格 §3.1）");
                    }
                    if count.is_some() {
                        return usage_fail("--count 不适用于 --proto udp（落盘即状态，无回传计数）");
                    }
                    eprintln!("单向 UDP 接收中: 0.0.0.0:{port} → {}（Ctrl+C 退出）", save.display());
                    let o = UdpRecvOptions {
                        save_dir: save,
                        stats: Some(Arc::new(trft_core::stats::StatsLog::default_log())),
                        ..Default::default()
                    };
                    let server = tokio::spawn(serve_udp(addr, o, None));
                    tokio::select! {
                        r = server => match r {
                            Ok(Ok(())) => 0,
                            Ok(Err(e)) => fail(&format!("接收器异常退出: {e}")),
                            Err(e) => fail(&format!("接收器任务崩溃: {e}")),
                        },
                        _ = tokio::signal::ctrl_c() => {
                            eprintln!("\n已停止");
                            0
                        }
                    }
                }
                _ => {
                    // 接收侧摘要缓存：0x00/0x01/0x03/0x02 组装免费填充 + 0x03 skip 判定。
                    let cache = Arc::new(Mutex::new(HashCache::load(
                        &cache_file_for(&save),
                        trft_core::hashcache::DEFAULT_TTL_DAYS,
                    )));
                    let o = RecvOptions {
                        save_dir: save.clone(),
                        pairing_code: code,
                        duplicate: DuplicatePolicy::Rename,
                        max_count: count,
                        encrypt: !noencrypt,
                        hash_cache: Some(cache),
                        stats: Some(Arc::new(trft_core::stats::StatsLog::default_log())),
                        ..Default::default()
                    };
                    let label = if proto == Proto::Udt { "QUIC(udt)" } else { "TCP" };
                    eprintln!("接收中[{label}]: 0.0.0.0:{port} → {}（Ctrl+C 退出）", o.save_dir.display());
                    let server = match proto {
                        Proto::Udt => tokio::spawn(serve_quic(addr, o)),
                        _ => tokio::spawn(receiver::serve(addr, o)),
                    };
                    tokio::select! {
                        r = server => match r {
                            Ok(Ok(())) => 0,
                            Ok(Err(e)) => fail(&format!("接收器异常退出: {e}")),
                            Err(e) => fail(&format!("接收器任务崩溃: {e}")),
                        },
                        _ = tokio::signal::ctrl_c() => {
                            eprintln!("\n已停止");
                            0
                        }
                    }
                }
            }
        }
        Cmd::Sync { folder, ip, port, proto, code, limit, nocompress } => {
            if proto == Proto::Udp {
                return usage_fail("单向 UDP 不支持文件夹传输（仅单文件，规格 §3.6）");
            }
            if let Err(e) = validate_code(&code) {
                return usage_fail(&e);
            }
            let addr = match addr_of(&ip, port) {
                Ok(a) => a,
                Err(e) => return usage_fail(&format!("目标地址非法: {e}")),
            };
            let opts = SendOptions {
                transport: transport_of(proto),
                pairing_code: code,
                speed_limit_bps: limit.unwrap_or(0).min(10_000_000) * 1024,
                compress: !nocompress,
                // CLI 与 GUI 同享 stats.log（TECH-STACK §7.10；轮 5 P2：sync 此前漏注）。
                stats: Some(std::sync::Arc::new(trft_core::stats::StatsLog::default_log())),
                ..Default::default()
            };
            // 稳定会话 ID：由 (源路径, 目标地址) 确定性派生（大小写/尾斜杠不敏感）。
            let target = format!("{ip}:{port}");
            let session = stable_session_id(&folder, &target);
            // 发送端摘要缓存：命中项免费携带哈希 → 服务端可判跳过（规格 §3.1）。
            // SyncVerifyContent（strict，规格 §3.3）：双侧生效 → 发送侧不携带缓存哈希。
            let strict = trft_core::config::Config::load(
                &trft_core::config::app_data_dir().join("config.toml"),
            )
            .map(|c| c.sync_verify_content)
            .unwrap_or(false);
            let client_cache = if strict {
                None
            } else {
                Some(Arc::new(Mutex::new(HashCache::load(
                    &cache_file_for(&folder),
                    trft_core::hashcache::DEFAULT_TTL_DAYS,
                ))))
            };
            match send_folder_resume(addr, &folder, &opts, session, client_cache.as_ref()).await {
                Ok(()) => {
                    println!("同步完成");
                    0
                }
                Err(trft_core::error::Error::Unsupported(m)) => {
                    fail(&format!("同步失败: {m}（同步需要 0x04 能力，旧对端请改用 send --folder）"))
                }
                Err(e) => fail(&format!("同步失败: {e}")),
            }
        }
        Cmd::Verify { dir } => {
            if !dir.is_dir() {
                return fail(&format!("目录不存在: {}", dir.display()));
            }
            // 规格 §3.5：逐文件重算 SHA-256 与摘要缓存比对（引擎 = trft_core::scrub，
            // 与 GUI「校验」共用同一实现——§3.6 复用同一逻辑层）；发现不一致退出码 1；
            // 无记录不算失败。缓存 = 目录内 .trft-hash-cache.txt（TTL 7 天）。
            let cache_path = cache_file_for(&dir);
            let mut cache = HashCache::load(&cache_path, trft_core::hashcache::DEFAULT_TTL_DAYS);
            let r = trft_core::scrub::verify_dir(&dir, &mut cache, None, None);
            if let Err(e) = cache.save(&cache_path) {
                eprintln!("警告: 缓存写入失败（下次全量重算）: {e}");
            }
            println!(
                "已扫描 {} 个文件（{} 字节）：缓存核对 {}，新记录 {}，无法读取 {}",
                r.scanned, r.bytes, r.hit, r.fresh, r.unreadable
            );
            if !r.mismatches.is_empty() {
                eprintln!("发现 {} 个文件与摘要缓存不一致：", r.mismatches.len());
                for m in &r.mismatches {
                    eprintln!("  不一致: {m}");
                }
                return 1;
            }
            0
        }
        Cmd::Update { url, check, restart } => {
            if restart {
                // 轮 5 P3：CLI 重启 spawn 无参 exe → clap 报用法错误——组合不成立。
                return usage_fail("--restart 仅对图形界面更新有意义（CLI 重启后无动词可执行）");
            }
            let manifest_url = match url.or_else(|| {
                trft_core::config::Config::load(&trft_core::config::app_data_dir().join("config.toml"))
                    .ok()
                    .and_then(|c| c.update_url)
            }) {
                Some(u) => u,
                None => return usage_fail("update 需要 --url 或配置 UpdateUrl"),
            };
            let Ok(pubkey) = trft_core::update::embedded_pubkey() else {
                return fail("内嵌更新公钥非法");
            };
            if check {
                // 仅检查：拉清单 → 验签 → 比版本。
                return match trft_core::update::fetch_manifest(&manifest_url, &pubkey).await {
                    Ok(m) => {
                        let current = env!("CARGO_PKG_VERSION");
                        if trft_core::update::version_gt(&m.version, current) {
                            println!("发现新版本 {}（当前 {current}）：{}", m.version, m.url);
                            0
                        } else {
                            println!("已是最新版本（{current}）");
                            0
                        }
                    }
                    Err(e) => fail(&format!("检查更新失败: {e}")),
                };
            }
            let work = trft_core::config::app_data_dir().join("updates");
            match trft_core::update::run_update(&manifest_url, &pubkey, env!("CARGO_PKG_VERSION"), &work).await {
                Ok(Some(bak)) => {
                    let _ = std::fs::remove_file(&bak); // 成功换入后清理备份
                    println!("已更新并换入（旧文件备份 {}）", bak.display());
                    if restart {
                        if let Err(e) = trft_core::update::spawn_restarted() {
                            return fail(&format!("已更新但重启失败（请手动启动）: {e}"));
                        }
                    }
                    0
                }
                Ok(None) => {
                    println!("已是最新版本（{}）", env!("CARGO_PKG_VERSION"));
                    0
                }
                Err(e) => fail(&format!("更新失败: {e}")),
            }
        }
    }
}
