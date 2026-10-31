//! Web 共享/管理面入口（规格 §3.4）：默认回环绑定；配对码开启鉴权。

use clap::Parser;

use std::path::PathBuf;
use std::sync::Arc;
use trft_server::{AuthConfig, WebState};

#[derive(Parser)]
#[command(name = "trft-server", version, about = "TrFileTransfer Web 共享/管理面")]
struct Args {
    /// 共享目录
    #[arg(long, default_value = ".")]
    dir: PathBuf,
    /// 监听端口（规格默认 8090）
    #[arg(long, default_value_t = 8090)]
    port: u16,
    /// 绑定地址（默认仅回环；放开需显式指定并建议配对码鉴权）
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,
    /// 配对码（4–12 位数字；设置后启用鉴权，`?t=` 令牌 = SHA-256(码‖域) 前 32 hex）
    #[arg(long)]
    code: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if !args.dir.is_dir() {
        eprintln!("错误: 共享目录不存在: {}", args.dir.display());
        std::process::exit(1);
    }
    if let Some(code) = &args.code {
        let n = code.chars().count();
        if !(4..=12).contains(&n) || !code.chars().all(|c| c.is_ascii_digit()) {
            eprintln!("错误: 配对码必须是 4–12 位数字");
            std::process::exit(2);
        }
    }
    let auth = args.code.clone().map(|pairing_code| AuthConfig { pairing_code });
    let state = Arc::new(WebState::new(args.dir.clone(), auth));
    let app = trft_server::build_router(state);
    let addr = format!("{}:{}", args.bind, args.port)
        .parse::<std::net::SocketAddr>()
        .expect("绑定地址非法");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("端口绑定失败");
    let auth_note = if args.code.is_some() { "鉴权=配对码" } else { "无鉴权（仅建议回环）" };
    eprintln!("Web 共享[{auth_note}]: http://{addr}/ → {}", args.dir.display());
    // 头读超时 15s（规格 §6.1；轮 2 P1——slowloris 不得占满并发闸）。
    trft_server::serve_with_header_timeout(listener, app)
        .await
        .expect("服务器异常退出");
}
