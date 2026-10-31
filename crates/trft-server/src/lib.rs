//! Web 管理面 / HTTP 共享（规格 §3.4）：目录浏览、鉴权（配对码 + 会话 Cookie + `?t=` 令牌 +
//! 按 IP 计错锁定）、Range 断点下载（206/416）、multipart 流式上传、无 JS 删除确认页 +
//! CSRF 双重校验、加固响应头与容量上限。
//!
//! 加固上限（规格 §6.1）：并发 32、整请求 4GB、单文件 2GB；统一
//! `Cache-Control: no-store` + `X-Frame-Options: DENY` + CSP；仅图片/音视频/pdf/txt 内联，
//! HTML/SVG 一律 attachment。

use axum::Router;
use axum::extract::{DefaultBodyLimit, Multipart, Path as AxPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use trft_core::protocol::frame::sanitize_name;
use trft_core::transfer::receiver::PairingGate;

/// 规格 §6.1：整请求 4GB、单文件 2GB。
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024 * 1024;
pub const MAX_UPLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// 请求体空闲读超时（轮 2 F6）：头读超时（15s）只覆盖请求头阶段；
/// 慢滴 body（每 chunk 1 字节/数秒）可无限占用并发闸——空闲 60s 即断。
const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// 规格 §6.1：HTTP 共享并发 32。
pub const MAX_CONCURRENCY: usize = 32;
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const SESSION_CAP: usize = 1024;
/// 会话/Cookie 名。
const SID_COOKIE: &str = "trft_sid";
const CSRF_COOKIE: &str = "trft_csrf";

pub struct AuthConfig {
    /// 配对码（明文门：登录时恒时比对；`?t=` 令牌 = SHA-256(code‖域) 前 32 hex）。
    pub pairing_code: String,
}

pub struct WebState {
    dir: PathBuf,
    auth: Option<AuthConfig>,
    /// `?t=` 令牌派生密钥（每安装随机 32B，hex；轮 6 P2-4：无密钥快速哈希
    /// 可被离线反推低熵配对码——HMAC 隔离后令牌泄漏只作废令牌不回传码）。
    token_secret: [u8; 32],
    gate: Arc<Mutex<PairingGate>>,
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
    permits: Arc<Semaphore>,
    /// 上传单文件上限（可注入以便测试；生产 = MAX_UPLOAD_BYTES）。
    pub max_upload_bytes: u64,
}

impl WebState {
    pub fn new(dir: PathBuf, auth: Option<AuthConfig>) -> Self {
        Self::with_token_secret(dir, auth, Self::random_secret())
    }

    /// 测试/外部注入派生密钥。
    pub fn with_token_secret(dir: PathBuf, auth: Option<AuthConfig>, token_secret: [u8; 32]) -> Self {
        Self {
            dir,
            auth,
            token_secret,
            gate: Arc::new(Mutex::new(PairingGate::default())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENCY)),
            max_upload_bytes: MAX_UPLOAD_BYTES,
        }
    }

    fn random_secret() -> [u8; 32] {
        let mut b = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut b);
        b
    }

    fn auth_enabled(&self) -> bool {
        self.auth.is_some()
    }

    /// `?t=` 直接访问令牌摘要：HMAC-SHA256(每安装密钥, code‖域) 截断 16B
    /// （轮 6 P2-1/P2-4：check_token 与 token_for 长度此前错开（64 vs 32 hex）
    /// ——扫码直连整链失效且判别测试绕过了 token_for 掩盖失配；现统一 32 hex）。
    fn token_digest(&self) -> Option<[u8; 32]> {
        let code = &self.auth.as_ref()?.pairing_code;
        let full = trft_core::crypto::kdf::hmac_sha256(&self.token_secret, &token_domain_input(code));
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&full[..16]);
        Some(out)
    }

    fn check_token(&self, t: &str) -> bool {
        let Some(expect) = self.token_digest() else { return false };
        let mut got = [0u8; 16];
        if t.len() != 32 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        for i in 0..16 {
            got[i] = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).unwrap_or(0xFF);
        }
        trft_core::crypto::kdf::ct_eq(&got, &expect[..16])
    }
}

pub fn build_router(state: Arc<WebState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(
            "/login",
            get(login_page)
                .post(login_submit)
                .layer(DefaultBodyLimit::max(8192)),
        )
        .route("/", get(view_root))
        .route("/view/{*path}", get(view_dir))
        .route("/dl/{*path}", get(download))
        .route("/up/{*path}", post(upload))
        .route("/up", post(upload_root).get(view_root))
        .route("/up/", post(upload_root).get(view_root))
        .route(
            "/del/{*path}",
            get(delete_confirm)
                .post(delete_submit)
                .layer(DefaultBodyLimit::max(8192)),
        )
        .layer(middleware::from_fn_with_state(state.clone(), security_headers_mw))
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
        .layer(middleware::from_fn_with_state(state.clone(), concurrency_mw))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state)
}

/// `?t=` 令牌的域分隔输入（GUI 二维码直接复用，防域串漂移——单一事实来源）。
fn token_domain_input(code: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(code.len() + 16);
    m.extend_from_slice(code.as_bytes());
    m.extend_from_slice(b"trft-web-token-v1");
    m
}

/// `?t=` 令牌明文（HMAC(密钥, code‖域) 截 16B → 32 hex）。
/// `secret`：每安装随机密钥（GUI 持久化于 config.toml，与 WebState 同源）——
/// 轮 6 P2-4：无密钥派生可离线反推低熵配对码，HMAC 隔离后泄漏只作废令牌。
pub fn token_for(secret: &[u8; 32], code: &str) -> String {
    let full = trft_core::crypto::kdf::hmac_sha256(secret, &token_domain_input(code));
    trft_core::hash::hex(&full[..16])
}

// ============ 中间件 ============

async fn concurrency_mw(
    State(st): State<Arc<WebState>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    // /health、/login 豁免并发闸（轮 2 P1：32 个慢连接不得锁死健康检查与登录入口；
    // login 自有 IP 锁定防线）。
    let path = req.uri().path();
    if path == "/health" || path == "/login" {
        return next.run(req).await;
    }
    // 规格 §3.4：并发 32 连接；获取加 30s 上限（慢连接占用时回 503 而非无限排队）。
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        st.permits.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(_permit)) => next.run(req).await,
        _ => (StatusCode::SERVICE_UNAVAILABLE, "服务繁忙，请稍后重试").into_response(),
    }
}

async fn security_headers_mw(_state: State<Arc<WebState>>, req: axum::extract::Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    res
}

/// 会话鉴权：/health、/login 豁免；其余要求（会话 Cookie | `?t=` 令牌 | 未启用鉴权）。
async fn auth_mw(
    State(st): State<Arc<WebState>>,
    Query(q): Query<HashMap<String, String>>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let path = req.uri().path();
    if !st.auth_enabled() || path == "/health" || path == "/login" {
        return next.run(req).await;
    }
    // ?t= 令牌（书签/脚本直连）。
    if let Some(t) = q.get("t") {
        if st.check_token(t) {
            return next.run(req).await;
        }
    }
    // 会话 Cookie（守卫不得跨 await——std Mutex 非 Send）。
    let sid_ok = cookie_of(req.headers(), SID_COOKIE)
        .map(|sid| {
            let mut sessions = st.sessions.lock().unwrap();
            match sessions.get(&sid) {
                Some(t) if t.elapsed() < SESSION_TTL => true,
                _ => {
                    sessions.remove(&sid); // 过期即清
                    false
                }
            }
        })
        .unwrap_or(false);
    if sid_ok {
        return next.run(req).await;
    }
    Redirect::to("/login").into_response()
}

fn cookie_of(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let (k, v) = part.trim().split_once('=')?;
        if k == name {
            return Some(v.to_string());
        }
    }
    None
}

fn rand_hex32() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    trft_core::hash::hex(&b)
}

// ============ 登录 ============

async fn health() -> &'static str {
    "ok"
}

async fn login_page() -> Html<String> {
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>登录 - TrFileTransfer</title></head>\
         <body style=\"font-family:sans-serif;max-width:24rem;margin:10vh auto\">\
         <h1>TrFileTransfer</h1><p>请输入配对码访问共享。</p>\
         <form method=\"post\" action=\"/login\">\
         <input type=\"password\" name=\"code\" pattern=\"[0-9]*\" required autofocus \
         style=\"width:100%;padding:.5rem;box-sizing:border-box\">\
         <button type=\"submit\" style=\"width:100%;padding:.5rem;margin-top:.5rem\">登录</button>\
         </form></body></html>"
    ))
}

async fn login_submit(
    State(st): State<Arc<WebState>>,
    addr: Option<axum::Extension<axum::extract::ConnectInfo<SocketAddr>>>,
    body: String,
) -> Response {
    let Some(auth) = &st.auth else {
        return Redirect::to("/").into_response();
    };
    // 规格 §3.4：按来源 IP 计错锁定（10 次 / 10 分钟，成功清零）——复用核心配对门。
    // （ConnectInfo 由 into_make_service_with_connect_info 注入；oneshot 测试无此扩展。）
    let ip = addr
        .map(|c| c.0 .0.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    {
        let gate = st.gate.lock().unwrap();
        if gate.locked(&ip) {
            return (StatusCode::TOO_MANY_REQUESTS, "失败次数过多，已临时锁定").into_response();
        }
    }
    let code = parse_form(&body)
        .into_iter()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v)
        .unwrap_or_default();
    let ok = trft_core::crypto::kdf::ct_eq(
        &trft_core::hash::sha256(code.trim().as_bytes()),
        &trft_core::hash::sha256(auth.pairing_code.as_bytes()),
    );
    if !ok {
        st.gate.lock().unwrap().fail(&ip);
        return (StatusCode::UNAUTHORIZED, "配对码错误").into_response();
    }
    st.gate.lock().unwrap().success(&ip);
    // 成功：会话 + CSRF（HttpOnly + SameSite=Strict，规格 §3.4）。
    let sid = rand_hex32();
    let csrf = rand_hex32();
    {
        let mut sessions = st.sessions.lock().unwrap();
        // 容量防线：先清过期，仍满则拒绝新会话（fail-closed，锁不放大）。
        sessions.retain(|_, t| t.elapsed() < SESSION_TTL);
        if sessions.len() < SESSION_CAP {
            sessions.insert(sid.clone(), Instant::now());
        }
    }
    let mut res = Redirect::to("/").into_response();
    let h = res.headers_mut();
    h.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!("{SID_COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/"))
            .unwrap_or(HeaderValue::from_static("")),
    );
    h.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!("{CSRF_COOKIE}={csrf}; HttpOnly; SameSite=Strict; Path=/"))
            .unwrap_or(HeaderValue::from_static("")),
    );
    res
}

fn parse_form(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in body.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.push((url_decode(k), url_decode(v)));
    }
    out
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() + 1 && i + 2 < b.len() + 1 => {
                let hex = |c: u8| (c as char).to_digit(16);
                if i + 2 < b.len() {
                    if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                        continue;
                    }
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ============ 目录浏览 ============

/// 路径穿越防线（规格 §5.1）：拒绝 `..`、绝对路径、盘符前缀与 NUL。
fn resolve_under(base: &Path, rel: &str) -> Result<PathBuf, (StatusCode, &'static str)> {
    let p = PathBuf::from(rel);
    if rel.contains('\0')
        || p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::RootDir | std::path::Component::Prefix(_)))
    {
        return Err((StatusCode::BAD_REQUEST, "非法路径"));
    }
    Ok(base.join(p))
}

async fn view_root(State(st): State<Arc<WebState>>) -> Response {
    view(&st, "").await
}

async fn view_dir(
    State(st): State<Arc<WebState>>,
    AxPath(path): AxPath<String>,
) -> Response {
    view(&st, &path).await
}

async fn view(st: &WebState, rel: &str) -> Response {
    let full = match resolve_under(&st.dir, rel) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if !full.is_dir() {
        return (StatusCode::NOT_FOUND, "目录不存在").into_response();
    }
    let mut entries: Vec<_> = std::fs::read_dir(&full)
        .map(|rd| rd.flatten().collect::<Vec<_>>())
        .unwrap_or_default();
    entries.sort_by_key(|e| (!e.path().is_dir(), e.file_name()));
    let mut rows = String::new();
    if !rel.is_empty() {
        let parent = Path::new(rel).parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
        rows.push_str(&format!(
            "<tr><td><a href=\"/view/{}\">[..]</a></td><td></td><td></td></tr>",
            url_escape(&parent)
        ));
    }
    for e in &entries {
        let name = e.file_name().to_string_lossy().to_string();
        let is_dir = e.path().is_dir();
        let size = e.metadata().map(|m| m.len()).unwrap_or(0);
        let sub = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let size_txt = if is_dir { "目录".into() } else { format_bytes(size) };
        let dl = if is_dir {
            String::new()
        } else {
            format!("<a href=\"/dl/{}\">下载</a> ", url_escape(&sub))
        };
        // 删除仅对文件开放（规格 §3.4：删除单个文件）。
        let del = if is_dir {
            String::new()
        } else {
            format!("<a href=\"/del/{}\">删除</a>", url_escape(&sub))
        };
        rows.push_str(&format!(
            "<tr><td><a href=\"/view/{}\">{}</a></td><td>{}</td><td>{dl}{del}</td></tr>",
            url_escape(&sub),
            html_escape(&name),
            size_txt
        ));
    }
    let upload_target = url_escape(rel);
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>TrFileTransfer 共享</title></head>\
         <body style=\"font-family:sans-serif;max-width:48rem;margin:2rem auto\">\
         <h1>共享目录: /{}</h1>\
         <form method=\"post\" action=\"/up/{}\" enctype=\"multipart/form-data\">\
         <input type=\"file\" name=\"file\" multiple required>\
         <button type=\"submit\">上传</button></form>\
         <table border=\"1\" cellpadding=\"4\" style=\"border-collapse:collapse;margin-top:1rem\">\
         <tr><th>名称</th><th>大小</th><th>操作</th></tr>{rows}</table>\
         </body></html>",
        html_escape(rel),
        upload_target
    ))
    .into_response()
}

fn format_bytes(n: u64) -> String {
    if n >= 1 << 30 { format!("{:.1} GiB", n as f64 / (1 << 30) as f64) }
    else if n >= 1 << 20 { format!("{:.1} MiB", n as f64 / (1 << 20) as f64) }
    else if n >= 1 << 10 { format!("{:.1} KiB", n as f64 / (1 << 10) as f64) }
    else { format!("{n} B") }
}

// ============ 下载（Range 断点续传） ============

/// 内联白名单（规格 §3.4：仅图片/音视频/pdf/txt 内联；HTML/SVG 一律 attachment）。
fn inline_kind(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp" | "ico" | "avif" => "image",
        "mp4" | "webm" | "mov" | "m4v" | "mp3" | "ogg" | "wav" | "flac" | "m4a" => "av",
        "pdf" => "pdf",
        "txt" => "txt",
        _ => return None,
    })
}

fn content_type_of(ext: &str) -> &'static str {
    match ext {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        "avif" => "image/avif",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "pdf" => "application/pdf",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// RFC5987：UTF-8 文件名的 `filename*` 编码 + ASCII 回退。
fn content_disposition(name: &str, ext: &str) -> String {
    let inline = inline_kind(ext).is_some();
    let disp = if inline { "inline" } else { "attachment" };
    let ascii: String = name
        .chars()
        .map(|c| if c.is_ascii_graphic() && c != '"' && c != '\\' { c } else { '_' })
        .collect();
    let mut pct = String::from("UTF-8''");
    for b in name.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                pct.push(*b as char)
            }
            _ => pct.push_str(&format!("%{b:02X}")),
        }
    }
    format!("{disp}; filename=\"{ascii}\"; filename*={pct}")
}

struct RangeSpec {
    start: u64,
    end: u64, // 含端
}

/// 解析单区间 Range（多区间按 RFC 容忍降级为 200 全量——由调用方处理）。
fn parse_range(h: &str, size: u64) -> Result<Option<RangeSpec>, ()> {
    let Some(spec) = h.strip_prefix("bytes=") else { return Err(()) };
    if spec.contains(',') {
        return Err(()); // 多区间：调用方回 200 全量
    }
    let (a, b) = spec.split_once('-').ok_or(())?;
    if a.is_empty() {
        // 后缀区间：bytes=-N（最后 N 字节；N=0 不可满足）。
        // N ≥ size：按 RFC 9110 §14.1.2 视为整个表示（回 200 全量，轮 4 F7——
        // 此前误回 416；断点续传客户端请求超出表示长度的后缀属常见边界）。
        let n: u64 = b.parse().map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        if n >= size {
            return Ok(None); // 调用方按无 Range 处理（200 全量）
        }
        Ok(Some(RangeSpec { start: size - n, end: size - 1 }))
    } else {
        let start: u64 = a.parse().map_err(|_| ())?;
        let end = if b.is_empty() { size - 1 } else { b.parse::<u64>().map_err(|_| ())?.min(size - 1) };
        if start > end || start >= size {
            return Err(());
        }
        Ok(Some(RangeSpec { start, end }))
    }
}

async fn download(
    State(st): State<Arc<WebState>>,
    AxPath(path): AxPath<String>,
    headers: HeaderMap,
) -> Response {
    let full = match resolve_under(&st.dir, &path) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    let Ok(meta) = tokio::fs::metadata(&full).await else {
        return (StatusCode::NOT_FOUND, "文件不存在").into_response();
    };
    if !meta.is_file() {
        return (StatusCode::BAD_REQUEST, "不是普通文件").into_response();
    }
    let size = meta.len();
    if size == 0 {
        // 空文件无可服务区间（轮 2 P3：避免 size-1 回绕/debug panic）。
        let mut res = (StatusCode::RANGE_NOT_SATISFIABLE, "bytes */0").into_response();
        res.headers_mut().insert(
            header::CONTENT_RANGE,
            HeaderValue::from_static("bytes */0"),
        );
        return res;
    }
    let name = full
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();
    let ext = full
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default();

    let mut h = HeaderMap::new();
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&content_disposition(&name, &ext))
            .unwrap_or(HeaderValue::from_static("attachment")),
    );
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type_of(&ext)));

    let range = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|h| parse_range(h, size));
    match range {
        Some(Ok(Some(spec))) => {
            let len = spec.end - spec.start + 1;
            let file = match tokio::fs::File::open(&full).await {
                Ok(f) => f,
                Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "打开失败").into_response(),
            };
            use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
            let mut file = file;
            if file.seek(std::io::SeekFrom::Start(spec.start)).await.is_err() {
                return (StatusCode::INTERNAL_SERVER_ERROR, "定位失败").into_response();
            }
            // 流式响应（轮 2 P2：内存 O(块)——此前整段驻留内存可被放大到 OOM）。
            let stream = tokio_util::io::ReaderStream::new(file.take(len));
            h.insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {}-{}/{}", spec.start, spec.end, size))
                    .unwrap_or(HeaderValue::from_static("bytes */0")),
            );
            let mut res = (
                StatusCode::PARTIAL_CONTENT,
                [(header::CONTENT_LENGTH, HeaderValue::from(len))],
                axum::body::Body::from_stream(stream),
            )
                .into_response();
            res.headers_mut().extend(h);
            res
        }
        Some(Ok(None)) | None => {
            // 无 Range 或多区间 → 200 全量（流式；轮 2 P2）。
            match tokio::fs::File::open(&full).await {
                Ok(file) => {
                    let mut res = (
                        StatusCode::OK,
                        [(header::CONTENT_LENGTH, HeaderValue::from(size))],
                        axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(file)),
                    )
                        .into_response();
                    res.headers_mut().extend(h);
                    res
                }
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "读取失败").into_response(),
            }
        }
        Some(Err(())) => {
            // 不可满足/非法 → 416（规格 §3.4：206/416）。
            let mut res = (
                StatusCode::RANGE_NOT_SATISFIABLE,
                format!("bytes */{size}"),
            )
                .into_response();
            res.headers_mut().insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{size}"))
                    .unwrap_or(HeaderValue::from_static("bytes */0")),
            );
            res
        }
    }
}

// ============ 上传（multipart 流式） ============

async fn upload_root(State(st): State<Arc<WebState>>, mp: Multipart) -> Response {
    upload_impl(st, "", mp).await
}

async fn upload(
    State(st): State<Arc<WebState>>,
    AxPath(path): AxPath<String>,
    mp: Multipart,
) -> Response {
    upload_impl(st, &path, mp).await
}

async fn upload_impl(st: Arc<WebState>, path: &str, mp: Multipart) -> Response {
    let st = &*st;
    let dest_dir = match resolve_under(&st.dir, path) {
        Ok(f) if f.is_dir() => f,
        Ok(_) => return (StatusCode::NOT_FOUND, "目标目录不存在").into_response(),
        Err(e) => return e.into_response(),
    };
    let mut mp = mp;
    let mut saved: Vec<String> = Vec::new();
    let mut field_count: usize = 0;
    loop {
        // 请求体空闲超时（轮 2 F6）：头读超时只覆盖请求头阶段，慢滴 body
        // 可无限占用并发闸（每 chunk 1 字节/数秒即绕过任何总量上限）。
        let mut field = match tokio::time::timeout(BODY_IDLE_TIMEOUT, mp.next_field()).await {
            Ok(Ok(Some(f))) => f,
            Ok(Ok(None)) => break,
            Ok(Err(_)) => {
                return (StatusCode::BAD_REQUEST, "multipart 解析失败").into_response();
            }
            Err(_) => {
                return (StatusCode::REQUEST_TIMEOUT, "上传请求体空闲超时").into_response();
            }
        };
        field_count += 1;
        if field_count > 1000 {
            // 轮 4 P2：字段数无上限——4GB 请求可拆出数千万个零字节文件字段
            //（每字段一个永久成品 + 数次系统调用），打满目录项。
            return (StatusCode::PAYLOAD_TOO_LARGE, "上传字段数超过 1000").into_response();
        }
        let Some(raw_name) = field.file_name().map(String::from) else {
            continue; // 非文件字段
        };
        let Ok(name) = sanitize_name(&raw_name) else {
            return (StatusCode::BAD_REQUEST, "非法文件名").into_response();
        };
        // 唯一半成品 + 流式落盘（防半截上传出现在最终名上）。
        let mut rnd = [0u8; 4];
        OsRng.fill_bytes(&mut rnd);
        let p = Path::new(&name);
        let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
        let ext = p.extension().and_then(|s| s.to_str()).map(|e| format!(".{e}")).unwrap_or_default();
        let part = dest_dir.join(format!("{stem}.up{:08x}{ext}.part", u32::from_le_bytes(rnd)));
        let mut out = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)
            .await
        {
            Ok(f) => f,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "无法写入目标目录").into_response(),
        };
        // Drop 守卫（轮 3 P3-11）：handler 被取消/abort 时清理分支不执行——
        // 半成品 .part 不在任何清扫器覆盖内，必须由守卫兜底。
        struct PartCleanup(std::path::PathBuf);
        impl Drop for PartCleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _part_guard = PartCleanup(part.clone());
        let mut written: u64 = 0;
        let mut too_big = false;
        use tokio::io::AsyncWriteExt as _;
        loop {
            match tokio::time::timeout(BODY_IDLE_TIMEOUT, field.chunk()).await {
                Ok(Ok(Some(chunk))) => {
                    written += chunk.len() as u64;
                    if written > st.max_upload_bytes {
                        too_big = true;
                        break; // 停止读该字段，统一清理后回 413
                    }
                    if out.write_all(&chunk).await.is_err() {
                        let _ = tokio::fs::remove_file(&part).await;
                        return (StatusCode::INTERNAL_SERVER_ERROR, "写入失败").into_response();
                    }
                }
                Ok(Ok(None)) => break,
                Ok(Err(_)) => {
                    let _ = tokio::fs::remove_file(&part).await;
                    return (StatusCode::BAD_REQUEST, "上传中断").into_response();
                }
                Err(_) => {
                    // 空闲超时：断开并清理（闸随连接释放）。
                    let _ = tokio::fs::remove_file(&part).await;
                    return (StatusCode::REQUEST_TIMEOUT, "上传请求体空闲超时").into_response();
                }
            }
        }
        drop(out);
        if too_big {
            let _ = tokio::fs::remove_file(&part).await;
            return (StatusCode::PAYLOAD_TOO_LARGE, "单文件超过 2GB 上限").into_response();
        }
        // 冲突命名：hard_link fail-if-exists + 冲突名循环重取（轮 2 P3：与 core
        // publish_part 同纪律——rename 在 Windows 上会静默覆盖，且 exists/rename
        // 之间存在 TOCTOU）。
        let mut published: Option<std::path::PathBuf> = None;
        for i in 0..10000u32 {
            let cand = if i == 0 {
                dest_dir.join(&name)
            } else {
                dest_dir.join(format!("{stem}_{i}{ext}"))
            };
            match tokio::fs::hard_link(&part, &cand).await {
                Ok(()) => {
                    published = Some(cand);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => break, // 卷不支持硬链接 → 走下方独占创建退化路径
            }
        }
        let final_path = match published {
            Some(p) => p,
            None => {
                // 退化路径：create_new 独占 + 拷贝（fail-if-exists 语义不变）。
                let mut done: Option<std::path::PathBuf> = None;
                for i in 0..10000u32 {
                    let cand = if i == 0 {
                        dest_dir.join(&name)
                    } else {
                        dest_dir.join(format!("{stem}_{i}{ext}"))
                    };
                    let Ok(mut dst) = tokio::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&cand)
                        .await
                    else {
                        continue;
                    };
                    let ok = async {
                        let mut src = tokio::fs::File::open(&part).await?;
                        tokio::io::copy(&mut src, &mut dst).await?;
                        dst.sync_all().await?;
                        Ok::<(), std::io::Error>(())
                    }
                    .await;
                    drop(dst);
                    if ok.is_ok() {
                        done = Some(cand);
                    } else {
                        let _ = tokio::fs::remove_file(&cand).await;
                        return (StatusCode::INTERNAL_SERVER_ERROR, "发布失败").into_response();
                    }
                    break;
                }
                match done {
                    Some(p) => p,
                    None => {
                        let _ = tokio::fs::remove_file(&part).await;
                        return (StatusCode::INTERNAL_SERVER_ERROR, "发布失败").into_response();
                    }
                }
            }
        };
        let _ = tokio::fs::remove_file(&part).await;
        saved.push(final_path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
    }
    if saved.is_empty() {
        return (StatusCode::BAD_REQUEST, "没有收到文件字段").into_response();
    }
    (StatusCode::SEE_OTHER, [("Location", format!("/view/{}", url_escape(path)))], format!("已接收 {} 个文件", saved.len()))
        .into_response()
}

// ============ 删除（无 JS 确认页 + CSRF 双重校验） ============

fn csrf_of(st: &WebState, headers: &HeaderMap) -> Option<String> {
    let _ = st;
    cookie_of(headers, CSRF_COOKIE)
}

async fn delete_confirm(
    State(st): State<Arc<WebState>>,
    AxPath(path): AxPath<String>,
    headers: HeaderMap,
) -> Response {
    let full = match resolve_under(&st.dir, &path) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    if !full.is_file() {
        return (StatusCode::NOT_FOUND, "文件不存在").into_response();
    }
    // CSRF Cookie 懒签发（无鉴权模式无登录发糖点）：缺失即签发并注入确认页。
    let (csrf, set_cookie) = match csrf_of(&st, &headers) {
        Some(c) => (c, None),
        None => {
            let c = rand_hex32();
            (c.clone(), Some(format!("{CSRF_COOKIE}={c}; HttpOnly; SameSite=Strict; Path=/")))
        }
    };
    let mut page = Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>确认删除</title></head>\
         <body style=\"font-family:sans-serif;max-width:32rem;margin:10vh auto\">\
         <h1>确认删除</h1><p>将删除文件：<code>{}</code>（不可恢复）</p>\
         <form method=\"post\" action=\"/del/{}\">\
         <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
         <button type=\"submit\">确认删除</button>\
         <a href=\"/view/{}\" style=\"margin-left:1rem\">取消</a>\
         </form></body></html>",
        html_escape(&path),
        url_escape(&path),
        html_escape(&csrf),
        url_escape(Path::new(&path).parent().map(|p| p.to_string_lossy()).unwrap_or_default().trim_matches('/')),
    ))
    .into_response();
    if let Some(sc) = set_cookie {
        page.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&sc).unwrap_or(HeaderValue::from_static("")),
        );
    }
    page
}

async fn delete_submit(
    State(st): State<Arc<WebState>>,
    AxPath(path): AxPath<String>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let full = match resolve_under(&st.dir, &path) {
        Ok(f) => f,
        Err(e) => return e.into_response(),
    };
    // CSRF 双重校验：表单字段必须与会话 Cookie 一致（规格 §3.4）。
    let cookie_csrf = csrf_of(&st, &headers).unwrap_or_default();
    let form_csrf = parse_form(&body)
        .into_iter()
        .find(|(k, _)| k == "csrf")
        .map(|(_, v)| v)
        .unwrap_or_default();
    let csrf_ok = !cookie_csrf.is_empty()
        && trft_core::crypto::kdf::ct_eq(
            &trft_core::hash::sha256(cookie_csrf.as_bytes()),
            &trft_core::hash::sha256(form_csrf.as_bytes()),
        );
    if !csrf_ok {
        return (StatusCode::FORBIDDEN, "CSRF 校验失败").into_response();
    }
    if full.is_dir() {
        return (StatusCode::BAD_REQUEST, "仅支持删除单个文件").into_response();
    }
    match tokio::fs::remove_file(&full).await {
        Ok(()) => {
            let parent = Path::new(&path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            Redirect::to(&format!("/view/{}", url_escape(parent.trim_matches('/')))).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "删除失败").into_response(),
    }
}

// ============ 编码工具 ============

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn url_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ============ 连接级 serve（规格 §6.1 头读超时 15s，轮 2 P1） ============

/// Web 上传半成品（`.up*.part`）孤儿清扫（轮 5 P2-2）：Drop 守卫只覆盖
/// handler 正常返回/panic/cancel；进程被强杀/崩溃时守卫不执行——TCP/UDP/
/// 续传半成品均有 7 天孤儿清扫兜底（「与进程被杀同口径」），Web 上传半成品
/// 此前不在任何清扫器覆盖内，落在用户共享目录永久残留。启动时按 7 天清扫
///（与 core `cleanup_part_orphans` 同口径；深度封顶防符号链接环）。
/// 上传半成品文件名判定（轮 8 P3-2）：`{stem}.up{8hex}{ext}.part`——
/// 与 upload_impl 的自产名严格同形。
fn is_upload_part_name(name: &str) -> bool {
    let Some(dot) = name.rfind(".up") else { return false };
    let after = &name[dot + 3..];
    // 自产形：".up" + 8 位 hex + ext（空或 ".xxx" 单段）+ ".part" 结尾。
    if after.len() < 8 || !after[..8].chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    let Some(stripped) = after[8..].strip_suffix(".part") else { return false };
    stripped.is_empty()
        || (stripped.starts_with('.') && !stripped[1..].contains('.'))
}

pub fn cleanup_upload_orphans(dir: &std::path::Path) {
    fn walk(dir: &std::path::Path, depth: u32) {
        if depth > 6 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        let now = std::time::SystemTime::now();
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, depth + 1);
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            // 上传半成品形态："{stem}.up{8 位 hex}{ext}.part"——按自产格式收紧
            // （轮 8 P3-2：宽松的 contains(".up") 理论上可误删形如
            // my.uploader.part 的用户文件）。
            if !is_upload_part_name(&name) {
                continue;
            }
            if let Ok(md) = e.metadata() {
                if md
                    .modified()
                    .map(|t| now.duration_since(t).map(|d| d > std::time::Duration::from_secs(7 * 24 * 3600)).unwrap_or(false))
                    .unwrap_or(false)
                {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
    }
    walk(dir, 0);
}

/// axum::serve 的替代：手动 serve 每条连接并设置 hyper `header_read_timeout`——
/// 慢速只发半个请求头的连接 15 秒后被掐断，32 个并发闸不再能被永久占满。
/// main 与 GUI 共享同一入口（行为一致）。
/// - 轮 4 F1：**必须配 Timer**——hyper 在每次读请求头时无条件武装该超时，
///   无 Timer 时（`Time::Empty`）每个 HTTP/1 请求直接 panic（debug/release 双
///   实证：明文 Web 面整体不可用；此前被进程内 oneshot 测试缺口掩盖）。
/// - 轮 4 F2：不再用 `server-auto`（h2c prior-knowledge 绕过 h1 专属的
///   header_read_timeout 且无 idle 上限——静默 h2 连接永生）。目标客户端
///   （手机浏览器）明文下只走 HTTP/1，直接用 http1 Builder。
pub async fn serve_with_header_timeout(
    listener: tokio::net::TcpListener,
    router: axum::Router,
) -> std::io::Result<()> {
    use hyper::server::conn::http1;
    use hyper_util::rt::{TokioIo, TokioTimer};
    use tower::util::ServiceExt as _;
    loop {
        let (socket, remote_addr) = listener.accept().await?;
        let app = router.clone();
        tokio::spawn(async move {
            let service = hyper_util::service::TowerToHyperService::new(tower::service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| {
                let app = app.clone();
                async move {
                    let mut req = req.map(axum::body::Body::new);
                    req.extensions_mut()
                        .insert(axum::extract::ConnectInfo(remote_addr));
                    app.oneshot(req).await.map_err(|e| {
                        std::io::Error::other(format!("router 调用失败: {e}"))
                    })
                }
            }));
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(std::time::Duration::from_secs(15));
            let _ = builder.serve_connection(TokioIo::new(socket), service).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 轮 8 P3-2 判别：上传半成品判定与自产名严格同形——宽松匹配
    /// （contains(".up")）会误删形如 my.uploader.part 的用户文件。
    #[test]
    fn upload_part_name_matches_produced_shape_only() {
        // 自产名全命中。
        assert!(is_upload_part_name("a.up1a2b3c4d.txt.part"));
        assert!(is_upload_part_name("报表.updeadbeef.pdf.part"));
        assert!(is_upload_part_name("noext.up00000000.part"));
        // 用户文件不误伤。
        assert!(!is_upload_part_name("my.uploader.part"));
        assert!(!is_upload_part_name("up.part"));
        assert!(!is_upload_part_name("a.up123.txt.part"), "hex 段长度/边界不符");
        assert!(!is_upload_part_name("a.upzzzzzzzz.txt.part"), "非 hex");
        assert!(!is_upload_part_name("a.up1a2b3c4d.t.x.part"), "扩展名含点非自产形");
    }
}
