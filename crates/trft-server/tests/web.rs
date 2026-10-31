//! Web 管理面端到端测试（进程内 oneshot，规格 §3.4 验收矩阵）。

use std::sync::Arc;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;
use trft_server::{AuthConfig, WebState};

fn state_with_auth(dir: std::path::PathBuf, code: &str) -> Arc<WebState> {
    Arc::new(WebState::new(dir, Some(AuthConfig { pairing_code: code.to_string() })))
}

fn state_open(dir: std::path::PathBuf) -> Arc<WebState> {
    Arc::new(WebState::new(dir, None))
}

async fn send(app: axum::Router, req: Request) -> axum::http::Response<Body> {
    app.oneshot(req).await.unwrap()
}

async fn body_bytes(b: Body) -> Vec<u8> {
    b.collect().await.unwrap().to_bytes().to_vec()
}

fn req(method: &str, uri: &str) -> Request {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn req_with(method: &str, uri: &str, headers: &[(&str, &str)], body: Vec<u8>) -> Request {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::from(body)).unwrap()
}

#[tokio::test]
async fn health_is_open() {
    let dir = tempfile::tempdir().unwrap();
    let app = trft_server::build_router(state_with_auth(dir.path().to_path_buf(), "123456"));
    let res = send(app, req("GET", "/health")).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_redirects_without_session() {
    let dir = tempfile::tempdir().unwrap();
    let app = trft_server::build_router(state_with_auth(dir.path().to_path_buf(), "123456"));
    let res = send(app, req("GET", "/")).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "无会话必须重定向登录");
    assert_eq!(res.headers().get(header::LOCATION).unwrap(), "/login");
}

#[tokio::test]
async fn token_query_grants_access() {
    let dir = tempfile::tempdir().unwrap();
    // 端到端判别（轮 6 P2-1）：必须经 token_for 生成——此前测试手写哈希绕过
    // token_for，掩盖了 check_token 与 token_for 长度错开（扫码直连整链失效）。
    let secret = [7u8; 32];
    let app = trft_server::build_router(Arc::new(
        trft_server::WebState::with_token_secret(
            dir.path().to_path_buf(),
            Some(AuthConfig { pairing_code: "123456".into() }),
            secret,
        ),
    ));
    let token = trft_server::token_for(&secret, "123456");
    let res = send(app.clone(), req("GET", &format!("/?t={token}"))).await;
    assert_eq!(res.status(), StatusCode::OK, "?t= 有效令牌必须放行（token_for↔check_token 同链）");
    let res = send(app, req("GET", "/?t=deadbeef")).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "无效令牌必须拒绝");
}

#[tokio::test]
async fn login_flow_and_lockout() {
    let dir = tempfile::tempdir().unwrap();
    let app = trft_server::build_router(state_with_auth(dir.path().to_path_buf(), "123456"));
    // 错误码 → 401，累计 10 次后锁定。
    let mut last = None;
    for i in 0..10 {
        let res = send(
            app.clone(),
            req_with("POST", "/login", &[("content-type", "application/x-www-form-urlencoded")], b"code=000000".to_vec()),
        )
        .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "第 {i} 次错误码必须 401");
        last = Some(res);
    }
    let res = send(
        app.clone(),
        req_with("POST", "/login", &[("content-type", "application/x-www-form-urlencoded")], b"code=000000".to_vec()),
    )
    .await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS, "10 次失败必须锁定");
    let _ = last;

    // 锁定期间正确码也被拒（按 IP 计错语义，测试无 ConnectInfo 视为同一 IP）。
    let res = send(
        app.clone(),
        req_with("POST", "/login", &[("content-type", "application/x-www-form-urlencoded")], b"code=123456".to_vec()),
    )
    .await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn login_success_sets_session_cookie() {
    let dir = tempfile::tempdir().unwrap();
    let app = trft_server::build_router(state_with_auth(dir.path().to_path_buf(), "123456"));
    let res = send(
        app.clone(),
        req_with("POST", "/login", &[("content-type", "application/x-www-form-urlencoded")], b"code=123456".to_vec()),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let cookie = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect::<Vec<_>>()
        .join("; ");
    assert!(cookie.contains("trft_sid="), "必须发会话 Cookie: {cookie}");
    assert!(cookie.contains("HttpOnly"), "会话必须 HttpOnly");
    assert!(cookie.contains("SameSite=Strict"), "会话必须 SameSite=Strict");
    assert!(cookie.contains("trft_csrf="), "必须发 CSRF Cookie");

    // 会话放行。
    let sid_start = cookie.find("trft_sid=").unwrap() + "trft_sid=".len();
    let sid = cookie[sid_start..sid_start + 32].to_string();
    let res = send(
        app,
        req_with("GET", "/", &[("cookie", &format!("trft_sid={sid}"))], vec![]),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "有效会话必须放行");
}

#[tokio::test]
async fn security_headers_present() {
    let dir = tempfile::tempdir().unwrap();
    let app = trft_server::build_router(state_open(dir.path().to_path_buf()));
    let res = send(app, req("GET", "/health")).await;
    assert_eq!(res.headers().get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(res.headers().get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    let csp = res.headers().get(header::CONTENT_SECURITY_POLICY).unwrap().to_str().unwrap();
    assert!(csp.contains("default-src 'none'"), "CSP 必须默认拒绝: {csp}");
}

#[tokio::test]
async fn traversal_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let app = trft_server::build_router(state_open(dir.path().to_path_buf()));
    for uri in ["/view/../etc", "/view/a%2F..%2Fb", "/view/..%5C.."] {
        let res = send(app.clone(), req("GET", uri)).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{uri} 必须拒绝");
    }
}

#[tokio::test]
async fn download_range_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let data = b"0123456789abcdef";
    std::fs::write(dir.path().join("blob.bin"), data).unwrap();
    let app = trft_server::build_router(state_open(dir.path().to_path_buf()));

    // 全量：Content-Length + Accept-Ranges。
    let res = send(app.clone(), req("GET", "/dl/blob.bin")).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");
    assert_eq!(body_bytes(res.into_body()).await, data);

    // 单区间 206 + Content-Range。
    let res = send(app.clone(), req_with("GET", "/dl/blob.bin", &[("range", "bytes=2-5")], vec![])).await;
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(res.headers().get(header::CONTENT_RANGE).unwrap(), "bytes 2-5/16");
    assert_eq!(body_bytes(res.into_body()).await, &data[2..6]);

    // 后缀区间。
    let res = send(app.clone(), req_with("GET", "/dl/blob.bin", &[("range", "bytes=-4")], vec![])).await;
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(body_bytes(res.into_body()).await, &data[12..]);

    // 不可满足 → 416 + bytes */size。
    let res = send(app.clone(), req_with("GET", "/dl/blob.bin", &[("range", "bytes=999-")], vec![])).await;
    assert_eq!(res.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(res.headers().get(header::CONTENT_RANGE).unwrap(), "bytes */16");

    // 端点越界裁剪（RFC 容忍）。
    let res = send(app.clone(), req_with("GET", "/dl/blob.bin", &[("range", "bytes=10-999")], vec![])).await;
    assert_eq!(res.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(body_bytes(res.into_body()).await, &data[10..]);
}

#[tokio::test]
async fn html_force_attachment() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("page.html"), b"<h1>hi</h1>").unwrap();
    std::fs::write(dir.path().join("pic.svg"), b"<svg/>").unwrap();
    std::fs::write(dir.path().join("a.txt"), b"plain").unwrap();
    let app = trft_server::build_router(state_open(dir.path().to_path_buf()));
    for (f, inline) in [("page.html", false), ("pic.svg", false), ("a.txt", true)] {
        let res = send(app.clone(), req("GET", &format!("/dl/{f}"))).await;
        let cd = res.headers().get(header::CONTENT_DISPOSITION).unwrap().to_str().unwrap();
        assert_eq!(cd.starts_with("inline"), inline, "{f}: {cd}");
        assert!(cd.contains("filename*="), "RFC5987 filename* 必须存在: {cd}");
    }
}

#[tokio::test]
async fn upload_multipart_streaming() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("sub")).unwrap();
    let app = trft_server::build_router(state_open(dir.path().to_path_buf()));
    let boundary = "XyZZy123";
    let mut body = Vec::new();
    for (name, content) in [("a.txt", &b"hello upload"[..]), ("b.bin", &[1u8, 2, 3, 4, 5][..])] {
        body.extend_from_slice(format!("--{boundary}\r\ncontent-disposition: form-data; name=\"file\"; filename=\"{name}\"\r\ncontent-type: application/octet-stream\r\n\r\n").as_bytes());
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let res = send(
        app,
        req_with(
            "POST",
            "/up/sub",
            &[("content-type", &format!("multipart/form-data; boundary={boundary}"))],
            body,
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "上传必须成功");
    assert_eq!(std::fs::read(dir.path().join("sub/a.txt")).unwrap(), b"hello upload");
    assert_eq!(std::fs::read(dir.path().join("sub/b.bin")).unwrap(), &[1, 2, 3, 4, 5]);
}

#[tokio::test]
async fn upload_rejects_bad_name_and_oversize() {
    let dir = tempfile::tempdir().unwrap();
    let app = trft_server::build_router(state_open(dir.path().to_path_buf()));
    // 非法文件名（路径穿越）→ 400。
    let boundary = "XyZZy";
    let body = format!(
        "--{boundary}\r\ncontent-disposition: form-data; name=\"file\"; filename=\"..\\\\evil.txt\"\r\n\r\nx\r\n--{boundary}--\r\n"
    );
    let res = send(
        app.clone(),
        req_with(
            "POST",
            "/up/",
            &[("content-type", &format!("multipart/form-data; boundary={boundary}"))],
            body.into_bytes(),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "穿越文件名必须拒绝");
    // 超限（注入小上限）→ 413。
    let st = state_open(dir.path().to_path_buf());
    let mut st = Arc::try_unwrap(st).ok().unwrap();
    st.max_upload_bytes = 4;
    let app = trft_server::build_router(Arc::new(st));
    let body = format!(
        "--{boundary}\r\ncontent-disposition: form-data; name=\"file\"; filename=\"big.txt\"\r\n\r\n1234567\r\n--{boundary}--\r\n"
    );
    let res = send(
        app,
        req_with(
            "POST",
            "/up/",
            &[("content-type", &format!("multipart/form-data; boundary={boundary}"))],
            body.into_bytes(),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // 半成品不得残留。
    let leftover: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
    assert!(leftover.is_empty(), "上传失败路径不得残留: {:?}", leftover.iter().map(|e| e.file_name()).collect::<Vec<_>>());
}

#[tokio::test]
async fn upload_conflict_gets_suffixed_name() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dup.txt"), b"old").unwrap();
    let app = trft_server::build_router(state_open(dir.path().to_path_buf()));
    let boundary = "XyZZy";
    let body = format!(
        "--{boundary}\r\ncontent-disposition: form-data; name=\"file\"; filename=\"dup.txt\"\r\n\r\nnew\r\n--{boundary}--\r\n"
    );
    let res = send(
        app,
        req_with(
            "POST",
            "/up/",
            &[("content-type", &format!("multipart/form-data; boundary={boundary}"))],
            body.into_bytes(),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(std::fs::read(dir.path().join("dup.txt")).unwrap(), b"old", "既有文件不得被覆盖");
    assert_eq!(std::fs::read(dir.path().join("dup_1.txt")).unwrap(), b"new", "冲突名追加序号");
}

#[tokio::test]
async fn delete_flow_with_csrf() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("gone.txt"), b"bye").unwrap();
    let app = trft_server::build_router(state_open(dir.path().to_path_buf()));

    // 确认页 → 取 csrf。
    let res = send(app.clone(), req("GET", "/del/gone.txt")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = String::from_utf8(body_bytes(res.into_body()).await).unwrap();
    let csrf = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string();

    // 无 csrf → 403。
    let res = send(
        app.clone(),
        req_with("POST", "/del/gone.txt", &[("cookie", &format!("trft_csrf={csrf}"))], b"csrf=wrong".to_vec()),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "CSRF 双重校验必须拦截");
    assert!(dir.path().join("gone.txt").exists(), "被拦删除不得删文件");

    // 有 csrf（表单 + Cookie 一致）→ 303 → 文件删除。
    let res = send(
        app.clone(),
        req_with("POST", "/del/gone.txt", &[("cookie", &format!("trft_csrf={csrf}"))], format!("csrf={csrf}").into_bytes()),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(!dir.path().join("gone.txt").exists(), "确认后文件必须删除");
}

#[tokio::test]
async fn delete_refuses_directories() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub/x.txt"), b"x").unwrap();
    let app = trft_server::build_router(state_open(dir.path().to_path_buf()));
    let res = send(
        app,
        req_with("POST", "/del/sub", &[("cookie", "trft_csrf=c")], b"csrf=c".to_vec()),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "目录删除必须拒绝（仅单文件）");
    assert!(dir.path().join("sub/x.txt").exists());
}

#[tokio::test]
async fn chinese_filename_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let app = trft_server::build_router(state_open(dir.path().to_path_buf()));
    let boundary = "XyZZy";
    let body = format!(
        "--{boundary}\r\ncontent-disposition: form-data; name=\"file\"; filename=\"报告 v2.txt\"\r\n\r\n内容\r\n--{boundary}--\r\n"
    );
    let res = send(
        app.clone(),
        req_with(
            "POST",
            "/up/",
            &[("content-type", &format!("multipart/form-data; boundary={boundary}"))],
            body.into_bytes(),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "中文名必须可上传");
    assert!(dir.path().join("报告 v2.txt").exists());
    // 下载：RFC5987 filename*。
    let res = send(app.clone(), req("GET", "/dl/%E6%8A%A5%E5%91%8A%20v2.txt")).await;
    assert_eq!(res.status(), StatusCode::OK);
    let cd = res.headers().get(header::CONTENT_DISPOSITION).unwrap().to_str().unwrap();
    assert!(cd.contains("filename*=UTF-8''%E6%8A%A5%E5%91%8A%20v2.txt"), "RFC5987 编码: {cd}");
    assert_eq!(body_bytes(res.into_body()).await, b"\xE5\x86\x85\xE5\xAE\xB9");
}
