//! SendRequest serde 契约测试：前端 `sendRequest` 构造对象的确切键形状 ↔ Rust 结构。
//! QueueItem camelCase 事故（键名错位 → serde 对缺失 Option 静默给 None）的同类
//! 风险在此钉住：srcPort/passes/fecParity 等键必须真实落位。

use trft_gui::commands::SendRequest;
use trft_gui::state::Proto;

fn base_json() -> serde_json::Value {
    serde_json::json!({
        "kind": "file",
        "path": "D:\\f.bin",
        "text": null,
        "ip": "192.168.1.20",
        "port": 8080,
        "proto": "tcp",
        "code": null,
        "limit": null,
        "chunks": null,
        "srcPort": null,
        "nocompress": false,
        "noencrypt": false,
        "passes": null,
        "fecParity": null,
        "nofec": false,
        "pin": null,
    })
}

#[test]
fn frontend_full_contract_deserializes() {
    let mut js = base_json();
    js["kind"] = "udpfile".into();
    js["proto"] = "udp".into();
    js["srcPort"] = 50000.into();
    js["passes"] = 2.into();
    js["fecParity"] = 3.into();
    js["nofec"] = true.into();
    js["limit"] = 512.into();
    let r: SendRequest = serde_json::from_value(js).unwrap();
    assert_eq!(
        r.src_port,
        Some(50000),
        "srcPort ↔ src_port（本轮新增接线）"
    );
    assert_eq!(r.passes, Some(2));
    assert_eq!(r.fec_parity, Some(3));
    assert_eq!(r.limit, Some(512));
    assert!(r.nofec);
    assert!(matches!(r.proto, Proto::Udp));
}

#[test]
fn missing_option_fields_default_to_none() {
    // 旧快照 / 精简 JSON：缺 Option 字段 = None（不得整包反序列化失败——
    // 轮 7 F13 同类：一个坏字段拖死整批）。
    let js = serde_json::json!({
        "kind": "file", "path": "p", "ip": "1.2.3.4", "port": 1,
        "proto": "tcp", "nocompress": false, "noencrypt": false, "nofec": false,
    });
    let r: SendRequest = serde_json::from_value(js).unwrap();
    assert_eq!(r.src_port, None);
    assert_eq!(r.code, None);
    assert_eq!(r.pin, None);
}

#[test]
fn display_name_three_shapes() {
    let mk = |path: Option<String>, text: Option<String>| SendRequest {
        kind: "file".into(),
        path,
        text,
        ip: "1.2.3.4".into(),
        port: 8080,
        proto: Proto::Tcp,
        code: None,
        limit: None,
        chunks: None,
        src_port: None,
        nocompress: false,
        noencrypt: false,
        passes: None,
        fec_parity: None,
        nofec: false,
        pin: None,
    };
    assert_eq!(
        mk(Some("D:\\a\\报告终稿.zip".into()), None).display_name(),
        "报告终稿.zip"
    );
    assert!(
        mk(None, Some("hello 文本消息".into()))
            .display_name()
            .starts_with("文本"),
        "文本任务显示名带前缀"
    );
    assert_eq!(
        mk(None, None).display_name(),
        "发送",
        "无路径无文本回落通用名"
    );
}
