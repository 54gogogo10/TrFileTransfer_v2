//! 队列持久化格式互锁测试。
//!
//! `queue.txt` 一层格式、两套对齐逻辑：serde `rename_all = "camelCase"`（前端
//! persistQueue ↔ QueueItem）与 `parse_queue_text` 手工行解析的手写 JSON 键——
//! 历史两次事故都在这层（轮 7 P1 tab 分割持久化形同虚设；轮 7 F2/本轮
//! camelCase 缺失致队列 UDP 参数跨重启静默丢失）。round-trip + 键对齐双向钉死。

use trft_gui::commands::{migrate_queue_text, parse_queue_text, queue_items_to_text, QueueItem};

fn full_item() -> QueueItem {
    QueueItem {
        kind: "udpfile".into(),
        path: "D:\\测试\\中文.zip".into(),
        ip: Some("192.168.1.20".into()),
        port: Some(8080),
        proto: Some("udp".into()),
        code: Some("123456".into()),
        limit: Some(1024),
        nocompress: Some(true),
        noencrypt: Some(false),
        passes: Some(3),
        fec_parity: Some(4),
        nofec: Some(true),
        src_port: Some(50000),
    }
}

#[test]
fn round_trip_full_thirteen_fields() {
    let item = full_item();
    let text = queue_items_to_text(std::slice::from_ref(&item));
    assert_eq!(text.matches('|').count(), 12, "13 字段 = 12 个分隔符");
    assert!(text.ends_with('\n'));
    let parsed = parse_queue_text(&text);
    assert_eq!(parsed.len(), 1);
    let back: QueueItem = serde_json::from_value(parsed[0].clone()).unwrap();
    assert_eq!(back, item, "13 字段全量 round-trip 必须逐字段保真");
}

#[test]
fn round_trip_none_snapshot_fields() {
    // 无快照条目（旧行为）：全 None —— 序列化仍 13 段（空段占位），解析回 None。
    let item = QueueItem {
        kind: "file".into(),
        path: "C:\\a.bin".into(),
        ..Default::default()
    };
    let text = queue_items_to_text(std::slice::from_ref(&item));
    let parsed = parse_queue_text(&text);
    assert_eq!(parsed.len(), 1);
    // 全字段键都存在（None 显式化——前端恢复逻辑按 hasSnap 判定 ip/port/proto 存在性）。
    for k in [
        "kind",
        "path",
        "ip",
        "port",
        "proto",
        "code",
        "limit",
        "nocompress",
        "noencrypt",
        "passes",
        "fecParity",
        "nofec",
        "srcPort",
    ] {
        assert!(parsed[0].get(k).is_some(), "缺键 {k}");
    }
    let back: QueueItem = serde_json::from_value(parsed[0].clone()).unwrap();
    assert_eq!(back, item);
}

#[test]
fn serde_keys_align_with_frontend_persist_shape() {
    // 回归钉子：QueueItem 曾缺 #[serde(rename_all = "camelCase")]——前端发的
    // fecParity/srcPort 键静默落 None，队列 UDP 参数跨重启丢失。
    // 此处用前端 persistQueue 的**确切 JSON 形状**（含手工 camelCase 键）钉 serde 侧；
    // parse_queue_text 的手写键由 round-trip 两侧钉住。
    let frontend_shape = serde_json::json!({
        "kind": "udpfile",
        "path": "D:\\x.bin",
        "ip": "192.168.1.20",
        "port": 8080,
        "proto": "udp",
        "code": null,
        "limit": null,
        "nocompress": false,
        "noencrypt": false,
        "passes": 2,
        "fecParity": 3,
        "nofec": false,
        "srcPort": 51000,
    });
    let it: QueueItem = serde_json::from_value(frontend_shape).unwrap();
    assert_eq!(it.passes, Some(2), "passes 必须落位（camelCase 同名）");
    assert_eq!(
        it.fec_parity,
        Some(3),
        "fecParity ↔ fec_parity（历史事故点）"
    );
    assert_eq!(
        it.src_port,
        Some(51000),
        "srcPort ↔ src_port（本轮新增字段）"
    );
    assert_eq!(it.nofec, Some(false));
    // 键对齐全链路：JSON → 结构 → 行 → 解析 → JSON → 结构。
    let back: QueueItem = serde_json::from_value(
        parse_queue_text(&queue_items_to_text(std::slice::from_ref(&it)))[0].clone(),
    )
    .unwrap();
    assert_eq!(back, it);
}

#[test]
fn legacy_line_formats_parse_compatible() {
    // 2 字段旧行（轮 6 前格式）：仅 kind|path，快照缺省。
    let v = parse_queue_text("file|D:\\a.bin\n");
    assert_eq!(v.len(), 1);
    assert_eq!(v[0]["kind"], "file");
    assert!(v[0].get("ip").is_none(), "2 字段档不得伪造快照键");
    let it: QueueItem = serde_json::from_value(v[0].clone()).unwrap();
    assert_eq!(it.port, None);
    assert_eq!(it.src_port, None);

    // 12 字段档（轮 7 F2 格式）：UDP 三参数在、srcPort 键不存在。
    let v12 = parse_queue_text("udpfile|D:\\u.bin|10.0.0.2|9000|udp|||1|0|5|6|1\n");
    assert!(v12[0].get("srcPort").is_none(), "12 字段档不得伪造 srcPort");
    assert_eq!(v12[0]["passes"], 5);
    assert_eq!(v12[0]["fecParity"], 6);
    let it: QueueItem = serde_json::from_value(v12[0].clone()).unwrap();
    assert_eq!(it.nocompress, Some(true));
    assert_eq!(it.noencrypt, Some(false));
    assert_eq!(it.passes, Some(5));
    assert_eq!(it.fec_parity, Some(6));
    assert_eq!(it.nofec, Some(true));
    assert_eq!(it.src_port, None);
}

#[test]
fn defensive_write_side_skips_separator_pollution() {
    // 写侧防御：path/ip/code 含 `|` 的条目整行跳过（该字符 Windows 文件名非法，
    // 出现即为异常输入——宁少存不写坏行）。
    let text = queue_items_to_text(&[
        QueueItem {
            kind: "file".into(),
            path: "bad|name.bin".into(),
            ..Default::default()
        },
        QueueItem {
            kind: "file".into(),
            path: "ok.bin".into(),
            ip: Some("bad|ip".into()),
            ..Default::default()
        },
        QueueItem {
            kind: "file".into(),
            path: "good.bin".into(),
            ..Default::default()
        },
    ]);
    let parsed = parse_queue_text(&text);
    assert_eq!(parsed.len(), 1, "污染行必须整行跳过");
    assert_eq!(parsed[0]["path"], "good.bin");
}

#[test]
fn parse_takes_first_500_and_ignores_junk_lines() {
    assert!(
        parse_queue_text("\n  \nx\n").is_empty(),
        "空行与 <2 段行忽略"
    );
    let many = queue_items_to_text(&vec![
        QueueItem {
            kind: "file".into(),
            path: "p.bin".into(),
            ..Default::default()
        };
        600
    ]);
    assert_eq!(
        parse_queue_text(&many).len(),
        500,
        "解析层钳 500（与写侧上限同口径）"
    );
}

/// UDT/QUIC 拆分存量迁移（TECH-STACK §7.28）：旧格式行 proto "udt"（=QUIC 槽位）
/// → "quic" + 版本头；幂等（二次迁移不动）；新格式行 "udt"（真 UDT）不迁移。
#[test]
fn legacy_udt_proto_migrates_to_quic_once() {
    // 13 字段旧行：proto 在第 5 段（index 4）。
    let legacy = "file|old.bin|192.168.1.5|8080|udt||1024|1|0|2|2|0|50000
";
    let migrated = migrate_queue_text(legacy);
    assert!(
        migrated.starts_with(
            "#trft-queue-v2
"
        ),
        "迁移必须加版本头"
    );
    let parsed = parse_queue_text(&migrated);
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["proto"], "quic", "存量 udt 必须迁移为 quic");
    // 幂等：带版本头的迁移结果二次迁移原样。
    assert_eq!(migrate_queue_text(&migrated), migrated);
    // 新格式（真 UDT 条目）不迁移。
    let fresh = format!(
        "#trft-queue-v2
{}
",
        legacy
    );
    assert_eq!(
        migrate_queue_text(&fresh),
        fresh,
        "带版本头的新文件不得再迁移"
    );
    let real_udt = "file|new.bin|192.168.1.6|8080|udt||1024|1|0|2|2|0|50000
";
    let fresh2 = format!(
        "#trft-queue-v2
{}
",
        real_udt
    );
    assert_eq!(
        migrate_queue_text(&fresh2),
        fresh2,
        "版本头之下 udt 即真 UDT"
    );
    // 旧格式但 proto 非 udt（tcp/udp）不误伤。
    let tcp = "file|a.bin|192.168.1.7|8080|tcp||1024|1|0|2|2|0|50000
";
    let m2 = migrate_queue_text(tcp);
    assert!(m2.contains("|tcp|"), "tcp 行不迁移");
}
