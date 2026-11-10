//! 设备记忆与发现共享层（规格 §3.3：已知设备 `Name|Ip|Port|flags`，上限 10 条）。
//!
//! 从 GUI 层下沉（M5'）：接收侧 `ConfirmReceive`（判「已知设备」）与
//! `PerDeviceFolder`（按记忆名解析落盘目录）都需要在 core 内读取设备记忆，
//! 而传输帧不携带设备名——名字仅来自 discovery 0xD1/0xD2 应答与发送成功记忆。
//! 持久化 `devices.json`，进程内 `DeviceStore` 快照供接收器热读。

use crate::error::{config_err, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;

/// 已知设备上限（规格 §3.3）；按 last_seen 淘汰。
pub const DEVICE_CAP: usize = 10;

/// 记录来源（轮 2 安全分级）：**is_known 只信任 Transfer/User**——
/// 0xD2 发现应答无认证（局域网任何人可广播伪造），不得作为
/// ConfirmReceive=unknown 的「已知设备」依据（TECH-STACK §7.12）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DeviceSource {
    /// discovery 0xD2 应答（未认证——仅供展示/命名）。
    #[default]
    Discovery,
    /// 成功传输记忆（收发任一侧实际完成）。
    Transfer,
    /// 用户手工固定（前端手动记录）。
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    pub ip: String,
    pub port: u16,
    /// "tcp" | "quic" | "udt"（拆分前存量 "udt" 于 load 时迁移为 "quic"）
    pub proto: String,
    pub needs_pairing: bool,
    pub last_seen: u64,
    /// 记录来源（旧 devices.json 无此字段 → 反序列化为 Discovery，保守方向）。
    #[serde(default)]
    pub source: DeviceSource,
}

pub fn devices_path() -> PathBuf {
    crate::config::app_data_dir().join("devices.json")
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 记录/更新一台设备（按 IP 去重、保留已知名、未知名回退 IP、超限按 last_seen 淘汰）。
/// 来源只升不降：Discovery 不得覆盖已有的 Transfer/User（轮 2 防污染）。
pub fn upsert(list: &mut Vec<DeviceInfo>, mut d: DeviceInfo) {
    d.last_seen = now_secs();
    if let Some(old) = list.iter_mut().find(|x| x.ip == d.ip) {
        // 只有「真实名字」（非空且非 IP 回退）才覆盖记忆名——匿名重记录
        // （如仅发送成功记忆）不得清空已知名（修复自 GUI 版的清名缺陷）。
        if !d.name.is_empty() && d.name != d.ip {
            old.name = d.name.clone();
        }
        old.port = d.port;
        old.proto = d.proto.clone();
        old.needs_pairing = d.needs_pairing;
        old.last_seen = d.last_seen;
        if old.source == DeviceSource::Discovery || d.source != DeviceSource::Discovery {
            old.source = d.source;
        }
    } else {
        if d.name.is_empty() {
            d.name = d.ip.clone(); // 未知名回退 IP（规格 §3.3）
        }
        list.push(d);
    }
    if list.len() > DEVICE_CAP {
        list.sort_by_key(|x| std::cmp::Reverse(x.last_seen));
        list.truncate(DEVICE_CAP);
    }
}

/// 进程内设备记忆（GUI 持有并共享给接收器；写穿持久化，读走内存快照）。
pub struct DeviceStore {
    inner: Mutex<Vec<DeviceInfo>>,
    path: Option<PathBuf>,
}

impl std::fmt::Debug for DeviceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceStore")
            .field("devices", &self.inner.lock().map(|l| l.len()).unwrap_or(0))
            .field("path", &self.path)
            .finish()
    }
}

impl DeviceStore {
    /// 从磁盘加载（文件缺失/损坏 = 空表——记忆属可再生数据）。
    /// 存量迁移（TECH-STACK §7.28）：UDT/QUIC 槽位拆分前写入的 `"udt"` 全部实为
    /// QUIC 槽位 → 首次加载一次性改写为 `"quic"` 并落盘；此后 `"udt"` 即真 UDT。
    pub fn load(path: PathBuf) -> Self {
        let list: Vec<DeviceInfo> = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let mut migrated = false;
        let list: Vec<DeviceInfo> = list
            .into_iter()
            .map(|mut d| {
                if d.proto == "udt" {
                    d.proto = "quic".into();
                    migrated = true;
                }
                d
            })
            .collect();
        let store = Self {
            inner: Mutex::new(list),
            path: Some(path.clone()),
        };
        if migrated {
            store.persist(&store.snapshot());
        }
        store
    }

    /// 纯内存实例（测试用；不落盘）。
    pub fn in_memory() -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
            path: None,
        }
    }

    fn persist(&self, list: &[DeviceInfo]) {
        if let Some(p) = &self.path {
            if let Ok(text) = serde_json::to_string_pretty(list) {
                let _ = crate::config::atomic_write(p, text.as_bytes());
            }
        }
    }

    pub fn snapshot(&self) -> Vec<DeviceInfo> {
        self.inner.lock().expect("设备锁").clone()
    }

    pub fn upsert(&self, d: DeviceInfo) {
        // 锁内只改内存，persist（含 100ms 重试的文件 IO）放锁外——轮 3 P3。
        let snapshot = {
            let mut list = self.inner.lock().expect("设备锁");
            upsert(&mut list, d);
            list.clone()
        };
        self.persist(&snapshot);
    }

    pub fn remove(&self, ip: &str) -> Result<()> {
        let snapshot = {
            let mut list = self.inner.lock().expect("设备锁");
            list.retain(|d| d.ip != ip);
            list.clone()
        };
        self.persist(&snapshot);
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        let snapshot = {
            let mut list = self.inner.lock().expect("设备锁");
            list.clear();
            list.clone()
        };
        self.persist(&snapshot);
        Ok(())
    }

    /// 记忆名解析（规格 §3.3：已知设备按记忆名，未知 → None 由调用方回退 IP）。
    pub fn name_for(&self, ip: IpAddr) -> Option<String> {
        let list = self.inner.lock().expect("设备锁");
        list.iter()
            .find(|d| d.ip.parse::<IpAddr>().map(|x| x == ip).unwrap_or(false))
            .map(|d| d.name.clone())
            .filter(|n| !n.is_empty())
    }

    /// 「已知设备」判定（规格 §3.3 ConfirmReceive=unknown）。
    /// **只信任 Transfer/User 来源**——Discovery 记录未认证，不得绕过用户确认
    /// （轮 2 P1：伪造 0xD2 应答不得把自己洗成「已知」）。
    pub fn is_known(&self, ip: IpAddr) -> bool {
        self.name_for(ip).is_some()
            && self.inner.lock().expect("设备锁").iter().any(|d| {
                d.ip.parse::<IpAddr>().map(|x| x == ip).unwrap_or(false)
                    && d.source != DeviceSource::Discovery
            })
    }
}

/// CLI/外部写入入口（保持与旧 GUI 直写等价的行为）。
pub fn record_to_disk(path: &PathBuf, devices: Vec<DeviceInfo>) -> Result<()> {
    let mut list = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<Vec<DeviceInfo>>(&t).ok())
        .unwrap_or_default();
    for d in devices {
        upsert(&mut list, d);
    }
    write_to_disk(path, &list)
}

pub fn write_to_disk(path: &PathBuf, list: &[DeviceInfo]) -> Result<()> {
    let text = serde_json::to_string_pretty(list).map_err(|e| config_err(e.to_string()))?;
    crate::config::atomic_write(path, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(name: &str, ip: &str) -> DeviceInfo {
        DeviceInfo {
            name: name.into(),
            ip: ip.into(),
            port: 8080,
            proto: "tcp".into(),
            needs_pairing: false,
            last_seen: 0,
            source: DeviceSource::Transfer,
        }
    }

    #[test]
    fn upsert_dedupes_by_ip_and_keeps_known_name() {
        let mut list = Vec::new();
        upsert(&mut list, dev("pc-a", "192.168.1.5"));
        upsert(&mut list, dev("", "192.168.1.5")); // 同 IP 重记录
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "pc-a", "已有名字不得被 IP 回退覆盖");
        upsert(&mut list, dev("", "10.0.0.2"));
        assert_eq!(list[1].name, "10.0.0.2", "未知名回退 IP");
    }

    #[test]
    fn upsert_evicts_beyond_cap_by_last_seen() {
        let mut list = Vec::new();
        for i in 0..DEVICE_CAP {
            let mut d = dev(&format!("d{i}"), &format!("10.0.0.{i}"));
            d.last_seen = i as u64;
            list.push(d);
        }
        upsert(&mut list, dev("new", "10.9.9.9")); // now_secs 实际时间戳，必然最新
        assert_eq!(list.len(), DEVICE_CAP);
        assert!(list.iter().any(|d| d.ip == "10.9.9.9"), "新设备必须进入");
        assert!(list.iter().all(|d| d.ip != "10.0.0.0"), "最旧设备被淘汰");
    }

    #[test]
    fn store_resolves_names_by_ip() {
        let st = DeviceStore::in_memory();
        st.upsert(dev("客厅电脑", "192.168.1.7"));
        let ip: IpAddr = "192.168.1.7".parse().unwrap();
        assert_eq!(st.name_for(ip).as_deref(), Some("客厅电脑"));
        assert!(st.is_known(ip));
        let other: IpAddr = "192.168.1.8".parse().unwrap();
        assert_eq!(st.name_for(other), None);
        assert!(!st.is_known(other), "未知 IP 不得判为已知（fail-closed）");
    }

    /// 轮 2 P1 判别：伪造 0xD2（Discovery 来源）不得绕过 ConfirmReceive=unknown；
    /// 来源只升不降（Discovery 不得覆盖 Transfer/User）。
    #[test]
    fn discovery_records_never_count_as_known() {
        let st = DeviceStore::in_memory();
        let mut fake = dev("attacker", "10.9.9.9");
        fake.source = DeviceSource::Discovery;
        st.upsert(fake.clone());
        let ip: IpAddr = "10.9.9.9".parse().unwrap();
        assert_eq!(
            st.name_for(ip).as_deref(),
            Some("attacker"),
            "名字可用于展示/命名"
        );
        assert!(
            !st.is_known(ip),
            "Discovery 来源不得判为已知（fail-closed）"
        );
        // 同 IP 的成功传输记忆把来源升级为 Transfer → 才算已知。
        let mut ok = fake;
        ok.source = DeviceSource::Transfer;
        st.upsert(ok);
        assert!(st.is_known(ip));
        // Discovery 重放不得降级回 Discovery。
        st.upsert(dev("attacker2", "10.9.9.9")); // source 默认 Discovery
        assert!(st.is_known(ip), "来源只升不降");
    }

    #[test]
    fn store_persists_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("devices.json");
        let st = DeviceStore::load(p.clone());
        st.upsert(dev("nas", "10.1.1.1"));
        drop(st);
        let st2 = DeviceStore::load(p);
        assert_eq!(
            st2.name_for("10.1.1.1".parse().unwrap()).as_deref(),
            Some("nas")
        );
    }

    /// 拆分迁移判别（TECH-STACK §7.28）：存量 "udt"（=QUIC 槽位）首载一次性改写
    /// 为 "quic" 并落盘；改写后再载入不得二次迁移（"udt" 即真 UDT）。
    #[test]
    fn legacy_udt_proto_migrates_to_quic_once() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("devices.json");
        let legacy = r#"[{
            "name": "old-box", "ip": "10.0.0.9", "port": 8080,
            "proto": "udt", "needs_pairing": false, "last_seen": 1,
            "source": "Transfer"
        }]"#;
        std::fs::write(&p, legacy).unwrap();
        let st = DeviceStore::load(p.clone());
        assert_eq!(
            st.snapshot()[0].proto,
            "quic",
            "存量 udt 必须迁移为 quic（旧 UDT 实为 QUIC 槽位）"
        );
        drop(st);
        // 落盘后文件里已是 "quic"。
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("\"quic\""), "迁移必须写穿: {text}");
        assert!(!text.contains("\"udt\""));
    }
}
