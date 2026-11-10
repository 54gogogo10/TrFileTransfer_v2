//! 配置持久化（规格 §3.8：键值文件；.tmp → .bak → 原子换入自愈；
//! 主文件缺失视为用户重置，不回退 .bak）。

use crate::error::{config_err, Error, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DuplicatePolicy {
    #[default]
    Rename,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ConfirmMode {
    #[default]
    Off,
    Unknown,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FilterMode {
    #[default]
    Off,
    Allow,
    Deny,
}

/// 应用数据根目录（`%AppData%\TrFileTransfer` / XDG 等价；规格 §8.1）。
pub fn app_data_dir() -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        return PathBuf::from(appdata).join("TrFileTransfer");
    }
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("TrFileTransfer")
}

fn default_save_dir(sub: &str) -> PathBuf {
    app_data_dir().join(sub)
}

/// 键名与规格书 §12.1 附录对齐（Rust 命名为 snake_case）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub language: String,
    pub theme: String,
    pub server_port_tcp: u16,
    pub server_port_quic: u16,
    pub server_port_udt: u16,
    pub server_port_udp: u16,
    pub save_dir_tcp: PathBuf,
    pub save_dir_quic: PathBuf,
    pub save_dir_udt: PathBuf,
    pub save_dir_udp: PathBuf,
    pub http_port: u16,
    pub discovery_port: u16,
    pub pairing_code: Option<String>,
    pub pairing_length: u8,
    pub confirm_receive: ConfirmMode,
    pub ip_filter_mode: FilterMode,
    pub ip_filter_list: Vec<String>,
    pub per_device_folder: bool,
    pub duplicate_files: DuplicatePolicy,
    pub speed_limit: u64,
    pub recv_speed_limit: u64,
    pub hash_cache_days: u32,
    pub sync_verify_content: bool,
    pub udp_passes: u32,
    pub udp_fec: bool,
    pub udp_fec_parity: u8,
    pub auto_archive: bool,
    pub notify_enabled: bool,
    /// 完成提示音（规格 §12.1 NotifySound；NotifyEnabled 的子开关）。
    pub notify_sound: bool,
    /// 自动升级清单 URL（规格 §12.1 UpdateUrl；None = 不检查）。
    pub update_url: Option<String>,
    /// 共享二维码的网卡地址记忆（规格 §12.1 QrAddress）。
    pub qr_address: Option<String>,
    /// 防火墙放行提示已展示过一次（规格 §3.7：首次成功启动服务器展示一次）。
    pub firewall_hinted: bool,
    /// 「跳过此版本」记忆（规格 §3.7 自动升级；值为被跳过的版本号）。
    pub skip_version: Option<String>,
    /// `?t=` 令牌派生密钥（64 hex，M6' 轮 6 P2-4；缺省首启生成）。
    pub token_secret: Option<String>,
    /// 发送队列失败自动重试次数（规格 §3.2/§12.1 QueueRetries：0–5，默认 1；
    /// 轮 6 P2-3 补齐——此前队列失败仅记日志继续，无重试）。
    pub queue_retries: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            language: "zh".into(),
            theme: "system".into(),
            server_port_tcp: 8080,
            server_port_quic: 8080,
            server_port_udt: 8080,
            server_port_udp: 8080,
            save_dir_tcp: default_save_dir("tcp"),
            save_dir_quic: default_save_dir("quic"),
            save_dir_udt: default_save_dir("udt"),
            save_dir_udp: default_save_dir("udp"),
            http_port: 8090,
            discovery_port: 45000,
            pairing_code: None,
            pairing_length: 6,
            confirm_receive: ConfirmMode::Off,
            ip_filter_mode: FilterMode::Off,
            ip_filter_list: Vec::new(),
            per_device_folder: false,
            duplicate_files: DuplicatePolicy::Rename,
            speed_limit: 0,
            recv_speed_limit: 0,
            hash_cache_days: 7,
            sync_verify_content: false,
            udp_passes: 2,
            udp_fec: true,
            udp_fec_parity: 2,
            auto_archive: false,
            notify_enabled: true,
            notify_sound: true,
            update_url: None,
            qr_address: None,
            firewall_hinted: false,
            skip_version: None,
            token_secret: None,
            queue_retries: 1,
        }
    }
}

impl Config {
    /// 加载配置（规格 §3.8 备份自愈）：
    /// - 文件**缺失** → 默认值（视为用户重置，不回退）；
    /// - 主文件存在但**不可读**/**解析为空**/解析失败 → 回退 `.bak`（轮 6 P2-1：
    ///   此前仅 toml 语法错误路径回退——恰好是 .bak 存在目的的损坏场景
    ///   （截断成空文件、占用不可读）静默丢配置）。
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let main: Result<Self> = match std::fs::read_to_string(path) {
            // 解析为空（规格 §3.8）：保存中途截断的典型形态，视为损坏。
            Ok(text) if text.trim().is_empty() => Err(config_err("主文件为空（疑似保存中途截断）")),
            Ok(text) => toml::from_str::<Config>(&text)
                .map_err(|e| config_err(format!("config 解析失败: {e}")))
                .and_then(|c| c.validate()),
            Err(e) => Err(config_err(format!("主文件不可读: {e}"))),
        };
        match main {
            Ok(c) => Ok(c),
            Err(main_err) => {
                let bak = path.with_extension("bak");
                if bak.exists() {
                    let bak_text = std::fs::read_to_string(&bak)?;
                    let c: Config = toml::from_str(&bak_text).map_err(|e2| {
                        config_err(format!("主文件损坏（{main_err}）且 .bak 无法解析: {e2}"))
                    })?;
                    c.validate()
                } else {
                    Err(main_err)
                }
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self).map_err(|e| config_err(e.to_string()))?;
        atomic_write(path, text.as_bytes())
    }

    /// fail-closed：非法值宁可报错也不带病运行。
    pub fn validate(&self) -> Result<Self> {
        if let Some(code) = &self.pairing_code {
            let n = code.chars().count();
            if !(4..=12).contains(&n) || !code.chars().all(|c| c.is_ascii_digit()) {
                return Err(config_err("配对码必须是 4–12 位数字"));
            }
        }
        if !(4..=12).contains(&self.pairing_length) {
            return Err(config_err("pairing_length 必须在 4–12 之间"));
        }
        Ok(self.clone())
    }
}

/// `?t=` 令牌派生密钥生成（64 hex；轮 6 P2-4）。
pub fn new_token_secret() -> String {
    use rand_core::RngCore;
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut b);
    crate::hash::hex(&b)
}

/// 现文件 → `.bak`（同样走 `.tmp` 原子换入，防撕裂备份）→ 主文件原子换入。
/// 注意：`.bak` 只在此处生成一次；`write_atomic` 内部**不再**做第二份 copy
/// （本轮 F9：旧实现里 `.bak` 被写两遍，且注释宣称"非裸 copy"而实现是 copy）。
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    if path.exists() {
        let old = std::fs::read(path)?;
        write_atomic(&path.with_extension("bak"), &old)?;
    }
    // Windows 上杀软/索引器会短暂锁定刚写入的文件：重试一次（间隔 100ms）。
    match write_atomic(path, data) {
        Ok(()) => Ok(()),
        Err(Error::Io(e)) if matches!(e.raw_os_error(), Some(32) | Some(5)) => {
            std::thread::sleep(std::time::Duration::from_millis(100));
            write_atomic(path, data)
        }
        Err(e) => Err(e),
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(p) = parent {
        std::fs::create_dir_all(p)?;
    }
    let dir = parent
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
    tmp.write_all(data)?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    // 备份由 `atomic_write` 统一生成（且是原子换入而非 copy）——此处不得再做
    // 第二份 copy：既重复写盘，也让"撕裂备份"重新出现（本轮 F9）。
    match tmp.persist(path) {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::Io(e.error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_config() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.toml");
        (dir, p)
    }

    #[test]
    fn roundtrip_preserves_values() {
        let (_d, p) = tmp_config();
        let mut c = Config::default();
        c.server_port_tcp = 9000;
        c.pairing_code = Some("123456".into());
        c.save(&p).unwrap();
        let c2 = Config::load(&p).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn corrupt_main_falls_back_to_bak() {
        let (_d, p) = tmp_config();
        let mut c = Config::default();
        c.server_port_tcp = 9100;
        c.save(&p).unwrap(); // 生成主文件
        c.server_port_tcp = 9200;
        c.save(&p).unwrap(); // 保存前把旧内容复制为 .bak（= 9100）
        std::fs::write(&p, "not toml {{{{").unwrap();
        let c2 = Config::load(&p).unwrap();
        assert_eq!(c2.server_port_tcp, 9100);
    }

    #[test]
    fn missing_main_is_user_reset() {
        let (_d, p) = tmp_config();
        assert_eq!(Config::load(&p).unwrap(), Config::default());
    }

    #[test]
    fn invalid_pairing_code_rejected() {
        let mut c = Config::default();
        c.pairing_code = Some("12ab".into());
        assert!(c.validate().is_err());
        c.pairing_code = Some("123".into());
        assert!(c.validate().is_err());
    }

    /// 轮 6 P2-1 判别：主文件**解析为空**（保存中途截断的典型形态）必须回退
    /// .bak（规格 §3.8）——修复前空文件被 serde(default) 解析为默认配置，
    /// 静默丢用户配置。
    #[test]
    fn empty_main_falls_back_to_bak() {
        let (_d, p) = tmp_config();
        let mut c = Config::default();
        c.server_port_tcp = 9100;
        c.save(&p).unwrap();
        c.server_port_tcp = 9200;
        c.save(&p).unwrap(); // .bak = 9100
        std::fs::write(&p, "").unwrap(); // 截断为空
        let c2 = Config::load(&p).unwrap();
        assert_eq!(
            c2.server_port_tcp, 9100,
            "空主文件必须回退 .bak（不得静默重置为默认）"
        );

        // 纯空白同理。
        std::fs::write(&p, "   \n\t\n").unwrap();
        let c3 = Config::load(&p).unwrap();
        assert_eq!(c3.server_port_tcp, 9100, "纯空白主文件同样按损坏处理");
    }
}
