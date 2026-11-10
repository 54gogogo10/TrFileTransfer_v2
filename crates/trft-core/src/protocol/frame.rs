//! TCP 帧类型常量、状态码与文件名净化。
//! 帧类型编号沿用规格书 §4.1 的产品语义；字节级布局见 docs/WIRE-PROTOCOL.md（权威）。

use crate::error::{proto, Result};

pub const T_SINGLE_FILE: u8 = 0x00;
pub const T_FOLDER: u8 = 0x01;
pub const T_CHUNKED: u8 = 0x02;
pub const T_RESUME_FILE: u8 = 0x03;
pub const T_RESUME_FOLDER: u8 = 0x04;
pub const T_PAIRING: u8 = 0x05;
pub const T_TEXT: u8 = 0x06;
/// 压缩协商（C→S）；S 接受回 0x18、拒绝回 STATUS_REJECT（认证后才接受）。
pub const T_COMPRESS: u8 = 0x08;
pub const T_COMPRESS_OK: u8 = 0x18;
pub const T_CAPABILITY: u8 = 0x0A; // 能力协商（S 回 0x1A + caps）
pub const T_COVERAGE_QUERY: u8 = 0x0B; // 分块覆盖率查询
pub const T_CHUNK_END: u8 = 0x0C; // 分块收尾标记
/// 通道绑定配对（M6'）：0x0D 宣告 → 0x1D 盐 → HMAC(K, salt‖证书指纹) → 0x01/0x00。
/// 仅 QUIC 槽位——双臂中继两腿证书必然不同，证明必败（WIRE-PROTOCOL.md §2.1）。
pub const T_PAIRING_BOUND: u8 = 0x0D;
/// 服务端→客户端应答帧：0x10 = 0x03 续传协商、0x11 = 0x04 清单位图、0x1A = 能力表、
/// 0x1D = 通道绑定配对的盐前导（兼作旧服务端判别——旧版对未知 0x0D 直接回 0x00）。
pub const R_RESUME_NEGO: u8 = 0x10;
pub const R_MANIFEST: u8 = 0x11;
pub const R_CAPABILITY: u8 = 0x1A;
pub const R_PAIRING_SALT: u8 = 0x1D;

pub const STATUS_OK: u8 = 0x01;
pub const STATUS_REJECT: u8 = 0x00;
/// 0x10/0x0C 专属状态：会话存在但尚未覆盖（客户端再查 0x0B 补发）。
pub const STATUS_INCOMPLETE: u8 = 0x02;

/// 能力位（0x1A caps）：bit0=0x02、bit1=0x0B（规格 §4.1 保留位）、bit2=0x03、bit3=0x04、bit4=0x08。
pub const CAP_CHUNKED: u8 = 1 << 0;
pub const CAP_COVERAGE: u8 = 1 << 1;
pub const CAP_RESUME_FILE: u8 = 1 << 2;
pub const CAP_RESUME_FOLDER: u8 = 1 << 3;
pub const CAP_COMPRESS: u8 = 1 << 4;

pub const MAX_NAME_LEN: usize = 1024;
pub const MAX_TEXT_LEN: usize = 1024 * 1024;
/// 规格 §6.1：单文件声明大小上限 1 PiB。
pub const MAX_TRANSFER_SIZE: u64 = 1 << 50;
/// 规格 §6.1：文件夹文件数上限（0x01）。
pub const MAX_FOLDER_FILES: usize = 1_000_000;
/// 0x02 块载荷上限（Rust v2；标准块 1 MiB，上限从宽防误伤）。
pub const MAX_CHUNK_PAYLOAD: u32 = 8 * 1024 * 1024;
/// 规格 §6.1：0x02/0x0B 合并区间上限（慢速 DoS 守卫）。
pub const MAX_MERGED_RANGES: usize = 8_192;
/// 0x04 清单项上限（Rust v2：位图内存有界；0x01 仍为 1,000,000）。
pub const MAX_MANIFEST_FILES: usize = 100_000;
/// 0x02 服务端会话表上限（与 UDP 会话表同源纪律）。
pub const MAX_CHUNK_SESSIONS: usize = 64;

/// Windows 保留设备名（不区分大小写，含带扩展名形式）。
const WINDOWS_RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// 危险 Unicode 格式字符（Cf）：RLO 等可视觉反转扩展名，诱导误开文件。
fn has_format_char(s: &str) -> bool {
    s.chars().any(|c| {
        let u = c as u32;
        matches!(u,
            0x200B..=0x200F   // ZWSP/ZWNJ/ZWJ/LRM/RLM
            | 0x202A..=0x202E // LRE/RLE/PDF/LRO/RLO
            | 0x2060..=0x2064 // WJ 等
            | 0xFEFF          // BOM
            | 0xFFF9..=0xFFFB // interlinear
        )
    })
}

fn check_segment(seg: &str, what: &str) -> Result<()> {
    if seg.is_empty() || seg == "." || seg == ".." || seg.contains(':') {
        return Err(proto(format!("{what} 含非法序列: {seg}")));
    }
    if seg.chars().any(|c| c.is_control()) || has_format_char(seg) {
        return Err(proto(format!("{what} 含控制/格式字符")));
    }
    // 尾点/尾空格会被 Win32 规范化掉，导致落盘名与校验名不一致。
    if seg.ends_with('.') || seg.ends_with(' ') {
        return Err(proto(format!("{what} 以点/空格结尾: {seg}")));
    }
    let stem = seg.split('.').next().unwrap_or("");
    if WINDOWS_RESERVED.contains(&stem.to_ascii_uppercase().as_str()) {
        return Err(proto(format!("{what} 使用 Windows 保留设备名: {stem}")));
    }
    Ok(())
}

/// 文件名净化：只接受裸文件名，拒绝路径分隔符、ADS 冒号、Windows 保留名、
/// 尾点/尾空格与控制/格式字符（规格 §5.1 路径穿越防线）。
pub fn sanitize_name(raw: &str) -> Result<String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(proto("文件名为空"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(proto(format!("文件名超过 {MAX_NAME_LEN} 字节")));
    }
    if name == "."
        || name == ".."
        || name.contains("..")
        || name.contains('/')
        || name.contains('\\')
    {
        return Err(proto(format!("文件名含非法序列: {raw}")));
    }
    check_segment(name, "文件名")?;
    Ok(name.to_string())
}

/// 文件夹内相对路径净化：'/' 分段，拒绝绝对路径、`..`、反斜杠与盘符（规格 §5.1 路径穿越防线）。
pub fn sanitize_rel(rel: &str) -> Result<std::path::PathBuf> {
    if rel.is_empty() {
        return Err(proto("相对路径为空"));
    }
    if rel.len() > 4096 {
        return Err(proto("相对路径过长"));
    }
    if rel.contains('\\') || rel.contains('\0') {
        return Err(proto("相对路径含非法字符"));
    }
    let mut out = std::path::PathBuf::new();
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(proto(format!("相对路径含非法段: {rel}")));
        }
        if seg.len() > 255 {
            return Err(proto("路径段超过 255 字节"));
        }
        check_segment(seg, "相对路径段")?;
        out.push(seg);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal() {
        assert!(sanitize_name("../etc/passwd").is_err());
        assert!(sanitize_name("a\\b").is_err());
        assert!(sanitize_name("a/b").is_err());
        assert!(sanitize_name("..").is_err());
        assert!(sanitize_name("").is_err());
    }

    #[test]
    fn rejects_ads_and_windows_traps() {
        // NTFS 备用数据流（可抹 Mark-of-the-Web）
        assert!(sanitize_name("payload.exe:Zone.Identifier").is_err());
        assert!(sanitize_name("a:b").is_err());
        // Windows 保留设备名（含带扩展名形式）
        assert!(sanitize_name("NUL").is_err());
        assert!(sanitize_name("con.txt").is_err());
        assert!(sanitize_name("COM1.log").is_err());
        // 尾点会被 Win32 规范化 → 拒绝；尾空格被 trim 归一化 → 落盘为 "foo"
        assert!(sanitize_name("foo.").is_err());
        assert_eq!(sanitize_name("foo ").unwrap(), "foo");
        // RLO 视觉反转
        assert!(sanitize_name("\u{202E}exe.jpg").is_err());
    }

    #[test]
    fn accepts_normal_and_chinese() {
        assert_eq!(sanitize_name("报告 v2.pdf").unwrap(), "报告 v2.pdf");
        assert_eq!(
            sanitize_name("v1.2.final.tar.gz").unwrap(),
            "v1.2.final.tar.gz"
        );
    }

    #[test]
    fn rel_rejects_traversal_and_absolute() {
        assert!(sanitize_rel("../x").is_err());
        assert!(sanitize_rel("a/../b").is_err());
        assert!(sanitize_rel("a\\b").is_err());
        assert!(sanitize_rel("C:/x").is_err());
        assert!(sanitize_rel("/abs").is_err());
        assert!(sanitize_rel("").is_err());
        assert!(sanitize_rel("a//b").is_err());
        assert!(sanitize_rel("docs/NUL.png").is_err());
    }

    #[test]
    fn rel_accepts_nested() {
        assert_eq!(
            sanitize_rel("docs/图纸 v2/最终.png").unwrap(),
            std::path::PathBuf::from("docs")
                .join("图纸 v2")
                .join("最终.png")
        );
    }
}
