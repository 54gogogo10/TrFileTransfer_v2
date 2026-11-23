//! 扩展名排除（发送文件夹 / 监控扫描共用一套口径）。
//!
//! 归一化：去空白与前导点、转小写、丢弃空项与含路径/分隔符字面的项，去重。
//! 命中判定：取文件名的扩展名（`Path::extension`），大小写不敏感比较；无扩展名的
//! 文件（`noext`、`.hidden`）永不命中——排除项只描述扩展名，不冒充通配符。

use std::path::Path;

/// 归一化扩展名列表（配置 / CLI / UI 共用）。
/// 例：`[" .TMP ", "log", ""]` → `["tmp", "log"]`。
pub fn normalize_exts(raw: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in raw {
        let e = item.trim().trim_start_matches('.').to_ascii_lowercase();
        if e.is_empty() || e.contains(['/', '\\', ' ', ',', ';', '|']) {
            continue; // 误填路径/分隔符的项直接忽略，不让它变成永远不命中的规则
        }
        if !out.contains(&e) {
            out.push(e);
        }
    }
    out
}

/// 文件名是否命中排除扩展名（大小写不敏感；无扩展名不排除）。
pub fn ext_excluded(name: &str, exclude_exts: &[String]) -> bool {
    if exclude_exts.is_empty() {
        return false;
    }
    match Path::new(name).extension().and_then(|e| e.to_str()) {
        Some(ext) => {
            let ext = ext.to_ascii_lowercase();
            exclude_exts.iter().any(|x| x.eq_ignore_ascii_case(&ext))
        }
        None => false,
    }
}

/// 便捷入口：路径的文件名是否命中排除扩展名。
pub fn path_excluded(p: &Path, exclude_exts: &[String]) -> bool {
    match p.file_name().and_then(|n| n.to_str()) {
        Some(name) => ext_excluded(name, exclude_exts),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 判别：归一化口径（去点/大小写/去重/丢路径与分隔符项）与命中判定
    /// （大小写不敏感、无扩展名不受影响、空列表不排除）。
    #[test]
    fn normalize_and_match() {
        let exts = normalize_exts(&[
            " .TMP ".to_string(),
            "log".to_string(),
            "".to_string(),
            "tmp".to_string(),
            "a/b".to_string(),
            "a,b".to_string(),
        ]);
        assert_eq!(exts, vec!["tmp".to_string(), "log".to_string()]);

        assert!(ext_excluded("dropped.tmp", &exts));
        assert!(ext_excluded("dropped.LOG", &exts), "大小写不敏感");
        assert!(!ext_excluded("keep.bin", &exts));
        assert!(!ext_excluded("noext", &exts), "无扩展名文件不受影响");
        assert!(!ext_excluded(".hidden", &exts), "点开头视为无扩展名");
        assert!(!ext_excluded("keep.tmp", &[]), "空列表 = 不排除");
        assert!(
            !ext_excluded("keep.tmpx", &exts),
            "只看真实扩展名，不做前缀匹配"
        );

        assert!(path_excluded(Path::new(r"C:\drop\a.TMP"), &exts));
        assert!(!path_excluded(Path::new(r"C:\drop\a.bin"), &exts));
    }
}
