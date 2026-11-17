//! 发布改名（真机 B3 发现 F2）：Windows 的 `MoveFileExW` 必须带
//! `MOVEFILE_WRITE_THROUGH` 才保证目录项更新落盘——否则硬断电后数据在、
//! 名字丢（文件仍是 `.trft-part`，而发送端已收到「完成」）。
//!
//! - `move_noreplace`：目标存在即失败（对齐原 `hard_link` 的 fail-if-exists），
//!   成功后源已不存在（同一操作，不再分「链接 + 删源」两步）。
//! - `move_replace`：原子覆盖（0x04 同步语义）。

use std::path::Path;

#[cfg(windows)]
fn wide(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(windows)]
fn move_ex(from: &Path, to: &Path, replace: bool) -> std::io::Result<()> {
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    const REPLACE_EXISTING: u32 = 0x1;
    const WRITE_THROUGH: u32 = 0x8;
    let mut flags = WRITE_THROUGH;
    if replace {
        flags |= REPLACE_EXISTING;
    }
    let (f, t) = (wide(from), wide(to));
    let ok = unsafe { MoveFileExW(f.as_ptr(), t.as_ptr(), flags) };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// 目标存在则失败；成功即源已消失。
pub fn move_noreplace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        move_ex(from, to, false)
    }
    #[cfg(not(windows))]
    {
        std::fs::hard_link(from, to)?;
        std::fs::remove_file(from)
    }
}

/// 原子覆盖（目标可存在）。
pub fn move_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        move_ex(from, to, true)
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(from, to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn move_noreplace_fails_when_dest_exists() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        std::fs::write(&a, b"x").unwrap();
        std::fs::write(&b, b"y").unwrap();
        assert!(move_noreplace(&a, &b).is_err(), "目标存在必须失败（fail-if-exists）");
        assert!(a.exists() && b.exists());
        std::fs::remove_file(&b).unwrap();
        move_noreplace(&a, &b).unwrap();
        assert!(b.exists() && !a.exists(), "成功后源必须消失");
    }

    #[test]
    fn move_replace_overwrites() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        std::fs::write(&a, b"new").unwrap();
        std::fs::write(&b, b"old").unwrap();
        move_replace(&a, &b).unwrap();
        assert_eq!(std::fs::read(&b).unwrap(), b"new");
        assert!(!a.exists());
    }
}