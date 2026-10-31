//! TrFileTransfer v2 桌面 GUI（Tauri 2，M4'）。
//!
//! 桌面集成口径（规格 §3.7 / TECH-STACK §5）：关闭窗口 = 隐藏 + 保存配置；
//! 仅托盘菜单「退出」真退出。逻辑全部在 trft-core，本 crate 只做参数收集与事件转发。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;
mod tray;

use state::AppState;
use tauri::Manager;

fn main() {
    // WebView2 运行时检测与引导（规格 §8.2 / TECH-STACK §7.1：缺失环境首次启动引导安装）。
    #[cfg(windows)]
    if !webview2_check() {
        return;
    }

    let cfg_path = trft_core::config::app_data_dir().join("config.toml");
    // 轮 6 P2-2：load 失败静默回默认 = 安全面（配对码/IP 过滤/确认）静默降级。
    // 至少告警——损坏的 validate（如配对码 3 位）必须可见。
    let cfg = match trft_core::config::Config::load(&cfg_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[警告] 配置加载失败，已回退默认值（安全项=关闭状态）: {e}");
            Default::default()
        }
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(AppState::new(cfg, cfg_path))
        .invoke_handler(tauri::generate_handler![
            commands::get_app_state,
            commands::save_config,
            commands::list_addresses,
            commands::send_start,
            commands::send_chunked_start,
            commands::send_cancel,
            commands::send_queue,
            commands::sync_start,
            commands::recv_start,
            commands::recv_stop,
            commands::http_start,
            commands::http_stop,
            commands::qr_svg,
            commands::verify_start,
            commands::verify_stop,
            commands::update_check,
            commands::update_install,
            commands::open_path,
            commands::autostart_set,
            commands::autostart_get,
            commands::queue_load,
            commands::queue_save,
            commands::text_history_load,
            commands::text_history_clear,
            commands::devices_load,
            commands::devices_record,
            commands::devices_remove,
            commands::devices_clear,
            commands::discover_devices,
            commands::confirm_reply,
            commands::stats_summary,
            commands::stats_records,
            commands::stats_export_csv,
            commands::stats_clear,
            commands::monitor_start,
            commands::monitor_stop,
            commands::monitor_status,
        ])
        .setup(|app| {
            tray::create(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // 规格 §3.7：关闭窗口 = 隐藏 + 保存配置；最小化 = 隐藏到托盘（托盘常驻）。
            match event {
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    api.prevent_close();
                    if let Some(state) = window.app_handle().try_state::<AppState>() {
                        let _ = state.save_config();
                    }
                    let _ = window.hide();
                }
                tauri::WindowEvent::Resized(_) => {
                    if let Ok(true) = window.is_minimized() {
                        let _ = window.hide();
                    }
                }
                _ => {}
            }
        })
        .run(tauri::generate_context!())
        .expect("TrFileTransfer GUI 启动失败");
}

/// WebView2 运行时检测：注册表三处（HKLM/HKCU/WOW6432Node）任一有效 `pv` 即已安装。
/// 缺失时弹原生对话框引导下载 Bootstrapper（go.microsoft.com 官方短链）。
#[cfg(windows)]
fn webview2_check() -> bool {
    const KEY: &str = r"Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    for (hive, sub) in [
        (HKEY_LOCAL_MACHINE, KEY.to_string()),
        (HKEY_LOCAL_MACHINE, format!(r"SOFTWARE\WOW6432Node\{KEY}")),
        (HKEY_CURRENT_USER, KEY.to_string()),
    ] {
        if let Ok(k) = RegKey::predef(hive).open_subkey_with_flags(&sub, KEY_READ) {
            if let Ok(pv) = k.get_value::<String, _>("pv") {
                if !pv.is_empty() && pv != "0.0.0.0" {
                    return true;
                }
            }
        }
    }
    let yes = message_box(
        "TrFileTransfer 需要 Microsoft WebView2 运行时。\r\n\r\n是否打开官方下载页面？（安装后重新启动本程序）\r\n\r\nTrFileTransfer requires the Microsoft WebView2 Runtime.\r\nOpen the official download page now?",
        "WebView2 Runtime",
    );
    if yes {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", "", "https://go.microsoft.com/fwlink/p/?LinkId=2124703"])
            .spawn();
    }
    false
}

/// 原生 MessageBoxW（是/否）。true = 用户选择「是」。
#[cfg(windows)]
fn message_box(text: &str, caption: &str) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDYES, MB_ICONWARNING, MB_SETFOREGROUND, MB_YESNO,
    };
    let wide: Vec<u16> = text.encode_utf16().chain([0]).collect();
    let cap: Vec<u16> = caption.encode_utf16().chain([0]).collect();
    let r = unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide.as_ptr(),
            cap.as_ptr(),
            MB_ICONWARNING | MB_YESNO | MB_SETFOREGROUND,
        )
    };
    r == IDYES
}
