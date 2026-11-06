//! TrFileTransfer v2 GUI 库层。
//!
//! 模块置于 lib（bin 仅保留入口）——Tauri 2 推荐结构（移动端同源），同时让
//! `tests/` 集成测试可以触达命令层（队列持久化格式、SendRequest serde 契约）。

pub mod commands;
pub mod state;
pub mod tray;
