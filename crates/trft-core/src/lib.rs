//! TrFileTransfer v2 核心库。
//!
//! 零 UI 依赖：GUI（Tauri）、CLI、Web 管理面共享同一逻辑层——对应
//! PRODUCT-SPEC.md §1.4「逻辑层与 UI 严格分层」的设计原则。

pub mod config;
pub mod crypto;
pub mod devices;
pub mod discovery;
pub mod error;
pub mod fec;
pub mod hash;
pub mod hashcache;
pub mod limiter;
pub mod monitor;
pub mod progress;
pub mod protocol;
pub mod scrub;
pub mod stats;
pub mod transfer;
pub mod update;
