//! 统一错误类型。

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("协议错误: {0}")]
    Protocol(String),
    #[error("加密错误: {0}")]
    Crypto(String),
    #[error("对端拒绝: {0}")]
    Rejected(String),
    /// 对端是旧版本/未启用对应特性——发送方可据此走降级路径（规格 §1.4 向后兼容）。
    #[error("对端不支持: {0}")]
    Unsupported(String),
    #[error("认证失败: {0}")]
    AuthRejected(String),
    #[error("配置错误: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn proto<T: Into<String>>(msg: T) -> Error {
    Error::Protocol(msg.into())
}

pub fn crypto<T: Into<String>>(msg: T) -> Error {
    Error::Crypto(msg.into())
}

pub fn config_err<T: Into<String>>(msg: T) -> Error {
    Error::Config(msg.into())
}
