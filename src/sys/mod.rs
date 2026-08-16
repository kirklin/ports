//! 平台相关的套接字枚举。

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::scan;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::scan;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn scan() -> std::io::Result<crate::model::Scan> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "ports 目前只支持 macOS 和 Linux",
    ))
}
