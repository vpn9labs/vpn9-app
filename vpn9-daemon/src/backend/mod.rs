#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub use linux::PlatformBackend;
#[cfg(target_os = "macos")]
pub use macos::PlatformBackend;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("vpn9-daemon currently supports only macOS and Linux targets");
