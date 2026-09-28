//! The host's system resolver, implemented once per platform.
//!
//! Every platform module exports a `SystemResolver` with the same API:
//!
//! - `fn new(query_timeout: Duration) -> Self`
//! - `async fn query(&self, query: &GatewayQuery<'_>) -> io::Result<Message>`
//! - `fn check_proxy_resolution(&self) -> io::Result<()>`
//!
//! This is the only place that selects code by platform.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub(crate) use linux::SystemResolver;
#[cfg(target_os = "macos")]
pub(crate) use macos::SystemResolver;
#[cfg(windows)]
pub(crate) use windows::SystemResolver;
