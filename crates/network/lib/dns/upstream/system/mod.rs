//! The host's system resolver, implemented once per platform.
//!
//! Every platform module exports a `SystemResolver` with the same API:
//!
//! - `async fn new(query_timeout: Duration) -> io::Result<Self>`
//! - `async fn query(&self, query: &GatewayQuery<'_>) -> io::Result<Message>`
//! - `fn check_proxy_resolution(&self) -> io::Result<()>`
//!
//! This module is the only place that selects an implementation by
//! platform.

#[cfg(not(windows))]
mod unix;
#[cfg(windows)]
mod windows;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

#[cfg(not(windows))]
pub(crate) use unix::SystemResolver;
#[cfg(windows)]
pub(crate) use windows::SystemResolver;
