//! Explicitly configured upstream nameservers.
//!
//! Hostnames in [`Nameserver`]s are looked up via the host's own OS
//! resolver, never via us: bootstrapping cannot depend on the interceptor
//! being up already. Without explicit nameservers, gateway queries use
//! the host's system resolver in `dns::upstream::system`.

pub mod parse;
pub use parse::{Nameserver, ParseNameserverError};

use std::net::SocketAddr;

/// Resolve a list of [`Nameserver`]s to concrete `SocketAddr`s.
///
/// Individual lookup failures are logged and skipped; the whole operation
/// errors only if every entry fails.
pub(super) async fn resolve_nameservers(
    nameservers: &[Nameserver],
) -> std::io::Result<Vec<SocketAddr>> {
    let mut out = Vec::with_capacity(nameservers.len());
    let mut last_err: Option<std::io::Error> = None;
    for ns in nameservers {
        match ns.resolve().await {
            Ok(sa) => out.push(sa),
            Err(e) => {
                tracing::warn!(nameserver = %ns, error = %e, "failed to resolve nameserver");
                last_err = Some(e);
            }
        }
    }
    if out.is_empty()
        && let Some(e) = last_err
    {
        return Err(e);
    }
    Ok(out)
}
