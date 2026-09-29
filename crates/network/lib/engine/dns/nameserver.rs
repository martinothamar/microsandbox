//! Explicitly configured upstream nameservers.
//!
//! Hostnames in [`Nameserver`]s are looked up via the host's own OS
//! resolver, never via us: bootstrapping cannot depend on the interceptor
//! being up already. Without explicit nameservers, gateway queries use
//! the host's system resolver in `engine::dns::upstream::system`.

use std::net::SocketAddr;

use crate::dns::Nameserver;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Nameserver {
    /// Resolve to a concrete address through the host's resolver.
    pub async fn resolve(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Addr(address) => Ok(*address),
            Self::Host { host, port } => tokio::net::lookup_host((host.as_str(), *port))
                .await?
                .next()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("no addresses resolved for {host}:{port}"),
                    )
                }),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve configured nameservers to concrete addresses.
///
/// Individual lookup failures are logged and skipped; the whole operation
/// errors only if every entry fails.
pub(crate) async fn resolve_nameservers(
    nameservers: &[Nameserver],
) -> std::io::Result<Vec<SocketAddr>> {
    let mut addresses = Vec::with_capacity(nameservers.len());
    let mut last_error = None;
    for nameserver in nameservers {
        match nameserver.resolve().await {
            Ok(address) => addresses.push(address),
            Err(error) => {
                tracing::warn!(nameserver = %nameserver, error = %error, "failed to resolve nameserver");
                last_error = Some(error);
            }
        }
    }
    if addresses.is_empty()
        && let Some(error) = last_error
    {
        return Err(error);
    }
    Ok(addresses)
}
