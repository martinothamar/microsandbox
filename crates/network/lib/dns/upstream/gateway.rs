//! The gateway upstream: pinned nameservers or the host's system resolver.

use std::io;

use hickory_net::proto::op::Message;

use super::PinnedUpstreams;
use super::system::SystemResolver;
use crate::dns::common::config::NormalizedDnsConfig;
use crate::dns::common::transport::Transport;
use crate::dns::nameserver::resolve_nameservers;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One guest query addressed to the sandbox gateway.
pub(crate) struct GatewayQuery<'a> {
    /// The parsed query. Its single question has passed policy checks,
    /// and upstreams send this message rather than the guest's original
    /// bytes, so what is resolved is exactly what was checked.
    pub(crate) message: &'a Message,
    /// The queried name without its trailing dot, for diagnostics.
    pub(crate) domain: &'a str,
    /// The transport the guest used.
    pub(crate) transport: Transport,
}

/// Resolver for queries the guest addresses to the sandbox gateway.
pub(crate) enum Upstream {
    /// Explicitly configured nameservers, fixed for the sandbox's lifetime.
    Pinned(PinnedUpstreams),
    /// The host's system resolver, used when no nameserver is configured.
    System(SystemResolver),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Upstream {
    /// Build the upstream selected by `config`: its nameservers when any
    /// are configured, otherwise the host's system resolver.
    pub(crate) async fn from_config(config: &NormalizedDnsConfig) -> io::Result<Self> {
        if config.nameservers.is_empty() {
            return Ok(Self::System(SystemResolver::new(config.query_timeout)));
        }

        let servers = resolve_nameservers(&config.nameservers).await?;
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no configured nameservers resolved to an address",
            ));
        }
        Ok(Self::Pinned(PinnedUpstreams::new(
            servers,
            config.query_timeout,
        )))
    }

    /// Resolve one gateway query. `Ok` carries any response code from a
    /// working resolver; `Err` means no usable answer was obtained.
    pub(crate) async fn query(&self, query: &GatewayQuery<'_>) -> io::Result<Message> {
        match self {
            Self::Pinned(upstreams) => upstreams.query(query).await,
            Self::System(resolver) => resolver.query(query).await,
        }
    }

    /// Return an error when this upstream may not resolve names for
    /// host-side proxy infrastructure.
    pub(crate) fn check_proxy_resolution(&self) -> io::Result<()> {
        match self {
            Self::Pinned(_) => Ok(()),
            Self::System(resolver) => resolver.check_proxy_resolution(),
        }
    }
}
