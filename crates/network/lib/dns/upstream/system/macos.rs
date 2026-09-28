//! macOS host DNS servers, read once when the sandbox network starts.

use std::io;
use std::time::Duration;

use hickory_net::proto::op::Message;

use crate::dns::nameserver::read_host_dns_servers;
use crate::dns::upstream::{GatewayQuery, PinnedUpstreams};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Resolver over the host's DNS servers, discovered at startup.
pub(crate) struct SystemResolver {
    upstreams: PinnedUpstreams,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SystemResolver {
    /// Discover the host's DNS servers. Fails when none are configured.
    pub(crate) async fn new(query_timeout: Duration) -> io::Result<Self> {
        let servers = read_host_dns_servers().await?;
        if servers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no upstream DNS servers discovered from host",
            ));
        }
        Ok(Self {
            upstreams: PinnedUpstreams::new(servers, query_timeout),
        })
    }

    /// Resolve one gateway query through the host's DNS servers.
    pub(crate) async fn query(&self, query: &GatewayQuery<'_>) -> io::Result<Message> {
        self.upstreams.query(query).await
    }

    /// Host DNS servers may resolve proxy infrastructure names.
    pub(crate) fn check_proxy_resolution(&self) -> io::Result<()> {
        Ok(())
    }
}
