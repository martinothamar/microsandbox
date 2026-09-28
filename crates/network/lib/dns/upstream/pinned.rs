//! A fixed, ordered list of upstream nameservers with failover.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use hickory_net::proto::op::Message;
use tokio::sync::OnceCell;

use super::gateway::GatewayQuery;
use crate::dns::client::{Client, build_tcp_client, build_udp_client, send_query};
use crate::dns::common::transport::Transport;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Upstream nameservers tried in order. The guest holds the gateway as
/// its only nameserver and cannot try the rest itself, so a timeout or
/// transport failure falls over to the next server.
pub(crate) struct PinnedUpstreams {
    upstreams: Vec<PinnedUpstream>,
    query_timeout: Duration,
}

/// One upstream and its per-transport clients.
struct PinnedUpstream {
    /// Address of this upstream, needed to build `tcp` on demand and for
    /// diagnostic logging.
    addr: SocketAddr,
    /// UDP client, connected at startup. Cheap to build for every
    /// upstream: since hickory 0.26 the constructor only wraps a request
    /// sender, so socket errors surface per-query instead.
    udp: Client,
    /// Lazy TCP client. Built on the first TCP query that reaches this
    /// upstream; many sandboxes never use TCP DNS at all, so the
    /// handshake is not paid up front.
    tcp: OnceCell<Client>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PinnedUpstreams {
    /// Build clients for `servers`, in order. Fails when no client could
    /// be built.
    pub(crate) async fn new(servers: &[SocketAddr], query_timeout: Duration) -> io::Result<Self> {
        let mut upstreams = Vec::with_capacity(servers.len());
        for &addr in servers {
            let Some(udp) = build_udp_client(addr, query_timeout).await else {
                tracing::warn!(upstream = %addr, "skipping upstream: failed to build UDP client");
                continue;
            };
            upstreams.push(PinnedUpstream {
                addr,
                udp,
                tcp: OnceCell::new(),
            });
        }
        if upstreams.is_empty() {
            return Err(io::Error::other("no upstream DNS client could be built"));
        }
        Ok(Self {
            upstreams,
            query_timeout,
        })
    }

    /// Forward `query` to each upstream in order and return the first
    /// answer. Fails when every upstream is unusable.
    pub(crate) async fn query(&self, query: &GatewayQuery<'_>) -> io::Result<Message> {
        let total = self.upstreams.len();
        for (index, upstream) in self.upstreams.iter().enumerate() {
            let Some(client) = self.client_for(upstream, query.transport).await else {
                continue;
            };
            if let Some(response) = send_query(&client, query.message, query.domain).await {
                return Ok(response);
            }
            if index + 1 < total {
                tracing::debug!(
                    domain = %query.domain,
                    upstream = %upstream.addr,
                    "upstream DNS unusable, trying next configured nameserver",
                );
            }
        }
        Err(io::Error::other("no upstream DNS server answered"))
    }

    /// Get the client for one upstream on `transport`. UDP is shared
    /// (pre-connected at startup); TCP is built on first use and cached
    /// per upstream. DoT guests reuse the TCP client: the upstream is
    /// typically on the host's loopback or internal network and serves
    /// plain DNS, so re-TLSing there is overkill.
    ///
    /// Called per upstream as the query walks the list, so an upstream
    /// that is never reached never pays for a TCP handshake.
    async fn client_for(&self, upstream: &PinnedUpstream, transport: Transport) -> Option<Client> {
        match transport {
            Transport::Udp => Some(upstream.udp.clone()),
            Transport::Tcp | Transport::Dot => {
                let timeout = self.query_timeout;
                let addr = upstream.addr;
                upstream
                    .tcp
                    .get_or_try_init(
                        || async move { build_tcp_client(addr, timeout).await.ok_or(()) },
                    )
                    .await
                    .ok()
                    .cloned()
            }
        }
    }
}
