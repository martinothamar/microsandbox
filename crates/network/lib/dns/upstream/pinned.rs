//! A fixed, ordered list of upstream nameservers with failover.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use hickory_net::proto::op::Message;

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
    servers: Vec<SocketAddr>,
    query_timeout: Duration,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PinnedUpstreams {
    pub(crate) fn new(servers: Vec<SocketAddr>, query_timeout: Duration) -> Self {
        Self {
            servers,
            query_timeout,
        }
    }

    /// Forward `query` to each upstream in order and return the first
    /// answer. Fails when every upstream is unusable.
    pub(crate) async fn query(&self, query: &GatewayQuery<'_>) -> io::Result<Message> {
        for (index, &server) in self.servers.iter().enumerate() {
            if let Some(client) = self.client(server, query.transport).await
                && let Some(response) = send_query(&client, query.message, query.domain).await
            {
                return Ok(response);
            }
            if index + 1 < self.servers.len() {
                tracing::debug!(
                    domain = %query.domain,
                    upstream = %server,
                    "upstream DNS unusable, trying next configured nameserver",
                );
            }
        }
        Err(io::Error::other("no upstream DNS server answered"))
    }

    /// Build a client for one query. Clients are cheap: hickory opens a
    /// fresh UDP socket per query anyway, and a TCP client cannot recover
    /// once the server closes its connection. DoT guests use plain TCP,
    /// since the upstream is typically on the host's own network.
    async fn client(&self, server: SocketAddr, transport: Transport) -> Option<Client> {
        match transport {
            Transport::Udp => build_udp_client(server, self.query_timeout).await,
            Transport::Tcp | Transport::Dot => build_tcp_client(server, self.query_timeout).await,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_net::proto::op::{MessageType, OpCode, Query, ResponseCode};
    use hickory_net::proto::rr::rdata::A;
    use hickory_net::proto::rr::{Name, RData, Record, RecordType};
    use hickory_net::proto::serialize::binary::{BinDecodable, BinEncodable};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// TCP resolver that answers one query per connection and then closes
    /// it, as resolvers do to idle connections. Counts connections.
    async fn closing_tcp_resolver() -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::clone(&connections);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    continue;
                };
                accepted.fetch_add(1, Ordering::SeqCst);
                let Ok(len) = socket.read_u16().await else {
                    continue;
                };
                let mut bytes = vec![0; usize::from(len)];
                if socket.read_exact(&mut bytes).await.is_err() {
                    continue;
                }
                let query = Message::from_bytes(&bytes).unwrap();
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.add_query(query.queries[0].clone());
                response.add_answer(Record::from_rdata(
                    query.queries[0].name().clone(),
                    60,
                    RData::A(A::from(Ipv4Addr::new(192, 0, 2, 1))),
                ));
                let bytes = response.to_bytes().unwrap();
                let _ = socket.write_u16(bytes.len() as u16).await;
                let _ = socket.write_all(&bytes).await;
                let _ = socket.shutdown().await;
            }
        });
        (addr, connections)
    }

    /// The reported bug: once the server closed the cached TCP connection,
    /// every later TCP query to it failed.
    #[tokio::test]
    async fn tcp_queries_survive_the_server_closing_the_connection() {
        let (addr, connections) = closing_tcp_resolver().await;
        let upstreams = PinnedUpstreams::new(vec![addr], Duration::from_millis(500));
        let mut message = Message::new(0x4242, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let query = GatewayQuery {
            message: &message,
            domain: "example.com",
            transport: Transport::Tcp,
        };

        for _ in 0..3 {
            let response = upstreams.query(&query).await.unwrap();
            assert_eq!(response.metadata.response_code, ResponseCode::NoError);
            assert_eq!(response.answers.len(), 1);
        }
        assert_eq!(connections.load(Ordering::SeqCst), 3);
    }
}
