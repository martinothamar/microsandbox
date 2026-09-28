//! Linux system resolver: the nameservers in `/etc/resolv.conf`, followed
//! as the file changes.
//!
//! Linux has no resolver service every host runs; the file is the system
//! configuration. Like glibc, this resolver re-stats it before each query
//! and re-reads it only when it changed. Under systemd-resolved the file
//! names the local stub, which follows network changes itself.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use hickory_net::proto::op::Message;
use resolv_conf::Config as ResolvConfig;

use crate::dns::upstream::{GatewayQuery, PinnedUpstreams};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// DNS port. `resolv.conf` cannot name another one.
const DNS_PORT: u16 = 53;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Resolver over the nameservers currently in `/etc/resolv.conf`.
pub(crate) struct SystemResolver {
    path: PathBuf,
    port: u16,
    query_timeout: Duration,
    /// The last loaded version of the file. `None` until the first query.
    loaded: Mutex<Option<Loaded>>,
}

/// Upstreams loaded from one version of the file.
struct Loaded {
    /// `None` when the file could not be stat'ed.
    stamp: Option<FileStamp>,
    /// `None` when the file names no usable nameserver.
    upstreams: Option<Arc<PinnedUpstreams>>,
}

/// Identity and timestamps that change whenever the file is replaced or
/// rewritten, as glibc compares them.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SystemResolver {
    pub(crate) async fn new(query_timeout: Duration) -> io::Result<Self> {
        Ok(Self::with_path(
            Path::new(RESOLV_CONF_PATH),
            DNS_PORT,
            query_timeout,
        ))
    }

    /// Resolve one gateway query through the nameservers the file names now.
    /// A file without usable nameservers fails queries until it names some.
    pub(crate) async fn query(&self, query: &GatewayQuery<'_>) -> io::Result<Message> {
        let upstreams = self.upstreams()?;
        upstreams.query(query).await
    }

    /// Host DNS servers may resolve proxy infrastructure names.
    pub(crate) fn check_proxy_resolution(&self) -> io::Result<()> {
        Ok(())
    }

    fn with_path(path: &Path, port: u16, query_timeout: Duration) -> Self {
        let resolver = Self {
            path: path.to_owned(),
            port,
            query_timeout,
            loaded: Mutex::new(None),
        };
        // Load now, so a missing configuration is logged at startup.
        let _ = resolver.upstreams();
        resolver
    }

    /// The upstreams for the file's current version, re-reading it first if
    /// it changed since the last load.
    fn upstreams(&self) -> io::Result<Arc<PinnedUpstreams>> {
        let stamp = FileStamp::read(&self.path);
        // The value is replaced whole, so a panicking writer cannot leave it
        // half-updated.
        let mut loaded = self.loaded.lock().unwrap_or_else(PoisonError::into_inner);
        if loaded.as_ref().is_none_or(|loaded| loaded.stamp != stamp) {
            *loaded = Some(Loaded {
                stamp,
                upstreams: self.load(),
            });
        }
        loaded
            .as_ref()
            .and_then(|loaded| loaded.upstreams.clone())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no usable nameserver in {}", self.path.display()),
                )
            })
    }

    fn load(&self) -> Option<Arc<PinnedUpstreams>> {
        let path = self.path.display();
        match std::fs::read(&self.path).and_then(|bytes| parse_resolv_conf(&bytes, self.port)) {
            Ok(servers) if !servers.is_empty() => {
                tracing::info!(%path, ?servers, "loaded host DNS servers");
                Some(Arc::new(PinnedUpstreams::new(servers, self.query_timeout)))
            }
            Ok(_) => {
                tracing::warn!(%path, "host DNS configuration names no nameserver");
                None
            }
            Err(error) => {
                tracing::warn!(%path, %error, "failed to read host DNS configuration");
                None
            }
        }
    }
}

impl FileStamp {
    /// Stamp the file at `path`, following symlinks.
    fn read(path: &Path) -> Option<Self> {
        let metadata = std::fs::metadata(path).ok()?;
        Some(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Parse a `resolv.conf` file and return its `nameserver` entries on
/// `port`, with the parser hickory-resolver uses.
fn parse_resolv_conf(bytes: &[u8], port: u16) -> io::Result<Vec<SocketAddr>> {
    let config = ResolvConfig::parse(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    Ok(config
        .nameservers
        .into_iter()
        .map(|nameserver| SocketAddr::new(IpAddr::from(nameserver), port))
        .collect())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hickory_net::proto::op::{MessageType, OpCode, Query, ResponseCode};
    use hickory_net::proto::rr::rdata::A;
    use hickory_net::proto::rr::{Name, RData, Record, RecordType};
    use hickory_net::proto::serialize::binary::{BinDecodable, BinEncodable};
    use tokio::net::UdpSocket;

    use super::*;
    use crate::dns::common::transport::Transport;

    /// A resolv.conf in its own temporary directory, replaced the way
    /// network managers do: write a new file, then rename it into place.
    struct TempResolvConf {
        dir: PathBuf,
        path: PathBuf,
    }

    impl TempResolvConf {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "msb-resolv-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("resolv.conf");
            Self { dir, path }
        }

        fn replace(&self, contents: &str) {
            let staged = self.dir.join("resolv.conf.new");
            std::fs::write(&staged, contents).unwrap();
            std::fs::rename(&staged, &self.path).unwrap();
        }

        fn remove(&self) {
            std::fs::remove_file(&self.path).unwrap();
        }
    }

    impl Drop for TempResolvConf {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Answer every query sent to `addr` with `answer`.
    async fn answering_udp(addr: SocketAddr, answer: Ipv4Addr) -> SocketAddr {
        let socket = UdpSocket::bind(addr).await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                    continue;
                };
                let Ok(query) = Message::from_bytes(&buf[..len]) else {
                    continue;
                };
                let mut response =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                if let Some(question) = query.queries.first() {
                    response.add_query(question.clone());
                    response.add_answer(Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::A(A::from(answer)),
                    ));
                }
                let _ = socket.send_to(&response.to_bytes().unwrap(), from).await;
            }
        });
        addr
    }

    /// Two loopback resolvers on the same port, standing in for the
    /// nameservers of two networks.
    async fn two_networks() -> (u16, Ipv4Addr, Ipv4Addr) {
        let first =
            answering_udp("127.0.0.1:0".parse().unwrap(), Ipv4Addr::new(192, 0, 2, 1)).await;
        answering_udp(
            SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), first.port()),
            Ipv4Addr::new(192, 0, 2, 2),
        )
        .await;
        (
            first.port(),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 2),
        )
    }

    async fn resolve(resolver: &SystemResolver) -> io::Result<Ipv4Addr> {
        let mut message = Message::new(0x4242, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let response = resolver
            .query(&GatewayQuery {
                message: &message,
                domain: "example.com",
                transport: Transport::Udp,
            })
            .await?;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        response
            .answers
            .iter()
            .find_map(|record| match record.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .ok_or_else(|| io::Error::other("no A answer"))
    }

    #[test]
    fn parses_nameservers_on_the_given_port() {
        let servers = parse_resolv_conf(
            b"# comment line\n\
              nameserver 1.1.1.1\n\
              nameserver 8.8.8.8  # inline comment\n\
              search example.com\n\
              options ndots:5\n\
              nameserver 2606:4700:4700::1111\n",
            53,
        )
        .unwrap();

        assert_eq!(
            servers,
            [
                "1.1.1.1:53".parse::<SocketAddr>().unwrap(),
                "8.8.8.8:53".parse().unwrap(),
                "[2606:4700:4700::1111]:53".parse().unwrap(),
            ]
        );
    }

    /// The reported bug: after the host moved to another network, queries
    /// kept going to the previous network's nameserver.
    #[tokio::test]
    async fn follows_a_replaced_resolv_conf() {
        let (port, first, second) = two_networks().await;
        let conf = TempResolvConf::new();
        conf.replace("nameserver 127.0.0.1\n");
        let resolver = SystemResolver::with_path(&conf.path, port, Duration::from_millis(300));

        assert_eq!(resolve(&resolver).await.unwrap(), first);
        conf.replace("nameserver 127.0.0.2\n");
        assert_eq!(resolve(&resolver).await.unwrap(), second);
    }

    /// A host that starts without DNS gets it once the file names a server.
    #[tokio::test]
    async fn recovers_when_resolv_conf_appears() {
        let (port, first, _) = two_networks().await;
        let conf = TempResolvConf::new();
        let resolver = SystemResolver::with_path(&conf.path, port, Duration::from_millis(300));

        let error = resolve(&resolver).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        conf.replace("nameserver 127.0.0.1\n");
        assert_eq!(resolve(&resolver).await.unwrap(), first);
    }

    /// Losing the configuration stops resolution instead of silently
    /// keeping servers the host no longer uses.
    #[tokio::test]
    async fn stops_when_resolv_conf_names_no_server() {
        let (port, first, _) = two_networks().await;
        let conf = TempResolvConf::new();
        conf.replace("nameserver 127.0.0.1\n");
        let resolver = SystemResolver::with_path(&conf.path, port, Duration::from_millis(300));
        assert_eq!(resolve(&resolver).await.unwrap(), first);

        conf.replace("# no nameservers\n");
        assert_eq!(
            resolve(&resolver).await.unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        conf.remove();
        assert_eq!(
            resolve(&resolver).await.unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}
