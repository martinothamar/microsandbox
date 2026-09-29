//! macOS system resolver: mDNSResponder, through `DNSServiceQueryRecord`.
//!
//! mDNSResponder is the resolver macOS applications use, so it follows
//! network changes, VPN split DNS and `/etc/resolver` files.
//!
//! The `dns_sd` calls block (a query start waits for the daemon, reply
//! processing reads whole messages), so each query runs on its own
//! blocking thread. Responses carry answer records only, with the
//! records' original TTLs; see [`answers`] for negative answers.

mod answers;
mod dnssd;

use std::ffi::{CStr, c_int};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_net::proto::op::Message;
use hickory_net::proto::rr::{DNSClass, Record, RecordType};
use tokio::sync::Semaphore;

use self::answers::{Collector, build_response, encode_name};
use self::dnssd::ActiveQuery;
use crate::dns::upstream::GatewayQuery;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Queries one sandbox may have in flight. Each holds a blocking thread and
/// a request on the host's mDNSResponder, which every application on the
/// host shares, so a guest flooding queries cannot load it without bound.
const MAX_IN_FLIGHT: usize = 64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Resolver that sends each query through mDNSResponder.
pub(crate) struct SystemResolver {
    query_timeout: Duration,
    in_flight: Arc<Semaphore>,
}

/// What woke a query thread.
enum Wake {
    Replies,
    Cancelled,
    Idle,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SystemResolver {
    pub(crate) fn new(query_timeout: Duration) -> Self {
        Self {
            query_timeout,
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
        }
    }

    /// Resolve one gateway query through mDNSResponder.
    pub(crate) async fn query(&self, query: &GatewayQuery<'_>) -> io::Result<Message> {
        let question = query.message.queries.first().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "DNS query has no question")
        })?;
        // Held by the query thread until it exits, which can be after this
        // future has timed out.
        let permit = Arc::clone(&self.in_flight)
            .try_acquire_owned()
            .map_err(|_| io::Error::other("too many macOS DNS queries in flight"))?;
        let name = encode_name(question.name())?;
        let record_type = question.query_type();
        let class = question.query_class();
        let deadline = Instant::now() + self.query_timeout;

        // The query thread watches `cancelled`. Dropping `_cancel`, when this
        // future completes, times out or is dropped, wakes the thread so it
        // cancels the query instead of running to its deadline.
        let (_cancel, cancelled) = UnixStream::pair()?;
        let resolving = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            resolve(&name, record_type, class, deadline, &cancelled)
        });
        let answers = tokio::time::timeout(self.query_timeout, resolving)
            .await
            .map_err(|_| timed_out())?
            .map_err(|error| {
                io::Error::other(format!("macOS DNS query thread failed: {error}"))
            })??;
        Ok(build_response(query.message, answers))
    }

    /// mDNSResponder may resolve proxy infrastructure names.
    pub(crate) fn check_proxy_resolution(&self) -> io::Result<()> {
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run one query on the calling thread until it is answered, `deadline`
/// passes or `cancelled` becomes readable. Returning drops, and so
/// cancels, the query.
fn resolve(
    name: &CStr,
    record_type: RecordType,
    class: DNSClass,
    deadline: Instant,
    cancelled: &UnixStream,
) -> io::Result<Vec<Record>> {
    // The thread may only get to run after its caller gave up, for example
    // behind a backlog of stalled queries. Starting costs a daemon round
    // trip, so skip it then.
    if Instant::now() >= deadline {
        return Err(timed_out());
    }
    if cancel_requested(cancelled)? {
        return Err(cancelled_error());
    }
    let mut lookup = ActiveQuery::start(
        name,
        u16::from(record_type),
        u16::from(class),
        Collector::new(record_type),
    )?;
    let socket = lookup.socket()?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timed_out());
        }
        match wait(socket, cancelled.as_raw_fd(), remaining)? {
            Wake::Cancelled => return Err(cancelled_error()),
            Wake::Idle => {}
            Wake::Replies => {
                // Reads every queued reply; blocks only if the daemon stalls
                // in the middle of a message.
                lookup.process()?;
                if let Some(outcome) = lookup.collector().finish() {
                    return outcome;
                }
            }
        }
    }
}

/// Wait up to `timeout` for replies on `query` or for `cancel` to become
/// readable, which it does once its peer is dropped.
fn wait(query: RawFd, cancel: RawFd, timeout: Duration) -> io::Result<Wake> {
    let mut fds = [
        libc::pollfd {
            fd: query,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: cancel,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let timeout = c_int::try_from(timeout.as_millis().max(1)).unwrap_or(c_int::MAX);
    // SAFETY: `fds` is a valid array of two pollfd structures.
    match unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) } {
        -1 => {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                Ok(Wake::Idle)
            } else {
                Err(error)
            }
        }
        0 => Ok(Wake::Idle),
        _ if fds[1].revents != 0 => Ok(Wake::Cancelled),
        // Hang-up and errors on the query socket also count as replies, so
        // processing reports them.
        _ => Ok(Wake::Replies),
    }
}

/// Whether the caller has dropped its end of the cancel socket.
fn cancel_requested(cancelled: &UnixStream) -> io::Result<bool> {
    cancelled.set_nonblocking(true)?;
    match (&*cancelled).read(&mut [0; 1]) {
        // End of stream: the peer is gone. Nothing is ever written.
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error),
    }
}

fn cancelled_error() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "macOS DNS query cancelled")
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "macOS system DNS query timed out")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use hickory_net::proto::op::{MessageType, OpCode, Query, ResponseCode};
    use hickory_net::proto::rr::{Name, RData, RecordType};

    use super::*;
    use crate::dns::common::transport::Transport;

    async fn resolve(name: &str, record_type: RecordType) -> Message {
        let mut message = Message::new(0x4242, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), record_type));
        SystemResolver::new(Duration::from_secs(10))
            .query(&GatewayQuery {
                message: &message,
                domain: name.trim_end_matches('.'),
                transport: Transport::Udp,
            })
            .await
            .unwrap()
    }

    #[test]
    fn cancellation_is_seen_once_the_caller_drops_its_end() {
        let (cancel, cancelled) = UnixStream::pair().unwrap();
        assert!(!cancel_requested(&cancelled).unwrap());
        drop(cancel);
        assert!(cancel_requested(&cancelled).unwrap());
    }

    #[tokio::test]
    #[ignore = "requires mDNSResponder and host network access"]
    async fn resolves_addresses_through_mdnsresponder() {
        let response = resolve("example.com.", RecordType::A).await;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.metadata.id, 0x4242);
        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::A(_))),
            "{response:?}"
        );
    }

    /// A multicast name nobody answers runs to the deadline; the query
    /// thread must then cancel the query rather than outlive it.
    #[tokio::test]
    #[ignore = "requires mDNSResponder and host network access"]
    async fn unanswered_queries_time_out_and_cancel() {
        let mut message = Message::new(0x4242, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("microsandbox-unanswered.local.").unwrap(),
            RecordType::A,
        ));
        let resolver = SystemResolver::new(Duration::from_millis(300));
        let started = Instant::now();
        let error = resolver
            .query(&GatewayQuery {
                message: &message,
                domain: "microsandbox-unanswered.local",
                transport: Transport::Udp,
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    /// Queries beyond the in-flight limit fail at once instead of queueing
    /// more work on the host's mDNSResponder.
    #[tokio::test]
    #[ignore = "requires mDNSResponder and host network access"]
    async fn queries_beyond_the_in_flight_limit_fail_at_once() {
        let resolver = Arc::new(SystemResolver::new(Duration::from_secs(2)));
        let unanswered = |index: usize| {
            let mut message = Message::new(0x4242, MessageType::Query, OpCode::Query);
            let name = format!("microsandbox-unanswered-{index}.local.");
            message.add_query(Query::query(
                Name::from_ascii(&name).unwrap(),
                RecordType::A,
            ));
            message
        };
        let pending: Vec<_> = (0..MAX_IN_FLIGHT)
            .map(|index| {
                let resolver = Arc::clone(&resolver);
                let message = unanswered(index);
                tokio::spawn(async move {
                    resolver
                        .query(&GatewayQuery {
                            message: &message,
                            domain: "unanswered.local",
                            transport: Transport::Udp,
                        })
                        .await
                })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let message = unanswered(MAX_IN_FLIGHT);
        let started = Instant::now();
        let error = resolver
            .query(&GatewayQuery {
                message: &message,
                domain: "unanswered.local",
                transport: Transport::Udp,
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("in flight"), "{error}");
        assert!(started.elapsed() < Duration::from_millis(100));
        for query in pending {
            assert!(query.await.unwrap().is_err());
        }
    }

    #[tokio::test]
    #[ignore = "requires mDNSResponder and host network access"]
    async fn missing_names_answer_without_records() {
        let response = resolve("microsandbox-missing.example.com.", RecordType::A).await;
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty(), "{response:?}");
    }
}
