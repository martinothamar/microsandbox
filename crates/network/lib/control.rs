//! Fail-closed host authorization for the in-process network engine.
//!
//! A controlled network keeps packet parsing and protocol handling inside the
//! trusted runtime, but delegates each outbound operation to a host-side
//! policy enforcement point before opening a host network socket. The local
//! transport carries bounded, length-delimited JSON messages.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot, watch};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Stable protocol selected by compatible Sandbox and Network Backends.
pub const NETWORK_CONTROL_PROTOCOL: &str = "microsandbox.network-control.v1";

/// Maximum serialized control message accepted from either peer.
pub const MAX_CONTROL_MESSAGE_LENGTH: usize = 64 * 1024;

const COMMAND_CAPACITY: usize = 256;
const AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Transport protocol associated with an outbound operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TransportProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Internet Control Message Protocol for IPv4.
    Icmpv4,
    /// Internet Control Message Protocol for IPv6.
    Icmpv6,
}

/// Trusted outbound operation described by the Microsandbox network engine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "camelCase")]
pub enum NetworkOperation {
    /// Open a transport-layer flow to a destination.
    Connect {
        /// Sandbox source address observed by the network engine.
        source: Option<SocketAddr>,
        /// Original destination requested by the Sandbox.
        destination: SocketAddr,
        /// Transport used by the flow.
        transport: TransportProtocol,
        /// Host name established by trusted protocol inspection, when available.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
    },
    /// Resolve one DNS name through the host network stack.
    DnsQuery {
        /// Canonical query name without a trailing root label.
        name: String,
        /// DNS record type as a stable textual value.
        record_type: String,
        /// Resolver selected by the Sandbox, when it did not use the virtual gateway.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolver: Option<SocketAddr>,
        /// UDP or TCP transport used by the query.
        transport: TransportProtocol,
    },
}

/// Message emitted by the trusted Microsandbox runtime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum RuntimeMessage {
    /// Establish the exact protocol version before exchanging requests.
    Hello {
        /// Requested protocol identity.
        protocol: String,
    },
    /// Ask the host to authorize an operation before it is performed.
    AuthorizationRequest {
        /// Request identifier scoped to this runtime instance.
        request_id: u64,
        /// Flow identifier used by later revocation.
        flow_id: u64,
        /// Operation observed by the trusted network engine.
        operation: NetworkOperation,
    },
    /// Release host-side state for a completed flow.
    FlowClosed {
        /// Flow identifier from the corresponding authorization request.
        flow_id: u64,
    },
}

/// Host authorization result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthorizationDecision {
    /// Permit the requested operation.
    Allow,
    /// Refuse the requested operation.
    Deny,
}

/// Message returned by the host-side Network Backend.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ControllerMessage {
    /// Accept the requested protocol version.
    HelloAccepted {
        /// Accepted protocol identity.
        protocol: String,
    },
    /// Complete one authorization request.
    AuthorizationDecision {
        /// Runtime request being completed.
        request_id: u64,
        /// Authorization result.
        decision: AuthorizationDecision,
    },
    /// Revoke a previously allowed live flow.
    Revoke {
        /// Flow to terminate.
        flow_id: u64,
    },
}

/// Cloneable runtime-side client for one Sandbox's host controller.
#[derive(Clone)]
pub struct NetworkControlClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    commands: mpsc::Sender<Command>,
    next_id: AtomicU64,
}

enum Command {
    Authorize {
        request_id: u64,
        flow_id: u64,
        operation: NetworkOperation,
        response: oneshot::Sender<AuthorizationDecision>,
        revoked: watch::Sender<bool>,
    },
    Cancel {
        request_id: u64,
        flow_id: u64,
    },
    CloseFlow {
        flow_id: u64,
    },
}

/// Revocable permission for one live outbound flow.
pub struct NetworkGrant {
    flow_id: u64,
    revoked: watch::Receiver<bool>,
    commands: mpsc::Sender<Command>,
}

struct PendingAuthorization {
    flow_id: u64,
    response: oneshot::Sender<AuthorizationDecision>,
    revoked: watch::Sender<bool>,
}

/// Failure to obtain a positive host authorization result.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    /// The bounded controller queue could not accept another request.
    #[error("Network controller is unavailable")]
    Unavailable,
    /// The controller did not decide before the fail-closed deadline.
    #[error("Network controller authorization timed out")]
    Timeout,
    /// The controller explicitly denied the operation.
    #[error("Network controller denied the operation")]
    Denied,
}

#[cfg(unix)]
type PlatformStream = tokio::net::UnixStream;

#[cfg(windows)]
type PlatformStream = tokio::net::windows::named_pipe::NamedPipeClient;

struct Connection {
    reader: tokio::io::ReadHalf<PlatformStream>,
    writer: tokio::io::WriteHalf<PlatformStream>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NetworkControlClient {
    /// Starts a client that connects lazily to the host-owned endpoint.
    #[must_use]
    pub fn new(endpoint: PathBuf, runtime: &tokio::runtime::Handle) -> Self {
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        runtime.spawn(run_client(endpoint, receiver));
        Self {
            inner: Arc::new(ClientInner {
                commands,
                next_id: AtomicU64::new(1),
            }),
        }
    }

    /// Requests permission and returns a revocable flow grant.
    ///
    /// # Errors
    ///
    /// Returns an error on explicit denial, timeout, transport failure, or
    /// bounded-queue exhaustion. Every error is a deny result to the caller.
    pub async fn authorize(
        &self,
        operation: NetworkOperation,
    ) -> Result<NetworkGrant, AuthorizationError> {
        let request_id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let flow_id = request_id;
        let (response_tx, response_rx) = oneshot::channel();
        let (revoked_tx, revoked_rx) = watch::channel(false);
        self.inner
            .commands
            .try_send(Command::Authorize {
                request_id,
                flow_id,
                operation,
                response: response_tx,
                revoked: revoked_tx,
            })
            .map_err(|_| AuthorizationError::Unavailable)?;

        match tokio::time::timeout(AUTHORIZATION_TIMEOUT, response_rx).await {
            Ok(Ok(AuthorizationDecision::Allow)) => Ok(NetworkGrant {
                flow_id,
                revoked: revoked_rx,
                commands: self.inner.commands.clone(),
            }),
            Ok(Ok(AuthorizationDecision::Deny)) => Err(AuthorizationError::Denied),
            Ok(Err(_)) => Err(AuthorizationError::Unavailable),
            Err(_) => {
                let _ = self.inner.commands.try_send(Command::Cancel {
                    request_id,
                    flow_id,
                });
                Err(AuthorizationError::Timeout)
            }
        }
    }
}

impl NetworkGrant {
    /// Completes when the host revokes this flow or the controller disconnects.
    pub async fn revoked(&mut self) {
        if *self.revoked.borrow() {
            return;
        }
        let _ = self.revoked.changed().await;
    }
}

impl Drop for NetworkGrant {
    fn drop(&mut self) {
        let _ = self.commands.try_send(Command::CloseFlow {
            flow_id: self.flow_id,
        });
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Waits for revocation when controlled networking is selected and otherwise remains pending.
pub(crate) async fn wait_for_revocation(grant: &mut Option<NetworkGrant>) {
    match grant {
        Some(grant) => grant.revoked().await,
        None => std::future::pending().await,
    }
}

async fn run_client(endpoint: PathBuf, mut commands: mpsc::Receiver<Command>) {
    let mut connection: Option<Connection> = None;
    let mut pending = HashMap::<u64, PendingAuthorization>::new();
    let mut flows = HashMap::<u64, watch::Sender<bool>>::new();

    loop {
        if connection.is_none() {
            let Some(command) = commands.recv().await else {
                break;
            };
            let connected =
                tokio::time::timeout(CONNECT_TIMEOUT, connect_and_handshake(&endpoint)).await;
            match connected {
                Ok(Ok(connected)) => connection = Some(connected),
                Ok(Err(error)) => {
                    tracing::debug!(endpoint = %endpoint.display(), %error, "Network controller connection failed");
                    deny_command(command);
                    continue;
                }
                Err(_) => {
                    tracing::debug!(endpoint = %endpoint.display(), "Network controller connection timed out");
                    deny_command(command);
                    continue;
                }
            }
            if handle_command(
                command,
                connection.as_mut().map(|connection| &mut connection.writer),
                &mut pending,
                &mut flows,
            )
            .await
            .is_err()
            {
                disconnect(&mut connection, &mut pending, &mut flows);
            }
            continue;
        }

        let active = connection.as_mut().expect("connection checked above");
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    break;
                };
                if handle_command(command, Some(&mut active.writer), &mut pending, &mut flows).await.is_err() {
                    disconnect(&mut connection, &mut pending, &mut flows);
                }
            }
            message = read_message::<_, ControllerMessage>(&mut active.reader) => {
                match message {
                    Ok(Some(message)) => handle_controller_message(message, &mut pending, &mut flows),
                    Ok(None) | Err(_) => disconnect(&mut connection, &mut pending, &mut flows),
                }
            }
        }
    }

    disconnect(&mut connection, &mut pending, &mut flows);
}

async fn handle_command(
    command: Command,
    writer: Option<&mut tokio::io::WriteHalf<PlatformStream>>,
    pending: &mut HashMap<u64, PendingAuthorization>,
    flows: &mut HashMap<u64, watch::Sender<bool>>,
) -> io::Result<()> {
    match command {
        Command::Authorize {
            request_id,
            flow_id,
            operation,
            response,
            revoked,
        } => {
            let Some(writer) = writer else {
                let _ = response.send(AuthorizationDecision::Deny);
                return Ok(());
            };
            write_message(
                writer,
                &RuntimeMessage::AuthorizationRequest {
                    request_id,
                    flow_id,
                    operation,
                },
            )
            .await?;
            pending.insert(
                request_id,
                PendingAuthorization {
                    flow_id,
                    response,
                    revoked,
                },
            );
        }
        Command::Cancel {
            request_id,
            flow_id,
        } => {
            pending.remove(&request_id);
            flows.remove(&flow_id);
            if let Some(writer) = writer {
                write_message(writer, &RuntimeMessage::FlowClosed { flow_id }).await?;
            }
        }
        Command::CloseFlow { flow_id } => {
            flows.remove(&flow_id);
            if let Some(writer) = writer {
                write_message(writer, &RuntimeMessage::FlowClosed { flow_id }).await?;
            }
        }
    }
    Ok(())
}

fn handle_controller_message(
    message: ControllerMessage,
    pending: &mut HashMap<u64, PendingAuthorization>,
    flows: &mut HashMap<u64, watch::Sender<bool>>,
) {
    match message {
        ControllerMessage::AuthorizationDecision {
            request_id,
            decision,
        } => {
            let Some(pending) = pending.remove(&request_id) else {
                return;
            };
            if decision == AuthorizationDecision::Allow {
                flows.insert(pending.flow_id, pending.revoked);
            }
            let _ = pending.response.send(decision);
        }
        ControllerMessage::Revoke { flow_id } => {
            if let Some(revoked) = flows.remove(&flow_id) {
                let _ = revoked.send(true);
            }
        }
        ControllerMessage::HelloAccepted { .. } => {
            tracing::debug!("unexpected Network controller handshake message");
        }
    }
}

fn disconnect(
    connection: &mut Option<Connection>,
    pending: &mut HashMap<u64, PendingAuthorization>,
    flows: &mut HashMap<u64, watch::Sender<bool>>,
) {
    *connection = None;
    for (_, pending) in pending.drain() {
        let _ = pending.response.send(AuthorizationDecision::Deny);
    }
    for (_, revoked) in flows.drain() {
        let _ = revoked.send(true);
    }
}

fn deny_command(command: Command) {
    if let Command::Authorize { response, .. } = command {
        let _ = response.send(AuthorizationDecision::Deny);
    }
}

async fn connect_and_handshake(endpoint: &Path) -> io::Result<Connection> {
    let mut stream = connect(endpoint).await?;
    write_message(
        &mut stream,
        &RuntimeMessage::Hello {
            protocol: NETWORK_CONTROL_PROTOCOL.to_string(),
        },
    )
    .await?;
    let response = read_message::<_, ControllerMessage>(&mut stream)
        .await?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Network controller closed during handshake",
            )
        })?;
    match response {
        ControllerMessage::HelloAccepted { protocol } if protocol == NETWORK_CONTROL_PROTOCOL => {
            let (reader, writer) = tokio::io::split(stream);
            Ok(Connection { reader, writer })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Network controller rejected the protocol handshake",
        )),
    }
}

#[cfg(unix)]
async fn connect(endpoint: &Path) -> io::Result<PlatformStream> {
    tokio::net::UnixStream::connect(endpoint).await
}

#[cfg(windows)]
async fn connect(endpoint: &Path) -> io::Result<PlatformStream> {
    tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint)
}

/// Writes one bounded, length-delimited JSON control message.
pub async fn write_message<W, T>(writer: &mut W, message: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(message)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let length = u32::try_from(payload.len())
        .ok()
        .filter(|length| *length as usize <= MAX_CONTROL_MESSAGE_LENGTH)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Network control message is too large",
            )
        })?;
    writer.write_u32(length).await?;
    writer.write_all(&payload).await?;
    writer.flush().await
}

/// Reads one bounded, length-delimited JSON control message.
pub async fn read_message<R, T>(reader: &mut R) -> io::Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let length = match reader.read_u32().await {
        Ok(length) => length as usize,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    if length > MAX_CONTROL_MESSAGE_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Network control message is too large",
        ));
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_framing_round_trips_protocol_messages() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let expected = RuntimeMessage::AuthorizationRequest {
            request_id: 7,
            flow_id: 9,
            operation: NetworkOperation::Connect {
                source: Some("192.0.2.2:40000".parse().unwrap()),
                destination: "198.51.100.10:443".parse().unwrap(),
                transport: TransportProtocol::Tcp,
                hostname: Some("example.com".to_string()),
            },
        };

        write_message(&mut writer, &expected).await.unwrap();
        let actual = read_message::<_, RuntimeMessage>(&mut reader)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_payload_allocation() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer
            .write_u32((MAX_CONTROL_MESSAGE_LENGTH + 1) as u32)
            .await
            .unwrap();

        let error = read_message::<_, RuntimeMessage>(&mut reader)
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
