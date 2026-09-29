//! Upstream resolution for queries the guest addresses to the sandbox gateway.
//!
//! [`Upstream`] is the forwarder's only interface to upstreams: pinned
//! nameservers when configured, otherwise the host's system resolver, which
//! [`system`] implements once per platform behind one API.

mod gateway;
mod pinned;
mod system;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub(crate) use gateway::{GatewayQuery, Upstream};
pub(crate) use pinned::PinnedUpstreams;
