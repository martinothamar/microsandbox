//! Upstream resolution for queries the guest addresses to the sandbox gateway.
//!
//! [`Upstream`] is the only interface the forwarder uses for the gateway
//! path. Explicitly configured nameservers are pinned for the sandbox's
//! lifetime on every platform. Without them, queries go through the host's
//! system resolver, which [`system`] implements once per platform behind one
//! API, so platform differences stay out of the forwarding logic.

mod gateway;
mod pinned;
mod system;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub(crate) use gateway::{GatewayQuery, Upstream};
pub(crate) use pinned::PinnedUpstreams;
