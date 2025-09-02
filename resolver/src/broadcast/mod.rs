//! Resolve data identified by a fixed-length key by broadcasting requests to all peers and
//! accepting push updates.
//!
//! Overview
//! - Fire-and-forget: on `fetch(key)`, send a request to all peers, then await any responses
//! - Push support: accept unsolicited responses (push) from any peer at any time
//! - Deduplication: cache content hashes per key, so repeated data is not re-delivered even if
//!   received from multiple peers or repeatedly from the same peer
//! - Cancellation: after `cancel(key)`, further deliveries for that key are ignored
//!
//! This module mirrors the structure of `resolver::p2p` while simplifying the request lifecycle:
//! there are no per-request IDs or retries; all initial requests are broadcast and subsequent
//! updates are push-driven.

use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_utils::Span;
use std::future::Future;

mod config;
pub use config::Config;
mod engine;
pub use engine::Engine;
mod ingress;
pub use ingress::Mailbox;
mod wire;

#[cfg(test)]
mod tests;

/// Serves data requested by the network (when this node receives a broadcast request).
pub trait Producer: Clone + Send + 'static {
    /// Type used to uniquely identify data.
    type Key: Span;

    /// Serve a request received from the network.
    fn produce(
        &mut self,
        key: Self::Key,
    ) -> impl Future<Output = futures::channel::oneshot::Receiver<Bytes>> + Send;
}

/// Manages the set of peers that can be used to broadcast requests.
pub trait Coordinator: Clone + Send + Sync + 'static {
    /// Type used to uniquely identify peers.
    type PublicKey: PublicKey;

    /// Returns the current list of peers to which requests will be broadcast.
    fn peers(&self) -> &Vec<Self::PublicKey>;

    /// Returns an identifier for the peer set. Must change whenever the peer list changes.
    fn peer_set_id(&self) -> u64;
}
