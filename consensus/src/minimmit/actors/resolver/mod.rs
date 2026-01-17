//! Resolver actor for Minimmit consensus.
//!
//! The resolver fetches missing certificates from peers to enable view progression.
//! It maintains a floor (highest finalization or M-notarization) and tracks nullifications
//! for views above the floor.

mod actor;
mod ingress;
mod state;

use crate::types::Epoch;
pub use actor::Actor;
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
pub use ingress::Mailbox;
use std::time::Duration;

/// Configuration for the resolver actor.
pub struct Config<S, B, T>
where
    S: Scheme,
    B: Blocker,
    T: Strategy,
{
    /// Signing scheme for certificate verification.
    pub scheme: S,
    /// Network blocker for malicious peers.
    pub blocker: B,
    /// Strategy for parallel operations.
    pub strategy: T,
    /// Current epoch.
    pub epoch: Epoch,
    /// Maximum number of messages to buffer.
    pub mailbox_size: usize,
    /// Maximum number of concurrent fetch requests.
    pub fetch_concurrent: usize,
    /// Timeout for fetch requests.
    pub fetch_timeout: Duration,
}
