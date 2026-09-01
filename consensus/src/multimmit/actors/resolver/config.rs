//! Resolver actor configuration.

use crate::multimmit::scheme::bls12381_threshold::Scheme;
use commonware_cryptography::{PublicKey, bls12381::primitives::variant::Variant};
use std::{num::NonZeroUsize, time::Duration};

/// Configuration for the resolver.
pub(crate) struct Config<P: PublicKey, V: Variant, B, T> {
    /// Scheme of the epoch committee.
    ///
    /// The resolver takes its serving peers, local identity, epoch, and decode bounds from it.
    pub(crate) scheme: Scheme<P, V>,
    /// Peer blocker shared with the engine.
    ///
    /// Resolver response rejection never invokes it because a bad response is not portable proof
    /// of a protocol fault.
    pub(crate) blocker: B,
    /// Execution strategy for proof codec work.
    pub(crate) strategy: T,
    /// Timeout and retry interval for unresolved peer fetches.
    pub(crate) fetch_timeout: Duration,
    /// Request mailbox capacity.
    pub(crate) mailbox_size: NonZeroUsize,
}
