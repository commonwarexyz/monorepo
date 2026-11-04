//! Resolver actor configuration.

use crate::multimmit::scheme::{Generic, Scheme};
use commonware_utils::NonZeroDuration;
use std::num::NonZeroUsize;

/// Configuration for the resolver.
pub(crate) struct Config<S: Scheme, B, T> {
    /// Scheme of the epoch committee.
    ///
    /// The resolver takes its serving peers, local identity, epoch, and decode bounds from it.
    pub(crate) scheme: Generic<S>,
    /// Peer blocker shared with the engine.
    ///
    /// Resolver response rejection never invokes it because a bad response is not portable proof
    /// of a protocol fault.
    pub(crate) blocker: B,
    /// Execution strategy for proof codec work.
    pub(crate) strategy: T,
    /// Timeout and retry interval for unresolved peer fetches.
    pub(crate) fetch_timeout: NonZeroDuration,
    /// Request mailbox capacity.
    pub(crate) mailbox_size: NonZeroUsize,
}
