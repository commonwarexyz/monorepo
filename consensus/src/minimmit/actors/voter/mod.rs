//! Voter actor for Minimmit consensus.
//!
//! The voter is the main consensus participant that processes proposals, votes,
//! and drives view progression.
//!
//! ## Crash Recovery
//!
//! The voter uses a journal to persist votes and certificates for crash recovery.
//! On restart, the journal is replayed to rebuild state, ensuring we don't
//! double-vote and can resume from where we left off.

// Allow dead code until fully integrated
#![allow(dead_code)]

mod actor;
mod egress;
mod ingress;

use crate::{
    elector::Config as Elector,
    minimmit::types::Activity,
    types::{Epoch, ViewDelta},
    Automaton, Relay, Reporter,
};
pub use actor::Actor;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::buffer::paged::CacheRef;
pub use ingress::Mailbox;
use std::{num::NonZeroUsize, time::Duration};

/// Configuration for the voter actor.
pub struct Config<S, L, B, D, A, R, F, T>
where
    S: Scheme,
    L: Elector<S>,
    B: Blocker,
    D: Digest,
    A: Automaton,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
    pub scheme: S,
    pub elector: L,
    pub blocker: B,
    pub automaton: A,
    pub relay: R,
    pub reporter: F,
    pub strategy: T,

    /// Partition name for the journal.
    pub partition: String,
    /// Number of bytes to buffer when replaying during startup.
    pub replay_buffer: NonZeroUsize,
    /// The size of the write buffer to use for each blob in the journal.
    pub write_buffer: NonZeroUsize,
    /// Page cache for the journal.
    pub page_cache: CacheRef,

    pub epoch: Epoch,
    pub mailbox_size: usize,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub activity_timeout: ViewDelta,
}
