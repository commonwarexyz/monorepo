//! Verifier actor configuration.

use crate::multimmit::scheme::bls12381_threshold::Scheme;
use commonware_cryptography::{PublicKey, bls12381::primitives::variant::Variant};
use std::num::NonZeroUsize;

/// Configuration for the verifier actor.
pub(crate) struct Config<P: PublicKey, V: Variant, T, C> {
    /// Verification scheme for the epoch committee.
    pub(crate) scheme: Scheme<P, V>,
    /// Execution strategy for every verdict the round does not wait on: transaction-block headers
    /// and data-availability votes and certificates.
    pub(crate) strategy: T,
    /// Execution strategy for the verdicts on the vote-to-finality path: leader blocks, votes,
    /// novotes, nullifies, nullifications, V-QCs, and L-QCs.
    pub(crate) critical_strategy: C,
    /// Maximum concurrently executing verification jobs.
    pub(crate) inflight_jobs: NonZeroUsize,
    /// Control mailbox capacity.
    pub(crate) mailbox_size: NonZeroUsize,
}
