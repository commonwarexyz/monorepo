//! Verifier actor configuration.

use crate::multimmit::scheme::bls12381::Scheme;
use commonware_cryptography::{PublicKey, bls12381::primitives::variant::Variant};
use std::num::NonZeroUsize;

/// Configuration for the verifier actor.
pub(crate) struct Config<P: PublicKey, V: Variant, T, C> {
    /// Verification scheme for the epoch committee.
    pub(crate) scheme: Scheme<P, V>,
    /// Execution strategy for every verdict the view does not wait on: transaction-block headers
    /// and L-QCs.
    pub(crate) strategy: T,
    /// Execution strategy for the verdicts on the path to the next view: leader blocks, vote
    /// updates, V-QCs, and finalization certificates.
    pub(crate) critical_strategy: C,
    /// Maximum concurrently executing verification jobs.
    pub(crate) inflight_jobs: NonZeroUsize,
    /// Control mailbox capacity.
    pub(crate) mailbox_size: NonZeroUsize,
}
