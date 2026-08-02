//! Bounded hostile-ingress and verification executor for one Multimmit epoch.
//!
//! The batcher owns the data, consensus, and certificate network planes. It decodes canonical
//! envelopes, enforces explicit item and byte bounds with per-peer and per-chain fairness, and
//! forwards bounded untrusted observation cohorts to the voter. It also executes machine-issued
//! verification jobs on shared runtime CPU tasks using the production scheme batch APIs.
//!
//! The batcher never chooses a quorum, admits an artifact, constructs a certificate, or forwards
//! protocol traffic on its own authority. Authoritative admission happens only when the machine
//! consumes an observation or verification completion delivered by the voter.
//!
//! Deployments must bound each physical channel's backlog and per-peer ingress quota so their
//! aggregate admitted traffic does not exceed the actor's service capacity. Plane rotation bounds
//! service among already-admitted messages; it does not replace those admission controls. Within
//! each lane, the actor reserves one capacity share beyond the `f` Byzantine shares and rotates
//! service across authenticated peers.

mod actor;
#[cfg(any(test, feature = "test-utils"))]
mod fuzz;
mod lanes;
mod metrics;

use crate::{
    multimmit::{
        config::CodecConfig,
        machine::{IdentifiedArtifact, VerificationCompletion, VerifyJob},
        scheme::bls12381_threshold::Scheme,
    },
    types::Round,
};
pub use actor::Actor;
use commonware_actor::mailbox::{Policy, UnreliablePolicy};
use commonware_cryptography::{Digest, PublicKey, bls12381::primitives::variant::Variant};
#[cfg(any(test, feature = "test-utils"))]
pub use fuzz::exercise_lanes;
use std::{collections::VecDeque, num::NonZeroUsize, time::Duration};
use tracing::Span;

/// Explicit ingress and verification resource bounds.
///
/// These bounds are hard ceilings enforced before any reliable mailbox. Saturation drops hostile
/// ingress with typed accounting instead of growing an unbounded queue.
#[derive(Copy, Clone, Debug)]
pub struct IngressLimits {
    /// Target artifacts forwarded in one observation cohort.
    ///
    /// An indivisible parent-and-proposal group may exceed this target by one artifact.
    pub cohort_items: NonZeroUsize,
    /// Maximum artifacts buffered per ingress lane.
    pub lane_items: NonZeroUsize,
    /// Maximum encoded artifact bytes buffered per ingress lane.
    pub lane_bytes: NonZeroUsize,
    /// Maximum concurrently executing verification jobs.
    pub inflight_jobs: NonZeroUsize,
    /// How long a partial cohort may wait for more ingress before it is flushed.
    pub coalesce: Duration,
}

/// Configuration for the batcher actor.
pub struct Config<P: PublicKey, V: Variant, B, T> {
    /// Verification scheme for the epoch committee.
    pub scheme: Scheme<P, V>,
    /// Peer blocker for malformed or contextually invalid traffic.
    pub blocker: B,
    /// Execution strategy for CPU-heavy verification.
    pub strategy: T,
    /// Bounded decode configuration for the epoch.
    pub codec: CodecConfig,
    /// Hard ingress and verification bounds.
    pub limits: IngressLimits,
    /// Control mailbox capacity.
    pub mailbox_size: NonZeroUsize,
    /// Maximum observation cohorts awaiting voter consumption.
    pub observation_capacity: NonZeroUsize,
}

/// Control messages accepted by the batcher.
pub enum Message<P: PublicKey, V: Variant, D: Digest> {
    /// Execute one exact machine-issued verification job.
    Verify {
        /// The caller's tracing span for this job.
        span: Span,
        /// The round that issued the job.
        round: Round,
        /// The exact machine-issued job.
        job: VerifyJob<V, D>,
        /// Authenticated network sources aligned with the job's exact item order.
        ///
        /// Machine-issued items for local or resolved artifacts have no source.
        sources: Vec<Option<P>>,
    },
    /// Release one observation slot after the voter consumed a cohort.
    ObservationConsumed,
}

impl<P: PublicKey, V: Variant, D: Digest> Policy for Message<P, V, D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // Every control message is issued against separately accounted machine or voter state
        // (in-flight verification jobs and validation requests), so retention is bounded.
        overflow.push_back(message);
    }
}

/// One bounded untrusted observation cohort for the voter.
///
/// Delivery uses a bounded unreliable mailbox with explicit credits. The batcher stops admitting
/// network traffic before this mailbox can saturate, so admitted artifacts are not lost.
pub struct Observed<P: PublicKey, V: Variant, D: Digest> {
    /// Decoded untrusted artifacts in observation order, each paired with its authenticated source.
    ///
    /// Identifiers hash the full encoding. The batcher owns that cost so the voter loop never
    /// re-hashes a multi-kilobyte certificate to deduplicate replayed ingress.
    pub artifacts: Vec<(P, IdentifiedArtifact<V, D>)>,
    /// The ingress tracing span for this cohort.
    pub span: Span,
}

impl<P: PublicKey, V: Variant, D: Digest> UnreliablePolicy for Observed<P, V, D> {
    type Overflow = VecDeque<Self>;

    fn handle(_: &mut Self::Overflow, _: Self) -> bool {
        // Reject under backpressure: untrusted ingress is never buffered unboundedly.
        false
    }
}

/// One exact verification completion for the voter's accounted control path.
pub struct Completed<D: Digest> {
    /// The issuing job's tracing span.
    pub span: Span,
    /// The round that issued the job.
    pub round: Round,
    /// The exact per-item verdicts.
    pub completion: VerificationCompletion<D>,
}

impl<D: Digest> Policy for Completed<D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // Completions are bounded by the in-flight verification job ceiling and must not be lost.
        overflow.push_back(message);
    }
}

/// Why one decoded message was dropped before verification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Drop {
    /// The destination lane reached its item or byte bound.
    Lane,
    /// The sending peer exceeded its item or byte share in the destination lane.
    Peer,
}

#[cfg(test)]
mod tests;
