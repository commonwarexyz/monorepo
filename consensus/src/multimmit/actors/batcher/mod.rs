//! Bounded hostile-ingress and verification executor for one Multimmit epoch.
//!
//! The batcher owns the data, consensus, and certificate network planes. It decodes canonical
//! envelopes, enforces explicit item and byte bounds with per-peer and per-chain fairness, and
//! forwards bounded untrusted observation cohorts to the voter. It also executes machine-issued
//! verification jobs on shared runtime CPU tasks using the production scheme batch APIs. A job
//! carrying view progress runs on the view-critical execution pool, so a vote or certificate
//! verdict never queues behind bulk header and availability verification.
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
use commonware_utils::N5f1;
#[cfg(any(test, feature = "test-utils"))]
pub use fuzz::exercise_lanes;
pub(crate) use lanes::VIEW_COHORT_ITEMS;
use std::{collections::VecDeque, num::NonZeroUsize, time::SystemTime};
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
}

impl IngressLimits {
    /// Returns one peer's item and byte share of a lane in a committee of `participants`.
    ///
    /// Splitting a lane across `f + 1` fault domains leaves a whole share for a correct peer no
    /// matter how the faulty ones fill theirs. The share is only useful if it holds more than one
    /// maximum-size group, which is what `lane_bytes` is sized for.
    pub(crate) fn peer_share(self, participants: usize) -> (usize, usize) {
        let fault_domains = N5f1::f_plus_one(participants) as usize;
        (
            self.lane_items.get() / fault_domains,
            self.lane_bytes.get() / fault_domains,
        )
    }
}

/// Configuration for the batcher actor.
pub struct Config<P: PublicKey, V: Variant, B, T, C> {
    /// Verification scheme for the epoch committee.
    pub scheme: Scheme<P, V>,
    /// Peer blocker for malformed or contextually invalid traffic.
    pub blocker: B,
    /// Execution strategy for bulk CPU-heavy verification.
    ///
    /// Carries plane decoding, ingress identification, and every verdict the round does not wait
    /// on: transaction-block headers and data-availability votes and certificates.
    pub strategy: T,
    /// Execution strategy for view-critical CPU-heavy verification.
    ///
    /// Carries the verdicts on the vote-to-finality path: leader blocks, votes, novotes,
    /// nullifies, nullifications, V-QCs, and L-QCs.
    pub critical_strategy: C,
    /// Bounded decode configuration for the epoch.
    pub codec: CodecConfig,
    /// Hard ingress and verification bounds.
    pub limits: IngressLimits,
    /// Control mailbox capacity.
    pub mailbox_size: NonZeroUsize,
    /// Maximum observation cohorts awaiting voter consumption.
    ///
    /// Ready ingress completions are grouped into bounded cohorts and forwarded as soon as credit
    /// is free. While every credit is in flight, ingress accumulates in the fair lanes.
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
    /// Release observation slots after the voter consumes their cohorts.
    ObservationsConsumed(usize),
    /// Block the authenticated senders of artifacts a later stage proved invalid.
    ///
    /// Data-availability shares are admitted on structural checks and only attributed when
    /// their quorum fails to recover, so their sources are named after the batcher has already
    /// returned a verdict. Blocking stays the batcher's authority.
    Block {
        /// Peers that supplied an invalid artifact.
        peers: Vec<P>,
    },
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
    /// The total canonical encoded length of the cohort's artifacts.
    ///
    /// Admission already measured every artifact, so the voter accounts for the cohort's residency
    /// from this total instead of re-walking each decoded value.
    pub bytes: usize,
    /// The ingress tracing span for this cohort.
    pub span: Span,
    /// When the batcher handed the cohort to the voter.
    pub forwarded_at: SystemTime,
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
