//! Inputs the machine accepts and the results each step returns.

#[cfg(any(test, feature = "mocks"))]
use crate::multimmit::machine::capability::Capability;
use crate::{
    multimmit::{
        machine::{
            artifact::IdentifiedArtifact,
            capability::Capabilities,
            chain::ChainError,
            durability::{BarrierAck, ChangeKind, EffectCompletion, ReplayError},
            finality::{FinalityError, LqcAggregateCompletion},
            job::Generation,
            producer::{BuildCompletion, CustodyCancellation, CustodyCompletion, ProductionTimer},
            resolution::{ResolutionCompletion, ResolutionError},
            verification::VerificationCompletion,
            view::{NullificationRecoveryCompletion, ViewError, ViewTimer, VqcAggregateCompletion},
            vote_body::VoteBuilds,
        },
        types::{Activity, ArtifactId, BlockRef, ChainId, DaCertificate, SignedTransactionBlock},
    },
    types::Height,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// A serialized input to the local state machine.
#[derive(Clone, Debug)]
pub(crate) enum Input<V: Variant, D: Digest> {
    /// Start a fresh machine after making its process generation durable.
    Start,
    /// Finish silent recovery and durably enter a new process generation.
    RecoveryComplete,
    /// Observe one bounded cohort of decoded, untrusted artifacts with their identifiers.
    ///
    /// Identifiers hash the full encoding, so ingress computes them once on its own task
    /// rather than re-hashing multi-kilobyte certificates on the voter loop.
    Observe(Vec<IdentifiedArtifact<V, D>>),
    /// Complete one machine-issued verification job.
    Verified(VerificationCompletion<V, D>),
    /// Complete one safety-journal barrier.
    Persisted(BarrierAck),
    /// Complete one stable durable outbox action.
    EffectCompleted(EffectCompletion<V, D>),
    /// Fire one logical view timer.
    TimerFired(ViewTimer),
    /// Wake the local producer.
    ///
    /// Repeated wakes coalesce until the machine issues a build for the current parent.
    ProducerWake,
    /// Complete one application block build.
    BlockBuilt(BuildCompletion<D>),
    /// Complete validation and durable custody of one locally prepared block.
    BlockCustodied(CustodyCompletion<D>),
    /// Complete cancellation of custody for one superseded prepared block.
    CustodyCancelled(CustodyCancellation),
    /// Complete one machine-issued view-proof request.
    ResolutionCompleted(ResolutionCompletion<V, D>),
    /// Fire one producer deadline bound to a parent.
    ProductionTimerFired(ProductionTimer<D>),
    /// Complete one recovery or aggregation job, which stages a durable change.
    Crypto(CryptoCompletion<V, D>),
}

/// One producer chain's eligible DA-vote run, offered by its chain plane.
///
/// An offer is not an [`Input`]: the core applies it at once through `CoreState::offer`, outside
/// the lanes, and the machine checks its generation.
#[derive(Clone, Debug)]
pub(crate) struct DaVotesOffer<V: Variant, D: Digest> {
    /// The process generation the plane ran under.
    pub(crate) generation: Generation,
    /// The producer chain the run belongs to.
    pub(crate) chain: ChainId,
    /// The contiguous eligible run above the certified anchor, lowest height first.
    pub(crate) candidates: Vec<Arc<SignedTransactionBlock<V, D>>>,
    /// The greatest height the run reaches, or the certified anchor when the run is empty.
    pub(crate) ready_through: Height,
}

/// A completed recovery or aggregation job.
///
/// Each completion stages a durable change, so completions park and drain in arrival order
/// through the machine's scheduler.
#[derive(Clone, Debug)]
pub(crate) enum CryptoCompletion<V: Variant, D: Digest> {
    /// A certificate the own-chain DA task recovered off-thread, to admit and publish.
    DaCertificate {
        /// The certified block.
        block: BlockRef<D>,
        /// The recovered certificate.
        certificate: DaCertificate<V, D>,
    },
    /// One nullification recovery request.
    Nullification(NullificationRecoveryCompletion<V>),
    /// One V-QC aggregation request.
    Vqc(Box<VqcAggregateCompletion<V, D>>),
    /// One L-QC aggregation request.
    Lqc(Box<LqcAggregateCompletion<V, D>>),
}

/// Why a decoded artifact did not enter cryptographic verification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Rejection {
    /// The artifact belongs to another epoch or immutable configuration.
    Context,
    /// An attributed participant is outside the committee.
    Participant,
    /// The encoded artifact exceeds the configured byte ceiling.
    ArtifactTooLarge,
    /// Uncertified traffic is too far ahead of the current view.
    FutureView,
    /// A producer block or data-availability vote is too far above its chain's certified height.
    FutureHeight,
    /// A data-availability vote this node cannot use: it does not produce the vote's chain, or it
    /// holds no verified producer block for the vote's header.
    Unsolicited,
    /// The chain position already retains its bound for this artifact: the signer's
    /// data-availability vote, or the most verified producer blocks.
    PositionFull,
    /// The bounded future-view index is full.
    FutureArtifactsFull,
    /// The artifact cache is full.
    ArtifactCacheFull,
    /// The bounded set of dependency-bearing observations is full.
    DependencyWaitersFull,
    /// No verification job slot is available.
    VerificationJobsFull,
    /// The observation cohort exceeds the configured batch bound.
    VerificationBatchTooLarge,
}

/// Result of admitting one item in an observation cohort.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ObservationResult<D: Digest> {
    pub(crate) id: Option<ArtifactId<D>>,
    pub(crate) status: ObservationStatus,
}

impl<D: Digest> ObservationResult<D> {
    /// Returns the artifact identifier when canonical hashing was required.
    ///
    /// Rejections made by cheap context, participant, view-distance, or byte-bound checks do not hash
    /// the artifact and therefore return `None`.
    #[cfg(test)]
    pub(crate) const fn id(self) -> Option<ArtifactId<D>> {
        self.id
    }

    /// Returns the pre-verification disposition.
    pub(crate) const fn status(self) -> ObservationStatus {
        self.status
    }
}

/// Pre-verification disposition of one observed artifact.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ObservationStatus {
    /// A verification request was emitted.
    Scheduled,
    /// The exact artifact or an equivalent certificate fact was already retained.
    Duplicate,
    /// The artifact failed a bounded pre-verification check.
    Rejected(Rejection),
}

/// Classification of the processed input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StepStatus<D: Digest> {
    /// The input was applied.
    Accepted,
    /// One decoded observation cohort was classified, in observation order.
    Observed(Vec<ObservationResult<D>>),
    /// An entire oversized observation cohort was rejected without hashing its contents.
    CohortRejected {
        /// Number of decoded artifacts supplied by the caller.
        count: usize,
        /// The cohort-level bound that rejected the input.
        rejection: Rejection,
    },
    /// A matching verification completion was applied.
    Verified {
        /// Number of cryptographically valid items.
        valid: usize,
        /// Number of cryptographically invalid items.
        invalid: usize,
    },
    /// A matched view-proof resolution was classified for verification.
    ResolutionCompleted {
        /// The proof's pre-verification disposition.
        admission: ObservationStatus,
    },
    /// A completion belonged to a missing or prior-generation job.
    StaleCompletion,
}

/// Authoritative capabilities and non-authoritative activities emitted by one core transition.
pub(crate) type StepParts<V, D> = (Capabilities<V, D>, Vec<Activity<V, D>>);

/// Bounded capabilities emitted while polling core-owned semantic work.
#[derive(Clone, Debug)]
pub(crate) struct PollResult<V: Variant, D: Digest> {
    pub(crate) capabilities: Capabilities<V, D>,
    pub(crate) activities: Vec<Activity<V, D>>,
    /// Vote-pass lifecycle events for tracing. They never influence protocol decisions.
    pub(crate) vote_builds: VoteBuilds,
}

impl<V: Variant, D: Digest> PollResult<V, D> {
    /// Returns capabilities in deterministic issuance order.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn capabilities(&self) -> &[Capability<V, D>] {
        &self.capabilities
    }

    /// Returns non-authoritative activities authorized by this poll.
    #[cfg(test)]
    pub(crate) fn activities(&self) -> &[Activity<V, D>] {
        &self.activities
    }

    /// Consumes the result and returns its capabilities.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn into_capabilities(self) -> Capabilities<V, D> {
        self.capabilities
    }

    /// Consumes the result and separates authoritative capabilities from telemetry.
    #[cfg(test)]
    pub(crate) fn into_parts(self) -> StepParts<V, D> {
        (self.capabilities, self.activities)
    }
}

/// Result of one deterministic machine step.
#[derive(Clone, Debug)]
pub(crate) struct Step<V: Variant, D: Digest> {
    pub(crate) status: StepStatus<D>,
    pub(crate) capabilities: Capabilities<V, D>,
    pub(crate) activities: Vec<Activity<V, D>>,
}

impl<V: Variant, D: Digest> Step<V, D> {
    pub(crate) fn new(status: StepStatus<D>, capabilities: impl Into<Capabilities<V, D>>) -> Self {
        Self {
            status,
            capabilities: capabilities.into(),
            activities: Vec::new(),
        }
    }

    /// Returns the result for a completion that belonged to a missing or prior-generation job.
    pub(crate) const fn stale() -> Self {
        Self {
            status: StepStatus::StaleCompletion,
            capabilities: Capabilities::new(),
            activities: Vec::new(),
        }
    }

    /// Returns the input classification.
    pub(crate) const fn status(&self) -> &StepStatus<D> {
        &self.status
    }

    /// Returns immutable capabilities in deterministic issuance order.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn capabilities(&self) -> &[Capability<V, D>] {
        &self.capabilities
    }

    /// Returns non-authoritative activities authorized by this step.
    #[cfg(test)]
    pub(crate) fn activities(&self) -> &[Activity<V, D>] {
        &self.activities
    }

    /// Consumes the result and returns its capabilities.
    pub(crate) fn into_capabilities(self) -> Capabilities<V, D> {
        self.capabilities
    }

    /// Consumes the result and separates authoritative capabilities from telemetry.
    pub(crate) fn into_parts(self) -> StepParts<V, D> {
        (self.capabilities, self.activities)
    }
}

impl<V: Variant, D: Digest> From<StepStatus<D>> for Step<V, D> {
    fn from(status: StepStatus<D>) -> Self {
        Self {
            status,
            capabilities: Capabilities::new(),
            activities: Vec::new(),
        }
    }
}

/// A malformed attached-executor completion or exhausted machine identifier.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum StepError {
    /// The completion did not exactly match the retained job and ticket order.
    #[error("completion does not match the issued job")]
    CompletionMismatch,
    /// A deterministic sequence identifier overflowed.
    #[error("machine identifier exhausted")]
    IdentifierExhausted,
    /// An input was not valid in the machine's startup or recovery lifecycle.
    #[error("input is not valid in the current machine lifecycle")]
    Lifecycle,
    /// A durable change the machine staged or restored failed its transition check.
    #[error("invalid durable {change} transition: {source}")]
    DurableTransition {
        /// The kind of the failed change.
        change: ChangeKind,
        /// The failed check.
        source: ReplayError,
    },
    /// An attached executor returned the wrong artifact or completion kind.
    #[error("durable effect completion does not match its request")]
    EffectMismatch,
    /// The local role, protocol context, or request shape may not authorize the effect.
    #[error("the local profile cannot authorize this effect")]
    UnauthorizedEffect,
    /// A previously authorized local completion cannot fit its reserved artifact slot.
    #[error("local artifact reservation was not preserved")]
    LocalArtifactReservation,
    /// A local signing completion exceeds the configured artifact byte ceiling.
    #[error("local signing completion exceeds the artifact byte ceiling")]
    LocalArtifactTooLarge,
    /// The durable external-action outbox reached its configured ceiling.
    #[error("durable effect outbox is full")]
    OutboxFull,
    /// The bounded persistence pipeline was driven without first receiving an acknowledgement.
    #[error("persistence pipeline is full")]
    PersistenceCapacity,
    /// First-forwarding history reached its configured ceiling.
    #[error("certificate forwarding history is full")]
    ForwardingHistoryFull,
    /// Authenticated chain facts contradict a local protocol invariant.
    #[error("authenticated transaction-chain facts violate a protocol invariant")]
    ChainInvariant,
    /// Authenticated view facts contradict a local protocol invariant.
    #[error("authenticated view facts violate a protocol invariant")]
    ViewInvariant,
    /// Authenticated finality facts contradict a local protocol invariant.
    #[error("authenticated leader-finality facts violate a protocol invariant")]
    FinalityInvariant,
}

impl From<ChainError> for StepError {
    fn from(error: ChainError) -> Self {
        match error {
            ChainError::IdentifierExhausted | ChainError::HeightOverflow => {
                Self::IdentifierExhausted
            }
            ChainError::CompletionMismatch => Self::CompletionMismatch,
            ChainError::Context
            | ChainError::CertifiedConflict
            | ChainError::ProducerConflict
            | ChainError::DaVoteConflict
            | ChainError::Reservation(_) => Self::ChainInvariant,
        }
    }
}

impl From<ViewError> for StepError {
    fn from(error: ViewError) -> Self {
        match error {
            ViewError::IdentifierExhausted => Self::IdentifierExhausted,
            ViewError::CompletionMismatch => Self::CompletionMismatch,
            ViewError::Slot(_)
            | ViewError::Proposal
            | ViewError::Certificate
            | ViewError::MissingParent => Self::ViewInvariant,
            ViewError::Chain => Self::ChainInvariant,
        }
    }
}

impl From<ResolutionError> for StepError {
    fn from(error: ResolutionError) -> Self {
        match error {
            ResolutionError::IdentifierExhausted => Self::IdentifierExhausted,
        }
    }
}

impl From<FinalityError> for StepError {
    fn from(error: FinalityError) -> Self {
        match error {
            FinalityError::IdentifierExhausted => Self::IdentifierExhausted,
            FinalityError::CompletionMismatch => Self::CompletionMismatch,
            FinalityError::LeaderCollision | FinalityError::Invariant => Self::FinalityInvariant,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_errors_map_to_the_failing_component() {
        assert_eq!(StepError::from(ViewError::Chain), StepError::ChainInvariant);
        for error in [
            ViewError::Proposal,
            ViewError::Certificate,
            ViewError::MissingParent,
        ] {
            assert_eq!(StepError::from(error), StepError::ViewInvariant);
        }
        assert_eq!(
            StepError::from(ViewError::IdentifierExhausted),
            StepError::IdentifierExhausted
        );
        assert_eq!(
            StepError::from(ViewError::CompletionMismatch),
            StepError::CompletionMismatch
        );
    }
}
