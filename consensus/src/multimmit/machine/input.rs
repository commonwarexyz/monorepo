//! Inputs the machine accepts, the completions of work it issued, and the results each step
//! returns.

#[cfg(any(test, feature = "mocks"))]
use crate::multimmit::machine::capability::Capability;
use crate::multimmit::{
    machine::{
        artifact::IdentifiedArtifact,
        capability::{AggregateId, BuildId, Capabilities},
        durability::{BarrierAck, ChangeKind, EffectCompletion, ReplayError},
        job::{Generation, Issued},
        resolution::ResolutionCompletion,
        scheduler::ProtocolComponent,
        verification::VerificationCompletion,
    },
    types::{Activity, ArtifactId, BlockRef, Lqc, TransactionBlockHeader, Vqc},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};

/// A monotonic local clock reading in milliseconds.
///
/// The voter reads its clock when it admits an input and when it runs a machine pass, and supplies
/// the reading to the core. The reading is volatile: durable events never carry it, so replay
/// reproduces state without a clock.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Now(u64);

impl Now {
    /// Wraps a reading of `millis` milliseconds.
    pub(crate) const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Returns the reading in milliseconds.
    pub(crate) const fn millis(self) -> u64 {
        self.0
    }

    /// Returns the reading `millis` milliseconds later, saturating at the largest reading.
    pub(crate) const fn saturating_add(self, millis: u64) -> Self {
        Self(self.0.saturating_add(millis))
    }

    /// Returns the milliseconds elapsed since `earlier`, or zero when `earlier` is later.
    pub(crate) const fn saturating_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// A logical deadline family the machine arms with
/// [`TimerCommand::Arm`](super::capability::TimerCommand::Arm).
///
/// A family holds at most one deadline: arming it again replaces the earlier one. A tick carries no
/// deadline, so the machine compares the pass's [`Now`] with the deadline it holds and ignores an
/// early or superseded tick.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum TimerFamily {
    /// The current view's progress deadlines.
    View,
    /// The next vote update this node may send.
    Update,
    /// The local producer's next production slot.
    Production,
    /// The deadline that forces the current view to resolve.
    Liveness,
}

impl TimerFamily {
    /// The number of families.
    pub(crate) const COUNT: usize = 4;
    /// Every family.
    pub(crate) const ALL: [Self; Self::COUNT] =
        [Self::View, Self::Update, Self::Production, Self::Liveness];
}

/// A serialized input to the local state machine.
#[derive(Clone, Debug)]
pub(crate) enum Input<V: Variant, D: Digest> {
    /// Start a fresh machine after making its process generation durable.
    Start,
    /// Finish silent recovery and durably enter a new process generation.
    RecoveryComplete,
    /// Observe one bounded cohort of decoded, untrusted artifacts with their identifiers.
    ///
    /// Identifiers hash the full encoding, so ingress computes them once on its own task rather
    /// than re-hashing large certificates on the voter loop.
    Observe(Vec<IdentifiedArtifact<V, D>>),
    /// Complete one machine-issued verification job.
    Verified(VerificationCompletion<D>),
    /// Complete one safety-journal barrier.
    Persisted(BarrierAck),
    /// Complete one stable durable outbox action.
    EffectCompleted(EffectCompletion<V, D>),
    /// Fire the deadline of one timer family.
    Tick(TimerFamily),
    /// Complete one application block build.
    BlockBuilt(BuildCompletion<D>),
    /// Complete durable custody of one locally built block.
    BlockCustodied(CustodyCompletion<D>),
    /// Report a chain plane's application verdict on one peer block, the fence for full
    /// acceptance.
    Validated(ValidationCompletion<D>),
    /// Complete one machine-issued retrieval.
    ResolutionCompleted(ResolutionCompletion<V, D>),
    /// Complete one certificate aggregation, which stages a durable change.
    Crypto(CryptoCompletion<V, D>),
}

impl<V: Variant, D: Digest> Input<V, D> {
    /// Returns the input's kind.
    pub(crate) const fn kind(&self) -> InputKind {
        match self {
            Self::Start | Self::RecoveryComplete => InputKind::Lifecycle,
            Self::Observe(_) => InputKind::Observe,
            Self::Verified(_) => InputKind::Verified,
            Self::Persisted(_) => InputKind::Persisted,
            Self::EffectCompleted(_) => InputKind::EffectCompleted,
            Self::Tick(_) => InputKind::Tick,
            Self::BlockBuilt(_) => InputKind::BlockBuilt,
            Self::BlockCustodied(_) => InputKind::BlockCustodied,
            Self::Validated(_) => InputKind::Validated,
            Self::ResolutionCompleted(_) => InputKind::ResolutionCompleted,
            Self::Crypto(_) => InputKind::Crypto,
        }
    }
}

/// The kind of an [`Input`], which attributes the core's service time.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum InputKind {
    /// A start or the end of recovery.
    Lifecycle,
    /// A peer observation cohort.
    Observe,
    /// A verification completion.
    Verified,
    /// A safety-journal barrier acknowledgement.
    Persisted,
    /// A durable outbox action completion.
    EffectCompleted,
    /// A timer tick.
    Tick,
    /// An application build completion.
    BlockBuilt,
    /// A durable custody completion.
    BlockCustodied,
    /// A chain plane's validation verdict.
    Validated,
    /// A retrieval completion.
    ResolutionCompleted,
    /// A certificate aggregation completion.
    Crypto,
}

impl InputKind {
    /// The number of kinds.
    pub(crate) const COUNT: usize = 11;
    /// Every kind.
    pub(crate) const ALL: [Self; Self::COUNT] = [
        Self::Lifecycle,
        Self::Observe,
        Self::Verified,
        Self::Persisted,
        Self::EffectCompleted,
        Self::Tick,
        Self::BlockBuilt,
        Self::BlockCustodied,
        Self::Validated,
        Self::ResolutionCompleted,
        Self::Crypto,
    ];
}

/// Completion of one application build request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct BuildCompletion<D: Digest> {
    issued: Issued<BuildId>,
    parent: BlockRef<D>,
    body: Option<D>,
}

impl<D: Digest> BuildCompletion<D> {
    /// Creates a build completion. `None` reports that the application built no block.
    ///
    /// A present body digest names a complete block. It grants no signing authority until a
    /// matching [`CustodyCompletion`] reports the body durably held.
    pub(crate) const fn new(issued: Issued<BuildId>, parent: BlockRef<D>, body: Option<D>) -> Self {
        Self {
            issued,
            parent,
            body,
        }
    }

    /// Returns the build this completes.
    pub(crate) const fn issued(&self) -> Issued<BuildId> {
        self.issued
    }

    /// Returns the producer parent the block extends.
    pub(crate) const fn parent(&self) -> BlockRef<D> {
        self.parent
    }

    /// Returns the built body's digest, if the application built a block.
    pub(crate) const fn body(&self) -> Option<D> {
        self.body
    }
}

/// Durable custody of one locally built block, which authorizes signing its header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CustodyCompletion<D: Digest> {
    issued: Issued<BuildId>,
    header: TransactionBlockHeader<D>,
}

impl<D: Digest> CustodyCompletion<D> {
    /// Creates a custody completion.
    pub(crate) const fn new(issued: Issued<BuildId>, header: TransactionBlockHeader<D>) -> Self {
        Self { issued, header }
    }

    /// Returns the build this completes.
    pub(crate) const fn issued(&self) -> Issued<BuildId> {
        self.issued
    }

    /// Returns the custodied header.
    pub(crate) const fn header(&self) -> &TransactionBlockHeader<D> {
        &self.header
    }
}

/// The application's verdict on one peer block's body.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum BlockValidity {
    /// The body is valid and durably held by the application.
    Valid,
    /// The body is invalid.
    Invalid,
    /// The application reached no verdict, so the block can only be adopted.
    Unavailable,
}

/// A chain plane's verdict on one block it was asked to validate.
///
/// Chain planes are volatile per process generation, so the verdict carries the generation of the
/// plane that produced it, and the machine ignores a verdict from an earlier generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidationCompletion<D: Digest> {
    generation: Generation,
    block: BlockRef<D>,
    validity: BlockValidity,
}

impl<D: Digest> ValidationCompletion<D> {
    /// Creates a verdict on `block` from a plane of `generation`.
    pub(crate) const fn new(
        generation: Generation,
        block: BlockRef<D>,
        validity: BlockValidity,
    ) -> Self {
        Self {
            generation,
            block,
            validity,
        }
    }

    /// Returns the generation of the plane that produced the verdict.
    pub(crate) const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the validated block.
    pub(crate) const fn block(&self) -> BlockRef<D> {
        self.block
    }

    /// Returns the verdict.
    pub(crate) const fn validity(&self) -> BlockValidity {
        self.validity
    }
}

/// An assembled certificate correlated to the aggregation job that requested it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Aggregated<C> {
    issued: Issued<AggregateId>,
    certificate: C,
}

impl<C> Aggregated<C> {
    /// Creates the completion of job `issued`.
    pub(crate) const fn new(issued: Issued<AggregateId>, certificate: C) -> Self {
        Self {
            issued,
            certificate,
        }
    }

    /// Returns the job this completes.
    pub(crate) const fn issued(&self) -> Issued<AggregateId> {
        self.issued
    }

    /// Returns the assembled certificate.
    pub(crate) const fn certificate(&self) -> &C {
        &self.certificate
    }

    /// Returns the assembled certificate, consuming the completion.
    pub(crate) fn into_certificate(self) -> C {
        self.certificate
    }
}

/// A completed certificate aggregation.
///
/// Each completion stages a durable change, so completions park and drain in arrival order
/// through the machine's scheduler.
#[derive(Clone, Debug)]
pub(crate) enum CryptoCompletion<V: Variant, D: Digest> {
    /// One V-QC aggregation.
    Vqc(Box<Aggregated<Vqc<V, D>>>),
    /// One L-QC aggregation.
    Lqc(Box<Aggregated<Lqc<V, D>>>),
}

impl<V: Variant, D: Digest> CryptoCompletion<V, D> {
    /// Returns the job this completes.
    pub(crate) const fn issued(&self) -> Issued<AggregateId> {
        match self {
            Self::Vqc(completion) => completion.issued(),
            Self::Lqc(completion) => completion.issued(),
        }
    }
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
    /// A view-tagged artifact lies outside the window of views the machine accepts.
    TagWindow,
    /// A producer block lies outside its chain's buffer: at or below the accepted tip, more than
    /// the tip lead `D + 2N` above the tip or above `h*`, or on the local producer's own chain.
    TipLead,
    /// The block's chain and height already hold their bound of retained blocks.
    HeightFull,
    /// The certificate's view already holds its bound of V-QCs.
    CertificatesFull,
    /// The sender already holds its bound of pending vote updates.
    PendingUpdatesFull,
    /// A vote update is not newer than one already read from its sender for its view tag, or
    /// follows the sender's final vote of the tag.
    Superseded,
    /// The bounded future-view index is full.
    FutureArtifactsFull,
    /// The artifact cache is full.
    ArtifactCacheFull,
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
    /// Rejections made by cheap context, participant, view-distance, or byte-bound checks do not
    /// hash the artifact and therefore return `None`.
    #[cfg(test)]
    pub(crate) const fn id(self) -> Option<ArtifactId<D>> {
        self.id
    }

    /// Returns the pre-verification outcome.
    pub(crate) const fn status(self) -> ObservationStatus {
        self.status
    }
}

/// Pre-verification outcome of one observed artifact.
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
    /// A matched retrieval was classified for verification.
    ResolutionCompleted {
        /// The retrieved artifact's pre-verification outcome.
        admission: ObservationStatus,
    },
    /// A completion belonged to a missing or prior-generation job.
    StaleCompletion,
}

/// Authoritative capabilities and non-authoritative activities emitted by one core transition.
pub(crate) type StepParts<V, D> = (Capabilities<V, D>, Vec<Activity<V, D>>);

/// Bounded capabilities emitted while polling machine-owned work.
#[derive(Clone, Debug)]
pub(crate) struct PollResult<V: Variant, D: Digest> {
    pub(crate) capabilities: Capabilities<V, D>,
    pub(crate) activities: Vec<Activity<V, D>>,
    /// The component whose quantum the poll drove, or `None` when it only completed issued work.
    pub(crate) driven: Option<ProtocolComponent>,
}

impl<V: Variant, D: Digest> PollResult<V, D> {
    /// Returns capabilities in deterministic issuance order.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn capabilities(&self) -> &[Capability<V, D>] {
        &self.capabilities
    }

    /// Consumes the result and separates authoritative capabilities from activities.
    #[cfg(any(test, feature = "mocks"))]
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

    /// Consumes the result and returns its capabilities.
    pub(crate) fn into_capabilities(self) -> Capabilities<V, D> {
        self.capabilities
    }

    /// Consumes the result and separates authoritative capabilities from activities.
    pub(crate) fn into_parts(self) -> StepParts<V, D> {
        (self.capabilities, self.activities)
    }
}

impl<V: Variant, D: Digest> From<StepStatus<D>> for Step<V, D> {
    fn from(status: StepStatus<D>) -> Self {
        Self::new(status, Capabilities::new())
    }
}

/// A malformed attached-executor completion, an exhausted identifier, or a broken invariant.
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
    /// Authenticated chain facts contradict a local protocol invariant.
    #[error("authenticated transaction-chain facts violate a protocol invariant")]
    ChainInvariant,
    /// Authenticated view facts contradict a local protocol invariant.
    #[error("authenticated view facts violate a protocol invariant")]
    ViewInvariant,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_saturates_at_both_ends() {
        let now = Now::from_millis(10);
        assert_eq!(now.saturating_add(5).millis(), 15);
        assert_eq!(
            Now::from_millis(u64::MAX).saturating_add(1).millis(),
            u64::MAX
        );
        assert_eq!(now.saturating_since(Now::from_millis(4)), 6);
        assert_eq!(now.saturating_since(Now::from_millis(40)), 0);
    }
}
