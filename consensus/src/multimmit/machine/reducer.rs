//! Deterministic input reduction and capability emission.

use super::{
    Artifact, ArtifactEntry, ArtifactId, ArtifactState, BarrierAck, BarrierId,
    BlockValidationOutcome, BuildCompletion, BuildJob, BuildOutcome, ChainEffect, ChainError,
    Change, DaRecoveryCompletion, DaRecoveryJob, DaVoteRequest, Dependency, DomainEvent,
    DurableEffect, DurableJob, DurableState, EffectCompletion, EffectId, FrozenAcknowledgement,
    IdentifiedArtifact, JobId, Lifecycle, LqcAggregateCompletion, LqcAggregateJob, Machine,
    NullificationRecoveryCompletion, NullificationRecoveryJob, Observation, PendingPersistence,
    PendingSigningCompletion, PersistDirective, PersistJob, ProductionTimer, ProtocolComponent,
    ReplayError, Replayed, ResolutionCompletion, ResolutionJob, Role, SelfAdmission, SendRequest,
    SignRequest, Timer, ValidationCompletion, ValidationJob, Verdict, VerificationCompletion,
    VerificationItem, VerificationTicket, VerifyJob, VqcAggregateCompletion, VqcAggregateJob,
    WorkKey,
    contracts::{Lane, ServiceCycle, ServiceError, TransitionCost},
    emission::ViewProof,
    finality::{FinalityEffect, FinalityError, FinalityOutput, PreparedLqc},
    view::{ViewEffect, ViewError},
};
use crate::{
    Epochable, Viewable,
    multimmit::types::{Activity, Anchor, BlockRef, CertificateId, ChainId, Lqc, ProposalParent},
    types::{Attributable, Height, Participant, Round, View, ViewDelta},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::{mem::take, ops::Deref};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    sync::Arc,
};

/// A serialized input to the local state machine.
#[derive(Clone, Debug)]
pub(super) enum Input<V: Variant, D: Digest> {
    /// Start a fresh machine after making its process generation durable.
    Start,
    /// Finish silent recovery and durably enter a new process generation.
    RecoveryComplete,
    /// Observe one bounded cohort of decoded, untrusted artifacts with their identifiers.
    ///
    /// Identifiers hash the full encoding, so the batcher computes them once on its own task
    /// rather than re-hashing multi-kilobyte certificates on the voter loop.
    Observe(Vec<IdentifiedArtifact<V, D>>),
    /// Complete one exact machine-issued verification job.
    Verified(VerificationCompletion<D>),
    /// Complete one exact safety-journal barrier.
    Persisted(BarrierAck),
    /// Complete one stable durable outbox action.
    EffectCompleted(EffectCompletion<V, D>),
    /// Fire one logical view timer.
    TimerFired(Timer),
    /// Wake the local producer.
    ///
    /// Repeated wakes coalesce until the machine issues a build for the current parent.
    ProducerWake,
    /// Complete one exact application block build.
    BlockBuilt(BuildCompletion<D>),
    /// Complete deterministic validation of one authenticated block payload.
    BlockValidated(ValidationCompletion),
    /// Complete one exact machine-issued immutable-object resolution request.
    ResolutionCompleted(ResolutionCompletion<V, D>),
    /// Fire one producer deadline bound to an exact parent.
    ProductionTimerFired(ProductionTimer<D>),
    /// Complete one exact data-availability recovery request.
    DaRecovered(DaRecoveryCompletion<V, D>),
    /// Complete one exact nullification recovery request.
    NullificationRecovered(NullificationRecoveryCompletion<V>),
    /// Complete one exact V-QC aggregation request.
    VqcAggregated(Box<VqcAggregateCompletion<V, D>>),
    /// Complete one exact L-QC aggregation request.
    LqcAggregated(Box<LqcAggregateCompletion<V, D>>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum VerificationPassPhase {
    Start,
    Validate,
    Apply,
    Complete,
}

/// Owned verification input and exact item cursor retained across core cycles.
pub(crate) struct VerificationPass<D: Digest> {
    completion: VerificationCompletion<D>,
    phase: VerificationPassPhase,
    position: usize,
}

impl<D: Digest> VerificationPass<D> {
    pub(crate) const fn new(completion: VerificationCompletion<D>) -> Self {
        Self {
            completion,
            phase: VerificationPassPhase::Start,
            position: 0,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SigningBatchPassPhase {
    Start,
    Prepare,
    Complete,
}

/// Owned signing completion and private preparation cursor retained across core cycles.
pub(crate) struct SigningBatchPass<V: Variant, D: Digest> {
    id: EffectId,
    generation: u64,
    artifacts: std::vec::IntoIter<Artifact<V, D>>,
    total: usize,
    phase: SigningBatchPassPhase,
    requests: Option<Arc<[SignRequest<V, D>]>>,
    signer: Option<Participant>,
    prepared: Vec<Arc<Artifact<V, D>>>,
    ids: Vec<ArtifactId<D>>,
    unique: BTreeSet<ArtifactId<D>>,
    da_chains: BTreeSet<ChainId>,
    da_reservation_matches: bool,
    all_da_votes: bool,
}

impl<V: Variant, D: Digest> SigningBatchPass<V, D> {
    pub(crate) fn new(id: EffectId, generation: u64, artifacts: Vec<Artifact<V, D>>) -> Self {
        let total = artifacts.len();
        Self {
            id,
            generation,
            artifacts: artifacts.into_iter(),
            total,
            phase: SigningBatchPassPhase::Start,
            requests: None,
            signer: None,
            prepared: Vec::new(),
            ids: Vec::new(),
            unique: BTreeSet::new(),
            da_chains: BTreeSet::new(),
            da_reservation_matches: true,
            all_da_votes: true,
        }
    }
}

/// One bounded prefix of a resumable core input.
pub(super) struct InputPass<V: Variant, D: Digest> {
    pub(crate) processed: usize,
    pub(crate) complete: bool,
    pub(crate) step: Step<V, D>,
}

/// Immutable work emitted through one attached-runtime ownership port.
#[derive(Clone, Debug)]
pub(crate) enum Capability<V: Variant, D: Digest> {
    /// Authentication of adversarial protocol artifacts.
    Verification(VerificationCapability<V, D>),
    /// Journal barriers and actions released by their exact durable boundary.
    Durability(DurabilityCapability<V, D>),
    /// Application and data-availability work for producer chains.
    Producer(ProducerCapability<V, D>),
    /// Timer and certificate work for the protocol-owned leader chain.
    Leader(LeaderCapability<V, D>),
    /// Dependency operations against the volatile resolver cache.
    Resolver(ResolverCapability),
}

/// Artifact authentication work.
#[derive(Clone, Debug)]
pub(crate) enum VerificationCapability<V: Variant, D: Digest> {
    /// Cryptographically verify retained decoded artifacts.
    Verify(VerifyJob<V, D>),
}

/// Work ordered against the safety journal.
#[derive(Clone, Debug)]
pub(crate) enum DurabilityCapability<V: Variant, D: Digest> {
    /// Append exact domain events after installing pre-publication resolver custody.
    Persist(PersistDirective<V, D>),
    /// Install resolver custody and accounting released by an exact durable acknowledgement.
    Acknowledged {
        retention: Vec<Arc<Artifact<V, D>>>,
        forwarded_nullifications: usize,
        #[cfg(test)]
        acknowledgement: BarrierAck,
        #[cfg(test)]
        retirements: Vec<EffectId>,
    },
    /// Execute an action released from the durable outbox.
    Released(DurableJob<DurableEffect<V, D>>),
    /// Retire volatile publication attempts after every successor command has executed.
    Retire(Vec<EffectId>),
}

/// Application and data-availability work for producer chains.
#[derive(Clone, Debug)]
pub(crate) enum ProducerCapability<V: Variant, D: Digest> {
    /// Arm a production deadline bound to one exact parent.
    ArmTimer(ProductionTimer<D>),
    /// Build an application block against an immutable parent.
    Build(BuildJob<D>),
    /// Validate an authenticated block whose payload is locally available.
    Validate(ValidationJob<V, D>),
    /// Stop application validation made obsolete by a certified producer-chain frontier.
    CancelValidations {
        /// Producer chain whose earlier validations are obsolete.
        chain: ChainId,
        /// Greatest obsolete height on the producer chain.
        through: Height,
    },
    /// Recover a certificate from one exact canonical subset of verified DA shares.
    RecoverDa(DaRecoveryJob<V, D>),
}

/// Timer and certificate work for the protocol-owned leader chain.
#[derive(Clone, Debug)]
pub(crate) enum LeaderCapability<V: Variant, D: Digest> {
    /// Arm a logical view timer outside the runtime-independent core.
    ArmTimer(Timer),
    /// Recover a certificate from one exact canonical subset of nullification shares.
    RecoverNullification(NullificationRecoveryJob<V>),
    /// Aggregate one exact canonical V-QC transcript.
    AggregateVqc(VqcAggregateJob<V, D>),
    /// Assemble one exact L-QC from complete votes selected by the core.
    AggregateLqc(LqcAggregateJob<V, D>),
}

/// Dependency operations against the volatile resolver cache.
#[derive(Copy, Clone, Debug)]
pub(crate) enum ResolverCapability {
    /// Resolve one exact immutable object required by ordering.
    Resolve(ResolutionJob),
    /// Stop one exact resolver job whose owner no longer needs it.
    Cancel(ResolutionJob),
    /// Reject cryptographically invalid content returned by one queried resolver peer.
    Reject(ResolutionJob),
    /// Retire exact view evidence below the core's current retention frontier.
    Prune(View),
}

/// Owned capabilities in deterministic issuance order.
///
/// Up to two capabilities remain inline. Larger results spill into a vector.
#[derive(Clone, Debug, Default)]
pub(crate) enum Capabilities<V: Variant, D: Digest> {
    /// No capabilities were emitted.
    #[default]
    None,
    /// Exactly one capability was emitted.
    One(Capability<V, D>),
    /// Exactly two capabilities were emitted.
    Two([Capability<V, D>; 2]),
    /// Three or more capabilities were emitted.
    Many(Vec<Capability<V, D>>),
}

impl<V: Variant, D: Digest> Capabilities<V, D> {
    /// Returns the capabilities in deterministic issuance order.
    pub fn as_slice(&self) -> &[Capability<V, D>] {
        match self {
            Self::None => &[],
            Self::One(capability) => core::slice::from_ref(capability),
            Self::Two(capabilities) => capabilities,
            Self::Many(capabilities) => capabilities,
        }
    }

    /// Appends a capability in deterministic issuance order.
    pub fn push(&mut self, capability: Capability<V, D>) {
        match self {
            Self::None => *self = Self::One(capability),
            Self::One(_) => {
                let Self::One(first) = core::mem::replace(self, Self::None) else {
                    unreachable!("the capabilities variant was just matched")
                };
                *self = Self::Two([first, capability]);
            }
            Self::Two(_) => {
                let Self::Two([first, second]) = core::mem::replace(self, Self::None) else {
                    unreachable!("the capabilities variant was just matched")
                };
                *self = Self::Many(vec![first, second, capability]);
            }
            Self::Many(capabilities) => capabilities.push(capability),
        }
    }

    /// Appends capabilities in iterator order.
    pub fn extend(&mut self, capabilities: impl IntoIterator<Item = Capability<V, D>>) {
        for capability in capabilities {
            self.push(capability);
        }
    }

    /// Removes and returns the last capability, if any.
    #[cfg(test)]
    pub fn pop(&mut self) -> Option<Capability<V, D>> {
        match self {
            Self::None => None,
            Self::One(_) => {
                let Self::One(capability) = core::mem::replace(self, Self::None) else {
                    unreachable!("the capabilities variant was just matched")
                };
                Some(capability)
            }
            Self::Two(_) => {
                let Self::Two([first, second]) = core::mem::replace(self, Self::None) else {
                    unreachable!("the capabilities variant was just matched")
                };
                *self = Self::One(first);
                Some(second)
            }
            Self::Many(capabilities) => {
                let capability = capabilities.pop();
                self.normalize_many();
                capability
            }
        }
    }

    /// Removes and returns the capability at `index`, shifting later capabilities forward.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[cfg(test)]
    pub fn remove(&mut self, index: usize) -> Capability<V, D> {
        match self {
            Self::None => panic!("removal index (is {index}) should be < len (is 0)"),
            Self::One(_) => {
                assert_eq!(
                    index, 0,
                    "removal index (is {index}) should be < len (is 1)"
                );
                let Self::One(capability) = core::mem::replace(self, Self::None) else {
                    unreachable!("the capabilities variant was just matched")
                };
                capability
            }
            Self::Two(_) => {
                assert!(
                    index < 2,
                    "removal index (is {index}) should be < len (is 2)"
                );
                let Self::Two([first, second]) = core::mem::replace(self, Self::None) else {
                    unreachable!("the capabilities variant was just matched")
                };
                if index == 0 {
                    *self = Self::One(second);
                    first
                } else {
                    *self = Self::One(first);
                    second
                }
            }
            Self::Many(capabilities) => {
                let capability = capabilities.remove(index);
                self.normalize_many();
                capability
            }
        }
    }

    #[cfg(test)]
    fn normalize_many(&mut self) {
        let Self::Many(capabilities) = self else {
            return;
        };
        match capabilities.len() {
            0 => *self = Self::None,
            1 => {
                let capability = capabilities
                    .pop()
                    .expect("the capabilities length was just checked");
                *self = Self::One(capability);
            }
            2 => {
                let second = capabilities
                    .pop()
                    .expect("the capabilities length was just checked");
                let first = capabilities
                    .pop()
                    .expect("the capabilities length was just checked");
                *self = Self::Two([first, second]);
            }
            _ => {}
        }
    }
}

impl<V: Variant, D: Digest> Deref for Capabilities<V, D> {
    type Target = [Capability<V, D>];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<V: Variant, D: Digest> From<Capability<V, D>> for Capabilities<V, D> {
    fn from(capability: Capability<V, D>) -> Self {
        Self::One(capability)
    }
}

impl<V: Variant, D: Digest> From<Vec<Capability<V, D>>> for Capabilities<V, D> {
    fn from(mut capabilities: Vec<Capability<V, D>>) -> Self {
        match capabilities.len() {
            0 => Self::None,
            1 => Self::One(
                capabilities
                    .pop()
                    .expect("the capabilities length was just checked"),
            ),
            2 => {
                let second = capabilities
                    .pop()
                    .expect("the capabilities length was just checked");
                let first = capabilities
                    .pop()
                    .expect("the capabilities length was just checked");
                Self::Two([first, second])
            }
            _ => Self::Many(capabilities),
        }
    }
}

/// Owning iterator over inline or spilled capabilities.
pub(crate) enum CapabilitiesIntoIter<V: Variant, D: Digest> {
    /// Empty capability sequence.
    None,
    /// One inline capability.
    One(core::option::IntoIter<Capability<V, D>>),
    /// Two inline capabilities.
    Two(core::array::IntoIter<Capability<V, D>, 2>),
    /// Heap-backed capability sequence.
    Many(std::vec::IntoIter<Capability<V, D>>),
}

impl<V: Variant, D: Digest> Iterator for CapabilitiesIntoIter<V, D> {
    type Item = Capability<V, D>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::None => None,
            Self::One(capabilities) => capabilities.next(),
            Self::Two(capabilities) => capabilities.next(),
            Self::Many(capabilities) => capabilities.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::None => (0, Some(0)),
            Self::One(capabilities) => capabilities.size_hint(),
            Self::Two(capabilities) => capabilities.size_hint(),
            Self::Many(capabilities) => capabilities.size_hint(),
        }
    }
}

impl<V: Variant, D: Digest> ExactSizeIterator for CapabilitiesIntoIter<V, D> {}

impl<V: Variant, D: Digest> DoubleEndedIterator for CapabilitiesIntoIter<V, D> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::None => None,
            Self::One(capabilities) => capabilities.next_back(),
            Self::Two(capabilities) => capabilities.next_back(),
            Self::Many(capabilities) => capabilities.next_back(),
        }
    }
}

impl<V: Variant, D: Digest> IntoIterator for Capabilities<V, D> {
    type Item = Capability<V, D>;
    type IntoIter = CapabilitiesIntoIter<V, D>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::None => CapabilitiesIntoIter::None,
            Self::One(capability) => CapabilitiesIntoIter::One(Some(capability).into_iter()),
            Self::Two(capabilities) => CapabilitiesIntoIter::Two(capabilities.into_iter()),
            Self::Many(capabilities) => CapabilitiesIntoIter::Many(capabilities.into_iter()),
        }
    }
}

impl<'a, V: Variant, D: Digest> IntoIterator for &'a Capabilities<V, D> {
    type Item = &'a Capability<V, D>;
    type IntoIter = core::slice::Iter<'a, Capability<V, D>>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<V: Variant, D: Digest> FromIterator<Capability<V, D>> for Capabilities<V, D> {
    fn from_iter<T: IntoIterator<Item = Capability<V, D>>>(iter: T) -> Self {
        let mut capabilities = Self::None;
        capabilities.extend(iter);
        capabilities
    }
}

/// Why a decoded artifact did not enter cryptographic verification.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The artifact belongs to another epoch or immutable configuration.
    Context,
    /// An attributed participant is outside the committee.
    Participant,
    /// The encoded artifact exceeds the configured byte ceiling.
    ArtifactTooLarge,
    /// Uncertified traffic is too far ahead of the current view.
    FutureView,
    /// The bounded future-view index is full.
    FutureArtifactsFull,
    /// The exact-artifact cache is full.
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
pub struct ObservationResult<D: Digest> {
    id: Option<ArtifactId<D>>,
    observation: Observation,
    status: ObservationStatus,
}

impl<D: Digest> ObservationResult<D> {
    /// Returns the stable ingress identity assigned before verification.
    pub(crate) const fn observation(self) -> Observation {
        self.observation
    }

    /// Returns the exact artifact identifier when canonical hashing was required.
    ///
    /// Rejections made by cheap context, participant, view-distance, or byte-bound checks do not hash
    /// the artifact and therefore return `None`.
    #[cfg(test)]
    pub const fn id(self) -> Option<ArtifactId<D>> {
        self.id
    }

    /// Returns the pre-verification disposition.
    pub const fn status(self) -> ObservationStatus {
        self.status
    }
}

/// Results from classifying one decoded observation cohort.
///
/// Singleton cohorts remain inline, while larger cohorts retain their exact heap-backed batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationResults<D: Digest> {
    /// One classified artifact.
    One(ObservationResult<D>),
    /// Zero or multiple classified artifacts in observation order.
    Many(Vec<ObservationResult<D>>),
}

impl<D: Digest> ObservationResults<D> {
    /// Returns the classified artifacts in observation order.
    pub fn as_slice(&self) -> &[ObservationResult<D>] {
        match self {
            Self::One(result) => core::slice::from_ref(result),
            Self::Many(results) => results,
        }
    }
}

impl<D: Digest> Deref for ObservationResults<D> {
    type Target = [ObservationResult<D>];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

/// Pre-verification disposition of one observed artifact.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ObservationStatus {
    /// A verification request was emitted.
    Scheduled,
    /// The exact artifact or an equivalent certificate fact was already retained.
    Duplicate,
    /// The artifact failed a bounded pre-verification check.
    Rejected(Rejection),
}

/// Classification of the processed input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepStatus<D: Digest> {
    /// A local state change is waiting for its exact durability barrier.
    DurabilityReserved,
    /// A matching persistence barrier was acknowledged.
    Persisted,
    /// A completion was parked until the outstanding persistence barrier is acknowledged.
    CompletionDeferred,
    /// One decoded observation cohort was classified.
    Observed(ObservationResults<D>),
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
    /// A stable outbox action completed or a volatile publication attempt was observed.
    EffectCompleted {
        /// A signed artifact self-admitted through the canonical artifact store.
        admission: Option<SelfAdmission<D>>,
    },
    /// An atomic signing batch completed and all artifacts self-admitted.
    EffectBatchCompleted {
        /// Constructed artifacts in signing-request order.
        admissions: Vec<SelfAdmission<D>>,
    },
    /// A current-generation timer was accepted by the reducer skeleton.
    TimerFired,
    /// A producer wake was accepted.
    ProducerWake,
    /// A matched application build completion was accepted.
    BlockBuilt,
    /// A matched deterministic block-validation completion was accepted.
    BlockValidated,
    /// A matched immutable-object resolution attempt completed without decoded protocol input.
    ResolutionCompleted,
    /// A current producer deadline was accepted.
    ProductionTimerFired,
    /// A matched data-availability recovery completion was accepted.
    DaRecovered {
        /// The constructed certificate admitted through the canonical artifact store.
        admission: SelfAdmission<D>,
    },
    /// A matched nullification recovery completion was accepted.
    NullificationRecovered {
        /// The constructed certificate admitted through the canonical artifact store.
        admission: SelfAdmission<D>,
    },
    /// A matched V-QC aggregation completion was accepted.
    VqcAggregated {
        /// The constructed certificate admitted through the canonical artifact store.
        admission: SelfAdmission<D>,
    },
    /// A matched L-QC aggregation completion was accepted.
    LqcAggregated {
        /// The constructed certificate admitted through the canonical artifact store.
        admission: SelfAdmission<D>,
    },
    /// A completion belonged to a missing or prior-generation job.
    StaleCompletion,
}

/// Authoritative capabilities and non-authoritative activities emitted by one core transition.
pub(crate) type StepParts<V, D> = (Capabilities<V, D>, Vec<Activity<V, D>>);
pub(crate) type CoreParts<V, D> = (StepStatus<D>, Capabilities<V, D>, Vec<Activity<V, D>>);

/// Bounded capabilities emitted while polling core-owned semantic work.
#[derive(Clone, Debug)]
pub(super) struct PollResult<V: Variant, D: Digest> {
    capabilities: Capabilities<V, D>,
    activities: Vec<Activity<V, D>>,
    work_remaining: bool,
}

impl<V: Variant, D: Digest> PollResult<V, D> {
    const fn new(
        capabilities: Capabilities<V, D>,
        activities: Vec<Activity<V, D>>,
        work_remaining: bool,
    ) -> Self {
        Self {
            capabilities,
            activities,
            work_remaining,
        }
    }

    /// Returns capabilities in deterministic issuance order.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn capabilities(&self) -> &[Capability<V, D>] {
        &self.capabilities
    }

    /// Returns non-authoritative activities authorized by this poll.
    #[cfg(test)]
    pub fn activities(&self) -> &[Activity<V, D>] {
        &self.activities
    }

    /// Returns whether another machine-owned quantum is ready.
    pub const fn work_remaining(&self) -> bool {
        self.work_remaining
    }

    /// Consumes the result and returns its capabilities.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn into_capabilities(self) -> Capabilities<V, D> {
        self.capabilities
    }

    /// Consumes the result and separates authoritative capabilities from telemetry.
    pub fn into_parts(self) -> StepParts<V, D> {
        (self.capabilities, self.activities)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum WorkStatus {
    Complete,
    Requeue,
    Blocked,
}

type WorkResult<V, D> = Result<(WorkStatus, Capabilities<V, D>), StepError>;

/// A durable effect paired with its precomputed visited artifact identifiers.
type ReferenceChanges<D> = BTreeMap<ArtifactId<D>, (usize, usize)>;

/// Result of one deterministic machine step.
#[derive(Clone, Debug)]
pub(super) struct Step<V: Variant, D: Digest> {
    status: StepStatus<D>,
    capabilities: Capabilities<V, D>,
    activities: Vec<Activity<V, D>>,
}

impl<V: Variant, D: Digest> Step<V, D> {
    fn new(status: StepStatus<D>, capabilities: impl Into<Capabilities<V, D>>) -> Self {
        Self {
            status,
            capabilities: capabilities.into(),
            activities: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_tests(
        status: StepStatus<D>,
        capabilities: impl Into<Capabilities<V, D>>,
        activities: Vec<Activity<V, D>>,
    ) -> Self {
        Self {
            status,
            capabilities: capabilities.into(),
            activities,
        }
    }

    /// Returns the input classification.
    pub const fn status(&self) -> &StepStatus<D> {
        &self.status
    }

    /// Returns immutable capabilities in deterministic issuance order.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn capabilities(&self) -> &[Capability<V, D>] {
        &self.capabilities
    }

    /// Returns non-authoritative activities authorized by this step.
    #[cfg(test)]
    pub fn activities(&self) -> &[Activity<V, D>] {
        &self.activities
    }

    /// Consumes the result and returns its capabilities.
    pub fn into_capabilities(self) -> Capabilities<V, D> {
        self.capabilities
    }

    /// Consumes the result and separates authoritative capabilities from telemetry.
    #[cfg(test)]
    pub fn into_parts(self) -> StepParts<V, D> {
        (self.capabilities, self.activities)
    }

    pub(crate) fn into_core_parts(self) -> CoreParts<V, D> {
        (self.status, self.capabilities, self.activities)
    }
}

/// A malformed attached-executor completion or exhausted machine identifier.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StepError {
    /// The completion did not exactly match the retained job and ticket order.
    #[error("completion does not match the issued job")]
    CompletionMismatch,
    /// A deterministic sequence identifier overflowed.
    #[error("machine identifier exhausted")]
    IdentifierExhausted,
    /// An input was not valid in the machine's startup or recovery lifecycle.
    #[error("input is not valid in the current machine lifecycle")]
    Lifecycle,
    /// A durable event violated a state transition invariant.
    #[error("invalid durable state transition: {0}")]
    DurableTransition(&'static str),
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
    /// Exact first-forwarding history reached its configured ceiling.
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
            ViewError::ProposalConflict
            | ViewError::VoteConflict
            | ViewError::VoteNoVoteConflict
            | ViewError::Proposal
            | ViewError::Certificate
            | ViewError::MissingParent
            | ViewError::Chain => Self::ViewInvariant,
        }
    }
}

impl From<FinalityError> for StepError {
    fn from(error: FinalityError) -> Self {
        match error {
            FinalityError::IdentifierExhausted => Self::IdentifierExhausted,
            FinalityError::CompletionMismatch => Self::CompletionMismatch,
            FinalityError::LeaderCollision | FinalityError::Algebra => Self::FinalityInvariant,
        }
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Applies one serialized input and returns deterministic immutable capabilities.
    pub(super) fn step(
        &mut self,
        input: Input<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let report_admissions = self.lifecycle == Lifecycle::Live;

        // Recovery and aggregation completions stage a durable change, so they always park and
        // drain through the scheduler: one FIFO decides staging order for every durable
        // transition, whether or not a barrier sync happens to be in flight.
        if matches!(
            input,
            Input::DaRecovered(_)
                | Input::NullificationRecovered(_)
                | Input::VqcAggregated(_)
                | Input::LqcAggregated(_)
        ) {
            self.ensure_live()?;
            self.pending_crypto.push_back(input);
            self.scheduler.enqueue(WorkKey::CompleteCrypto);
            return Ok(Step::new(StepStatus::CompletionDeferred, Vec::new()));
        }

        let mut step = match input {
            Input::Start => self.start(false),
            Input::RecoveryComplete => self.start(true),
            Input::Persisted(completion) => self.complete_persistence(completion),
            Input::Observe(artifacts) => {
                self.ensure_live()?;
                self.observe(artifacts)
            }
            Input::Verified(completion) => {
                self.ensure_live()?;
                self.complete_verification(completion)
            }
            Input::EffectCompleted(completion) => {
                self.ensure_live()?;
                self.complete_effect(completion)
            }
            Input::TimerFired(timer) => {
                self.ensure_live()?;
                self.fire_timer(timer)
            }
            Input::ProducerWake => {
                self.ensure_live()?;
                self.wake_producer()
            }
            Input::BlockBuilt(completion) => {
                self.ensure_live()?;
                self.complete_block_build(completion)
            }
            Input::BlockValidated(completion) => {
                self.ensure_live()?;
                self.complete_block_validation(completion)
            }
            Input::ResolutionCompleted(completion) => {
                self.ensure_live()?;
                self.complete_resolution(completion)
            }
            Input::ProductionTimerFired(timer) => {
                self.ensure_live()?;
                self.fire_production_timer(timer)
            }
            Input::DaRecovered(_)
            | Input::NullificationRecovered(_)
            | Input::VqcAggregated(_)
            | Input::LqcAggregated(_) => {
                unreachable!("crypto completions park before reduction")
            }
        }?;

        // Recovery and replay promotions are never externalized, but they must still be drained
        // so they cannot leak into the first reporting step.
        if report_admissions {
            let accepted = self.drain_protocol_acceptances();
            step.activities.extend(accepted);
        } else {
            self.newly_ready.clear();
        }
        step.capabilities
            .extend(self.take_resolution_capabilities());

        Ok(step)
    }

    /// Observes an owned prefix without materializing a temporary input vector.
    pub(crate) fn step_observations(
        &mut self,
        artifacts: impl ExactSizeIterator<Item = IdentifiedArtifact<V, H::Digest>>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let report_admissions = self.lifecycle == Lifecycle::Live;
        self.ensure_live()?;
        let mut step = self.observe_artifacts(artifacts, true)?;
        if report_admissions {
            step.activities.extend(self.drain_protocol_acceptances());
        } else {
            self.newly_ready.clear();
        }
        Ok(step)
    }

    /// Applies at most `budget` real verification items and retains the exact suffix cursor.
    pub(crate) fn advance_verification_pass(
        &mut self,
        pass: &mut VerificationPass<H::Digest>,
        budget: usize,
    ) -> Result<InputPass<V, H::Digest>, StepError> {
        self.ensure_live()?;
        debug_assert!(budget > 0);

        let mut processed = 0;
        let mut applied = 0;
        let mut valid = 0;
        let mut invalid = 0;
        while processed < budget && pass.phase != VerificationPassPhase::Complete {
            match pass.phase {
                VerificationPassPhase::Start => {
                    processed += 1;
                    if pass.completion.generation() != self.durable.generation
                        || !self.jobs.contains_key(&pass.completion.job())
                    {
                        pass.phase = VerificationPassPhase::Complete;
                        return Ok(InputPass {
                            processed,
                            complete: true,
                            step: Step::new(StepStatus::StaleCompletion, Vec::new()),
                        });
                    }
                    let tickets = &self.jobs[&pass.completion.job()];
                    if tickets.len() != pass.completion.verdicts().len() {
                        return Err(StepError::CompletionMismatch);
                    }
                    if pass.completion.verdicts().is_empty() {
                        self.jobs
                            .remove(&pass.completion.job())
                            .expect("the empty verification job remains retained");
                        pass.phase = VerificationPassPhase::Complete;
                    } else {
                        pass.phase = VerificationPassPhase::Validate;
                    }
                }
                VerificationPassPhase::Validate => {
                    let expected = self.jobs[&pass.completion.job()][pass.position];
                    let actual = pass.completion.verdicts()[pass.position].ticket();
                    if expected != actual {
                        return Err(StepError::CompletionMismatch);
                    }
                    pass.position += 1;
                    processed += 1;
                    if pass.position == pass.completion.verdicts().len() {
                        self.jobs
                            .remove(&pass.completion.job())
                            .expect("the validated verification job remains retained");
                        pass.position = 0;
                        pass.phase = if pass.completion.verdicts().is_empty() {
                            VerificationPassPhase::Complete
                        } else {
                            VerificationPassPhase::Apply
                        };
                    }
                }
                VerificationPassPhase::Apply => {
                    let verdict = pass.completion.verdicts()[pass.position];
                    if let Some(verdict_valid) = self.apply_verification_verdict(verdict)? {
                        valid += usize::from(verdict_valid);
                        invalid += usize::from(!verdict_valid);
                    }
                    pass.position += 1;
                    processed += 1;
                    applied += 1;
                    if pass.position == pass.completion.verdicts().len() {
                        pass.phase = VerificationPassPhase::Complete;
                    }
                }
                VerificationPassPhase::Complete => unreachable!("the loop excludes completion"),
            }
        }

        let complete = pass.phase == VerificationPassPhase::Complete;
        let mut step = if applied > 0 || complete {
            self.finish_verification_prefix(valid, invalid)?
        } else {
            Step::new(
                StepStatus::Verified {
                    valid: 0,
                    invalid: 0,
                },
                Vec::new(),
            )
        };
        step.activities.extend(self.drain_protocol_acceptances());
        step.capabilities
            .extend(self.take_resolution_capabilities());
        Ok(InputPass {
            processed,
            complete,
            step,
        })
    }

    /// Privately prepares at most `budget` signed artifacts before one atomic admission.
    pub(crate) fn advance_signing_batch_pass(
        &mut self,
        pass: &mut SigningBatchPass<V, H::Digest>,
        budget: usize,
    ) -> Result<InputPass<V, H::Digest>, StepError> {
        self.ensure_live()?;
        debug_assert!(budget > 0);

        let mut processed = 0;
        while processed < budget && pass.phase != SigningBatchPassPhase::Complete {
            match pass.phase {
                SigningBatchPassPhase::Start => {
                    processed += 1;
                    if pass.generation != self.durable.generation
                        || self.pending_signing.contains_key(&pass.id)
                        || !self.contains_durable_effect(pass.id)
                    {
                        pass.phase = SigningBatchPassPhase::Complete;
                        return Ok(InputPass {
                            processed,
                            complete: true,
                            step: Step::new(StepStatus::StaleCompletion, Vec::new()),
                        });
                    }
                    let effect = self
                        .durable_effect(pass.id)
                        .expect("the signing reservation was checked above");
                    let DurableEffect::SignBatch(requests) = effect else {
                        return Err(StepError::EffectMismatch);
                    };
                    let Role::Validator(signer) = self.profile.role() else {
                        return Err(StepError::UnauthorizedEffect);
                    };
                    if requests.is_empty() {
                        return Err(StepError::UnauthorizedEffect);
                    }
                    if requests.len() != pass.total {
                        return Err(StepError::EffectMismatch);
                    }
                    pass.prepared.reserve_exact(pass.total);
                    pass.ids.reserve_exact(pass.total);
                    pass.requests = Some(requests);
                    pass.signer = Some(signer);
                    pass.phase = SigningBatchPassPhase::Prepare;
                }
                SigningBatchPassPhase::Prepare => {
                    let artifact = pass
                        .artifacts
                        .next()
                        .expect("the signing cursor remains below its exact batch length");
                    let index = pass.ids.len();
                    let request = &pass
                        .requests
                        .as_ref()
                        .expect("the signing pass retained its exact requests")[index];
                    if !request.matches_context(self.profile.protocol().epoch()) {
                        return Err(StepError::UnauthorizedEffect);
                    }
                    if let SignRequest::DaVote(da_request) = request {
                        let chain = da_request.header().chain();
                        let in_committee = (chain.get() as usize)
                            < self.profile.protocol().codec_config().chains();
                        pass.all_da_votes &= in_committee && pass.da_chains.insert(chain);
                        pass.da_reservation_matches &=
                            self.chain
                                .issued_signing_request(pass.id, pass.generation, index)
                                == Some(request);
                    } else {
                        pass.all_da_votes = false;
                    }
                    if !request.matches(
                        pass.signer
                            .expect("the signing pass retained its exact signer"),
                        &artifact,
                    ) {
                        return Err(StepError::EffectMismatch);
                    }
                    let id = self.validate_self_admission(&artifact)?;
                    if !pass.unique.insert(id) {
                        return Err(StepError::LocalArtifactReservation);
                    }
                    pass.prepared.push(Arc::new(artifact));
                    pass.ids.push(id);
                    processed += 1;
                    if pass.ids.len() == pass.total {
                        let current = self.durable_effect(pass.id);
                        let expected = pass
                            .requests
                            .as_ref()
                            .expect("the signing pass retained its exact requests");
                        if pass.generation != self.durable.generation || current.is_none() {
                            pass.phase = SigningBatchPassPhase::Complete;
                            return Ok(InputPass {
                                processed,
                                complete: true,
                                step: Step::new(StepStatus::StaleCompletion, Vec::new()),
                            });
                        }
                        let Some(effect) = current else {
                            return Err(StepError::EffectMismatch);
                        };
                        let DurableEffect::SignBatch(requests) = &effect else {
                            return Err(StepError::EffectMismatch);
                        };
                        if !Arc::ptr_eq(requests, expected) {
                            return Err(StepError::EffectMismatch);
                        }
                        let timeout_pair = matches!(expected.as_ref(), [
                            SignRequest::NoVote { round: left },
                            SignRequest::Nullify { round: right },
                        ] if left == right);
                        let da_votes = pass.all_da_votes && pass.da_chains.len() == pass.total;
                        if !timeout_pair && !da_votes {
                            return Err(StepError::UnauthorizedEffect);
                        }
                        if da_votes
                            && (!pass.da_reservation_matches
                                || self
                                    .chain
                                    .issued_signing_batch_len(pass.id, self.durable.generation)
                                    != Some(pass.total))
                        {
                            return Err(StepError::EffectMismatch);
                        }
                        if self.artifacts.len() + pass.ids.len()
                            > self.profile.resources().max_cached_artifacts()
                        {
                            return Err(StepError::LocalArtifactReservation);
                        }
                        let artifacts = Arc::from(take(&mut pass.prepared));
                        let ids = take(&mut pass.ids);
                        self.pending_signing
                            .insert(pass.id, PendingSigningCompletion::Batch { artifacts, ids });
                        self.scheduler.enqueue(WorkKey::CompleteEffect(pass.id));
                        pass.phase = SigningBatchPassPhase::Complete;
                    }
                }
                SigningBatchPassPhase::Complete => unreachable!("the loop excludes completion"),
            }
        }

        Ok(InputPass {
            processed,
            complete: pass.phase == SigningBatchPassPhase::Complete,
            step: Step::new(StepStatus::EffectCompleted { admission: None }, Vec::new()),
        })
    }

    /// Performs at most `budget` machine-owned semantic work quanta.
    ///
    /// Staged changes apply immediately and accumulate into group-commit batches; the poll
    /// hands ready batches to the driver on exit. Work blocked on resolution is not reported
    /// as ready; the matching completion wakes it.
    pub(super) fn poll(
        &mut self,
        budget: NonZeroUsize,
    ) -> Result<PollResult<V, H::Digest>, StepError> {
        self.ensure_live()?;
        let mut capabilities = Capabilities::None;

        for _ in 0..budget.get() {
            let Some(key) = self.scheduler.pop() else {
                break;
            };
            let (status, emitted) = match key {
                WorkKey::CompleteEffect(id) => self.drive_signing_completion(id)?,
                WorkKey::CompleteCrypto => self.drive_crypto_completion()?,
                WorkKey::Drive(component) => {
                    let mut cycle = ServiceCycle::new();
                    self.drive_component_quantum(component, &mut cycle)?
                }
            };
            capabilities.extend(emitted);

            if status == WorkStatus::Requeue {
                self.scheduler.enqueue(key);
            }
            // One component key owns one finite service cycle. Returning here ensures an actor
            // observes ready work and yields before beginning another component quantum.
            if matches!(key, WorkKey::Drive(_)) {
                break;
            }
        }

        // Hand one ready group-commit batch to the driver.
        capabilities.extend(self.emit_staged());
        capabilities.extend(self.take_resolution_capabilities());
        let activities = self.drain_protocol_acceptances();
        let has_work = self.scheduler.has_work() || self.next_staged_index().is_some();
        Ok(PollResult::new(capabilities, activities, has_work))
    }

    /// Reports every artifact promoted to ready since the last drain, in canonical order.
    ///
    /// A promotion that the same drain window also discarded is not an admission: the artifact
    /// is no longer retained, so it is filtered out exactly as a before-and-after comparison of
    /// the retained map would have.
    fn drain_protocol_acceptances(&mut self) -> Vec<Activity<V, H::Digest>> {
        if self.newly_ready.is_empty() {
            return Vec::new();
        }
        let mut accepted = take(&mut self.newly_ready);
        accepted.retain(|(_, id, _)| {
            self.artifacts
                .get(id)
                .is_some_and(|entry| matches!(entry.state, ArtifactState::Ready))
        });
        accepted.sort_unstable_by_key(|(observation, id, _)| (*observation, *id));
        accepted
            .into_iter()
            .map(|(_, artifact_id, artifact)| Activity::ProtocolAccepted {
                artifact_id,
                artifact,
            })
            .collect()
    }

    /// Replays one contiguous durable event without emitting live capabilities.
    pub fn replay(&mut self, event: DomainEvent<V, H::Digest>) -> Result<Replayed, ReplayError> {
        if self.lifecycle != Lifecycle::Recovering || !self.staged.is_empty() {
            return Err(ReplayError::Lifecycle);
        }
        self.apply_event(&event)?;
        // Replay never externalizes admissions, and the boundary step that follows must not
        // inherit them.
        self.newly_ready.clear();
        Ok(Replayed::new(event.cursor()))
    }

    fn ensure_live(&self) -> Result<(), StepError> {
        if self.lifecycle != Lifecycle::Live {
            return Err(StepError::Lifecycle);
        }
        Ok(())
    }

    fn claim_finality(
        &mut self,
        artifact_id: ArtifactId<H::Digest>,
        observation: Observation,
        artifact: Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), StepError> {
        self.finality
            .claim_finality::<H>(artifact_id, observation, artifact, &self.profile)?;
        Ok(())
    }

    fn validate_finality(
        &mut self,
        artifact_id: ArtifactId<H::Digest>,
        observation: Observation,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), StepError> {
        let outputs = self.finality.validate_finality_claim::<H>(
            artifact_id,
            observation,
            artifact,
            &self.profile,
        )?;
        for output in outputs {
            let FinalityOutput::Finality(artifact_id, observation, certificate) = output;
            self.apply_finality(artifact_id, observation, certificate)?;
        }
        Ok(())
    }

    fn reject_finality(
        &mut self,
        artifact_id: ArtifactId<H::Digest>,
        observation: Observation,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), StepError> {
        let outputs = self.finality.reject_finality_claim::<H>(
            artifact_id,
            observation,
            artifact,
            &self.profile,
        )?;
        for output in outputs {
            let FinalityOutput::Finality(artifact_id, observation, certificate) = output;
            self.apply_finality(artifact_id, observation, certificate)?;
        }
        Ok(())
    }

    fn retire_finality_through(&mut self, floor: View) -> Result<(), StepError> {
        let outputs = self.finality.retire_through::<H>(&self.profile, floor)?;
        for output in outputs {
            let FinalityOutput::Finality(artifact_id, observation, certificate) = output;
            self.apply_finality(artifact_id, observation, certificate)?;
        }
        Ok(())
    }

    pub(super) fn apply_finality(
        &mut self,
        artifact_id: ArtifactId<H::Digest>,
        observation: Observation,
        certificate: Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), StepError> {
        let Artifact::Lqc(lqc) = certificate.as_ref() else {
            return Err(StepError::ViewInvariant);
        };
        if lqc.view() <= self.signing_floor_view() {
            return Ok(());
        }
        let selected = self
            .views
            .observe_finality(artifact_id, &certificate)
            .map_err(|_| StepError::ViewInvariant)?;
        if !selected || lqc.view() < self.durable.view {
            return Ok(());
        }
        self.observe_derived_vqc(lqc, observation)
    }

    fn sync_signing_completions(&mut self) {
        for id in self.pending_signing.keys().copied() {
            self.scheduler.enqueue(WorkKey::CompleteEffect(id));
        }
        if !self.pending_crypto.is_empty() || self.prepared_lqc.is_some() {
            self.scheduler.enqueue(WorkKey::CompleteCrypto);
        }
    }

    /// Returns the greatest view whose state the machine has stopped retaining.
    ///
    /// The machine can never act in a view it has already left, so retirement is measured from the
    /// current view rather than from finality. Memory therefore stays bounded while finality
    /// stalls.
    pub(crate) const fn retention_floor(&self) -> View {
        self.durable
            .view
            .saturating_sub(self.profile.view_retention())
            .saturating_sub(ViewDelta::new(1))
    }

    fn proposal_anchor(&self) -> (View, Option<CertificateId<H::Digest>>) {
        let Some(Artifact::Vqc(anchor)) = self.durable.proposal_anchor.as_deref() else {
            return (View::zero(), None);
        };
        (anchor.view(), Some(anchor.id::<H>()))
    }

    fn chain_retention_height(&self, chain: usize) -> Height {
        self.durable.certified_tips[chain].height()
    }

    /// Applies durable transition and consensus signing floors to volatile state.
    pub(crate) fn retire_view_history(&mut self) -> Result<(), ReplayError> {
        let transition_floor = self.durable.retired_view;
        let finality_floor = self.signing_floor_view();
        let (anchor_view, anchor) = self.proposal_anchor();
        self.views.retire_transitions_through(transition_floor);
        self.views.retire_forwarded_through(transition_floor);
        self.views
            .retire_finality_proofs_through(self.signing_floor_view());
        self.retire_finality_through(self.retention_floor())
            .map_err(|_| ReplayError::Transition)?;
        self.retract_unneeded_resolutions();
        self.available.retain(|dependency| {
            !matches!(dependency, Dependency::Leader { round, .. }
                if !round.view().is_zero() && round.view() <= transition_floor)
        });
        let parent_floor = finality_floor.max(anchor_view);
        for id in self.views.retire_parents_through(parent_floor, anchor) {
            let dependency = Dependency::Vqc(id);
            self.available.remove(&dependency);
            self.providers.remove(&dependency);
        }
        Ok(())
    }

    fn wake_producer(&mut self) -> Result<Step<V, H::Digest>, StepError> {
        self.chain.wake_producer();
        self.wake_components();
        Ok(Step::new(StepStatus::ProducerWake, Vec::new()))
    }

    fn complete_block_build(
        &mut self,
        completion: BuildCompletion<H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let outcome = self.chain.complete_build(&self.profile, completion)?;
        let status = match outcome {
            BuildOutcome::Stale => return Ok(Step::new(StepStatus::StaleCompletion, Vec::new())),
            BuildOutcome::Superseded => StepStatus::StaleCompletion,
            // The chain retains the pending build sign request, so the drive quantum derives
            // and stages it when the barrier pipeline has room.
            BuildOutcome::Empty | BuildOutcome::Sign(_) => StepStatus::BlockBuilt,
        };
        self.wake_components();
        Ok(Step::new(status, Vec::new()))
    }

    fn complete_block_validation(
        &mut self,
        completion: ValidationCompletion,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let outcome = self
            .chain
            .complete_validation::<H>(completion, self.durable.generation)?;
        match outcome {
            BlockValidationOutcome::Stale => {
                return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
            }
            BlockValidationOutcome::Retained => {}
            BlockValidationOutcome::Invalid(artifact) => {
                self.remove_terminal_artifact(artifact)?;
            }
        }
        self.wake_components();
        Ok(Step::new(StepStatus::BlockValidated, Vec::new()))
    }

    fn complete_resolution(
        &mut self,
        completion: ResolutionCompletion<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if !self.resolution.matches(&completion) {
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        }

        let view = completion.view();
        let proof_matches = match completion.proof() {
            ViewProof::Nullification(proof) => proof.view() == view,
            ViewProof::Vqc(proof) => proof.view() == view,
            ViewProof::Lqc(proof) => proof.view() >= view,
        };
        if !proof_matches {
            return Err(StepError::CompletionMismatch);
        }

        match completion.into_proof() {
            ViewProof::Nullification(proof) => {
                self.observe_resolution(view, Artifact::Nullification(*proof))
            }
            ViewProof::Vqc(proof) => self.observe_resolution(view, Artifact::Vqc(*proof)),
            ViewProof::Lqc(proof) => self.observe_resolution(view, Artifact::Lqc(*proof)),
        }
    }

    fn observe_resolution(
        &mut self,
        view: View,
        artifact: Artifact<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let id = artifact.id::<H>();
        let step = self.observe_artifacts([(id, artifact)].into_iter(), false)?;
        let status = match step.status() {
            StepStatus::Observed(results) => match results.as_slice() {
                [result] => result.status(),
                _ => return Err(StepError::CompletionMismatch),
            },
            _ => {
                self.cancel_resolution(view);
                return Ok(step);
            }
        };
        match status {
            ObservationStatus::Scheduled => {
                self.resolution.begin_verification(view, id);
                return Ok(step);
            }
            ObservationStatus::Duplicate => {
                let entry = self
                    .artifacts
                    .get(&id)
                    .ok_or(StepError::CompletionMismatch)?;
                if !matches!(entry.state, ArtifactState::Ready) {
                    self.resolution.begin_verification(view, id);
                    return Ok(step);
                }
            }
            ObservationStatus::Rejected(_) => {}
        }

        self.cancel_resolution(view);
        self.wake_components();
        Ok(Step::new(
            StepStatus::ResolutionCompleted,
            step.into_capabilities(),
        ))
    }

    fn fire_production_timer(
        &mut self,
        timer: ProductionTimer<H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if !self.chain.fire_timer(timer) {
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        }
        self.wake_components();
        Ok(Step::new(StepStatus::ProductionTimerFired, Vec::new()))
    }

    fn drive_finality_component(
        &mut self,
        _cycle: &mut ServiceCycle,
    ) -> Result<(bool, Capabilities<V, H::Digest>), StepError> {
        let mut capabilities = Capabilities::None;
        if let Some(view) = self.floor_resolution_view() {
            self.floor_probe_view = self.durable.view;
            if let Some(job) = self.request_resolution(view)? {
                capabilities.push(Capability::Resolver(ResolverCapability::Resolve(job)));
            }
        }
        if let Some(change) = self.next_finality_floor_change() {
            let Change::FinalityFloorAdvanced { proof, .. } = &change else {
                unreachable!("the finality-floor selector returns a floor change")
            };
            let Artifact::Lqc(certificate) = proof.as_ref() else {
                unreachable!("finality floors carry L-QCs")
            };
            let floor_view = certificate.view();
            // A late floor never carries a forwarding obligation: its view already advanced
            // through the ordinary exit, and a retired view can never re-enter the forwarding
            // frontier, so gating on it would freeze the floor for the rest of the epoch.
            let late = floor_view < self.durable.view;
            if !late && !self.durable.vqc_forwarded(floor_view) {
                // This turn durably forwards the exit proof and then advances the dependent
                // floor. Reserve worst-case room for both one-event batches before applying
                // either transition; a persistence acknowledgement wakes this component.
                if self.staged.len().saturating_add(2) > Self::MAX_STAGED_BARRIERS {
                    return Ok((false, capabilities));
                }
                // The ordinary frontier stays authoritative for forwarding order, so the next
                // pending artifact forwards regardless of whether it is the floor's own V-QC.
                if let Some(forwarding) = self.next_artifact_forwarding(None)? {
                    capabilities.extend(self.reserve_change(forwarding)?.into_capabilities());
                    // Stage the floor only once the view's first-V-QC forwarding duty is durable,
                    // recomputing the retirement ledgers the forwarding may have changed. A
                    // different same-view anchor is carried by the proposal that selects it.
                    if self.durable.vqc_forwarded(floor_view)
                        && let Some(change) = self.next_finality_floor_change()
                        && self.finality_floor_fits(&change)?
                    {
                        capabilities.extend(self.reserve_change(change)?.into_capabilities());
                    }
                    return Ok((true, capabilities));
                }
            } else if self.finality_floor_fits(&change)? {
                capabilities.extend(self.reserve_change(change)?.into_capabilities());
                return Ok((true, capabilities));
            }
        }

        // Assembly retains only the certificate artifact; publication defers separately when
        // the outbox is full, so a saturated outbox must not stall aggregation or leave the
        // component claiming ready work it cannot perform.
        let aggregate_slots = self.certificate_artifact_slots().min(1);
        self.finality
            .drive_aggregate(self.durable.generation, aggregate_slots)?;
        capabilities.extend(self.take_finality_capabilities());
        Ok((
            self.finality.has_ready_aggregate() && aggregate_slots > 0,
            capabilities,
        ))
    }

    fn drive_da_component(
        &mut self,
        cycle: &mut ServiceCycle,
    ) -> Result<(bool, Capabilities<V, H::Digest>), StepError> {
        if let Some(request) = self.chain.pending_build_sign_request(&self.profile)? {
            let effect = DurableEffect::Sign(request);
            if self.effect_fits(&effect, 1)? {
                // Consume the volatile build slot before staging: application observes the
                // producer choice immediately and expects the reservation consumed.
                self.chain.mark_build_reserved();
                let step = self.reserve_effect_prechecked(effect)?;
                return Ok((true, step.into_capabilities()));
            }
        }

        let mut capabilities = Capabilities::None;
        let deferred_da = take(&mut self.defer_da_certificate);
        if !deferred_da && self.advance_da_certificate(&mut capabilities)? {
            return Ok((true, capabilities));
        }

        capabilities.extend(self.take_chain_capabilities()?);
        let certificate_slots = self.certificate_slots();
        let deferred = (certificate_slots > 0)
            .then(|| self.views.deferred_certificate_view(self.durable.view))
            .flatten();
        let reserve_deferred = self.prefer_deferred_view_certificate && deferred.is_some();
        let da_recovery_slots = self
            .da_recovery_slots()
            .saturating_sub(usize::from(reserve_deferred));
        self.chain.drive(
            &self.profile,
            self.durable.generation,
            da_recovery_slots.min(1),
            false,
        )?;
        if deferred.is_some() {
            self.prefer_deferred_view_certificate = true;
            self.scheduler
                .enqueue(WorkKey::Drive(ProtocolComponent::View));
        }
        capabilities.extend(self.take_chain_capabilities()?);

        let production_credit = self.can_reserve_build_credit();
        self.chain
            .drive(&self.profile, self.durable.generation, 0, production_credit)?;
        capabilities.extend(self.take_chain_capabilities()?);

        if deferred_da && self.advance_da_certificate(&mut capabilities)? {
            return Ok((true, capabilities));
        }

        if self.certificate_outbox_slots() > 0 && self.certificate_artifact_slots() > 0 {
            match cycle.charge(Lane::LocalCompletion, TransitionCost::ArtifactItems(1)) {
                Ok(()) => {}
                Err(ServiceError::CoreBudgetExhausted | ServiceError::LaneExhausted) => {
                    return Ok((true, capabilities));
                }
                Err(ServiceError::CostOverflow) => return Err(StepError::IdentifierExhausted),
            }
            if let Some(block) = self.chain.next_ready_da_vote::<H>(&self.profile)? {
                // The chain cursor advances only with this exact choice, so each eligible chain
                // receives one DA quantum before any chain can be selected again.
                self.chain.mark_da_vote_reserved(block.header().clone());
                let effect = DurableEffect::Sign(SignRequest::DaVote(DaVoteRequest::new(block)));
                capabilities.extend(self.reserve_effect_prechecked(effect)?.into_capabilities());
            }
        }
        let recovery_slots = self.da_recovery_slots().saturating_sub(usize::from(
            self.prefer_deferred_view_certificate && deferred.is_some(),
        ));
        let recovery_ready = recovery_slots > 0 && self.chain.has_ready_recovery();
        Ok((recovery_ready, capabilities))
    }

    fn drive_view_component(
        &mut self,
        cycle: &mut ServiceCycle,
    ) -> Result<(bool, Capabilities<V, H::Digest>), StepError> {
        let mut capabilities = self.take_view_capabilities();
        let local_leader = matches!(
            self.profile.role(),
            Role::Validator(me) if me == self.profile.protocol().leader(self.durable.view)
        );
        if let Some(view) = self
            .views
            .missing_nullification(self.durable.view, local_leader)
            && let Some(job) = self.request_resolution(view)?
        {
            capabilities.push(Capability::Resolver(ResolverCapability::Resolve(job)));
        }

        if let Some(request) = self.views.cutoff_vote(self.durable.view) {
            let effect = DurableEffect::Sign(request);
            if self.effect_fits(&effect, 0)? {
                capabilities.extend(self.reserve_effect(effect)?.into_capabilities());
                return Ok((true, capabilities));
            }
        }
        if let Some(requests) = self
            .views
            .timeout_requests(&self.profile, self.durable.view)
        {
            let effect = DurableEffect::SignBatch(requests);
            if self.effect_fits(&effect, 0)? {
                capabilities.extend(self.reserve_effect(effect)?.into_capabilities());
                return Ok((true, capabilities));
            }
        }
        let regular = self.views.drive_regular_sign_request::<H>(
            &self.profile,
            self.durable.view,
            &self.chain,
            cycle.remaining_core() as usize,
        )?;
        if regular.processed > 0 {
            cycle
                .charge(
                    Lane::LocalCompletion,
                    TransitionCost::CommitteePass(regular.processed),
                )
                .map_err(|_| StepError::IdentifierExhausted)?;
        }
        if !regular.complete {
            return Ok((true, capabilities));
        }
        if let Some(request) = regular.request {
            let effect = DurableEffect::Sign(request);
            if self.effect_fits(&effect, 0)? {
                capabilities.extend(self.reserve_effect(effect)?.into_capabilities());
                return Ok((true, capabilities));
            }
        }

        if cycle.remaining_core() == 0 {
            return Ok((true, capabilities));
        }

        let drive = self.views.drive_certificates(
            &self.profile,
            self.durable.generation,
            self.durable.view,
            self.certificate_artifact_slots().min(1),
            cycle.remaining_core() as usize,
        )?;
        if drive.processed > 0 {
            cycle
                .charge(
                    Lane::LocalCompletion,
                    TransitionCost::CommitteePass(drive.processed),
                )
                .map_err(|_| StepError::IdentifierExhausted)?;
        }
        capabilities.extend(self.take_view_capabilities());
        if !drive.complete {
            return Ok((true, capabilities));
        }

        let proof = self
            .durable
            .forwarded_vqcs
            .get(&self.durable.view)
            .or_else(|| {
                self.durable
                    .forwarded_nullifications
                    .get(&self.durable.view)
            })
            .cloned();
        if let Some(exit) = proof.and_then(|proof| {
            self.views
                .exit::<H>(&self.profile, self.durable.view, proof)
        }) {
            if let Some(leader) = exit.rescue {
                let request = self
                    .views
                    .rescue_vote::<H>(&self.profile, &self.chain, &leader)?;
                let effect = DurableEffect::Sign(request);
                if self.effect_fits(&effect, 0)? {
                    capabilities.extend(self.reserve_effect(effect)?.into_capabilities());
                    return Ok((true, capabilities));
                }
            } else {
                let proof = exit.proof.id::<H>();
                let next = self
                    .durable
                    .view
                    .get()
                    .checked_add(1)
                    .ok_or(StepError::IdentifierExhausted)?;
                let floor = View::new(next)
                    .saturating_sub(self.profile.view_retention())
                    .saturating_sub(ViewDelta::new(1))
                    .max(self.durable.retired_view);
                let retired = self.obligations_retired_by_floor(floor);
                let step = self.reserve_change(Change::ViewAdvanced { proof, retired })?;
                capabilities.extend(step.into_capabilities());
                return Ok((true, capabilities));
            }
        }

        if let Some(change) = self.next_artifact_forwarding(None)? {
            capabilities.extend(self.reserve_change(change)?.into_capabilities());
            return Ok((true, capabilities));
        }
        if let Some(request) = self
            .views
            .post_vote_nullify(&self.profile, self.durable.view)
        {
            let effect = DurableEffect::Sign(request);
            if self.effect_fits(&effect, 0)? {
                capabilities.extend(self.reserve_effect(effect)?.into_capabilities());
                return Ok((true, capabilities));
            }
        }

        if self.prefer_deferred_view_certificate
            && let Some(view) = self.views.deferred_certificate_view(self.durable.view)
        {
            if cycle.remaining_core() == 0 {
                return Ok((true, capabilities));
            }
            let before = self.views.certificate_reservations();
            let drive = self.views.drive_deferred_certificate(
                &self.profile,
                self.durable.generation,
                view,
                self.certificate_slots(),
                cycle.remaining_core() as usize,
            )?;
            if drive.processed > 0 {
                cycle
                    .charge(
                        Lane::LocalCompletion,
                        TransitionCost::CommitteePass(drive.processed),
                    )
                    .map_err(|_| StepError::IdentifierExhausted)?;
            }
            if self.views.certificate_reservations() > before {
                self.prefer_deferred_view_certificate = false;
            }
            capabilities.extend(self.take_view_capabilities());
            if !drive.complete {
                return Ok((true, capabilities));
            }
        }
        Ok((false, capabilities))
    }

    /// Selects the highest verified L-QC that can raise the current signing view.
    /// Returns the durable signing floor's view, or zero before any floor is recorded.
    pub(crate) fn signing_floor_view(&self) -> View {
        self.durable
            .signing_floor
            .as_deref()
            .and_then(|artifact| match artifact {
                Artifact::Lqc(certificate) => Some(certificate.view()),
                _ => None,
            })
            .unwrap_or_else(View::zero)
    }

    /// Returns the oldest certificate view that could raise a lagging finality floor.
    fn floor_resolution_view(&self) -> Option<View> {
        let floor = self.signing_floor_view();
        let next = floor.get().checked_add(1).map(View::new)?;
        (self.durable.view > next
            && self.floor_probe_view < self.durable.view
            && self.views.signing_floor_candidate(floor).is_none())
        .then_some(next)
    }

    fn next_finality_floor_change(&self) -> Option<Change<V, H::Digest>> {
        let proof = self
            .views
            .signing_floor_candidate(self.signing_floor_view())?;
        let Artifact::Lqc(certificate) = proof.as_ref() else {
            unreachable!("the finality index admits only L-QCs")
        };
        let view = certificate.view();
        let change = Change::FinalityFloorAdvanced {
            proof,
            retired: self.obsolete_consensus_signing_effects(view),
            publication_retired: self.obligations_retired_by_floor(view),
        };
        Some(change)
    }

    fn next_artifact_forwarding(
        &self,
        required: Option<&Lqc<V, H::Digest>>,
    ) -> Result<Option<Change<V, H::Digest>>, StepError> {
        let Some(artifact) = self.views.next_forward() else {
            return Ok(None);
        };
        if required.is_some_and(|required| {
            !matches!(artifact.as_ref(), Artifact::Vqc(certificate)
                if required.equivalent_vqc(certificate))
        }) {
            return Ok(None);
        }
        let effect =
            DurableEffect::publication(Arc::clone(&artifact), None, self.profile.protocol())
                .ok_or(StepError::UnauthorizedEffect)?;
        let retired =
            self.obligations_retired_by_exit(artifact.view().expect("exit proof has a view"));
        if !self.effect_fits_after_retiring(&effect, &retired)? {
            return Ok(None);
        }
        let forwarding_facts =
            self.durable.forwarded_vqcs.len() + self.durable.forwarded_nullifications.len();
        if forwarding_facts >= self.profile.resources().max_forwarded_certificates() {
            return Err(StepError::ForwardingHistoryFull);
        }
        let cursor = self
            .durable
            .cursor
            .next()
            .ok_or(StepError::IdentifierExhausted)?;
        Ok(Some(Change::ArtifactForwarded {
            publication: EffectId::from_cursor(cursor),
            retired,
            artifact,
        }))
    }

    /// Makes the all-vote V-QC carried by an L-QC visible to the normal forwarding selector.
    ///
    /// The paper treats certificates derivable from received constituents as present in local
    /// State. Reusing the L-QC aggregate preserves the original observation order without another
    /// cryptographic job.
    fn observe_derived_vqc(
        &mut self,
        certificate: &Lqc<V, H::Digest>,
        observation: Observation,
    ) -> Result<(), StepError> {
        let certificate = certificate
            .derive_vqc(self.profile.protocol().codec_config())
            .map_err(|_| StepError::ViewInvariant)?;
        let artifact = Arc::new(Artifact::Vqc(certificate));
        let id = artifact.id::<H>();
        if artifact.view().is_some_and(|view| view < self.durable.view) {
            self.views
                .retain_vqc_parent::<H>(&artifact, &self.profile)
                .map_err(|_| StepError::ViewInvariant)?;
        } else {
            self.views
                .observe::<H>(id, observation, &artifact, &self.profile)
                .map_err(|_| StepError::ViewInvariant)?;
        }
        Ok(())
    }

    fn obsolete_consensus_signing_effects(&self, floor: View) -> Vec<EffectId> {
        self.durable
            .signing_reservations
            .iter()
            .filter_map(|(id, effect)| {
                let obsolete = match effect {
                    DurableEffect::Sign(request) => {
                        request.consensus_view().is_some_and(|view| view <= floor)
                    }
                    DurableEffect::SignBatch(requests) => requests
                        .iter()
                        .all(|request| request.consensus_view().is_some_and(|view| view <= floor)),
                    _ => false,
                };
                obsolete.then_some(*id)
            })
            .collect()
    }

    fn advance_da_certificate(
        &mut self,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<bool, StepError> {
        let Some(artifact) = self.next_durable_da_certificate() else {
            return Ok(false);
        };
        let Artifact::DaCertificate(certificate) = artifact.as_ref() else {
            return Err(StepError::ChainInvariant);
        };
        let retired = self
            .obligations_retired_by_da(certificate.header().chain(), certificate.header().height());
        let publication = if retired.is_empty() {
            None
        } else {
            Some(EffectId::from_cursor(
                self.durable
                    .cursor
                    .next()
                    .ok_or(StepError::IdentifierExhausted)?,
            ))
        };
        let change = Change::DaCertificateAdvanced {
            publication,
            retired,
            artifact,
        };
        let step = self.reserve_change(change)?;
        self.defer_da_certificate = true;
        capabilities.extend(step.into_capabilities());
        Ok(true)
    }

    fn next_durable_da_certificate(&self) -> Option<Arc<Artifact<V, H::Digest>>> {
        self.chain
            .next_certificate_above(&self.durable.certified_tips)
            .map(|certificate| Arc::new(Artifact::DaCertificate(certificate)))
    }

    fn effect_fits(
        &self,
        effect: &DurableEffect<V, H::Digest>,
        consumed_build_credits: usize,
    ) -> Result<bool, StepError> {
        match self.check_effect_capacity(effect, consumed_build_credits) {
            Ok(()) => Ok(true),
            Err(StepError::OutboxFull | StepError::LocalArtifactReservation) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn effect_fits_after_retiring(
        &self,
        effect: &DurableEffect<V, H::Digest>,
        retired: &[EffectId],
    ) -> Result<bool, StepError> {
        if retired.is_empty() {
            return self.effect_fits(effect, 0);
        }
        self.ensure_live()?;
        if !effect.authorized(&self.profile) {
            return Err(StepError::UnauthorizedEffect);
        }

        let occupied = self
            .durable_effect_count()
            .checked_sub(retired.len())
            .and_then(|occupied| occupied.checked_add(self.pending_artifact_reservations()));
        if occupied.is_none_or(|occupied| occupied >= self.profile.resources().max_outbox_effects())
        {
            return Ok(false);
        }

        let added_reservations = DurableState::effect_reservations(effect);
        if self.artifacts.len() + self.local_artifact_reservations() + added_reservations
            > self.profile.resources().max_cached_artifacts()
        {
            return Ok(false);
        }

        let occupancy = self
            .durable_occupancy_after_retiring(effect, retired)
            .and_then(|occupancy| occupancy.checked_add(self.pending_artifact_reservations()));
        Ok(occupancy
            .is_some_and(|occupancy| occupancy <= self.profile.resources().max_cached_artifacts()))
    }

    fn durable_occupancy_after_retiring(
        &self,
        effect: &DurableEffect<V, H::Digest>,
        retired: &[EffectId],
    ) -> Option<usize> {
        let (mut changes, released_reservations) = self.released_effect_references(retired)?;
        let mut overflow = false;
        DurableState::visit_effect_artifacts::<H>(effect, |artifact| {
            let added = &mut changes.entry(artifact).or_default().1;
            let Some(next) = added.checked_add(1) else {
                overflow = true;
                return;
            };
            *added = next;
        });
        if overflow {
            return None;
        }
        self.adjusted_durable_occupancy(
            changes,
            released_reservations,
            DurableState::effect_reservations(effect),
        )
    }

    fn can_reserve_build_credit(&self) -> bool {
        self.durable_effect_count() + self.pending_artifact_reservations()
            < self.profile.resources().max_outbox_effects()
            && self.artifacts.len() + self.local_artifact_reservations()
                < self.profile.resources().max_cached_artifacts()
            && self.durable_artifact_occupancy().is_some_and(|occupancy| {
                occupancy < self.profile.resources().max_cached_artifacts()
            })
    }

    fn certificate_slots(&self) -> usize {
        self.certificate_artifact_slots()
            .min(self.certificate_outbox_slots())
    }

    fn da_recovery_slots(&self) -> usize {
        let mut outbox_slots = self.certificate_outbox_slots();
        // A recovered own-chain certificate sits strictly above the durable certified tip, so
        // it supersedes the tip certificate's broadcast and the completion retires that
        // publication before its own capacity check. An outstanding own-chain certificate
        // broadcast therefore funds one recovery slot even when the outbox is otherwise full,
        // keeping certificate formation decoupled from unrelated egress pressure.
        if outbox_slots == 0 && self.own_certificate_publication_outstanding() {
            outbox_slots = 1;
        }
        self.certificate_artifact_slots().min(outbox_slots)
    }

    fn own_certificate_publication_outstanding(&self) -> bool {
        let Role::Validator(me) = self.profile.role() else {
            return false;
        };
        let Some(chain) = self.profile.protocol().producer_chain(me) else {
            return false;
        };
        self.durable.outbox.values().any(|effect| {
            matches!(effect, DurableEffect::Broadcast(artifact)
                if matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                    if certificate.header().chain() == chain))
        })
    }

    fn certificate_artifact_slots(&self) -> usize {
        let resources = self.profile.resources();
        let volatile_slots = resources
            .max_cached_artifacts()
            .saturating_sub(self.artifacts.len() + self.local_artifact_reservations());
        let durable_slots = self.durable_artifact_occupancy().map_or(0, |occupancy| {
            resources.max_cached_artifacts().saturating_sub(occupancy)
        });
        volatile_slots.min(durable_slots)
    }

    fn certificate_outbox_slots(&self) -> usize {
        self.profile
            .resources()
            .max_outbox_effects()
            .saturating_sub(self.durable_effect_count() + self.pending_artifact_reservations())
    }

    fn durable_effect_count(&self) -> usize {
        self.durable.effect_count()
    }

    fn durable_effect(&self, id: EffectId) -> Option<DurableEffect<V, H::Digest>> {
        self.durable.effect(&id)
    }

    fn contains_durable_effect(&self, id: EffectId) -> bool {
        self.durable.contains_effect(&id)
    }

    fn take_chain_capabilities(&mut self) -> Result<Capabilities<V, H::Digest>, StepError> {
        let pending = self.chain.take_effects();
        let mut capabilities = Capabilities::None;
        for chain_effect in pending {
            match chain_effect {
                ChainEffect::Build(job) => {
                    capabilities.push(Capability::Producer(ProducerCapability::Build(job)));
                }
                ChainEffect::Validate(job) => {
                    capabilities.push(Capability::Producer(ProducerCapability::Validate(job)));
                }
                ChainEffect::CancelValidations { chain, through } => {
                    capabilities.push(Capability::Producer(
                        ProducerCapability::CancelValidations { chain, through },
                    ));
                }
                ChainEffect::ArmTimer(timer) => {
                    capabilities.push(Capability::Producer(ProducerCapability::ArmTimer(timer)));
                }
                ChainEffect::Recover(job) => {
                    capabilities.push(Capability::Producer(ProducerCapability::RecoverDa(job)));
                }
            }
        }
        Ok(capabilities)
    }

    /// Returns whether the machine still needs evidence crossing the requested view.
    fn resolution_needed(&self, view: View) -> bool {
        !self.has_exit_for(view) || self.floor_resolution_view() == Some(view)
    }

    fn has_exit_for(&self, view: View) -> bool {
        self.artifacts.values().any(|entry| {
            matches!(entry.state, ArtifactState::Ready)
                && (matches!(
                    entry.artifact.as_ref(),
                    Artifact::Nullification(proof) if proof.view() == view
                ) || matches!(
                    entry.artifact.as_ref(),
                    Artifact::Vqc(proof) if proof.view() == view
                ))
        })
    }

    fn retract_unneeded_resolutions(&mut self) {
        let views = self.resolution.keys().collect::<Vec<_>>();
        for view in views {
            if !self.resolution_needed(view) {
                self.cancel_resolution(view);
            }
        }
    }

    fn cancel_resolution(&mut self, view: View) {
        if let Some(job) = self.resolution.resolved(view) {
            self.resolution_effects
                .push(Capability::Resolver(ResolverCapability::Cancel(job)));
        }
    }

    fn fail_resolution_verification(
        &mut self,
        artifact: ArtifactId<H::Digest>,
    ) -> Vec<ResolutionJob> {
        let failed = self.resolution.verification_failed(artifact);
        if !failed.is_empty() {
            self.wake_components();
        }
        for job in &failed {
            self.resolution_effects
                .push(Capability::Resolver(ResolverCapability::Reject(*job)));
        }
        failed
    }

    fn rearm_failed_resolutions(
        &mut self,
        failed: impl IntoIterator<Item = ResolutionJob>,
    ) -> Result<(), StepError> {
        for failed in failed {
            let view = failed.view();
            if self.resolution_needed(view)
                && let Some(retry) = self.request_resolution(view)?
            {
                self.resolution_effects
                    .push(Capability::Resolver(ResolverCapability::Resolve(retry)));
            }
        }
        Ok(())
    }

    fn take_resolution_capabilities(&mut self) -> Capabilities<V, H::Digest> {
        take(&mut self.resolution_effects).into()
    }

    fn request_resolution(&mut self, view: View) -> Result<Option<ResolutionJob>, StepError> {
        self.resolution
            .request(
                self.durable.generation,
                view,
                self.profile.resources().max_dependency_waiters(),
            )
            .map_err(|()| StepError::IdentifierExhausted)
    }

    fn take_view_capabilities(&mut self) -> Capabilities<V, H::Digest> {
        self.views
            .take_effects()
            .into_iter()
            .map(|view_effect| match view_effect {
                ViewEffect::RecoverNullification(job) => {
                    Capability::Leader(LeaderCapability::RecoverNullification(job))
                }
                ViewEffect::AggregateVqc(job) => {
                    Capability::Leader(LeaderCapability::AggregateVqc(job))
                }
            })
            .collect()
    }

    fn take_finality_capabilities(&mut self) -> Capabilities<V, H::Digest> {
        self.finality
            .take_finality_effects()
            .into_iter()
            .map(|finality_effect| match finality_effect {
                FinalityEffect::AggregateLqc(job) => {
                    Capability::Leader(LeaderCapability::AggregateLqc(job))
                }
            })
            .collect()
    }

    fn complete_da_recovery(
        &mut self,
        completion: &DaRecoveryCompletion<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let Some(artifact) = self
            .chain
            .prepare_recovery::<H>(completion, self.durable.generation)?
        else {
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        };
        // Retirement can drop the producer header a recovery belongs to while that recovery is in
        // flight. Journaling the certificate anyway would record an event that neither this
        // machine nor a replay of its journal can re-derive, so a retired subject makes the
        // completion stale rather than fatal.
        if !matches!(
            artifact.as_ref(),
            Artifact::DaCertificate(certificate)
                if self.chain.is_producer_header(certificate.header())
        ) {
            // Release the job as well: a reservation nobody will complete holds a recovery slot
            // for the rest of the epoch.
            self.chain.abandon_recovery::<H>(completion.id());
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        }
        let id = self.validate_self_admission(&artifact)?;
        let cursor = self
            .durable
            .cursor
            .next()
            .ok_or(StepError::IdentifierExhausted)?;
        let publication = EffectId::from_cursor(cursor);
        let Artifact::DaCertificate(certificate) = artifact.as_ref() else {
            return Err(StepError::ChainInvariant);
        };
        let retired = self
            .obligations_retired_by_da(certificate.header().chain(), certificate.header().height());
        let remaining = self.durable_effect_count().saturating_sub(retired.len());
        if remaining >= self.profile.resources().max_outbox_effects() {
            return Err(StepError::OutboxFull);
        }
        let mut step = self.reserve_change(Change::DaCertificateAdvanced {
            publication: Some(publication),
            retired,
            artifact: Arc::clone(&artifact),
        })?;
        self.self_admit(artifact, id)?;
        self.chain.finish_recovery::<H>(completion.id());
        step.status = StepStatus::DaRecovered {
            admission: SelfAdmission::new(id),
        };
        Ok(step)
    }

    fn complete_nullification_recovery(
        &mut self,
        completion: &NullificationRecoveryCompletion<V>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let Some(prepared) = self
            .views
            .prepare_nullification(completion, self.durable.generation)?
        else {
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        };
        let id = self.validate_self_admission(&prepared.artifact)?;
        if self.durable.local.contains_key(&id) {
            // The durable set already holds this exact certificate. apply_event rejects a second
            // creation of it, and apply_event is also the replay path, so reserving one would
            // journal an event no restart could re-derive. Recovering a certificate the node
            // already created is redundant, not a fault.
            self.views.finish_nullification(completion.id());
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        }
        let mut step = self.reserve_view_certificate(
            Arc::clone(&prepared.artifact),
            id,
            prepared.observation,
        )?;
        self.views.finish_nullification(completion.id());
        step.status = StepStatus::NullificationRecovered {
            admission: SelfAdmission::new(id),
        };
        Ok(step)
    }

    fn complete_vqc_aggregation(
        &mut self,
        completion: &VqcAggregateCompletion<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let Some(prepared) =
            self.views
                .prepare_vqc::<H>(&self.profile, completion, self.durable.generation)?
        else {
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        };
        let id = self.validate_self_admission(&prepared.artifact)?;
        if self.durable.local.contains_key(&id) {
            // Already held: the proposal this node built carried the same certificate. Reserving a
            // second creation would journal an event apply_event, and therefore replay, rejects.
            self.views.finish_vqc(completion.id());
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        }
        let mut step = self.reserve_view_certificate(
            Arc::clone(&prepared.artifact),
            id,
            prepared.observation,
        )?;
        self.views.finish_vqc(completion.id());
        step.status = StepStatus::VqcAggregated {
            admission: SelfAdmission::new(id),
        };
        Ok(step)
    }

    fn complete_lqc_aggregation(
        &mut self,
        prepared: &PreparedLqc<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        self.validate_self_admission_with_metadata(
            &prepared.artifact,
            prepared.artifact_id,
            prepared.encoded_len,
        )?;
        if self.durable.local.contains_key(&prepared.artifact_id) {
            // Aggregation may rediscover an L-QC already held locally. Recreating it would make
            // the journal invalid because artifact creation is unique by identifier.
            self.finality.finish_lqc(prepared.aggregate);
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        }
        if self.durable_effect_count() >= self.profile.resources().max_outbox_effects() {
            return Err(StepError::OutboxFull);
        }
        let cursor = self
            .durable
            .cursor
            .next()
            .ok_or(StepError::IdentifierExhausted)?;
        let publication = EffectId::from_cursor(cursor);
        let mut step = self.reserve_change(Change::ArtifactCreated {
            publication,
            artifact: Arc::clone(&prepared.artifact),
        })?;
        self.self_admit_at(
            Arc::clone(&prepared.artifact),
            prepared.artifact_id,
            prepared.observation,
        )?;
        self.finality.finish_lqc(prepared.aggregate);
        step.status = StepStatus::LqcAggregated {
            admission: SelfAdmission::new(prepared.artifact_id),
        };
        Ok(step)
    }

    fn reserve_view_certificate(
        &mut self,
        artifact: Arc<Artifact<V, H::Digest>>,
        id: ArtifactId<H::Digest>,
        observation: Observation,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let step = self.reserve_change(Change::ViewCertificateCreated {
            artifact: Arc::clone(&artifact),
        })?;
        self.self_admit_at(artifact, id, observation)?;
        Ok(step)
    }

    fn start(&mut self, recovery: bool) -> Result<Step<V, H::Digest>, StepError> {
        let expected = if recovery {
            Lifecycle::Recovering
        } else {
            Lifecycle::Fresh
        };
        if self.lifecycle != expected || !self.staged.is_empty() {
            return Err(StepError::Lifecycle);
        }
        if recovery {
            self.restore_durable_artifacts()?;
        }
        let generation = self
            .durable
            .generation
            .checked_add(1)
            .ok_or(StepError::IdentifierExhausted)?;
        // Every recovered event was replayed from the synced journal, so the durable prefix
        // and any recovered signature exposure are both acknowledged already.
        self.acked = self.durable.cursor;
        self.own_exposure = self.durable.cursor;
        let mut step = self.reserve_change(Change::GenerationAdvanced(generation))?;
        // State transitions happen at staging; the acknowledgement releases the recovered
        // outbox once the new generation is durable.
        self.lifecycle = Lifecycle::Live;
        self.restore_ready_artifacts()?;
        if recovery {
            let view = self.durable.view;
            if self.resolution_needed(view)
                && let Some(job) = self.request_resolution(view)?
            {
                step.capabilities
                    .push(Capability::Resolver(ResolverCapability::Resolve(job)));
            }
        }
        step.capabilities.extend(self.emit_staged());
        Ok(step)
    }

    fn observe(
        &mut self,
        artifacts: Vec<IdentifiedArtifact<V, H::Digest>>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        self.observe_artifacts(artifacts.into_iter(), true)
    }

    fn observe_artifacts(
        &mut self,
        artifacts: impl ExactSizeIterator<Item = IdentifiedArtifact<V, H::Digest>>,
        peer_attributed: bool,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let artifact_count = artifacts.len();
        let cohort = self.next_cohort;
        self.next_cohort = self
            .next_cohort
            .checked_add(1)
            .ok_or(StepError::IdentifierExhausted)?;

        let resources = self.profile.resources();
        if artifact_count > resources.max_verification_batch()
            || u32::try_from(artifact_count).is_err()
        {
            return Ok(Step::new(
                StepStatus::CohortRejected {
                    count: artifact_count,
                    rejection: Rejection::VerificationBatchTooLarge,
                },
                Vec::new(),
            ));
        }

        let job = JobId::new(self.next_job);
        let jobs_full = self.jobs.len() >= resources.max_inflight_verifications();
        let local_artifact_reservations = self.local_artifact_reservations();
        let mut single_result = None;
        let mut results = (artifact_count != 1).then(|| Vec::with_capacity(artifact_count));
        let mut items = None;

        let mut push_result = |result| match &mut results {
            Some(results) => results.push(result),
            None => {
                debug_assert!(single_result.is_none(), "a singleton cohort has one result");
                single_result = Some(result);
            }
        };

        for (index, (id, artifact)) in artifacts.enumerate() {
            let observation = Observation::new(cohort, index as u32);
            if let Some(rejection) = self.precheck_unidentified(&artifact) {
                push_result(ObservationResult {
                    id: None,
                    observation,
                    status: ObservationStatus::Rejected(rejection),
                });
                continue;
            }

            // Identifiers arrive precomputed from the same-process batcher, and every retained
            // index keys off them. A mismatch would poison the artifact cache, so it is checked
            // wherever the extra hash is affordable.
            debug_assert_eq!(
                id,
                artifact.id::<H>(),
                "artifact identifier matches content"
            );
            let mut status =
                self.precheck_identified(&artifact, id, jobs_full, local_artifact_reservations);
            let dependency_slot =
                status == ObservationStatus::Scheduled && self.needs_dependency_slot(&artifact);
            if dependency_slot
                && self.dependency_slots >= self.profile.resources().max_dependency_waiters()
            {
                status = ObservationStatus::Rejected(Rejection::DependencyWaitersFull);
            }

            if status == ObservationStatus::Scheduled
                && let Artifact::DaCertificate(certificate) = &artifact
                && !self
                    .chain
                    .claim_da_certificate::<H>(id, observation, certificate)?
            {
                status = ObservationStatus::Duplicate;
            }

            if status != ObservationStatus::Scheduled {
                push_result(ObservationResult {
                    id: Some(id),
                    observation,
                    status,
                });
                continue;
            }

            let future_view = artifact.view().filter(|view| *view > self.durable.view);
            let future = future_view.is_some();
            let artifact = Arc::new(artifact);
            // A proposal is actionable only with its parent certificate. Keeping an unresolved
            // proposal as a transition claim would order later V-QCs and nullifications behind a
            // dependency that the view owner cannot discharge.
            let deferred_proposal =
                dependency_slot && matches!(artifact.as_ref(), Artifact::LeaderBlock(_));
            if !deferred_proposal {
                self.views.claim(id, observation, &artifact);
            }
            self.claim_finality(id, observation, Arc::clone(&artifact))?;
            let provisions = self.retain_provider_index(id, &artifact);
            if dependency_slot {
                self.dependency_slots += 1;
            }
            let ticket = VerificationTicket::new(job, id, observation);
            self.artifacts.insert(
                id,
                ArtifactEntry {
                    artifact: Arc::clone(&artifact),
                    provisions,
                    observation,
                    state: ArtifactState::Pending(ticket),
                    dependency_protected: false,
                    future,
                    view_observed: false,
                    dependency_slot,
                },
            );
            if let Some(view) = future_view {
                self.future.insert((view, id));
            }
            if let Artifact::TransactionBlock(block) = artifact.as_ref() {
                self.chain
                    .register_transaction_block(id, observation, block)?;
            }
            items
                .get_or_insert_with(|| Vec::with_capacity(artifact_count))
                .push(VerificationItem::new(ticket, artifact, peer_attributed));
            push_result(ObservationResult {
                id: Some(id),
                observation,
                status,
            });
        }

        let mut capabilities = if let Some(items) = items {
            self.next_job = self
                .next_job
                .checked_add(1)
                .ok_or(StepError::IdentifierExhausted)?;
            let tickets = items.iter().map(VerificationItem::ticket).collect();
            self.jobs.insert(job, tickets);
            Capabilities::One(Capability::Verification(VerificationCapability::Verify(
                VerifyJob::new(job, self.durable.generation, items),
            )))
        } else {
            Capabilities::None
        };
        capabilities.extend(self.take_chain_capabilities()?);

        let results = results.map_or_else(
            || {
                ObservationResults::One(
                    single_result.expect("a singleton cohort produces exactly one result"),
                )
            },
            ObservationResults::Many,
        );

        Ok(Step::new(StepStatus::Observed(results), capabilities))
    }

    fn precheck_unidentified(&self, artifact: &Artifact<V, H::Digest>) -> Option<Rejection> {
        let resources = self.profile.resources();
        let protocol = self.profile.protocol();
        if artifact.epoch() != protocol.epoch() {
            return Some(Rejection::Context);
        }
        if artifact.signer().is_some_and(|participant| {
            participant.get() as usize >= protocol.codec_config().participants()
        }) {
            return Some(Rejection::Participant);
        }
        let chain = match artifact {
            Artifact::TransactionBlock(block) => Some(block.header().chain()),
            Artifact::DaVote(vote) => Some(vote.header().chain()),
            Artifact::DaCertificate(certificate) => Some(certificate.header().chain()),
            _ => None,
        };
        if chain.is_some_and(|chain| chain.get() as usize >= protocol.codec_config().chains()) {
            return Some(Rejection::Context);
        }
        if let Artifact::TransactionBlock(block) = artifact
            && protocol.producer(block.header().chain()) != Some(block.signer())
        {
            return Some(Rejection::Participant);
        }
        if artifact.encoded_len() > resources.max_artifact_bytes() {
            return Some(Rejection::ArtifactTooLarge);
        }
        if let Some(view) = artifact.view()
            && view > self.durable.view
            && !artifact.self_certifying_view()
            && view.get().saturating_sub(self.durable.view.get())
                > resources.max_future_view_distance()
        {
            return Some(Rejection::FutureView);
        }
        None
    }

    fn precheck_identified(
        &self,
        artifact: &Artifact<V, H::Digest>,
        id: ArtifactId<H::Digest>,
        jobs_full: bool,
        local_artifact_reservations: usize,
    ) -> ObservationStatus {
        if let Some(existing) = self.artifacts.get(&id) {
            // An identifier hashes the exact encoding, so a hit names the same artifact under
            // the collision resistance the journal and resolution already stand on. Comparing
            // the values instead would force the arriving copy's lazy signature decodes, and
            // gossip echoes make that the machine's dominant arrival cost.
            debug_assert!(
                existing.artifact.as_ref() == artifact,
                "two artifacts encode to one identifier"
            );
            return ObservationStatus::Duplicate;
        }

        let resources = self.profile.resources();
        if let Some(view) = artifact.view()
            && view > self.durable.view
            && self.future.len() >= resources.max_future_artifacts()
        {
            return ObservationStatus::Rejected(Rejection::FutureArtifactsFull);
        }
        if self.artifacts.len() + local_artifact_reservations >= resources.max_cached_artifacts() {
            return ObservationStatus::Rejected(Rejection::ArtifactCacheFull);
        }
        if jobs_full {
            return ObservationStatus::Rejected(Rejection::VerificationJobsFull);
        }

        ObservationStatus::Scheduled
    }

    fn local_artifact_reservations(&self) -> usize {
        self.durable_signing_reservations
            + self.chain.build_reservations()
            + self.chain.recovery_reservations()
            + self.views.certificate_reservations()
            + self.finality.aggregate_reservations()
    }

    fn pending_artifact_reservations(&self) -> usize {
        self.chain.build_reservations()
            + self.chain.recovery_reservations()
            + self.views.certificate_reservations()
            + self.finality.aggregate_reservations()
    }

    fn durable_artifact_occupancy(&self) -> Option<usize> {
        self.durable_artifact_references
            .len()
            .checked_add(self.durable_signing_reservations)?
            .checked_add(self.pending_artifact_reservations())
    }

    fn complete_verification(
        &mut self,
        completion: VerificationCompletion<H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if completion.generation() != self.durable.generation {
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        }
        let job = completion.job();
        let Some(tickets) = self.jobs.get(&job) else {
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        };
        if tickets.len() != completion.verdicts().len()
            || !tickets
                .iter()
                .zip(completion.verdicts())
                .all(|(expected, verdict)| expected == &verdict.ticket())
        {
            return Err(StepError::CompletionMismatch);
        }

        let verdicts = completion.into_verdicts();
        self.jobs.remove(&job);
        let mut valid = 0;
        let mut invalid = 0;
        for verdict in verdicts {
            if let Some(verdict_valid) = self.apply_verification_verdict(verdict)? {
                valid += usize::from(verdict_valid);
                invalid += usize::from(!verdict_valid);
            }
        }

        self.finish_verification_prefix(valid, invalid)
    }

    fn apply_verification_verdict(
        &mut self,
        verdict: Verdict<H::Digest>,
    ) -> Result<Option<bool>, StepError> {
        let ticket = verdict.ticket();
        let current = matches!(
            self.artifacts.get(&ticket.artifact()).map(|entry| &entry.state),
            Some(ArtifactState::Pending(expected)) if *expected == ticket
        );
        if !current {
            return Ok(None);
        }
        if verdict.valid() {
            let (observation, artifact) = {
                let entry = &self.artifacts[&ticket.artifact()];
                (entry.observation, Arc::clone(&entry.artifact))
            };
            self.validate_finality(ticket.artifact(), observation, &artifact)?;
            if matches!(artifact.as_ref(), Artifact::Vote(_)) {
                self.views.observe::<H>(
                    ticket.artifact(),
                    observation,
                    &artifact,
                    &self.profile,
                )?;
                self.artifacts
                    .get_mut(&ticket.artifact())
                    .expect("verified artifact remains retained")
                    .view_observed = true;
            }
            self.authenticate(ticket.artifact())?;
            return Ok(Some(true));
        }

        let failed = self.fail_resolution_verification(ticket.artifact());
        let artifact = Arc::clone(
            &self
                .artifacts
                .get(&ticket.artifact())
                .expect("issued verification ticket must retain its artifact")
                .artifact,
        );
        self.chain
            .reject_unverified::<H>(ticket.artifact(), &artifact)?;
        let invalid_dependency = artifact
            .provisions::<H>()
            .into_iter()
            .find(|dependency| matches!(dependency, Dependency::Vqc(_)));
        self.remove_terminal_artifact(ticket.artifact())?;
        self.rearm_failed_resolutions(failed)?;
        if let Some(dependency) = invalid_dependency {
            self.reject_dependency(dependency)?;
        }
        Ok(Some(false))
    }

    fn finish_verification_prefix(
        &mut self,
        valid: usize,
        invalid: usize,
    ) -> Result<Step<V, H::Digest>, StepError> {
        self.discard_chain_artifacts()?;
        self.wake_components();
        self.forget_retired_artifacts()?;
        Ok(Step::new(
            StepStatus::Verified { valid, invalid },
            Vec::new(),
        ))
    }

    fn authenticate(&mut self, id: ArtifactId<H::Digest>) -> Result<(), StepError> {
        let entry = &self.artifacts[&id];
        let dependency_protected = entry.dependency_protected;
        let dependencies = entry
            .artifact
            .dependencies()
            .into_iter()
            .filter(|dependency| !self.available.contains(dependency))
            .collect::<BTreeSet<_>>();

        if dependencies.is_empty() {
            return self.make_ready(id);
        }
        if !dependency_protected
            && (dependencies
                .iter()
                .any(|dependency| self.invalid_dependencies.contains(dependency))
                || self.dependency_rejections_saturated
                    && dependencies
                        .iter()
                        .any(|dependency| !self.has_retained_provider(*dependency)))
        {
            self.remove_terminal_artifact(id)?;
            return Ok(());
        }
        self.waiting += 1;
        for dependency in &dependencies {
            self.waiters.entry(*dependency).or_default().insert(id);
        }
        self.artifacts.get_mut(&id).expect("artifact exists").state =
            ArtifactState::Waiting(dependencies);
        Ok(())
    }

    fn reject_dependency(&mut self, dependency: Dependency<H::Digest>) -> Result<(), StepError> {
        let reject_all = !self.dependency_rejections_saturated
            && !self.invalid_dependencies.contains(&dependency)
            && self.invalid_dependencies.len() >= self.profile.resources().max_dependency_waiters();
        if reject_all {
            self.dependency_rejections_saturated = true;
            self.invalid_dependencies.clear();
        } else if !self.dependency_rejections_saturated {
            self.invalid_dependencies.insert(dependency);
        }

        let waiters = if reject_all {
            self.waiters
                .values()
                .flat_map(|waiters| waiters.iter().copied())
                .filter(|waiter| {
                    let Some(entry) = self.artifacts.get(waiter) else {
                        return false;
                    };
                    let ArtifactState::Waiting(missing) = &entry.state else {
                        return false;
                    };
                    !entry.dependency_protected
                        && missing
                            .iter()
                            .any(|dependency| !self.has_retained_provider(*dependency))
                })
                .collect::<BTreeSet<_>>()
        } else {
            self.waiters
                .get(&dependency)
                .into_iter()
                .flatten()
                .copied()
                .filter(|waiter| {
                    self.artifacts
                        .get(waiter)
                        .is_some_and(|entry| !entry.dependency_protected)
                })
                .collect()
        };
        for waiter in waiters {
            let Some(entry) = self.artifacts.get(&waiter) else {
                continue;
            };
            if !matches!(entry.state, ArtifactState::Waiting(_)) {
                continue;
            }
            self.remove_terminal_artifact(waiter)?;
        }
        Ok(())
    }

    fn has_retained_provider(&self, dependency: Dependency<H::Digest>) -> bool {
        self.providers.contains_key(&dependency)
    }

    fn remove_terminal_artifact(&mut self, id: ArtifactId<H::Digest>) -> Result<(), StepError> {
        let mut pending = BTreeSet::from([id]);
        let mut failed_resolutions = Vec::new();
        while let Some(id) = pending.pop_first() {
            failed_resolutions.extend(self.fail_resolution_verification(id));
            let Some(entry) = self.artifacts.remove(&id) else {
                continue;
            };
            self.reject_finality(id, entry.observation, &entry.artifact)?;
            self.views.reject(id, &entry.artifact);
            if entry.future {
                let view = entry.artifact.view().expect("future artifacts have a view");
                self.future.remove(&(view, id));
            }
            if entry.dependency_slot {
                self.dependency_slots -= 1;
            }
            if let ArtifactState::Waiting(missing) = entry.state {
                self.waiting -= 1;
                for dependency in missing {
                    let empty = self.waiters.get_mut(&dependency).is_some_and(|waiters| {
                        waiters.remove(&id);
                        waiters.is_empty()
                    });
                    if empty {
                        self.waiters.remove(&dependency);
                    }
                }
            }

            for provision in entry.provisions.iter().copied() {
                let empty = self.providers.get_mut(&provision).is_some_and(|providers| {
                    providers.remove(&id);
                    providers.is_empty()
                });
                if empty {
                    self.providers.remove(&provision);
                }
                if !self.dependency_rejections_saturated || self.has_retained_provider(provision) {
                    continue;
                }
                let waiters = self.waiters.get(&provision).cloned().unwrap_or_default();
                pending.extend(waiters.into_iter().filter(|waiter| {
                    let Some(entry) = self.artifacts.get(waiter) else {
                        return false;
                    };
                    let ArtifactState::Waiting(missing) = &entry.state else {
                        return false;
                    };
                    !entry.dependency_protected
                        && missing
                            .iter()
                            .any(|dependency| !self.has_retained_provider(*dependency))
                }));
            }
        }
        self.retract_unneeded_resolutions();
        self.rearm_failed_resolutions(failed_resolutions)
    }

    fn make_ready(&mut self, first: ArtifactId<H::Digest>) -> Result<(), StepError> {
        let mut ready = BTreeSet::from([first]);
        while let Some(id) = ready.pop_first() {
            let was_waiting = matches!(
                self.artifacts.get(&id).map(|entry| &entry.state),
                Some(ArtifactState::Waiting(_))
            );
            let entry = self.artifacts.get_mut(&id).expect("artifact exists");
            let promoted = !matches!(entry.state, ArtifactState::Ready);
            entry.state = ArtifactState::Ready;
            if promoted {
                let (observation, artifact) = (entry.observation, Arc::clone(&entry.artifact));
                self.newly_ready.push((observation, id, artifact));
            }
            if let Artifact::Vqc(certificate) = self.artifacts[&id].artifact.as_ref() {
                let certificate = certificate.id::<H>();
                if self
                    .vqcs
                    .insert(certificate, id)
                    .is_some_and(|existing| existing != id)
                {
                    return Err(StepError::ViewInvariant);
                }
            }
            let entry = self.artifacts.get_mut(&id).expect("artifact exists");
            if entry.dependency_slot {
                entry.dependency_slot = false;
                self.dependency_slots -= 1;
            }
            if was_waiting {
                self.waiting -= 1;
            }

            if self.lifecycle == Lifecycle::Live {
                for key in self.resolution.verification_ready(id) {
                    self.cancel_resolution(key);
                }
                let entry = &self.artifacts[&id];
                let observation = entry.observation;
                let artifact = Arc::clone(&entry.artifact);
                match artifact.as_ref() {
                    Artifact::Nullification(certificate) => {
                        self.cancel_resolution(certificate.view());
                    }
                    Artifact::Vqc(certificate) => {
                        self.cancel_resolution(certificate.view());
                    }
                    Artifact::Lqc(certificate) => {
                        let covered = self
                            .resolution
                            .keys()
                            .filter(|view| *view <= certificate.view())
                            .collect::<Vec<_>>();
                        for key in covered {
                            self.cancel_resolution(key);
                        }
                    }
                    _ => {}
                }
                self.chain
                    .observe::<H>(id, observation, &artifact, self.durable.generation)?;
                if let Artifact::LeaderBlock(block) = artifact.as_ref() {
                    let anchors = block.block().proposals().iter().filter_map(|proposal| {
                        match proposal.anchor() {
                            Anchor::Certificate(certificate) => Some(certificate.clone()),
                            Anchor::Tip(_) => None,
                        }
                    });
                    self.chain.install_verified_anchors::<H>(anchors)?;
                }
                if !self.artifacts[&id].view_observed {
                    self.views
                        .observe::<H>(id, observation, &artifact, &self.profile)
                        .map_err(|_| StepError::ViewInvariant)?;
                    self.artifacts
                        .get_mut(&id)
                        .expect("artifact exists")
                        .view_observed = true;
                }
            }

            let provisions = Arc::clone(&self.artifacts[&id].provisions);
            for provision in provisions.iter().copied() {
                if !self.available.insert(provision) {
                    continue;
                }
                let Some(waiters) = self.waiters.remove(&provision) else {
                    continue;
                };
                for waiter in waiters {
                    let Some(ArtifactState::Waiting(missing)) = self
                        .artifacts
                        .get_mut(&waiter)
                        .map(|entry| &mut entry.state)
                    else {
                        continue;
                    };
                    missing.remove(&provision);
                    if missing.is_empty() {
                        ready.insert(waiter);
                    }
                }
            }
        }
        self.discard_chain_artifacts()?;
        self.retract_unneeded_resolutions();
        self.forget_retired_artifacts()?;
        Ok(())
    }

    fn discard_chain_artifacts(&mut self) -> Result<(), StepError> {
        for id in self.chain.take_discarded_certificates() {
            self.remove_terminal_artifact(id)?;
        }
        Ok(())
    }

    /// The largest event batch one barrier may carry. The journal derives its record limits from
    /// these ceilings, including room for one indivisible event larger than the byte target.
    pub(crate) const MAX_BATCH_EVENTS: usize = 32;
    pub(crate) const MAX_BATCH_BYTES: usize = 1 << 20;
    /// Emitted-but-unacknowledged barriers allowed before ordinary batches stop entering the
    /// journal pipeline.
    const MAX_INFLIGHT_BARRIERS: usize = 4;
    /// Total unacknowledged batches retained by the synchronous owner: the journal pipeline,
    /// one coalescing batch, and one urgent successor that must not merge behind it.
    pub(crate) const MAX_STAGED_BARRIERS: usize = Self::MAX_INFLIGHT_BARRIERS + 2;

    /// Stages one durable change: applies it immediately and queues it for group commit.
    ///
    /// Staging is application. Every event mutates machine state through [`Self::apply_event`],
    /// the same transition function recovery replays, exactly once and in cursor order, so all
    /// later derivations see every staged event.
    ///
    /// External release splits by what durability protects. An effect referencing one of our
    /// signatures releases only once [`Machine::acked`] reaches its exposure floor: for the
    /// publication of a fresh signature that floor is this very event, so the record is always
    /// durable before the signature leaves. Forwarded certificates release after their exact batch
    /// enters the journal; other independently verifiable work can release in the returned step.
    /// A crash that forgets either publication is indistinguishable from network reordering.
    fn reserve_change(
        &mut self,
        change: Change<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let cursor = self
            .durable
            .cursor
            .next()
            .ok_or(StepError::IdentifierExhausted)?;
        let previous = self.durable.cursor;
        let generation = self.durable.generation;
        let event = DomainEvent::new(self.profile.protocol().epoch(), cursor, change);
        let kind = event.change().kind();
        let view_before = self.durable.view;
        let retired_before = self.durable.retired_view;
        let bytes = event.encode_size();
        let append_to_open = self.staged.back().is_some_and(|open| {
            !open.emitted
                && open.job.events().len() < Self::MAX_BATCH_EVENTS
                && open.bytes.saturating_add(bytes) <= Self::MAX_BATCH_BYTES
        });
        if !append_to_open && self.staged.len() >= Self::MAX_STAGED_BARRIERS {
            return Err(StepError::PersistenceCapacity);
        }
        if self.apply_event(&event).is_err() {
            // The machine derived a change its own validator rejects: internal corruption.
            return Err(StepError::DurableTransition(kind));
        }

        let mut capabilities = Capabilities::None;
        if self.durable.retired_view > retired_before {
            capabilities.push(Capability::Resolver(ResolverCapability::Prune(
                self.durable.retired_view,
            )));
        }
        // The recovered outbox re-releases at the generation barrier's acknowledgement, when
        // every recovered record is durable again under the new generation.
        let mut urgent = matches!(event.change(), Change::GenerationAdvanced(_));
        let release_after_enqueue = if let Some(id) = event.change().queued_effect() {
            if event.change().records_local_signature() {
                self.own_exposure = cursor;
                self.deferred_releases.push_back((cursor, id));
                urgent = true;
                None
            } else {
                let me = match self.profile.role() {
                    Role::Validator(participant) => Some(participant),
                    Role::Observer => None,
                };
                let referenced = self
                    .durable
                    .outbox
                    .get(&id)
                    .is_some_and(|effect| effect.references_own_signature(me));
                if referenced && self.own_exposure > self.acked {
                    self.deferred_releases.push_back((self.own_exposure, id));
                    None
                } else if matches!(event.change(), Change::ArtifactForwarded { .. }) {
                    self.release_outbox_job(id)
                } else {
                    self.release_outbox([id], &mut capabilities);
                    None
                }
            }
        } else {
            None
        };
        // A late finality floor leaves the view where the ordinary exit put it; re-arming the
        // timer for it would push out the deadline the running view already earned.
        if matches!(
            event.change(),
            Change::ViewAdvanced { .. } | Change::GenerationAdvanced(_)
        ) || (matches!(event.change(), Change::FinalityFloorAdvanced { .. })
            && self.durable.view != view_before)
        {
            capabilities.push(Capability::Leader(LeaderCapability::ArmTimer(Timer::new(
                self.durable.generation,
                Round::new(self.profile.protocol().epoch(), self.durable.view),
                self.profile.timers().view_timeout(),
            ))));
        }

        if append_to_open {
            let open = self
                .staged
                .back_mut()
                .expect("an appendable persistence batch remains staged");
            open.job.push_event(event, urgent);
            if let Some(job) = release_after_enqueue {
                open.release_after_enqueue.push(job);
            }
            open.bytes = open.bytes.saturating_add(bytes);
        } else {
            let id = BarrierId::new(self.next_barrier);
            self.next_barrier = self
                .next_barrier
                .checked_add(1)
                .ok_or(StepError::IdentifierExhausted)?;
            let job = PersistJob::new(id, generation, previous, vec![event], urgent);
            self.staged.push_back(PendingPersistence {
                job,
                release_after_enqueue: release_after_enqueue.into_iter().collect(),
                emitted: false,
                acknowledgement: None,
                bytes,
            });
        }
        Ok(Step::new(StepStatus::DurabilityReserved, capabilities))
    }

    /// Hands one cut batch to the driver while keeping the group-commit window open.
    ///
    /// Eligible batches emit in cursor order, one per poll, so the caller needs exactly one journal
    /// command slot before entering the reducer. The open batch at the back emits only when it is
    /// the sole staged batch: while any barrier is in flight it keeps absorbing non-urgent events,
    /// so batch sizes scale with storage latency and an idle machine still emits immediately.
    /// Urgent work makes every earlier batch eligible; repeated polls hand that prefix to the
    /// journal without allowing a later range to overtake it.
    fn next_staged_index(&self) -> Option<usize> {
        let staged = self.staged.len();
        let inflight = self.staged.iter().filter(|batch| batch.emitted).count();
        let force_through = self
            .staged
            .iter()
            .enumerate()
            .rev()
            .find(|(_, batch)| !batch.emitted && batch.job.urgent())
            .map(|(index, _)| index);
        for (index, batch) in self.staged.iter().enumerate() {
            if batch.emitted {
                continue;
            }
            let forced = force_through.is_some_and(|through| index <= through);
            if inflight >= Self::MAX_INFLIGHT_BARRIERS && !forced {
                break;
            }
            let last = index + 1 == staged;
            let full = batch.job.events().len() >= Self::MAX_BATCH_EVENTS
                || batch.bytes >= Self::MAX_BATCH_BYTES;
            if last && staged > 1 && !full && !forced {
                return None;
            }
            return Some(index);
        }
        None
    }

    fn freeze_persistence(
        &self,
        job: PersistJob<V, H::Digest>,
        release_after_enqueue: Vec<DurableJob<DurableEffect<V, H::Digest>>>,
    ) -> (
        PersistDirective<V, H::Digest>,
        FrozenAcknowledgement<V, H::Digest>,
    ) {
        let mut signed_publication = None;
        let mut staged_retention = Vec::new();
        let mut retention = Vec::new();
        let mut retirements = Vec::new();
        let mut forwarded_nullifications = 0usize;

        for event in job.events() {
            match event.change() {
                Change::SignedArtifact {
                    sign, publication, ..
                }
                | Change::SignedArtifactBatch {
                    sign, publication, ..
                } => {
                    signed_publication.get_or_insert((*sign, *publication));
                    self.extend_queued_publication(*publication, &mut retention);
                }
                Change::ArtifactCreated { publication, .. } => {
                    self.extend_queued_publication(*publication, &mut retention);
                }
                Change::OutboxQueued { effect, .. } => {
                    Self::extend_publication(effect, &mut retention);
                }
                Change::DaCertificateAdvanced {
                    artifact, retired, ..
                } => {
                    retention.push(Arc::clone(artifact));
                    retirements.extend(retired);
                }
                Change::ViewCertificateCreated { artifact } => {
                    retention.push(Arc::clone(artifact));
                }
                Change::ArtifactForwarded {
                    retired, artifact, ..
                } => {
                    staged_retention.push(Arc::clone(artifact));
                    retirements.extend(retired);
                    forwarded_nullifications +=
                        usize::from(matches!(artifact.as_ref(), Artifact::Nullification(_)));
                }
                Change::ViewAdvanced { retired, .. } => retirements.extend(retired),
                Change::FinalityFloorAdvanced {
                    proof,
                    publication_retired,
                    ..
                } => {
                    retention.push(Arc::clone(proof));
                    retirements.extend(publication_retired);
                }
                Change::GenerationAdvanced(_) => {}
            }
        }
        retirements.sort_unstable();
        retirements.dedup();
        (
            PersistDirective::new(
                job,
                staged_retention,
                release_after_enqueue,
                signed_publication,
            ),
            FrozenAcknowledgement {
                retention,
                retirements,
                forwarded_nullifications,
            },
        )
    }

    fn extend_queued_publication(
        &self,
        id: EffectId,
        retention: &mut Vec<Arc<Artifact<V, H::Digest>>>,
    ) {
        let Some(effect) = self.durable.outbox.get(&id) else {
            return;
        };
        Self::extend_publication(effect, retention);
    }

    fn extend_publication(
        effect: &DurableEffect<V, H::Digest>,
        retention: &mut Vec<Arc<Artifact<V, H::Digest>>>,
    ) {
        if !effect.is_network_publication() {
            return;
        }
        match effect {
            DurableEffect::Broadcast(artifact) => retention.push(Arc::clone(artifact)),
            DurableEffect::BroadcastBatch(artifacts) => {
                retention.extend(artifacts.iter().cloned());
            }
            DurableEffect::Send(request) => retention.push(Arc::clone(request.artifact())),
            DurableEffect::SendBatch(requests) => {
                retention.extend(
                    requests
                        .iter()
                        .map(|request| Arc::clone(request.artifact())),
                );
            }
            DurableEffect::Propose(_) => {}
            DurableEffect::Sign(_) | DurableEffect::SignBatch(_) => unreachable!(
                "signing requests are excluded by the network-publication classification"
            ),
        }
    }

    fn emit_staged(&mut self) -> Capabilities<V, H::Digest> {
        let Some(index) = self.next_staged_index() else {
            return Capabilities::None;
        };
        let batch = &self.staged[index];
        let job = batch.job.clone();
        let release_after_enqueue = batch.release_after_enqueue.clone();
        let (persist, acknowledgement) = self.freeze_persistence(job, release_after_enqueue);
        let batch = &mut self.staged[index];
        batch.emitted = true;
        debug_assert!(batch.acknowledgement.is_none());
        batch.acknowledgement = Some(acknowledgement);
        Capability::Durability(DurabilityCapability::Persist(persist)).into()
    }

    /// Acknowledges the oldest in-flight barrier and releases its external effects.
    ///
    /// The barrier's events were applied at staging; durability only opens the gate for the
    /// actions they authorized to leave the process.
    fn complete_persistence(
        &mut self,
        completion: BarrierAck,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if self.applied_barrier == Some(completion) {
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        }
        let Some(pending) = self.staged.front() else {
            if self
                .applied_barrier
                .is_some_and(|applied| completion.generation() < applied.generation())
            {
                return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
            }
            return Err(StepError::CompletionMismatch);
        };
        if completion.generation() < pending.job.generation() {
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        }
        if !pending.emitted
            || completion.barrier() != pending.job.id()
            || completion.generation() != pending.job.generation()
            || completion.cursor() != pending.job.last_cursor()
        {
            return Err(StepError::CompletionMismatch);
        }

        let pending = self
            .staged
            .pop_front()
            .expect("persistence job was just matched");
        let starts_generation = pending.starts_generation();
        let acknowledgement = pending
            .acknowledgement
            .expect("an emitted persistence job freezes its acknowledgement directives");
        self.acked = completion.cursor();
        self.applied_barrier = Some(completion);
        let FrozenAcknowledgement {
            retention,
            retirements,
            forwarded_nullifications,
        } = acknowledgement;
        #[cfg(test)]
        let retirements_for_test = retirements.clone();
        let acknowledged = !retention.is_empty()
            || forwarded_nullifications != 0
            || cfg!(test) && !retirements.is_empty();
        let mut capabilities = Capabilities::None;
        if acknowledged {
            capabilities.push(Capability::Durability(DurabilityCapability::Acknowledged {
                retention,
                forwarded_nullifications,
                #[cfg(test)]
                acknowledgement: completion,
                #[cfg(test)]
                retirements: retirements_for_test,
            }));
        }
        if starts_generation {
            // Everything recovered is durable again under the new generation, so the deferred
            // queue is subsumed by re-releasing the outbox.
            self.deferred_releases.clear();
            let mut released = self
                .durable
                .signing_reservations
                .keys()
                .copied()
                .chain(self.durable.outbox.keys().copied())
                .collect::<Vec<_>>();
            released.sort_unstable();
            self.release_outbox(released, &mut capabilities);
        } else {
            while let Some((floor, _)) = self.deferred_releases.front() {
                if *floor > self.acked {
                    break;
                }
                let (_, id) = self
                    .deferred_releases
                    .pop_front()
                    .expect("the deferred front was just inspected");
                self.release_outbox([id], &mut capabilities);
            }
        }
        self.sync_signing_completions();
        self.wake_components();
        // Acknowledgement may unblock the next batch in the pipeline.
        capabilities.extend(self.emit_staged());
        if !retirements.is_empty() {
            capabilities.push(Capability::Durability(DurabilityCapability::Retire(
                retirements,
            )));
        }
        Ok(Step::new(StepStatus::Persisted, capabilities))
    }

    fn restore_ready_artifacts(&mut self) -> Result<(), StepError> {
        let mut ready = self
            .artifacts
            .iter()
            .filter_map(|(id, entry)| {
                matches!(entry.state, ArtifactState::Ready).then_some((
                    entry.observation,
                    *id,
                    Arc::clone(&entry.artifact),
                ))
            })
            .collect::<Vec<_>>();
        ready.sort_unstable_by_key(|(observation, _, _)| *observation);
        for (observation, id, artifact) in ready {
            self.claim_finality(id, observation, Arc::clone(&artifact))?;
            self.validate_finality(id, observation, &artifact)?;
            self.chain
                .observe::<H>(id, observation, &artifact, self.durable.generation)?;
            self.views
                .observe::<H>(id, observation, &artifact, &self.profile)
                .map_err(|_| StepError::ViewInvariant)?;
        }
        Ok(())
    }

    fn durable_occupancy_after(
        &self,
        artifacts: impl IntoIterator<Item = ArtifactId<H::Digest>>,
        released_reservations: usize,
        added_reservations: usize,
    ) -> Option<usize> {
        let reservations = self
            .durable_signing_reservations
            .checked_sub(released_reservations)?
            .checked_add(added_reservations)?;
        let mut added = BTreeSet::new();
        for id in artifacts {
            if !self.durable_artifact_references.contains_key(&id) {
                added.insert(id);
            }
        }
        self.durable_artifact_references
            .len()
            .checked_add(added.len())?
            .checked_add(reservations)
    }

    fn durable_occupancy_with_effect(&self, effect: &DurableEffect<V, H::Digest>) -> Option<usize> {
        let mut artifacts = Vec::new();
        DurableState::visit_effect_artifacts::<H>(effect, |id| artifacts.push(id));
        self.durable_occupancy_after(artifacts, 0, DurableState::effect_reservations(effect))
    }

    fn finality_floor_occupancy(
        &self,
        retired: &[EffectId],
        proof: ArtifactId<H::Digest>,
        proposal_anchor: Option<ArtifactId<H::Digest>>,
    ) -> Option<usize> {
        let (mut changes, released_reservations) = self.released_effect_references(retired)?;
        if let Some(previous) = self.durable.signing_floor.as_ref() {
            changes.entry(previous.id::<H>()).or_default().0 += 1;
        }
        changes.entry(proof).or_default().1 += 1;
        if let Some(anchor) = proposal_anchor {
            if let Some(previous) = self.durable.proposal_anchor.as_ref() {
                changes.entry(previous.id::<H>()).or_default().0 += 1;
            }
            changes.entry(anchor).or_default().1 += 1;
        }

        self.adjusted_durable_occupancy(changes, released_reservations, 0)
    }

    fn finality_floor_fits(&self, change: &Change<V, H::Digest>) -> Result<bool, StepError> {
        let Change::FinalityFloorAdvanced { proof, retired, .. } = change else {
            return Err(StepError::DurableTransition("finality floor capacity"));
        };
        let Artifact::Lqc(certificate) = proof.as_ref() else {
            return Err(StepError::ViewInvariant);
        };
        let anchor = certificate
            .derive_vqc(self.profile.protocol().codec_config())
            .map_err(|_| StepError::ViewInvariant)?;
        let proposal_anchor = (certificate.view() >= self.proposal_anchor().0)
            .then(|| Artifact::Vqc(anchor).id::<H>());
        let occupancy = self
            .finality_floor_occupancy(retired, proof.id::<H>(), proposal_anchor)
            .and_then(|occupancy| occupancy.checked_add(self.pending_artifact_reservations()));

        Ok(occupancy
            .is_some_and(|occupancy| occupancy <= self.profile.resources().max_cached_artifacts()))
    }

    fn released_effect_references(
        &self,
        retired: &[EffectId],
    ) -> Option<(ReferenceChanges<H::Digest>, usize)> {
        let mut changes = ReferenceChanges::new();
        let mut reservations = 0usize;
        for id in retired {
            let effect = self.durable_effect(*id)?;
            match self.durable_effect_ids.get(id) {
                Some(ids) => {
                    for artifact in ids.iter().copied() {
                        changes.entry(artifact).or_default().0 += 1;
                    }
                }
                None => DurableState::visit_effect_artifacts::<H>(&effect, |artifact| {
                    changes.entry(artifact).or_default().0 += 1;
                }),
            }
            reservations = reservations.checked_add(DurableState::effect_reservations(&effect))?;
        }
        Some((changes, reservations))
    }

    fn adjusted_durable_occupancy(
        &self,
        changes: ReferenceChanges<H::Digest>,
        released_reservations: usize,
        added_reservations: usize,
    ) -> Option<usize> {
        let mut artifacts = self.durable_artifact_references.len();
        for (id, (released, added)) in changes {
            let before = self
                .durable_artifact_references
                .get(&id)
                .copied()
                .unwrap_or(0);
            let after = before.checked_sub(released)?.checked_add(added)?;
            match (before == 0, after == 0) {
                (true, false) => artifacts = artifacts.checked_add(1)?,
                (false, true) => artifacts = artifacts.checked_sub(1)?,
                _ => {}
            }
        }
        let reservations = self
            .durable_signing_reservations
            .checked_sub(released_reservations)?
            .checked_add(added_reservations)?;
        artifacts.checked_add(reservations)
    }

    fn retain_durable_artifact(&mut self, id: ArtifactId<H::Digest>) -> Result<(), ReplayError> {
        let references = self.durable_artifact_references.entry(id).or_default();
        *references = references.checked_add(1).ok_or(ReplayError::Transition)?;
        Ok(())
    }

    fn release_durable_artifact(&mut self, id: ArtifactId<H::Digest>) -> Result<(), ReplayError> {
        let Some(references) = self.durable_artifact_references.get_mut(&id) else {
            return Err(ReplayError::Transition);
        };
        *references = references.checked_sub(1).ok_or(ReplayError::Transition)?;
        if *references == 0 {
            self.durable_artifact_references.remove(&id);
        }
        Ok(())
    }

    /// Returns the artifact identifiers an effect carries, hashing each artifact once.
    fn effect_artifact_ids(effect: &DurableEffect<V, H::Digest>) -> Vec<ArtifactId<H::Digest>> {
        let mut ids = Vec::new();
        DurableState::visit_effect_artifacts::<H>(effect, |id| ids.push(id));
        ids
    }

    /// Retains an effect's artifacts and caches its identifiers for later release.
    ///
    /// `ids` must be the effect's own visited identifiers; callers that already computed them
    /// for validation pass them through so each artifact is hashed exactly once.
    fn admit_durable_effect(
        &mut self,
        id: EffectId,
        effect: &DurableEffect<V, H::Digest>,
        ids: Vec<ArtifactId<H::Digest>>,
    ) -> Result<(), ReplayError> {
        for artifact in ids.iter().copied() {
            self.retain_durable_artifact(artifact)?;
        }
        self.durable_signing_reservations = self
            .durable_signing_reservations
            .checked_add(DurableState::effect_reservations(effect))
            .ok_or(ReplayError::Transition)?;
        self.durable_effect_ids.insert(id, ids);
        Ok(())
    }

    /// Releases an effect's artifacts using its cached identifiers.
    pub(super) fn release_durable_effect(
        &mut self,
        id: EffectId,
        effect: &DurableEffect<V, H::Digest>,
    ) -> Result<(), ReplayError> {
        let ids = self
            .durable_effect_ids
            .remove(&id)
            .unwrap_or_else(|| Self::effect_artifact_ids(effect));
        for artifact in ids {
            self.release_durable_artifact(artifact)?;
        }
        self.durable_signing_reservations = self
            .durable_signing_reservations
            .checked_sub(DurableState::effect_reservations(effect))
            .ok_or(ReplayError::Transition)?;
        Ok(())
    }

    fn advance_proposal_anchor(
        &mut self,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), ReplayError> {
        let Artifact::Vqc(certificate) = artifact.as_ref() else {
            return Err(ReplayError::Transition);
        };
        let current = self
            .durable
            .proposal_anchor
            .as_deref()
            .and_then(|anchor| match anchor {
                Artifact::Vqc(anchor) => Some(anchor.view()),
                _ => None,
            })
            .unwrap_or_else(View::zero);
        if certificate.view() <= current || certificate.view() > self.durable.view {
            return Ok(());
        }

        self.set_proposal_anchor(artifact)
    }

    /// Installs an exact proposal parent, including a finality-backed same-view replacement.
    fn set_proposal_anchor(
        &mut self,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), ReplayError> {
        let Artifact::Vqc(certificate) = artifact.as_ref() else {
            return Err(ReplayError::Transition);
        };
        if certificate.view() > self.durable.view {
            return Err(ReplayError::Transition);
        }

        self.views
            .retain_vqc_parent::<H>(artifact, &self.profile)
            .map_err(|_| ReplayError::Transition)?;

        let id = artifact.id::<H>();
        self.retain_durable_artifact(id)?;
        if let Some(previous) = self.durable.proposal_anchor.replace(Arc::clone(artifact)) {
            self.release_durable_artifact(previous.id::<H>())?;
        }
        self.durable.proposal_nullified_through = self
            .durable
            .proposal_nullified_through
            .max(certificate.view());
        self.views
            .restore_proposal_frontier(certificate.view(), self.durable.proposal_nullified_through);
        Ok(())
    }

    /// Retires every view strictly below the retention floor.
    ///
    /// The floor is measured from the current view, so this runs whether or not finality advanced:
    /// a view the machine has left can never be acted in again, and its exact certificates, local
    /// artifacts, and exit proof are only reachable by resolution afterwards.
    fn compact_view_history(&mut self) -> Result<(), ReplayError> {
        let floor = self.retention_floor().max(self.durable.retired_view);
        self.durable.retired_view = floor;

        // Retention makes views at or below the floor unactionable, so their pending consensus
        // signing authority retires with the same durable transition regardless of which path
        // advanced the floor. A completion that arrives afterwards reconciles as a stale
        // observation instead of exposing a signature for a retired view.
        for id in self.obsolete_consensus_signing_effects(floor) {
            let effect = self
                .durable
                .signing_reservations
                .remove(&id)
                .ok_or(ReplayError::Transition)?;
            self.release_durable_effect(id, &effect)?;
        }

        let local = self
            .durable
            .local
            .iter()
            .filter_map(|(id, artifact)| {
                artifact
                    .view()
                    .is_some_and(|view| view <= floor)
                    .then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in local {
            self.durable.local.remove(&id);
            self.release_durable_artifact(id)?;
        }

        let forwarded = self
            .durable
            .forwarded_vqcs
            .range(..=floor)
            .chain(self.durable.forwarded_nullifications.range(..=floor))
            .map(|(_, artifact)| artifact.id::<H>())
            .collect::<Vec<_>>();
        self.durable.forwarded_vqcs.retain(|view, _| *view > floor);
        self.durable
            .forwarded_nullifications
            .retain(|view, _| *view > floor);
        for id in forwarded {
            self.release_durable_artifact(id)?;
        }
        self.durable.exits.retain(|view, _| *view > floor);

        self.retire_view_history()?;
        self.forget_retired_artifacts()
            .map_err(|_| ReplayError::Transition)?;
        Ok(())
    }

    const fn artifact_position(artifact: &Artifact<V, H::Digest>) -> Option<(ChainId, Height)> {
        let header = match artifact {
            Artifact::TransactionBlock(block) => block.header(),
            Artifact::DaVote(vote) => vote.header(),
            Artifact::DaCertificate(certificate) => certificate.header(),
            _ => return None,
        };
        Some((header.chain(), header.height()))
    }

    fn forget_ready_artifacts(&mut self, mut forget: impl FnMut(&Artifact<V, H::Digest>) -> bool) {
        let ids = self
            .artifacts
            .iter()
            .filter_map(|(id, entry)| {
                (!entry.future
                    && !self.durable_artifact_references.contains_key(id)
                    && matches!(entry.state, ArtifactState::Ready)
                    && forget(&entry.artifact))
                .then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in ids {
            let entry = self
                .artifacts
                .remove(&id)
                .expect("selected ready artifact remains retained");
            if let Artifact::Vqc(certificate) = entry.artifact.as_ref() {
                let certificate = certificate.id::<H>();
                if self.vqcs.get(&certificate) == Some(&id) {
                    self.vqcs.remove(&certificate);
                }
            }
            for provision in entry.provisions.iter() {
                let empty = self.providers.get_mut(provision).is_some_and(|providers| {
                    providers.remove(&id);
                    providers.is_empty()
                });
                if empty {
                    self.providers.remove(provision);
                    if matches!(provision, Dependency::Leader { round, .. }
                        if !round.view().is_zero() && round.view() <= self.durable.retired_view)
                    {
                        self.available.remove(provision);
                    }
                }
            }
        }
    }

    fn forget_retired_artifacts(&mut self) -> Result<(), StepError> {
        let view = self.durable.retired_view;
        let waiting = self
            .artifacts
            .iter()
            .filter_map(|(id, entry)| {
                (!entry.future
                    && !self.durable_artifact_references.contains_key(id)
                    && matches!(entry.state, ArtifactState::Waiting(_))
                    && entry
                        .artifact
                        .view()
                        .is_some_and(|artifact_view| artifact_view <= view))
                .then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in waiting {
            self.remove_terminal_artifact(id)?;
        }
        let floors = (0..self.durable.certified_tips.len())
            .map(|chain| self.chain_retention_height(chain))
            .collect::<Vec<_>>();
        self.forget_ready_artifacts(|artifact| {
            artifact
                .view()
                .is_some_and(|artifact_view| artifact_view <= view)
                || Self::artifact_position(artifact).is_some_and(|(chain, height)| {
                    floors
                        .get(chain.get() as usize)
                        .is_some_and(|floor| height <= *floor)
                })
        });
        Ok(())
    }

    fn apply_event(&mut self, event: &DomainEvent<V, H::Digest>) -> Result<(), ReplayError> {
        if event.epoch() != self.profile.protocol().epoch() {
            return Err(ReplayError::Context);
        }
        if self.durable.cursor.next() != Some(event.cursor()) {
            return Err(ReplayError::Cursor);
        }
        match event.change() {
            Change::GenerationAdvanced(generation) => {
                if self.durable.generation.checked_add(1) != Some(*generation) {
                    return Err(ReplayError::Transition);
                }
                self.durable.generation = *generation;
            }
            Change::OutboxQueued { id, effect } => {
                let is_publication = effect.is_network_publication();
                let ids = Self::effect_artifact_ids(effect);
                let proposal_attachment_valid = match effect.as_ref() {
                    DurableEffect::Sign(SignRequest::LeaderBlock(request)) => {
                        match request.parent() {
                            ProposalParent::Genesis => !request.attach_parent(),
                            ProposalParent::Exact(_) => true,
                        }
                    }
                    _ => true,
                };
                if *id != EffectId::from_cursor(event.cursor())
                    || self.contains_durable_effect(*id)
                    || self.durable_effect_count() >= self.profile.resources().max_outbox_effects()
                    || self
                        .durable_occupancy_after(
                            ids.iter().copied(),
                            0,
                            DurableState::effect_reservations(effect),
                        )
                        .is_none_or(|occupancy| {
                            occupancy > self.profile.resources().max_cached_artifacts()
                        })
                    || !effect.authorized(&self.profile)
                    || !proposal_attachment_valid
                {
                    return Err(ReplayError::Transition);
                }
                if let DurableEffect::Sign(SignRequest::TransactionBlock(header)) = effect.as_ref()
                {
                    let certified = self
                        .durable
                        .certified_tips
                        .get(header.chain().get() as usize)
                        .map(BlockRef::height)
                        .ok_or(ReplayError::Transition)?;
                    // Another process using this participant identity may have certified the
                    // parent. That certificate is already durable earlier in the journal prefix.
                    let parent_height = self.durable.produced_height.max(certified);
                    if parent_height.get().checked_add(1) != Some(header.height().get()) {
                        return Err(ReplayError::Transition);
                    }
                    self.chain
                        .observe_producer_choice::<H>(header)
                        .map_err(|_| ReplayError::Transition)?;
                    self.durable.produced_blocks = self
                        .durable
                        .produced_blocks
                        .checked_add(1)
                        .ok_or(ReplayError::Transition)?;
                    self.durable.produced_height = header.height();
                }
                let da_requests: Vec<&DaVoteRequest<V, H::Digest>> = match effect.as_ref() {
                    DurableEffect::Sign(SignRequest::DaVote(request)) => vec![request],
                    DurableEffect::SignBatch(requests) => requests
                        .iter()
                        .filter_map(|request| match request {
                            SignRequest::DaVote(request) => Some(request),
                            _ => None,
                        })
                        .collect(),
                    _ => Vec::new(),
                };
                for request in da_requests {
                    let header = request.header();
                    let Some(safe) = self
                        .durable
                        .da_safety_heights
                        .get_mut(header.chain().get() as usize)
                    else {
                        return Err(ReplayError::Transition);
                    };
                    if safe.get().checked_add(1) != Some(header.height().get()) {
                        return Err(ReplayError::Transition);
                    }
                    self.chain
                        .observe_da_choice(header)
                        .map_err(|_| ReplayError::Transition)?;
                    *safe = header.height();
                }
                if let DurableEffect::Sign(request) = effect.as_ref() {
                    self.views
                        .observe_sign_request(request)
                        .map_err(|_| ReplayError::Transition)?;
                }
                if let DurableEffect::SignBatch(requests) = effect.as_ref() {
                    for request in requests.iter() {
                        self.views
                            .observe_sign_request(request)
                            .map_err(|_| ReplayError::Transition)?;
                    }
                }
                self.chain
                    .reserve_signing(*id, effect)
                    .map_err(|_| ReplayError::Transition)?;
                self.admit_durable_effect(*id, effect, ids)?;
                let owned = effect.as_ref().clone();
                if matches!(&owned, DurableEffect::Sign(_) | DurableEffect::SignBatch(_)) {
                    if self
                        .durable
                        .signing_reservations
                        .insert(*id, owned)
                        .is_some()
                    {
                        return Err(ReplayError::Transition);
                    }
                } else {
                    self.durable.outbox.insert(*id, owned);
                }
                if is_publication && !self.install_publication_obligation(*id, effect) {
                    return Err(ReplayError::Transition);
                }
            }
            Change::SignedArtifact {
                sign,
                publication,
                artifact,
            } => {
                let Role::Validator(signer) = self.profile.role() else {
                    return Err(ReplayError::Transition);
                };
                let Some(DurableEffect::Sign(request)) =
                    self.durable.signing_reservations.get(sign)
                else {
                    return Err(ReplayError::Transition);
                };
                let request = request.clone();
                let valid_request = request.matches(signer, artifact);
                let attach_parent = matches!(
                    &request,
                    SignRequest::LeaderBlock(request) if request.attach_parent()
                );
                let parent = match &request {
                    SignRequest::LeaderBlock(request) => request.parent().exact().map(|parent| {
                        let artifact = Arc::new(Artifact::Vqc(parent.as_ref().clone()));
                        (artifact.id::<H>(), artifact)
                    }),
                    _ => None,
                };
                let parent_forwarding =
                    attach_parent
                        .then_some(parent.as_ref())
                        .flatten()
                        .map(|(id, artifact)| {
                            let Artifact::Vqc(certificate) = artifact.as_ref() else {
                                unreachable!("proposal parents are V-QCs");
                            };
                            (*id, certificate.view(), Arc::clone(artifact))
                        });
                let forwarding_facts =
                    self.durable.forwarded_vqcs.len() + self.durable.forwarded_nullifications.len();
                let adds_forwarding_fact = parent_forwarding
                    .as_ref()
                    .is_some_and(|(_, view, _)| !self.durable.forwarded_vqcs.contains_key(view));
                if artifact.encoded_len() > self.profile.resources().max_artifact_bytes() {
                    return Err(ReplayError::Transition);
                }
                let artifact_id = artifact.id::<H>();
                let Some(publication_effect) = DurableEffect::publication(
                    Arc::clone(artifact),
                    Some(&request),
                    self.profile.protocol(),
                ) else {
                    return Err(ReplayError::Transition);
                };
                if *publication != EffectId::from_cursor(event.cursor())
                    || !valid_request
                    || artifact.epoch() != self.profile.protocol().epoch()
                    || self
                        .durable_occupancy_after([artifact_id], 1, 0)
                        .is_none_or(|occupancy| {
                            occupancy > self.profile.resources().max_cached_artifacts()
                        })
                    || self.durable.local.contains_key(&artifact_id)
                    || parent.as_ref().is_some_and(|(id, parent)| {
                        self.durable
                            .local
                            .get(id)
                            .is_some_and(|existing| existing != parent)
                    })
                    || self.contains_durable_effect(*publication)
                    || (adds_forwarding_fact
                        && forwarding_facts
                            >= self.profile.resources().max_forwarded_certificates())
                    || !publication_effect.authorized(&self.profile)
                {
                    return Err(ReplayError::Transition);
                }
                if let Some((parent_id, parent)) = parent.as_ref()
                    && !self.durable.local.contains_key(parent_id)
                {
                    self.durable.local.insert(*parent_id, Arc::clone(parent));
                    self.retain_durable_artifact(*parent_id)?;
                }
                self.durable.local.insert(artifact_id, Arc::clone(artifact));
                self.retain_durable_artifact(artifact_id)?;
                self.chain
                    .complete_signing(
                        *sign,
                        self.durable.generation,
                        &DurableEffect::Sign(request),
                        self.lifecycle == Lifecycle::Recovering,
                    )
                    .map_err(|_| ReplayError::Transition)?;
                let completed = self
                    .durable
                    .signing_reservations
                    .remove(sign)
                    .expect("validated signing effect exists");
                self.release_durable_effect(*sign, &completed)?;
                let ids = Self::effect_artifact_ids(&publication_effect);
                let publish = self
                    .publication_obligation(*publication, &publication_effect)
                    .is_some();
                if publish {
                    self.admit_durable_effect(*publication, &publication_effect, ids)?;
                }
                if let Some((parent_id, view, parent)) = parent_forwarding {
                    let replaced = self
                        .durable
                        .forwarded_vqcs
                        .insert(view, Arc::clone(&parent));
                    if let Some(replaced) = replaced {
                        self.release_durable_artifact(replaced.id::<H>())?;
                    }
                    self.views.observe_forwarded::<H>(&parent);
                    self.retain_durable_artifact(parent_id)?;
                    self.advance_proposal_anchor(&parent)?;
                }
                if publish {
                    if !self.install_publication_obligation(*publication, &publication_effect) {
                        return Err(ReplayError::Transition);
                    }
                    self.durable.outbox.insert(*publication, publication_effect);
                }
            }
            Change::SignedArtifactBatch {
                sign,
                publication,
                artifacts,
            } => {
                let Role::Validator(signer) = self.profile.role() else {
                    return Err(ReplayError::Transition);
                };
                let Some(DurableEffect::SignBatch(requests)) =
                    self.durable.signing_reservations.get(sign)
                else {
                    return Err(ReplayError::Transition);
                };
                let requests = Arc::clone(requests);
                let valid_requests = requests.len() == artifacts.len()
                    && requests
                        .iter()
                        .zip(artifacts.iter())
                        .all(|(request, artifact)| request.matches(signer, artifact));
                let Some(publication_effect) = DurableEffect::publication_batch(
                    Arc::clone(artifacts),
                    self.profile.protocol(),
                ) else {
                    return Err(ReplayError::Transition);
                };
                let ids = artifacts
                    .iter()
                    .map(|artifact| artifact.id::<H>())
                    .collect::<BTreeSet<_>>();
                if *publication != EffectId::from_cursor(event.cursor())
                    || !valid_requests
                    || ids.len() != artifacts.len()
                    || artifacts.iter().any(|artifact| {
                        artifact.epoch() != self.profile.protocol().epoch()
                            || artifact.encoded_len()
                                > self.profile.resources().max_artifact_bytes()
                    })
                    || self
                        .durable_occupancy_after(ids.iter().copied(), requests.len(), 0)
                        .is_none_or(|occupancy| {
                            occupancy > self.profile.resources().max_cached_artifacts()
                        })
                    || ids.iter().any(|id| self.durable.local.contains_key(id))
                    || self.contains_durable_effect(*publication)
                    || !publication_effect.authorized(&self.profile)
                {
                    return Err(ReplayError::Transition);
                }
                for artifact in artifacts.iter() {
                    let id = artifact.id::<H>();
                    self.durable.local.insert(id, Arc::clone(artifact));
                    self.retain_durable_artifact(id)?;
                }
                let signing_effect = DurableEffect::SignBatch(requests);
                self.chain
                    .complete_signing(
                        *sign,
                        self.durable.generation,
                        &signing_effect,
                        self.lifecycle == Lifecycle::Recovering,
                    )
                    .map_err(|_| ReplayError::Transition)?;
                let completed = self
                    .durable
                    .signing_reservations
                    .remove(sign)
                    .expect("validated batch signing effect exists");
                self.release_durable_effect(*sign, &completed)?;
                let ids = Self::effect_artifact_ids(&publication_effect);
                let publish = self
                    .publication_obligation(*publication, &publication_effect)
                    .is_some();
                if publish {
                    self.admit_durable_effect(*publication, &publication_effect, ids)?;
                    if !self.install_publication_obligation(*publication, &publication_effect) {
                        return Err(ReplayError::Transition);
                    }
                    self.durable.outbox.insert(*publication, publication_effect);
                }
            }
            Change::ArtifactCreated {
                publication,
                artifact,
            } => {
                let artifact_id = artifact.id::<H>();
                let Some(effect) =
                    DurableEffect::publication(Arc::clone(artifact), None, self.profile.protocol())
                else {
                    return Err(ReplayError::Transition);
                };
                if *publication != EffectId::from_cursor(event.cursor())
                    || !matches!(artifact.as_ref(),
                        Artifact::DaCertificate(certificate)
                            if self.chain.is_producer_header(certificate.header())
                    ) && !matches!(artifact.as_ref(), Artifact::Lqc(_))
                    || artifact.epoch() != self.profile.protocol().epoch()
                    || artifact.encoded_len() > self.profile.resources().max_artifact_bytes()
                    || self
                        .durable_occupancy_after([artifact_id], 0, 0)
                        .is_none_or(|occupancy| {
                            occupancy > self.profile.resources().max_cached_artifacts()
                        })
                    || self.durable.local.contains_key(&artifact_id)
                    || self.contains_durable_effect(*publication)
                    || !effect.authorized(&self.profile)
                {
                    return Err(ReplayError::Transition);
                }
                self.durable.local.insert(artifact_id, Arc::clone(artifact));
                self.retain_durable_artifact(artifact_id)?;
                self.admit_durable_effect(*publication, &effect, vec![artifact_id])?;
                if !self.install_publication_obligation(*publication, &effect) {
                    return Err(ReplayError::Transition);
                }
                self.durable.outbox.insert(*publication, effect);
            }
            Change::DaCertificateAdvanced {
                publication,
                retired,
                artifact,
            } => {
                let Artifact::DaCertificate(certificate) = artifact.as_ref() else {
                    return Err(ReplayError::Transition);
                };
                let block = certificate.block_ref::<H>();
                let chain = block.chain().get() as usize;
                let Some(floor) = self.durable.certified_tips.get(chain).copied() else {
                    return Err(ReplayError::Transition);
                };
                let retired_height = block.height();
                let successor = DurableEffect::Broadcast(Arc::clone(artifact));
                let expected = self.obligations_retired_by_da(
                    certificate.header().chain(),
                    certificate.header().height(),
                );
                let remaining = self.durable_effect_count().saturating_sub(retired.len());
                let publishes = usize::from(publication.is_some());
                if block.height() <= floor.height()
                    || artifact.epoch() != self.profile.protocol().epoch()
                    || artifact.encoded_len() > self.profile.resources().max_artifact_bytes()
                    || retired != &expected
                    || retired.windows(2).any(|pair| pair[0] >= pair[1])
                    || remaining.saturating_add(publishes)
                        > self.profile.resources().max_outbox_effects()
                    || !successor.authorized(&self.profile)
                    || publication.is_some_and(|id| {
                        id != EffectId::from_cursor(event.cursor())
                            || self.contains_durable_effect(id)
                    })
                {
                    return Err(ReplayError::Transition);
                }

                let obsolete_local = self
                    .durable
                    .local
                    .iter()
                    .filter_map(|(id, artifact)| {
                        let obsolete = match artifact.as_ref() {
                            Artifact::TransactionBlock(old) => {
                                old.header().chain() == block.chain()
                                    && old.header().height() <= block.height()
                            }
                            Artifact::DaVote(vote) => {
                                vote.header().chain() == block.chain()
                                    && vote.header().height() <= retired_height
                            }
                            Artifact::DaCertificate(old) => old.header().chain() == block.chain(),
                            _ => false,
                        };
                        obsolete.then_some(*id)
                    })
                    .collect::<Vec<_>>();
                for id in obsolete_local {
                    self.durable.local.remove(&id);
                    self.release_durable_artifact(id)?;
                }
                let artifact_id = artifact.id::<H>();
                if self
                    .durable
                    .local
                    .insert(artifact_id, Arc::clone(artifact))
                    .is_some()
                {
                    return Err(ReplayError::Transition);
                }
                self.retain_durable_artifact(artifact_id)?;
                self.durable.certified_tips[chain] = block;
                self.durable.da_safety_heights[chain] = match self.profile.role() {
                    Role::Validator(_) => self.durable.da_safety_heights[chain].max(block.height()),
                    Role::Observer => block.height(),
                };
                self.retire_publication_obligations(retired)?;
                if let Some(id) = publication {
                    self.admit_durable_effect(*id, &successor, vec![artifact_id])?;
                    if !self.install_publication_obligation(*id, &successor) {
                        return Err(ReplayError::Transition);
                    }
                    self.durable.outbox.insert(*id, successor);
                }
                self.chain
                    .compact_certified::<H>(certificate, retired_height)
                    .map_err(|_| ReplayError::Transition)?;
                let floors = (0..self.durable.certified_tips.len())
                    .map(|chain| self.chain_retention_height(chain))
                    .collect::<Vec<_>>();
                self.forget_ready_artifacts(|artifact| {
                    Self::artifact_position(artifact).is_some_and(|(chain, height)| {
                        floors
                            .get(chain.get() as usize)
                            .is_some_and(|floor| height <= *floor)
                    })
                });
            }
            Change::ViewCertificateCreated { artifact } => {
                let artifact_id = artifact.id::<H>();
                if !matches!(
                    artifact.as_ref(),
                    Artifact::Nullification(_) | Artifact::Vqc(_)
                ) || artifact.epoch() != self.profile.protocol().epoch()
                    || artifact.encoded_len() > self.profile.resources().max_artifact_bytes()
                    || self
                        .durable_occupancy_after([artifact_id], 0, 0)
                        .is_none_or(|occupancy| {
                            occupancy > self.profile.resources().max_cached_artifacts()
                        })
                    || self.durable.local.contains_key(&artifact_id)
                {
                    return Err(ReplayError::Transition);
                }
                self.durable.local.insert(artifact_id, Arc::clone(artifact));
                self.retain_durable_artifact(artifact_id)?;
                // Record the assembly in view state exactly as the live path does. Without this,
                // a machine restored from a snapshot taken before this event would re-assemble a
                // certificate it already has, and the duplicate is rejected on persistence.
                self.views
                    .observe_durable_artifact(artifact, self.profile.role())
                    .map_err(|_| ReplayError::Transition)?;
            }
            Change::ArtifactForwarded {
                publication,
                retired,
                artifact,
            } => {
                let Some(effect) =
                    DurableEffect::publication(Arc::clone(artifact), None, self.profile.protocol())
                else {
                    return Err(ReplayError::Transition);
                };
                let new = match artifact.as_ref() {
                    Artifact::Vqc(certificate) => !self.durable.vqc_forwarded(certificate.view()),
                    Artifact::Nullification(certificate) => {
                        !self.durable.nullification_forwarded(certificate.view())
                    }
                    _ => false,
                };
                let artifact_id = artifact.id::<H>();
                let view = artifact.view().ok_or(ReplayError::Transition)?;
                let expected_retired = self.obligations_retired_by_exit(view);
                let forwarding_facts =
                    self.durable.forwarded_vqcs.len() + self.durable.forwarded_nullifications.len();
                let remaining = self.durable_effect_count().checked_sub(retired.len());
                if *publication != EffectId::from_cursor(event.cursor())
                    || !new
                    || artifact.epoch() != self.profile.protocol().epoch()
                    || artifact.encoded_len() > self.profile.resources().max_artifact_bytes()
                    || remaining.is_none_or(|remaining| {
                        remaining >= self.profile.resources().max_outbox_effects()
                    })
                    || forwarding_facts >= self.profile.resources().max_forwarded_certificates()
                    || self
                        .durable_occupancy_after_retiring(&effect, retired)
                        .is_none_or(|occupancy| {
                            occupancy > self.profile.resources().max_cached_artifacts()
                        })
                    || self.contains_durable_effect(*publication)
                    || !effect.authorized(&self.profile)
                    || retired != &expected_retired
                {
                    return Err(ReplayError::Transition);
                }
                self.retire_publication_obligations(retired)?;
                match artifact.as_ref() {
                    Artifact::Vqc(certificate) => {
                        self.durable
                            .forwarded_vqcs
                            .insert(certificate.view(), Arc::clone(artifact));
                    }
                    Artifact::Nullification(certificate) => {
                        self.durable
                            .forwarded_nullifications
                            .insert(certificate.view(), Arc::clone(artifact));
                    }
                    _ => unreachable!("certificate kind was validated"),
                }
                self.views.observe_forwarded::<H>(artifact);
                self.retain_durable_artifact(artifact_id)?;
                if matches!(artifact.as_ref(), Artifact::Vqc(_)) {
                    self.advance_proposal_anchor(artifact)?;
                }
                self.admit_durable_effect(*publication, &effect, vec![artifact_id])?;
                if !self.install_publication_obligation(*publication, &effect) {
                    return Err(ReplayError::Transition);
                }
                self.durable.outbox.insert(*publication, effect);
            }
            Change::ViewAdvanced { proof, retired } => {
                let view = self.durable.view;
                let proof_id = *proof;
                let Some(proof) = self
                    .durable
                    .forwarded_vqcs
                    .get(&view)
                    .into_iter()
                    .chain(self.durable.forwarded_nullifications.get(&view))
                    .find(|artifact| artifact.id::<H>() == proof_id)
                    .cloned()
                else {
                    return Err(ReplayError::Transition);
                };
                if self.durable.exits.contains_key(&view) {
                    return Err(ReplayError::Transition);
                }
                let Some(next) = view.get().checked_add(1) else {
                    return Err(ReplayError::Transition);
                };
                let floor = View::new(next)
                    .saturating_sub(self.profile.view_retention())
                    .saturating_sub(ViewDelta::new(1))
                    .max(self.durable.retired_view);
                if *retired != self.obligations_retired_by_floor(floor) {
                    return Err(ReplayError::Transition);
                }
                self.retire_publication_obligations(retired)?;
                match proof.as_ref() {
                    Artifact::Vqc(_) => self.advance_proposal_anchor(&proof)?,
                    Artifact::Nullification(_) => {
                        let expected = self
                            .durable
                            .proposal_nullified_through
                            .get()
                            .checked_add(1)
                            .ok_or(ReplayError::Transition)?;
                        if expected != view.get() {
                            return Err(ReplayError::Transition);
                        }
                        self.durable.proposal_nullified_through = view;
                        let (anchor, _) = self.proposal_anchor();
                        self.views.restore_proposal_frontier(anchor, view);
                    }
                    _ => return Err(ReplayError::Transition),
                }
                self.durable.exits.insert(view, proof);
                self.views.observe_exit(view, proof_id);
                self.durable.view = View::new(next);
                let current = self.durable.view;
                while let Some((view, id)) = self.future.first().copied() {
                    if view > current {
                        break;
                    }
                    self.future.pop_first();
                    self.artifacts
                        .get_mut(&id)
                        .expect("future index references retained artifact")
                        .future = false;
                }
                self.compact_view_history()?;
            }
            Change::FinalityFloorAdvanced {
                proof,
                retired,
                publication_retired,
            } => {
                let Artifact::Lqc(certificate) = proof.as_ref() else {
                    return Err(ReplayError::Transition);
                };
                let current = self.durable.view;
                // View position controls view and proposal progress. A delayed L-QC may still
                // advance the proposal anchor after another exit advanced view.
                let late = certificate.view() < current;
                let Some(next) = certificate.view().get().checked_add(1) else {
                    return Err(ReplayError::Transition);
                };
                let anchor = Arc::new(Artifact::Vqc(
                    certificate
                        .derive_vqc(self.profile.protocol().codec_config())
                        .map_err(|_| ReplayError::Transition)?,
                ));
                let proof_id = proof.id::<H>();
                let anchor_id = anchor.id::<H>();
                let anchor_installs = certificate.view() >= self.proposal_anchor().0;
                if (late && certificate.view() <= self.signing_floor_view())
                    || (!late && !self.durable.vqc_forwarded(certificate.view()))
                    || proof.epoch() != self.profile.protocol().epoch()
                    || proof.encoded_len() > self.profile.resources().max_artifact_bytes()
                    || anchor.encoded_len() > self.profile.resources().max_artifact_bytes()
                    || retired.windows(2).any(|pair| pair[0] >= pair[1])
                    || *retired != self.obsolete_consensus_signing_effects(certificate.view())
                    || *publication_retired != self.obligations_retired_by_floor(certificate.view())
                    || self
                        .finality_floor_occupancy(
                            retired,
                            proof_id,
                            anchor_installs.then_some(anchor_id),
                        )
                        .is_none_or(|occupancy| {
                            occupancy > self.profile.resources().max_cached_artifacts()
                        })
                {
                    return Err(ReplayError::Transition);
                }

                for id in retired {
                    let effect = self
                        .durable
                        .signing_reservations
                        .remove(id)
                        .ok_or(ReplayError::Transition)?;
                    self.release_durable_effect(*id, &effect)?;
                }
                self.retire_publication_obligations(publication_retired)?;
                self.retain_durable_artifact(proof_id)?;
                if let Some(previous) = self.durable.signing_floor.replace(Arc::clone(proof)) {
                    self.release_durable_artifact(previous.id::<H>())?;
                }
                if !late {
                    self.durable.view = View::new(next);
                }
                if anchor_installs {
                    self.set_proposal_anchor(&anchor)?;
                }
                self.durable.retired_view = self.durable.retired_view.max(certificate.view());
                let current = self.durable.view;
                while let Some((view, id)) = self.future.first().copied() {
                    if view > current {
                        break;
                    }
                    self.future.pop_first();
                    self.artifacts
                        .get_mut(&id)
                        .expect("future index references retained artifact")
                        .future = false;
                }
                self.compact_view_history()?;
            }
        }
        self.durable.cursor = event.cursor();
        Ok(())
    }

    fn release_outbox(
        &mut self,
        ids: impl IntoIterator<Item = EffectId>,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) {
        for id in ids {
            if let Some(job) = self.release_outbox_job(id) {
                capabilities.push(Capability::Durability(DurabilityCapability::Released(job)));
            }
        }
    }

    fn release_outbox_job(
        &mut self,
        id: EffectId,
    ) -> Option<DurableJob<DurableEffect<V, H::Digest>>> {
        let effect = self.durable_effect(id)?;
        if !effect.authorized(&self.profile) {
            return None;
        }
        self.chain
            .issue_signing(id, self.durable.generation, &effect)
            .expect("a released DA signing effect has an exact durable reservation");
        Some(DurableJob::new(id, self.durable.generation, effect))
    }

    fn complete_effect(
        &mut self,
        completion: EffectCompletion<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let id = completion.id();
        if completion.generation() != self.durable.generation
            || self.pending_signing.contains_key(&id)
            || !self.contains_durable_effect(id)
        {
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        }
        let effect = self
            .durable_effect(id)
            .expect("live durable effect was checked above");
        if !effect.authorized(&self.profile) {
            return Err(StepError::UnauthorizedEffect);
        }
        if !self
            .chain
            .signing_issued(id, self.durable.generation, &effect)
        {
            return Err(StepError::EffectMismatch);
        }

        if matches!(
            (&effect, &completion),
            (
                DurableEffect::Broadcast(_)
                    | DurableEffect::BroadcastBatch(_)
                    | DurableEffect::Propose(_)
                    | DurableEffect::Send(_)
                    | DurableEffect::SendBatch(_),
                EffectCompletion::Delivered { .. }
            )
        ) {
            return Ok(Step::new(
                StepStatus::EffectCompleted { admission: None },
                Vec::new(),
            ));
        }

        let completion = self.prepare_signing_completion(effect, completion)?;
        self.pending_signing.insert(id, completion);
        self.scheduler.enqueue(WorkKey::CompleteEffect(id));
        Ok(Step::new(
            StepStatus::EffectCompleted { admission: None },
            Vec::new(),
        ))
    }

    fn prepare_signing_completion(
        &mut self,
        effect: DurableEffect<V, H::Digest>,
        completion: EffectCompletion<V, H::Digest>,
    ) -> Result<PendingSigningCompletion<V, H::Digest>, StepError> {
        match (effect, completion) {
            (DurableEffect::Sign(request), EffectCompletion::Signed { artifact, .. }) => {
                let Role::Validator(signer) = self.profile.role() else {
                    return Err(StepError::UnauthorizedEffect);
                };
                if !request.matches(signer, &artifact) {
                    return Err(StepError::EffectMismatch);
                }
                let id = self.validate_self_admission(&artifact)?;
                Ok(PendingSigningCompletion::One { artifact, id })
            }
            (
                DurableEffect::SignBatch(requests),
                EffectCompletion::SignedBatch { artifacts, .. },
            ) => {
                let Role::Validator(signer) = self.profile.role() else {
                    return Err(StepError::UnauthorizedEffect);
                };
                if requests.len() != artifacts.len()
                    || !requests
                        .iter()
                        .zip(&artifacts)
                        .all(|(request, artifact)| request.matches(signer, artifact))
                {
                    return Err(StepError::EffectMismatch);
                }
                let artifacts = artifacts.into_iter().map(Arc::new).collect::<Arc<[_]>>();
                let ids = artifacts
                    .iter()
                    .map(|artifact| self.validate_self_admission(artifact))
                    .collect::<Result<Vec<_>, _>>()?;
                if ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len()
                    || self.artifacts.len() + ids.len()
                        > self.profile.resources().max_cached_artifacts()
                {
                    return Err(StepError::LocalArtifactReservation);
                }
                Ok(PendingSigningCompletion::Batch { artifacts, ids })
            }
            _ => Err(StepError::EffectMismatch),
        }
    }

    fn stage_signing_completion(
        &mut self,
        id: EffectId,
        completion: PendingSigningCompletion<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        if !self.durable.signing_reservations.contains_key(&id) {
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        }

        let change = match &completion {
            PendingSigningCompletion::One { artifact, .. } => {
                let cursor = self
                    .durable
                    .cursor
                    .next()
                    .ok_or(StepError::IdentifierExhausted)?;
                let publication = EffectId::from_cursor(cursor);
                Change::SignedArtifact {
                    sign: id,
                    publication,
                    artifact: Arc::clone(artifact),
                }
            }
            PendingSigningCompletion::Batch { artifacts, .. } => {
                let cursor = self
                    .durable
                    .cursor
                    .next()
                    .ok_or(StepError::IdentifierExhausted)?;
                let publication = EffectId::from_cursor(cursor);
                Change::SignedArtifactBatch {
                    sign: id,
                    publication,
                    artifacts: Arc::clone(artifacts),
                }
            }
        };
        let mut step = self.reserve_change(change)?;
        step.status = match completion {
            PendingSigningCompletion::One { artifact, id } => {
                self.self_admit(artifact, id)?;
                StepStatus::EffectCompleted {
                    admission: Some(SelfAdmission::new(id)),
                }
            }
            PendingSigningCompletion::Batch { artifacts, ids } => {
                for (artifact, id) in artifacts.iter().cloned().zip(ids.iter().copied()) {
                    self.self_admit(artifact, id)?;
                }
                StepStatus::EffectBatchCompleted {
                    admissions: ids.into_iter().map(SelfAdmission::new).collect(),
                }
            }
        };
        Ok(step)
    }

    fn drive_signing_completion(&mut self, id: EffectId) -> WorkResult<V, H::Digest> {
        let Some(completion) = self.pending_signing.get(&id).cloned() else {
            return Ok((WorkStatus::Complete, Capabilities::None));
        };
        let step = self.stage_signing_completion(id, completion)?;
        self.pending_signing.remove(&id);
        Ok((WorkStatus::Complete, step.into_capabilities()))
    }

    fn drive_crypto_completion(&mut self) -> WorkResult<V, H::Digest> {
        if let Some(prepared) = self.prepared_lqc.take() {
            return self.drive_prepared_lqc(prepared);
        }
        if matches!(self.pending_crypto.front(), Some(Input::LqcAggregated(_))) {
            let Input::LqcAggregated(completion) = self
                .pending_crypto
                .pop_front()
                .expect("the L-QC completion remains at the queue head")
            else {
                unreachable!("the queue head was checked above")
            };
            let prepared = match self.finality.prepare_lqc::<H>(
                &self.profile,
                *completion,
                self.durable.generation,
            ) {
                Ok(Some(prepared)) => prepared,
                Ok(None) => return Ok((self.pending_crypto_status(), Capabilities::None)),
                Err(error) => return Err(error.into()),
            };
            return self.drive_prepared_lqc(prepared);
        }
        let Some(input) = self.pending_crypto.pop_front() else {
            return Ok((WorkStatus::Complete, Capabilities::None));
        };
        let step = match &input {
            Input::DaRecovered(completion) => self.complete_da_recovery(completion),
            Input::NullificationRecovered(completion) => {
                self.complete_nullification_recovery(completion)
            }
            Input::VqcAggregated(completion) => self.complete_vqc_aggregation(completion),
            Input::LqcAggregated(_) => unreachable!("L-QC completions move out of the FIFO"),
            _ => unreachable!("only crypto completions park in the scheduler"),
        };
        let step = match step {
            Ok(step) => step,
            // Capacity is released by later barrier acknowledgements, so transient pressure
            // reparks the completion at the queue head instead of failing the machine.
            Err(StepError::OutboxFull | StepError::LocalArtifactReservation) => {
                self.pending_crypto.push_front(input);
                return Ok((WorkStatus::Blocked, Capabilities::None));
            }
            // A rejected completion is consumed: the underlying recovery or aggregation job
            // survives for a corrected completion, and the error surfaces exactly once rather
            // than poisoning every later drain of the queue.
            Err(error) => return Err(error),
        };
        let status = if self.pending_crypto.is_empty() {
            WorkStatus::Complete
        } else {
            WorkStatus::Requeue
        };
        Ok((status, step.into_capabilities()))
    }

    fn drive_prepared_lqc(
        &mut self,
        prepared: PreparedLqc<V, H::Digest>,
    ) -> WorkResult<V, H::Digest> {
        if !self
            .finality
            .lqc_aggregation_is_current(prepared.aggregate, prepared.generation)
        {
            // The prepared certificate can no longer commit; return the reservation to its pool
            // so aggregation re-derives instead of waiting behind a consumed completion.
            self.finality.abandon_lqc(prepared.aggregate);
            return Ok((self.pending_crypto_status(), Capabilities::None));
        }
        let Artifact::Lqc(certificate) = prepared.artifact.as_ref() else {
            unreachable!("L-QC preparation returns an L-QC")
        };
        if self.retention_floor().max(self.durable.retired_view) > certificate.view() {
            // The view aged out while aggregation was in flight, so its publication obligation
            // is already discharged and the completion cannot affect live consensus state.
            self.finality.finish_lqc(prepared.aggregate);
            return Ok((self.pending_crypto_status(), Capabilities::None));
        }

        match self.forward_before_lqc_completion(&prepared) {
            Ok(Some(step)) => {
                self.prepared_lqc = Some(prepared);
                self.scheduler.enqueue_front(WorkKey::CompleteCrypto);
                return Ok((WorkStatus::Complete, step.into_capabilities()));
            }
            Ok(None) => {}
            Err(StepError::OutboxFull | StepError::LocalArtifactReservation) => {
                self.prepared_lqc = Some(prepared);
                return Ok((WorkStatus::Blocked, Capabilities::None));
            }
            Err(error) => return Err(error),
        }

        let step = match self.complete_lqc_aggregation(&prepared) {
            Ok(step) => step,
            Err(StepError::OutboxFull | StepError::LocalArtifactReservation) => {
                self.prepared_lqc = Some(prepared);
                return Ok((WorkStatus::Blocked, Capabilities::None));
            }
            Err(error) => return Err(error),
        };
        Ok((self.pending_crypto_status(), step.into_capabilities()))
    }

    fn pending_crypto_status(&self) -> WorkStatus {
        if self.pending_crypto.is_empty() {
            WorkStatus::Complete
        } else {
            WorkStatus::Requeue
        }
    }

    fn forward_before_lqc_completion(
        &mut self,
        prepared: &PreparedLqc<V, H::Digest>,
    ) -> Result<Option<Step<V, H::Digest>>, StepError> {
        let Artifact::Lqc(certificate) = prepared.artifact.as_ref() else {
            unreachable!("L-QC preparation returns an L-QC")
        };
        let Some(change) = self.next_artifact_forwarding(Some(certificate))? else {
            return Ok(None);
        };
        self.reserve_change(change).map(Some)
    }

    fn drive_component_quantum(
        &mut self,
        component: ProtocolComponent,
        cycle: &mut ServiceCycle,
    ) -> WorkResult<V, H::Digest> {
        let before = self.durable.cursor;
        let (requeue, capabilities) = match component {
            ProtocolComponent::Finality => self.drive_finality_component(cycle)?,
            ProtocolComponent::View => self.drive_view_component(cycle)?,
            ProtocolComponent::Da => self.drive_da_component(cycle)?,
        };
        // Queued sources are serviced only through this component key, so completing the
        // quantum while any remain would strand them until an unrelated wake.
        let status = if requeue || self.durable.cursor != before {
            WorkStatus::Requeue
        } else {
            WorkStatus::Complete
        };
        Ok((status, capabilities))
    }

    fn wake_components(&mut self) {
        self.scheduler.enqueue_components();
    }

    fn restore_durable_artifacts(&mut self) -> Result<(), StepError> {
        let mut artifacts = self.durable.local.values().cloned().collect::<Vec<_>>();
        artifacts.extend(self.durable.signing_floor.iter().cloned());
        artifacts.extend(self.durable.proposal_anchor.iter().cloned());
        artifacts.extend(
            self.durable
                .forwarded_vqcs
                .values()
                .chain(self.durable.forwarded_nullifications.values())
                .cloned(),
        );
        artifacts.extend(self.durable.exits.values().cloned());
        for effect in self.durable.outbox.values() {
            match effect {
                DurableEffect::Broadcast(artifact) => artifacts.push(artifact.clone()),
                DurableEffect::BroadcastBatch(batch) => {
                    artifacts.extend(batch.iter().cloned());
                }
                DurableEffect::Propose(publication) => {
                    artifacts.push(Arc::new(Artifact::LeaderBlock(
                        publication.block().as_ref().clone(),
                    )));
                    if let Some(parent) = publication.parent().exact() {
                        artifacts.push(Arc::new(Artifact::Vqc(parent.as_ref().clone())));
                    }
                }
                DurableEffect::Send(request) => {
                    artifacts.push(Arc::clone(request.artifact()));
                }
                DurableEffect::SendBatch(requests) => {
                    artifacts.extend(requests.iter().map(SendRequest::artifact).cloned());
                }
                DurableEffect::Sign(_) | DurableEffect::SignBatch(_) => {
                    return Err(StepError::DurableTransition(
                        "signing reservation stored in publication outbox",
                    ));
                }
            }
        }
        for effect in self.durable.signing_reservations.values() {
            let requests: &[SignRequest<V, H::Digest>] = match effect {
                DurableEffect::Sign(request) => core::slice::from_ref(request),
                DurableEffect::SignBatch(requests) => requests,
                _ => {
                    return Err(StepError::DurableTransition(
                        "publication stored in signing reservations",
                    ));
                }
            };
            for request in requests {
                if let SignRequest::LeaderBlock(request) = request
                    && let Some(parent) = request.parent().exact()
                {
                    artifacts.push(Arc::new(Artifact::Vqc(parent.as_ref().clone())));
                }
            }
        }

        for artifact in artifacts {
            let id = self.validate_self_admission(&artifact)?;
            self.self_admit(artifact, id)?;
        }
        Ok(())
    }

    fn validate_self_admission(
        &mut self,
        artifact: &Artifact<V, H::Digest>,
    ) -> Result<ArtifactId<H::Digest>, StepError> {
        let encoded_len = artifact.encoded_len();
        self.validate_self_admission_shape(artifact, encoded_len)?;
        let id = artifact.id_with_scratch::<H>(&mut self.artifact_id_scratch);
        self.validate_self_admission_reservation(artifact, id)?;
        Ok(id)
    }

    fn validate_self_admission_with_metadata(
        &self,
        artifact: &Artifact<V, H::Digest>,
        id: ArtifactId<H::Digest>,
        encoded_len: usize,
    ) -> Result<(), StepError> {
        self.validate_self_admission_shape(artifact, encoded_len)?;
        self.validate_self_admission_reservation(artifact, id)
    }

    fn validate_self_admission_shape(
        &self,
        artifact: &Artifact<V, H::Digest>,
        encoded_len: usize,
    ) -> Result<(), StepError> {
        if artifact.epoch() != self.profile.protocol().epoch() {
            return Err(StepError::EffectMismatch);
        }
        if encoded_len > self.profile.resources().max_artifact_bytes() {
            return Err(StepError::LocalArtifactTooLarge);
        }
        Ok(())
    }

    fn validate_self_admission_reservation(
        &self,
        artifact: &Artifact<V, H::Digest>,
        id: ArtifactId<H::Digest>,
    ) -> Result<(), StepError> {
        if let Some(existing) = self.artifacts.get(&id) {
            return if existing.artifact.as_ref() == artifact {
                Ok(())
            } else {
                Err(StepError::EffectMismatch)
            };
        }
        if self.artifacts.len() >= self.profile.resources().max_cached_artifacts() {
            return Err(StepError::LocalArtifactReservation);
        }
        if self.next_cohort.checked_add(1).is_none() {
            return Err(StepError::IdentifierExhausted);
        }
        Ok(())
    }

    fn self_admit(
        &mut self,
        artifact: Arc<Artifact<V, H::Digest>>,
        id: ArtifactId<H::Digest>,
    ) -> Result<(), StepError> {
        if let Some(existing) = self.artifacts.get(&id) {
            return self.self_admit_at(artifact, id, existing.observation);
        }
        let cohort = self.next_cohort;
        self.next_cohort = self
            .next_cohort
            .checked_add(1)
            .expect("local admission identifier was prevalidated");
        let observation = Observation::new(cohort, 0);
        self.self_admit_at(artifact, id, observation)
    }

    fn self_admit_at(
        &mut self,
        artifact: Arc<Artifact<V, H::Digest>>,
        id: ArtifactId<H::Digest>,
        observation: Observation,
    ) -> Result<(), StepError> {
        if let Some(existing) = self.artifacts.get(&id) {
            if existing.artifact.as_ref() != artifact.as_ref() {
                return Err(StepError::EffectMismatch);
            }
            let mut release_dependency_slot = false;
            let state = {
                let existing = self.artifacts.get_mut(&id).expect("artifact exists");
                let ready = matches!(existing.state, ArtifactState::Ready);
                if observation < existing.observation {
                    existing.observation = observation;
                    if ready && self.lifecycle == Lifecycle::Live {
                        self.views
                            .observe::<H>(id, observation, &artifact, &self.profile)?;
                    }
                }
                existing.dependency_protected = true;
                if existing.dependency_slot {
                    existing.dependency_slot = false;
                    release_dependency_slot = true;
                }
                existing.state.clone()
            };
            if release_dependency_slot {
                self.dependency_slots -= 1;
            }
            let observation = self.artifacts[&id].observation;
            self.validate_finality(id, observation, &artifact)?;
            if matches!(state, ArtifactState::Ready | ArtifactState::Waiting(_)) {
                return Ok(());
            }
            return self.authenticate(id);
        }
        let future_view = artifact.view().filter(|view| *view > self.durable.view);
        let future = future_view.is_some();
        self.claim_finality(id, observation, Arc::clone(&artifact))?;
        self.validate_finality(id, observation, &artifact)?;
        let provisions = self.retain_provider_index(id, &artifact);
        self.artifacts.insert(
            id,
            ArtifactEntry {
                artifact,
                provisions,
                observation,
                state: ArtifactState::Dropped,
                dependency_protected: true,
                future,
                view_observed: false,
                dependency_slot: false,
            },
        );
        if let Some(view) = future_view {
            self.future.insert((view, id));
        }
        self.authenticate(id)
    }

    fn needs_dependency_slot(&self, artifact: &Artifact<V, H::Digest>) -> bool {
        artifact
            .dependencies()
            .iter()
            .any(|dependency| !self.available.contains(dependency))
    }

    fn retain_provider_index(
        &mut self,
        id: ArtifactId<H::Digest>,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Arc<[Dependency<H::Digest>]> {
        let provisions = Arc::<[_]>::from(artifact.provisions::<H>());
        for provision in provisions.iter().copied() {
            self.providers.entry(provision).or_default().insert(id);
        }
        provisions
    }

    fn fire_timer(&mut self, timer: Timer) -> Result<Step<V, H::Digest>, StepError> {
        let current = timer.generation() == self.durable.generation
            && timer.round() == Round::new(self.profile.protocol().epoch(), self.durable.view);
        if !current {
            return Ok(Step::new(StepStatus::StaleCompletion, Vec::new()));
        }
        self.views
            .fire_timer::<H>(&self.profile, self.durable.view, &self.chain)?;
        self.wake_components();
        Ok(Step::new(StepStatus::TimerFired, Vec::new()))
    }

    pub(crate) fn reserve_effect(
        &mut self,
        effect: DurableEffect<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        self.check_effect_capacity(&effect, 0)?;
        self.reserve_effect_prechecked(effect)
    }

    /// Stages one capacity-checked effect.
    ///
    /// Callers that consume a volatile reservation (build or vote slots) check capacity while
    /// the reservation is still outstanding, consume it, and only then stage: application runs
    /// at staging and expects the consumed slot to exist.
    fn reserve_effect_prechecked(
        &mut self,
        effect: DurableEffect<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let cursor = self
            .durable
            .cursor
            .next()
            .ok_or(StepError::IdentifierExhausted)?;
        let id = EffectId::from_cursor(cursor);
        self.reserve_change(Change::OutboxQueued {
            id,
            effect: Box::new(effect),
        })
    }

    fn check_effect_capacity(
        &self,
        effect: &DurableEffect<V, H::Digest>,
        consumed_build_credits: usize,
    ) -> Result<(), StepError> {
        self.ensure_live()?;
        if consumed_build_credits > self.chain.build_reservations() {
            return Err(StepError::LocalArtifactReservation);
        }
        if self.durable_effect_count() + self.pending_artifact_reservations()
            - consumed_build_credits
            >= self.profile.resources().max_outbox_effects()
        {
            return Err(StepError::OutboxFull);
        }
        if !effect.authorized(&self.profile) {
            return Err(StepError::UnauthorizedEffect);
        }
        let reservations = DurableState::effect_reservations(effect);
        if self.artifacts.len() + self.local_artifact_reservations() + reservations
            - consumed_build_credits
            > self.profile.resources().max_cached_artifacts()
        {
            return Err(StepError::LocalArtifactReservation);
        }
        let promised = self
            .pending_artifact_reservations()
            .checked_sub(consumed_build_credits)
            .ok_or(StepError::LocalArtifactReservation)?;
        if self
            .durable_occupancy_with_effect(effect)
            .and_then(|occupancy| occupancy.checked_add(promised))
            .is_none_or(|occupancy| occupancy > self.profile.resources().max_cached_artifacts())
        {
            return Err(StepError::LocalArtifactReservation);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn next_finality_floor_change_for_test(&self) -> Option<Change<V, H::Digest>> {
        self.next_finality_floor_change()
    }

    #[cfg(test)]
    pub(crate) fn reserve_test_effect(
        &mut self,
        effect: DurableEffect<V, H::Digest>,
    ) -> Result<Step<V, H::Digest>, StepError> {
        let mut step = self.reserve_effect(effect)?;
        step.capabilities.extend(self.emit_staged());
        Ok(step)
    }
}
