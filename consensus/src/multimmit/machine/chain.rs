//! Application-independent transaction-chain work and validation.

use super::{
    Artifact, ArtifactId, DurableEffect, EffectId, Observation, Profile, ReservationBook,
    ReservationError, Role, SignRequest,
};
use crate::{
    multimmit::types::{
        Anchor, BlockRef, ChainId, ChainProposal, Context, DaCertificate, DaVote, Extension,
        LeaderBlock, Position, SignedTransactionBlock, TransactionBlockHeader, VoteBody,
    },
    types::{Attributable, Height, Participant},
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::{ops::Bound, time::Duration};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

pub(crate) struct ChainProposalPass<V: Variant, D: Digest> {
    tip: BlockRef<D>,
    anchor: Anchor<V, D>,
    parent: BlockRef<D>,
    payloads: Vec<D>,
    attempted: usize,
    limit: usize,
}

pub(crate) enum ChainProposalProgress<V: Variant, D: Digest> {
    Pending,
    Complete(ChainProposal<V, D>),
}

#[derive(Clone, Debug)]
enum SigningSubject<V: Variant, D: Digest> {
    One(SignRequest<V, D>),
    Batch(Arc<[SignRequest<V, D>]>),
}

impl<V: Variant, D: Digest> SigningSubject<V, D> {
    fn as_slice(&self) -> &[SignRequest<V, D>] {
        match self {
            Self::One(request) => core::slice::from_ref(request),
            Self::Batch(requests) => requests,
        }
    }

    fn get(&self, index: usize) -> Option<&SignRequest<V, D>> {
        self.as_slice().get(index)
    }

    fn len(&self) -> usize {
        self.as_slice().len()
    }
}

impl<V: Variant, D: Digest> PartialEq for SigningSubject<V, D> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<V: Variant, D: Digest> Eq for SigningSubject<V, D> {}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum VoteBodyPhase {
    Proposal,
    Extension,
}

pub(crate) struct VoteBodyPass<V: Variant, D: Digest> {
    leader: LeaderBlock<V, D>,
    chain: usize,
    phase: VoteBodyPhase,
    parent: Option<BlockRef<D>>,
    proposal_index: usize,
    extension_index: usize,
    position: usize,
    extension_payloads: Vec<D>,
    positions: Vec<Position>,
    extensions: Vec<Extension<D>>,
    extension_bound: usize,
}

pub(crate) enum VoteBodyProgress<D: Digest> {
    Pending,
    Complete(VoteBody<D>),
}

/// Identifies one volatile application build request within a process generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct BuildId(u64);

impl BuildId {
    #[cfg(test)]
    pub(crate) const fn fabricate(id: u64) -> Self {
        Self(id)
    }
}

/// Exact application build request for the local producer's next block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BuildJob<D: Digest> {
    id: BuildId,
    generation: u64,
    parent: BlockRef<D>,
}

impl<D: Digest> BuildJob<D> {
    /// Returns the job identifier.
    pub const fn id(&self) -> BuildId {
        self.id
    }

    /// Returns the process generation issuing the job.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact producer parent.
    pub const fn parent(&self) -> BlockRef<D> {
        self.parent
    }
}

/// Completion of one exact application build request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct BuildCompletion<D: Digest> {
    id: BuildId,
    generation: u64,
    parent: BlockRef<D>,
    commitment: Option<D>,
}

impl<D: Digest> BuildCompletion<D> {
    /// Creates a matched build completion. `None` reports that no work was selected.
    ///
    /// A present commitment identifies a complete block selected by the attached application. The
    /// machine prepares descendants from this identity, but grants no signing authority until a
    /// matching [`CustodyCompletion`] proves the exact payload valid and durably retrievable.
    pub const fn new(
        id: BuildId,
        generation: u64,
        parent: BlockRef<D>,
        commitment: Option<D>,
    ) -> Self {
        Self {
            id,
            generation,
            parent,
            commitment,
        }
    }
}

/// Exact application custody request for one locally prepared producer block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CustodyJob<D: Digest> {
    id: BuildId,
    generation: u64,
    header: TransactionBlockHeader<D>,
}

impl<D: Digest> CustodyJob<D> {
    /// Returns the originating build identifier.
    pub const fn id(&self) -> BuildId {
        self.id
    }

    /// Returns the process generation issuing the request.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact prepared header whose body must enter custody.
    pub const fn header(&self) -> &TransactionBlockHeader<D> {
        &self.header
    }
}

/// Successful validation and durable custody of one locally prepared block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CustodyCompletion<D: Digest> {
    id: BuildId,
    generation: u64,
    header: TransactionBlockHeader<D>,
}

impl<D: Digest> CustodyCompletion<D> {
    /// Creates an exact custody completion.
    pub const fn new(
        id: BuildId,
        generation: u64,
        header: TransactionBlockHeader<D>,
    ) -> Self {
        Self {
            id,
            generation,
            header,
        }
    }
}

/// Exact cancellation of custody work for one superseded prepared block.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct CustodyCancellation {
    id: BuildId,
    generation: u64,
}

impl CustodyCancellation {
    pub(crate) const fn new(id: BuildId, generation: u64) -> Self {
        Self { id, generation }
    }

    /// Returns the originating build identifier.
    pub const fn id(self) -> BuildId {
        self.id
    }

    /// Returns the process generation issuing the cancellation.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Identifies one deterministic block-validation request.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ValidationId(u64);

impl ValidationId {
    #[cfg(test)]
    pub(crate) const fn fabricate(id: u64) -> Self {
        Self(id)
    }
}

/// Exact immutable block metadata whose payload must be validated.
#[derive(Clone, Debug)]
pub(crate) struct ValidationJob<V: Variant, D: Digest> {
    id: ValidationId,
    generation: u64,
    block: Arc<SignedTransactionBlock<V, D>>,
}

impl<V: Variant, D: Digest> ValidationJob<V, D> {
    /// Returns the job identifier.
    pub const fn id(&self) -> ValidationId {
        self.id
    }

    /// Returns the process generation issuing the job.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact authenticated block header.
    pub fn block(&self) -> &SignedTransactionBlock<V, D> {
        &self.block
    }
}

/// Deterministic application verdict for one immutable transaction block.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum BlockValidity {
    /// The payload is available and valid under the epoch's application rules.
    Valid,
    /// The available payload is invalid.
    Invalid,
}

/// Completion of one exact block-validation request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidationCompletion {
    id: ValidationId,
    generation: u64,
    validity: BlockValidity,
}

impl ValidationCompletion {
    /// Creates a validation completion.
    pub const fn new(id: ValidationId, generation: u64, validity: BlockValidity) -> Self {
        Self {
            id,
            generation,
            validity,
        }
    }
}

/// Identifies one exact data-availability recovery request.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DaRecoveryId(u64);

impl DaRecoveryId {
    /// Returns the generation-local sequence.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Exact verified shares selected for one data-availability certificate.
#[derive(Clone, Debug)]
pub(crate) struct DaRecoveryJob<V: Variant, D: Digest> {
    id: DaRecoveryId,
    generation: u64,
    votes: Arc<[DaVote<V, D>]>,
}

impl<V: Variant, D: Digest> DaRecoveryJob<V, D> {
    /// Returns the job identifier.
    pub const fn id(&self) -> DaRecoveryId {
        self.id
    }

    /// Returns the process generation issuing the job.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact canonical signer subset in participant order.
    pub fn votes(&self) -> &[DaVote<V, D>] {
        &self.votes
    }
}

/// Completion of one exact data-availability recovery request.
#[derive(Clone, Debug)]
pub(crate) struct DaRecoveryCompletion<V: Variant, D: Digest> {
    id: DaRecoveryId,
    generation: u64,
    certificate: DaCertificate<V, D>,
}

impl<V: Variant, D: Digest> DaRecoveryCompletion<V, D> {
    /// Creates a matched recovery completion.
    pub const fn new(id: DaRecoveryId, generation: u64, certificate: DaCertificate<V, D>) -> Self {
        Self {
            id,
            generation,
            certificate,
        }
    }

    /// Returns the completed job identifier.
    pub const fn id(&self) -> DaRecoveryId {
        self.id
    }
}

/// A production deadline bound to one exact local parent.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProductionTimer<D: Digest> {
    generation: u64,
    parent: BlockRef<D>,
    delay: Duration,
}

impl<D: Digest> ProductionTimer<D> {
    /// Returns the process generation owning this deadline.
    #[cfg(test)]
    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the parent from which elapsed production time is measured.
    pub const fn parent(self) -> BlockRef<D> {
        self.parent
    }

    /// Returns the logical delay requested from the runtime.
    pub const fn delay(self) -> Duration {
        self.delay
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ChainEffect<V: Variant, D: Digest> {
    Build(BuildJob<D>),
    Custody(CustodyJob<D>),
    CancelCustody(CustodyCancellation),
    Validate(ValidationJob<V, D>),
    CancelValidations { chain: ChainId, through: Height },
    ArmTimer(ProductionTimer<D>),
    Recover(DaRecoveryJob<V, D>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum BlockValidationOutcome<D: Digest> {
    Stale,
    Retained,
    Invalid(ArtifactId<D>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ValidationState {
    Authenticating,
    Ready,
    Pending(ValidationId),
    Valid,
}

#[derive(Copy, Clone, Debug)]
struct ValidationLimits {
    items: usize,
    items_per_chain: usize,
    bytes: usize,
    bytes_per_chain: usize,
}

#[derive(Clone, Debug)]
struct ValidationReservations {
    items: usize,
    bytes: usize,
    chain_items: Vec<usize>,
    chain_bytes: Vec<usize>,
}

#[derive(Clone, Debug)]
struct BlockRecord<V: Variant, D: Digest> {
    artifact: ArtifactId<D>,
    observation: Observation,
    block: Arc<SignedTransactionBlock<V, D>>,
    state: ValidationState,
}

#[derive(Copy, Clone, Debug)]
struct ValidationRecord<D: Digest> {
    chain: ChainId,
    height: Height,
    artifact: ArtifactId<D>,
    bytes: usize,
}

#[derive(Clone, Debug)]
struct PreparedBuild<D: Digest> {
    id: BuildId,
    generation: u64,
    header: TransactionBlockHeader<D>,
    state: PreparedState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedState {
    AwaitingCustody,
    Custodied,
    Reserved,
}

#[derive(Clone, Debug)]
struct VotePool<V: Variant, D: Digest> {
    header: TransactionBlockHeader<D>,
    shares: BTreeMap<Participant, Arc<DaVote<V, D>>>,
}

#[derive(Clone, Debug)]
struct Certified<V: Variant, D: Digest> {
    block: BlockRef<D>,
    certificate: Option<DaCertificate<V, D>>,
}

#[derive(Clone, Debug)]
struct CertificateCandidate<V: Variant, D: Digest> {
    artifact: ArtifactId<D>,
    observation: Observation,
    certificate: DaCertificate<V, D>,
    ready: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProducerStatus {
    pub chain: ChainId,
    pub produced: Height,
    pub certified: Height,
    pub vote_shares: usize,
    pub da_quorum: usize,
    pub pipeline_depth: u64,
    pub prepared: usize,
    pub pipeline_blocked: bool,
    pub ready_recovery: bool,
    pub pending_recovery: bool,
    pub active_recovery: bool,
    pub wake: bool,
    pub timer_armed: bool,
    pub build_pending: bool,
    pub production_credit: bool,
}

pub(crate) enum BuildOutcome {
    Stale,
    Superseded,
    Empty,
    Prepared,
}

/// Volatile, rebuildable chain indexes owned by the deterministic machine.
pub(crate) struct ChainState<V: Variant, D: Digest> {
    own_chain: Option<ChainId>,
    da_quorum: usize,
    pipeline_depth: u64,
    genesis: Vec<BlockRef<D>>,
    produced: Option<BlockRef<D>>,
    producer_headers: BTreeMap<Height, TransactionBlockHeader<D>>,
    local_da_votes: Vec<BTreeMap<Height, TransactionBlockHeader<D>>>,
    da_safe_through: Vec<Height>,
    data_retired_through: Vec<Height>,
    pending_da_votes: Vec<Option<TransactionBlockHeader<D>>>,
    next_da_chain: usize,
    certified: Vec<BTreeMap<Height, Certified<V, D>>>,
    vote_pools: BTreeMap<D, VotePool<V, D>>,
    ready_recoveries: BTreeSet<BlockRef<D>>,
    recovery_jobs: BTreeMap<DaRecoveryId, DaRecoveryJob<V, D>>,
    pending_recoveries: BTreeSet<BlockRef<D>>,
    certificate_candidates: BTreeMap<BlockRef<D>, Vec<CertificateCandidate<V, D>>>,
    discarded_certificates: Vec<ArtifactId<D>>,
    ancestry: BTreeMap<BlockRef<D>, BlockRef<D>>,
    blocks: Vec<BTreeMap<Height, Vec<BlockRecord<V, D>>>>,
    validation_jobs: BTreeMap<ValidationId, ValidationRecord<D>>,
    validation_limits: ValidationLimits,
    validation_reservations: ValidationReservations,
    next_validation_chain: usize,
    next_job: u64,
    producer_wake: bool,
    deadline: Option<ProductionTimer<D>>,
    pending_build: Option<BuildJob<D>>,
    prepared: VecDeque<PreparedBuild<D>>,
    cancelling_custody: BTreeMap<BuildId, u64>,
    signing: ReservationBook<SigningSubject<V, D>>,
    production_credit: bool,
    capabilities: Vec<ChainEffect<V, D>>,
    processed: BTreeSet<ArtifactId<D>>,
}

impl<V: Variant, D: Digest> ChainState<V, D> {
    pub(crate) fn new<H: Hasher<Digest = D>>(profile: &Profile<H, V>) -> Self {
        let genesis = profile.protocol().genesis().tips().to_vec();
        let own_chain = match profile.role() {
            Role::Validator(participant) => profile.protocol().producer_chain(participant),
            Role::Observer => None,
        };
        let produced = own_chain.and_then(|chain| genesis.get(chain.get() as usize).copied());
        let certified = genesis
            .iter()
            .map(|block| {
                BTreeMap::from([(
                    block.height(),
                    Certified {
                        block: *block,
                        certificate: None,
                    },
                )])
            })
            .collect();
        let chains = genesis.len();
        let blocks = (0..chains).map(|_| BTreeMap::new()).collect();
        let pipeline_depth = profile.protocol().codec_config().pipeline_depth() as u64;
        let local_da_votes = (0..genesis.len()).map(|_| BTreeMap::new()).collect();
        let da_safe_through = genesis.iter().map(BlockRef::height).collect();
        let data_retired_through = genesis.iter().map(BlockRef::height).collect();
        let resources = profile.resources();
        let validation_limits = ValidationLimits {
            items: resources.max_cached_artifacts(),
            items_per_chain: profile.validation_parallelism(),
            bytes: resources
                .max_cached_artifacts()
                .saturating_mul(resources.max_artifact_bytes()),
            bytes_per_chain: profile
                .validation_parallelism()
                .saturating_mul(resources.max_artifact_bytes()),
        };
        let validation_reservations = ValidationReservations {
            items: 0,
            bytes: 0,
            chain_items: vec![0; chains],
            chain_bytes: vec![0; chains],
        };
        Self {
            own_chain,
            da_quorum: profile.protocol().codec_config().da_quorum(),
            pipeline_depth,
            genesis,
            produced,
            producer_headers: BTreeMap::new(),
            local_da_votes,
            da_safe_through,
            data_retired_through,
            pending_da_votes: vec![None; chains],
            next_da_chain: 0,
            certified,
            vote_pools: BTreeMap::new(),
            ready_recoveries: BTreeSet::new(),
            recovery_jobs: BTreeMap::new(),
            pending_recoveries: BTreeSet::new(),
            certificate_candidates: BTreeMap::new(),
            discarded_certificates: Vec::new(),
            ancestry: BTreeMap::new(),
            blocks,
            validation_jobs: BTreeMap::new(),
            validation_limits,
            validation_reservations,
            next_validation_chain: 0,
            next_job: 0,
            producer_wake: false,
            deadline: None,
            pending_build: None,
            prepared: VecDeque::new(),
            cancelling_custody: BTreeMap::new(),
            signing: ReservationBook::new(resources.max_outbox_effects()),
            production_credit: false,
            capabilities: Vec::new(),
            processed: BTreeSet::new(),
        }
    }

    /// Installs producer-chain certificates carried by an admitted leader block.
    pub(crate) fn install_verified_anchors<H: Hasher<Digest = D>>(
        &mut self,
        anchors: impl IntoIterator<Item = DaCertificate<V, D>>,
    ) -> Result<(), ChainError> {
        for certificate in anchors {
            let block = certificate.block_ref::<H>();
            let Some(chain) = self.certified.get(block.chain().get() as usize) else {
                return Err(ChainError::Context);
            };
            if let Some((height, certified)) = chain.last_key_value() {
                if *height > block.height() {
                    continue;
                }
                if *height == block.height() && certified.block == block {
                    continue;
                }
            }
            self.install_certificate::<H>(block, certificate)?;
        }
        Ok(())
    }

    fn signing_subject(effect: &DurableEffect<V, D>) -> Option<SigningSubject<V, D>> {
        match effect {
            DurableEffect::Sign(request @ SignRequest::TransactionBlock(_))
            | DurableEffect::Sign(request @ SignRequest::DaVote(_)) => {
                Some(SigningSubject::One(request.clone()))
            }
            DurableEffect::SignBatch(requests)
                if requests
                    .iter()
                    .all(|request| matches!(request, SignRequest::DaVote(_))) =>
            {
                Some(SigningSubject::Batch(Arc::clone(requests)))
            }
            _ => None,
        }
    }

    /// Reserves the exact durable DA signing subject represented by a signing-reservation row.
    pub(crate) fn reserve_signing(
        &mut self,
        id: EffectId,
        effect: &DurableEffect<V, D>,
    ) -> Result<(), ChainError> {
        let Some(subject) = Self::signing_subject(effect) else {
            return Ok(());
        };
        self.signing
            .reserve(id.get(), subject)
            .map_err(ChainError::Reservation)
    }

    /// Issues a volatile capability without changing the exact durable subject.
    pub(crate) fn issue_signing(
        &mut self,
        id: EffectId,
        generation: u64,
        effect: &DurableEffect<V, D>,
    ) -> Result<(), ChainError> {
        if Self::signing_subject(effect).is_none() {
            return Ok(());
        }
        self.signing
            .issue(id.get(), generation)
            .map_err(ChainError::Reservation)
    }

    pub(crate) fn signing_issued(
        &self,
        id: EffectId,
        generation: u64,
        effect: &DurableEffect<V, D>,
    ) -> bool {
        let Some(subject) = Self::signing_subject(effect) else {
            return true;
        };
        self.signing.is_issued(id.get(), generation, &subject)
    }

    pub(crate) fn issued_signing_request(
        &self,
        id: EffectId,
        generation: u64,
        index: usize,
    ) -> Option<&SignRequest<V, D>> {
        self.signing
            .issued_subject(id.get(), generation)?
            .get(index)
    }

    pub(crate) fn issued_signing_batch_len(&self, id: EffectId, generation: u64) -> Option<usize> {
        Some(self.signing.issued_subject(id.get(), generation)?.len())
    }

    /// Completes the active slot, or consumes the exact reserved subject during replay.
    pub(crate) fn complete_signing(
        &mut self,
        id: EffectId,
        generation: u64,
        effect: &DurableEffect<V, D>,
        replay: bool,
    ) -> Result<(), ChainError> {
        let Some(subject) = Self::signing_subject(effect) else {
            return Ok(());
        };
        let result = if replay {
            self.signing.replay_complete(id.get(), &subject)
        } else {
            self.signing.complete(id.get(), generation, &subject)
        };
        result.map_err(ChainError::Reservation)
    }

    /// Restores the durable DA state used to bound each chain's live suffix.
    pub(crate) fn restore_da_state(
        &mut self,
        tips: &[BlockRef<D>],
        safe: &[Height],
    ) -> Result<(), ChainError> {
        if tips.len() != self.genesis.len() || safe.len() != self.genesis.len() {
            return Err(ChainError::Context);
        }
        for (index, tip) in tips.iter().copied().enumerate() {
            let applied = self.genesis[index];
            if tip.chain() != applied.chain()
                || tip.height() < applied.height()
                || tip.height() == applied.height() && tip != applied
                || safe[index] < applied.height()
            {
                return Err(ChainError::Context);
            }
            self.da_safe_through[index] = safe[index];
            self.data_retired_through[index] = tip.height();
            if tip != applied {
                self.certified[index].insert(
                    tip.height(),
                    Certified {
                        block: tip,
                        certificate: None,
                    },
                );
            }
        }
        Ok(())
    }

    /// Prunes chain work made obsolete by a durably recorded DA certificate.
    pub(crate) fn compact_certified<H: Hasher<Digest = D>>(
        &mut self,
        certificate: &DaCertificate<V, D>,
        retired: Height,
    ) -> Result<(), ChainError> {
        let block = certificate.block_ref::<H>();
        let index = block.chain().get() as usize;
        let applied = *self
            .data_retired_through
            .get(index)
            .ok_or(ChainError::Context)?;
        if retired < applied || retired > block.height() {
            return Err(ChainError::Context);
        }

        self.install_certificate::<H>(block, certificate.clone())?;
        let retired_validations = self
            .validation_jobs
            .iter()
            .filter_map(|(id, job)| {
                (job.chain == block.chain() && job.height <= retired).then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in &retired_validations {
            let job = self
                .validation_jobs
                .remove(id)
                .expect("selected validation job remains retained");
            self.release_validation(job)?;
        }
        if !retired_validations.is_empty() {
            self.capabilities.push(ChainEffect::CancelValidations {
                chain: block.chain(),
                through: retired,
            });
        }
        self.certified[index].retain(|height, certified| {
            *height == self.genesis[index].height() || *height > retired || certified.block == block
        });

        let mut removed = Vec::new();
        self.blocks[index].retain(|height, records| {
            if *height > retired {
                return true;
            }
            removed.extend(records.iter().map(|record| record.artifact));
            false
        });
        for artifact in removed {
            self.processed.remove(&artifact);
        }
        self.local_da_votes[index].retain(|height, _| *height > retired);
        self.vote_pools.retain(|_, pool| {
            let candidate = pool.header.block_ref::<H>();
            candidate.chain() != block.chain() || candidate.height() > block.height()
        });
        self.ready_recoveries.retain(|candidate| {
            candidate.chain() != block.chain() || candidate.height() > block.height()
        });
        self.pending_recoveries.retain(|candidate| {
            candidate.chain() != block.chain() || candidate.height() > block.height()
        });
        self.recovery_jobs.retain(|_, job| {
            job.votes.first().is_none_or(|vote| {
                let candidate = vote.header().block_ref::<H>();
                candidate.chain() != block.chain() || candidate.height() > block.height()
            })
        });
        self.certificate_candidates.retain(|candidate, _| {
            candidate.chain() != block.chain() || candidate.height() > retired
        });
        self.ancestry
            .retain(|child, _| child.chain() != block.chain() || child.height() > retired);
        if self.pending_da_votes[block.chain().get() as usize]
            .as_ref()
            .is_some_and(|header| header.height() <= retired)
        {
            self.pending_da_votes[block.chain().get() as usize] = None;
        }
        if self.own_chain == Some(block.chain()) {
            self.producer_headers
                .retain(|height, _| *height > block.height());
            let produced = self.produced.ok_or(ChainError::ProducerConflict)?;
            if produced.height() <= block.height() {
                self.advance_produced::<H>(block);
            }
        }
        // A durable certificate is a new base for the paper's DA-voting rule. Lower choices can no
        // longer add availability, so retiring them keeps the exact local suffix pipeline-bounded.
        self.da_safe_through[index] = self.da_safe_through[index].max(block.height());
        self.data_retired_through[index] = retired;
        Ok(())
    }

    /// Returns the greatest locally usable and DA-certified height on every chain.
    pub(crate) fn tip_heights(&self) -> Vec<(Height, Height)> {
        self.genesis
            .iter()
            .enumerate()
            .map(|(index, floor)| {
                let certified = self.certified[index]
                    .iter()
                    .rev()
                    .find(|(_, certified)| certified.certificate.is_some())
                    .map_or(Height::zero(), |(height, _)| *height);

                let locally_valid = self.blocks[index]
                    .iter()
                    .rev()
                    .find(|(_, records)| {
                        records
                            .iter()
                            .any(|record| record.state == ValidationState::Valid)
                    })
                    .map(|(height, _)| *height);
                let da_voted = self.local_da_votes[index]
                    .last_key_value()
                    .map(|(height, _)| *height);
                let produced = self
                    .produced
                    .filter(|tip| tip.chain().get() as usize == index)
                    .map(|tip| tip.height());
                let known = [
                    Some(floor.height()),
                    Some(certified),
                    locally_valid,
                    da_voted,
                    produced,
                ]
                .into_iter()
                .flatten()
                .max()
                .expect("every chain has a floor");

                (known, certified)
            })
            .collect()
    }

    pub(crate) fn producer_status<H: Hasher<Digest = D>>(&self) -> Option<ProducerStatus> {
        let chain = self.own_chain?;
        let produced = self.produced?;
        let certified = self.certified[chain.get() as usize]
            .iter()
            .rev()
            .find(|(_, certified)| certified.certificate.is_some())
            .map_or(Height::zero(), |(height, _)| *height);
        let vote_shares = self
            .producer_headers
            .get(&produced.height())
            .filter(|header| header.block_ref::<H>() == produced)
            .and_then(|header| self.vote_pools.get(&header.digest::<H>()))
            .map_or(0, |pool| pool.shares.len());
        let active_recovery = self.recovery_jobs.values().any(|job| {
            job.votes
                .first()
                .is_some_and(|vote| vote.header().block_ref::<H>() == produced)
        });

        Some(ProducerStatus {
            chain,
            produced: produced.height(),
            certified,
            vote_shares,
            da_quorum: self.da_quorum,
            pipeline_depth: self.pipeline_depth,
            prepared: self.prepared.len(),
            pipeline_blocked: self
                .planned_tip::<H>()
                .is_some_and(|tip| {
                    tip.height().get().saturating_sub(certified.get()) >= self.pipeline_depth
                }),
            ready_recovery: self.ready_recoveries.contains(&produced),
            pending_recovery: self.pending_recoveries.contains(&produced),
            active_recovery,
            wake: self.producer_wake,
            timer_armed: self.deadline.is_some(),
            build_pending: self.pending_build.is_some(),
            production_credit: self.production_credit,
        })
    }

    pub(crate) fn next_certificate_above(
        &self,
        floors: &[BlockRef<D>],
    ) -> Option<DaCertificate<V, D>> {
        self.certified
            .iter()
            .zip(floors)
            .find_map(|(certificates, floor)| {
                certificates.iter().rev().find_map(|(height, certified)| {
                    (*height > floor.height())
                        .then(|| certified.certificate.clone())
                        .flatten()
                })
            })
    }

    pub(crate) fn observe<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Artifact<V, D>,
        generation: u64,
    ) -> Result<(), ChainError> {
        let block = match artifact {
            Artifact::TransactionBlock(block) => Some(block.header().block_ref::<H>()),
            Artifact::DaVote(vote) => Some(vote.header().block_ref::<H>()),
            Artifact::DaCertificate(certificate) => Some(certificate.block_ref::<H>()),
            _ => None,
        };
        if block.is_some_and(|block| {
            self.genesis
                .get(block.chain().get() as usize)
                .is_some_and(|genesis| block.height() <= genesis.height())
        }) {
            return Ok(());
        }
        if matches!(artifact, Artifact::TransactionBlock(_)) && self.processed.contains(&id) {
            return Ok(());
        }
        match artifact {
            Artifact::TransactionBlock(block) => {
                let locally_custodied = self.is_producer_header(block.header());
                let state = if locally_custodied {
                    ValidationState::Valid
                } else {
                    ValidationState::Ready
                };
                let chain = block.header().chain();
                let records = self
                    .blocks
                    .get_mut(chain.get() as usize)
                    .ok_or(ChainError::Context)?;
                let block = Arc::new(block.clone());
                let records = records.entry(block.header().height()).or_default();
                if let Some(record) = records.iter_mut().find(|record| record.artifact == id) {
                    if record.block.as_ref() != block.as_ref()
                        || record.state != ValidationState::Authenticating
                    {
                        return Err(ChainError::Context);
                    }
                    record.state = state;
                } else {
                    let index = records.partition_point(|record| record.observation < observation);
                    records.insert(
                        index,
                        BlockRecord {
                            artifact: id,
                            observation,
                            block: Arc::clone(&block),
                            state,
                        },
                    );
                }
                if !locally_custodied {
                    self.schedule_ready_validations::<H>(generation)?;
                }
            }
            Artifact::DaVote(vote) => self.observe_da_vote::<H>(vote)?,
            Artifact::DaCertificate(certificate) => {
                if !self.record_header::<H>(certificate.header())? {
                    return Err(ChainError::CertifiedConflict);
                }
                self.observe_certificate::<H>(id, observation, certificate)?;
            }
            _ => return Ok(()),
        }
        if matches!(artifact, Artifact::TransactionBlock(_)) {
            self.processed.insert(id);
        }
        Ok(())
    }

    pub(crate) fn register_transaction_block(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        block: &SignedTransactionBlock<V, D>,
    ) -> Result<(), ChainError> {
        let records = self
            .blocks
            .get_mut(block.header().chain().get() as usize)
            .ok_or(ChainError::Context)?
            .entry(block.header().height())
            .or_default();
        if records.iter().any(|record| record.artifact == id) {
            return Ok(());
        }
        let index = records.partition_point(|record| record.observation < observation);
        records.insert(
            index,
            BlockRecord {
                artifact: id,
                observation,
                block: Arc::new(block.clone()),
                state: ValidationState::Authenticating,
            },
        );
        Ok(())
    }

    pub(crate) fn claim_da_certificate<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        certificate: &DaCertificate<V, D>,
    ) -> Result<bool, ChainError> {
        let block = certificate.block_ref::<H>();
        if block.chain().get() as usize >= self.certified.len() {
            return Err(ChainError::Context);
        }
        let certified = &self.certified[block.chain().get() as usize];
        if certified
            .last_key_value()
            .is_some_and(|(height, _)| *height > block.height())
            || certified.get(&block.height()).is_some_and(|certified| {
                certified.block == block && certified.certificate.is_some()
            })
        {
            return Ok(false);
        }
        let candidates = self.certificate_candidates.entry(block).or_default();
        let index = candidates.partition_point(|candidate| candidate.observation < observation);
        candidates.insert(
            index,
            CertificateCandidate {
                artifact: id,
                observation,
                certificate: certificate.clone(),
                ready: false,
            },
        );
        Ok(true)
    }

    pub(crate) fn reject_unverified<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        artifact: &Artifact<V, D>,
    ) -> Result<(), ChainError> {
        match artifact {
            Artifact::TransactionBlock(block) => {
                let blocks = self
                    .blocks
                    .get_mut(block.header().chain().get() as usize)
                    .ok_or(ChainError::Context)?;
                let records = blocks
                    .get_mut(&block.header().height())
                    .ok_or(ChainError::Context)?;
                let index = records
                    .iter()
                    .position(|record| record.artifact == id)
                    .ok_or(ChainError::Context)?;
                if records[index].state != ValidationState::Authenticating {
                    return Err(ChainError::Context);
                }
                records.remove(index);
                if records.is_empty() {
                    blocks.remove(&block.header().height());
                }
                self.processed.remove(&id);
            }
            Artifact::DaCertificate(certificate) => {
                let block = certificate.block_ref::<H>();
                if let Some(candidates) = self.certificate_candidates.get_mut(&block) {
                    candidates.retain(|candidate| candidate.artifact != id);
                    if candidates.is_empty() {
                        self.certificate_candidates.remove(&block);
                    }
                }
                self.promote_certificate::<H>(block)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn observe_da_vote<H: Hasher<Digest = D>>(
        &mut self,
        vote: &DaVote<V, D>,
    ) -> Result<(), ChainError> {
        let block = vote.header().block_ref::<H>();
        let header = vote.header().digest::<H>();
        let pool = self.vote_pools.entry(header).or_insert_with(|| VotePool {
            header: vote.header().clone(),
            shares: BTreeMap::new(),
        });
        debug_assert_eq!(pool.header, *vote.header());
        pool.shares
            .entry(vote.signer())
            .or_insert_with(|| Arc::new(vote.clone()));
        self.refresh_recovery::<H>(block);
        Ok(())
    }

    fn observe_certificate<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        certificate: &DaCertificate<V, D>,
    ) -> Result<(), ChainError> {
        let block = certificate.block_ref::<H>();
        let certified = &self.certified[block.chain().get() as usize];
        if certified
            .last_key_value()
            .is_some_and(|(height, _)| *height > block.height())
            || certified.get(&block.height()).is_some_and(|certified| {
                certified.block == block && certified.certificate.is_some()
            })
        {
            return Ok(());
        }
        let candidates = self.certificate_candidates.entry(block).or_default();
        if let Some(candidate) = candidates
            .iter_mut()
            .find(|candidate| candidate.artifact == id)
        {
            candidate.ready = true;
        } else {
            let index = candidates.partition_point(|candidate| candidate.observation < observation);
            candidates.insert(
                index,
                CertificateCandidate {
                    artifact: id,
                    observation,
                    certificate: certificate.clone(),
                    ready: true,
                },
            );
        }
        self.promote_certificate::<H>(block)
    }

    fn promote_certificate<H: Hasher<Digest = D>>(
        &mut self,
        block: BlockRef<D>,
    ) -> Result<(), ChainError> {
        let Some(candidates) = self.certificate_candidates.get(&block) else {
            return Ok(());
        };
        let Some(first) = candidates.first() else {
            self.certificate_candidates.remove(&block);
            return Ok(());
        };
        if !first.ready {
            return Ok(());
        }
        let certificate = first.certificate.clone();
        let selected = first.artifact;
        let candidates = self
            .certificate_candidates
            .remove(&block)
            .expect("certificate candidates were just inspected");
        for candidate in candidates {
            if candidate.artifact == selected {
                continue;
            }
            self.processed.remove(&candidate.artifact);
            self.discarded_certificates.push(candidate.artifact);
        }

        self.install_certificate::<H>(block, certificate)
    }

    fn install_certificate<H: Hasher<Digest = D>>(
        &mut self,
        block: BlockRef<D>,
        certificate: DaCertificate<V, D>,
    ) -> Result<(), ChainError> {
        let chain = self
            .certified
            .get_mut(block.chain().get() as usize)
            .ok_or(ChainError::Context)?;
        match chain.entry(block.height()) {
            std::collections::btree_map::Entry::Occupied(existing)
                if existing.get().block != block =>
            {
                return Err(ChainError::CertifiedConflict);
            }
            std::collections::btree_map::Entry::Occupied(mut existing) => {
                existing.get_mut().certificate = Some(certificate);
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Certified {
                    block,
                    certificate: Some(certificate),
                });
            }
        }
        self.pending_recoveries.remove(&block);
        self.ready_recoveries.remove(&block);
        self.recovery_jobs.retain(|_, job| {
            job.votes
                .first()
                .is_none_or(|vote| vote.header().block_ref::<H>() != block)
        });
        Ok(())
    }

    pub(crate) fn take_discarded_certificates(&mut self) -> Vec<ArtifactId<D>> {
        self.discarded_certificates.drain(..).collect()
    }

    /// Latches one coalescible opportunity for the producer to build.
    pub(crate) const fn wake_producer(&mut self) {
        self.producer_wake = true;
    }

    pub(crate) fn complete_build<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        completion: BuildCompletion<D>,
    ) -> Result<BuildOutcome, ChainError> {
        let Some(pending) = self.pending_build.as_ref() else {
            return Ok(BuildOutcome::Stale);
        };
        if completion.generation != pending.generation
            || completion.id != pending.id
            || completion.parent != pending.parent
        {
            return Ok(BuildOutcome::Stale);
        }
        if self.planned_tip::<H>() != Some(pending.parent) {
            self.pending_build = None;
            return Ok(BuildOutcome::Superseded);
        }
        let Some(commitment) = completion.commitment else {
            let timer = ProductionTimer {
                generation: pending.generation,
                parent: pending.parent,
                delay: profile.timers().production_interval(),
            };
            self.pending_build = None;
            self.producer_wake = false;
            self.deadline = Some(timer);
            self.capabilities.push(ChainEffect::ArmTimer(timer));
            return Ok(BuildOutcome::Empty);
        };

        let job = self
            .pending_build
            .take()
            .expect("the matched build remains pending");
        let height = job
            .parent
            .height()
            .get()
            .checked_add(1)
            .ok_or(ChainError::HeightOverflow)?;
        let header = TransactionBlockHeader::new(
            profile.protocol().epoch(),
            job.parent.chain(),
            Height::new(height),
            job.parent.digest(),
            commitment,
        )
        .map_err(|_| ChainError::HeightOverflow)?;
        self.prepared.push_back(PreparedBuild {
            id: job.id,
            generation: job.generation,
            header: header.clone(),
            state: PreparedState::AwaitingCustody,
        });
        self.producer_wake = true;
        self.capabilities.push(ChainEffect::Custody(CustodyJob {
            id: job.id,
            generation: job.generation,
            header,
        }));
        Ok(BuildOutcome::Prepared)
    }

    /// Accepts custody only for the exact prepared block that requested it.
    pub(crate) fn complete_custody(
        &mut self,
        completion: CustodyCompletion<D>,
    ) -> Result<bool, ChainError> {
        let Some(prepared) = self
            .prepared
            .iter_mut()
            .find(|prepared| {
                prepared.id == completion.id && prepared.generation == completion.generation
            })
        else {
            return Ok(false);
        };
        if prepared.header != completion.header {
            return Err(ChainError::CompletionMismatch);
        }
        match prepared.state {
            PreparedState::AwaitingCustody => prepared.state = PreparedState::Custodied,
            PreparedState::Custodied | PreparedState::Reserved => return Ok(false),
        }
        Ok(true)
    }

    /// Reconciles one runtime custody cancellation before replacement production resumes.
    pub(crate) fn complete_custody_cancellation(
        &mut self,
        cancellation: CustodyCancellation,
        generation: u64,
    ) -> Result<bool, ChainError> {
        if cancellation.generation != generation {
            return Ok(false);
        }
        let Some(pending_generation) = self.cancelling_custody.remove(&cancellation.id) else {
            return Ok(false);
        };
        if pending_generation != cancellation.generation {
            return Err(ChainError::CompletionMismatch);
        }
        self.producer_wake = true;
        Ok(true)
    }

    /// Returns the oldest custodied producer header not yet reserved for signing.
    pub(crate) fn pending_build_sign_request(&self) -> Option<SignRequest<V, D>> {
        self.prepared
            .front()
            .filter(|prepared| prepared.state == PreparedState::Custodied)
            .map(|prepared| SignRequest::TransactionBlock(prepared.header.clone()))
    }

    pub(crate) fn mark_build_reserved(&mut self) {
        let prepared = self
            .prepared
            .front_mut()
            .expect("a custodied build must remain prepared until signing is reserved");
        debug_assert_eq!(prepared.state, PreparedState::Custodied);
        prepared.state = PreparedState::Reserved;
    }

    pub(crate) fn build_reservations(&self) -> usize {
        usize::from(self.pending_build.is_some())
            + self
                .prepared
                .iter()
                .filter(|prepared| prepared.state != PreparedState::Reserved)
                .count()
    }

    pub(crate) fn complete_validation<H: Hasher<Digest = D>>(
        &mut self,
        completion: ValidationCompletion,
        generation: u64,
    ) -> Result<BlockValidationOutcome<D>, ChainError> {
        if completion.generation != generation {
            return Ok(BlockValidationOutcome::Stale);
        }
        let Some(job) = self.validation_jobs.remove(&completion.id) else {
            return Ok(BlockValidationOutcome::Stale);
        };
        self.release_validation(job)?;
        let Some(blocks) = self.blocks.get_mut(job.chain.get() as usize) else {
            return Err(ChainError::Context);
        };
        let Some(records) = blocks.get_mut(&job.height) else {
            self.schedule_ready_validations::<H>(generation)?;
            return Ok(BlockValidationOutcome::Stale);
        };
        let Some(index) = records
            .iter()
            .position(|record| record.artifact == job.artifact)
        else {
            self.schedule_ready_validations::<H>(generation)?;
            return Ok(BlockValidationOutcome::Stale);
        };
        if records[index].state != ValidationState::Pending(completion.id) {
            self.schedule_ready_validations::<H>(generation)?;
            return Ok(BlockValidationOutcome::Stale);
        }
        let header = records[index].block.header().clone();
        if completion.validity == BlockValidity::Invalid || !self.record_header::<H>(&header)? {
            self.discard_validation::<H>(job, generation)?;
            return Ok(BlockValidationOutcome::Invalid(job.artifact));
        }
        let record = self
            .blocks
            .get_mut(job.chain.get() as usize)
            .and_then(|blocks| blocks.get_mut(&job.height))
            .and_then(|records| {
                records
                    .iter_mut()
                    .find(|record| record.artifact == job.artifact)
            })
            .ok_or(ChainError::Context)?;
        if record.state != ValidationState::Pending(completion.id) {
            return Err(ChainError::Context);
        }
        record.state = ValidationState::Valid;
        self.schedule_ready_validations::<H>(generation)?;
        Ok(BlockValidationOutcome::Retained)
    }

    fn discard_validation<H: Hasher<Digest = D>>(
        &mut self,
        job: ValidationRecord<D>,
        generation: u64,
    ) -> Result<(), ChainError> {
        let blocks = self
            .blocks
            .get_mut(job.chain.get() as usize)
            .ok_or(ChainError::Context)?;
        let records = blocks.get_mut(&job.height).ok_or(ChainError::Context)?;
        let index = records
            .iter()
            .position(|record| record.artifact == job.artifact)
            .ok_or(ChainError::Context)?;
        records.remove(index);
        if records.is_empty() {
            blocks.remove(&job.height);
        }
        self.processed.remove(&job.artifact);
        self.schedule_ready_validations::<H>(generation)?;
        Ok(())
    }

    /// Fills the bounded application pipeline with parent-anchored validation jobs.
    ///
    /// A candidate is dispatched only after its exact parent is certified or has entered the
    /// application pipeline. This lets dependent requests overlap without allowing descendants
    /// that arrive first to occupy every slot needed to execute their missing parent.
    ///
    /// Saturated producers retain their authenticated block in the existing artifact-cache slot.
    /// The rotating cursor continues across other chains, so one producer cannot turn local
    /// application pressure into a fatal error or global validation head-of-line blocking.
    fn schedule_ready_validations<H: Hasher<Digest = D>>(
        &mut self,
        generation: u64,
    ) -> Result<(), ChainError> {
        loop {
            if self.validation_reservations.items >= self.validation_limits.items {
                return Ok(());
            }

            let mut scheduled = false;
            for offset in 0..self.blocks.len() {
                let chain_index = (self.next_validation_chain + offset) % self.blocks.len();
                let chain = ChainId::new(chain_index as u32);
                if self.validation_reservations.chain_items[chain_index]
                    >= self.validation_limits.items_per_chain
                {
                    continue;
                }

                let candidate = self.blocks[chain_index]
                    .iter()
                    .find_map(|(height, records)| {
                        records
                            .iter()
                            .enumerate()
                            .find(|(_, record)| {
                                record.state == ValidationState::Ready
                                    && self.validation_parent_available::<H>(
                                        chain_index,
                                        record.block.header(),
                                    )
                            })
                            .map(|(index, record)| (*height, index, record.artifact))
                    });
                let Some((height, record_index, artifact)) = candidate else {
                    continue;
                };
                let block = Arc::clone(&self.blocks[chain_index][&height][record_index].block);
                let block_bytes = block.encode_size();
                if self
                    .validation_reservations
                    .bytes
                    .checked_add(block_bytes)
                    .is_none_or(|bytes| bytes > self.validation_limits.bytes)
                    || self.validation_reservations.chain_bytes[chain_index]
                        .checked_add(block_bytes)
                        .is_none_or(|bytes| bytes > self.validation_limits.bytes_per_chain)
                {
                    continue;
                }

                let validation = ValidationId(self.next_job);
                self.next_job = self
                    .next_job
                    .checked_add(1)
                    .ok_or(ChainError::IdentifierExhausted)?;
                self.reserve_validation(chain_index, block_bytes)?;
                self.blocks
                    .get_mut(chain_index)
                    .and_then(|blocks| blocks.get_mut(&height))
                    .and_then(|records| records.get_mut(record_index))
                    .expect("the selected validation block remains retained")
                    .state = ValidationState::Pending(validation);
                let previous = self.validation_jobs.insert(
                    validation,
                    ValidationRecord {
                        chain,
                        height,
                        artifact,
                        bytes: block_bytes,
                    },
                );
                assert!(previous.is_none(), "validation identifiers are unique");
                self.capabilities.push(ChainEffect::Validate(ValidationJob {
                    id: validation,
                    generation,
                    block,
                }));
                self.next_validation_chain = (chain_index + 1) % self.blocks.len();
                scheduled = true;
                break;
            }
            if !scheduled {
                return Ok(());
            }
        }
    }

    fn validation_parent_available<H: Hasher<Digest = D>>(
        &self,
        chain: usize,
        header: &TransactionBlockHeader<D>,
    ) -> bool {
        let Some(parent_height) = header.height().get().checked_sub(1).map(Height::new) else {
            return false;
        };
        if self.certified[chain]
            .get(&parent_height)
            .is_some_and(|parent| parent.block.digest() == header.parent())
        {
            return true;
        }
        self.blocks[chain]
            .get(&parent_height)
            .is_some_and(|records| {
                records.iter().any(|parent| {
                    matches!(
                        parent.state,
                        ValidationState::Pending(_) | ValidationState::Valid
                    ) && parent.block.header().digest::<H>() == header.parent()
                })
            })
    }

    fn reserve_validation(&mut self, chain: usize, bytes: usize) -> Result<(), ChainError> {
        let items = self
            .validation_reservations
            .items
            .checked_add(1)
            .ok_or(ChainError::IdentifierExhausted)?;
        let total_bytes = self
            .validation_reservations
            .bytes
            .checked_add(bytes)
            .ok_or(ChainError::IdentifierExhausted)?;
        let chain_items = self.validation_reservations.chain_items[chain]
            .checked_add(1)
            .ok_or(ChainError::IdentifierExhausted)?;
        let chain_bytes = self.validation_reservations.chain_bytes[chain]
            .checked_add(bytes)
            .ok_or(ChainError::IdentifierExhausted)?;

        self.validation_reservations.items = items;
        self.validation_reservations.bytes = total_bytes;
        self.validation_reservations.chain_items[chain] = chain_items;
        self.validation_reservations.chain_bytes[chain] = chain_bytes;
        Ok(())
    }

    fn release_validation(&mut self, job: ValidationRecord<D>) -> Result<(), ChainError> {
        let chain = job.chain.get() as usize;
        let items = self
            .validation_reservations
            .items
            .checked_sub(1)
            .ok_or(ChainError::Context)?;
        let total_bytes = self
            .validation_reservations
            .bytes
            .checked_sub(job.bytes)
            .ok_or(ChainError::Context)?;
        let chain_items = self.validation_reservations.chain_items[chain]
            .checked_sub(1)
            .ok_or(ChainError::Context)?;
        let chain_bytes = self.validation_reservations.chain_bytes[chain]
            .checked_sub(job.bytes)
            .ok_or(ChainError::Context)?;

        self.validation_reservations.items = items;
        self.validation_reservations.bytes = total_bytes;
        self.validation_reservations.chain_items[chain] = chain_items;
        self.validation_reservations.chain_bytes[chain] = chain_bytes;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn validation_usage(&self) -> (usize, usize, &[usize], &[usize]) {
        (
            self.validation_reservations.items,
            self.validation_reservations.bytes,
            &self.validation_reservations.chain_items,
            &self.validation_reservations.chain_bytes,
        )
    }

    fn record_header<H: Hasher<Digest = D>>(
        &mut self,
        header: &TransactionBlockHeader<D>,
    ) -> Result<bool, ChainError> {
        let height = header
            .height()
            .get()
            .checked_sub(1)
            .ok_or(ChainError::Context)?;
        let child = header.block_ref::<H>();
        let chain = child.chain().get() as usize;
        if self
            .data_retired_through
            .get(chain)
            .is_some_and(|retired| child.height() <= *retired)
        {
            return Ok(true);
        }
        let parent = BlockRef::new(header.chain(), Height::new(height), header.parent());
        if self
            .ancestry
            .get(&child)
            .is_some_and(|existing| *existing != parent)
        {
            return Ok(false);
        }
        self.ancestry.entry(child).or_insert(parent);
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn retained_ancestry(&self) -> usize {
        self.ancestry.len()
    }

    pub(crate) fn fire_timer(&mut self, timer: ProductionTimer<D>) -> bool {
        if self.deadline != Some(timer) {
            return false;
        }
        self.deadline = None;
        self.producer_wake = true;
        true
    }

    pub(crate) fn reconcile<H: Hasher<Digest = D>>(
        &mut self,
        headers: impl IntoIterator<Item = TransactionBlockHeader<D>>,
    ) -> Result<(), ChainError> {
        let Some(own_chain) = self.own_chain else {
            return Ok(());
        };
        let mut selected = BTreeMap::new();
        for header in headers {
            if header.chain() != own_chain {
                continue;
            }
            match selected.insert(header.height(), header.clone()) {
                Some(existing) if existing != header => {
                    return Err(ChainError::ProducerConflict);
                }
                _ => {}
            }
        }
        let mut tip = self.certified[own_chain.get() as usize]
            .last_key_value()
            .map(|(_, certified)| certified.block)
            .ok_or(ChainError::Context)?;
        for header in selected.values() {
            if tip.height().get().checked_add(1) != Some(header.height().get())
                || header.parent() != tip.digest()
            {
                return Err(ChainError::ProducerConflict);
            }
            tip = header.block_ref::<H>();
        }
        if self
            .produced
            .is_some_and(|current| tip.height() < current.height())
        {
            return Err(ChainError::ProducerConflict);
        }
        self.producer_headers = selected;
        self.advance_produced::<H>(tip);
        Ok(())
    }

    pub(crate) fn observe_producer_choice<H: Hasher<Digest = D>>(
        &mut self,
        header: &TransactionBlockHeader<D>,
    ) -> Result<(), ChainError> {
        if Some(header.chain()) != self.own_chain {
            return Err(ChainError::ProducerConflict);
        }
        if let Some(existing) = self.producer_headers.get(&header.height()) {
            return if existing == header {
                Ok(())
            } else {
                Err(ChainError::ProducerConflict)
            };
        }
        let block = header.block_ref::<H>();
        let parent = self.produced.ok_or(ChainError::ProducerConflict)?;
        if parent.height().get().checked_add(1) != Some(header.height().get())
            || parent.digest() != header.parent()
        {
            return Err(ChainError::ProducerConflict);
        }
        self.producer_headers
            .insert(header.height(), header.clone());
        self.refresh_recovery::<H>(header.block_ref::<H>());
        self.advance_produced::<H>(block);
        Ok(())
    }

    pub(crate) fn reconcile_da_choices(
        &mut self,
        headers: impl IntoIterator<Item = TransactionBlockHeader<D>>,
    ) -> Result<(), ChainError> {
        for votes in &mut self.local_da_votes {
            votes.clear();
        }
        for header in headers {
            self.insert_da_choice(header)?;
        }
        for chain in 0..self.local_da_votes.len() {
            let mut height = self.data_retired_through[chain]
                .get()
                .checked_add(1)
                .ok_or(ChainError::HeightOverflow)?;
            while height <= self.da_safe_through[chain].get() {
                if !self.local_da_votes[chain].contains_key(&Height::new(height)) {
                    return Err(ChainError::DaVoteConflict);
                }
                if height == self.da_safe_through[chain].get() {
                    break;
                }
                height = height.checked_add(1).ok_or(ChainError::HeightOverflow)?;
            }
        }
        Ok(())
    }

    /// Returns every application payload whose recovered local authority requires reverification.
    pub(crate) fn recovered_payloads(&self) -> Vec<(Context<D>, D)> {
        let mut headers = self
            .producer_headers
            .values()
            .chain(self.local_da_votes.iter().flat_map(BTreeMap::values))
            .cloned()
            .collect::<Vec<_>>();
        headers.sort_by(|left, right| {
            left.chain()
                .get()
                .cmp(&right.chain().get())
                .then_with(|| left.height().get().cmp(&right.height().get()))
                .then_with(|| left.parent().as_ref().cmp(right.parent().as_ref()))
                .then_with(|| {
                    left.body_digest()
                        .as_ref()
                        .cmp(right.body_digest().as_ref())
                })
        });
        headers.dedup();
        headers
            .iter()
            .map(|header| (Context::from(header), header.body_digest()))
            .collect()
    }

    pub(crate) fn observe_da_choice(
        &mut self,
        header: &TransactionBlockHeader<D>,
    ) -> Result<(), ChainError> {
        let chain = header.chain().get() as usize;
        if self.pending_da_votes[chain]
            .as_ref()
            .is_some_and(|pending| pending != header)
        {
            return Err(ChainError::DaVoteConflict);
        }
        self.insert_da_choice(header.clone())?;
        if self.pending_da_votes[chain].as_ref() == Some(header) {
            self.pending_da_votes[chain] = None;
        }
        Ok(())
    }

    fn insert_da_choice(&mut self, header: TransactionBlockHeader<D>) -> Result<(), ChainError> {
        let chain = header.chain().get() as usize;
        let retired = *self
            .data_retired_through
            .get(chain)
            .ok_or(ChainError::Context)?;
        if header.height() <= retired {
            return Ok(());
        }
        let safe = self.da_safe_through[chain];
        if header.height() > safe {
            if safe.get().checked_add(1) != Some(header.height().get()) {
                return Err(ChainError::DaVoteConflict);
            }
            self.da_safe_through[chain] = header.height();
        }
        let votes = self
            .local_da_votes
            .get_mut(chain)
            .ok_or(ChainError::Context)?;
        match votes.get(&header.height()) {
            Some(existing) if existing != &header => Err(ChainError::DaVoteConflict),
            Some(_) => Ok(()),
            None => {
                votes.insert(header.height(), header);
                Ok(())
            }
        }
    }

    /// Returns the next eligible data-availability vote in round-robin chain order.
    pub(crate) fn next_ready_da_vote<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
    ) -> Result<Option<Arc<SignedTransactionBlock<V, D>>>, ChainError> {
        if !matches!(profile.role(), Role::Validator(_)) {
            return Ok(None);
        }
        for offset in 0..self.blocks.len() {
            let index = (self.next_da_chain + offset) % self.blocks.len();
            if self.pending_da_votes[index].is_some() {
                continue;
            }
            if let Some(header) = self.eligible_da_vote::<H>(profile, index)? {
                self.next_da_chain = (index + 1) % self.blocks.len();
                return Ok(Some(header));
            }
        }
        Ok(None)
    }

    fn eligible_da_vote<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        chain: usize,
    ) -> Result<Option<Arc<SignedTransactionBlock<V, D>>>, ChainError> {
        // Candidates derive from the retained block records on every pass rather than from an
        // event-maintained set. A valid block observed while the local certified floor lags the
        // cluster becomes votable the moment the floor catches up; there is no insertion event
        // whose loss could silence this chain's DA votes.
        let (floor, _) = self.certified[chain]
            .last_key_value()
            .ok_or(ChainError::Context)?;
        let start = (*floor).max(self.data_retired_through[chain]);
        for height in self.blocks[chain]
            .range((Bound::Excluded(start), Bound::Unbounded))
            .map(|(height, _)| height)
        {
            if self.local_da_votes[chain].contains_key(height) {
                continue;
            }
            let Some((certified_height, certified)) =
                self.certified[chain].range(..height).next_back()
            else {
                return Err(ChainError::Context);
            };
            if height.get().saturating_sub(certified_height.get())
                > profile.protocol().codec_config().pipeline_depth() as u64
            {
                continue;
            }

            let mut parent = certified.block;
            let mut next = certified_height
                .get()
                .checked_add(1)
                .ok_or(ChainError::HeightOverflow)?;
            while next < height.get() {
                let Some(header) = self.local_da_votes[chain].get(&Height::new(next)) else {
                    break;
                };
                if header.parent() != parent.digest() || !self.has_valid_block(header) {
                    break;
                }
                parent = header.block_ref::<H>();
                next = next.checked_add(1).ok_or(ChainError::HeightOverflow)?;
            }
            if next != height.get() {
                continue;
            }

            let Some(records) = self.blocks[chain].get(height) else {
                continue;
            };
            let Some(record) = records
                .iter()
                .find(|record| record.block.header().parent() == parent.digest())
            else {
                continue;
            };
            if record.state == ValidationState::Valid {
                return Ok(Some(Arc::clone(&record.block)));
            }
        }
        Ok(None)
    }

    pub(crate) fn mark_da_vote_reserved(&mut self, header: TransactionBlockHeader<D>) {
        let chain = header.chain().get() as usize;
        self.next_da_chain = (chain + 1) % self.blocks.len();
        self.pending_da_votes[chain] = Some(header);
    }

    /// Prepares a recovery completion's certificate, or consumes a stale completion.
    ///
    /// Returning `None` releases a matching reservation whose dispatch generation is no longer
    /// current and re-derives the block's recovery readiness, so a completion that cannot
    /// commit can never strand its job.
    pub(crate) fn prepare_recovery<H: Hasher<Digest = D>>(
        &mut self,
        completion: &DaRecoveryCompletion<V, D>,
        generation: u64,
    ) -> Result<Option<Arc<Artifact<V, D>>>, ChainError> {
        if self
            .recovery_jobs
            .get(&completion.id)
            .is_some_and(|job| job.generation != generation)
        {
            self.abandon_recovery::<H>(completion.id);
            return Ok(None);
        }
        if completion.generation != generation {
            return Ok(None);
        }
        let Some(job) = self.recovery_jobs.get(&completion.id) else {
            return Ok(None);
        };
        let certificate = &completion.certificate;
        let Some(first) = job.votes.first() else {
            return Err(ChainError::CompletionMismatch);
        };
        if certificate.header() != first.header() || certificate.certificate().get().is_none() {
            return Err(ChainError::CompletionMismatch);
        }
        Ok(Some(Arc::new(Artifact::DaCertificate(certificate.clone()))))
    }

    /// Releases a recovery reservation without a certificate and re-derives readiness.
    ///
    /// The vote pool survives the job, so a block whose recovery was abandoned re-readies
    /// immediately when its pool still satisfies the quorum and producer-header rules.
    pub(crate) fn abandon_recovery<H: Hasher<Digest = D>>(&mut self, id: DaRecoveryId) {
        let Some(job) = self.recovery_jobs.remove(&id) else {
            return;
        };
        if let Some(vote) = job.votes.first() {
            let block = vote.header().block_ref::<H>();
            self.pending_recoveries.remove(&block);
            self.refresh_recovery::<H>(block);
        }
    }

    pub(crate) fn finish_recovery<H: Hasher<Digest = D>>(&mut self, id: DaRecoveryId) {
        let Some(job) = self.recovery_jobs.remove(&id) else {
            return;
        };
        if let Some(vote) = job.votes.first() {
            self.pending_recoveries
                .remove(&vote.header().block_ref::<H>());
        }
    }

    pub(crate) fn recovery_reservations(&self) -> usize {
        self.recovery_jobs.len()
    }

    pub(crate) fn is_producer_header(&self, header: &TransactionBlockHeader<D>) -> bool {
        Some(header.chain()) == self.own_chain
            && self.producer_headers.get(&header.height()) == Some(header)
    }

    fn planned_tip<H: Hasher<Digest = D>>(&self) -> Option<BlockRef<D>> {
        self.prepared
            .back()
            .map(|prepared| prepared.header.block_ref::<H>())
            .or(self.produced)
    }

    fn discard_prepared_prefix(&mut self, count: usize) {
        for _ in 0..count {
            let prepared = self
                .prepared
                .pop_front()
                .expect("the discarded prepared prefix is present");
            if prepared.state != PreparedState::AwaitingCustody {
                continue;
            }
            let cancellation = CustodyCancellation::new(prepared.id, prepared.generation);
            let previous = self
                .cancelling_custody
                .insert(cancellation.id, cancellation.generation);
            debug_assert!(previous.is_none());
            self.capabilities
                .push(ChainEffect::CancelCustody(cancellation));
        }
    }

    fn advance_produced<H: Hasher<Digest = D>>(&mut self, tip: BlockRef<D>) {
        if self.produced == Some(tip) {
            return;
        }

        let discarded = if let Some(position) = self
            .prepared
            .iter()
            .position(|prepared| prepared.header.block_ref::<H>() == tip)
        {
            position + 1
        } else {
            self.prepared.len()
        };
        self.discard_prepared_prefix(discarded);
        self.produced = Some(tip);
        self.deadline = None;
        self.producer_wake = true;
    }

    pub(crate) fn begin_proposal_pass<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        tip: BlockRef<D>,
    ) -> Result<ChainProposalPass<V, D>, ChainError> {
        let chain = tip.chain().get() as usize;
        let certificates = self.certified.get(chain).ok_or(ChainError::Context)?;
        let certified = certificates
            .range(..)
            .rev()
            .take_while(|(height, _)| **height > tip.height())
            .find_map(|(_, certified)| {
                certified
                    .certificate
                    .clone()
                    .map(|certificate| (certificate, certified.block))
            });
        let (anchor, parent) = match certified {
            Some((certificate, block)) => (Anchor::Certificate(certificate), block),
            None => (Anchor::Tip(tip), tip),
        };
        Ok(ChainProposalPass {
            tip,
            anchor,
            parent,
            payloads: Vec::new(),
            attempted: 0,
            limit: profile.protocol().codec_config().pipeline_depth(),
        })
    }

    pub(crate) fn resume_proposal_pass<H: Hasher<Digest = D>>(
        &self,
        pass: &mut ChainProposalPass<V, D>,
    ) -> Result<ChainProposalProgress<V, D>, ChainError> {
        if pass.attempted < pass.limit {
            pass.attempted += 1;
            let Some(height) = pass.parent.height().get().checked_add(1).map(Height::new) else {
                pass.attempted = pass.limit;
                return self.finish_proposal_pass(pass);
            };
            let votes = self
                .local_da_votes
                .get(pass.tip.chain().get() as usize)
                .ok_or(ChainError::Context)?;
            let Some(header) = votes.get(&height) else {
                pass.attempted = pass.limit;
                return self.finish_proposal_pass(pass);
            };
            if header.parent() != pass.parent.digest() || !self.has_valid_block(header) {
                pass.attempted = pass.limit;
                return self.finish_proposal_pass(pass);
            }
            pass.payloads.push(header.body_digest());
            pass.parent = header.block_ref::<H>();
            if pass.attempted < pass.limit {
                return Ok(ChainProposalProgress::Pending);
            }
        }
        self.finish_proposal_pass(pass)
    }

    fn finish_proposal_pass(
        &self,
        pass: &ChainProposalPass<V, D>,
    ) -> Result<ChainProposalProgress<V, D>, ChainError> {
        let proposal = ChainProposal::new(
            pass.tip.chain(),
            pass.anchor.clone(),
            pass.payloads.clone(),
            pass.limit,
        )
        .map_err(|_| ChainError::Context)?;
        Ok(ChainProposalProgress::Complete(proposal))
    }

    #[cfg(test)]
    pub(crate) fn proposal<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        tip: BlockRef<D>,
    ) -> Result<ChainProposal<V, D>, ChainError> {
        let mut pass = self.begin_proposal_pass::<H>(profile, tip)?;
        loop {
            match self.resume_proposal_pass::<H>(&mut pass)? {
                ChainProposalProgress::Pending => {}
                ChainProposalProgress::Complete(proposal) => return Ok(proposal),
            }
        }
    }

    pub(crate) fn begin_vote_body_pass(
        &self,
        profile: &Profile<impl Hasher<Digest = D>, V>,
        leader: LeaderBlock<V, D>,
    ) -> VoteBodyPass<V, D> {
        VoteBodyPass {
            leader,
            chain: 0,
            phase: VoteBodyPhase::Proposal,
            parent: None,
            proposal_index: 0,
            extension_index: 0,
            position: 0,
            extension_payloads: Vec::new(),
            positions: Vec::with_capacity(profile.protocol().codec_config().chains()),
            extensions: Vec::with_capacity(profile.protocol().codec_config().chains()),
            extension_bound: profile.protocol().codec_config().extension_bound(),
        }
    }

    pub(crate) fn resume_vote_body_pass<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        pass: &mut VoteBodyPass<V, D>,
    ) -> Result<VoteBodyProgress<D>, ChainError> {
        if pass.chain == pass.leader.proposals().len() {
            let body = VoteBody::for_leader::<H, V>(
                &pass.leader,
                pass.positions.clone(),
                pass.extensions.clone(),
                profile.protocol().codec_config(),
            )
            .map_err(|_| ChainError::Context)?;
            return Ok(VoteBodyProgress::Complete(body));
        }

        let proposal = &pass.leader.proposals()[pass.chain];
        let parent = pass
            .parent
            .get_or_insert_with(|| proposal.anchor().block_ref::<H>());
        let votes = self
            .local_da_votes
            .get(pass.chain)
            .ok_or(ChainError::Context)?;
        match pass.phase {
            VoteBodyPhase::Proposal => {
                let Some(payload) = proposal.payloads().get(pass.proposal_index) else {
                    pass.phase = VoteBodyPhase::Extension;
                    return Ok(VoteBodyProgress::Pending);
                };
                pass.proposal_index += 1;
                let Some(height) = parent.height().get().checked_add(1).map(Height::new) else {
                    pass.phase = VoteBodyPhase::Extension;
                    return Ok(VoteBodyProgress::Pending);
                };
                let Some(header) = votes.get(&height) else {
                    pass.phase = VoteBodyPhase::Extension;
                    return Ok(VoteBodyProgress::Pending);
                };
                if header.chain().get() as usize != pass.chain
                    || header.parent() != parent.digest()
                    || header.body_digest() != *payload
                    || !self.has_valid_block(header)
                {
                    pass.phase = VoteBodyPhase::Extension;
                    return Ok(VoteBodyProgress::Pending);
                }
                pass.position += 1;
                *parent = header.block_ref::<H>();
                Ok(VoteBodyProgress::Pending)
            }
            VoteBodyPhase::Extension => {
                if pass.extension_index < pass.extension_bound {
                    pass.extension_index += 1;
                    let Some(height) = parent.height().get().checked_add(1).map(Height::new) else {
                        pass.extension_index = pass.extension_bound;
                        return Ok(VoteBodyProgress::Pending);
                    };
                    let Some(header) = votes.get(&height) else {
                        pass.extension_index = pass.extension_bound;
                        return Ok(VoteBodyProgress::Pending);
                    };
                    if header.chain().get() as usize != pass.chain
                        || header.parent() != parent.digest()
                        || !self.has_valid_block(header)
                    {
                        pass.extension_index = pass.extension_bound;
                        return Ok(VoteBodyProgress::Pending);
                    }
                    pass.extension_payloads.push(header.body_digest());
                    *parent = header.block_ref::<H>();
                    return Ok(VoteBodyProgress::Pending);
                }

                let position = u32::try_from(pass.position).map_err(|_| ChainError::Context)?;
                pass.positions.push(Position::new(position));
                pass.extensions.push(
                    Extension::new(pass.extension_payloads.clone(), pass.extension_bound)
                        .map_err(|_| ChainError::Context)?,
                );
                pass.chain += 1;
                pass.phase = VoteBodyPhase::Proposal;
                pass.parent = None;
                pass.proposal_index = 0;
                pass.extension_index = 0;
                pass.position = 0;
                pass.extension_payloads.clear();
                Ok(VoteBodyProgress::Pending)
            }
        }
    }

    pub(crate) fn vote_body<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        leader: &LeaderBlock<V, D>,
    ) -> Result<VoteBody<D>, ChainError> {
        let config = profile.protocol().codec_config();
        let mut positions = Vec::with_capacity(config.chains());
        let mut extensions = Vec::with_capacity(config.chains());

        for (index, proposal) in leader.proposals().iter().enumerate() {
            let chain = ChainId::new(index as u32);
            let votes = self.local_da_votes.get(index).ok_or(ChainError::Context)?;
            let mut parent = proposal.anchor().block_ref::<H>();
            let mut position = 0usize;

            for payload in proposal.payloads() {
                let Some(height) = parent.height().get().checked_add(1).map(Height::new) else {
                    return Err(ChainError::HeightOverflow);
                };
                let Some(header) = votes.get(&height) else {
                    break;
                };
                if header.chain() != chain
                    || header.parent() != parent.digest()
                    || header.body_digest() != *payload
                    || !self.has_valid_block(header)
                {
                    break;
                }
                position += 1;
                parent = header.block_ref::<H>();
            }

            let mut payloads = Vec::with_capacity(config.extension_bound());
            for _ in 0..config.extension_bound() {
                let Some(height) = parent.height().get().checked_add(1).map(Height::new) else {
                    return Err(ChainError::HeightOverflow);
                };
                let Some(header) = votes.get(&height) else {
                    break;
                };
                if header.chain() != chain
                    || header.parent() != parent.digest()
                    || !self.has_valid_block(header)
                {
                    break;
                }
                payloads.push(header.body_digest());
                parent = header.block_ref::<H>();
            }

            let position = u32::try_from(position).map_err(|_| ChainError::Context)?;
            positions.push(Position::new(position));
            extensions.push(
                Extension::new(payloads, config.extension_bound())
                    .map_err(|_| ChainError::Context)?,
            );
        }

        VoteBody::for_leader::<H, V>(leader, positions, extensions, config)
            .map_err(|_| ChainError::Context)
    }

    fn has_valid_block(&self, header: &TransactionBlockHeader<D>) -> bool {
        self.blocks
            .get(header.chain().get() as usize)
            .and_then(|blocks| blocks.get(&header.height()))
            .is_some_and(|records| {
                records.iter().any(|record| {
                    record.block.header() == header && record.state == ValidationState::Valid
                })
            })
    }

    pub(crate) fn drive<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        generation: u64,
        recovery_slots: usize,
        production_credit: bool,
    ) -> Result<(), ChainError> {
        self.production_credit = production_credit;
        self.schedule_ready_validations::<H>(generation)?;
        let recoveries_before = self.recovery_jobs.len();
        self.drive_recoveries::<H>(profile, generation, recovery_slots)?;
        if self.recovery_jobs.len() > recoveries_before {
            return Ok(());
        }
        let Some(parent) = self.planned_tip::<H>() else {
            return Ok(());
        };
        if !production_credit
            || !self.producer_wake
            || self.deadline.is_some()
            || self.pending_build.is_some()
            || !self.cancelling_custody.is_empty()
        {
            return Ok(());
        }
        let certified = self.certified[parent.chain().get() as usize]
            .last_key_value()
            .map(|(height, _)| *height)
            .ok_or(ChainError::Context)?;
        let next = parent
            .height()
            .get()
            .checked_add(1)
            .ok_or(ChainError::HeightOverflow)?;
        if next.saturating_sub(certified.get())
            > profile.protocol().codec_config().pipeline_depth() as u64
        {
            return Ok(());
        }
        let id = BuildId(self.next_job);
        self.next_job = self
            .next_job
            .checked_add(1)
            .ok_or(ChainError::IdentifierExhausted)?;
        let job = BuildJob {
            id,
            generation,
            parent,
        };
        self.producer_wake = false;
        self.pending_build = Some(job.clone());
        self.capabilities.push(ChainEffect::Build(job));
        Ok(())
    }

    fn drive_recoveries<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        generation: u64,
        mut slots: usize,
    ) -> Result<(), ChainError> {
        if slots == 0 {
            return Ok(());
        }
        let Some(own_chain) = self.own_chain else {
            return Ok(());
        };
        debug_assert_eq!(
            self.da_quorum,
            profile.protocol().codec_config().da_quorum()
        );

        while slots > 0 {
            let Some(block) = self.ready_recoveries.pop_first() else {
                break;
            };
            slots -= 1;
            debug_assert_eq!(
                block.chain(),
                own_chain,
                "refresh_recovery only readies own-chain blocks"
            );
            let Some(header) = self.producer_headers.get(&block.height()) else {
                continue;
            };
            if header.block_ref::<H>() != block {
                continue;
            }
            let Some(pool) = self.vote_pools.get(&header.digest::<H>()) else {
                continue;
            };
            let certified = self.certified[own_chain.get() as usize]
                .get(&block.height())
                .is_some_and(|certified| certified.block == block);
            if certified {
                continue;
            }
            if pool.shares.len() < self.da_quorum
                || self.pending_recoveries.contains(&block)
                || self.producer_headers.get(&block.height()) != Some(&pool.header)
            {
                continue;
            }
            let id = DaRecoveryId(self.next_job);
            self.next_job = self
                .next_job
                .checked_add(1)
                .ok_or(ChainError::IdentifierExhausted)?;
            let votes = pool
                .shares
                .values()
                .take(self.da_quorum)
                .map(|vote| vote.as_ref().clone())
                .collect::<Arc<[_]>>();
            let job = DaRecoveryJob {
                id,
                generation,
                votes,
            };
            self.recovery_jobs.insert(id, job.clone());
            self.pending_recoveries.insert(block);
            self.capabilities.push(ChainEffect::Recover(job));
        }
        Ok(())
    }

    pub(crate) fn has_ready_recovery(&self) -> bool {
        !self.ready_recoveries.is_empty()
    }

    fn refresh_recovery<H: Hasher<Digest = D>>(&mut self, block: BlockRef<D>) {
        let pool = self
            .producer_headers
            .get(&block.height())
            .filter(|header| header.block_ref::<H>() == block)
            .and_then(|header| self.vote_pools.get(&header.digest::<H>()));
        let ready = Some(block.chain()) == self.own_chain
            && !self.pending_recoveries.contains(&block)
            && self
                .certified
                .get(block.chain().get() as usize)
                .is_some_and(|certified| {
                    certified
                        .get(&block.height())
                        .is_none_or(|certificate| certificate.block != block)
                })
            && pool.is_some_and(|pool| {
                pool.shares.len() >= self.da_quorum
                    && self.producer_headers.get(&block.height()) == Some(&pool.header)
            });
        if ready {
            self.ready_recoveries.insert(block);
        } else {
            self.ready_recoveries.remove(&block);
        }
    }

    pub(crate) fn take_effects(&mut self) -> Vec<ChainEffect<V, D>> {
        self.capabilities.drain(..).collect()
    }
}

/// A malformed application completion or contradictory chain fact.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ChainError {
    #[error("chain object is outside the configured epoch context")]
    Context,
    #[error("chain job identifier exhausted")]
    IdentifierExhausted,
    #[error("chain height overflow")]
    HeightOverflow,
    #[error("application completion does not match its exact job")]
    CompletionMismatch,
    #[error("conflicting data-availability certificates were admitted")]
    CertifiedConflict,
    #[error("local producer choices conflict")]
    ProducerConflict,
    #[error("local data-availability vote choices conflict")]
    DaVoteConflict,
    #[error("data-availability signing reservation failed: {0}")]
    Reservation(ReservationError),
}
