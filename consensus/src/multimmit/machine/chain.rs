//! Application-independent transaction-chain work and validation.

use super::{
    Artifact, ArtifactId, DurableEffect, EffectId, Observation, Profile, ProposalPolicy,
    ReservationBook, ReservationError, Role, SignRequest,
};
use crate::{
    multimmit::types::{
        Anchor, BlockRef, ChainId, ChainProposal, Context, DaCertificate, DaVote, Extension,
        LeaderBlock, Position, SignedTransactionBlock, TransactionBlockHeader, VoteBody,
    },
    types::Height,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
#[cfg(not(target_arch = "wasm32"))]
use commonware_runtime::telemetry::traces::TracedExt as _;
use core::{ops::Bound, time::Duration};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
#[cfg(not(target_arch = "wasm32"))]
use tracing::{Span, info_span};

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

pub(crate) struct VoteBodyPass<V: Variant, D: Digest> {
    leader: LeaderBlock<V, D>,
    // A vote decision uses one immutable DA frontier even if later validations complete while
    // its budgeted body construction is still in progress.
    da_frontiers: Vec<Height>,
    chain: usize,
    positions: Vec<Position>,
    extensions: Vec<Extension<D>>,
    extension_bound: usize,
    /// Owns the snapshot-to-body interval, including yields between chain decisions.
    #[cfg(not(target_arch = "wasm32"))]
    span: Option<Span>,
}

pub(crate) enum VoteBodyProgress<D: Digest> {
    Pending,
    Complete(VoteBody<D>),
}

/// Identifies one volatile application build request within a process generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct BuildId(u64);

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
    pub const fn new(id: BuildId, generation: u64, header: TransactionBlockHeader<D>) -> Self {
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
    /// Creates a validation identity.
    pub(crate) const fn new(id: u64) -> Self {
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

    /// Creates a validation job.
    pub(crate) const fn new(
        id: ValidationId,
        generation: u64,
        block: Arc<SignedTransactionBlock<V, D>>,
    ) -> Self {
        Self {
            id,
            generation,
            block,
        }
    }

    /// Returns the shared authenticated block.
    pub(crate) const fn block_arc(&self) -> &Arc<SignedTransactionBlock<V, D>> {
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
    /// The application reached no verdict: the payload could not be fetched or the application
    /// was unavailable. The block stays ready and its validation is scheduled again.
    Unavailable,
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

    /// Returns the validation identity.
    pub(crate) const fn id(&self) -> ValidationId {
        self.id
    }

    /// Returns the process generation that issued the validation.
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the application verdict.
    pub(crate) const fn validity(&self) -> BlockValidity {
        self.validity
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
    ArmTimer(ProductionTimer<D>),
    /// Forward an authenticated own-chain data-availability share to the own-chain DA task.
    ForwardShare(Arc<DaVote<V, D>>),
    /// Route an authenticated block to its producer chain's remote validator plane. Central minted
    /// the observation identity and recorded producer ancestry before emitting this.
    ObserveBlock {
        /// The observation identity central assigned.
        id: ArtifactId<D>,
        /// The observation order central assigned.
        observation: Observation,
        /// The authenticated block.
        block: Arc<SignedTransactionBlock<V, D>>,
        /// Whether this is the local producer's own custodied block.
        custodied: bool,
    },
    /// Tell a chain's validator plane its certified anchor advanced to this block.
    ValidatorAnchor(BlockRef<D>),
    /// Replace a chain's validator-plane read-copy of central's durable DA choices above the anchor.
    ValidatorChosen {
        /// The producer chain.
        chain: ChainId,
        /// The retained DA choices above the anchor.
        choices: Vec<DaChoice<D>>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct DaChoice<D: Digest> {
    header: TransactionBlockHeader<D>,
    block_ref: BlockRef<D>,
}

impl<D: Digest> DaChoice<D> {
    /// Returns the voted header.
    pub(crate) const fn header(&self) -> &TransactionBlockHeader<D> {
        &self.header
    }

    /// Returns the voted block reference.
    pub(crate) const fn block_ref(&self) -> BlockRef<D> {
        self.block_ref
    }

    /// Builds a choice directly, for validator-plane unit tests that seed the read-copy.
    #[cfg(test)]
    pub(crate) const fn for_test(
        header: TransactionBlockHeader<D>,
        block_ref: BlockRef<D>,
    ) -> Self {
        Self { header, block_ref }
    }
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
    pub da_quorum: usize,
    pub pipeline_depth: u64,
    pub prepared: usize,
    pub pipeline_blocked: bool,
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

/// Volatile, rebuildable per-producer-chain data-availability state, indexed by [`ChainId`].
///
/// Every field is derived from admitted artifacts and durable anchors, so it can be dropped and
/// rebuilt without changing normalized protocol state.
struct PerChainDa<V: Variant, D: Digest> {
    local_da_votes: BTreeMap<Height, DaChoice<D>>,
    /// A height through which every integer height above `data_retired_through` is already a local
    /// DA choice.
    ///
    /// Eligibility scans resume above this height instead of rediscovering the voted prefix on
    /// every pass. The value is a lower bound: an entry below the true contiguous run only costs
    /// a longer scan, so a missed extension can never hide an eligible block.
    da_voted_run: Height,
    da_safe_through: Height,
    data_retired_through: Height,
    /// Reserved DA votes whose signing is in flight, in ascending height order.
    ///
    /// A chain reserves at most one run at a time; completions consume the queue front in
    /// order, so the queue is also the expected application sequence.
    pending_da_votes: VecDeque<TransactionBlockHeader<D>>,
    certified: BTreeMap<Height, Certified<V, D>>,
    /// The contiguous eligible DA-vote run this chain's validator plane last offered, lowest height
    /// first. Central drains it in its reservation loop; it is the frontier shadow the plane feeds
    /// and reads synchronously at vote and proposal time.
    offered: Vec<Arc<SignedTransactionBlock<V, D>>>,
    /// The greatest height `offered` reaches, or the certified anchor when empty. A safe lower bound
    /// on the plane's true frontier, since central mints every durable choice.
    ready_through: Height,
}

/// Volatile, rebuildable chain indexes owned by the deterministic machine.
pub(crate) struct ChainState<V: Variant, D: Digest> {
    own_chain: Option<ChainId>,
    da_quorum: usize,
    pipeline_depth: u64,
    genesis: Vec<BlockRef<D>>,
    produced: Option<BlockRef<D>>,
    producer_headers: BTreeMap<Height, TransactionBlockHeader<D>>,
    chains: Vec<PerChainDa<V, D>>,
    next_da_chain: usize,
    certificate_candidates: BTreeMap<BlockRef<D>, Vec<CertificateCandidate<V, D>>>,
    discarded_certificates: Vec<ArtifactId<D>>,
    ancestry: BTreeMap<BlockRef<D>, BlockRef<D>>,
    next_job: u64,
    producer_wake: bool,
    deadline: Option<ProductionTimer<D>>,
    pending_build: Option<BuildJob<D>>,
    prepared: VecDeque<PreparedBuild<D>>,
    cancelling_custody: BTreeMap<BuildId, u64>,
    signing: ReservationBook<SigningSubject<V, D>>,
    production_credit: bool,
    capabilities: Vec<ChainEffect<V, D>>,
}

impl<V: Variant, D: Digest> ChainState<V, D> {
    pub(crate) fn new<H: Hasher<Digest = D>>(profile: &Profile<H, V>) -> Self {
        let genesis = profile.protocol().genesis().tips().to_vec();
        let own_chain = match profile.role() {
            Role::Validator(participant) => profile.protocol().producer_chain(participant),
            Role::Observer => None,
        };
        let produced = own_chain.and_then(|chain| genesis.get(chain.get() as usize).copied());
        let chains = genesis
            .iter()
            .map(|block| PerChainDa {
                local_da_votes: BTreeMap::new(),
                da_voted_run: block.height(),
                da_safe_through: block.height(),
                data_retired_through: block.height(),
                pending_da_votes: VecDeque::new(),
                certified: BTreeMap::from([(
                    block.height(),
                    Certified {
                        block: *block,
                        certificate: None,
                    },
                )]),
                offered: Vec::new(),
                ready_through: block.height(),
            })
            .collect();
        let pipeline_depth = profile.protocol().codec_config().pipeline_depth() as u64;
        let resources = profile.resources();
        Self {
            own_chain,
            da_quorum: profile.protocol().codec_config().da_quorum(),
            pipeline_depth,
            genesis,
            produced,
            producer_headers: BTreeMap::new(),
            chains,
            next_da_chain: 0,
            certificate_candidates: BTreeMap::new(),
            discarded_certificates: Vec::new(),
            ancestry: BTreeMap::new(),
            next_job: 0,
            producer_wake: false,
            deadline: None,
            pending_build: None,
            prepared: VecDeque::new(),
            cancelling_custody: BTreeMap::new(),
            signing: ReservationBook::new(resources.max_outbox_effects()),
            production_credit: false,
            capabilities: Vec::new(),
        }
    }

    /// Installs producer-chain certificates carried by an admitted leader block.
    pub(crate) fn install_verified_anchors<H: Hasher<Digest = D>>(
        &mut self,
        anchors: impl IntoIterator<Item = DaCertificate<V, D>>,
    ) -> Result<(), ChainError> {
        for certificate in anchors {
            let block = certificate.block_ref::<H>();
            let Some(chain) = self.chains.get(block.chain().get() as usize) else {
                return Err(ChainError::Context);
            };
            if let Some((height, certified)) = chain.certified.last_key_value() {
                if *height > block.height() {
                    continue;
                }
                if *height == block.height() && certified.block == block {
                    continue;
                }
            }
            self.install_certificate(block, certificate)?;
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
            self.chains[index].da_safe_through = safe[index];
            self.chains[index].data_retired_through = tip.height();
            self.chains[index].da_voted_run = self.chains[index].da_voted_run.max(tip.height());
            if tip != applied {
                self.chains[index].certified.insert(
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
        let applied = self
            .chains
            .get(index)
            .ok_or(ChainError::Context)?
            .data_retired_through;
        if retired < applied || retired > block.height() {
            return Err(ChainError::Context);
        }

        self.install_certificate(block, certificate.clone())?;
        self.chains[index].certified.retain(|height, certified| {
            *height == self.genesis[index].height() || *height > retired || certified.block == block
        });
        // A vote reports positions from the leader's anchor, and a leader anchors at the newest
        // certificate it held when it proposed. Certificates keep arriving while the proposal
        // travels, so a voter's own certified floor commonly passes that anchor before it votes.
        // Choices at or below the floor add no availability, but they are exactly the record a
        // vote needs to endorse the leader's payloads, so keep one pipelining depth of them.
        let retained = Height::new(retired.get().saturating_sub(self.pipeline_depth));
        self.chains[index]
            .local_da_votes
            .retain(|height, _| *height > retained);
        // Retirement only drops choices below the retained window, so the prefix above the new
        // floor stays contiguous; raising the cursor to the floor keeps it a valid lower bound.
        self.chains[index].da_voted_run = self.chains[index].da_voted_run.max(retired);
        self.certificate_candidates.retain(|candidate, _| {
            candidate.chain() != block.chain() || candidate.height() > retired
        });
        self.ancestry
            .retain(|child, _| child.chain() != block.chain() || child.height() > retired);
        self.chains[block.chain().get() as usize]
            .pending_da_votes
            .retain(|header| header.height() > retired);
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
        self.chains[index].da_safe_through = self.chains[index].da_safe_through.max(block.height());
        self.chains[index].data_retired_through = retired;
        // The block store and its validations live in the chain's validator plane: route the new
        // certified anchor so the plane settles them, and the surviving DA choices so its
        // eligibility read-copy tracks this durable retirement.
        self.capabilities.push(ChainEffect::ValidatorAnchor(block));
        self.emit_validator_chosen(index);
        Ok(())
    }

    /// Routes a chain's current durable DA choices above the anchor to its validator plane so the
    /// plane's eligibility read-copy stays a lower-bound mirror of central's durable record.
    fn emit_validator_chosen(&mut self, chain: usize) {
        let retired = self.chains[chain].data_retired_through;
        let choices = self.chains[chain]
            .local_da_votes
            .range(Height::new(retired.get().saturating_add(1))..)
            .map(|(_, choice)| choice.clone())
            .collect();
        self.capabilities.push(ChainEffect::ValidatorChosen {
            chain: ChainId::new(chain as u32),
            choices,
        });
    }

    /// Returns the greatest locally usable, DA-certified, and locally DA-voted height on every
    /// chain.
    pub(crate) fn tip_heights(&self) -> Vec<(Height, Height, Height)> {
        self.genesis
            .iter()
            .enumerate()
            .map(|(index, floor)| {
                let certified = self.chains[index]
                    .certified
                    .iter()
                    .rev()
                    .find(|(_, certified)| certified.certificate.is_some())
                    .map_or(Height::zero(), |(height, _)| *height);

                // The validator plane owns the block store; its offered run's reach is the
                // highest locally validated height central still tracks for this chain.
                let locally_valid = Some(self.chains[index].ready_through);
                let da_voted = self.chains[index]
                    .local_da_votes
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

                // Retention drops DA votes at or below the retired frontier, so an empty vote map
                // reports that frontier rather than dipping back to the genesis floor.
                let da_voted = da_voted
                    .unwrap_or_else(|| self.chains[index].data_retired_through.max(floor.height()));

                (known, certified, da_voted)
            })
            .collect()
    }

    pub(crate) fn producer_status<H: Hasher<Digest = D>>(&self) -> Option<ProducerStatus> {
        let chain = self.own_chain?;
        let produced = self.produced?;
        let certified = self.chains[chain.get() as usize]
            .certified
            .iter()
            .rev()
            .find(|(_, certified)| certified.certificate.is_some())
            .map_or(Height::zero(), |(height, _)| *height);

        Some(ProducerStatus {
            chain,
            produced: produced.height(),
            certified,
            da_quorum: self.da_quorum,
            pipeline_depth: self.pipeline_depth,
            prepared: self.prepared.len(),
            pipeline_blocked: self.planned_tip::<H>().is_some_and(|tip| {
                tip.height().get().saturating_sub(certified.get()) >= self.pipeline_depth
            }),
            wake: self.producer_wake,
            timer_armed: self.deadline.is_some(),
            build_pending: self.pending_build.is_some(),
            production_credit: self.production_credit,
        })
    }

    /// Returns the data-availability certificate this node holds for `block`, if any.
    pub(crate) fn held_certificate(&self, block: BlockRef<D>) -> Option<&DaCertificate<V, D>> {
        let certified = self
            .chains
            .get(block.chain().get() as usize)?
            .certified
            .get(&block.height())?;
        (certified.block == block)
            .then_some(certified.certificate.as_ref())
            .flatten()
    }

    /// Returns whether any chain holds a certificate above its durable floor.
    pub(crate) fn has_certificate_above(&self, floors: &[BlockRef<D>]) -> bool {
        (0..self.chains.len()).any(|chain| self.certificate_above(floors, chain).is_some())
    }

    pub(crate) fn next_certificate_above(
        &self,
        floors: &[BlockRef<D>],
        preferred: Option<ChainId>,
    ) -> Option<DaCertificate<V, D>> {
        let preferred = preferred.map(|chain| chain.get() as usize);
        preferred
            .into_iter()
            .chain(0..self.chains.len())
            .find_map(|chain| self.certificate_above(floors, chain))
            .cloned()
    }

    /// Returns one chain's highest held certificate above its durable floor.
    fn certificate_above(
        &self,
        floors: &[BlockRef<D>],
        chain: usize,
    ) -> Option<&DaCertificate<V, D>> {
        let certificates = &self.chains.get(chain)?.certified;
        let floor = floors.get(chain)?;
        certificates
            .range((Bound::Excluded(floor.height()), Bound::Unbounded))
            .rev()
            .find_map(|(_, certified)| certified.certificate.as_ref())
    }

    pub(crate) fn observe<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Artifact<V, D>,
    ) -> Result<(), ChainError> {
        let block_ref = match artifact {
            Artifact::TransactionBlock(block) => Some(block.header().block_ref::<H>()),
            Artifact::DaVote(vote) => Some(vote.header().block_ref::<H>()),
            Artifact::DaCertificate(certificate) => Some(certificate.block_ref::<H>()),
            _ => None,
        };
        if block_ref.is_some_and(|block| {
            self.genesis
                .get(block.chain().get() as usize)
                .is_some_and(|genesis| block.height() <= genesis.height())
        }) {
            return Ok(());
        }
        match artifact {
            Artifact::TransactionBlock(block) => {
                let _ = block_ref.ok_or(ChainError::Context)?;
                // Central records producer ancestry and detects forks before the block leaves for
                // its chain's remote validator plane, keeping observation identity, order, and fork
                // detection central (invariant 1). The block store and application validation live
                // in the plane; a fork is rejected here rather than routed.
                if !self.record_header::<H>(block.header())? {
                    return Err(ChainError::ProducerConflict);
                }
                let custodied = self.is_producer_header(block.header());
                self.capabilities.push(ChainEffect::ObserveBlock {
                    id,
                    observation,
                    block: Arc::new(block.clone()),
                    custodied,
                });
            }
            Artifact::DaVote(vote) => {
                // Shares are only useful to the chain's producer; the own-chain task pools them
                // and decides recovery. Central keeps minting their observation identity.
                if self.own_chain == Some(vote.header().chain()) {
                    self.capabilities
                        .push(ChainEffect::ForwardShare(Arc::new(vote.clone())));
                }
            }
            Artifact::DaCertificate(certificate) => {
                if !self.record_header::<H>(certificate.header())? {
                    return Err(ChainError::CertifiedConflict);
                }
                self.observe_certificate::<H>(id, observation, certificate)?;
            }
            _ => return Ok(()),
        }
        Ok(())
    }

    pub(crate) fn claim_da_certificate<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        certificate: &DaCertificate<V, D>,
    ) -> Result<bool, ChainError> {
        let block = certificate.block_ref::<H>();
        if block.chain().get() as usize >= self.chains.len() {
            return Err(ChainError::Context);
        }
        let certified = &self.chains[block.chain().get() as usize].certified;
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
            // A block is routed to its validator plane only after producer-signature verification,
            // so a rejected-unverified block was never stored centrally nor routed: nothing to drop.
            Artifact::TransactionBlock(_) => {}
            Artifact::DaCertificate(certificate) => {
                let block = certificate.block_ref::<H>();
                if let Some(candidates) = self.certificate_candidates.get_mut(&block) {
                    candidates.retain(|candidate| candidate.artifact != id);
                    if candidates.is_empty() {
                        self.certificate_candidates.remove(&block);
                    }
                }
                self.promote_certificate(block)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn observe_certificate<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        certificate: &DaCertificate<V, D>,
    ) -> Result<(), ChainError> {
        let block = certificate.block_ref::<H>();
        let certified = &self.chains[block.chain().get() as usize].certified;
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
        self.promote_certificate(block)
    }

    fn promote_certificate(&mut self, block: BlockRef<D>) -> Result<(), ChainError> {
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
            self.discarded_certificates.push(candidate.artifact);
        }

        self.install_certificate(block, certificate)
    }

    fn install_certificate(
        &mut self,
        block: BlockRef<D>,
        certificate: DaCertificate<V, D>,
    ) -> Result<(), ChainError> {
        let chain = &mut self
            .chains
            .get_mut(block.chain().get() as usize)
            .ok_or(ChainError::Context)?
            .certified;
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
        Ok(())
    }

    pub(crate) fn take_discarded_certificates(&mut self) -> Vec<ArtifactId<D>> {
        std::mem::take(&mut self.discarded_certificates)
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
        let Some(prepared) = self.prepared.iter_mut().find(|prepared| {
            prepared.id == completion.id && prepared.generation == completion.generation
        }) else {
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
            .chains
            .get(chain)
            .is_some_and(|chain| child.height() <= chain.data_retired_through)
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
        let mut tip = self.chains[own_chain.get() as usize]
            .certified
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
        self.advance_produced::<H>(block);
        Ok(())
    }

    pub(crate) fn reconcile_da_choices<H: Hasher<Digest = D>>(
        &mut self,
        headers: impl IntoIterator<Item = TransactionBlockHeader<D>>,
    ) -> Result<(), ChainError> {
        for chain in &mut self.chains {
            chain.local_da_votes.clear();
        }
        for header in headers {
            self.insert_da_choice::<H>(header)?;
        }
        // Recovered choices arrive in no particular order, so rebuild every prefix once the set
        // is complete rather than relying on insertion to close each gap in turn.
        for chain in 0..self.chains.len() {
            self.chains[chain].da_voted_run = self.chains[chain].data_retired_through;
            self.chase_da_voted_run(chain);
        }
        for chain in 0..self.chains.len() {
            let mut height = self.chains[chain]
                .data_retired_through
                .get()
                .checked_add(1)
                .ok_or(ChainError::HeightOverflow)?;
            while height <= self.chains[chain].da_safe_through.get() {
                if !self.chains[chain]
                    .local_da_votes
                    .contains_key(&Height::new(height))
                {
                    return Err(ChainError::DaVoteConflict);
                }
                if height == self.chains[chain].da_safe_through.get() {
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
            .chain(
                self.chains
                    .iter()
                    .flat_map(|chain| chain.local_da_votes.values())
                    .map(|choice| &choice.header),
            )
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

    pub(crate) fn observe_da_choice<H: Hasher<Digest = D>>(
        &mut self,
        header: &TransactionBlockHeader<D>,
    ) -> Result<(), ChainError> {
        let chain = header.chain().get() as usize;
        if self.chains[chain]
            .pending_da_votes
            .front()
            .is_some_and(|pending| pending != header)
        {
            return Err(ChainError::DaVoteConflict);
        }
        self.insert_da_choice::<H>(header.clone())?;
        if self.chains[chain].pending_da_votes.front() == Some(header) {
            self.chains[chain].pending_da_votes.pop_front();
        }
        self.emit_validator_chosen(chain);
        Ok(())
    }

    fn insert_da_choice<H: Hasher<Digest = D>>(
        &mut self,
        header: TransactionBlockHeader<D>,
    ) -> Result<(), ChainError> {
        let chain = header.chain().get() as usize;
        let retired = self
            .chains
            .get(chain)
            .ok_or(ChainError::Context)?
            .data_retired_through;
        if header.height() <= retired {
            return Ok(());
        }
        let safe = self.chains[chain].da_safe_through;
        if header.height() > safe {
            if safe.get().checked_add(1) != Some(header.height().get()) {
                return Err(ChainError::DaVoteConflict);
            }
            self.chains[chain].da_safe_through = header.height();
        }
        let votes = &mut self
            .chains
            .get_mut(chain)
            .ok_or(ChainError::Context)?
            .local_da_votes;
        match votes.get(&header.height()) {
            Some(existing) if existing.header != header => Err(ChainError::DaVoteConflict),
            Some(_) => Ok(()),
            None => {
                let block_ref = header.block_ref::<H>();
                votes.insert(header.height(), DaChoice { header, block_ref });
                self.chase_da_voted_run(chain);
                Ok(())
            }
        }
    }

    /// Extends a chain's contiguous DA-choice prefix over every height it now covers.
    fn chase_da_voted_run(&mut self, chain: usize) {
        let chain = &mut self.chains[chain];
        let votes = &chain.local_da_votes;
        let run = &mut chain.da_voted_run;
        let mut extended = *run;
        while let Some(next) = extended.get().checked_add(1).map(Height::new) {
            if !votes.contains_key(&next) {
                break;
            }
            extended = next;
        }
        *run = extended;
    }

    /// Returns an eligible data-availability frontier in round-robin chain order.
    ///
    /// Each chain contributes at most one run of up to `run_limit` consecutive blocks; the spec
    /// admits DA-voting a path of blocks in one timeslot, with each vote counting as sent for
    /// the eligibility of the next. `limit` bounds the total across chains.
    /// Records one chain's offered eligible run and frontier reach from its validator plane.
    ///
    /// This is the sole writer of the frontier shadow central reads at vote and proposal time. A
    /// plane's messages are FIFO, so central applies every queued offer before the read; the shadow
    /// can only lag a plane, never lead it, because central alone mints the durable choice.
    pub(crate) fn note_da_vote_ready(
        &mut self,
        chain: ChainId,
        candidates: Vec<Arc<SignedTransactionBlock<V, D>>>,
        ready_through: Height,
    ) {
        if let Some(state) = self.chains.get_mut(chain.get() as usize) {
            state.offered = candidates;
            state.ready_through = ready_through;
        }
    }

    /// Returns one chain's certified anchor: its highest retained certified block, else its genesis
    /// tip. A validator plane anchors its eligibility here and is re-seeded with it after a restart.
    pub(crate) fn certified_anchor(&self, chain: ChainId) -> BlockRef<D> {
        let index = chain.get() as usize;
        self.chains
            .get(index)
            .and_then(|state| state.certified.last_key_value())
            .map(|(_, certified)| certified.block)
            .unwrap_or_else(|| self.genesis[index])
    }

    /// Returns one chain's durable DA choices above the anchor, to re-seed a validator plane's
    /// eligibility read-copy after a restart.
    pub(crate) fn chosen_choices(&self, chain: ChainId) -> Vec<DaChoice<D>> {
        self.chains
            .get(chain.get() as usize)
            .map(|state| state.local_da_votes.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the eligible data-availability-vote frontier in round-robin chain order.
    ///
    /// Each chain's validator plane pre-computes its contiguous eligible run off-thread and offers
    /// it through `note_da_vote_ready`; this drains those offers instead of scanning a block store.
    /// A chain with a reservation in flight is skipped (one unacknowledged run at a time), and the
    /// already-voted prefix is filtered so a lagging offer never re-proposes a durable choice.
    pub(crate) fn ready_da_votes(
        &self,
        profile: &Profile<impl Hasher<Digest = D>, V>,
        limit: usize,
        run_limit: usize,
    ) -> Result<Vec<Arc<SignedTransactionBlock<V, D>>>, ChainError> {
        if !matches!(profile.role(), Role::Validator(_)) || limit == 0 || run_limit == 0 {
            return Ok(Vec::new());
        }
        let mut ready = Vec::with_capacity(limit.min(self.chains.len()));
        for offset in 0..self.chains.len() {
            let index = (self.next_da_chain + offset) % self.chains.len();
            if !self.chains[index].pending_da_votes.is_empty() {
                continue;
            }
            let remaining = limit - ready.len();
            ready.extend(self.eligible_offered(index, run_limit.min(remaining)));
            if ready.len() == limit {
                break;
            }
        }
        Ok(ready)
    }

    /// Returns one chain's offered eligible run above its durable DA-vote frontier, up to `cap`.
    ///
    /// The offer is a contiguous validated run above the plane's anchor; filtering to heights above
    /// the durable `da_voted_run` drops any prefix a not-yet-synced plane still lists as unvoted, so
    /// central never re-proposes a height it already chose. The reducer's safety-extension check is
    /// the final authority on which prefix it reserves.
    fn eligible_offered(&self, chain: usize, cap: usize) -> Vec<Arc<SignedTransactionBlock<V, D>>> {
        let voted = self.chains[chain].da_voted_run;
        self.chains[chain]
            .offered
            .iter()
            .filter(|block| block.header().height() > voted)
            .take(cap)
            .cloned()
            .collect()
    }

    /// Returns the chain of the first offered eligible vote `select` accepts, in round-robin order.
    pub(crate) fn selected_da_chain(
        &self,
        profile: &Profile<impl Hasher<Digest = D>, V>,
        mut select: impl FnMut(ChainId, Height) -> bool,
    ) -> Result<Option<ChainId>, ChainError> {
        if !matches!(profile.role(), Role::Validator(_)) {
            return Ok(None);
        }
        for offset in 0..self.chains.len() {
            let index = (self.next_da_chain + offset) % self.chains.len();
            if !self.chains[index].pending_da_votes.is_empty() {
                continue;
            }
            let Some(block) = self.eligible_offered(index, 1).into_iter().next() else {
                continue;
            };
            let header = block.header();
            if select(header.chain(), header.height()) {
                return Ok(Some(header.chain()));
            }
        }
        Ok(None)
    }

    pub(crate) fn mark_da_vote_reserved(&mut self, header: TransactionBlockHeader<D>) {
        let chain = header.chain().get() as usize;
        self.next_da_chain = (chain + 1) % self.chains.len();
        self.chains[chain].pending_da_votes.push_back(header);
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

    /// Builds one chain's proposal: the anchor, then this node's own DA choices for consecutive
    /// heights above it, up to the policy's budget and the local DA frontier.
    ///
    /// The anchor sits at the highest certificate this node holds on the chain, so nothing above
    /// it can be certified here: a [`ProposalPolicy::Certified`] proposal is its anchor alone.
    pub(crate) fn propose_chain<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        tip: BlockRef<D>,
    ) -> Result<ChainProposal<V, D>, ChainError> {
        let chain = tip.chain().get() as usize;
        let state = self.chains.get(chain).ok_or(ChainError::Context)?;
        let certified = state
            .certified
            .range(..)
            .rev()
            .take_while(|(height, _)| **height > tip.height())
            .find_map(|(_, certified)| {
                certified
                    .certificate
                    .clone()
                    .map(|certificate| (certificate, certified.block))
            });
        let (anchor, mut parent) = match certified {
            Some((certificate, block)) => (Anchor::Certificate(certificate), block),
            None => (Anchor::Tip(tip), tip),
        };
        let pipeline_depth = profile.protocol().codec_config().pipeline_depth();
        let budget = match profile.proposal_policy() {
            ProposalPolicy::Certified => 0,
            ProposalPolicy::Endorsed => pipeline_depth,
        };
        let mut payloads = Vec::with_capacity(budget);
        while payloads.len() < budget {
            let Some(height) = parent.height().get().checked_add(1).map(Height::new) else {
                break;
            };
            let Some(choice) = state
                .local_da_votes
                .get(&height)
                .filter(|choice| choice.header.parent() == parent.digest())
            else {
                break;
            };
            payloads.push(choice.header.body_digest());
            parent = choice.block_ref;
        }
        ChainProposal::new(tip.chain(), anchor, payloads, pipeline_depth)
            .map_err(|_| ChainError::Context)
    }

    #[cfg(test)]
    pub(crate) fn proposal<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H, V>,
        tip: BlockRef<D>,
    ) -> Result<ChainProposal<V, D>, ChainError> {
        self.propose_chain::<H>(profile, tip)
    }

    pub(crate) fn begin_vote_body_pass(
        &self,
        profile: &Profile<impl Hasher<Digest = D>, V>,
        leader: LeaderBlock<V, D>,
    ) -> VoteBodyPass<V, D> {
        #[cfg(not(target_arch = "wasm32"))]
        let span = info_span!(
            "multimmit.vote.build",
            epoch = leader.round().epoch().get().traced(),
            view = leader.round().view().get().traced(),
            extension_bound = profile.protocol().codec_config().extension_bound().traced(),
            complete = false,
            eligible_extensions = tracing::field::Empty,
            short_chains = tracing::field::Empty,
            extension_cap_chains = tracing::field::Empty,
            late_da_chains = tracing::field::Empty,
        );
        VoteBodyPass {
            leader,
            da_frontiers: self
                .chains
                .iter()
                .map(|chain| {
                    chain
                        .local_da_votes
                        .last_key_value()
                        .map_or(Height::zero(), |(height, _)| *height)
                })
                .collect(),
            chain: 0,
            positions: Vec::with_capacity(profile.protocol().codec_config().chains()),
            extensions: Vec::with_capacity(profile.protocol().codec_config().chains()),
            extension_bound: profile.protocol().codec_config().extension_bound(),
            #[cfg(not(target_arch = "wasm32"))]
            span: Some(span),
        }
    }

    /// Advances one vote-body pass by one chain: the endorsed proposal prefix, then up to the
    /// extension bound of this node's DA choices above it.
    ///
    /// Each chain costs at most the pipelining depth plus the extension bound of map lookups, so a
    /// step is cheap however deep the proposal reaches, and a body for every chain completes
    /// within a single drive rather than trickling out one payload entry per credit.
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
            #[cfg(not(target_arch = "wasm32"))]
            if let Some(span) = pass.span.take()
                && !span.is_disabled()
            {
                let mut eligible_extensions = 0usize;
                let mut short_chains = 0usize;
                let mut extension_cap_chains = 0usize;
                for ((proposal, position), extension) in pass
                    .leader
                    .proposals()
                    .iter()
                    .zip(&pass.positions)
                    .zip(&pass.extensions)
                {
                    let position = position.get() as usize;
                    let full = position == proposal.payloads().len();
                    if full {
                        eligible_extensions += extension.len();
                    }
                    short_chains += usize::from(!full);
                    extension_cap_chains += usize::from(
                        pass.extension_bound > 0 && extension.len() == pass.extension_bound,
                    );
                }
                // A later DA choice can miss this vote's immutable snapshot even while body
                // construction is still yielding between chains.
                let late_da_chains = self
                    .chains
                    .iter()
                    .zip(&pass.da_frontiers)
                    .filter(|(chain, frozen)| {
                        chain
                            .local_da_votes
                            .last_key_value()
                            .is_some_and(|(height, _)| height > *frozen)
                    })
                    .count();
                span.record("eligible_extensions", eligible_extensions.traced());
                span.record("short_chains", short_chains.traced());
                span.record("extension_cap_chains", extension_cap_chains.traced());
                span.record("late_da_chains", late_da_chains.traced());
                span.record("complete", true);
            }
            return Ok(VoteBodyProgress::Complete(body));
        }

        let proposal = &pass.leader.proposals()[pass.chain];
        let votes = &self
            .chains
            .get(pass.chain)
            .ok_or(ChainError::Context)?
            .local_da_votes;
        let frontier = *pass
            .da_frontiers
            .get(pass.chain)
            .ok_or(ChainError::Context)?;
        let mut parent = proposal.anchor().block_ref::<H>();
        let mut position = 0usize;
        for payload in proposal.payloads() {
            let Some(choice) = Self::next_da_choice(votes, parent, frontier, pass.chain) else {
                break;
            };
            if choice.header.body_digest() != *payload {
                break;
            }
            position += 1;
            parent = choice.block_ref;
        }
        let mut extension_payloads = Vec::with_capacity(pass.extension_bound);
        while extension_payloads.len() < pass.extension_bound {
            let Some(choice) = Self::next_da_choice(votes, parent, frontier, pass.chain) else {
                break;
            };
            extension_payloads.push(choice.header.body_digest());
            parent = choice.block_ref;
        }
        let position = u32::try_from(position).map_err(|_| ChainError::Context)?;
        pass.positions.push(Position::new(position));
        pass.extensions.push(
            Extension::new(extension_payloads, pass.extension_bound)
                .map_err(|_| ChainError::Context)?,
        );
        pass.chain += 1;
        Ok(VoteBodyProgress::Pending)
    }

    /// Returns this node's DA choice for the block above `parent`, when it lies within the frozen
    /// frontier and extends `parent` on `chain`.
    fn next_da_choice(
        votes: &BTreeMap<Height, DaChoice<D>>,
        parent: BlockRef<D>,
        frontier: Height,
        chain: usize,
    ) -> Option<&DaChoice<D>> {
        let height = Height::new(parent.height().get().checked_add(1)?);
        if height > frontier {
            return None;
        }
        let choice = votes.get(&height)?;
        (choice.header.chain().get() as usize == chain && choice.header.parent() == parent.digest())
            .then_some(choice)
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
            let votes = &self
                .chains
                .get(index)
                .ok_or(ChainError::Context)?
                .local_da_votes;
            let mut parent = proposal.anchor().block_ref::<H>();
            let mut position = 0usize;

            for payload in proposal.payloads() {
                let Some(height) = parent.height().get().checked_add(1).map(Height::new) else {
                    break;
                };
                let Some(choice) = votes.get(&height) else {
                    break;
                };
                let header = &choice.header;
                if header.chain() != chain
                    || header.parent() != parent.digest()
                    || header.body_digest() != *payload
                {
                    break;
                }
                position += 1;
                parent = choice.block_ref;
            }

            let mut payloads = Vec::with_capacity(config.extension_bound());
            for _ in 0..config.extension_bound() {
                let Some(height) = parent.height().get().checked_add(1).map(Height::new) else {
                    break;
                };
                let Some(choice) = votes.get(&height) else {
                    break;
                };
                let header = &choice.header;
                if header.chain() != chain || header.parent() != parent.digest() {
                    break;
                }
                payloads.push(header.body_digest());
                parent = choice.block_ref;
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

    pub(crate) fn drive<H: Hasher<Digest = D>>(
        &mut self,
        profile: &Profile<H, V>,
        generation: u64,
        production_credit: bool,
    ) -> Result<(), ChainError> {
        self.production_credit = production_credit;
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
        let certified = self.chains[parent.chain().get() as usize]
            .certified
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

    pub(crate) fn take_effects(&mut self) -> Vec<ChainEffect<V, D>> {
        std::mem::take(&mut self.capabilities)
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
