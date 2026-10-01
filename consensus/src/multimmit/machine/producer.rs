//! The local producer's build pipeline: application builds, custody, and signing of its own
//! chain's blocks.
//!
//! Each block moves through a build, where the application selects a payload against an
//! immutable parent, then custody, where the application proves that payload valid and durably
//! retrievable, then signing of its header. Builds may run ahead of certification by the
//! pipeline depth, but only a custody completion grants signing authority. Observers have no
//! producer.

use super::{
    capability::{AppJob, Capability, TimerCommand},
    chain::{ChainError, ChainState},
    durability::SignRequest,
    job::{Generation, IdSequence, Issued, SequenceId},
};
use crate::{
    multimmit::types::{BlockRef, ChainId, TransactionBlockHeader},
    types::Height,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::time::Duration;
use std::collections::{BTreeMap, VecDeque};

/// Identifies one volatile application build request within a process generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct BuildId(u64);

impl SequenceId for BuildId {
    fn at(sequence: u64) -> Self {
        Self(sequence)
    }
}

/// Application build request for the local producer's next block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BuildJob<D: Digest> {
    issued: Issued<BuildId>,
    parent: BlockRef<D>,
}

impl<D: Digest> BuildJob<D> {
    /// Returns the job's identity and issuing generation.
    pub(crate) const fn issued(&self) -> Issued<BuildId> {
        self.issued
    }

    /// Returns the producer parent.
    pub(crate) const fn parent(&self) -> BlockRef<D> {
        self.parent
    }
}

/// Completion of one application build request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct BuildCompletion<D: Digest> {
    issued: Issued<BuildId>,
    parent: BlockRef<D>,
    commitment: Option<D>,
}

impl<D: Digest> BuildCompletion<D> {
    /// Creates a matched build completion. `None` reports that no work was selected.
    ///
    /// A present commitment identifies a complete block selected by the attached application. The
    /// machine prepares descendants from this identity, but grants no signing authority until a
    /// matching [`CustodyCompletion`] proves the payload valid and durably retrievable.
    pub(crate) const fn new(
        issued: Issued<BuildId>,
        parent: BlockRef<D>,
        commitment: Option<D>,
    ) -> Self {
        Self {
            issued,
            parent,
            commitment,
        }
    }
}

/// Application custody request for one locally prepared producer block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CustodyJob<D: Digest> {
    issued: Issued<BuildId>,
    header: TransactionBlockHeader<D>,
}

impl<D: Digest> CustodyJob<D> {
    /// Returns the originating build's identity and issuing generation.
    pub(crate) const fn issued(&self) -> Issued<BuildId> {
        self.issued
    }

    /// Returns the prepared header whose body must enter custody.
    pub(crate) const fn header(&self) -> &TransactionBlockHeader<D> {
        &self.header
    }
}

/// Successful validation and durable custody of one locally prepared block.
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
}

/// Cancellation of custody work for one superseded prepared block.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct CustodyCancellation {
    issued: Issued<BuildId>,
}

impl CustodyCancellation {
    pub(crate) const fn new(issued: Issued<BuildId>) -> Self {
        Self { issued }
    }

    /// Returns the cancelled build's identity and issuing generation.
    pub(crate) const fn issued(self) -> Issued<BuildId> {
        self.issued
    }
}

/// A production deadline bound to one local parent.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProductionTimer<D: Digest> {
    generation: Generation,
    parent: BlockRef<D>,
    delay: Duration,
}

impl<D: Digest> ProductionTimer<D> {
    /// Returns the parent from which elapsed production time is measured.
    pub(crate) const fn parent(self) -> BlockRef<D> {
        self.parent
    }

    /// Returns the logical delay requested from the runtime.
    pub(crate) const fn delay(self) -> Duration {
        self.delay
    }
}

#[cfg(test)]
impl<D: Digest> ProductionTimer<D> {
    /// Returns the process generation owning this deadline.
    pub(crate) const fn generation(self) -> Generation {
        self.generation
    }
}

/// A locally built header moving through custody and signing.
#[derive(Clone, Debug)]
struct PreparedBuild<D: Digest> {
    issued: Issued<BuildId>,
    header: TransactionBlockHeader<D>,
    state: PreparedState,
}

/// How far a prepared build has moved toward signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedState {
    AwaitingCustody,
    Custodied,
    Reserved,
}

/// The local producer's current build and DA-certificate state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProducerProgress {
    chain: ChainId,
    produced: Height,
    certified: Height,
    da_quorum: usize,
    pipeline_depth: u64,
    prepared: usize,
    pipeline_blocked: bool,
    wake: bool,
    timer_armed: bool,
    build_pending: bool,
    production_credit: bool,
}

impl ProducerProgress {
    /// Returns the local producer chain.
    pub const fn chain(self) -> ChainId {
        self.chain
    }

    /// Returns the latest locally produced height.
    pub const fn produced(self) -> Height {
        self.produced
    }

    /// Returns the latest locally held DA-certified height.
    pub const fn certified(self) -> Height {
        self.certified
    }

    /// Returns the DA share quorum.
    pub const fn da_quorum(self) -> usize {
        self.da_quorum
    }

    /// Returns the configured producer pipeline depth.
    pub const fn pipeline_depth(self) -> u64 {
        self.pipeline_depth
    }

    /// Returns locally prepared producer blocks not yet reserved for signing.
    pub const fn prepared(self) -> usize {
        self.prepared
    }

    /// Returns whether production has a pending wake.
    pub const fn wake(self) -> bool {
        self.wake
    }

    /// Returns whether the production delay timer is armed.
    pub const fn timer_armed(self) -> bool {
        self.timer_armed
    }

    /// Returns whether an application build is pending.
    pub const fn build_pending(self) -> bool {
        self.build_pending
    }

    /// Returns whether durable-effect capacity permits another build.
    pub const fn production_credit(self) -> bool {
        self.production_credit
    }

    /// Returns whether another build is blocked by the DA pipeline window.
    pub const fn pipeline_blocked(self) -> bool {
        self.pipeline_blocked
    }
}

/// What a build completion did to the pipeline.
pub(crate) enum BuildOutcome {
    Stale,
    Superseded,
    Empty,
    Prepared,
}

/// The local producer's pipeline for its own chain.
pub(crate) struct ProducerState<D: Digest> {
    /// The chain this node produces.
    pub(super) chain: ChainId,
    /// The newest block of this node's chain that it produced or adopted.
    pub(super) produced: BlockRef<D>,
    /// This node's signed producer headers above its newest durable certificate, by height.
    pub(super) headers: BTreeMap<Height, TransactionBlockHeader<D>>,
    deadline: Option<ProductionTimer<D>>,
    pending_build: Option<BuildJob<D>>,
    prepared: VecDeque<PreparedBuild<D>>,
    cancelling_custody: BTreeMap<BuildId, Generation>,
    /// Whether the machine could fund a build when it last granted production credit.
    production_credit: bool,
    /// How long an empty build waits before the producer tries again.
    production_interval: Duration,
    /// A latched, coalescible opportunity to build.
    wake: bool,
    next_job: IdSequence<BuildId>,
}

impl<D: Digest> ProducerState<D> {
    /// Returns a producer for `chain` whose newest block is `genesis`.
    pub(super) const fn new(
        chain: ChainId,
        genesis: BlockRef<D>,
        production_interval: Duration,
    ) -> Self {
        Self {
            chain,
            produced: genesis,
            headers: BTreeMap::new(),
            deadline: None,
            pending_build: None,
            prepared: VecDeque::new(),
            cancelling_custody: BTreeMap::new(),
            production_credit: false,
            production_interval,
            wake: false,
            next_job: IdSequence::new(),
        }
    }

    /// Returns the block the next build extends: the newest prepared block, else the newest
    /// produced one.
    fn planned_tip<H: Hasher<Digest = D>>(&self) -> BlockRef<D> {
        self.prepared
            .back()
            .map_or(self.produced, |prepared| prepared.header.block_ref::<H>())
    }
}

impl<V: Variant, D: Digest> ChainState<V, D> {
    /// Returns the own chain's production state, if this node produces.
    pub(crate) fn producer_status<H: Hasher<Digest = D>>(&self) -> Option<ProducerProgress> {
        let producer = self.producer.as_ref()?;
        let certified = self.da.chains[producer.chain.index()].certified_height();

        Some(ProducerProgress {
            chain: producer.chain,
            produced: producer.produced.height(),
            certified,
            da_quorum: self.da_quorum,
            pipeline_depth: self.pipeline_depth,
            prepared: producer.prepared.len(),
            pipeline_blocked: producer
                .planned_tip::<H>()
                .height()
                .get()
                .saturating_sub(certified.get())
                >= self.pipeline_depth,
            wake: producer.wake,
            timer_armed: producer.deadline.is_some(),
            build_pending: producer.pending_build.is_some(),
            production_credit: producer.production_credit,
        })
    }

    /// Latches one coalescible opportunity for the producer to build.
    pub(crate) const fn wake_producer(&mut self) {
        if let Some(producer) = &mut self.producer {
            producer.wake = true;
        }
    }

    /// Records whether the machine can fund a build this drive.
    pub(crate) const fn set_production_credit(&mut self, credit: bool) {
        if let Some(producer) = &mut self.producer {
            producer.production_credit = credit;
        }
    }

    /// Applies an application build completion, preparing the next header when it selected a
    /// payload.
    pub(crate) fn complete_build<H: Hasher<Digest = D>>(
        &mut self,
        completion: BuildCompletion<D>,
    ) -> Result<BuildOutcome, ChainError> {
        let Some(producer) = &mut self.producer else {
            return Ok(BuildOutcome::Stale);
        };
        let Some(pending) = producer.pending_build.as_ref() else {
            return Ok(BuildOutcome::Stale);
        };
        if completion.issued != pending.issued || completion.parent != pending.parent {
            return Ok(BuildOutcome::Stale);
        }
        if producer.planned_tip::<H>() != pending.parent {
            producer.pending_build = None;
            return Ok(BuildOutcome::Superseded);
        }
        let Some(commitment) = completion.commitment else {
            let timer = ProductionTimer {
                generation: pending.issued.generation(),
                parent: pending.parent,
                delay: producer.production_interval,
            };
            producer.pending_build = None;
            producer.wake = false;
            producer.deadline = Some(timer);
            self.capabilities
                .push(Capability::Timer(TimerCommand::Production(timer)));
            return Ok(BuildOutcome::Empty);
        };

        let job = producer
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
            self.epoch,
            job.parent.chain(),
            Height::new(height),
            job.parent.digest(),
            commitment,
        )
        .map_err(|_| ChainError::HeightOverflow)?;
        producer.prepared.push_back(PreparedBuild {
            issued: job.issued,
            header: header.clone(),
            state: PreparedState::AwaitingCustody,
        });
        producer.wake = true;
        self.capabilities
            .push(Capability::Application(AppJob::Custody(CustodyJob {
                issued: job.issued,
                header,
            })));
        Ok(BuildOutcome::Prepared)
    }

    /// Accepts custody only for the prepared block that requested it.
    pub(crate) fn complete_custody(
        &mut self,
        completion: CustodyCompletion<D>,
    ) -> Result<bool, ChainError> {
        let Some(prepared) = self.producer.as_mut().and_then(|producer| {
            producer
                .prepared
                .iter_mut()
                .find(|prepared| prepared.issued == completion.issued)
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
        generation: Generation,
    ) -> Result<bool, ChainError> {
        let issued = cancellation.issued;
        if issued.generation() != generation {
            return Ok(false);
        }
        let Some(producer) = &mut self.producer else {
            return Ok(false);
        };
        let Some(pending_generation) = producer.cancelling_custody.remove(&issued.id()) else {
            return Ok(false);
        };
        if pending_generation != issued.generation() {
            return Err(ChainError::CompletionMismatch);
        }
        producer.wake = true;
        Ok(true)
    }

    /// Returns the oldest custodied producer header not yet reserved for signing.
    pub(crate) fn pending_build_sign_request(&self) -> Option<SignRequest<V, D>> {
        self.producer
            .as_ref()?
            .prepared
            .front()
            .filter(|prepared| prepared.state == PreparedState::Custodied)
            .map(|prepared| SignRequest::TransactionBlock(prepared.header.clone()))
    }

    /// Marks the oldest custodied build as reserved for signing.
    pub(crate) fn mark_build_reserved(&mut self) {
        let prepared = self
            .producer
            .as_mut()
            .and_then(|producer| producer.prepared.front_mut())
            .expect("a custodied build must remain prepared until signing is reserved");
        debug_assert_eq!(prepared.state, PreparedState::Custodied);
        prepared.state = PreparedState::Reserved;
    }

    /// Returns the number of builds and prepared blocks still holding a build reservation.
    pub(crate) fn build_reservations(&self) -> usize {
        self.producer.as_ref().map_or(0, |producer| {
            usize::from(producer.pending_build.is_some())
                + producer
                    .prepared
                    .iter()
                    .filter(|prepared| prepared.state != PreparedState::Reserved)
                    .count()
        })
    }

    /// Consumes the production deadline `timer` and returns whether it was the armed one.
    pub(crate) fn fire_timer(&mut self, timer: ProductionTimer<D>) -> bool {
        let Some(producer) = self
            .producer
            .as_mut()
            .filter(|producer| producer.deadline == Some(timer))
        else {
            return false;
        };
        producer.deadline = None;
        producer.wake = true;
        true
    }

    /// Rebuilds the producer's signed headers from recovered `headers`, failing if they do not
    /// form one chain above the newest certificate.
    pub(crate) fn reconcile<H: Hasher<Digest = D>>(
        &mut self,
        headers: impl IntoIterator<Item = TransactionBlockHeader<D>>,
    ) -> Result<(), ChainError> {
        let Some((own_chain, produced)) = self
            .producer
            .as_ref()
            .map(|producer| (producer.chain, producer.produced))
        else {
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
        let mut tip = self.da.chains[own_chain.index()]
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
        if tip.height() < produced.height() {
            return Err(ChainError::ProducerConflict);
        }
        self.producer
            .as_mut()
            .expect("the producer was checked above")
            .headers = selected;
        self.advance_produced::<H>(tip);
        Ok(())
    }

    /// Records a durably signed header of this node's own chain.
    pub(crate) fn observe_producer_choice<H: Hasher<Digest = D>>(
        &mut self,
        header: &TransactionBlockHeader<D>,
    ) -> Result<(), ChainError> {
        let Some(producer) = self
            .producer
            .as_mut()
            .filter(|producer| producer.chain == header.chain())
        else {
            return Err(ChainError::ProducerConflict);
        };
        if let Some(existing) = producer.headers.get(&header.height()) {
            return if existing == header {
                Ok(())
            } else {
                Err(ChainError::ProducerConflict)
            };
        }
        let block = header.block_ref::<H>();
        let parent = producer.produced;
        if parent.height().get().checked_add(1) != Some(header.height().get())
            || parent.digest() != header.parent()
        {
            return Err(ChainError::ProducerConflict);
        }
        producer.headers.insert(header.height(), header.clone());
        self.advance_produced::<H>(block);
        Ok(())
    }

    /// Returns whether this node produces `chain`.
    pub(crate) fn produces(&self, chain: ChainId) -> bool {
        self.producer
            .as_ref()
            .is_some_and(|producer| producer.chain == chain)
    }

    /// Returns whether `header` is one this node signed for its own chain.
    pub(crate) fn is_producer_header(&self, header: &TransactionBlockHeader<D>) -> bool {
        self.producer.as_ref().is_some_and(|producer| {
            producer.chain == header.chain()
                && producer.headers.get(&header.height()) == Some(header)
        })
    }

    /// Moves the produced tip to `tip`, discarding the prepared prefix it covers.
    pub(super) fn advance_produced<H: Hasher<Digest = D>>(&mut self, tip: BlockRef<D>) {
        let Some(producer) = &mut self.producer else {
            return;
        };
        if producer.produced == tip {
            return;
        }

        let discarded = producer
            .prepared
            .iter()
            .position(|prepared| prepared.header.block_ref::<H>() == tip)
            .map_or(producer.prepared.len(), |position| position + 1);
        for _ in 0..discarded {
            let prepared = producer
                .prepared
                .pop_front()
                .expect("the discarded prepared prefix is present");
            if prepared.state != PreparedState::AwaitingCustody {
                continue;
            }
            let previous = producer
                .cancelling_custody
                .insert(prepared.issued.id(), prepared.issued.generation());
            debug_assert!(previous.is_none());
            self.capabilities
                .push(Capability::Application(AppJob::CancelCustody(
                    CustodyCancellation::new(prepared.issued),
                )));
        }
        producer.produced = tip;
        producer.deadline = None;
        producer.wake = true;
    }

    /// Issues the next build when production credit, the pipeline window and the producer's
    /// state all allow one.
    pub(crate) fn drive<H: Hasher<Digest = D>>(
        &mut self,
        generation: Generation,
    ) -> Result<(), ChainError> {
        let Some(producer) = &mut self.producer else {
            return Ok(());
        };
        let parent = producer.planned_tip::<H>();
        if !producer.production_credit
            || !producer.wake
            || producer.deadline.is_some()
            || producer.pending_build.is_some()
            || !producer.cancelling_custody.is_empty()
        {
            return Ok(());
        }
        let certified = self.da.chains[parent.chain().index()]
            .certified
            .last_key_value()
            .map(|(height, _)| *height)
            .ok_or(ChainError::Context)?;
        let next = parent
            .height()
            .get()
            .checked_add(1)
            .ok_or(ChainError::HeightOverflow)?;
        if next.saturating_sub(certified.get()) > self.pipeline_depth {
            return Ok(());
        }
        let id = producer
            .next_job
            .issue()
            .ok_or(ChainError::IdentifierExhausted)?;
        let job = BuildJob {
            issued: Issued::new(id, generation),
            parent,
        };
        producer.wake = false;
        producer.pending_build = Some(job.clone());
        self.capabilities
            .push(Capability::Application(AppJob::Build(job)));
        Ok(())
    }
}
