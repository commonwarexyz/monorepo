//! Data-availability state per producer chain: this node's DA choices, the certified tips and
//! the certificates offered for them, and producer ancestry.
//!
//! A DA choice is this node's one DA vote at one height of one chain, and the choices mirror
//! durable state. Certificates are offered per block; the earliest verified one becomes the
//! chain's certified tip, and blocks that equivocate at one height keep separate candidates.

use super::{
    chain::ChainError,
    util::{ObservedList, retire_prefix},
    verification::Observation,
};
use crate::{
    multimmit::types::{
        ArtifactId, BlockRef, ChainId, DaCertificate, SignedTransactionBlock,
        TransactionBlockHeader,
    },
    types::Height,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::ops::Bound;
use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    sync::Arc,
};

/// This node's DA vote at one height of one chain.
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
}

#[cfg(test)]
impl<D: Digest> DaChoice<D> {
    /// Builds a choice directly, for chain-plane unit tests that seed the read-copy.
    pub(crate) const fn for_test(
        header: TransactionBlockHeader<D>,
        block_ref: BlockRef<D>,
    ) -> Self {
        Self { header, block_ref }
    }
}

/// A certified block and, once held, its certificate.
#[derive(Clone, Debug)]
pub(super) struct Certified<V: Variant, D: Digest> {
    pub(super) block: BlockRef<D>,
    pub(super) certificate: Option<DaCertificate<V, D>>,
}

/// One certificate offered for a block, and whether its verification completed.
#[derive(Clone, Debug)]
struct CertificateCandidate<V: Variant, D: Digest> {
    certificate: DaCertificate<V, D>,
    ready: bool,
}

/// Certificates offered for one block by artifact, earliest first.
type CertificateCandidates<V, D> = ObservedList<ArtifactId<D>, CertificateCandidate<V, D>>;

/// Data-availability state for one producer chain.
///
/// `local_da_votes` mirrors the durable DA choices. Every other field is derived from admitted
/// artifacts and durable anchors, so it can be dropped and rebuilt without changing normalized
/// protocol state.
pub(super) struct PerChainDa<V: Variant, D: Digest> {
    /// This node's DA choices by height, mirroring durable state.
    pub(super) local_da_votes: BTreeMap<Height, DaChoice<D>>,
    /// A height through which every integer height above `data_retired_through` is already a local
    /// DA choice.
    ///
    /// Eligibility scans resume above this height instead of rediscovering the voted prefix on
    /// every pass. The value is a lower bound: an entry below the true contiguous run only costs
    /// a longer scan, so a missed extension can never hide an eligible block.
    pub(super) da_voted_run: Height,
    pub(super) da_safe_through: Height,
    pub(super) data_retired_through: Height,
    /// Reserved DA votes whose signing is in flight, in ascending height order.
    ///
    /// A chain reserves at most one run at a time; completions consume the queue front in
    /// order, so the queue is also the expected application sequence.
    pub(super) pending_da_votes: VecDeque<TransactionBlockHeader<D>>,
    pub(super) certified: BTreeMap<Height, Certified<V, D>>,
    /// Certificates offered for blocks not yet certified, by height and then block, so blocks
    /// that equivocate at one height keep separate candidates.
    candidates: BTreeMap<Height, BTreeMap<BlockRef<D>, CertificateCandidates<V, D>>>,
    /// The parent each observed header names, by height and then block.
    ancestry: BTreeMap<Height, BTreeMap<BlockRef<D>, BlockRef<D>>>,
    /// The contiguous eligible DA-vote run this chain's chain plane last offered, lowest height
    /// first. The machine drains it in its reservation loop and reads it synchronously at vote and
    /// proposal time as its copy of the plane's eligible frontier.
    offered: Vec<Arc<SignedTransactionBlock<V, D>>>,
    /// The greatest height `offered` reaches, or the certified anchor when empty. A safe lower bound
    /// on the plane's true frontier, since the machine mints every durable choice.
    pub(super) ready_through: Height,
}

impl<V: Variant, D: Digest> PerChainDa<V, D> {
    fn new(genesis: BlockRef<D>) -> Self {
        Self {
            local_da_votes: BTreeMap::new(),
            da_voted_run: genesis.height(),
            da_safe_through: genesis.height(),
            data_retired_through: genesis.height(),
            pending_da_votes: VecDeque::new(),
            certified: BTreeMap::from([(
                genesis.height(),
                Certified {
                    block: genesis,
                    certificate: None,
                },
            )]),
            candidates: BTreeMap::new(),
            ancestry: BTreeMap::new(),
            offered: Vec::new(),
            ready_through: genesis.height(),
        }
    }

    /// Returns the greatest height holding a DA certificate, or zero when none is held.
    pub(super) fn certified_height(&self) -> Height {
        self.certified
            .iter()
            .rev()
            .find(|(_, certified)| certified.certificate.is_some())
            .map_or(Height::zero(), |(height, _)| *height)
    }

    /// Returns the certificates offered for `block`.
    fn candidates_mut(&mut self, block: BlockRef<D>) -> &mut CertificateCandidates<V, D> {
        self.candidates
            .entry(block.height())
            .or_default()
            .entry(block)
            .or_default()
    }

    /// Removes and returns the certificates offered for `block`.
    fn take_candidates(&mut self, block: BlockRef<D>) -> Option<CertificateCandidates<V, D>> {
        let at_height = self.candidates.get_mut(&block.height())?;
        let candidates = at_height.remove(&block);
        if at_height.is_empty() {
            self.candidates.remove(&block.height());
        }
        candidates
    }
}

/// Data-availability state for every producer chain, indexed by [`ChainId`].
pub(crate) struct DaState<V: Variant, D: Digest> {
    /// Each chain's genesis tip, below which nothing is retained.
    pub(super) genesis: Vec<BlockRef<D>>,
    pub(super) chains: Vec<PerChainDa<V, D>>,
    /// The chain after the last DA-vote reservation, where round-robin selection resumes.
    next_da_chain: usize,
    /// Certificates dropped when another candidate for their block was installed.
    discarded_certificates: Vec<ArtifactId<D>>,
}

impl<V: Variant, D: Digest> DaState<V, D> {
    /// Creates DA state with each chain certified at its genesis tip.
    pub(super) fn new(genesis: Vec<BlockRef<D>>) -> Self {
        let chains = genesis.iter().copied().map(PerChainDa::new).collect();
        Self {
            genesis,
            chains,
            next_da_chain: 0,
            discarded_certificates: Vec::new(),
        }
    }

    /// Installs producer-chain certificates carried by an admitted leader block.
    pub(crate) fn install_anchors<H: Hasher<Digest = D>>(
        &mut self,
        anchors: impl IntoIterator<Item = DaCertificate<V, D>>,
    ) -> Result<(), ChainError> {
        for certificate in anchors {
            let block = certificate.block_ref::<H>();
            let Some(chain) = self.chains.get(block.chain().index()) else {
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

    /// Restores the durable DA state used to bound each chain's live suffix.
    pub(crate) fn restore(
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
            let chain = &mut self.chains[index];
            chain.da_safe_through = safe[index];
            chain.data_retired_through = tip.height();
            chain.da_voted_run = chain.da_voted_run.max(tip.height());
            if tip != applied {
                chain.certified.insert(
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

    /// Retires one chain's state at or below `retired` after `block` became its durable
    /// certified tip, keeping one pipelining depth of DA choices below the floor.
    pub(super) fn retire(&mut self, block: BlockRef<D>, retired: Height, pipeline_depth: u64) {
        let index = block.chain().index();
        let genesis = self.genesis[index].height();
        let chain = &mut self.chains[index];
        chain.certified.retain(|height, certified| {
            *height == genesis || *height > retired || certified.block == block
        });
        // A vote reports positions from the leader's anchor, and a leader anchors at the newest
        // certificate it held when it proposed. Certificates keep arriving while the proposal
        // travels, so a voter's own certified floor commonly passes that anchor before it votes.
        // Choices at or below the floor add no availability, but they are exactly the record a
        // vote needs to endorse the leader's payloads, so keep one pipelining depth of them.
        let kept = Height::new(retired.get().saturating_sub(pipeline_depth));
        chain.local_da_votes.retain(|height, _| *height > kept);
        // Retirement only drops choices below the retained window, so the prefix above the new
        // floor stays contiguous; raising the cursor to the floor keeps it a valid lower bound.
        chain.da_voted_run = chain.da_voted_run.max(retired);
        retire_prefix(&mut chain.candidates, |height| *height <= retired);
        retire_prefix(&mut chain.ancestry, |height| *height <= retired);
        chain
            .pending_da_votes
            .retain(|header| header.height() > retired);
        // A node DA-votes only a contiguous path above its newest durable certificate, so the
        // certificate becomes that path's base. Lower choices can no longer add availability, so
        // retiring them keeps the local suffix pipeline-bounded.
        chain.da_safe_through = chain.da_safe_through.max(block.height());
        chain.data_retired_through = retired;
    }

    /// Returns one chain's DA choices above its retired floor.
    pub(super) fn choices_above_floor(&self, chain: ChainId) -> Vec<DaChoice<D>> {
        let state = &self.chains[chain.index()];
        let retired = state.data_retired_through;
        state
            .local_da_votes
            .range(Height::new(retired.get().saturating_add(1))..)
            .map(|(_, choice)| choice.clone())
            .collect()
    }

    /// Returns the data-availability certificate this node holds for `block`, if any.
    pub(crate) fn held_certificate(&self, block: BlockRef<D>) -> Option<&DaCertificate<V, D>> {
        let certified = self
            .chains
            .get(block.chain().index())?
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

    /// Returns a held certificate above a chain's tip in `floors`, trying `preferred` first and
    /// then chains in order.
    pub(crate) fn next_certificate_above(
        &self,
        floors: &[BlockRef<D>],
        preferred: Option<ChainId>,
    ) -> Option<DaCertificate<V, D>> {
        let preferred = preferred.map(ChainId::index);
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

    /// Records an unverified certificate for its block and returns whether the block still
    /// needs one.
    pub(crate) fn claim_certificate<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        certificate: &DaCertificate<V, D>,
    ) -> Result<bool, ChainError> {
        let block = certificate.block_ref::<H>();
        if block.chain().index() >= self.chains.len() {
            return Err(ChainError::Context);
        }
        if self.certificate_settled(block) {
            return Ok(false);
        }
        self.chains[block.chain().index()]
            .candidates_mut(block)
            .upsert_min(id, observation, || CertificateCandidate {
                certificate: certificate.clone(),
                ready: false,
            });
        Ok(true)
    }

    /// Drops a certificate that failed verification and promotes the next ready candidate.
    pub(super) fn reject_certificate<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        certificate: &DaCertificate<V, D>,
    ) -> Result<(), ChainError> {
        let block = certificate.block_ref::<H>();
        if let Some(chain) = self.chains.get_mut(block.chain().index())
            && let Some(at_height) = chain.candidates.get_mut(&block.height())
            && let Some(candidates) = at_height.get_mut(&block)
        {
            candidates.remove(id);
            if candidates.is_empty() {
                chain.take_candidates(block);
            }
        }
        self.promote_certificate(block)
    }

    /// Marks a verified certificate ready and installs the earliest ready candidate.
    pub(super) fn observe_certificate<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        certificate: &DaCertificate<V, D>,
    ) -> Result<(), ChainError> {
        let block = certificate.block_ref::<H>();
        if self.certificate_settled(block) {
            return Ok(());
        }
        self.chains[block.chain().index()]
            .candidates_mut(block)
            .upsert_min(id, observation, || CertificateCandidate {
                certificate: certificate.clone(),
                ready: true,
            })
            .ready = true;
        self.promote_certificate(block)
    }

    /// Returns whether `block` needs no further certificate: a higher height on its chain is
    /// already certified, or `block` itself holds one.
    fn certificate_settled(&self, block: BlockRef<D>) -> bool {
        let certified = &self.chains[block.chain().index()].certified;
        certified
            .last_key_value()
            .is_some_and(|(height, _)| *height > block.height())
            || certified.get(&block.height()).is_some_and(|certified| {
                certified.block == block && certified.certificate.is_some()
            })
    }

    fn promote_certificate(&mut self, block: BlockRef<D>) -> Result<(), ChainError> {
        let Some(chain) = self.chains.get_mut(block.chain().index()) else {
            return Ok(());
        };
        let Some(candidates) = chain
            .candidates
            .get(&block.height())
            .and_then(|at_height| at_height.get(&block))
        else {
            return Ok(());
        };
        let Some((selected, first)) = candidates.first() else {
            chain.take_candidates(block);
            return Ok(());
        };
        if !first.value.ready {
            return Ok(());
        }
        let certificate = first.value.certificate.clone();
        let candidates = chain
            .take_candidates(block)
            .expect("certificate candidates were just inspected");
        for (candidate, _) in candidates.iter() {
            if candidate == selected {
                continue;
            }
            self.discarded_certificates.push(candidate);
        }

        self.install_certificate(block, certificate)
    }

    /// Installs `certificate` for `block`, or fails if another block is certified at its height.
    pub(super) fn install_certificate(
        &mut self,
        block: BlockRef<D>,
        certificate: DaCertificate<V, D>,
    ) -> Result<(), ChainError> {
        let chain = &mut self
            .chains
            .get_mut(block.chain().index())
            .ok_or(ChainError::Context)?
            .certified;
        match chain.entry(block.height()) {
            Entry::Occupied(existing) if existing.get().block != block => {
                return Err(ChainError::CertifiedConflict);
            }
            Entry::Occupied(mut existing) => {
                existing.get_mut().certificate = Some(certificate);
            }
            Entry::Vacant(entry) => {
                entry.insert(Certified {
                    block,
                    certificate: Some(certificate),
                });
            }
        }
        Ok(())
    }

    /// Takes the certificate artifacts dropped since the last call.
    pub(crate) fn take_discarded_certificates(&mut self) -> Vec<ArtifactId<D>> {
        std::mem::take(&mut self.discarded_certificates)
    }

    /// Records the parent a header names and returns false when it contradicts the parent
    /// already recorded for that block.
    pub(super) fn record_header<H: Hasher<Digest = D>>(
        &mut self,
        header: &TransactionBlockHeader<D>,
    ) -> Result<bool, ChainError> {
        let height = header
            .height()
            .get()
            .checked_sub(1)
            .ok_or(ChainError::Context)?;
        let child = header.block_ref::<H>();
        let chain = self
            .chains
            .get_mut(child.chain().index())
            .ok_or(ChainError::Context)?;
        if child.height() <= chain.data_retired_through {
            return Ok(true);
        }
        let parent = BlockRef::new(header.chain(), Height::new(height), header.parent());
        let recorded = chain.ancestry.entry(child.height()).or_default();
        if recorded
            .get(&child)
            .is_some_and(|existing| *existing != parent)
        {
            return Ok(false);
        }
        recorded.entry(child).or_insert(parent);
        Ok(true)
    }

    /// Replaces every chain's DA choices with the recovered `headers`.
    pub(crate) fn reconcile_choices<H: Hasher<Digest = D>>(
        &mut self,
        headers: impl IntoIterator<Item = TransactionBlockHeader<D>>,
    ) -> Result<(), ChainError> {
        for chain in &mut self.chains {
            chain.local_da_votes.clear();
        }
        for header in headers {
            self.insert_choice::<H>(header)?;
        }
        // Recovered choices arrive in no particular order, so rebuild every prefix once the set
        // is complete rather than relying on insertion to close each gap in turn.
        for chain in 0..self.chains.len() {
            self.chains[chain].da_voted_run = self.chains[chain].data_retired_through;
            self.chase_voted_run(chain);
        }
        for chain in &self.chains {
            let first = chain
                .data_retired_through
                .get()
                .checked_add(1)
                .ok_or(ChainError::HeightOverflow)?;
            if !(first..=chain.da_safe_through.get())
                .all(|height| chain.local_da_votes.contains_key(&Height::new(height)))
            {
                return Err(ChainError::DaVoteConflict);
            }
        }
        Ok(())
    }

    /// Records one durable DA choice, consuming the matching in-flight reservation.
    pub(super) fn observe_choice<H: Hasher<Digest = D>>(
        &mut self,
        header: &TransactionBlockHeader<D>,
    ) -> Result<(), ChainError> {
        let chain = header.chain().index();
        if self.chains[chain]
            .pending_da_votes
            .front()
            .is_some_and(|pending| pending != header)
        {
            return Err(ChainError::DaVoteConflict);
        }
        self.insert_choice::<H>(header.clone())?;
        if self.chains[chain].pending_da_votes.front() == Some(header) {
            self.chains[chain].pending_da_votes.pop_front();
        }
        Ok(())
    }

    fn insert_choice<H: Hasher<Digest = D>>(
        &mut self,
        header: TransactionBlockHeader<D>,
    ) -> Result<(), ChainError> {
        let chain = header.chain().index();
        let state = self.chains.get_mut(chain).ok_or(ChainError::Context)?;
        if header.height() <= state.data_retired_through {
            return Ok(());
        }
        let safe = state.da_safe_through;
        if header.height() > safe {
            if safe.get().checked_add(1) != Some(header.height().get()) {
                return Err(ChainError::DaVoteConflict);
            }
            state.da_safe_through = header.height();
        }
        match state.local_da_votes.get(&header.height()) {
            Some(existing) if existing.header != header => Err(ChainError::DaVoteConflict),
            Some(_) => Ok(()),
            None => {
                let block_ref = header.block_ref::<H>();
                state
                    .local_da_votes
                    .insert(header.height(), DaChoice { header, block_ref });
                self.chase_voted_run(chain);
                Ok(())
            }
        }
    }

    /// Extends a chain's contiguous DA-choice prefix over every height it now covers.
    fn chase_voted_run(&mut self, chain: usize) {
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

    /// Records one chain's offered eligible run and frontier reach from its chain plane.
    ///
    /// This is the sole writer of the offered run the machine reads at vote and proposal time. A
    /// plane's messages are FIFO, so the machine applies every queued offer before the read; the
    /// offered run can only lag a plane, never lead it, because the machine alone mints the
    /// durable choice.
    pub(crate) fn note_da_vote_ready(
        &mut self,
        chain: ChainId,
        candidates: Vec<Arc<SignedTransactionBlock<V, D>>>,
        ready_through: Height,
    ) {
        if let Some(state) = self.chains.get_mut(chain.index()) {
            state.offered = candidates;
            state.ready_through = ready_through;
        }
    }

    /// Returns one chain's certified anchor: its highest retained certified block, else its genesis
    /// tip. A chain plane anchors its eligibility here and is re-seeded with it after a restart.
    pub(crate) fn certified_anchor(&self, chain: ChainId) -> BlockRef<D> {
        let index = chain.index();
        self.chains
            .get(index)
            .and_then(|state| state.certified.last_key_value())
            .map(|(_, certified)| certified.block)
            .unwrap_or_else(|| self.genesis[index])
    }

    /// Returns one chain's durable DA choices above the anchor, to re-seed a chain plane's
    /// eligibility read-copy after a restart.
    pub(crate) fn chosen_choices(&self, chain: ChainId) -> Vec<DaChoice<D>> {
        self.chains
            .get(chain.index())
            .map(|state| state.local_da_votes.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns the eligible data-availability-vote frontier in round-robin chain order.
    ///
    /// Each chain's chain plane pre-computes its contiguous eligible run off-thread and offers
    /// it as a `DaVotesOffer`; this drains those offers instead of scanning a block store.
    /// A chain with a reservation in flight is skipped (one unacknowledged run at a time), and the
    /// already-voted prefix is filtered so a lagging offer never re-proposes a durable choice. Each
    /// chain contributes at most `run_limit` consecutive blocks, and `limit` bounds the total.
    pub(super) fn ready_votes(
        &self,
        limit: usize,
        run_limit: usize,
    ) -> Vec<Arc<SignedTransactionBlock<V, D>>> {
        if limit == 0 || run_limit == 0 {
            return Vec::new();
        }
        let mut ready = Vec::with_capacity(limit.min(self.chains.len()));
        for index in self.idle_chains_round_robin() {
            let remaining = limit - ready.len();
            ready.extend(
                self.eligible_offered(index, run_limit.min(remaining))
                    .cloned(),
            );
            if ready.len() == limit {
                break;
            }
        }
        ready
    }

    /// Returns chain indexes without a DA-vote reservation in flight, in round-robin order from the
    /// chain after the last reservation.
    fn idle_chains_round_robin(&self) -> impl Iterator<Item = usize> {
        let chains = self.chains.len();
        (0..chains)
            .map(move |offset| (self.next_da_chain + offset) % chains)
            .filter(move |index| self.chains[*index].pending_da_votes.is_empty())
    }

    /// Returns one chain's offered eligible run above its durable DA-vote frontier, up to `cap`.
    ///
    /// The offer is a contiguous validated run above the plane's anchor; filtering to heights above
    /// the durable `da_voted_run` drops any prefix a not-yet-synced plane still lists as unvoted, so
    /// the machine never re-proposes a height it already chose. The reducer's safety-extension check
    /// is the final authority on which prefix it reserves.
    fn eligible_offered(
        &self,
        chain: usize,
        cap: usize,
    ) -> impl Iterator<Item = &Arc<SignedTransactionBlock<V, D>>> {
        let voted = self.chains[chain].da_voted_run;
        self.chains[chain]
            .offered
            .iter()
            .filter(move |block| block.header().height() > voted)
            .take(cap)
    }

    /// Returns the chain of the first offered eligible vote `select` accepts, in round-robin order.
    pub(super) fn selected_chain(
        &self,
        mut select: impl FnMut(ChainId, Height) -> bool,
    ) -> Option<ChainId> {
        for index in self.idle_chains_round_robin() {
            let Some(block) = self.eligible_offered(index, 1).next() else {
                continue;
            };
            let header = block.header();
            if select(header.chain(), header.height()) {
                return Some(header.chain());
            }
        }
        None
    }

    /// Queues a reserved DA vote whose signing is in flight, and moves the reservation cursor to
    /// the next chain.
    pub(crate) fn mark_da_vote_reserved(&mut self, header: TransactionBlockHeader<D>) {
        let chain = header.chain().index();
        self.next_da_chain = (chain + 1) % self.chains.len();
        self.chains[chain].pending_da_votes.push_back(header);
    }
}

#[cfg(test)]
impl<V: Variant, D: Digest> DaState<V, D> {
    /// Returns the number of retained header-parent records.
    pub(crate) fn retained_ancestry(&self) -> usize {
        self.chains
            .iter()
            .flat_map(|chain| chain.ancestry.values())
            .map(BTreeMap::len)
            .sum()
    }

    /// Returns the number of blocks holding offered certificate candidates.
    pub(crate) fn candidate_blocks(&self) -> usize {
        self.chains
            .iter()
            .flat_map(|chain| chain.candidates.values())
            .map(BTreeMap::len)
            .sum()
    }
}
