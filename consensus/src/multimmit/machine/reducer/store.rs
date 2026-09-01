//! The retained artifact store and the indexes admission and retirement keep over it.

use crate::{
    multimmit::{
        config::VERIFIED_BLOCKS_PER_HEIGHT,
        machine::{
            artifact::Dependency,
            util::remove_indexed,
            verification::{Observation, VerificationTicket},
        },
        types::{
            Artifact, ArtifactId, BlockRef, CertificateId, ChainId, DaVote, TransactionBlockHeader,
        },
    },
    types::{Attributable as _, Height, Participant, View},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use core::ops::Bound;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Admission progress of one retained artifact.
#[derive(Clone, Debug)]
pub(crate) enum ArtifactState<D: Digest> {
    /// Awaiting the verification verdict for this ticket.
    Pending(VerificationTicket<D>),
    /// Authenticated, but waiting for a missing dependency to become available.
    Waiting(Dependency<D>),
    /// Authenticated with every dependency available, and observed by the protocol partitions.
    Ready,
    /// Locally created and not yet placed in [`Self::Ready`] or [`Self::Waiting`].
    Dropped,
}

/// One artifact in the machine's store, with the indexes and flags admission maintains for it.
#[derive(Clone, Debug)]
pub(crate) struct ArtifactEntry<V: Variant, D: Digest> {
    /// The artifact.
    pub(crate) artifact: Arc<Artifact<V, D>>,
    /// The dependencies this artifact provides to waiting artifacts.
    pub(crate) provisions: Arc<[Dependency<D>]>,
    /// The earliest observation of this artifact, which orders it against its peers.
    pub(crate) observation: Observation,
    /// The artifact's admission progress.
    pub(crate) state: ArtifactState<D>,
    /// Set for locally created artifacts, which a rejected dependency never removes.
    pub(crate) dependency_protected: bool,
    /// Set while the artifact's view is above the current view and it sits in the future index.
    pub(crate) future: bool,
    /// Set once the view state observed the artifact, so promotion does not observe it again.
    pub(crate) view_observed: bool,
    /// Set while the artifact holds one of the bounded dependency-waiter slots.
    pub(crate) dependency_slot: bool,
}

/// Where an artifact entering the store sits against the retention floors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum FloorPosition {
    /// Above every floor: the sweep of its view or height reaches it once that retires.
    Above,
    /// At or below a floor whose sweep already passed, so it queues for the next pass instead.
    Retired,
}

/// One artifact promoted to [`ArtifactState::Ready`], as admission telemetry needs it.
pub(crate) type ReadyPromotion<V, D> = (Observation, ArtifactId<D>, Arc<Artifact<V, D>>);

/// A chain position and the signer of one data-availability vote at it.
pub(crate) type VoteSlotKey = (ChainId, Height, Participant);

/// Returns the slot `vote` takes: its chain position and signer.
pub(crate) fn vote_slot_key<V: Variant, D: Digest>(vote: &DaVote<V, D>) -> VoteSlotKey {
    (vote.header().chain(), vote.header().height(), vote.signer())
}

/// The verified producer blocks retained at one chain position, in verification order.
pub(crate) type VerifiedBlocks<D> = [Option<ArtifactId<D>>; VERIFIED_BLOCKS_PER_HEIGHT];

/// Retained artifacts with the indexes admission and retirement keep over them.
pub(crate) struct ArtifactStore<V: Variant, D: Digest> {
    pub(in crate::multimmit::machine) artifacts: BTreeMap<ArtifactId<D>, ArtifactEntry<V, D>>,
    /// Retained view-scoped artifacts by view, so retirement visits only the views it retires.
    pub(in crate::multimmit::machine) by_view: BTreeMap<View, BTreeSet<ArtifactId<D>>>,
    /// Retained chain artifacts by chain and height, so retirement visits only heights at or
    /// below a chain's retention floor.
    pub(in crate::multimmit::machine) by_position:
        BTreeMap<(ChainId, Height), BTreeSet<ArtifactId<D>>>,
    /// Highest view whose retained artifacts retirement has already examined.
    ///
    /// Views at or below it are swept exactly once when they retire; an artifact that stays
    /// retained past that sweep is re-examined only when its own state changes.
    pub(in crate::multimmit::machine) swept_view: Option<View>,
    /// Per-chain highest height whose retained artifacts retirement has already examined.
    pub(in crate::multimmit::machine) swept_floors: Vec<Option<Height>>,
    /// Retained artifacts whose state changed in a way that may make them retirable.
    pub(in crate::multimmit::machine) retirement_pending: Vec<ArtifactId<D>>,
    /// Ready V-QCs by certificate identifier.
    pub(in crate::multimmit::machine) vqcs: BTreeMap<CertificateId<D>, ArtifactId<D>>,
    /// Retained artifacts above the current view, by view.
    pub(in crate::multimmit::machine) future: BTreeSet<(View, ArtifactId<D>)>,
    /// Verified producer blocks by chain position, which bounds the forks retained at one height.
    pub(in crate::multimmit::machine) verified_blocks:
        BTreeMap<(ChainId, Height), VerifiedBlocks<D>>,
    /// The data-availability vote each signer holds at a chain position above the durable
    /// certified tip.
    pub(in crate::multimmit::machine) vote_slots: BTreeMap<VoteSlotKey, ArtifactId<D>>,
    /// Artifacts promoted to [`ArtifactState::Ready`] since the last drain, in promotion order.
    ///
    /// Admission telemetry needs the set of newly ready artifacts, and the retained map holds
    /// hundreds of entries: tracking promotions as they happen keeps every step and poll off a
    /// full scan. Entries are drained by both, so a promotion is never reported twice.
    pub(in crate::multimmit::machine) newly_ready: Vec<ReadyPromotion<V, D>>,
    /// Reused canonical encoding buffer for machine-validated local artifacts.
    pub(in crate::multimmit::machine) id_scratch: Vec<u8>,
    /// The input cohort the next observation belongs to.
    pub(in crate::multimmit::machine) next_cohort: u64,
}

impl<V: Variant, D: Digest> ArtifactStore<V, D> {
    pub(super) const fn new() -> Self {
        Self {
            artifacts: BTreeMap::new(),
            by_view: BTreeMap::new(),
            by_position: BTreeMap::new(),
            swept_view: None,
            swept_floors: Vec::new(),
            retirement_pending: Vec::new(),
            vqcs: BTreeMap::new(),
            future: BTreeSet::new(),
            verified_blocks: BTreeMap::new(),
            vote_slots: BTreeMap::new(),
            newly_ready: Vec::new(),
            id_scratch: Vec::new(),
            next_cohort: 0,
        }
    }

    /// Retains `entry` under `id` and records it in the retirement and future indices.
    ///
    /// An artifact at a [`FloorPosition::Retired`] position missed the sweep of its view or
    /// height, so it is queued for the next retirement pass instead.
    pub(super) fn insert(
        &mut self,
        id: ArtifactId<D>,
        entry: ArtifactEntry<V, D>,
        position: FloorPosition,
    ) {
        let view = entry.artifact.view();
        if let Some(view) = view {
            self.by_view.entry(view).or_default().insert(id);
        }
        if let Some(position) = entry.artifact.chain_position() {
            self.by_position.entry(position).or_default().insert(id);
        }
        if position == FloorPosition::Retired {
            self.retirement_pending.push(id);
        }
        if entry.future {
            let view = view.expect("future artifacts have a view");
            self.future.insert((view, id));
        }
        self.artifacts.insert(id, entry);
    }

    /// Removes the artifact retained under `id` from the store and its retirement, future, and
    /// chain position indices.
    pub(super) fn remove(&mut self, id: ArtifactId<D>) -> Option<ArtifactEntry<V, D>> {
        let entry = self.artifacts.remove(&id)?;
        let view = entry.artifact.view();
        if let Some(view) = view {
            remove_indexed(&mut self.by_view, &view, &id);
        }
        if let Some(position) = entry.artifact.chain_position() {
            remove_indexed(&mut self.by_position, &position, &id);
        }
        match entry.artifact.as_ref() {
            Artifact::TransactionBlock(block) => {
                let position = (block.header().chain(), block.header().height());
                if let Some(blocks) = self.verified_blocks.get_mut(&position) {
                    for held in blocks.iter_mut().filter(|held| **held == Some(id)) {
                        *held = None;
                    }
                    if blocks.iter().all(Option::is_none) {
                        self.verified_blocks.remove(&position);
                    }
                }
            }
            Artifact::DaVote(vote) => {
                let key = vote_slot_key(vote);
                if self.vote_slots.get(&key) == Some(&id) {
                    self.vote_slots.remove(&key);
                }
            }
            _ => {}
        }
        if entry.future {
            let view = view.expect("future artifacts have a view");
            self.future.remove(&(view, id));
        }
        Some(entry)
    }

    /// Records the verified producer block `id` at `position`.
    pub(super) fn note_verified_block(&mut self, position: (ChainId, Height), id: ArtifactId<D>) {
        let blocks = self
            .verified_blocks
            .entry(position)
            .or_insert([None; VERIFIED_BLOCKS_PER_HEIGHT]);
        let free = blocks.iter_mut().find(|held| held.is_none());
        debug_assert!(
            free.is_some(),
            "a verified block beyond the bound is dropped"
        );
        if let Some(free) = free {
            *free = Some(id);
        }
    }

    /// Returns whether `position` already retains the most verified producer blocks.
    pub(super) fn verified_blocks_full(&self, position: (ChainId, Height)) -> bool {
        self.verified_blocks
            .get(&position)
            .is_some_and(|blocks| blocks.iter().all(Option::is_some))
    }

    /// Returns whether a retained verified producer block carries `header`.
    pub(super) fn holds_verified_header(&self, header: &TransactionBlockHeader<D>) -> bool {
        self.verified_blocks
            .get(&(header.chain(), header.height()))
            .into_iter()
            .flatten()
            .flatten()
            .any(|id| {
                self.artifacts.get(id).is_some_and(|entry| {
                    matches!(entry.artifact.as_ref(), Artifact::TransactionBlock(block)
                        if block.header() == header)
                })
            })
    }

    /// Records `id` as the data-availability vote held at `key`.
    pub(super) fn claim_vote_slot(&mut self, key: VoteSlotKey, id: ArtifactId<D>) {
        let previous = self.vote_slots.insert(key, id);
        debug_assert!(previous.is_none(), "a vote slot holds one vote");
    }

    /// Drops the ready V-QC index entries a forgotten artifact `id` provided.
    pub(super) fn forget_vqcs(&mut self, id: ArtifactId<D>, provisions: &[Dependency<D>]) {
        for provision in provisions {
            if let Dependency::Vqc(certificate) = provision
                && self.vqcs.get(certificate) == Some(&id)
            {
                self.vqcs.remove(certificate);
            }
        }
    }

    /// Appends the retained artifacts of every view at or below `retired` not swept before.
    pub(super) fn sweep_retired_views(
        &mut self,
        retired: View,
        candidates: &mut Vec<ArtifactId<D>>,
    ) {
        if self.swept_view.is_some_and(|swept| swept >= retired) {
            return;
        }
        let lower = self.swept_view.map_or(Bound::Unbounded, Bound::Excluded);
        candidates.extend(
            self.by_view
                .range((lower, Bound::Included(retired)))
                .flat_map(|(_, ids)| ids.iter().copied()),
        );
        self.swept_view = Some(retired);
    }

    /// Appends the retained artifacts of every chain height at or below its certified tip in
    /// `tips` not swept before.
    pub(in crate::multimmit::machine) fn sweep_retired_floors(
        &mut self,
        tips: &[BlockRef<D>],
        candidates: &mut Vec<ArtifactId<D>>,
    ) {
        self.swept_floors.resize(tips.len(), None);
        for (tip, swept) in tips.iter().zip(self.swept_floors.iter_mut()) {
            let floor = tip.height();
            if swept.is_some_and(|swept| swept >= floor) {
                continue;
            }
            let chain = tip.chain();
            let lower = swept.map_or(Bound::Included((chain, Height::zero())), |swept| {
                Bound::Excluded((chain, swept))
            });
            candidates.extend(
                self.by_position
                    .range((lower, Bound::Included((chain, floor))))
                    .flat_map(|(_, ids)| ids.iter().copied()),
            );
            *swept = Some(floor);
        }
    }
}
