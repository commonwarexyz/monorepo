//! The V-QC store: V-QCs held with their parent chain, the facts each fixes, forwarding, and view
//! entry.
//!
//! A V-QC is held only together with every V-QC on its parent chain, back to the epoch's genesis
//! V-QC. An authenticated V-QC whose parent is not held waits for it in the artifact store, and the
//! parent is requested by identifier; holding the parent wakes it. Admission checks the V-QC
//! against its parent's facts ([`validate_vqc`]): exactly `n - f` final votes of the view after the
//! parent's, every tip above the base resolved by its paths, and the parent forced whenever
//! `n - 3f` of the votes designate a leader block. A malformed V-QC is dropped without blame: its
//! assembler is unknown and its signers may be correct. Admission fixes the V-QC's tips `Tips(Q)`
//! and its history record `(C(parent), Tips(Q))`, a pure function of the V-QC and its parent chain,
//! holds the headers its paths rebuild, and reads its final votes into the pool as votes received
//! now.
//!
//! # Forwarding and entry
//!
//! The first V-QC held for a view is the view's new V-QC. It is forwarded once, together with every
//! V-QC on its parent chain not forwarded before, lowest view first, while their publication duty
//! lasts (a V-QC of view `u` is published until view `u + 2` is entered). The new V-QC of the
//! current view ends it: this node sends its final vote for the view ([`Machine::finish_view`]),
//! then stages the entry into the next view on that V-QC and fixes the next view's volatile state
//! ([`Machine::enter_view`]).
//!
//! # Bounds and discarding
//!
//! At most `n` V-QCs are held per view, plus any V-QC a stored artifact or a durable orphan waits
//! on as its parent: anyone can assemble further valid V-QCs of a view from its public final votes,
//! and they must not crowd out the parent a proposal or a later V-QC names. The artifact store
//! bounds the waiting artifacts, so the extra V-QCs are bounded too. Once a leader block of view
//! `v` has `n - f` votes, every V-QC of `v` and of later views descends from that block's parent,
//! so the V-QCs of views below `v` off its chain are discarded.
//!
//! # Restart
//!
//! Durable state retains every V-QC this node entered a view on, assembled, or still publishes,
//! above the retired view, and the retention root: the V-QC of the retired view on the chain this
//! node entered later views on, with its history record. Entering a view also retains the V-QCs on
//! the entry V-QC's parent chain that nothing else retains, so that chain stays durable down to the
//! root even where it diverges from the V-QCs earlier views were entered on. A restart holds the
//! retained V-QCs again in view order on the genesis V-QC or the root. One whose parent above the
//! retired view is gone waits as an orphan for that parent, which is requested from peers; one
//! whose parent was retired and is not the root lies off the root's chain and is not held.
//!
//! # L-QCs
//!
//! An authenticated L-QC is kept, one per view. When the V-QC its leader block names is held, the
//! L-QC must open to that V-QC's history record ([`validate_floor`]); one that does not is dropped.

use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        algebra::{validate_floor, validate_vqc},
        config::Role,
        machine::{
            capability::Capabilities,
            chain::is_capacity,
            durability::{Change, Retained, RetentionRoot},
            input::{Now, Rejection, StepError},
            reducer::{
                components::{Precheck, WorkResult, WorkStatus},
                machine::Machine,
            },
            resolution::RetrievalKey,
            scheduler::ProtocolComponent,
            view::proposal::HeldVqc,
        },
        types::{Artifact, ArtifactId, CertificateId, HistoryRecord, Lqc, Vqc},
    },
    types::View,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::RangeInclusive,
    sync::Arc,
};

/// A V-QC held with its whole parent chain, and the facts it fixes.
#[derive(Clone, Debug)]
pub(crate) struct StoredVqc<V: Variant, D: Digest> {
    /// The V-QC as leader blocks and the view layer name it.
    pub(crate) held: HeldVqc<D>,
    /// The V-QC as the artifact store and durable state hold it.
    pub(crate) artifact: Arc<Artifact<V, D>>,
    /// The identifier of [`Self::artifact`].
    pub(crate) artifact_id: ArtifactId<D>,
    /// The parent V-QC.
    pub(crate) parent: CertificateId<D>,
    /// The history record `(C(parent), Tips(Q))`, whose commitment is `held.history`.
    pub(crate) record: Arc<HistoryRecord<D>>,
    /// The leader block at least `n - 3f` of the V-QC's votes designate.
    pub(crate) designated: Option<D>,
}

/// A shared artifact with its identifier.
pub(crate) type Identified<V, D> = (ArtifactId<D>, Arc<Artifact<V, D>>);

/// The V-QCs and L-QCs this node holds.
pub(crate) struct VqcStore<V: Variant, D: Digest> {
    held: BTreeMap<CertificateId<D>, StoredVqc<V, D>>,
    /// The held V-QCs of each view, in the order they were held; never empty.
    by_view: BTreeMap<View, Vec<CertificateId<D>>>,
    /// Durably retained V-QCs whose parent is not held, by parent.
    orphans: BTreeMap<CertificateId<D>, Vec<Identified<V, D>>>,
    /// Retrieval keys made available since the forwarding drive last ran without admitting the
    /// artifact they name, whose waiters the drive settles: the updates of a sender whose final
    /// vote a V-QC carried, and durable orphans held once their parent was.
    pub(in crate::multimmit::machine) available: Vec<RangeInclusive<RetrievalKey<D>>>,
    /// The highest view whose leader block reached `n - f` votes and discarded the V-QCs below it.
    discarded: View,
    /// The first authenticated L-QC of each view.
    lqcs: BTreeMap<View, Identified<V, D>>,
}

impl<V: Variant, D: Digest> VqcStore<V, D> {
    pub(crate) const fn new() -> Self {
        Self {
            held: BTreeMap::new(),
            by_view: BTreeMap::new(),
            orphans: BTreeMap::new(),
            available: Vec::new(),
            discarded: View::zero(),
            lqcs: BTreeMap::new(),
        }
    }

    /// Returns the held V-QC `id`.
    pub(crate) fn get(&self, id: &CertificateId<D>) -> Option<&StoredVqc<V, D>> {
        self.held.get(id)
    }

    /// Returns how many V-QCs of `view` are held.
    pub(crate) fn view_len(&self, view: View) -> usize {
        self.by_view.get(&view).map_or(0, Vec::len)
    }

    /// Returns the V-QCs held for `view`, in the order they were held.
    pub(crate) fn held_in(&self, view: View) -> impl Iterator<Item = &StoredVqc<V, D>> {
        self.by_view
            .get(&view)
            .into_iter()
            .flatten()
            .filter_map(|id| self.held.get(id))
    }

    /// Returns the L-QCs held for `view` and later views, in view order.
    pub(crate) fn lqcs_from(&self, view: View) -> impl Iterator<Item = (View, &Identified<V, D>)> {
        self.lqcs.range(view..).map(|(view, lqc)| (*view, lqc))
    }

    /// Returns how many durably retained V-QCs wait for their parent.
    #[cfg(test)]
    pub(crate) fn orphan_count(&self) -> usize {
        self.orphans.values().map(Vec::len).sum()
    }

    /// Returns the first V-QC held for `view`, its new V-QC.
    pub(crate) fn first(&self, view: View) -> Option<&StoredVqc<V, D>> {
        self.by_view
            .get(&view)
            .and_then(|ids| ids.first())
            .and_then(|id| self.held.get(id))
    }

    fn insert(&mut self, stored: StoredVqc<V, D>) {
        self.by_view
            .entry(stored.held.view)
            .or_default()
            .push(stored.held.id);
        self.held.insert(stored.held.id, stored);
    }

    /// Drops the V-QCs, orphans, and L-QCs of views at or below `view`, and returns the
    /// artifact-store entries of the V-QCs dropped.
    fn retire_through(&mut self, view: View) -> Vec<ArtifactId<D>> {
        let kept = self.by_view.split_off(&view.next());
        let retired = core::mem::replace(&mut self.by_view, kept);
        let ids = retired
            .into_values()
            .flatten()
            .filter_map(|id| self.held.remove(&id))
            .map(|stored| stored.artifact_id)
            .collect();
        self.orphans.retain(|_, orphans| {
            orphans.retain(|(_, artifact)| artifact.view().is_some_and(|orphan| orphan > view));
            !orphans.is_empty()
        });
        self.lqcs = self.lqcs.split_off(&view.next());
        ids
    }

    fn remove(&mut self, id: &CertificateId<D>) -> Option<StoredVqc<V, D>> {
        let stored = self.held.remove(id)?;
        let view = stored.held.view;
        if let Some(ids) = self.by_view.get_mut(&view) {
            ids.retain(|held| held != id);
            if ids.is_empty() {
                self.by_view.remove(&view);
            }
        }
        Some(stored)
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns the held V-QC `id` with the facts it fixes.
    pub(in crate::multimmit::machine) fn stored_vqc(
        &self,
        id: &CertificateId<H::Digest>,
    ) -> Option<&StoredVqc<V, H::Digest>> {
        self.components.vqcs.get(id)
    }

    /// Returns the L-QC held for `view`, with its artifact identifier.
    pub(in crate::multimmit::machine) fn lqc(
        &self,
        view: View,
    ) -> Option<&Identified<V, H::Digest>> {
        self.components.vqcs.lqcs.get(&view)
    }

    /// Refuses a V-QC of a view that already holds `n` of them, unless it is needed as a parent.
    pub(in crate::multimmit::machine) fn precheck_vqc(
        &self,
        vqc: &Vqc<V, H::Digest>,
    ) -> Result<Precheck<H::Digest>, Rejection> {
        if !self.vqc_fits(vqc) {
            return Err(Rejection::CertificatesFull);
        }
        Ok(Precheck::Verify(None))
    }

    /// Returns whether `vqc` may be held under the per-view bound: its view holds fewer than `n`
    /// V-QCs, or a stored artifact or a durable orphan waits on it as its parent.
    fn vqc_fits(&self, vqc: &Vqc<V, H::Digest>) -> bool {
        let vqcs = &self.components.vqcs;
        if vqcs.view_len(vqc.view()) < self.profile.codec().participants() {
            return true;
        }
        let id = vqc.id::<H>();
        self.store.has_waiters(&RetrievalKey::Vqc(id)) || vqcs.orphans.contains_key(&id)
    }

    /// Returns the parent an authenticated V-QC waits for, unless it is held with its chain.
    pub(in crate::multimmit::machine) fn vqc_dependency(
        &self,
        vqc: &Vqc<V, H::Digest>,
    ) -> Option<RetrievalKey<H::Digest>> {
        let parent = vqc.parent();
        self.held_vqc(&parent)
            .is_none()
            .then_some(RetrievalKey::Vqc(parent))
    }

    /// Holds an authenticated V-QC received at `received` whose parent is held, or drops it from
    /// the artifact store when it is malformed.
    pub(in crate::multimmit::machine) fn admit_vqc(
        &mut self,
        id: ArtifactId<H::Digest>,
        artifact: &Arc<Artifact<V, H::Digest>>,
        now: Now,
        received: Now,
    ) {
        if !self.hold_vqc(id, artifact, now, received) {
            self.store.remove(&id);
        }
    }

    /// Holds the V-QC `artifact`, received at `received`, if its parent is held and it is well
    /// formed as its child, and returns whether it is held.
    ///
    /// Holding it fixes its facts, holds the headers its paths rebuild, reads its final votes into
    /// the pool, discards the V-QCs a pinned leader block rules out, and holds the durable orphans
    /// waiting for it. An orphan, a V-QC this node assembled, and a restored one count as received
    /// at `now`.
    fn hold_vqc(
        &mut self,
        id: ArtifactId<H::Digest>,
        artifact: &Arc<Artifact<V, H::Digest>>,
        now: Now,
        received: Now,
    ) -> bool {
        let Artifact::Vqc(vqc) = artifact.as_ref() else {
            return false;
        };
        let certificate = vqc.id::<H>();
        if self.components.vqcs.get(&certificate).is_some() {
            return true;
        }
        let view = vqc.view();
        let codec = self.profile.codec();
        let Some(parent) = self.held_vqc(&vqc.parent()) else {
            return false;
        };
        if parent.view.next() != view || !self.vqc_fits(vqc) {
            return false;
        }
        let Ok(valid) = validate_vqc::<H, V>(vqc, parent.history, &parent.tips, codec) else {
            return false;
        };
        for path in valid.ancestry.paths() {
            for (header, block) in path.rebuilt() {
                if !self.hold_rebuilt(header, block.digest()) {
                    break;
                }
            }
        }
        self.read_certified_finals(&valid.contents, now, received);
        let held = HeldVqc {
            view,
            id: certificate,
            history: valid.commitment,
            tips: valid.record.tips().into(),
        };
        self.components.vqcs.insert(StoredVqc {
            held: held.clone(),
            artifact: Arc::clone(artifact),
            artifact_id: id,
            parent: vqc.parent(),
            record: Arc::new(valid.record),
            designated: valid.designated,
        });
        if let Some(leader) = valid.designated
            && self.leader_votes(view, &leader) >= codec.view_quorum()
        {
            self.discard_vqcs(view, vqc.parent());
        }
        self.resume_entry_parent(&held, id);
        self.wake(ProtocolComponent::Emission);
        let orphans = self
            .components
            .vqcs
            .orphans
            .remove(&certificate)
            .unwrap_or_default();
        for (orphan, artifact) in orphans {
            if self.hold_vqc(orphan, &artifact, now, now)
                && let Artifact::Vqc(vqc) = artifact.as_ref()
            {
                let key = RetrievalKey::Vqc(vqc.id::<H>());
                self.components.vqcs.available.push(key..=key);
            }
        }
        self.wake(ProtocolComponent::Forwarding);
        true
    }

    /// Gives the view layer the V-QC it entered the current view on once that V-QC is held, when
    /// a restart could not hold it.
    fn resume_entry_parent(&mut self, held: &HeldVqc<H::Digest>, id: ArtifactId<H::Digest>) {
        let state = &self.components.view.state;
        if state.parent.is_some() || held.view.next() != state.view {
            return;
        }
        let entered = self
            .durable
            .state
            .exits
            .get(&held.view)
            .is_some_and(|exit| exit.id::<H>() == id);
        if entered {
            self.components.view.state.parent = Some(held.clone());
            self.wake(ProtocolComponent::View);
        }
    }

    /// Discards every held V-QC of a view below `view` that is not on the parent chain of
    /// `reference`, the parent of the leader block of `view` that `n - f` validators voted for.
    ///
    /// Every V-QC of `view` and later views descends from `reference`, so a discarded V-QC can
    /// never again be a parent, an entry, or forwarded.
    pub(in crate::multimmit::machine) fn discard_vqcs(
        &mut self,
        view: View,
        reference: CertificateId<H::Digest>,
    ) {
        let vqcs = &mut self.components.vqcs;
        if view <= vqcs.discarded {
            return;
        }
        vqcs.discarded = view;
        let mut chain = BTreeSet::new();
        let mut current = vqcs.get(&reference);
        while let Some(stored) = current {
            chain.insert(stored.held.id);
            current = vqcs.get(&stored.parent);
        }
        let off = vqcs
            .by_view
            .range(..view)
            .flat_map(|(_, ids)| ids)
            .filter(|id| !chain.contains(*id))
            .copied()
            .collect::<Vec<_>>();
        for id in off {
            if let Some(stored) = vqcs.remove(&id) {
                self.store.remove(&stored.artifact_id);
            }
        }
        vqcs.orphans.retain(|_, orphans| {
            orphans.retain(|(_, artifact)| artifact.view().is_none_or(|orphan| orphan >= view));
            !orphans.is_empty()
        });
    }

    /// Runs one quantum of certificate forwarding and view entry at `now`: settles the artifacts
    /// waiting on keys made available, then anchors on a floor held, stages an assembled V-QC,
    /// forwards the next new V-QC or ancestor, enters the next view on the current view's new V-QC,
    /// or else assembles one.
    pub(in crate::multimmit::machine) fn drive_forwarding(
        &mut self,
        now: Now,
    ) -> WorkResult<V, H::Digest> {
        let mut capabilities = Capabilities::new();
        for keys in core::mem::take(&mut self.components.vqcs.available) {
            capabilities.extend(self.settle_waiters(keys, now)?);
        }
        let status = if let Some(status) = self.anchor(&mut capabilities, now)? {
            status
        } else if let Some(status) = self.create_assembled(&mut capabilities, now)? {
            status
        } else if let Some(id) = self.next_forward() {
            self.forward(&id, &mut capabilities)?
        } else if let Some(id) = self
            .components
            .vqcs
            .first(self.durable.state.view)
            .map(|stored| stored.held.id)
        {
            self.enter_on(&id, &mut capabilities, now)?
        } else {
            capabilities.extend(self.assemble()?);
            WorkStatus::Complete
        };
        Ok((status, capabilities))
    }

    /// Stages the assembled V-QC waiting to be created and holds it, unless a V-QC of its view was
    /// held meanwhile or this node left its view. Returns `None` when none waits.
    fn create_assembled(
        &mut self,
        capabilities: &mut Capabilities<V, H::Digest>,
        now: Now,
    ) -> Result<Option<WorkStatus>, StepError> {
        let Some((id, artifact)) = self.components.assembly.created.take() else {
            return Ok(None);
        };
        let view = artifact.view().ok_or(StepError::ViewInvariant)?;
        if view != self.durable.state.view || self.components.vqcs.view_len(view) > 0 {
            return Ok(Some(WorkStatus::Requeue));
        }
        let created = Change::CertificateCreated {
            artifact: Arc::clone(&artifact),
        };
        if !self.fits(&[id]) || !self.stage(created, capabilities)? {
            self.components.assembly.created = Some((id, artifact));
            return Ok(Some(WorkStatus::Blocked));
        }
        // The aggregate covers votes this node verified and paths it built from held headers.
        if !self.hold_vqc(id, &artifact, now, now) {
            return Err(StepError::ViewInvariant);
        }
        Ok(Some(WorkStatus::Requeue))
    }

    /// Stages `change`, returning `false` when persistence lacks capacity for it.
    pub(in crate::multimmit::machine) fn stage(
        &mut self,
        change: Change<V, H::Digest>,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<bool, StepError> {
        match self.reserve_change(change) {
            Ok(staged) => {
                capabilities.extend(staged);
                Ok(true)
            }
            Err(error) if is_capacity(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Returns whether durable state can reference `ids` within the artifact cache.
    pub(in crate::multimmit::machine) fn fits(&self, ids: &[ArtifactId<H::Digest>]) -> bool {
        self.durable
            .occupancy_after(ids, &[], 0, 0)
            .is_some_and(|occupancy| occupancy <= self.profile.resources().max_cached_artifacts())
    }

    /// Makes the certificate `artifact` (identified by `id`) durable unless durable state already
    /// references it, returning `false` when the artifact cache or persistence lacks room.
    pub(in crate::multimmit::machine) fn retain_certificate(
        &mut self,
        id: ArtifactId<H::Digest>,
        artifact: &Arc<Artifact<V, H::Digest>>,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<bool, StepError> {
        if self.durable.references(&id) {
            return Ok(true);
        }
        let created = Change::CertificateCreated {
            artifact: Arc::clone(artifact),
        };
        Ok(self.fits(&[id]) && self.stage(created, capabilities)?)
    }

    /// Returns the next V-QC to forward: the lowest V-QC not forwarded on the parent chain of the
    /// new V-QC of the lowest view none of whose V-QCs was forwarded, among views whose
    /// publication duty lasts.
    fn next_forward(&self) -> Option<CertificateId<H::Digest>> {
        let state = &self.durable.state;
        if state.forwarded_count() >= self.profile.resources().max_forwarded_certificates() {
            return None;
        }
        let floor = state
            .view
            .previous()
            .filter(|previous| !previous.is_zero())
            .unwrap_or(state.view);
        let vqcs = &self.components.vqcs;
        let (view, ids) = vqcs.by_view.range(floor..).find(|(view, _)| {
            state
                .forwarded_vqcs
                .get(view)
                .is_none_or(BTreeSet::is_empty)
        })?;
        let mut next = *ids.first()?;
        let mut current = vqcs.get(&next);
        while let Some(stored) = current.filter(|stored| stored.held.view >= floor) {
            if !state.vqc_forwarded(stored.held.view, &stored.held.id) {
                next = stored.held.id;
            }
            current = vqcs.get(&stored.parent);
        }
        debug_assert!(
            vqcs.get(&next)
                .is_some_and(|stored| stored.held.view <= *view)
        );
        Some(next)
    }

    /// Forwards the held V-QC `id`, returning [`WorkStatus::Blocked`] while the outbox, the
    /// artifact cache, or persistence lacks room.
    fn forward(
        &mut self,
        id: &CertificateId<H::Digest>,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<WorkStatus, StepError> {
        let stored = self
            .components
            .vqcs
            .get(id)
            .ok_or(StepError::ViewInvariant)?;
        let (artifact, artifact_id) = (Arc::clone(&stored.artifact), stored.artifact_id);
        if self.durable.state.effect_count() >= self.profile.resources().max_outbox_effects()
            || !self.fits(&[artifact_id])
        {
            return Ok(WorkStatus::Blocked);
        }
        let change = self.forwarding(artifact)?;
        Ok(if self.stage(change, capabilities)? {
            WorkStatus::Requeue
        } else {
            WorkStatus::Blocked
        })
    }

    /// Ends the current view on its new V-QC `id`: sends this node's final vote for the view, makes
    /// the V-QC durable if no publication holds it, stages the entry into the next view, and enters
    /// it.
    fn enter_on(
        &mut self,
        id: &CertificateId<H::Digest>,
        capabilities: &mut Capabilities<V, H::Digest>,
        now: Now,
    ) -> Result<WorkStatus, StepError> {
        let stored = self
            .components
            .vqcs
            .get(id)
            .cloned()
            .ok_or(StepError::ViewInvariant)?;
        let parent = self
            .held_vqc(&stored.parent)
            .ok_or(StepError::ViewInvariant)?;
        if matches!(self.profile.role(), Role::Validator(_)) {
            let (status, finished) = self.finish_view(&parent, stored.designated.is_some(), now)?;
            capabilities.extend(finished);
            if status != WorkStatus::Complete {
                return Ok(status);
            }
        }
        if !self.retain_certificate(stored.artifact_id, &stored.artifact, capabilities)? {
            return Ok(WorkStatus::Blocked);
        }
        let (ids, ancestors): (Vec<_>, Vec<_>) = self
            .entry_ancestors(stored.parent)?
            .into_iter()
            .map(|ancestor| (ancestor.artifact_id, Arc::clone(&ancestor.artifact)))
            .unzip();
        if !self.fits(&ids)
            || !self.stage(self.view_entry(stored.artifact_id, ancestors), capabilities)?
        {
            return Ok(WorkStatus::Blocked);
        }
        self.enter_view(stored.held, now)?;
        self.retire_attestations_below(self.durable.state.view);
        self.wake(ProtocolComponent::Retention);
        Ok(WorkStatus::Requeue)
    }

    /// Returns, newest first, the held V-QCs from `parent`, the parent of a V-QC of the current
    /// view, down its chain to the first V-QC a retention holder keeps, exclusive: the ancestors
    /// entering the next view on that V-QC retains.
    ///
    /// # Errors
    ///
    /// Returns [`StepError::ViewInvariant`] unless that chain is held above the retired view.
    fn entry_ancestors(
        &self,
        mut parent: CertificateId<H::Digest>,
    ) -> Result<Vec<&StoredVqc<V, H::Digest>>, StepError> {
        let state = &self.durable.state;
        let genesis = self.profile.protocol().genesis().vqc();
        let mut view = state.view.previous().ok_or(StepError::ViewInvariant)?;
        let mut ancestors = Vec::new();
        while !state.retains_vqc::<H>(view, &parent, &genesis) {
            let stored = self
                .stored_vqc(&parent)
                .filter(|stored| stored.held.view == view && view > state.retired_view)
                .ok_or(StepError::ViewInvariant)?;
            ancestors.push(stored);
            parent = stored.parent;
            view = view.previous().ok_or(StepError::ViewInvariant)?;
        }
        Ok(ancestors)
    }

    /// Holds again the V-QCs and L-QCs durable state retains, at `now`, and requests the parents
    /// above the retired view of V-QCs whose chain is gone. A V-QC whose parent was retired and is
    /// not the root lies off the root's chain and is dropped.
    pub(in crate::multimmit::machine) fn restore_vqcs(
        &mut self,
        now: Now,
    ) -> Result<Capabilities<V, H::Digest>, StepError> {
        self.components.vqcs = VqcStore::new();
        self.restore_assembly();
        let mut vqcs = BTreeMap::new();
        let mut lqcs = BTreeMap::new();
        self.durable.state.visit_retained(|_, retained| {
            let view = match &retained {
                Retained::Artifact(artifact) => match artifact.as_ref() {
                    Artifact::Vqc(vqc) => vqc.view(),
                    Artifact::Lqc(lqc) => {
                        lqcs.entry(lqc.view())
                            .or_insert_with(|| (retained.id::<H>(), Arc::clone(artifact)));
                        return;
                    }
                    _ => return,
                },
                Retained::Vqc(vqc) => vqc.view(),
                Retained::Header(_) | Retained::LeaderBlock(_) => return,
            };
            vqcs.entry((view, retained.id::<H>()))
                .or_insert_with(|| retained.to_artifact());
        });
        self.components.vqcs.lqcs = lqcs;
        let retired = self.durable.state.retired_view;
        for ((view, id), artifact) in vqcs {
            let Artifact::Vqc(vqc) = artifact.as_ref() else {
                continue;
            };
            let parent = vqc.parent();
            if self.held_vqc(&parent).is_some() {
                self.hold_vqc(id, &artifact, now, now);
            } else if view > retired.next() {
                self.components
                    .vqcs
                    .orphans
                    .entry(parent)
                    .or_default()
                    .push((id, artifact));
            }
        }
        let vqcs = &self.components.vqcs;
        let orphaned = vqcs
            .orphans
            .values()
            .flatten()
            .filter_map(|(_, artifact)| match artifact.as_ref() {
                Artifact::Vqc(vqc) => Some(vqc.id::<H>()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let missing = vqcs
            .orphans
            .keys()
            .filter(|parent| !orphaned.contains(*parent))
            .copied()
            .collect::<Vec<_>>();
        let mut capabilities = Capabilities::new();
        for parent in missing {
            capabilities.extend(self.request(RetrievalKey::Vqc(parent))?);
        }
        self.wake(ProtocolComponent::Forwarding);
        Ok(capabilities)
    }

    /// Returns the root a retention floor at `floor` keeps: the V-QC of view `floor` on the chain
    /// of the V-QC this node entered the current view on, once that chain is held.
    pub(in crate::multimmit::machine) fn retention_root(
        &self,
        floor: View,
    ) -> Option<RetentionRoot<H::Digest>> {
        let entry = self.components.view.state.parent.as_ref()?;
        let mut current = self.stored_vqc(&entry.id);
        while let Some(stored) = current.filter(|stored| stored.held.view >= floor) {
            if stored.held.view == floor {
                return Some(RetentionRoot {
                    vqc: stored.held.id,
                    record: stored.record.as_ref().clone(),
                });
            }
            current = self.stored_vqc(&stored.parent);
        }
        None
    }

    /// Drops the V-QCs and L-QCs of views at or below `view` and their artifact-store entries.
    pub(in crate::multimmit::machine) fn retire_vqcs_through(&mut self, view: View) {
        for id in self.components.vqcs.retire_through(view) {
            self.store.remove(&id);
        }
    }

    /// Refuses an L-QC of a view that already holds one: every L-QC of a view certifies the same
    /// leader block.
    pub(in crate::multimmit::machine) fn precheck_lqc(
        &self,
        lqc: &Lqc<V, H::Digest>,
    ) -> Result<Precheck<H::Digest>, Rejection> {
        if self.components.vqcs.lqcs.contains_key(&lqc.view()) {
            return Err(Rejection::Superseded);
        }
        Ok(Precheck::Verify(None))
    }

    /// Accounts for the votes an authenticated L-QC's aggregate vouches for, then keeps the L-QC
    /// as its view's, unless the V-QC its leader block names is held and the L-QC does not open to
    /// that V-QC's history record, in which case it is dropped.
    pub(in crate::multimmit::machine) fn admit_lqc(
        &mut self,
        id: ArtifactId<H::Digest>,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) {
        let Artifact::Lqc(lqc) = artifact.as_ref() else {
            return;
        };
        for (signer, content) in lqc.contents::<H>() {
            self.account_vote(signer, &Arc::new(content));
        }
        let view = lqc.view();
        if let Some((held, _)) = self.components.vqcs.lqcs.get(&view) {
            if *held != id {
                self.store.remove(&id);
            }
            return;
        }
        if let Some(parent) = self.components.vqcs.get(&lqc.leader().parent())
            && validate_floor::<H, V>(
                lqc,
                &parent.record,
                self.profile.protocol().epoch(),
                self.profile.codec(),
            )
            .is_err()
        {
            self.store.remove(&id);
            return;
        }
        self.components
            .vqcs
            .lqcs
            .insert(view, (id, Arc::clone(artifact)));
        self.wake(ProtocolComponent::Emission);
    }

    /// Drops the L-QC `id` held for `view`, which does not open to its parent's history record.
    pub(in crate::multimmit::machine) fn drop_lqc(
        &mut self,
        view: View,
        id: ArtifactId<H::Digest>,
    ) {
        self.components.vqcs.lqcs.remove(&view);
        self.store.remove(&id);
    }
}
