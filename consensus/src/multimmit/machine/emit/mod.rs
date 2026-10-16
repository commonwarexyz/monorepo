//! Emission: the per-view agreement facts consensus reports to marshal.
//!
//! The emission state of view `v` is its base `beta_v`, the tips every V-QC of view `v - 1` that
//! can be an ancestor of anything has (CS L757-805). It is defined for view one (the genesis tips)
//! and becomes defined for later views in two ways, which agree whenever both apply (Lemma inv):
//!
//! - Case (a), pinned: an L-QC for the leader block `l` of view `v` (`n - f` votes for `l`) whose
//!   parent `Q'` is held with its chain. Let `u0` be the greatest view below `v` whose state is
//!   defined. Every view from `u0` to `v - 1` resolves to the tips of the V-QC of that view on
//!   `Q'`'s chain, so `beta_{u+1} = Tips(Q_u)` for each, and `beta_v = Tips(Q')`. Views without a
//!   defined state in between (a run of leaderless views) are resolved by the same walk.
//! - Case (b), determined: `state(v - 1)` is defined and some `n - f` final votes of view `v - 1`,
//!   one per signer with every tip resolvable, determine every chain (`Det(G)` in
//!   [`det`]); then `beta_v = Det(G)`.
//!
//! Each emission is written once, durably, in view order without gaps
//! ([`Change::EmissionResolved`]), and only then is the resolution of view `v - 1` it fixes
//! reported ([`Activity::ViewResolved`]). A pinned emission names the L-QC finalizing it, so case
//! (a) waits until an L-QC of `v` is held: one received from a peer, or one this node assembles
//! from the votes it read (see [`lqc`](crate::multimmit::machine::pool::lqc)). The L-QC is made
//! durable and reported with the record opening its leader block's history commitment
//! ([`Activity::LeaderFinalized`]).
//!
//! For the greatest view whose state is defined, consensus reports the pool's progress within it
//! ([`Activity::ViewSweep`]): per chain the final tip `b*` and whether the chain is settled.
//! Reports are coalesced and monotone: a final tip never retreats and a settled chain stays
//! settled.
//!
//! The sweep is maintained as votes are read, in time proportional to what changed: `b*` resumes
//! its walk from where it last stopped, since endorsements only accumulate, and each first binding
//! vote of the view is classified once by what it reaches in the window ([`Bindings`]), so a
//! chain's settledness is evaluated over its distinct reaches, and only when `b*` or its first
//! binding votes changed, or a tip held headers could not yet relate to the base resolves.
//!
//! A restart reports the retained resolutions again and, as the L-QCs durable state retains are
//! held again, the finalizations they certify.

use crate::{
    Epochable as _,
    multimmit::{
        algebra::{Bindings, Reach, det, reach, validate_floor},
        machine::{
            capability::Capabilities,
            durability::Change,
            input::StepError,
            reducer::{
                components::{WorkResult, WorkStatus},
                machine::Machine,
            },
            resolution::RetrievalKey,
            scheduler::ProtocolComponent,
            view::vqc::StoredVqc,
        },
        types::{
            Activity, Artifact, BlockRef, CertificateId, ChainSet, Floor, HistoryRecord,
            Resolution, VoteContent,
        },
    },
    types::{Participant, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::BTreeMap, sync::Arc};

/// The emission component's volatile state.
pub(crate) struct Emitter<D: Digest> {
    /// The highest view whose L-QC was reported finalized since the start; view one's leader block
    /// opens no history record and is never reported.
    pub(in crate::multimmit::machine) finalized: View,
    /// The sweep of the greatest view whose state is defined, as last reported.
    sweep: Option<Sweep<D>>,
    /// The view whose final votes were last checked for determination, and how many were read.
    checked: Option<(View, usize)>,
    /// The view whose `n - f` or more final votes last failed to determine it, and the chains
    /// they left undetermined.
    undetermined: Option<(View, UndeterminedChains)>,
    /// The view boundaries pinned after their final votes failed to determine them, since the
    /// emitter started.
    pub(in crate::multimmit::machine) pinned_undetermined: PinnedUndetermined,
    /// How many first binding tips the sweeps classified.
    #[cfg(test)]
    pub(in crate::multimmit::machine) classified: usize,
    /// How many chain settledness evaluations the sweeps ran.
    #[cfg(test)]
    pub(in crate::multimmit::machine) evaluations: usize,
}

impl<D: Digest> Emitter<D> {
    pub(crate) const fn new() -> Self {
        Self {
            finalized: View::new(1),
            sweep: None,
            checked: None,
            undetermined: None,
            pinned_undetermined: PinnedUndetermined {
                boundaries: 0,
                chains: UndeterminedChains {
                    unresolved: 0,
                    split: 0,
                },
            },
            #[cfg(test)]
            classified: 0,
            #[cfg(test)]
            evaluations: 0,
        }
    }
}

/// The chains `n - f` or more final votes of a view left undetermined, by cause.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct UndeterminedChains {
    /// Chains on which fewer than `n - f` of the votes' tips resolve to a reach above the base:
    /// headers the tips name are missing.
    pub(crate) unresolved: u64,
    /// Chains on which `n - f` or more tips resolve but no `n - f` of them share one reach: the
    /// votes split.
    pub(crate) split: u64,
}

/// Cumulative counts of the view boundaries case (a) pinned after `n - f` or more final votes of
/// the view failed to determine them (case (b)), and the chains those votes left undetermined.
///
/// A boundary pinned before `n - f` final votes of its view were read is not counted; the
/// difference from all pinned boundaries is those.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PinnedUndetermined {
    /// Boundaries pinned after a failed determination.
    pub(crate) boundaries: u64,
    /// The chains the latest failed determination of each left undetermined.
    pub(crate) chains: UndeterminedChains,
}

impl PinnedUndetermined {
    const fn record(&mut self, chains: UndeterminedChains) {
        self.boundaries += 1;
        self.chains.unresolved += chains.unresolved;
        self.chains.split += chains.split;
    }
}

/// Returns the chains on which no `quorum` of the per-vote `reaches` (each `None` where the
/// vote's tip does not resolve) agree, by cause.
pub(in crate::multimmit::machine) fn undetermined_chains<D: Digest>(
    reaches: &[Vec<Option<Option<BlockRef<D>>>>],
    chains: usize,
    quorum: usize,
) -> UndeterminedChains {
    let mut undetermined = UndeterminedChains::default();
    let mut resolved = Vec::with_capacity(reaches.len());
    for chain in 0..chains {
        resolved.clear();
        resolved.extend(reaches.iter().filter_map(|vote| vote[chain]));
        if resolved.len() < quorum {
            undetermined.unresolved += 1;
            continue;
        }
        resolved.sort_unstable();
        if resolved
            .chunk_by(|left, right| left == right)
            .all(|run| run.len() < quorum)
        {
            undetermined.split += 1;
        }
    }
    undetermined
}

/// The sweep of one view whose state is defined: what was reported, and per chain the first
/// binding votes of the view read so far.
struct Sweep<D: Digest> {
    view: View,
    /// Per chain, the reported `b*`.
    finals: Vec<BlockRef<D>>,
    /// The chains reported settled.
    settled: ChainSet,
    chains: Vec<ChainSweep<D>>,
}

/// One chain's first binding votes in a swept view.
struct ChainSweep<D: Digest> {
    /// How many of the pool's first binding votes on the chain are tallied.
    read: usize,
    bindings: Bindings<D>,
    /// The chain's header revision when the tips the tally could not resolve were last tried.
    tried: u64,
}

impl<D: Digest> Sweep<D> {
    fn new(view: View, base: &[BlockRef<D>], cap: u32) -> Self {
        Self {
            view,
            finals: base.to_vec(),
            settled: ChainSet::empty(base.len()),
            chains: base
                .iter()
                .map(|base| ChainSweep {
                    read: 0,
                    bindings: Bindings::new(*base, cap),
                    tried: 0,
                })
                .collect(),
        }
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns the greatest view whose emission state is defined; the states of every view at or
    /// below it are defined too.
    pub(in crate::multimmit::machine) fn defined_through(&self) -> View {
        self.durable
            .state
            .emission
            .last_key_value()
            .map_or(View::new(1), |(view, _)| *view)
    }

    /// Returns the base `beta_view`, the genesis tips for view one, or `None` when the state of
    /// `view` is not retained.
    pub(in crate::multimmit::machine) fn base_of(
        &self,
        view: View,
    ) -> Option<&[BlockRef<H::Digest>]> {
        if view == View::new(1) {
            return Some(self.profile.protocol().genesis().tips());
        }
        Some(self.durable.state.emission.get(&view)?.base())
    }

    /// Returns the commitment of the history record whose tips are `beta_view`, the genesis history
    /// for view one, or `None` when the state of `view` is not retained.
    fn commitment_of(&self, view: View) -> Option<H::Digest> {
        if view == View::new(1) {
            return Some(self.profile.protocol().genesis().history());
        }
        let emission = self.durable.state.emission.get(&view)?;
        Some(emission.record.commitment::<H>())
    }

    /// Returns the resolution of `view` that the emission states of `view` and the next view fix.
    fn view_resolved(&self, view: View) -> Option<Activity<V, H::Digest>> {
        let next = self.durable.state.emission.get(&view.next())?;
        let base = self.base_of(view)?;
        Some(Activity::ViewResolved {
            view,
            base: base.into(),
            tips: next.base().into(),
            commitment: next.record.commitment::<H>(),
            parent_commitment: next.record.parent(),
            by: next.by.clone(),
        })
    }

    /// Runs one quantum of emission: stages an assembled L-QC, then reports the next finalization
    /// (case (a)), else determines the next view (case (b)), else issues the next L-QC aggregation;
    /// finally reports the sweep of the greatest view whose state is defined.
    pub(in crate::multimmit::machine) fn drive_emission(&mut self) -> WorkResult<V, H::Digest> {
        let mut capabilities = Capabilities::new();
        if let Some(status) = self.create_assembled_lqc(&mut capabilities)? {
            return Ok((status, capabilities));
        }
        if let Some(status) = self.finalize_next(&mut capabilities)? {
            return Ok((status, capabilities));
        }
        if let Some(status) = self.determine_next(&mut capabilities)? {
            return Ok((status, capabilities));
        }
        capabilities.extend(self.assemble_lqc()?);
        self.report_sweep();
        Ok((WorkStatus::Complete, capabilities))
    }

    /// Reports the next held L-QC of a view above the last finalized one that opens to its parent's
    /// history record: makes it durable, pins the views its parent's chain resolves (case (a)),
    /// discards the V-QCs off that chain, and serves it with its opening as this node's newest
    /// floor. An L-QC that does not open to the record is dropped.
    ///
    /// Returns `None` when no L-QC can be reported yet; the parent of an L-QC whose view's state is
    /// undefined is requested while it is not held, and holding it wakes this drive.
    fn finalize_next(
        &mut self,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<Option<WorkStatus>, StepError> {
        let floor = self.components.emitter.finalized.next();
        let candidates = self
            .components
            .vqcs
            .lqcs_from(floor)
            .map(|(view, (id, artifact))| (view, *id, Arc::clone(artifact)))
            .collect::<Vec<_>>();
        for (view, id, artifact) in candidates {
            let Artifact::Lqc(lqc) = artifact.as_ref() else {
                continue;
            };
            let parent = lqc.leader().parent();
            let stored = self
                .stored_vqc(&parent)
                .filter(|stored| stored.held.view.next() == view)
                .cloned();
            let opening = match (self.durable.state.emission.get(&view), &stored) {
                (Some(emission), stored) => {
                    // Cases (a) and (b) agree on every base while at most `f` validators are
                    // faulty.
                    if stored
                        .as_ref()
                        .is_some_and(|stored| *stored.record != emission.record)
                    {
                        return Err(StepError::ViewInvariant);
                    }
                    Arc::new(emission.record.clone())
                }
                (None, Some(stored)) => Arc::clone(&stored.record),
                (None, None) => {
                    capabilities.extend(self.request(RetrievalKey::Vqc(parent))?);
                    continue;
                }
            };
            let codec = self.profile.codec();
            if validate_floor::<H, V>(lqc, &opening, self.profile.protocol().epoch(), codec)
                .is_err()
            {
                self.drop_lqc(view, id);
                continue;
            }
            if !self.retain_certificate(id, &artifact, capabilities)? {
                return Ok(Some(WorkStatus::Blocked));
            }
            if let Some(stored) = &stored
                && !self.pin(view, lqc.id::<H>(), stored, capabilities)?
            {
                return Ok(Some(WorkStatus::Blocked));
            }
            if !self.emission_defined(view) {
                // The parent's chain does not reach the greatest defined view.
                continue;
            }
            self.finalize_chains(opening.tips());
            let lqc = Arc::new(lqc.clone());
            self.report_in_order([Activity::LeaderFinalized {
                lqc: Arc::clone(&lqc),
                opening: Arc::clone(&opening),
            }]);
            self.serve_in_order(
                Arc::new(Artifact::Floor(Floor::new(lqc, opening))),
                capabilities,
            );
            self.components.emitter.finalized = view;
            self.retire_leader_votes_through(view);
            self.wake(ProtocolComponent::Retention);
            if let Some(stored) = stored {
                self.discard_vqcs(view, stored.held.id);
            }
            return Ok(Some(WorkStatus::Requeue));
        }
        Ok(None)
    }

    /// Pins the views from the greatest defined one below `view` up to `view` on the chain of
    /// `parent`, the V-QC the leader block finalized by L-QC `lqc` names (case (a)), and reports
    /// each view resolved. Returns `false` when persistence lacks room; already defined views are
    /// left as they are, and a chain that does not reach the greatest defined view pins nothing.
    fn pin(
        &mut self,
        view: View,
        lqc: CertificateId<H::Digest>,
        parent: &StoredVqc<V, H::Digest>,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<bool, StepError> {
        let defined = self.defined_through();
        let horizon = self
            .durable
            .state
            .view
            .get()
            .saturating_add(self.profile.resources().max_future_view_distance());
        // Emission states beyond the future-view horizon wait until this node catches up.
        if defined >= view || view.get() > horizon {
            return Ok(true);
        }
        // The records of the chain's V-QCs from view `defined` up to the parent's, newest first.
        let mut records = Vec::new();
        let mut current = Some(parent);
        while let Some(stored) = current.filter(|stored| stored.held.view >= defined) {
            records.push(Arc::clone(&stored.record));
            current = self.stored_vqc(&stored.parent);
        }
        let reaches = records.len() as u64 == view.get() - defined.get();
        let Some(commitment) = self.commitment_of(defined).filter(|_| reaches) else {
            return Ok(true);
        };
        if records
            .last()
            .is_some_and(|oldest| oldest.parent() != commitment)
        {
            // Cases (a) and (b) agree on every base while at most `f` validators are faulty.
            return Err(StepError::ViewInvariant);
        }
        let by = Resolution::Pinned { view, lqc };
        for (resolved, record) in (defined.get()..)
            .map(View::new)
            .zip(records.into_iter().rev())
        {
            if !self.emit(resolved, record.as_ref().clone(), by.clone(), capabilities)? {
                return Ok(false);
            }
            let emitter = &mut self.components.emitter;
            if let Some((_, chains)) = emitter
                .undetermined
                .take_if(|(undetermined, _)| *undetermined == resolved)
            {
                emitter.pinned_undetermined.record(chains);
            }
        }
        Ok(true)
    }

    /// Determines the view after the greatest defined one from the final votes read for the
    /// greatest defined view (case (b)). Returns `None` when they do not determine it yet.
    fn determine_next(
        &mut self,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<Option<WorkStatus>, StepError> {
        let view = self.defined_through();
        let finals = self
            .finals(view)
            .map(|(sender, content)| (sender, Arc::clone(content)))
            .collect::<Vec<_>>();
        let quorum = self.profile.codec().view_quorum();
        if finals.len() < quorum || self.components.emitter.checked == Some((view, finals.len())) {
            return Ok(None);
        }
        let (Some(base), Some(commitment)) = (self.base_of(view), self.commitment_of(view)) else {
            return Ok(None);
        };
        let tips = match self.determination(base, &finals) {
            Ok(tips) => tips,
            Err(undetermined) => {
                let emitter = &mut self.components.emitter;
                emitter.checked = Some((view, finals.len()));
                emitter.undetermined = Some((view, undetermined));
                return Ok(None);
            }
        };
        let record = HistoryRecord::new(commitment, tips).map_err(|_| StepError::ViewInvariant)?;
        if !self.emit(view, record, Resolution::Determined, capabilities)? {
            return Ok(Some(WorkStatus::Blocked));
        }
        Ok(Some(WorkStatus::Requeue))
    }

    /// Returns `Det(G)` over `base` for some `G` of `n - f` of `finals` whose tips all resolve,
    /// when one determines every chain, else the chains `finals` leave undetermined.
    ///
    /// With exactly `n - f` votes a chain is determined iff every vote reaches the same window top
    /// above its base (or none does), so some `G` determines every chain iff `n - f` votes share
    /// one reach on every chain; votes are grouped by that reach vector.
    fn determination(
        &self,
        base: &[BlockRef<H::Digest>],
        finals: &[(Participant, Arc<VoteContent<H::Digest>>)],
    ) -> Result<Vec<BlockRef<H::Digest>>, UndeterminedChains> {
        let codec = self.profile.codec();
        let cap = codec.window().cap();
        let quorum = codec.view_quorum();
        let headers = &self.components.chain.headers;
        // Per vote, per chain: the reach of the vote's tip, `None` when it does not resolve.
        let reaches = finals
            .iter()
            .map(|(_, content)| {
                base.iter()
                    .zip(content.tips())
                    .map(|(base, tip)| match reach(base, cap, tip, headers) {
                        Reach::Outside => Some(None),
                        Reach::Top(top) => Some(Some(top)),
                        Reach::Unresolved => None,
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut groups = BTreeMap::<&[Option<Option<BlockRef<H::Digest>>>], Vec<usize>>::new();
        for (index, reaches) in reaches.iter().enumerate() {
            if reaches.iter().all(Option::is_some) {
                groups.entry(reaches).or_default().push(index);
            }
        }
        let determined = groups
            .into_values()
            .find(|members| members.len() >= quorum)
            .and_then(|group| {
                let chosen = group
                    .into_iter()
                    .take(quorum)
                    .map(|index| {
                        let (sender, content) = &finals[index];
                        (*sender, content.as_ref().clone())
                    })
                    .collect::<Vec<_>>();
                det(base, &chosen, codec, headers).ok().flatten()
            });
        determined.ok_or_else(|| undetermined_chains(&reaches, base.len(), quorum))
    }

    /// Stages the emission state of the view after `resolved` and reports `resolved` resolved once
    /// it is durable. Returns `false` when persistence lacks room.
    fn emit(
        &mut self,
        resolved: View,
        record: HistoryRecord<H::Digest>,
        by: Resolution<H::Digest>,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<bool, StepError> {
        let view = resolved.next();
        let tips = record.tips().to_vec();
        if !self.stage(Change::EmissionResolved { view, record, by }, capabilities)? {
            return Ok(false);
        }
        self.finalize_chains(&tips);
        let report = self
            .view_resolved(resolved)
            .ok_or(StepError::ViewInvariant)?;
        self.report_when_durable([report]);
        Ok(true)
    }

    /// Reports the pool's progress in the greatest view whose state is defined when it changed
    /// since the last report: per chain `b*`, which only rises, and the settled chains, which
    /// stay settled. Each chain's walk, tally, and settledness advance only by what changed since
    /// the last sweep.
    fn report_sweep(&mut self) {
        let view = self.defined_through();
        let Some(base) = self.base_of(view).map(<[_]>::to_vec) else {
            return;
        };
        let codec = self.profile.codec();
        let mut sweep = match self.components.emitter.sweep.take() {
            Some(sweep) if sweep.view == view => sweep,
            _ => Sweep::new(view, &base, codec.window().cap()),
        };
        let headers = &self.components.chain.headers;
        let mut changed = false;
        for (index, base) in base.iter().enumerate() {
            let chain = base.chain();
            let final_tip = self.final_tip(view, base, sweep.finals[index]);
            let raised = final_tip != sweep.finals[index];
            sweep.finals[index] = final_tip;
            changed |= raised;
            let tally = &mut sweep.chains[index];
            let bindings = self.first_binding(view, chain);
            let read = bindings.len() - tally.read;
            for (_, tip) in &bindings[tally.read..] {
                tally.bindings.add(*tip, headers);
            }
            tally.read = bindings.len();
            let revision = headers.revision(chain);
            let resolved = tally.bindings.has_unresolved()
                && tally.tried != revision
                && tally.bindings.retry(headers);
            tally.tried = revision;
            #[cfg(test)]
            {
                self.components.emitter.classified += read;
            }
            if sweep.settled.contains(chain) || !(raised || read > 0 || resolved) {
                continue;
            }
            #[cfg(test)]
            {
                self.components.emitter.evaluations += 1;
            }
            if tally
                .bindings
                .settledness(&final_tip, codec, headers)
                .settled
            {
                sweep.settled.insert(chain);
                changed = true;
            }
        }
        if changed {
            self.finalize_chains(&sweep.finals);
            self.report_in_order([Activity::ViewSweep {
                view,
                finals: sweep.finals.as_slice().into(),
                settled: sweep.settled.clone(),
            }]);
        }
        self.components.emitter.sweep = Some(sweep);
    }

    /// Resets the emission component at a start or restart and reports every retained resolution
    /// again; the drive then reports the finalizations of the L-QCs held again and the sweep.
    pub(in crate::multimmit::machine) fn restore_emission(&mut self) {
        self.components.emitter = Emitter::new();
        self.restore_lqc_assembly();
        let state = &self.durable.state;
        let Some(first) = state.emission.first_key_value().map(|(view, _)| *view) else {
            return;
        };
        let last = self.defined_through();
        let reports = (first.previous().unwrap_or(first).get()..last.get())
            .filter_map(|view| self.view_resolved(View::new(view)))
            .collect::<Vec<_>>();
        if let Some(newest) = reports.last()
            && let Activity::ViewResolved { tips, .. } = newest
        {
            self.finalize_chains(tips);
        }
        self.report_in_order(reports);
        self.wake(ProtocolComponent::Emission);
    }
}
