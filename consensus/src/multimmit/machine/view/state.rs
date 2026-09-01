//! View state: per-view entries, retirement, and the dispatch of observed facts.

#[cfg(test)]
use super::slot::ViewTransition;
use super::{
    certificate::{CertificateScan, ViewCertificateId, ViewCertificateJob},
    claims::{Claim, ClaimIndex, ClaimKind},
    proposal::{PassRestarts, RegularSignPass, TimeoutCutoff, ViewMetrics},
    slot::{SlotError, ViewSlotSnapshot},
    store::{
        LeaderRecord, MessageRecords, NullificationRecords, NullifyRecord, ParentProof,
        ParentRecord, ProposalRecords, StickyMessage, ViewMessageKind, VqcRecords,
    },
};
use crate::{
    Epochable as _, Viewable,
    multimmit::{
        algebra::{Tips, ValidatedVqc},
        config::{Profile, Role},
        machine::{
            artifact::{Held, LeaderBlockKind, NullificationKind, NullifyKind, VqcKind},
            capability::{Capabilities, Capability, CryptoJob},
            durability::SignRequest,
            job::{Generation, IdSequence, JobTable},
            util::{ObservedList, drain_prefix},
            verification::Observation,
            vote_body::VoteBuilds,
        },
        types::{
            Artifact, ArtifactId, CertificateId, CodecConfig, LeaderBlock, SelectedCommitments,
            TipRecord, genesis_history,
        },
    },
    types::{Epoch, Participant, Round, View},
};
use bytes::Bytes;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound::Excluded,
    sync::Arc,
};

/// A logical view timer interpreted by an attached runtime.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ViewTimer {
    generation: Generation,
    round: Round,
    delay: Duration,
}

impl ViewTimer {
    /// Creates the timer for `round`, owned by `generation`, firing after `delay`.
    pub(crate) const fn new(generation: Generation, round: Round, delay: Duration) -> Self {
        Self {
            generation,
            round,
            delay,
        }
    }

    /// Returns the process generation owning this timer.
    pub(crate) const fn generation(self) -> Generation {
        self.generation
    }

    /// Returns the round whose timeout this timer represents.
    pub(crate) const fn round(self) -> Round {
        self.round
    }

    /// Returns the logical delay requested from the runtime.
    pub(crate) const fn delay(self) -> Duration {
        self.delay
    }
}

/// The floors below which view state is no longer retained.
pub(crate) struct RetireFloors<D: Digest> {
    /// The durably retired view: slots, records and claims at or below it are dropped.
    pub(crate) transitions: View,
    /// Proposal parents strictly below this view are dropped unless still referenced.
    pub(crate) parents: View,
    /// The proposal anchor, which is always retained as a parent.
    pub(crate) anchor: Option<CertificateId<D>>,
}

/// View-layer facts and this node's view choices for one epoch.
///
/// It owns each retained view's entry, the proposal parents later views may build on, the claims
/// of unverified view-scoped artifacts, certificate jobs and the certificate scan, forwarding
/// marks, the in-flight proposal or vote pass, and the proposal frontier.
pub(crate) struct ViewState<V: Variant, D: Digest> {
    pub(super) config: CodecConfig,
    /// This node's participant when it validates, or `None` when it observes.
    pub(super) me: Option<Participant>,
    pub(super) epoch: Epoch,
    /// Views at or below this one are retired.
    pub(super) retired_transitions: View,
    /// The view of the V-QC this node's next proposal builds on.
    pub(super) proposal_anchor_view: View,
    /// Every view above the anchor's view and at or below this one is nullified.
    pub(super) proposal_nullified_through: View,
    /// Proposal parents by certificate identifier.
    pub(super) parents: BTreeMap<CertificateId<D>, ParentRecord<V, D>>,
    /// Proposal parent identifiers by the view their V-QC certified.
    pub(super) parents_by_view: BTreeMap<View, Vec<CertificateId<D>>>,
    /// Everything retained for each view.
    pub(super) views: BTreeMap<View, ViewEntry<V, D>>,
    /// The view and signer of every retained view message.
    pub(super) message_locations: BTreeMap<ArtifactId<D>, (View, Participant)>,
    /// Slots claimed by artifacts awaiting verification.
    pub(super) claims: ClaimIndex<D>,
    /// Certificate jobs in flight.
    pub(super) certificate_jobs: JobTable<ViewCertificateId, ViewCertificateJob<V, D>>,
    /// Views whose nullification was forwarded.
    pub(super) forwarded_nullifications: BTreeSet<View>,
    /// The V-QC forwarded for each view.
    pub(super) forwarded_vqcs: BTreeMap<View, CertificateId<D>>,
    /// Views holding a nullification not yet forwarded.
    pub(super) forwardable_nullifications: BTreeSet<View>,
    /// Views holding a V-QC not yet forwarded.
    pub(super) forwardable_vqcs: BTreeSet<View>,
    /// Views with enough settled messages or nullify shares for certificate work.
    pub(super) ready_certificate_views: BTreeSet<View>,
    /// The certificate scan in progress, if any.
    pub(super) certificate_scan: Option<CertificateScan<V, D>>,
    /// This node's proposal or vote pass in progress, if any.
    pub(super) regular_sign_pass: Option<RegularSignPass<V, D>>,
    /// Vote-pass lifecycle events not yet drained for tracing.
    pub(super) vote_builds: VoteBuilds,
    /// Header-triggered restarts consumed by the in-flight proposal pass.
    ///
    /// Stored outside the pass because each restart discards the pass.
    pub(super) pass_restarts: PassRestarts,
    /// Proposal diagnostics for metrics.
    pub(super) metrics: ViewMetrics,
    /// Identifiers for certificate jobs.
    pub(super) certificate_ids: IdSequence<ViewCertificateId>,
    /// Certificate work issued and not yet taken.
    pub(super) capabilities: Capabilities<V, D>,
}

/// Everything retained for one view.
pub(super) struct ViewEntry<V: Variant, D: Digest> {
    /// This node's local choices in the view.
    pub(super) slot: ViewSlotSnapshot<V, D>,
    /// The earliest proposal or certificate designating each leader block, by digest.
    pub(super) leaders: BTreeMap<D, LeaderRecord<V, D>>,
    pub(super) proposals: ProposalRecords<V, D>,
    pub(super) messages: BTreeMap<Participant, MessageRecords<V, D>>,
    /// The view message settled for each signer once no earlier claim can displace it.
    pub(super) sticky: BTreeMap<Participant, StickyMessage<V, D>>,
    pub(super) nullifies: BTreeMap<Participant, NullifyRecord<V, D>>,
    /// Signers whose messages or nullify shares oppose this node's vote.
    pub(super) post_vote_evidence: BTreeSet<Participant>,
    /// The choice frozen when the view's timer fired.
    pub(super) timeout: Option<TimeoutCutoff<D>>,
    /// V-QCs, with the latest strictly extending transcript assembled for each target. Per-view
    /// aggregation is serialized, and completing a job invalidates the view's scan before
    /// another candidate is selected.
    pub(super) vqc: VqcTrack<V, D>,
    /// Nullifications, and whether this node assembled one.
    pub(super) nullification: NullificationTrack<V, D>,
}

impl<V: Variant, D: Digest> Default for ViewEntry<V, D> {
    fn default() -> Self {
        Self {
            slot: ViewSlotSnapshot::default(),
            leaders: BTreeMap::new(),
            proposals: ObservedList::default(),
            messages: BTreeMap::new(),
            sticky: BTreeMap::new(),
            nullifies: BTreeMap::new(),
            post_vote_evidence: BTreeSet::new(),
            timeout: None,
            vqc: CertificateTrack::default(),
            nullification: CertificateTrack::default(),
        }
    }
}

/// V-QCs for a view, with the latest strictly extending transcript assembled for each target.
pub(super) type VqcTrack<V, D> =
    CertificateTrack<VqcRecords<V, D>, BTreeMap<D, Vec<ArtifactId<D>>>>;

/// Nullifications for a view, and whether this node assembled one.
pub(super) type NullificationTrack<V, D> = CertificateTrack<NullificationRecords<V, D>, bool>;

/// One exit kind's certificates for a view.
#[derive(Default)]
pub(super) struct CertificateTrack<R, A> {
    /// Verified certificates, earliest first.
    pub(super) records: R,
    /// The observation of the assembly job in flight, if any.
    pub(super) pending: Option<Observation>,
    /// What this node already assembled.
    pub(super) assembled: A,
}

/// A contradictory authenticated view fact or malformed derived transition.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ViewError {
    #[error(transparent)]
    Slot(#[from] SlotError),
    #[error("the selected proposal is malformed")]
    Proposal,
    #[error("the selected parent certificate is malformed")]
    Certificate,
    #[error("the selected proposal parent is unavailable")]
    MissingParent,
    #[error("a producer-chain fact required by the view transition is malformed")]
    Chain,
    #[error("a view-certificate completion does not match its issued transcript")]
    CompletionMismatch,
    #[error("a view-certificate identifier overflowed")]
    IdentifierExhausted,
}

impl<V: Variant, D: Digest> ViewState<V, D> {
    /// Creates the view state for the profile's epoch, with the genesis anchor as the only
    /// proposal parent.
    pub(crate) fn new<H: Hasher<Digest = D>>(profile: &Profile<H::Digest>) -> Self {
        let genesis = profile.protocol().genesis();
        let tips = Tips::new(genesis.tips().to_vec())
            .expect("validated genesis has one tip per canonical chain");
        let history = genesis_history::<H>(genesis);
        let proposed = genesis
            .tips()
            .iter()
            .map(|tip| tip.height())
            .collect::<Vec<_>>();
        let parent = ParentRecord {
            id: genesis.vqc(),
            view: View::zero(),
            history,
            canonical: Bytes::new(),
            proof: ParentProof::Genesis,
            child_history: TipRecord::new(history, tips.blocks().to_vec(), proposed.clone())
                .ok()
                .map(|record| record.commitment::<H>()),
            proposed,
            tips: Arc::new(tips),
            commitments: SelectedCommitments::new(genesis.epoch(), Vec::new()),
            messages: 0,
        };
        let me = match profile.role() {
            Role::Validator(participant) => Some(participant),
            Role::Observer => None,
        };
        Self {
            config: profile.codec(),
            me,
            epoch: profile.protocol().epoch(),
            retired_transitions: View::zero(),
            proposal_anchor_view: View::zero(),
            proposal_nullified_through: View::zero(),
            parents: BTreeMap::from([(genesis.vqc(), parent)]),
            parents_by_view: BTreeMap::from([(View::zero(), vec![genesis.vqc()])]),
            views: BTreeMap::new(),
            message_locations: BTreeMap::new(),
            claims: ClaimIndex::default(),
            certificate_jobs: JobTable::new(),
            forwarded_nullifications: BTreeSet::new(),
            forwarded_vqcs: BTreeMap::new(),
            forwardable_nullifications: BTreeSet::new(),
            forwardable_vqcs: BTreeSet::new(),
            ready_certificate_views: BTreeSet::new(),
            certificate_scan: None,
            regular_sign_pass: None,
            vote_builds: VoteBuilds::default(),
            pass_restarts: PassRestarts {
                view: View::zero(),
                count: 0,
            },
            metrics: ViewMetrics::default(),
            certificate_ids: IdSequence::new(),
            capabilities: Vec::new(),
        }
    }

    /// Returns selected paths owned by this V-QC or the leader's retained parent.
    pub(crate) fn selected_commitments(
        &self,
        artifact: &Arc<Artifact<V, D>>,
    ) -> Option<&SelectedCommitments<D>> {
        match artifact.as_ref() {
            Artifact::Vqc(certificate) => self
                .parents_by_view
                .get(&certificate.view())?
                .iter()
                .filter_map(|id| self.parents.get(id))
                .find(|parent| {
                    matches!(
                        &parent.proof,
                        ParentProof::Vqc(retained) if Arc::ptr_eq(retained.arc(), artifact)
                    )
                })
                .map(|parent| &parent.commitments),
            Artifact::LeaderBlock(block) => self
                .parents
                .get(&block.block().parent())
                .map(|parent| &parent.commitments),
            _ => None,
        }
    }

    /// Reconstructs the safe-tip opening committed by a leader from its retained parent.
    pub(crate) fn leader_history<H: Hasher<Digest = D>>(
        &self,
        leader: &LeaderBlock<V, D>,
    ) -> Result<Arc<TipRecord<D>>, ViewError> {
        let parent = self
            .parents
            .get(&leader.parent())
            .ok_or(ViewError::MissingParent)?;
        let history = Arc::new(parent.tip_record()?);
        (history.commitment::<H>() == leader.history())
            .then_some(history)
            .ok_or(ViewError::Proposal)
    }

    /// Applies every retirement floor in dependency order and returns the retired proposal
    /// parents.
    pub(crate) fn retire(&mut self, floors: RetireFloors<D>) -> Vec<CertificateId<D>> {
        self.retire_transitions_through(floors.transitions);
        let retired = self.retire_parents_through(floors.parents, floors.anchor);
        self.retire_forwarded_through(floors.transitions);
        retired
    }

    /// Returns whether this node may still vote, abstain or time out in `view`.
    pub(super) fn can_vote(&self, view: View) -> bool {
        self.entry(view).is_none_or(|entry| entry.slot.can_vote())
    }

    /// Returns whether this node voted in `view`.
    pub(super) fn has_voted(&self, view: View) -> bool {
        self.entry(view).is_some_and(|entry| entry.slot.has_voted())
    }

    fn slot_mut(&mut self, view: View) -> &mut ViewSlotSnapshot<V, D> {
        &mut self.entry_mut(view).slot
    }

    /// Returns the entry retained for `view`, if any.
    pub(super) fn entry(&self, view: View) -> Option<&ViewEntry<V, D>> {
        self.views.get(&view)
    }

    /// Returns the entry for `view`, creating an empty one if none is retained.
    pub(super) fn entry_mut(&mut self, view: View) -> &mut ViewEntry<V, D> {
        self.views.entry(view).or_default()
    }

    /// Drops every view entry, claim, certificate job, and certificate scan at or below `floor`.
    pub(crate) fn retire_transitions_through(&mut self, floor: View) {
        if floor <= self.retired_transitions {
            return;
        }
        self.retired_transitions = floor;
        let retained = |view: &View| *view > floor;

        for (_, entry) in drain_prefix(&mut self.views, |view| !retained(view)) {
            for records in entry.messages.values() {
                for (id, _) in records.iter() {
                    self.message_locations.remove(&id);
                }
            }
        }
        self.claims.retire_through(floor);
        self.certificate_jobs.retain(|job| retained(&job.view()));
        for views in [
            &mut self.forwardable_nullifications,
            &mut self.forwardable_vqcs,
            &mut self.ready_certificate_views,
        ] {
            views.extract_if(..=floor, |_| true).for_each(drop);
        }
        if self
            .certificate_scan
            .as_ref()
            .is_some_and(|scan| !retained(&scan.view))
        {
            self.certificate_scan = None;
        }
        // The view state issues only nullification recoveries and V-QC aggregations.
        self.capabilities.retain(|capability| match capability {
            Capability::Crypto(CryptoJob::RecoverNullification(job)) => retained(&job.view),
            Capability::Crypto(CryptoJob::AggregateVqc(job)) => retained(&job.leader().view()),
            _ => true,
        });
    }

    /// Retains forwarding facts for live views and retained proposal parents.
    ///
    /// Parent provenance allows proposals to omit a certificate already authorized for dissemination.
    /// Retire parents first so facts below the floor remain bounded by retained parents.
    pub(crate) fn retire_forwarded_through(&mut self, floor: View) {
        self.forwarded_vqcs
            .extract_if(..=floor, |_, id| !self.parents.contains_key(id))
            .for_each(drop);
        self.forwarded_nullifications
            .extract_if(..=floor, |_| true)
            .for_each(drop);
    }

    /// Drops proposal parents strictly below `floor`, except `anchor` and parents a retained
    /// leader block names, and returns the dropped identifiers in ascending order.
    pub(crate) fn retire_parents_through(
        &mut self,
        floor: View,
        anchor: Option<CertificateId<D>>,
    ) -> Vec<CertificateId<D>> {
        if floor.is_zero() {
            return Vec::new();
        }
        let live_leader_parents = self
            .views
            .values()
            .flat_map(|entry| entry.leaders.values())
            .map(|leader| leader.value.get().parent())
            .collect::<BTreeSet<_>>();
        let mut removed = Vec::new();
        self.parents_by_view
            .extract_if((Excluded(View::zero()), Excluded(floor)), |_, ids| {
                ids.retain(|id| {
                    if Some(*id) == anchor || live_leader_parents.contains(id) {
                        return true;
                    }
                    self.parents.remove(id);
                    removed.push(*id);
                    false
                });
                ids.is_empty()
            })
            .for_each(drop);
        removed.sort_unstable();
        removed
    }

    /// Sets the proposal anchor's view and the view through which the views above it are
    /// nullified.
    pub(crate) const fn restore_proposal_frontier(
        &mut self,
        anchor: View,
        nullified_through: View,
    ) {
        self.proposal_anchor_view = anchor;
        self.proposal_nullified_through = nullified_through;
    }

    /// Installs the local view choices of a restored snapshot.
    pub(crate) fn restore_slots(&mut self, slots: BTreeMap<View, ViewSlotSnapshot<V, D>>) {
        for entry in self.views.values_mut() {
            entry.slot = ViewSlotSnapshot::default();
        }
        for (view, slot) in slots {
            self.entry_mut(view).slot = slot;
        }
    }

    /// Records the proof whose durable transition exited `view`.
    pub(crate) fn observe_exit(&mut self, view: View, proof: ArtifactId<D>) {
        self.slot_mut(view).observe_exit(proof);
    }

    /// Returns whether a V-QC for `view` was forwarded.
    pub(super) fn vqc_forwarded(&self, view: View) -> bool {
        self.forwarded_vqcs.contains_key(&view)
    }

    /// Returns whether a nullification for `view` was forwarded.
    pub(super) fn nullification_forwarded(&self, view: View) -> bool {
        self.forwarded_nullifications.contains(&view)
    }

    /// Returns whether `artifact` is too old to change view state.
    ///
    /// Certificates at or below the retired transition floor still feed exits and forwarding: a
    /// V-QC always does, and a nullification does until its view has been forwarded. Any other
    /// view-scoped artifact is ignored strictly below the floor.
    fn ignores_retired(&self, artifact: &Artifact<V, D>) -> bool {
        let Some(view) = artifact.view() else {
            return false;
        };
        if view > self.retired_transitions {
            return false;
        }
        match artifact {
            Artifact::Vqc(_) => false,
            Artifact::Nullification(_) => self.nullification_forwarded(view),
            _ => view < self.retired_transitions,
        }
    }

    /// Records the view slot an unverified `artifact` claims, so records from later cohorts wait
    /// for its verdict.
    pub(crate) fn claim(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Artifact<V, D>,
    ) {
        let Some(claim) = Claim::for_artifact(artifact) else {
            return;
        };
        self.claims.insert(claim, id, observation);
        self.refresh_view(claim.view);
    }

    /// Releases the claim of an artifact that failed verification, and re-settles its signer's
    /// view message.
    pub(crate) fn reject(&mut self, id: ArtifactId<D>, artifact: &Artifact<V, D>) {
        let Some(claim) = Claim::for_artifact(artifact) else {
            return;
        };
        self.claims.remove(claim, id);
        if let ClaimKind::ViewMessage(participant) = claim.kind {
            let view = claim.view;
            self.remove_message(id, view, participant);
            self.settle_message(view, participant);
            if self.has_voted(view) {
                self.rebuild_post_vote_evidence(view);
            }
        }
        self.refresh_view(claim.view);
    }

    /// Records a verified artifact and releases its claim.
    ///
    /// Artifacts too old to change view state are dropped after their claim is released.
    pub(crate) fn observe<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        artifact: &Arc<Artifact<V, D>>,
        validated_vqc: Option<ValidatedVqc<D>>,
    ) -> Result<(), ViewError> {
        let claim = Claim::for_artifact(artifact);
        if let Some(claim) = claim {
            self.claims.remove(claim, id);
        }
        if self.ignores_retired(artifact) {
            return Ok(());
        }
        if let Some(block) = Held::<LeaderBlockKind, V, D>::try_new(artifact) {
            self.observe_proposal::<H>(id, observation, block);
        } else if let Some(message) = Held::<ViewMessageKind, V, D>::try_new(artifact) {
            let (view, signer) = message.author();
            self.observe_message(id, observation, message);
            self.settle_message(view, signer);
        } else if let Some(share) = Held::<NullifyKind, V, D>::try_new(artifact) {
            self.observe_nullify(observation, share);
        } else if let Some(certificate) = Held::<NullificationKind, V, D>::try_new(artifact) {
            self.observe_nullification(id, observation, certificate);
        } else if let Some(certificate) = Held::<VqcKind, V, D>::try_new(artifact) {
            self.observe_vqc::<H>(id, observation, certificate, validated_vqc)?;
        }
        if let Some(claim) = claim {
            self.refresh_view(claim.view);
        }
        Ok(())
    }

    /// Applies a durably reserved signing request to the slot of its view.
    pub(crate) fn observe_sign_request(
        &mut self,
        request: &SignRequest<V, D>,
    ) -> Result<(), ViewError> {
        if matches!(request, SignRequest::DaVote(_))
            && matches!(
                self.regular_sign_pass,
                Some(RegularSignPass::Proposal { .. })
            )
        {
            self.regular_sign_pass = None;
        }
        let Some(view) = request.consensus_view() else {
            return Ok(());
        };
        self.slot_mut(view).observe_request(request)?;
        if matches!(request, SignRequest::Vote(_)) {
            self.rebuild_post_vote_evidence(view);
        }
        Ok(())
    }

    /// Applies a durably retained artifact: this node's own view messages update its slot, and
    /// a locally assembled certificate marks its view.
    pub(crate) fn observe_durable_artifact(
        &mut self,
        artifact: &Artifact<V, D>,
    ) -> Result<(), ViewError> {
        match artifact {
            Artifact::LeaderBlock(_)
            | Artifact::Vote(_)
            | Artifact::NoVote(_)
            | Artifact::Nullify(_) => {
                let (Some(view), Some(signer)) = (artifact.view(), artifact.signer()) else {
                    return Ok(());
                };
                if self.me != Some(signer) {
                    return Ok(());
                }
                self.slot_mut(view).observe_artifact(artifact)?;
                if matches!(artifact, Artifact::Vote(_)) {
                    self.rebuild_post_vote_evidence(view);
                }
                Ok(())
            }
            Artifact::Nullification(certificate) => {
                self.entry_mut(certificate.view()).nullification.assembled = true;
                self.refresh_view(certificate.view());
                Ok(())
            }
            Artifact::Vqc(certificate) => {
                self.refresh_view(certificate.view());
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Records that a V-QC or nullification was forwarded, dropping the records of a retired view
    /// that only forwarding still needed.
    pub(crate) fn observe_forwarded<H: Hasher<Digest = D>>(&mut self, artifact: &Artifact<V, D>) {
        let view = match artifact {
            Artifact::Vqc(certificate) => {
                self.forwarded_vqcs
                    .insert(certificate.view(), certificate.id::<H>());
                if certificate.view() <= self.retired_transitions {
                    if let Some(entry) = self.views.get_mut(&certificate.view()) {
                        entry.vqc.records = ObservedList::default();
                    }
                    self.forwardable_vqcs.remove(&certificate.view());
                }
                certificate.view()
            }
            Artifact::Nullification(certificate) => {
                self.forwarded_nullifications.insert(certificate.view());
                if certificate.view() <= self.retired_transitions {
                    if let Some(entry) = self.views.get_mut(&certificate.view()) {
                        entry.nullification.records = ObservedList::default();
                    }
                    self.forwardable_nullifications.remove(&certificate.view());
                }
                certificate.view()
            }
            _ => return,
        };
        self.refresh_view(view);
    }
}

#[cfg(test)]
impl<V: Variant, D: Digest> ViewState<V, D> {
    /// Returns the number of assembled V-QC transcripts retained.
    pub(crate) fn retained_vqc_transcripts(&self) -> usize {
        self.views
            .values()
            .map(|entry| entry.vqc.assembled.len())
            .sum()
    }

    /// Returns the exit proof of every retained exited view.
    pub(crate) fn retained_exit_proofs(&self) -> BTreeMap<View, ArtifactId<D>> {
        self.views
            .iter()
            .filter_map(|(view, entry)| match entry.slot.transition {
                ViewTransition::Exited(proof) => Some((*view, proof)),
                ViewTransition::Active => None,
            })
            .collect()
    }

    /// Returns the number of views with a forwarded V-QC.
    pub(crate) fn retained_forwarded_vqcs(&self) -> usize {
        self.forwarded_vqcs.len()
    }

    /// Returns the number of retained proposal parents.
    pub(crate) fn retained_parents(&self) -> usize {
        self.parents.len()
    }

    /// Reports whether a certificate assembly is marked in flight for the view.
    pub(crate) fn certificate_pending(&self, view: View) -> bool {
        self.entry(view).is_some_and(|entry| {
            entry.vqc.pending.is_some() || entry.nullification.pending.is_some()
        })
    }

    /// Reports whether the view re-derived as ready for certificate work.
    pub(crate) fn certificate_ready(&self, view: View) -> bool {
        self.ready_certificate_views.contains(&view)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Artifact, ArtifactId, Claim, ClaimIndex, ClaimKind, Held, Observation, Participant, View,
        ViewState,
    };
    use crate::multimmit::machine::{
        testing::fixtures::Harness,
        tests::fixtures::{leader, view_vote},
    };
    use commonware_cryptography::{Hasher, Sha256};
    use std::{collections::BTreeMap, sync::Arc};

    fn claim_kinds() -> [ClaimKind; 7] {
        [
            ClaimKind::Proposal,
            ClaimKind::ViewMessage(Participant::new(0)),
            ClaimKind::ViewMessage(Participant::new(u32::MAX)),
            ClaimKind::Nullify(Participant::new(0)),
            ClaimKind::Nullify(Participant::new(u32::MAX)),
            ClaimKind::Nullification,
            ClaimKind::Vqc,
        ]
    }

    #[test]
    fn retirement_preserves_message_and_claim_indices() {
        let insert_claims = |claims: &mut ClaimIndex<_>, view: View| {
            for kind in claim_kinds() {
                for cohort in [7u64, 9] {
                    let id = ArtifactId::new(Sha256::hash(&[&cohort.to_le_bytes()]));
                    claims.insert(Claim::new(view, kind), id, Observation::new(cohort, 0));
                }
            }
        };
        let (machine, _) = Harness::observer().participants(6).start();
        let mut views = ViewState::new::<Sha256>(machine.profile());
        for view in [1, 2, 3] {
            let block = leader(&machine, view);
            for signer in [0, 1] {
                let artifact = Arc::new(Artifact::Vote(view_vote(&machine, &block, signer)));
                let id = artifact.id::<Sha256>();
                let message = Held::try_new(&artifact).expect("votes are view messages");
                views.observe_message(id, Observation::new(9, signer), message.clone());
                views.observe_message(id, Observation::new(7, signer), message);
            }
            insert_claims(&mut views.claims, View::new(view));
        }
        let mut expected_messages = views.message_locations.clone();
        let mut retired = View::zero();
        for floor in [0, 1, 1, 0, 2, u64::MAX] {
            let floor = View::new(floor);
            views.retire_transitions_through(floor);
            retired = retired.max(floor);
            expected_messages.retain(|_, (view, _)| *view > floor);
            assert_eq!(views.message_locations, expected_messages);
            let mut expected_claims = ClaimIndex::default();
            for view in [1, 2, 3]
                .map(View::new)
                .into_iter()
                .filter(|view| *view > retired)
            {
                insert_claims(&mut expected_claims, view);
            }
            assert_eq!(views.claims, expected_claims);
            for view in [1, 2, 3].map(View::new) {
                let expected = (view > retired).then_some(7);
                for kind in claim_kinds() {
                    assert_eq!(views.claims.first_cohort(Claim::new(view, kind)), expected);
                }
                assert_eq!(views.claims.first_message_cohort(view), expected);
                assert_eq!(views.claims.first_nullify_cohort(view), expected);
            }
            let locations = views
                .views
                .iter()
                .flat_map(|(view, entry)| {
                    entry.messages.iter().flat_map(move |(signer, records)| {
                        records.iter().map(move |(id, record)| {
                            // The earlier of the two observations is retained.
                            assert_eq!(record.observation.cohort(), 7);
                            (id, (*view, *signer))
                        })
                    })
                })
                .collect::<BTreeMap<_, _>>();
            assert_eq!(locations, expected_messages);
        }
    }
}
