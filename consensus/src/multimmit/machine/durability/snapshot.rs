//! Checkpoint snapshots, their validation, and the view projection derived on restore.

#[cfg(test)]
use super::SignEffect;
use super::{
    Cursor, DurableState, EffectId, OutboxEntry, ReplayError, SignRequest, TransitionReason,
};
#[cfg(test)]
use crate::multimmit::types::{ArtifactId, BlockRef};
use crate::{
    Epochable, Viewable,
    multimmit::{
        config::{Profile, Role},
        machine::view::{ViewSlotSnapshot, ViewStance, ViewTransition},
        types::{Artifact, ArtifactKind},
    },
    types::{Epoch, Height, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::BTreeMap, sync::Arc};

/// A projection of the last acknowledged durable cursor.
///
/// Verification jobs, unsynced reservations, and other volatile work are intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot<V: Variant, D: Digest> {
    pub(super) epoch: Epoch,
    pub(super) role: Role,
    pub(super) state: DurableState<V, D>,
}

impl<V: Variant, D: Digest> Snapshot<V, D> {
    pub(crate) const fn new(epoch: Epoch, role: Role, state: DurableState<V, D>) -> Self {
        Self { epoch, role, state }
    }

    /// Returns the acknowledged journal cursor.
    pub(crate) const fn cursor(&self) -> Cursor {
        self.state.cursor
    }

    /// Returns the highest view whose state the snapshot no longer retains.
    pub(crate) const fn retired_view(&self) -> View {
        self.state.retired_view
    }

    pub(crate) const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the greatest genesis or witnessed DA certificate on every producer chain.
    #[cfg(test)]
    pub(crate) fn certified_tips(&self) -> &[BlockRef<D>] {
        &self.state.certified_tips
    }

    /// Returns each chain's durable frontier for future DA votes.
    ///
    /// A validator advances a frontier by committing a vote or accepting a higher certificate.
    /// Observers mirror their certified heights because they never vote.
    #[cfg(test)]
    pub(crate) fn da_safety_heights(&self) -> &[Height] {
        &self.state.da_safety_heights
    }

    /// Returns network publications that remain durably outstanding, with their discharges.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) const fn outbox(&self) -> &BTreeMap<EffectId, OutboxEntry<V, D>> {
        &self.state.outbox
    }

    /// Returns local signing requests that remain durably authorized.
    #[cfg(test)]
    pub(crate) const fn signing_reservations(&self) -> &BTreeMap<EffectId, SignEffect<V, D>> {
        &self.state.signing_reservations
    }

    /// Returns locally created artifacts retained independently of publication lifetime.
    #[cfg(test)]
    pub(crate) const fn local_artifacts(&self) -> &BTreeMap<ArtifactId<D>, Arc<Artifact<V, D>>> {
        &self.state.local
    }

    /// Returns every artifact durably retained by this snapshot, once per holder.
    ///
    /// Locally created artifacts are only part of the set: certificates this node forwarded, the
    /// proofs it exited views with, the artifacts its outbox publishes (including a proposal's
    /// block and parent), and the blocks and parents its signing reservations reference are
    /// equally relevant to recovery validation.
    pub(crate) fn retained_artifacts(&self) -> impl Iterator<Item = Arc<Artifact<V, D>>> {
        let mut artifacts = Vec::new();
        self.state
            .visit_retained(|_, retained| artifacts.push(retained.to_artifact()));
        artifacts.into_iter()
    }

    pub(crate) fn into_state(self) -> DurableState<V, D> {
        self.state
    }

    /// Returns a codec-valid fixture at the requested acknowledged cursor.
    #[cfg(test)]
    pub(crate) const fn at_cursor_for_test(mut self, cursor: Cursor) -> Self {
        self.state.cursor = cursor;
        self
    }

    /// Validates the snapshot against `profile` and derives its view projection.
    pub(crate) fn validate<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H::Digest>,
    ) -> Result<ViewSnapshot<V, D>, ReplayError> {
        if self.epoch != profile.protocol().epoch() || self.role != profile.role() {
            return Err(ReplayError::Context);
        }
        let projection = ViewSnapshot::from_durable::<H>(self.epoch, self.role, &self.state)
            .map_err(|_| invalid(SnapshotReason::View))?;
        self.check_bounds::<H>(profile)?;
        self.check_local_artifacts::<H>(profile)?;
        self.check_certified_tips::<H>(profile)?;
        self.check_effects::<H>(profile)?;
        self.check_obligations()?;
        self.check_forwarded(profile)?;
        self.check_exits()?;
        self.check_proposal_anchor(profile)?;
        Ok(projection)
    }

    /// Checks entry counts, effect ownership, artifact occupancy, and produced height.
    fn check_bounds<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H::Digest>,
    ) -> Result<(), ReplayError> {
        let resources = profile.resources();
        let chains = profile.codec().chains();
        let initial_produced_height = match self.role {
            Role::Validator(participant) => profile
                .protocol()
                .producer_chain(participant)
                .map_or_else(Height::zero, |chain| {
                    profile.protocol().genesis().tips()[chain.index()].height()
                }),
            Role::Observer => Height::zero(),
        };
        let state = &self.state;
        if state.local.len() > resources.max_cached_artifacts()
            || state.effect_count() > resources.max_outbox_effects()
            || state
                .signing_reservations
                .keys()
                .any(|id| state.outbox.contains_key(id))
            || state.artifact_occupancy::<H>() > resources.max_cached_artifacts()
            || state.produced_height < initial_produced_height
            || matches!(self.role, Role::Observer) && !state.produced_height.is_zero()
            || state.certified_tips.len() != chains
            || state.da_safety_heights.len() != chains
        {
            return Err(invalid(SnapshotReason::Bounds));
        }
        Ok(())
    }

    /// Checks that every locally held artifact is in bounds, identified by its key, and one this
    /// role could have constructed.
    fn check_local_artifacts<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H::Digest>,
    ) -> Result<(), ReplayError> {
        let resources = profile.resources();
        let chains = profile.codec().chains();
        for (id, artifact) in &self.state.local {
            let locally_constructible = match (profile.role(), artifact.as_ref()) {
                (Role::Validator(_) | Role::Observer, Artifact::DaCertificate(certificate)) => self
                    .state
                    .certified_tips
                    .get(certificate.header().chain().index())
                    .is_some_and(|tip| certificate.block_ref::<H>() == *tip),
                (
                    Role::Validator(_) | Role::Observer,
                    Artifact::Nullification(_) | Artifact::Vqc(_) | Artifact::Lqc(_),
                ) => true,
                (Role::Validator(signer), _) => artifact.signer() == Some(signer),
                (Role::Observer, _) => false,
            };
            // A locally constructed transaction block is bound to its producer's own chain, the
            // same way the network path binds it. Without this, a tampered checkpoint could carry
            // an out-of-range chain into the per-chain tables.
            if let Artifact::TransactionBlock(block) = artifact.as_ref()
                && (block.header().chain().index() >= chains
                    || profile.protocol().producer(block.header().chain()) != artifact.signer())
            {
                return Err(invalid(SnapshotReason::LocalArtifact));
            }
            if artifact.encoded_len() > resources.max_artifact_bytes()
                || artifact.epoch() != self.epoch
                || !locally_constructible
                || artifact.id::<H>() != *id
                || matches!(artifact.as_ref(), Artifact::DaVote(vote)
                    if self.state
                        .da_safety_heights
                        .get(vote.header().chain().index())
                        .is_none_or(|height| vote.header().height() > *height))
            {
                return Err(invalid(SnapshotReason::LocalArtifact));
            }
        }
        Ok(())
    }

    /// Checks certified tips against genesis, DA safety heights against the tips, and that each
    /// advanced tip keeps exactly one retained certificate.
    fn check_certified_tips<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<H::Digest>,
    ) -> Result<(), ReplayError> {
        let genesis = profile.protocol().genesis().tips();
        let pipeline_depth = profile.codec().pipeline_depth() as u64;
        let state = &self.state;
        let tips_valid = state.certified_tips.iter().zip(genesis).enumerate().all(
            |(chain, (certified, genesis))| {
                certified.chain().index() == chain
                    && certified.height() >= genesis.height()
                    && (certified.height() != genesis.height() || certified == genesis)
            },
        );
        let safety_valid = state
            .da_safety_heights
            .iter()
            .zip(&state.certified_tips)
            .all(|(safe, certified)| match profile.role() {
                Role::Validator(_) => {
                    *safe >= certified.height()
                        && safe.get().saturating_sub(certified.height().get()) <= pipeline_depth
                }
                Role::Observer => *safe == certified.height(),
            });
        if !tips_valid || !safety_valid {
            return Err(invalid(SnapshotReason::CertifiedTip));
        }
        for (certified, genesis) in state.certified_tips.iter().zip(genesis) {
            if certified == genesis {
                continue;
            }
            let retained = state.local.values().filter(|artifact| {
                matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                    if certificate.header().chain() == certified.chain()
                        && certificate.block_ref::<H>() == *certified)
            });
            if retained.count() != 1 {
                return Err(invalid(SnapshotReason::CertifiedTip));
            }
        }
        Ok(())
    }

    /// Checks that every durable effect was minted at or before the cursor, is authorized, and
    /// votes no higher than its chain's DA safety height.
    fn check_effects<H: Hasher<Digest = D>>(
        &self,
        profile: &Profile<D>,
    ) -> Result<(), ReplayError> {
        let state = &self.state;
        let minted = |id: &EffectId| id.get() != 0 && id.get() <= state.cursor.get();
        let safe = |request: &SignRequest<V, D>| match request {
            SignRequest::DaVote(request) => state
                .da_safety_heights
                .get(request.header().chain().index())
                .is_some_and(|height| request.header().height() <= *height),
            _ => true,
        };
        if state.signing_reservations.iter().any(|(id, effect)| {
            !minted(id) || !effect.authorized::<H>(profile) || !effect.requests().iter().all(safe)
        }) || state
            .outbox
            .iter()
            .any(|(id, entry)| !minted(id) || !entry.publication.authorized::<H>(profile))
        {
            return Err(invalid(SnapshotReason::Effect));
        }
        Ok(())
    }

    /// Checks that every queued publication has discharges consistent with its items.
    fn check_obligations(&self) -> Result<(), ReplayError> {
        if !self.state.outbox.values().all(OutboxEntry::consistent) {
            return Err(invalid(SnapshotReason::Obligation));
        }
        Ok(())
    }

    /// Checks forwarded certificates: kind, view, epoch, size, and the forwarding history bound.
    fn check_forwarded(&self, profile: &Profile<D>) -> Result<(), ReplayError> {
        let resources = profile.resources();
        let forwarded_maps = [
            (&self.state.forwarded_vqcs, ArtifactKind::Vqc),
            (
                &self.state.forwarded_nullifications,
                ArtifactKind::Nullification,
            ),
        ];
        for (forwarded_map, expected_kind) in forwarded_maps {
            for (view, artifact) in forwarded_map {
                // A certificate observed for a view below the retention floor can still be
                // forwarded once, so the fact outlives that view until the next compaction.
                if view.is_zero()
                    || artifact.view() != Some(*view)
                    || artifact.kind() != expected_kind
                    || artifact.epoch() != self.epoch
                    || artifact.encoded_len() > resources.max_artifact_bytes()
                {
                    return Err(invalid(SnapshotReason::Forwarded));
                }
            }
        }
        if self.state.forwarded_count() > resources.max_forwarded_certificates() {
            return Err(invalid(SnapshotReason::Forwarded));
        }
        Ok(())
    }

    /// Checks that the retired view lies below the current one and that exits cover every retained
    /// view below the current one, each with a forwarded exit certificate for its view.
    ///
    /// The retired view is not checked against this profile's retention window: a snapshot written
    /// under a larger retention retains more views. Replay applies the floor each journaled view
    /// exit recorded, and the first exit staged after restore compacts to this profile's floor.
    fn check_exits(&self) -> Result<(), ReplayError> {
        let state = &self.state;
        if state.retired_view >= state.view {
            return Err(invalid(SnapshotReason::Exits));
        }
        let mut expected = state
            .retired_view
            .get()
            .checked_add(1)
            .ok_or(invalid(SnapshotReason::Exits))?;
        let contiguous = !state.view.is_zero()
            && state.exits.keys().all(|view| {
                if view.get() != expected {
                    return false;
                }
                let Some(next) = expected.checked_add(1) else {
                    return false;
                };
                expected = next;
                true
            })
            && expected == state.view.get();
        if !contiguous
            || state.exits.iter().any(|(view, proof)| {
                proof.view() != Some(*view)
                    || !matches!(
                        proof.as_ref(),
                        Artifact::Vqc(_) | Artifact::Nullification(_)
                    )
                    || state
                        .forwarded_vqcs
                        .get(view)
                        .into_iter()
                        .chain(state.forwarded_nullifications.get(view))
                        .all(|forwarded| forwarded.as_ref() != proof.as_ref())
            })
        {
            return Err(invalid(SnapshotReason::Exits));
        }
        Ok(())
    }

    /// Checks the signing floor, the proposal anchor, and the nullified suffix above it.
    fn check_proposal_anchor(&self, profile: &Profile<D>) -> Result<(), ReplayError> {
        let max_artifact_bytes = profile.resources().max_artifact_bytes();
        let state = &self.state;
        let signing_floor_view = match state.signing_floor.as_deref() {
            Some(artifact @ Artifact::Lqc(floor))
                if !floor.view().is_zero()
                    && floor.view() <= state.retired_view
                    && floor.view() < state.view
                    && artifact.epoch() == self.epoch
                    && artifact.encoded_len() <= max_artifact_bytes =>
            {
                floor.view()
            }
            Some(_) => return Err(invalid(SnapshotReason::ProposalAnchor)),
            None => View::zero(),
        };
        let anchor_view = match state.proposal_anchor.as_deref() {
            Some(artifact @ Artifact::Vqc(anchor))
                if !anchor.view().is_zero()
                    && artifact.epoch() == self.epoch
                    && artifact.encoded_len() <= max_artifact_bytes =>
            {
                anchor.view()
            }
            Some(_) => return Err(invalid(SnapshotReason::ProposalAnchor)),
            None => View::zero(),
        };
        if anchor_view < signing_floor_view
            || state.proposal_nullified_through < anchor_view
            || state.proposal_nullified_through > state.view
            || state.proposal_nullified_through == state.view && anchor_view != state.view
        {
            return Err(invalid(SnapshotReason::ProposalAnchor));
        }
        if signing_floor_view == anchor_view
            && let (Some(Artifact::Lqc(floor)), Some(Artifact::Vqc(anchor))) = (
                state.signing_floor.as_deref(),
                state.proposal_anchor.as_deref(),
            )
            && !floor.equivalent_vqc(anchor)
        {
            return Err(invalid(SnapshotReason::ProposalAnchor));
        }
        Ok(())
    }
}

/// The snapshot check a restored state failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotReason {
    /// The view projection derived from the state is inconsistent.
    #[error("view projection is inconsistent")]
    View,
    /// Entry counts, effect ownership, artifact occupancy, or produced height exceed their bounds.
    #[error("state exceeds its bounds")]
    Bounds,
    /// A locally held artifact is out of bounds, misidentified, or not locally constructible.
    #[error("local artifact is invalid")]
    LocalArtifact,
    /// A certified tip, DA safety height, or retained certificate is inconsistent.
    #[error("certified tip is invalid")]
    CertifiedTip,
    /// A durable effect is unminted, unauthorized, or votes above its safety height.
    #[error("durable effect is invalid")]
    Effect,
    /// A queued publication's discharges do not match its items.
    #[error("publication obligation is invalid")]
    Obligation,
    /// A forwarded certificate is invalid or the forwarding history exceeds its bound.
    #[error("forwarded certificate is invalid")]
    Forwarded,
    /// The exits do not cover the retained views with forwarded exit certificates.
    #[error("view exits are invalid")]
    Exits,
    /// The signing floor, proposal anchor, or nullified suffix is inconsistent.
    #[error("proposal anchor is invalid")]
    ProposalAnchor,
}

/// Returns a snapshot failure naming `reason`.
const fn invalid(reason: SnapshotReason) -> ReplayError {
    ReplayError::Snapshot(reason)
}

/// Canonical stable View state at one acknowledged checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ViewSnapshot<V: Variant, D: Digest> {
    pub(crate) slots: BTreeMap<View, ViewSlotSnapshot<V, D>>,
}

impl<V: Variant, D: Digest> Default for ViewSnapshot<V, D> {
    fn default() -> Self {
        Self {
            slots: BTreeMap::new(),
        }
    }
}

impl<V: Variant, D: Digest> ViewSnapshot<V, D> {
    fn structurally_valid(&self, epoch: Epoch) -> bool {
        self.slots.iter().all(|(view, slot)| {
            !view.is_zero()
                && slot.stable()
                && slot
                    .proposal
                    .as_ref()
                    .is_none_or(|block| block.epoch() == epoch && block.view() == *view)
                && !matches!(&slot.stance, ViewStance::Voted(body)
                    if body.epoch() != epoch || body.view() != *view)
        })
    }

    fn slot_mut(&mut self, view: View) -> Result<&mut ViewSlotSnapshot<V, D>, ReplayError> {
        if view.is_zero() {
            return Err(ReplayError::Transition(TransitionReason::ViewState));
        }
        Ok(self.slots.entry(view).or_default())
    }

    fn observe_request(
        &mut self,
        request: &SignRequest<V, D>,
        retired: View,
    ) -> Result<(), ReplayError> {
        let Some(view) = request.consensus_view() else {
            return Ok(());
        };
        if view <= retired {
            return Err(ReplayError::Transition(TransitionReason::ViewState));
        }
        self.slot_mut(view)?
            .observe_request(request)
            .map_err(|_| ReplayError::Transition(TransitionReason::ViewState))?;
        Ok(())
    }

    fn observe_artifact(
        &mut self,
        artifact: &Artifact<V, D>,
        role: Role,
        retired: View,
    ) -> Result<(), ReplayError> {
        let Role::Validator(me) = role else {
            return Ok(());
        };
        if artifact.signer() != Some(me) {
            return Ok(());
        }
        let Some(view) = artifact.view() else {
            return Ok(());
        };
        if view <= retired {
            return Err(ReplayError::Transition(TransitionReason::ViewState));
        }
        self.slot_mut(view)?
            .observe_artifact(artifact)
            .map_err(|_| ReplayError::Transition(TransitionReason::ViewState))?;
        Ok(())
    }

    fn from_durable<H: Hasher<Digest = D>>(
        epoch: Epoch,
        role: Role,
        state: &DurableState<V, D>,
    ) -> Result<Self, ReplayError> {
        // Reservations carry issue order, but signed artifacts in `local` do not, and a signature
        // may complete while an older reservation is still pending. Observing signed choices
        // first, then reservations in issue order, then signed nullifies accepts every honest
        // vote-then-nullify form. A vote is therefore rejected only when it was reserved after a
        // still-pending nullify reservation, or after the nullify in the same batch. A signed
        // nullify followed by a reserved or signed vote is indistinguishable from the honest
        // order and is accepted; journal replay enforces the full rule.
        let mut snapshot = Self::default();
        for artifact in state
            .local
            .values()
            .filter(|artifact| !matches!(artifact.as_ref(), Artifact::Nullify(_)))
        {
            snapshot.observe_artifact(artifact, role, state.retired_view)?;
        }
        for request in state
            .signing_reservations
            .values()
            .flat_map(|effect| effect.requests())
        {
            snapshot.observe_request(request, state.retired_view)?;
        }
        for artifact in state
            .local
            .values()
            .filter(|artifact| matches!(artifact.as_ref(), Artifact::Nullify(_)))
        {
            snapshot.observe_artifact(artifact, role, state.retired_view)?;
        }
        for (view, proof) in &state.exits {
            if *view <= state.retired_view || *view >= state.view {
                return Err(ReplayError::Transition(TransitionReason::ViewState));
            }
            snapshot.slot_mut(*view)?.observe_exit(proof.id::<H>());
        }
        if !snapshot.structurally_valid(epoch)
            || snapshot.slots.iter().any(|(view, slot)| {
                matches!(slot.transition, ViewTransition::Active) && *view < state.view
            })
        {
            return Err(ReplayError::Transition(TransitionReason::ViewState));
        }
        Ok(snapshot)
    }
}
