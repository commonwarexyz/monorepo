//! The durable state at one journal cursor.

use super::{Cursor, EffectId, OutboxEntry, Publication, Retained, SignEffect, SignRequest};
use crate::{
    Viewable,
    multimmit::{
        machine::job::Generation,
        types::{Artifact, ArtifactId, BlockRef, ChainId, ViewProof},
    },
    types::{Height, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::BTreeMap, sync::Arc};

/// The part of durable state that holds a retained artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Holder {
    /// A locally created artifact.
    Local,
    /// The finality floor proof.
    SigningFloor,
    /// The proposal anchor.
    ProposalAnchor,
    /// A forwarded exit certificate.
    Forwarded,
    /// The proof a view was exited with.
    Exit,
    /// A queued publication.
    Outbox,
    /// A reserved signing request.
    SigningReservation,
}

/// The acknowledged protocol state, retained artifacts, and outstanding effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DurableState<V: Variant, D: Digest> {
    /// The current view.
    pub(in crate::multimmit::machine) view: View,
    /// Blocks this node signed for its own chain.
    pub(in crate::multimmit::machine) produced_blocks: u64,
    /// The height of the newest block this node signed for its own chain.
    pub(in crate::multimmit::machine) produced_height: Height,
    /// The process generation that issued outstanding volatile work.
    pub(in crate::multimmit::machine) generation: Generation,
    /// The cursor of the newest applied event.
    pub(in crate::multimmit::machine) cursor: Cursor,
    /// Each chain's highest block with an accepted DA certificate.
    pub(in crate::multimmit::machine) certified_tips: Vec<BlockRef<D>>,
    /// Each chain's DA-vote frontier: this node's next DA vote on the chain must be exactly one
    /// height above it. A validator raises it by voting or by accepting a higher certificate; an
    /// observer mirrors its certified height.
    pub(in crate::multimmit::machine) da_safety_heights: Vec<Height>,
    /// Views at or below this one are retired: their slots, local artifacts, forwarded
    /// certificates, and exits are no longer retained.
    pub(in crate::multimmit::machine) retired_view: View,
    /// The L-QC proving finality through the signing floor, which retires consensus signing at
    /// or below its view.
    pub(in crate::multimmit::machine) signing_floor: Option<Arc<Artifact<V, D>>>,
    /// The V-QC this node's next proposal builds on.
    pub(in crate::multimmit::machine) proposal_anchor: Option<Arc<Artifact<V, D>>>,
    /// Every view above the proposal anchor's view and at or below this one is nullified, so a
    /// leader of the next view may build on the anchor.
    pub(in crate::multimmit::machine) proposal_nullified_through: View,
    /// Artifacts this node signed, retained until their view retires.
    pub(in crate::multimmit::machine) local: BTreeMap<ArtifactId<D>, Arc<Artifact<V, D>>>,
    /// Signing requests reserved but not yet completed.
    pub(in crate::multimmit::machine) signing_reservations: BTreeMap<EffectId, SignEffect<V, D>>,
    /// Publications waiting for the durable fact that discharges them.
    pub(in crate::multimmit::machine) outbox: BTreeMap<EffectId, OutboxEntry<V, D>>,
    /// The V-QC forwarded for each view.
    pub(in crate::multimmit::machine) forwarded_vqcs: BTreeMap<View, Arc<Artifact<V, D>>>,
    /// The nullification forwarded for each view.
    pub(in crate::multimmit::machine) forwarded_nullifications: BTreeMap<View, Arc<Artifact<V, D>>>,
    /// The certificate each view was exited with.
    pub(in crate::multimmit::machine) exits: BTreeMap<View, Arc<Artifact<V, D>>>,
}

impl<V: Variant, D: Digest> DurableState<V, D> {
    /// Creates the state of a fresh node at view one, certified at `certified_tips`.
    pub(crate) fn new(certified_tips: Vec<BlockRef<D>>, produced_height: Height) -> Self {
        let da_safety_heights = certified_tips.iter().map(BlockRef::height).collect();
        Self {
            view: View::new(1),
            produced_blocks: 0,
            produced_height,
            generation: Generation::default(),
            cursor: Cursor::zero(),
            certified_tips,
            da_safety_heights,
            retired_view: View::zero(),
            signing_floor: None,
            proposal_anchor: None,
            proposal_nullified_through: View::zero(),
            local: BTreeMap::new(),
            signing_reservations: BTreeMap::new(),
            outbox: BTreeMap::new(),
            forwarded_vqcs: BTreeMap::new(),
            forwarded_nullifications: BTreeMap::new(),
            exits: BTreeMap::new(),
        }
    }

    /// Visits every artifact, or artifact part, durable state retains, with its holder.
    ///
    /// An artifact held in several places is visited once per holder.
    pub(crate) fn visit_retained(&self, mut visit: impl FnMut(Holder, Retained<'_, V, D>)) {
        for artifact in self.local.values() {
            visit(Holder::Local, Retained::Artifact(artifact));
        }
        if let Some(artifact) = &self.signing_floor {
            visit(Holder::SigningFloor, Retained::Artifact(artifact));
        }
        if let Some(artifact) = &self.proposal_anchor {
            visit(Holder::ProposalAnchor, Retained::Artifact(artifact));
        }
        for artifact in self
            .forwarded_vqcs
            .values()
            .chain(self.forwarded_nullifications.values())
        {
            visit(Holder::Forwarded, Retained::Artifact(artifact));
        }
        for artifact in self.exits.values() {
            visit(Holder::Exit, Retained::Artifact(artifact));
        }
        for entry in self.outbox.values() {
            entry
                .publication
                .visit_retained(|retained| visit(Holder::Outbox, retained));
        }
        for effect in self.signing_reservations.values() {
            effect.visit_retained(|retained| visit(Holder::SigningReservation, retained));
        }
    }

    /// Projects resolver evidence directly from durable custody.
    pub(crate) fn resolver_proofs(&self) -> Vec<ViewProof<V, D>> {
        let mut proofs = Vec::new();
        self.visit_retained(|_, retained| proofs.extend(retained.view_proof()));
        proofs
    }

    /// Returns whether a V-QC for `view` is durably marked forwarded.
    pub(crate) fn vqc_forwarded(&self, view: View) -> bool {
        self.forwarded_vqcs.contains_key(&view)
    }

    /// Returns how many exit certificates are durably marked forwarded.
    pub(crate) fn forwarded_count(&self) -> usize {
        self.forwarded_vqcs.len() + self.forwarded_nullifications.len()
    }

    /// Returns the certified height of `chain`, or `None` for a chain outside the committee.
    pub(crate) fn certified_height(&self, chain: ChainId) -> Option<Height> {
        self.certified_tips.get(chain.index()).map(BlockRef::height)
    }

    /// Returns the view of the durable proposal anchor, or zero before any anchor is installed.
    pub(crate) fn proposal_anchor_view(&self) -> View {
        match self.proposal_anchor.as_deref() {
            Some(Artifact::Vqc(anchor)) => anchor.view(),
            _ => View::zero(),
        }
    }

    /// Returns whether a nullification for `view` is durably marked forwarded.
    pub(crate) fn nullification_forwarded(&self, view: View) -> bool {
        self.forwarded_nullifications.contains_key(&view)
    }

    /// Counts the artifact cache references durable state holds, per artifact.
    ///
    /// An exit shares its proof with the forwarded certificate that holds its reference, and a
    /// block awaiting a data-availability vote is charged as a signing reservation instead.
    pub(crate) fn artifact_references<H: Hasher<Digest = D>>(
        &self,
    ) -> BTreeMap<ArtifactId<D>, usize> {
        let mut references = BTreeMap::new();
        self.visit_retained(|holder, retained| {
            if holder == Holder::Exit || matches!(retained, Retained::DaVoteBlock(_)) {
                return;
            }
            *references.entry(retained.id::<H>()).or_default() += 1;
        });
        references
    }

    /// Returns the artifact cache slots durable state occupies: one per referenced artifact plus
    /// the signing reservations.
    pub(crate) fn artifact_occupancy<H: Hasher<Digest = D>>(&self) -> usize {
        self.artifact_references::<H>().len() + self.signing_reservations()
    }

    /// Returns the artifact cache slots reserved for outstanding signing results.
    pub(crate) fn signing_reservations(&self) -> usize {
        self.signing_reservations
            .values()
            .map(|effect| effect.requests().len())
            .sum()
    }

    /// Returns every reserved signing request, in reservation and request order.
    pub(crate) fn sign_requests(&self) -> impl Iterator<Item = &SignRequest<V, D>> {
        self.signing_reservations
            .values()
            .flat_map(SignEffect::requests)
    }

    /// Returns the outstanding signing choice `id`, if any.
    pub(crate) fn signing(&self, id: &EffectId) -> Option<&SignEffect<V, D>> {
        self.signing_reservations.get(id)
    }

    /// Returns the queued publication `id`, if any.
    pub(crate) fn publication(&self, id: &EffectId) -> Option<&Publication<V, D>> {
        self.outbox.get(id).map(OutboxEntry::publication)
    }

    /// Returns whether `id` names an outstanding signing choice or queued publication.
    pub(crate) fn contains_effect(&self, id: &EffectId) -> bool {
        self.signing_reservations.contains_key(id) || self.outbox.contains_key(id)
    }

    /// Returns the number of outstanding signing choices and queued publications.
    pub(crate) fn effect_count(&self) -> usize {
        self.signing_reservations.len() + self.outbox.len()
    }

    /// Returns every outstanding effect identifier: signing choices, then publications.
    pub(crate) fn effect_ids(&self) -> impl Iterator<Item = EffectId> + '_ {
        self.signing_reservations
            .keys()
            .chain(self.outbox.keys())
            .copied()
    }
}
