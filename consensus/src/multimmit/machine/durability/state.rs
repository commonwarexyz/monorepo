//! The durable state at one journal cursor.

use super::{
    Cursor, DischargeKind, EffectId, OutboxEntry, Publication, Retained, SignEffect, SignRequest,
};
use crate::{
    Viewable as _,
    multimmit::{
        machine::job::Generation,
        types::{
            Artifact, ArtifactId, BlockRef, CertificateId, ChainId, ChainSet, HistoryRecord,
            Resolution, SignedTransactionBlock, TransactionBlockHeader, ViewProof, VoteContent,
        },
    },
    types::{Height, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// The part of durable state that holds a retained artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Holder {
    /// A locally created artifact.
    Local,
    /// An accepted header.
    Accepted,
    /// The proof a view was exited with.
    Exit,
    /// A V-QC on the parent chain of a proof a view was exited with.
    Ancestor,
    /// A queued publication.
    Outbox,
    /// A reserved signing request.
    SigningReservation,
}

/// One accepted header and how it was accepted.
///
/// A header accepted in full passed the application's verification, so its body is in custody,
/// and its producer signature is retained so the node can serve it. An adopted header was accepted
/// on `alpha` endorsements without its body, which marshal fetches. Its parent and payload hash
/// determine it, so no signature need be held for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Acceptance<V: Variant, D: Digest> {
    /// Accepted with a verified body.
    Full(Arc<SignedTransactionBlock<V, D>>),
    /// Adopted on endorsements.
    Adopted(TransactionBlockHeader<D>),
}

impl<V: Variant, D: Digest> Acceptance<V, D> {
    /// Returns the accepted header.
    pub(crate) fn header(&self) -> &TransactionBlockHeader<D> {
        match self {
            Self::Full(block) => block.header(),
            Self::Adopted(header) => header,
        }
    }

    /// Returns the producer-signed header of a header accepted in full.
    pub(crate) const fn signed(&self) -> Option<&Arc<SignedTransactionBlock<V, D>>> {
        match self {
            Self::Full(block) => Some(block),
            Self::Adopted(_) => None,
        }
    }

    /// Returns whether the header was adopted without its body.
    pub(crate) const fn adopted(&self) -> bool {
        matches!(self, Self::Adopted(_))
    }
}

/// One chain's accepted headers above the retention floor, by height.
pub(crate) type AcceptedChain<V, D> = BTreeMap<Height, Acceptance<V, D>>;

/// The durable record of this node's votes for one view tag.
///
/// Every update this node signs for the view must not lower the recorded tips or sequence number,
/// must keep every declared chain, and must not sign a second, different final content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VoteWatermark<D: Digest> {
    /// The sequence number of the latest signed update.
    pub(in crate::multimmit::machine) seq: u32,
    /// The tips of the latest signed update, one per chain.
    pub(in crate::multimmit::machine) tips: Vec<BlockRef<D>>,
    /// The chains declared final.
    pub(in crate::multimmit::machine) declared: ChainSet,
    /// The tip height each declared chain had when it was declared, in ascending chain order.
    pub(in crate::multimmit::machine) declared_at: Vec<Height>,
    /// The final content this node signed for the view, if any.
    pub(in crate::multimmit::machine) final_content: Option<VoteContent<D>>,
}

impl<D: Digest> VoteWatermark<D> {
    /// Returns the tip height `chain` had when it was declared, if it is declared.
    pub(crate) fn declaration(&self, chain: ChainId) -> Option<Height> {
        self.declared
            .iter()
            .zip(&self.declared_at)
            .find_map(|(declared, height)| (declared == chain).then_some(*height))
    }
}

/// The emission state of view `v`: its base `beta_v`, the tips of view `v - 1` on the surviving
/// V-QC chain, and how consensus fixed it.
///
/// The record `(C(Q_{v-2}), beta_v)` opens the commitment `C(Q_{v-1})` of view `v - 1`, so the
/// records of consecutive views form the tips-history chain from the epoch's genesis: each one's
/// parent is the previous one's commitment. An emission is written once per view, in view order
/// without gaps, before the resolution of view `v - 1` it fixes is reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Emission<D: Digest> {
    /// The history record of view `v - 1`, whose tips are `beta_v`.
    pub(in crate::multimmit::machine) record: HistoryRecord<D>,
    /// How consensus fixed the base.
    pub(in crate::multimmit::machine) by: Resolution<D>,
}

impl<D: Digest> Emission<D> {
    /// Returns the base `beta_v`, one tip per chain.
    pub(in crate::multimmit::machine) fn base(&self) -> &[BlockRef<D>] {
        self.record.tips()
    }
}

/// The V-QC of the retired view that the retained V-QCs this node entered views on descend from,
/// with the history record fixing its facts.
///
/// Retention drops every V-QC at or below the retired view, so a restart holds the retained V-QCs
/// on this root rather than on their dropped ancestors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetentionRoot<D: Digest> {
    /// The V-QC's identifier `H(Q)`.
    pub(in crate::multimmit::machine) vqc: CertificateId<D>,
    /// The history record `(C(parent), Tips(Q))`, whose commitment is `C(Q)`.
    pub(in crate::multimmit::machine) record: HistoryRecord<D>,
}

/// The durable views, and the vote window read from them, that decide which publication duties
/// have ended.
///
/// Every [`DischargeKind`] is a function of these views and the vote watermarks, so a transition
/// that moves them can name the publications it ends before it applies.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct DischargeFacts {
    /// The current view: an exit certificate is replaced once a later view was exited.
    pub(crate) view: View,
    /// The retired view: every duty for a view at or below it has ended.
    pub(crate) retired: View,
    /// Own headers at or below this height were endorsed by `n - 2f` validators.
    ///
    /// The producer signs height `p` only while `p - h* <= D`, so once it has signed height
    /// `produced`, every own header at or below `produced - D` had reached the height quorum.
    pub(crate) endorsed_headers: Height,
    /// How many views below `view` vote tags are still read (`W_back`).
    ///
    /// A node in `view` reads no vote of an older tag, so its own votes and leader block of such
    /// a view are no longer re-sent; a peer further behind fetches them from resolver custody.
    pub(crate) vote_window: u64,
}

impl DischargeFacts {
    /// Returns whether the votes of view `tag` are no longer read: `tag` lies below the vote
    /// window of the current view, or is retired.
    const fn unread(self, tag: View) -> bool {
        tag.get() <= self.retired.get()
            || tag.get().saturating_add(self.vote_window) < self.view.get()
    }
}

/// The acknowledged protocol state, retained artifacts, and outstanding effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DurableState<V: Variant, D: Digest> {
    /// The current view.
    pub(in crate::multimmit::machine) view: View,
    /// The process generation that issued outstanding volatile work.
    pub(in crate::multimmit::machine) generation: Generation,
    /// The cursor of the newest applied event.
    pub(in crate::multimmit::machine) cursor: Cursor,
    /// Views at or below this one are retired: their slots, local artifacts, forwarded
    /// certificates, exits, and emissions are no longer retained.
    pub(in crate::multimmit::machine) retired_view: View,
    /// The V-QC of the retired view on the chain this node entered later views on; `None` while
    /// no view is retired.
    pub(in crate::multimmit::machine) root: Option<RetentionRoot<D>>,
    /// Each chain's accepted headers above the retention floor.
    pub(in crate::multimmit::machine) accepted: Vec<AcceptedChain<V, D>>,
    /// Per chain, the finalized block its accepted path starts from: the genesis object, or the
    /// base of the view this node anchored at. A chain retaining no acceptance has it as its tip.
    pub(in crate::multimmit::machine) origin: Vec<BlockRef<D>>,
    /// The height of the newest header this node signed for its own chain.
    pub(in crate::multimmit::machine) produced: Height,
    /// The parent certificate and history commitment of the leader block this node signed for
    /// each view.
    pub(in crate::multimmit::machine) leader_blocks: BTreeMap<View, (CertificateId<D>, D)>,
    /// The leader block this node voted for in each view.
    pub(in crate::multimmit::machine) notarised: BTreeMap<View, D>,
    /// This node's vote watermark for each view tag.
    pub(in crate::multimmit::machine) watermark: BTreeMap<View, VoteWatermark<D>>,
    /// The newest view this node voted final in, and the tips of that final vote.
    ///
    /// After an anchor at view `v` it is `(v - 1, base)`: this node never voted in `v - 1`,
    /// but its next vote tag is `v` and the finalized base caps what it endorses.
    pub(in crate::multimmit::machine) last_final: (View, Vec<BlockRef<D>>),
    /// The vote tag of the view this node anchored on, until it signs a final vote.
    ///
    /// Update zero of that tag, the final vote of the view before, was never signed, so the first
    /// two updates of the tag name every chain.
    pub(in crate::multimmit::machine) anchored_tag: Option<View>,
    /// The resolution facts of each resolved view.
    pub(in crate::multimmit::machine) emission: BTreeMap<View, Emission<D>>,
    /// Artifacts this node signed or assembled, retained until their view retires.
    pub(in crate::multimmit::machine) local: BTreeMap<ArtifactId<D>, Arc<Artifact<V, D>>>,
    /// Signing requests reserved but not yet completed.
    pub(in crate::multimmit::machine) signing_reservations: BTreeMap<EffectId, SignEffect<V, D>>,
    /// Publications waiting for the durable fact that discharges them.
    pub(in crate::multimmit::machine) outbox: BTreeMap<EffectId, OutboxEntry<V, D>>,
    /// The V-QCs forwarded for each view.
    pub(in crate::multimmit::machine) forwarded_vqcs: BTreeMap<View, BTreeSet<CertificateId<D>>>,
    /// The certificate each view was exited with.
    pub(in crate::multimmit::machine) exits: BTreeMap<View, Arc<Artifact<V, D>>>,
    /// The V-QCs above the retired view on the parent chains of the exit proofs that no other
    /// retention holder keeps, by identifier.
    ///
    /// With the exits, local certificates, and the root they make the parent chain of every exit
    /// proof durable at its entry, so a restart holds the V-QC the current view was entered on
    /// without retrieving anything.
    pub(in crate::multimmit::machine) ancestors: BTreeMap<CertificateId<D>, Arc<Artifact<V, D>>>,
}

impl<V: Variant, D: Digest> DurableState<V, D> {
    /// Creates the state of a fresh node at view one, with every chain at its genesis tip and the
    /// own chain produced through `produced`.
    pub(crate) fn new(genesis: Vec<BlockRef<D>>, produced: Height) -> Self {
        Self {
            view: View::new(1),
            generation: Generation::default(),
            cursor: Cursor::zero(),
            retired_view: View::zero(),
            root: None,
            accepted: vec![AcceptedChain::new(); genesis.len()],
            origin: genesis.clone(),
            produced,
            leader_blocks: BTreeMap::new(),
            notarised: BTreeMap::new(),
            watermark: BTreeMap::new(),
            last_final: (View::zero(), genesis),
            anchored_tag: None,
            emission: BTreeMap::new(),
            local: BTreeMap::new(),
            signing_reservations: BTreeMap::new(),
            outbox: BTreeMap::new(),
            forwarded_vqcs: BTreeMap::new(),
            exits: BTreeMap::new(),
            ancestors: BTreeMap::new(),
        }
    }

    /// Visits every artifact, or artifact part, durable state retains, with its holder.
    ///
    /// An artifact held in several places is visited once per holder.
    pub(crate) fn visit_retained(&self, mut visit: impl FnMut(Holder, Retained<'_, V, D>)) {
        for artifact in self.local.values() {
            visit(Holder::Local, Retained::Artifact(artifact));
        }
        for acceptance in self.accepted.iter().flat_map(BTreeMap::values) {
            if let Some(block) = acceptance.signed() {
                visit(Holder::Accepted, Retained::Header(block));
            }
        }
        for artifact in self.exits.values() {
            visit(Holder::Exit, Retained::Artifact(artifact));
        }
        for artifact in self.ancestors.values() {
            visit(Holder::Ancestor, Retained::Artifact(artifact));
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

    /// Projects the view proofs durable state retains, for the resolver to serve.
    pub(crate) fn resolver_proofs(&self) -> Vec<ViewProof<V, D>> {
        let mut proofs = Vec::new();
        self.visit_retained(|_, retained| proofs.extend(retained.view_proof()));
        proofs
    }

    /// Returns whether a retention holder keeps the V-QC `id` of `view`: the epoch's genesis V-QC
    /// `genesis` or the root at the retired view, and an exit, a local certificate, or an ancestor
    /// above it.
    ///
    /// Publications and signing reservations do not count: publication facts, not retention, end
    /// them.
    pub(crate) fn retains_vqc<H: Hasher<Digest = D>>(
        &self,
        view: View,
        id: &CertificateId<D>,
        genesis: &CertificateId<D>,
    ) -> bool {
        if view <= self.retired_view {
            return view == self.retired_view
                && self
                    .root
                    .as_ref()
                    .map_or(id == genesis, |root| root.vqc == *id);
        }
        let held = |artifact: &Arc<Artifact<V, D>>| {
            let Artifact::Vqc(vqc) = artifact.as_ref() else {
                return false;
            };
            vqc.view() == view && vqc.id::<H>() == *id
        };
        self.ancestors.contains_key(id)
            || self.exits.get(&view).is_some_and(held)
            || self.local.values().any(held)
    }

    /// Returns whether the V-QC `id` for `view` is durably marked forwarded.
    pub(crate) fn vqc_forwarded(&self, view: View, id: &CertificateId<D>) -> bool {
        self.forwarded_vqcs
            .get(&view)
            .is_some_and(|forwarded| forwarded.contains(id))
    }

    /// Returns how many V-QCs are durably marked forwarded.
    pub(crate) fn forwarded_count(&self) -> usize {
        self.forwarded_vqcs.values().map(BTreeSet::len).sum()
    }

    /// Returns the accepted header of `chain` at `height`, if one is retained.
    #[cfg(test)]
    pub(crate) fn accepted(&self, chain: ChainId, height: Height) -> Option<&Acceptance<V, D>> {
        self.accepted.get(chain.index())?.get(&height)
    }

    /// Returns `chain`'s origin ([`Self::origin`]).
    pub(crate) fn origin(&self, chain: ChainId) -> BlockRef<D> {
        self.origin[chain.index()]
    }

    /// Returns `chain`'s accepted tip: its highest retained accepted header, or its origin.
    pub(crate) fn accepted_tip<H: Hasher<Digest = D>>(&self, chain: ChainId) -> BlockRef<D> {
        self.accepted[chain.index()].last_key_value().map_or_else(
            || self.origin(chain),
            |(_, acceptance)| acceptance.header().block_ref::<H>(),
        )
    }

    /// Returns, per chain, the lowest height whose accepted header retention keeps: the base of
    /// the view after the retired one (`genesis` while none is retired), or the accepted tip
    /// when that is lower, so each chain keeps its tip.
    pub(crate) fn retained_heights(&self, genesis: &[BlockRef<D>]) -> Vec<Height> {
        let base = self
            .emission
            .get(&self.retired_view.next())
            .map_or(genesis, Emission::base);
        base.iter()
            .zip(&self.accepted)
            .map(|(base, accepted)| {
                let tip = accepted
                    .last_key_value()
                    .map_or_else(|| self.origin(base.chain()).height(), |(height, _)| *height);
                base.height().min(tip)
            })
            .collect()
    }

    /// Returns whether `block` lies on its chain's durable accepted path: the chain's genesis
    /// object `genesis`, a retained accepted header, or below every retained acceptance, where
    /// retention keeps at least the accepted tip. A chain retaining no acceptance has its origin
    /// as its tip.
    pub(crate) fn on_accepted_path<H: Hasher<Digest = D>>(
        &self,
        block: &BlockRef<D>,
        genesis: &[BlockRef<D>],
    ) -> bool {
        let chain = block.chain();
        let Some(accepted) = self.accepted.get(chain.index()) else {
            return false;
        };
        if block.height().is_zero() {
            return *block == genesis[chain.index()];
        }
        let Some((lowest, _)) = accepted.first_key_value() else {
            let origin = self.origin(chain);
            return *block == origin || block.height() < origin.height();
        };
        accepted.get(&block.height()).map_or_else(
            || block.height() < *lowest,
            |acceptance| acceptance.header().block_ref::<H>() == *block,
        )
    }

    /// Returns whether this node can anchor at view `view`: it lies more than two views above the
    /// current one, above every vote tag holding a watermark, and above the tag after the last
    /// final vote, so no statement signed after the anchor shares a tag or a view with one signed
    /// before it, and above every view whose emission is written, so no emission is rewritten.
    pub(crate) fn anchorable(&self, view: View) -> bool {
        view.get() > self.view.get().saturating_add(2)
            && self
                .watermark
                .last_key_value()
                .is_none_or(|(tag, _)| *tag < view)
            && view.get() > self.last_final.0.get().saturating_add(1)
            && self
                .emission
                .last_key_value()
                .is_none_or(|(written, _)| *written < view)
    }

    /// Counts the artifact cache references durable state holds, per artifact.
    pub(crate) fn artifact_references<H: Hasher<Digest = D>>(
        &self,
    ) -> BTreeMap<ArtifactId<D>, usize> {
        let mut references = BTreeMap::new();
        self.visit_retained(|_, retained| {
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

    /// Returns the facts that end publication duties in this state, under the flow bound `flow`
    /// (`D`) and the vote window `vote_window`.
    pub(crate) const fn discharge_facts(&self, flow: u64, vote_window: u64) -> DischargeFacts {
        DischargeFacts {
            view: self.view,
            retired: self.retired_view,
            endorsed_headers: Height::new(self.produced.get().saturating_sub(flow)),
            vote_window,
        }
    }

    /// Returns whether `kind` holds under `facts` and this state's vote watermarks.
    pub(crate) fn discharge_holds(&self, kind: DischargeKind, facts: DischargeFacts) -> bool {
        match kind {
            DischargeKind::HeaderBelowHstar { height, .. } => height <= facts.endorsed_headers,
            DischargeKind::UpdateSuperseded { view, seq } => {
                facts.unread(view)
                    || self
                        .watermark
                        .get(&view)
                        .is_some_and(|watermark| u64::from(watermark.seq) >= u64::from(seq) + 2)
            }
            DischargeKind::ExitReplacedAfter { view } => {
                view <= facts.retired || view.get().saturating_add(1) < facts.view.get()
            }
            DischargeKind::ViewUnread { view } => facts.unread(view),
        }
    }

    /// Returns the queued publications whose every item is discharged under `facts`, in
    /// identifier order.
    pub(crate) fn discharged(&self, facts: DischargeFacts) -> Vec<EffectId> {
        self.outbox
            .iter()
            .filter(|(_, entry)| {
                entry
                    .discharges()
                    .iter()
                    .all(|discharge| self.discharge_holds(discharge.until(), facts))
            })
            .map(|(id, _)| *id)
            .collect()
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
