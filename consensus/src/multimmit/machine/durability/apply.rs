//! Application of one durable event, shared by staging and replay.
//!
//! [`Machine::apply_event`] checks the event's epoch and cursor, then applies its
//! [`Change`]. Each change is validated against the durable state before it mutates
//! anything, and a failed check is named by a [`TransitionReason`]. Live
//! staging and replay call the same function, so a journal replays to exactly the state the writer
//! staged.
//!
//! Publication duties end by durable facts alone (see [`DischargeFacts`]). A change that moves
//! those facts retires every publication they end in the same event: the journal names them when
//! the change carries a list, and the transition derives them otherwise. A signing reservation
//! whose publication those facts would already end is retired the same way, so its signature,
//! should it still complete, is stale and never published.

use crate::{
    Epochable, Viewable,
    multimmit::{
        algebra::validate_floor,
        config::Role,
        machine::{
            durability::{
                Acceptance, Change, DischargeFacts, DischargeKind, DomainEvent, DurableEffect,
                EffectId, Emission, OutboxEntry, ProposalParent, Publication, ReplayError,
                Retained, RetentionRoot, SignEffect, SignRequest, TransitionReason, VoteWatermark,
            },
            input::StepError,
            job::Generation,
            reducer::machine::{Lifecycle, Machine},
        },
        types::{
            Artifact, ArtifactBatch, ArtifactId, BlockRef, CertificateId, ChainId, Floor,
            HistoryRecord, Resolution,
        },
    },
    types::{Attributable as _, Height, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Rejects the transition with `$reason` unless `$cond` holds.
macro_rules! ensure {
    ($cond:expr, $reason:ident) => {
        if !$cond {
            return Err(reject(TransitionReason::$reason));
        }
    };
}

/// Returns a transition failure naming `reason`.
const fn reject(reason: TransitionReason) -> ReplayError {
    ReplayError::Transition(reason)
}

/// The view and certificate identifier of a forwarded V-QC.
type ForwardedVqc<D> = (View, CertificateId<D>);

/// The certificate and artifact identifiers of a retained V-QC.
type VqcIds<D> = (CertificateId<D>, ArtifactId<D>);

/// The signing slots one reserved request advances, computed before any slot changes.
enum SlotAdvance<D: Digest> {
    /// The own-chain header at this height.
    Header(Height),
    /// The leader block of a view, naming its parent and history commitment.
    LeaderBlock {
        view: View,
        parent: CertificateId<D>,
        history: D,
    },
    /// The vote watermark of a view tag, with the notarised leader and final tips it fixes.
    Update {
        view: View,
        watermark: VoteWatermark<D>,
        notarised: Option<D>,
        last_final: Option<Vec<BlockRef<D>>>,
    },
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Applies one durable event: the single transition function for staging and replay.
    ///
    /// Returns the publications the event retired, in identifier order.
    pub(crate) fn apply_event(
        &mut self,
        event: &DomainEvent<V, H::Digest>,
    ) -> Result<Vec<EffectId>, ReplayError> {
        if event.epoch() != self.profile.protocol().epoch() {
            return Err(ReplayError::Context);
        }
        if self.durable.state.cursor.next() != Some(event.cursor()) {
            return Err(ReplayError::Cursor);
        }
        let minted = EffectId::from_cursor(event.cursor());
        let retired = match event.change() {
            Change::GenerationAdvanced(generation) => {
                self.apply_generation_advanced(*generation)?;
                Vec::new()
            }
            Change::OutboxQueued { id, effect } => self.apply_outbox_queued(minted, *id, effect)?,
            Change::SignedArtifacts {
                sign,
                publication,
                artifacts,
            } => {
                self.apply_signed_artifacts(minted, *sign, *publication, artifacts)?;
                Vec::new()
            }
            Change::Accepted { blocks } => {
                self.apply_accepted(blocks)?;
                Vec::new()
            }
            Change::EmissionResolved { view, record, by } => {
                self.apply_emission_resolved(*view, record, by)?;
                Vec::new()
            }
            Change::ArtifactForwarded {
                publication,
                artifact,
            } => {
                self.apply_artifact_forwarded(minted, *publication, artifact)?;
                Vec::new()
            }
            Change::ViewEntered {
                proof,
                ancestors,
                retired_publications,
            } => {
                self.apply_view_entered(*proof, ancestors, retired_publications)?;
                retired_publications.clone()
            }
            Change::CertificateCreated { artifact } => {
                self.apply_certificate_created(artifact)?;
                Vec::new()
            }
            Change::RetentionAdvanced {
                floor,
                root,
                retired_signing,
                retired_publications,
            } => {
                self.apply_retention_advanced(*floor, root, retired_signing, retired_publications)?;
                retired_publications.clone()
            }
            Change::Anchored {
                floor,
                retired_signing,
                retired_publications,
            } => {
                self.apply_anchored(floor, retired_signing, retired_publications)?;
                retired_publications.clone()
            }
        };
        self.durable.state.cursor = event.cursor();
        Ok(retired)
    }

    fn apply_generation_advanced(&mut self, generation: Generation) -> Result<(), ReplayError> {
        ensure!(
            self.durable.state.generation.next() == Some(generation),
            Generation
        );
        self.durable.state.generation = generation;
        Ok(())
    }

    fn apply_outbox_queued(
        &mut self,
        minted: EffectId,
        id: EffectId,
        effect: &DurableEffect<V, H::Digest>,
    ) -> Result<Vec<EffectId>, ReplayError> {
        let state = &self.durable.state;
        ensure!(id == minted, EffectCursor);
        ensure!(!state.contains_effect(&id), DuplicateEffect);
        ensure!(
            state.effect_count() < self.profile.resources().max_outbox_effects(),
            OutboxFull
        );
        ensure!(effect.authorized::<H>(&self.profile), Unauthorized);
        let ids = Self::retained_ids(|visit| effect.visit_retained(visit));
        self.check_occupancy(&ids, &[], effect.reservations(), 0)?;
        match effect {
            DurableEffect::Sign(sign) => self.apply_signing_queued(id, sign, ids),
            DurableEffect::Publish(publication) => {
                let entry = OutboxEntry::of(publication.clone());
                ensure!(!self.ended(&entry, self.discharge_facts()), Obligation);
                self.durable.admit_effect(id, ids)?;
                self.durable.state.outbox.insert(id, entry);
                Ok(Vec::new())
            }
        }
    }

    /// Reserves a signing choice and advances the signing slots it occupies.
    ///
    /// A watermark advance can end older updates' publications, and a header advance older own
    /// headers' publications, which this event retires, together with the reservations of older
    /// updates still being signed whose publication would already be ended.
    fn apply_signing_queued(
        &mut self,
        id: EffectId,
        sign: &SignEffect<V, H::Digest>,
        ids: Vec<ArtifactId<H::Digest>>,
    ) -> Result<Vec<EffectId>, ReplayError> {
        let [request] = sign.requests() else {
            return Err(reject(TransitionReason::Unauthorized));
        };
        let advance = self.slot_advance(request)?;
        self.durable.admit_effect(id, ids)?;
        self.durable
            .state
            .signing_reservations
            .insert(id, sign.clone());
        let state = &mut self.durable.state;
        let moves_discharges = !matches!(advance, SlotAdvance::LeaderBlock { .. });
        match advance {
            SlotAdvance::Header(height) => state.produced = height,
            SlotAdvance::LeaderBlock {
                view,
                parent,
                history,
            } => {
                state.leader_blocks.insert(view, (parent, history));
            }
            SlotAdvance::Update {
                view,
                watermark,
                notarised,
                last_final,
            } => {
                state.watermark.insert(view, watermark);
                if let Some(leader) = notarised {
                    state.notarised.insert(view, leader);
                }
                if let Some(tips) = last_final {
                    state.last_final = (view, tips);
                    state.anchored_tag = None;
                }
            }
        }
        if !moves_discharges {
            return Ok(Vec::new());
        }
        self.retire_superseded_reservations()?;
        let retired = self.durable.state.discharged(self.discharge_facts());
        self.retire_publications(&retired)?;
        Ok(retired)
    }

    /// Retires the vote and leader-block reservations whose publication the durable facts already
    /// end.
    fn retire_superseded_reservations(&mut self) -> Result<(), ReplayError> {
        let state = &self.durable.state;
        let facts = self.discharge_facts();
        let superseded = state
            .signing_reservations
            .iter()
            .filter(|(_, effect)| {
                effect.requests().iter().all(|request| {
                    let kind = match request {
                        SignRequest::Update(update) => DischargeKind::UpdateSuperseded {
                            view: update.content().view(),
                            seq: update.seq(),
                        },
                        SignRequest::LeaderBlock(proposal) => DischargeKind::ViewUnread {
                            view: proposal.block().view(),
                        },
                        SignRequest::TransactionBlock(_) => return false,
                    };
                    state.discharge_holds(kind, facts)
                })
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in superseded {
            self.retire_reservation(id)?;
        }
        Ok(())
    }

    /// Drops the signing reservation `id` before it was signed.
    fn retire_reservation(&mut self, id: EffectId) -> Result<(), ReplayError> {
        ensure!(
            self.durable
                .state
                .signing_reservations
                .remove(&id)
                .is_some(),
            Signing
        );
        self.signing_issued.remove(&id);
        self.durable.release_effect(id)
    }

    /// Returns the slot advance signing `request` makes, or the slot it would conflict with.
    ///
    /// One header per own-chain height, in order; one leader block per view; and per view tag a
    /// watermark whose sequence numbers increase, whose tips lie on the durable accepted path and
    /// never fall below the recorded ones (so each extends the one before), whose declared chains
    /// only grow with their declaration heights fixed and never exceeded, whose leader never
    /// changes, and which signs nothing after its final.
    fn slot_advance(
        &self,
        request: &SignRequest<V, H::Digest>,
    ) -> Result<SlotAdvance<H::Digest>, ReplayError> {
        let state = &self.durable.state;
        match request {
            SignRequest::TransactionBlock(header) => {
                ensure!(
                    state.produced.get().checked_add(1) == Some(header.height().get()),
                    ProducerHeight
                );
                Ok(SlotAdvance::Header(header.height()))
            }
            SignRequest::LeaderBlock(proposal) => {
                let block = proposal.block();
                ensure!(
                    !matches!(proposal.parent(), ProposalParent::Genesis)
                        || !proposal.attach_parent(),
                    ProposalParent
                );
                ensure!(
                    !state.leader_blocks.contains_key(&block.view()),
                    SigningSlot
                );
                Ok(SlotAdvance::LeaderBlock {
                    view: block.view(),
                    parent: block.parent(),
                    history: block.history(),
                })
            }
            SignRequest::Update(update) => {
                let content = update.content();
                let view = content.view();
                let tips = content.tips();
                ensure!(tips.len() == self.profile.codec().chains(), SigningSlot);
                let genesis = self.profile.protocol().genesis().tips();
                ensure!(
                    tips.iter()
                        .all(|tip| state.on_accepted_path::<H>(tip, genesis)),
                    SigningSlot
                );
                let previous = state.watermark.get(&view);
                let declared_at = content
                    .declared()
                    .iter()
                    .map(|chain| {
                        previous
                            .and_then(|previous| previous.declaration(chain))
                            .unwrap_or(tips[chain.index()].height())
                    })
                    .collect::<Vec<_>>();
                if let Some(previous) = previous {
                    ensure!(update.seq() > previous.seq, SigningSlot);
                    ensure!(previous.final_content.is_none(), SigningSlot);
                    ensure!(previous.declared.is_subset(content.declared()), SigningSlot);
                    ensure!(
                        previous.tips.iter().zip(tips).all(|(before, after)| {
                            after.height() > before.height() || after == before
                        }),
                        SigningSlot
                    );
                }
                ensure!(
                    content
                        .declared()
                        .iter()
                        .zip(&declared_at)
                        .all(|(chain, height)| tips[chain.index()].height() <= *height),
                    SigningSlot
                );
                let notarised = state.notarised.get(&view).copied();
                ensure!(
                    notarised.is_none_or(|leader| content.leader() == Some(leader)),
                    SigningSlot
                );
                let last_final = content.is_final().then(|| tips.to_vec());
                ensure!(
                    last_final.is_none() || view > state.last_final.0,
                    SigningSlot
                );
                Ok(SlotAdvance::Update {
                    view,
                    watermark: VoteWatermark {
                        seq: update.seq(),
                        tips: tips.to_vec(),
                        declared: content.declared().clone(),
                        declared_at,
                        final_content: content.is_final().then(|| content.clone()),
                    },
                    notarised: content.leader().filter(|_| notarised.is_none()),
                    last_final,
                })
            }
        }
    }

    fn apply_signed_artifacts(
        &mut self,
        minted: EffectId,
        sign: EffectId,
        publication: EffectId,
        artifacts: &ArtifactBatch<V, H::Digest>,
    ) -> Result<(), ReplayError> {
        let Role::Validator(signer) = self.profile.role() else {
            return Err(reject(TransitionReason::Signing));
        };
        let effect = self
            .durable
            .state
            .signing(&sign)
            .cloned()
            .ok_or(reject(TransitionReason::Signing))?;
        let requests = effect.requests();
        ensure!(
            requests.len() == artifacts.len()
                && requests
                    .iter()
                    .zip(artifacts.iter())
                    .all(|(request, artifact)| request.matches(signer, artifact)),
            RequestMismatch
        );
        let mut ids = Vec::with_capacity(artifacts.len());
        for artifact in artifacts.iter() {
            self.check_artifact_bounds(artifact)?;
            ids.push(artifact.id::<H>());
        }
        ensure!(
            ids.iter().collect::<BTreeSet<_>>().len() == ids.len()
                && !ids
                    .iter()
                    .any(|id| self.durable.state.local.contains_key(id)),
            DuplicateArtifact
        );
        self.check_publication(minted, publication)?;
        let published = Publication::signed(requests, artifacts)
            .ok_or(reject(TransitionReason::Unauthorized))?;
        ensure!(published.authorized::<H>(&self.profile), Unauthorized);
        let entry = OutboxEntry::of(published);
        ensure!(!self.ended(&entry, self.discharge_facts()), Obligation);
        let forwarded = self.attached_parent(requests)?;
        let published_ids = Self::retained_ids(|visit| entry.publication().visit_retained(visit));
        let released = self
            .durable
            .effect_ids(&sign)
            .ok_or(reject(TransitionReason::References))?
            .to_vec();
        let added = ids
            .iter()
            .chain(&published_ids)
            .copied()
            .collect::<Vec<_>>();
        self.check_occupancy(&added, &released, 0, requests.len())?;
        ensure!(
            self.lifecycle == Lifecycle::Recovering
                || self.signing_issued.get(&sign) == Some(&self.durable.state.generation),
            Signing
        );

        self.signing_issued.remove(&sign);
        for (id, artifact) in ids.into_iter().zip(artifacts.iter()) {
            self.durable.state.local.insert(id, Arc::clone(artifact));
            self.durable.retain(id)?;
        }
        self.durable.state.signing_reservations.remove(&sign);
        self.durable.release_effect(sign)?;
        if let Some((view, parent)) = forwarded {
            self.durable
                .state
                .forwarded_vqcs
                .entry(view)
                .or_default()
                .insert(parent);
        }
        self.durable.admit_effect(publication, published_ids)?;
        self.durable.state.outbox.insert(publication, entry);
        Ok(())
    }

    /// Returns the view and identifier of the parent V-QC a signed proposal attaches, which its
    /// publication forwards, after checking the forwarding history has room for it.
    fn attached_parent(
        &self,
        requests: &[SignRequest<V, H::Digest>],
    ) -> Result<Option<ForwardedVqc<H::Digest>>, ReplayError> {
        let [SignRequest::LeaderBlock(proposal)] = requests else {
            return Ok(None);
        };
        let Some(parent) = proposal
            .parent()
            .exact()
            .filter(|_| proposal.attach_parent())
        else {
            return Ok(None);
        };
        let (view, id) = (parent.view(), parent.id::<H>());
        ensure!(
            self.durable.state.vqc_forwarded(view, &id)
                || self.durable.state.forwarded_count()
                    < self.profile.resources().max_forwarded_certificates(),
            ForwardingFull
        );
        Ok(Some((view, id)))
    }

    fn apply_accepted(&mut self, blocks: &[Acceptance<V, H::Digest>]) -> Result<(), ReplayError> {
        ensure!(!blocks.is_empty(), Acceptance);
        let protocol = self.profile.protocol();
        let mut tips = Vec::<BlockRef<H::Digest>>::with_capacity(blocks.len());
        let mut ids = Vec::with_capacity(blocks.len());
        for acceptance in blocks {
            let header = acceptance.header();
            let chain = header.chain();
            ensure!(chain.index() < self.profile.codec().chains(), Acceptance);
            ensure!(header.epoch() == protocol.epoch(), Epoch);
            if let Some(block) = acceptance.signed() {
                ensure!(protocol.producer(chain) == Some(block.signer()), Acceptance);
                ids.push(Retained::<V, H::Digest>::Header(block).id::<H>());
            }
            let tip = tips
                .iter()
                .rev()
                .find(|tip| tip.chain() == chain)
                .copied()
                .unwrap_or_else(|| self.accepted_tip(chain));
            ensure!(
                tip.height().get().checked_add(1) == Some(header.height().get())
                    && header.parent() == tip.digest(),
                Acceptance
            );
            tips.push(header.block_ref::<H>());
        }
        self.check_occupancy(&ids, &[], 0, 0)?;
        for acceptance in blocks {
            let header = acceptance.header();
            self.durable.state.accepted[header.chain().index()]
                .insert(header.height(), acceptance.clone());
        }
        for id in ids {
            self.durable.retain(id)?;
        }
        Ok(())
    }

    /// Returns the accepted tip of `chain`: its highest accepted header, or its origin.
    pub(in crate::multimmit::machine) fn accepted_tip(
        &self,
        chain: ChainId,
    ) -> BlockRef<H::Digest> {
        self.durable.state.accepted_tip::<H>(chain)
    }

    /// Writes the emission state of `view`: it follows the latest one (view one's genesis base when
    /// none is retained) without a gap, its record extends that one's commitment, and its base
    /// lowers no chain.
    fn apply_emission_resolved(
        &mut self,
        view: View,
        record: &HistoryRecord<H::Digest>,
        by: &Resolution<H::Digest>,
    ) -> Result<(), ReplayError> {
        let state = &self.durable.state;
        let horizon = state
            .view
            .get()
            .saturating_add(self.profile.resources().max_future_view_distance());
        ensure!(view > state.retired_view && view.get() <= horizon, Emission);
        let genesis = self.profile.protocol().genesis();
        let (last, commitment, previous) = state.emission.last_key_value().map_or_else(
            || (View::new(1), genesis.history(), genesis.tips()),
            |(last, emission)| (*last, emission.record.commitment::<H>(), emission.base()),
        );
        ensure!(
            view == last.next() && record.parent() == commitment,
            Emission
        );
        let base = record.tips();
        ensure!(
            base.len() == previous.len()
                && base
                    .iter()
                    .zip(previous)
                    .all(|(tip, before)| tip.height() >= before.height()),
            Emission
        );
        ensure!(
            match by {
                Resolution::Determined => true,
                Resolution::Pinned { view: pinned, .. } => *pinned >= view,
            },
            Emission
        );
        self.durable.state.emission.insert(
            view,
            Emission {
                record: record.clone(),
                by: by.clone(),
            },
        );
        Ok(())
    }

    fn apply_artifact_forwarded(
        &mut self,
        minted: EffectId,
        publication: EffectId,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), ReplayError> {
        let Artifact::Vqc(certificate) = artifact.as_ref() else {
            return Err(reject(TransitionReason::ArtifactKind));
        };
        let (view, certificate) = (certificate.view(), certificate.id::<H>());
        let state = &self.durable.state;
        let resources = self.profile.resources();
        ensure!(!state.vqc_forwarded(view, &certificate), DuplicateArtifact);
        self.check_publication(minted, publication)?;
        self.check_artifact_bounds(artifact)?;
        ensure!(
            state.forwarded_count() < resources.max_forwarded_certificates(),
            ForwardingFull
        );
        ensure!(
            state.effect_count() < resources.max_outbox_effects(),
            OutboxFull
        );
        let entry = OutboxEntry::of(Publication::broadcast(Arc::clone(artifact)));
        ensure!(
            entry.publication().authorized::<H>(&self.profile),
            Unauthorized
        );
        ensure!(!self.ended(&entry, self.discharge_facts()), Obligation);
        let id = artifact.id::<H>();
        self.check_occupancy(&[id], &[], 0, 0)?;

        self.durable.admit_effect(publication, vec![id])?;
        self.durable
            .state
            .forwarded_vqcs
            .entry(view)
            .or_default()
            .insert(certificate);
        self.durable.state.outbox.insert(publication, entry);
        Ok(())
    }

    fn apply_view_entered(
        &mut self,
        proof: ArtifactId<H::Digest>,
        ancestors: &[Arc<Artifact<V, H::Digest>>],
        retired: &[EffectId],
    ) -> Result<(), ReplayError> {
        let state = &self.durable.state;
        let view = state.view;
        let artifact = self
            .durable_certificate(&proof)
            .ok_or(reject(TransitionReason::Exit))?;
        let parent = match artifact.as_ref() {
            Artifact::Vqc(vqc) => vqc.parent(),
            Artifact::Lqc(lqc) => lqc.leader().parent(),
            _ => return Err(reject(TransitionReason::Exit)),
        };
        ensure!(
            artifact.view() == Some(view) && !state.exits.contains_key(&view),
            Exit
        );
        let next = view
            .get()
            .checked_add(1)
            .map(View::new)
            .ok_or(reject(TransitionReason::Overflow))?;
        ensure!(retired == self.ended_by_view_entry(), Retirement);
        let kept = self.check_ancestors(view, parent, ancestors)?;
        let released = self.retired_ids(retired)?;
        let added = core::iter::once(proof)
            .chain(kept.iter().map(|(_, id)| *id))
            .collect::<Vec<_>>();
        self.check_occupancy(&added, &released, 0, 0)?;

        for id in added {
            self.durable.retain(id)?;
        }
        self.retire_publications(retired)?;
        let state = &mut self.durable.state;
        for ((certificate, _), ancestor) in kept.into_iter().zip(ancestors) {
            state.ancestors.insert(certificate, Arc::clone(ancestor));
        }
        state.exits.insert(view, artifact);
        self.durable.state.view = next;
        self.store.release_future_through(next);
        self.retire_superseded_reservations()
    }

    /// Checks that `ancestors` are, newest first, the V-QCs on the parent chain of a proof of
    /// `view` whose parent is `parent`, none kept by a retention holder and each above the retired
    /// view, down to a parent a retention holder keeps. Returns each one's certificate and artifact
    /// identifiers.
    fn check_ancestors(
        &self,
        view: View,
        mut parent: CertificateId<H::Digest>,
        ancestors: &[Arc<Artifact<V, H::Digest>>],
    ) -> Result<Vec<VqcIds<H::Digest>>, ReplayError> {
        let state = &self.durable.state;
        let genesis = self.profile.protocol().genesis().vqc();
        let mut child = view;
        let mut kept = Vec::with_capacity(ancestors.len());
        for ancestor in ancestors {
            let Artifact::Vqc(vqc) = ancestor.as_ref() else {
                return Err(reject(TransitionReason::Ancestors));
            };
            self.check_artifact_bounds(ancestor)?;
            let (view, certificate) = (vqc.view(), vqc.id::<H>());
            ensure!(
                certificate == parent
                    && child.previous() == Some(view)
                    && view > state.retired_view
                    && !state.retains_vqc::<H>(view, &certificate, &genesis),
                Ancestors
            );
            kept.push((certificate, ancestor.id::<H>()));
            parent = vqc.parent();
            child = view;
        }
        ensure!(
            child
                .previous()
                .is_some_and(|view| state.retains_vqc::<H>(view, &parent, &genesis)),
            Ancestors
        );
        Ok(kept)
    }

    /// Returns the durably held certificate `id`: a locally created one or one a queued
    /// publication carries.
    fn durable_certificate(
        &self,
        id: &ArtifactId<H::Digest>,
    ) -> Option<Arc<Artifact<V, H::Digest>>> {
        let state = &self.durable.state;
        if let Some(artifact) = state.local.get(id) {
            return Some(Arc::clone(artifact));
        }
        state.outbox.iter().find_map(|(effect, entry)| {
            let index = self
                .durable
                .effect_ids(effect)?
                .iter()
                .position(|held| held == id)?;
            entry.publication().artifacts().get(index).cloned()
        })
    }

    fn apply_certificate_created(
        &mut self,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), ReplayError> {
        ensure!(
            matches!(artifact.as_ref(), Artifact::Vqc(_) | Artifact::Lqc(_)),
            ArtifactKind
        );
        self.check_artifact_bounds(artifact)?;
        let id = artifact.id::<H>();
        ensure!(
            !self.durable.state.local.contains_key(&id),
            DuplicateArtifact
        );
        self.check_occupancy(&[id], &[], 0, 0)?;
        self.durable.state.local.insert(id, Arc::clone(artifact));
        self.durable.retain(id)
    }

    /// Retires every view at or below `floor` on `root`: drops their signing slots, emissions,
    /// forwarding records, exits, entry-chain ancestors, and local artifacts, every accepted and
    /// own header below the heights retention keeps, and the publications and signing requests the
    /// floor ends.
    ///
    /// The newest emission lies above the floor, so the emission chain keeps extending and the
    /// floor's root and the retained bases stay defined.
    fn apply_retention_advanced(
        &mut self,
        floor: View,
        root: &RetentionRoot<H::Digest>,
        retired_signing: &[EffectId],
        retired_publications: &[EffectId],
    ) -> Result<(), ReplayError> {
        let state = &self.durable.state;
        ensure!(
            floor > state.retired_view
                && floor < state.view
                && state.emission.contains_key(&floor.next())
                && root.record.tips().len() == self.profile.codec().chains()
                && state.retains_vqc::<H>(
                    floor,
                    &root.vqc,
                    &self.profile.protocol().genesis().vqc()
                ),
            RetentionFloor
        );
        let (obsolete, ended) = self.ended_by_retention(floor);
        ensure!(retired_signing == obsolete, Retirement);
        ensure!(retired_publications == ended, Retirement);

        for id in retired_signing {
            self.retire_reservation(*id)?;
        }
        self.retire_publications(retired_publications)?;
        let retained = floor.next();
        let genesis = self.profile.protocol().genesis().tips();
        let state = &mut self.durable.state;
        state.leader_blocks = state.leader_blocks.split_off(&retained);
        state.notarised = state.notarised.split_off(&retained);
        state.watermark = state.watermark.split_off(&retained);
        state.emission = state.emission.split_off(&retained);
        state.forwarded_vqcs = state.forwarded_vqcs.split_off(&retained);
        let kept = state.exits.split_off(&retained);
        let exits = core::mem::replace(&mut state.exits, kept);
        let ancestors = state
            .ancestors
            .extract_if(.., |_, ancestor| {
                ancestor.view().is_none_or(|view| view <= floor)
            })
            .map(|(_, ancestor)| ancestor)
            .collect::<Vec<_>>();
        state.retired_view = floor;
        state.root = Some(root.clone());
        let heights = state.retained_heights(genesis);
        let mut headers = Vec::new();
        for (accepted, height) in state.accepted.iter_mut().zip(&heights) {
            let kept = accepted.split_off(height);
            headers.extend(
                core::mem::replace(accepted, kept)
                    .values()
                    .filter_map(Acceptance::signed)
                    .map(|block| Retained::Header(block).id::<H>()),
            );
        }
        let local = state
            .local
            .iter()
            .filter(|(_, artifact)| match artifact.as_ref() {
                Artifact::TransactionBlock(block) => {
                    let header = block.header();
                    header.height() < heights[header.chain().index()]
                }
                artifact => artifact.view().is_some_and(|view| view <= floor),
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for retired in exits.values().chain(&ancestors) {
            self.durable.release(retired.id::<H>())?;
        }
        for id in headers {
            self.durable.release(id)?;
        }
        for id in local {
            self.durable.state.local.remove(&id);
            self.durable.release(id)?;
        }
        self.store.retire_through(floor);
        Ok(())
    }

    /// Re-roots consensus at the finalization certificate `floor` of view `v`, whose leader block
    /// names `Q'` and whose opening's tips are the base: enters `v` on `Q'` as the retention root
    /// with its emission pinned by the certificate, retires every earlier view's signing slots,
    /// emissions, forwarding records, exits, ancestors, and view-scoped local artifacts, resumes
    /// the vote tags at `v` above the base, and keeps the anchoring L-QC.
    ///
    /// Every chain's origin becomes its base. Its accepted path keeps its headers from the base up
    /// when it holds the base (or the base is genesis), and starts afresh at the base otherwise.
    /// The own chain keeps its headers from the base up and its produced height: peers finalize
    /// only own headers this node signed.
    fn apply_anchored(
        &mut self,
        floor: &Arc<Artifact<V, H::Digest>>,
        retired_signing: &[EffectId],
        retired_publications: &[EffectId],
    ) -> Result<(), ReplayError> {
        let Artifact::Floor(certificate) = floor.as_ref() else {
            return Err(reject(TransitionReason::ArtifactKind));
        };
        self.check_artifact_bounds(floor)?;
        ensure!(self.anchors(certificate), Anchor);
        let view = certificate.lqc().view();
        let retired = view.previous().ok_or(reject(TransitionReason::Anchor))?;
        let (obsolete, ended) = self.ended_by(self.anchor_facts(view));
        ensure!(retired_signing == obsolete, Retirement);
        ensure!(retired_publications == ended, Retirement);
        let lqc = Arc::new(Artifact::Lqc(certificate.lqc().clone()));
        let lqc_id = lqc.id::<H>();
        let fresh = !self.durable.state.local.contains_key(&lqc_id);
        if fresh {
            self.check_occupancy(&[lqc_id], &[], 0, 0)?;
        }

        for id in retired_signing {
            self.retire_reservation(*id)?;
        }
        self.retire_publications(retired_publications)?;
        let own = self.own_chain();
        let opening = certificate.opening();
        let base = opening.tips();
        let state = &mut self.durable.state;
        state.leader_blocks = state.leader_blocks.split_off(&view);
        state.notarised = state.notarised.split_off(&view);
        state.watermark = state.watermark.split_off(&view);
        state.forwarded_vqcs = state.forwarded_vqcs.split_off(&view);
        let kept = state.exits.split_off(&view);
        let exits = core::mem::replace(&mut state.exits, kept);
        let ancestors = core::mem::take(&mut state.ancestors);
        state.emission = BTreeMap::from([(
            view,
            Emission {
                record: opening.clone(),
                by: Resolution::Pinned {
                    view,
                    lqc: certificate.lqc().id::<H>(),
                },
            },
        )]);
        state.retired_view = retired;
        state.root = Some(RetentionRoot {
            vqc: certificate.lqc().leader().parent(),
            record: opening.clone(),
        });
        state.view = view;
        state.last_final = (retired, base.to_vec());
        state.anchored_tag = Some(view);
        state.origin = base.to_vec();
        let mut headers = Vec::new();
        for (accepted, base) in state.accepted.iter_mut().zip(base) {
            let keeps = Some(base.chain()) == own
                || base.height().is_zero()
                || accepted
                    .get(&base.height())
                    .is_some_and(|acceptance| acceptance.header().block_ref::<H>() == *base);
            let kept = if keeps {
                accepted.split_off(&base.height())
            } else {
                BTreeMap::new()
            };
            headers.extend(
                core::mem::replace(accepted, kept)
                    .values()
                    .filter_map(Acceptance::signed)
                    .map(|block| Retained::Header(block).id::<H>()),
            );
        }
        let local = state
            .local
            .iter()
            .filter(|(_, artifact)| artifact.view().is_some_and(|local| local < view))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for dropped in exits.values().chain(ancestors.values()) {
            self.durable.release(dropped.id::<H>())?;
        }
        for id in headers {
            self.durable.release(id)?;
        }
        for id in local {
            self.durable.state.local.remove(&id);
            self.durable.release(id)?;
        }
        if fresh {
            self.durable.state.local.insert(lqc_id, lqc);
            self.durable.retain(lqc_id)?;
        }
        self.store.retire_through(retired);
        self.store.release_future_through(view);
        Ok(())
    }

    /// Returns whether this node can anchor on `floor`: a well-formed finalization certificate of
    /// this epoch (its aggregate is verified before it is staged), of a view this node can anchor
    /// at ([`DurableState::anchorable`]), whose base on the own chain is a header this node
    /// produced.
    ///
    /// [`DurableState::anchorable`]: crate::multimmit::machine::durability::DurableState::anchorable
    pub(in crate::multimmit::machine) fn anchors(&self, floor: &Floor<V, H::Digest>) -> bool {
        let state = &self.durable.state;
        validate_floor::<H, V>(
            floor.lqc(),
            floor.opening(),
            self.profile.protocol().epoch(),
            self.profile.codec(),
        )
        .is_ok()
            && state.anchorable(floor.lqc().view())
            && self
                .own_chain()
                .is_none_or(|own| floor.tips()[own.index()].height() <= state.produced)
    }

    /// Returns this node's producer chain, if it produces one.
    fn own_chain(&self) -> Option<ChainId> {
        match self.profile.role() {
            Role::Validator(participant) => self.profile.protocol().producer_chain(participant),
            Role::Observer => None,
        }
    }

    /// Returns the change anchoring on the [`Artifact::Floor`] `floor`, retiring the signing
    /// reservations and publications of the views it retires.
    ///
    /// # Panics
    ///
    /// Panics unless `floor` is a floor.
    pub(in crate::multimmit::machine) fn anchoring(
        &self,
        floor: Arc<Artifact<V, H::Digest>>,
    ) -> Change<V, H::Digest> {
        let view = floor.view().expect("a floor has a view");
        let (retired_signing, retired_publications) = self.ended_by(self.anchor_facts(view));
        Change::Anchored {
            floor,
            retired_signing,
            retired_publications,
        }
    }

    /// Returns the discharge facts once this node anchored at `view`.
    fn anchor_facts(&self, view: View) -> DischargeFacts {
        DischargeFacts {
            view,
            retired: view.previous().unwrap_or(view),
            ..self.discharge_facts()
        }
    }

    /// Returns the change entering the next view with the durably held certificate `proof` of
    /// the current view, retaining `ancestors`, the V-QCs of the proof's parent chain no retention
    /// holder keeps, newest first, and retiring the publications the entry ends.
    pub(in crate::multimmit::machine) fn view_entry(
        &self,
        proof: ArtifactId<H::Digest>,
        ancestors: Vec<Arc<Artifact<V, H::Digest>>>,
    ) -> Change<V, H::Digest> {
        Change::ViewEntered {
            proof,
            ancestors,
            retired_publications: self.ended_by_view_entry(),
        }
    }

    /// Returns the change raising the retention floor to `floor` on `root`, retiring the signing
    /// reservations and publications it makes obsolete.
    pub(in crate::multimmit::machine) fn retention_advance(
        &self,
        floor: View,
        root: RetentionRoot<H::Digest>,
    ) -> Change<V, H::Digest> {
        let (retired_signing, retired_publications) = self.ended_by_retention(floor);
        Change::RetentionAdvanced {
            floor,
            root,
            retired_signing,
            retired_publications,
        }
    }

    /// Returns the change forwarding the V-QC `artifact` under the publication identifier the
    /// next event mints.
    pub(in crate::multimmit::machine) fn forwarding(
        &self,
        artifact: Arc<Artifact<V, H::Digest>>,
    ) -> Result<Change<V, H::Digest>, StepError> {
        Ok(Change::ArtifactForwarded {
            publication: self.next_effect_id()?,
            artifact,
        })
    }

    /// Returns the publications entering the next view ends.
    fn ended_by_view_entry(&self) -> Vec<EffectId> {
        let state = &self.durable.state;
        state.discharged(DischargeFacts {
            view: View::new(state.view.get().saturating_add(1)),
            ..self.discharge_facts()
        })
    }

    /// Returns the signing reservations of views at or below `floor` and the publications a
    /// retention floor of `floor` ends.
    fn ended_by_retention(&self, floor: View) -> (Vec<EffectId>, Vec<EffectId>) {
        self.ended_by(DischargeFacts {
            retired: floor,
            ..self.discharge_facts()
        })
    }

    /// Returns the signing reservations of views at or below the retired view of `facts` and the
    /// publications `facts` end.
    fn ended_by(&self, facts: DischargeFacts) -> (Vec<EffectId>, Vec<EffectId>) {
        let state = &self.durable.state;
        let obsolete = state
            .signing_reservations
            .iter()
            .filter(|(_, effect)| {
                effect.requests().iter().any(|request| {
                    request
                        .consensus_view()
                        .is_some_and(|view| view <= facts.retired)
                })
            })
            .map(|(id, _)| *id)
            .collect();
        (obsolete, state.discharged(facts))
    }

    /// Returns the facts that end publication duties in the current durable state.
    pub(in crate::multimmit::machine) fn discharge_facts(&self) -> DischargeFacts {
        self.durable.state.discharge_facts(
            u64::from(self.profile.codec().window().flow()),
            self.profile.tuning().vote_window.get(),
        )
    }

    /// Returns whether every item of `entry` is already ended under `facts`.
    fn ended(&self, entry: &OutboxEntry<V, H::Digest>, facts: DischargeFacts) -> bool {
        entry
            .discharges()
            .iter()
            .all(|discharge| self.durable.state.discharge_holds(discharge.until(), facts))
    }

    /// Removes the queued publications `ids` and drops their references.
    fn retire_publications(&mut self, ids: &[EffectId]) -> Result<(), ReplayError> {
        for id in ids {
            ensure!(self.durable.state.outbox.remove(id).is_some(), Obligation);
            self.durable.release_effect(*id)?;
        }
        Ok(())
    }

    /// Returns the artifact references the queued publications `ids` hold.
    fn retired_ids(&self, ids: &[EffectId]) -> Result<Vec<ArtifactId<H::Digest>>, ReplayError> {
        let mut released = Vec::new();
        for id in ids {
            ensure!(self.durable.state.outbox.contains_key(id), Obligation);
            released.extend_from_slice(
                self.durable
                    .effect_ids(id)
                    .ok_or(reject(TransitionReason::References))?,
            );
        }
        Ok(released)
    }

    /// Returns the identifiers of the artifacts `visit` reports.
    fn retained_ids(
        visit: impl FnOnce(&mut dyn FnMut(Retained<'_, V, H::Digest>)),
    ) -> Vec<ArtifactId<H::Digest>> {
        let mut ids = Vec::new();
        visit(&mut |retained| ids.push(retained.id::<H>()));
        ids
    }

    /// Checks a durable artifact's epoch and encoded size.
    fn check_artifact_bounds(&self, artifact: &Artifact<V, H::Digest>) -> Result<(), ReplayError> {
        ensure!(artifact.epoch() == self.profile.protocol().epoch(), Epoch);
        ensure!(
            artifact.encoded_len() <= self.profile.resources().max_artifact_bytes(),
            ArtifactSize
        );
        Ok(())
    }

    /// Checks that durable occupancy fits the artifact cache after the given reference changes.
    fn check_occupancy(
        &self,
        added: &[ArtifactId<H::Digest>],
        released: &[ArtifactId<H::Digest>],
        reservations_added: usize,
        reservations_released: usize,
    ) -> Result<(), ReplayError> {
        let occupancy = self.durable.occupancy_after(
            added,
            released,
            reservations_added,
            reservations_released,
        );
        ensure!(
            occupancy.is_some_and(|occupancy| {
                occupancy <= self.profile.resources().max_cached_artifacts()
            }),
            ArtifactCapacity
        );
        Ok(())
    }

    /// Checks that a new publication takes the identifier the event minted and is not held.
    fn check_publication(
        &self,
        minted: EffectId,
        publication: EffectId,
    ) -> Result<(), ReplayError> {
        ensure!(publication == minted, EffectCursor);
        ensure!(
            !self.durable.state.contains_effect(&publication),
            DuplicateEffect
        );
        Ok(())
    }
}
