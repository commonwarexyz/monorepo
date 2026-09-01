//! Application of one durable event, shared by staging and replay.
//!
//! [`Machine::apply_event`] checks the event's position, then dispatches to one function per
//! [`Change`]. Each function validates its change against the durable state before mutating it,
//! and names the failed check with a [`TransitionReason`].

use crate::{
    Epochable, Viewable,
    multimmit::{
        algebra::DerivedVqc,
        config::Role,
        machine::{
            durability::{
                Change, DomainEvent, DurableEffect, EffectId, ProposalParent, Publication,
                ReplayError, SignEffect, SignRequest, TransitionReason,
            },
            job::{Generation, Issued},
            reducer::machine::{Lifecycle, Machine},
        },
        types::{Artifact, ArtifactBatch, ArtifactId, BlockRef},
    },
    types::View,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::BTreeSet, sync::Arc};

/// Rejects the transition with `$reason` unless `$cond` holds.
macro_rules! ensure {
    ($cond:expr, $reason:ident) => {
        if !$cond {
            return Err(ReplayError::Transition(TransitionReason::$reason));
        }
    };
}

/// The parent V-QC a signed leader block retains.
struct SignedParent<V: Variant, D: Digest> {
    id: ArtifactId<D>,
    view: View,
    artifact: Arc<Artifact<V, D>>,
    /// Whether the proposal attaches the parent, which forwards it for its view.
    attached: bool,
}

impl<V: Variant, D: Digest> SignedParent<V, D> {
    /// Returns the parent a leader-block signing request retains, if any.
    fn of<H: Hasher<Digest = D>>(request: &SignRequest<V, D>) -> Option<Self> {
        let SignRequest::LeaderBlock(request) = request else {
            return None;
        };
        let parent = request.parent().exact()?;
        let artifact = Arc::new(Artifact::Vqc(parent.as_ref().clone()));
        Some(Self {
            id: artifact.id::<H>(),
            view: parent.view(),
            artifact,
            attached: request.attach_parent(),
        })
    }
}

/// Returns a transition failure naming `reason`.
const fn reject(reason: TransitionReason) -> ReplayError {
    ReplayError::Transition(reason)
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Applies one durable event: the single transition function for staging and replay.
    pub(crate) fn apply_event(
        &mut self,
        event: &DomainEvent<V, H::Digest>,
    ) -> Result<(), ReplayError> {
        self.check_position(event)?;
        let minted = EffectId::from_cursor(event.cursor());
        match event.change() {
            Change::GenerationAdvanced(generation) => self.apply_generation_advanced(*generation),
            Change::OutboxQueued { id, effect } => self.apply_outbox_queued(minted, *id, effect),
            Change::SignedArtifacts {
                sign,
                publication,
                artifacts,
            } => self.apply_signed_artifacts(minted, *sign, *publication, artifacts),
            Change::DaCertificateAdvanced {
                publication,
                retired_publications,
                artifact,
            } => self.apply_da_certificate_advanced(
                minted,
                *publication,
                retired_publications,
                artifact,
            ),
            Change::ViewCertificateCreated { artifact } => {
                self.apply_view_certificate_created(artifact)
            }
            Change::ArtifactForwarded {
                publication,
                retired_publications,
                artifact,
            } => {
                self.apply_artifact_forwarded(minted, *publication, retired_publications, artifact)
            }
            Change::ViewAdvanced {
                proof,
                floor,
                retired_publications,
            } => self.apply_view_advanced(*proof, *floor, retired_publications),
            Change::FinalityFloorAdvanced {
                proof,
                retired_signing,
                retired_publications,
            } => self.apply_finality_floor_advanced(proof, retired_signing, retired_publications),
        }?;
        self.durable.state.cursor = event.cursor();
        Ok(())
    }

    fn check_position(&self, event: &DomainEvent<V, H::Digest>) -> Result<(), ReplayError> {
        if event.epoch() != self.profile.protocol().epoch() {
            return Err(ReplayError::Context);
        }
        if self.durable.state.cursor.next() != Some(event.cursor()) {
            return Err(ReplayError::Cursor);
        }
        Ok(())
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
    ) -> Result<(), ReplayError> {
        let ids = Self::effect_artifact_ids(effect);
        ensure!(id == minted, EffectCursor);
        ensure!(!self.contains_durable_effect(id), DuplicateEffect);
        ensure!(
            self.durable_effect_count() < self.profile.resources().max_outbox_effects(),
            OutboxFull
        );
        self.check_occupancy(self.durable_occupancy_after(&ids, 0, effect.reservations()))?;
        ensure!(effect.authorized::<H>(&self.profile), Unauthorized);
        match effect {
            DurableEffect::Sign(sign) => self.apply_signing_queued(id, sign, ids),
            DurableEffect::Publish(publication) => {
                self.admit_durable_effect(id, 0, ids)?;
                ensure!(
                    self.install_publication(id, publication.clone()),
                    Obligation
                );
                Ok(())
            }
        }
    }

    /// Reserves a signing choice: records the choices it commits to, then holds it until its
    /// artifacts are signed or it retires.
    fn apply_signing_queued(
        &mut self,
        id: EffectId,
        sign: &SignEffect<V, H::Digest>,
        ids: Vec<ArtifactId<H::Digest>>,
    ) -> Result<(), ReplayError> {
        let requests = sign.requests();
        if let [SignRequest::LeaderBlock(request)] = requests {
            ensure!(
                !matches!(request.parent(), ProposalParent::Genesis) || !request.attach_parent(),
                ProposalParent
            );
        }
        if let [SignRequest::TransactionBlock(header)] = requests {
            let certified = self
                .durable
                .state
                .certified_height(header.chain())
                .ok_or(reject(TransitionReason::ProducerHeight))?;
            // Another process using this participant identity may have certified the parent.
            // That certificate is already durable earlier in the journal prefix.
            let parent_height = self.durable.state.produced_height.max(certified);
            ensure!(
                parent_height.get().checked_add(1) == Some(header.height().get()),
                ProducerHeight
            );
            self.chain
                .observe_producer_choice::<H>(header)
                .map_err(|_| reject(TransitionReason::ChainState))?;
            self.durable.state.produced_blocks = self
                .durable
                .state
                .produced_blocks
                .checked_add(1)
                .ok_or(reject(TransitionReason::Overflow))?;
            self.durable.state.produced_height = header.height();
        }
        self.observe_da_votes(requests)?;
        for request in requests {
            self.views
                .observe_sign_request(request)
                .map_err(|_| reject(TransitionReason::ViewState))?;
        }
        self.chain
            .reserve_signing(id, sign)
            .map_err(|_| reject(TransitionReason::ChainState))?;

        self.admit_durable_effect(id, requests.len(), ids)?;
        let replaced = self
            .durable
            .state
            .signing_reservations
            .insert(id, sign.clone());
        ensure!(replaced.is_none(), Signing);
        Ok(())
    }

    /// Advances each DA-vote request's chain to the request's height, which must be the next one.
    fn observe_da_votes(
        &mut self,
        requests: &[SignRequest<V, H::Digest>],
    ) -> Result<(), ReplayError> {
        for request in requests {
            let SignRequest::DaVote(block) = request else {
                continue;
            };
            let header = block.header();
            let safe = self
                .durable
                .state
                .da_safety_heights
                .get_mut(header.chain().index())
                .ok_or(reject(TransitionReason::DaHeight))?;
            ensure!(
                safe.get().checked_add(1) == Some(header.height().get()),
                DaHeight
            );
            self.chain
                .observe_da_choice::<H>(header)
                .map_err(|_| reject(TransitionReason::ChainState))?;
            *safe = header.height();
        }
        Ok(())
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
        let parent = match requests {
            [request] => SignedParent::of::<H>(request),
            _ => None,
        };
        let ids = artifacts
            .iter()
            .map(|artifact| self.check_local_artifact(artifact))
            .collect::<Result<Vec<_>, _>>()?;
        let publication_effect = Publication::signed(requests, artifacts, self.profile.protocol())
            .ok_or(reject(TransitionReason::Unauthorized))?;
        self.check_publication(minted, publication)?;
        ensure!(
            ids.iter().copied().collect::<BTreeSet<_>>().len() == ids.len(),
            DuplicateArtifact
        );
        self.check_occupancy(self.durable_occupancy_after(&ids, requests.len(), 0))?;
        ensure!(
            !ids.iter()
                .any(|id| self.durable.state.local.contains_key(id)),
            DuplicateArtifact
        );
        self.check_signed_parent(parent.as_ref())?;
        ensure!(
            publication_effect.authorized::<H>(&self.profile),
            Unauthorized
        );

        if let Some(parent) = parent.as_ref()
            && !self.durable.state.local.contains_key(&parent.id)
        {
            self.insert_local(parent.id, &parent.artifact)?;
        }
        for (id, artifact) in ids.iter().copied().zip(artifacts.iter()) {
            self.insert_local(id, artifact)?;
        }
        self.finish_signing(sign, &effect)?;
        let references = ids
            .into_iter()
            .chain(parent.as_ref().map(|parent| parent.id))
            .collect::<Vec<_>>();
        debug_assert_eq!(
            references,
            Self::effect_artifact_ids(&DurableEffect::Publish(publication_effect.clone())),
            "a signed publication carries its artifacts, then any exact parent, in order"
        );
        // A publication whose items are all already ended is never queued.
        let publish = self.discharges(&publication_effect).is_some();
        if publish {
            self.admit_durable_effect(publication, 0, references)?;
        }
        if let Some(parent) = parent.filter(|parent| parent.attached) {
            self.forward_proposal_parent(parent)?;
        }
        if publish {
            ensure!(
                self.install_publication(publication, publication_effect),
                Obligation
            );
        }
        Ok(())
    }

    /// Checks that a signed proposal's parent matches any held copy and that forwarding an
    /// attached parent fits the forwarding history.
    fn check_signed_parent(
        &self,
        parent: Option<&SignedParent<V, H::Digest>>,
    ) -> Result<(), ReplayError> {
        let Some(parent) = parent else {
            return Ok(());
        };
        ensure!(
            self.durable
                .state
                .local
                .get(&parent.id)
                .is_none_or(|existing| existing == &parent.artifact),
            ProposalParent
        );
        let adds_forwarding_fact =
            parent.attached && !self.durable.state.forwarded_vqcs.contains_key(&parent.view);
        ensure!(
            !adds_forwarding_fact
                || self.durable.state.forwarded_count()
                    < self.profile.resources().max_forwarded_certificates(),
            ForwardingFull
        );
        Ok(())
    }

    /// Records a signed proposal's attached parent as its view's forwarded V-QC.
    fn forward_proposal_parent(
        &mut self,
        parent: SignedParent<V, H::Digest>,
    ) -> Result<(), ReplayError> {
        if let Some(replaced) = self
            .durable
            .state
            .forwarded_vqcs
            .insert(parent.view, Arc::clone(&parent.artifact))
        {
            self.release_durable_artifact(replaced.id::<H>())?;
        }
        self.views.observe_forwarded::<H>(&parent.artifact);
        self.retain_durable_artifact(parent.id)?;
        self.advance_proposal_anchor(&parent.artifact)
    }

    fn apply_da_certificate_advanced(
        &mut self,
        minted: EffectId,
        publication: Option<EffectId>,
        retired: &[EffectId],
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), ReplayError> {
        let Artifact::DaCertificate(certificate) = artifact.as_ref() else {
            return Err(reject(TransitionReason::ArtifactKind));
        };
        let block = certificate.block_ref::<H>();
        let chain = block.chain().index();
        let floor = self
            .durable
            .state
            .certified_tips
            .get(chain)
            .copied()
            .ok_or(reject(TransitionReason::ChainState))?;
        let successor = publication.map(|_| Publication::broadcast(Arc::clone(artifact)));
        let expected = self.obligations_retired_by_da(block.chain(), block.height());
        let remaining = self.durable_effect_count().saturating_sub(retired.len());
        ensure!(block.height() > floor.height(), StaleCertificate);
        self.check_artifact_bounds(artifact)?;
        ensure!(retired == expected, Retirement);
        ensure!(retired.windows(2).all(|pair| pair[0] < pair[1]), Retirement);
        ensure!(
            remaining.saturating_add(usize::from(publication.is_some()))
                <= self.profile.resources().max_outbox_effects(),
            OutboxFull
        );
        ensure!(
            successor
                .as_ref()
                .is_none_or(|effect| effect.authorized::<H>(&self.profile)),
            Unauthorized
        );
        if let Some(id) = publication {
            self.check_publication(minted, id)?;
        }

        self.release_obsolete_chain_artifacts(block)?;
        let artifact_id = artifact.id::<H>();
        let replaced = self
            .durable
            .state
            .local
            .insert(artifact_id, Arc::clone(artifact));
        ensure!(replaced.is_none(), DuplicateArtifact);
        self.retain_durable_artifact(artifact_id)?;
        self.durable.state.certified_tips[chain] = block;
        self.durable.state.da_safety_heights[chain] = match self.profile.role() {
            Role::Validator(_) => self.durable.state.da_safety_heights[chain].max(block.height()),
            Role::Observer => block.height(),
        };
        self.retire_publication_obligations(retired)?;
        if let (Some(id), Some(successor)) = (publication, successor) {
            self.queue_publication(id, successor, vec![artifact_id])?;
        }
        self.chain
            .compact_certified::<H>(certificate, block.height())
            .map_err(|_| reject(TransitionReason::ChainState))?;
        let mut candidates = Vec::new();
        self.store
            .sweep_retired_floors(&self.durable.state.certified_tips, &mut candidates);
        self.forget_ready(candidates.into_iter());
        Ok(())
    }

    /// Releases the local producer artifacts a new certificate for `block` makes obsolete.
    fn release_obsolete_chain_artifacts(
        &mut self,
        block: BlockRef<H::Digest>,
    ) -> Result<(), ReplayError> {
        let obsolete = self
            .durable
            .state
            .local
            .iter()
            .filter_map(|(id, artifact)| {
                let obsolete = match artifact.as_ref() {
                    Artifact::TransactionBlock(old) => {
                        old.header().chain() == block.chain()
                            && old.header().height() <= block.height()
                    }
                    Artifact::DaVote(vote) => {
                        vote.header().chain() == block.chain()
                            && vote.header().height() <= block.height()
                    }
                    Artifact::DaCertificate(old) => old.header().chain() == block.chain(),
                    _ => false,
                };
                obsolete.then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in obsolete {
            self.durable.state.local.remove(&id);
            self.release_durable_artifact(id)?;
        }
        Ok(())
    }

    fn apply_view_certificate_created(
        &mut self,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), ReplayError> {
        ensure!(
            matches!(
                artifact.as_ref(),
                Artifact::Nullification(_) | Artifact::Vqc(_) | Artifact::Lqc(_)
            ),
            ArtifactKind
        );
        let artifact_id = self.check_local_artifact(artifact)?;
        self.check_occupancy(self.durable_occupancy_after(&[artifact_id], 0, 0))?;
        ensure!(
            !self.durable.state.local.contains_key(&artifact_id),
            DuplicateArtifact
        );

        self.insert_local(artifact_id, artifact)?;
        // Record the assembly in view state as the live path does. Without this, a machine
        // restored from a snapshot taken before this event would re-assemble a certificate it
        // already has, and the duplicate is rejected on persistence.
        self.views
            .observe_durable_artifact(artifact)
            .map_err(|_| reject(TransitionReason::ViewState))
    }

    fn apply_artifact_forwarded(
        &mut self,
        minted: EffectId,
        publication: EffectId,
        retired: &[EffectId],
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), ReplayError> {
        let (is_vqc, view) = match artifact.as_ref() {
            Artifact::Vqc(certificate) => (true, certificate.view()),
            Artifact::Nullification(certificate) => (false, certificate.view()),
            _ => return Err(reject(TransitionReason::ArtifactKind)),
        };
        let effect = Publication::broadcast(Arc::clone(artifact));
        let forwarded = if is_vqc {
            self.durable.state.vqc_forwarded(view)
        } else {
            self.durable.state.nullification_forwarded(view)
        };
        ensure!(!forwarded, DuplicateArtifact);
        let artifact_id = artifact.id::<H>();
        let expected = self.obligations_retired_by_exit(view);
        self.check_publication(minted, publication)?;
        self.check_artifact_bounds(artifact)?;
        ensure!(
            self.durable_effect_count()
                .checked_sub(retired.len())
                .is_some_and(|remaining| {
                    remaining < self.profile.resources().max_outbox_effects()
                }),
            OutboxFull
        );
        ensure!(
            self.durable.state.forwarded_count()
                < self.profile.resources().max_forwarded_certificates(),
            ForwardingFull
        );
        self.check_occupancy(self.durable_occupancy_after_retiring(&[artifact_id], 0, retired))?;
        ensure!(effect.authorized::<H>(&self.profile), Unauthorized);
        ensure!(retired == expected, Retirement);

        self.retire_publication_obligations(retired)?;
        let forwarded = if is_vqc {
            &mut self.durable.state.forwarded_vqcs
        } else {
            &mut self.durable.state.forwarded_nullifications
        };
        forwarded.insert(view, Arc::clone(artifact));
        self.views.observe_forwarded::<H>(artifact);
        self.retain_durable_artifact(artifact_id)?;
        if is_vqc {
            self.advance_proposal_anchor(artifact)?;
        }
        self.queue_publication(publication, effect, vec![artifact_id])
    }

    fn apply_view_advanced(
        &mut self,
        proof_id: ArtifactId<H::Digest>,
        floor: View,
        retired: &[EffectId],
    ) -> Result<(), ReplayError> {
        let view = self.durable.state.view;
        let proof = self
            .durable
            .state
            .forwarded_vqcs
            .get(&view)
            .into_iter()
            .chain(self.durable.state.forwarded_nullifications.get(&view))
            .find(|artifact| artifact.id::<H>() == proof_id)
            .cloned()
            .ok_or(reject(TransitionReason::Exit))?;
        ensure!(!self.durable.state.exits.contains_key(&view), Exit);
        let next = view
            .get()
            .checked_add(1)
            .map(View::new)
            .ok_or(reject(TransitionReason::Overflow))?;
        // The floor never falls below the retired view, and a view retention of at least one keeps
        // the exited view itself retained.
        ensure!(
            floor >= self.durable.state.retired_view && floor < view,
            Retirement
        );
        ensure!(
            retired == self.obligations_retired_by_floor(floor),
            Retirement
        );

        self.retire_publication_obligations(retired)?;
        match proof.as_ref() {
            Artifact::Vqc(_) => self.advance_proposal_anchor(&proof)?,
            Artifact::Nullification(_) => {
                ensure!(
                    self.durable
                        .state
                        .proposal_nullified_through
                        .get()
                        .checked_add(1)
                        == Some(view.get()),
                    Exit
                );
                self.durable.state.proposal_nullified_through = view;
                let anchor = self.durable.state.proposal_anchor_view();
                self.views.restore_proposal_frontier(anchor, view);
            }
            _ => return Err(reject(TransitionReason::ArtifactKind)),
        }
        self.durable.state.exits.insert(view, proof);
        self.views.observe_exit(view, proof_id);
        self.durable.state.view = next;
        self.release_future_through(next);
        self.compact_view_history(floor)
    }

    fn apply_finality_floor_advanced(
        &mut self,
        proof: &Arc<Artifact<V, H::Digest>>,
        retired_signing: &[EffectId],
        retired_publications: &[EffectId],
    ) -> Result<(), ReplayError> {
        let Artifact::Lqc(certificate) = proof.as_ref() else {
            return Err(reject(TransitionReason::ArtifactKind));
        };
        let view = certificate.view();
        // View position controls view and proposal progress. A delayed L-QC may still advance
        // the proposal anchor after another exit advanced view.
        let late = view < self.durable.state.view;
        let next = view
            .get()
            .checked_add(1)
            .map(View::new)
            .ok_or(reject(TransitionReason::Overflow))?;
        let (anchor, anchor_id, validated) = match self.finality.finality_anchor(proof) {
            Some(derived) => (
                Arc::clone(derived.artifact.arc()),
                derived.artifact_id,
                derived.validated.clone(),
            ),
            None => {
                let derived = DerivedVqc::from_lqc::<H>(certificate, self.profile.codec())
                    .map_err(|_| reject(TransitionReason::FinalityState))?;
                (
                    derived.artifact.into_arc(),
                    derived.artifact_id,
                    derived.validated,
                )
            }
        };
        let proof_id = proof.id::<H>();
        let anchor_installs = view >= self.durable.state.proposal_anchor_view();
        ensure!(!late || view > self.signing_floor_view(), FinalityFloor);
        ensure!(
            late || self.durable.state.vqc_forwarded(view),
            FinalityFloor
        );
        self.check_artifact_bounds(proof)?;
        ensure!(
            anchor.encoded_len() <= self.profile.resources().max_artifact_bytes(),
            ArtifactSize
        );
        ensure!(
            retired_signing.windows(2).all(|pair| pair[0] < pair[1]),
            Retirement
        );
        ensure!(
            retired_signing == self.obsolete_consensus_signing_effects(view),
            Retirement
        );
        ensure!(
            retired_publications == self.obligations_retired_by_floor(view),
            Retirement
        );
        self.check_occupancy(self.finality_floor_occupancy(
            retired_signing,
            proof_id,
            anchor_installs.then_some(anchor_id),
        ))?;

        for id in retired_signing {
            self.retire_signing(*id)?;
        }
        self.retire_publication_obligations(retired_publications)?;
        self.retain_durable_artifact(proof_id)?;
        if let Some(previous) = self.durable.state.signing_floor.replace(Arc::clone(proof)) {
            self.release_durable_artifact(previous.id::<H>())?;
        }
        if !late {
            self.durable.state.view = next;
        }
        if anchor_installs {
            self.set_proposal_anchor(&anchor, Some(validated))?;
        }
        self.durable.state.retired_view = self.durable.state.retired_view.max(view);
        self.release_future_through(self.durable.state.view);
        self.compact_view_history(self.durable.state.retired_view)
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

    /// Checks a durable artifact's epoch and encoded size, then returns its identifier.
    fn check_local_artifact(
        &self,
        artifact: &Artifact<V, H::Digest>,
    ) -> Result<ArtifactId<H::Digest>, ReplayError> {
        self.check_artifact_bounds(artifact)?;
        Ok(artifact.id::<H>())
    }

    /// Checks that durable artifacts fit the artifact cache after the transition.
    fn check_occupancy(&self, occupancy: Option<usize>) -> Result<(), ReplayError> {
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
        ensure!(!self.contains_durable_effect(publication), DuplicateEffect);
        Ok(())
    }

    /// Durably holds one locally created artifact.
    fn insert_local(
        &mut self,
        id: ArtifactId<H::Digest>,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), ReplayError> {
        self.durable.state.local.insert(id, Arc::clone(artifact));
        self.retain_durable_artifact(id)
    }

    /// Admits a publication and queues it in the outbox with its discharges.
    fn queue_publication(
        &mut self,
        id: EffectId,
        publication: Publication<V, H::Digest>,
        ids: Vec<ArtifactId<H::Digest>>,
    ) -> Result<(), ReplayError> {
        self.admit_durable_effect(id, 0, ids)?;
        ensure!(self.install_publication(id, publication), Obligation);
        Ok(())
    }

    /// Completes the signing reservation `sign` with the requests it authorized, then retires it.
    fn finish_signing(
        &mut self,
        sign: EffectId,
        effect: &SignEffect<V, H::Digest>,
    ) -> Result<(), ReplayError> {
        let signed = if self.lifecycle == Lifecycle::Recovering {
            self.chain.replay_signing(sign, effect)
        } else {
            self.chain
                .complete_signing(Issued::new(sign, self.durable.state.generation), effect)
        };
        signed.map_err(|_| reject(TransitionReason::ChainState))?;
        self.retire_signing(sign)
    }

    /// Removes one signing reservation and releases what it retained.
    pub(crate) fn retire_signing(&mut self, id: EffectId) -> Result<(), ReplayError> {
        let effect = self
            .durable
            .state
            .signing_reservations
            .remove(&id)
            .ok_or(reject(TransitionReason::Signing))?;
        self.release_durable_effect(id, &DurableEffect::Sign(effect))
    }

    /// Clears the future mark on every indexed artifact at or below `view`.
    fn release_future_through(&mut self, view: View) {
        while let Some((future, id)) = self.store.future.first().copied() {
            if future > view {
                break;
            }
            self.store.future.pop_first();
            self.store
                .artifacts
                .get_mut(&id)
                .expect("future index references retained artifact")
                .future = false;
            self.note_retirement_candidate(id);
        }
    }
}
