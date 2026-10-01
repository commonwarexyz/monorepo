//! Component drivers: finality, DA, view, floor, and forwarding work.

use super::{
    machine::{DaOrder, Machine, ViewCertificates},
    persistence::MAX_STAGED_BARRIERS,
    store::ArtifactState,
};
use crate::{
    Viewable,
    multimmit::{
        algebra::{CertificateDerivations, DerivedVqc},
        config::Role,
        machine::{
            capability::{Capabilities, Capability, ChainCommand, ResolverCommand},
            durability::{Change, DurableEffect, EffectId, SignEffect, SignRequest},
            finality::FinalityOutput,
            input::StepError,
            resolution::ResolutionJob,
            scheduler::{Budget, DA_VOTE_RUN, ProtocolComponent, WorkKey},
            verification::Observation,
        },
        types::{Artifact, ArtifactId, CertificateId, ChainId, Lqc},
    },
    types::{Height, View},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use core::mem::take;
use std::{collections::BTreeMap, sync::Arc};

/// Proposal and vote-body pass steps covered by one core credit.
///
/// A pass step handles one producer chain: at most the pipelining depth plus the extension bound
/// of digest comparisons and map lookups, still far cheaper than the transitions core credits are
/// calibrated for. Metering by chain rather than by payload entry keeps a body for every chain
/// inside one drive, so the pass cost does not grow with pipeline depth.
const SIGN_PASS_CHAINS_PER_CREDIT: usize = 4;

/// Where one unit of component work left its component.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum WorkStatus {
    /// The component has no ready work left.
    Complete,
    /// The component has more ready work and yields for this quantum.
    Requeue,
    /// The component waits on capacity a later acknowledgement or completion frees.
    Blocked,
}

pub(super) type WorkResult<V, D> = Result<(WorkStatus, Capabilities<V, D>), StepError>;

impl<H: Hasher, V: Variant> Machine<H, V> {
    pub(super) fn claim_finality(
        &mut self,
        artifact_id: ArtifactId<H::Digest>,
        observation: Observation,
        artifact: Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), StepError> {
        self.finality
            .claim_finality::<H>(artifact_id, observation, artifact, &self.profile)?;
        Ok(())
    }

    pub(super) fn validate_finality(
        &mut self,
        artifact_id: ArtifactId<H::Digest>,
        observation: Observation,
        artifact: &Arc<Artifact<V, H::Digest>>,
        prepared: Option<CertificateDerivations<V, H::Digest>>,
    ) -> Result<(), StepError> {
        let outputs = self.finality.validate_finality_claim::<H>(
            artifact_id,
            observation,
            artifact,
            &self.profile,
            prepared,
        )?;
        self.apply_finality_outputs(outputs)
    }

    pub(super) fn reject_finality(
        &mut self,
        artifact_id: ArtifactId<H::Digest>,
        observation: Observation,
        artifact: &Arc<Artifact<V, H::Digest>>,
    ) -> Result<(), StepError> {
        let outputs = self.finality.reject_finality_claim::<H>(
            artifact_id,
            observation,
            artifact,
            &self.profile,
        )?;
        self.apply_finality_outputs(outputs)
    }

    pub(super) fn retire_finality_through(&mut self, floor: View) -> Result<(), StepError> {
        let outputs = self.finality.retire_through::<H>(&self.profile, floor)?;
        self.apply_finality_outputs(outputs)
    }

    fn apply_finality_outputs(
        &mut self,
        outputs: Vec<FinalityOutput<V, H::Digest>>,
    ) -> Result<(), StepError> {
        for output in outputs {
            self.apply_finality(output.observation, output.certificate, output.derived)?;
        }
        Ok(())
    }

    pub(crate) fn apply_finality(
        &mut self,
        observation: Observation,
        certificate: Arc<Artifact<V, H::Digest>>,
        derived: Option<DerivedVqc<V, H::Digest>>,
    ) -> Result<(), StepError> {
        let Artifact::Lqc(lqc) = certificate.as_ref() else {
            return Err(StepError::ViewInvariant);
        };
        if lqc.view() <= self.signing_floor_view() {
            return Ok(());
        }
        let selected = self.finality.retain_proof::<H>(&certificate, derived)?;
        if !selected || lqc.view() < self.durable.state.view {
            return Ok(());
        }
        self.observe_derived_vqc(&certificate, observation)
    }

    pub(super) fn sync_signing_completions(&mut self) {
        for id in self.completions.pending_signing.keys().copied() {
            self.scheduler.enqueue(WorkKey::CompleteEffect(id));
        }
        if !self.completions.pending_crypto.is_empty() || self.completions.prepared_lqc.is_some() {
            self.scheduler.enqueue(WorkKey::CompleteCrypto);
        }
    }

    pub(crate) fn proposal_anchor(&self) -> (View, Option<CertificateId<H::Digest>>) {
        let Some(Artifact::Vqc(anchor)) = self.durable.state.proposal_anchor.as_deref() else {
            return (View::zero(), None);
        };
        (anchor.view(), Some(anchor.id::<H>()))
    }

    pub(super) fn drive_finality_component(&mut self) -> WorkResult<V, H::Digest> {
        let mut capabilities = Capabilities::new();
        if let Some(view) = self.floor_resolution_view() {
            self.resolution.floor_probe_view = self.durable.state.view;
            if let Some(job) = self.request_resolution(view)? {
                capabilities.push(Capability::Resolver(ResolverCommand::Resolve(job)));
            }
        }
        if let Some(change) = self.next_finality_floor_change() {
            let Change::FinalityFloorAdvanced {
                proof,
                retired_signing,
                ..
            } = &change
            else {
                unreachable!("the finality-floor selector returns a floor change")
            };
            let Artifact::Lqc(certificate) = proof.as_ref() else {
                unreachable!("finality floors carry L-QCs")
            };
            let floor_view = certificate.view();
            // A late floor never carries a forwarding obligation: its view already advanced
            // through the ordinary exit, and a retired view can never re-enter the forwarding
            // frontier, so gating on it would freeze the floor for the rest of the epoch.
            let late = floor_view < self.durable.state.view;
            if !late && !self.durable.state.vqc_forwarded(floor_view) {
                // This turn durably forwards the exit proof and then advances the dependent
                // floor. Reserve worst-case room for both one-event batches before applying
                // either transition; a persistence acknowledgement wakes this component.
                if self.pipeline.staged.len().saturating_add(2) > MAX_STAGED_BARRIERS {
                    return Ok((WorkStatus::Complete, capabilities));
                }
                // The ordinary frontier stays authoritative for forwarding order, so the next
                // pending artifact forwards regardless of whether it is the floor's own V-QC.
                if let Some(forwarding) = self.next_artifact_forwarding(None)? {
                    capabilities.extend(self.reserve_change(forwarding)?);
                    // Stage the floor only once the view's first-V-QC forwarding duty is durable,
                    // recomputing the retirement ledgers the forwarding may have changed. A
                    // different same-view anchor is carried by the proposal that selects it.
                    if self.durable.state.vqc_forwarded(floor_view)
                        && let Some(change) = self.next_finality_floor_change()
                        && let Change::FinalityFloorAdvanced {
                            proof,
                            retired_signing,
                            ..
                        } = &change
                        && self.finality_floor_fits(proof, retired_signing)?
                    {
                        capabilities.extend(self.reserve_change(change)?);
                    }
                    return Ok((WorkStatus::Requeue, capabilities));
                }
            } else if self.finality_floor_fits(proof, retired_signing)? {
                capabilities.extend(self.reserve_change(change)?);
                return Ok((WorkStatus::Requeue, capabilities));
            }
        }

        // Assembly retains only the certificate artifact; publication defers separately when
        // the outbox is full, so a saturated outbox must not stall aggregation or leave the
        // component claiming ready work it cannot perform.
        let has_slot = self.view_proof_artifact_slots() > 0;
        self.finality
            .drive_aggregate(self.durable.state.generation, usize::from(has_slot))?;
        capabilities.extend(self.finality.take_capabilities());
        let status = if self.finality.has_ready_aggregate() && has_slot {
            WorkStatus::Requeue
        } else {
            WorkStatus::Complete
        };
        Ok((status, capabilities))
    }

    pub(super) fn drive_da_component(&mut self, budget: &mut Budget) -> WorkResult<V, H::Digest> {
        if let Some(request) = self.chain.pending_build_sign_request() {
            let effect = DurableEffect::sign(request);
            if self.effect_fits(&effect, 1, &[])? {
                // Consume the volatile build slot before staging: application observes the
                // producer choice immediately and expects the reservation consumed.
                self.chain.mark_build_reserved();
                return Ok((WorkStatus::Requeue, self.reserve_effect_prechecked(effect)?));
            }
        }

        let mut capabilities = Capabilities::new();
        let order = take(&mut self.da_order);
        if order == DaOrder::CertificateFirst && self.advance_da_certificate(&mut capabilities)? {
            return Ok((WorkStatus::Requeue, capabilities));
        }

        capabilities.extend(self.chain.take_capabilities());
        let deferred = (self.view_proof_slots() > 0)
            .then(|| {
                self.views
                    .deferred_certificate_view(self.durable.state.view)
            })
            .flatten();
        if deferred.is_some() {
            self.view_certificates = ViewCertificates::WithDeferred;
            self.scheduler
                .enqueue(WorkKey::Drive(ProtocolComponent::View));
        }

        let production_credit = self.can_reserve_build_credit();
        self.chain.set_production_credit(production_credit);
        self.chain.drive::<H>(self.durable.state.generation)?;
        capabilities.extend(self.chain.take_capabilities());

        if order == DaOrder::ChainFirst && self.advance_da_certificate(&mut capabilities)? {
            return Ok((WorkStatus::Requeue, capabilities));
        }

        let (status, da_capabilities) =
            if self.views.regular_vote_in_progress(self.durable.state.view) {
                (WorkStatus::Complete, Capabilities::new())
            } else {
                self.reserve_ready_da_votes(budget)?
            };
        capabilities.extend(da_capabilities);
        let status = if status == WorkStatus::Requeue {
            WorkStatus::Requeue
        } else {
            WorkStatus::Complete
        };
        Ok((status, capabilities))
    }

    fn reserve_ready_da_votes(&mut self, budget: &mut Budget) -> WorkResult<V, H::Digest> {
        if budget.remaining() == 0 {
            return Ok((WorkStatus::Requeue, Capabilities::new()));
        }
        // One DA-vote reservation is unacknowledged at a time. Blocks that become eligible while
        // its barrier is in flight join the next reservation instead of each staging its own
        // signing action, durable event, and barrier; the acknowledgement wakes this component,
        // so the window is the journal's own group-commit rhythm rather than a timer, and a vote
        // waits at most one signature barrier. The signed result supplies the sync demand.
        if self.pipeline.da_vote_reserved_through > self.pipeline.acked {
            return Ok((WorkStatus::Complete, Capabilities::new()));
        }
        // A run is one outbox action whose completion replaces the signing reservation with one
        // publication, so the outbox funds the action while the artifact cache funds the votes.
        if self.certificate_outbox_slots() == 0 {
            return Ok((WorkStatus::Blocked, Capabilities::new()));
        }
        let resource_slots = self.certificate_artifact_slots();
        // The journal decodes one signing batch and its publication as at most one DA-vote run
        // per producer chain, so a reservation may never exceed that ceiling.
        let encodable = self.profile.codec().chains().saturating_mul(DA_VOTE_RUN);
        let available = resource_slots.min(budget.remaining()).min(encodable);
        let blocks = self.chain.ready_da_votes(available.max(1), DA_VOTE_RUN);
        if blocks.is_empty() {
            return Ok((WorkStatus::Complete, Capabilities::new()));
        }
        if blocks.len() > resource_slots {
            return Ok((WorkStatus::Blocked, Capabilities::new()));
        }
        if blocks.len() > available {
            return Ok((WorkStatus::Requeue, Capabilities::new()));
        }
        // Eligibility includes verified certificates that may not be durable yet. Defer a run
        // whose first height does not extend the DA owner's durable signing-safety height; each
        // later entry extends the one before it in the same batch.
        let mut expected: BTreeMap<ChainId, Height> = BTreeMap::new();
        let deferred = blocks.iter().any(|block| {
            let header = block.header();
            let extends = expected.get(&header.chain()).map_or_else(
                || self.da_vote_extends_durable_safety(header.chain(), header.height()),
                |next| header.height() == *next,
            );
            expected.insert(header.chain(), header.height().next());
            !extends
        });
        if deferred {
            return Ok((WorkStatus::Requeue, Capabilities::new()));
        }

        let requests = blocks
            .iter()
            .cloned()
            .map(|block| SignRequest::DaVote(block))
            .collect::<Vec<_>>();
        let effect = DurableEffect::Sign(SignEffect::new(requests.into()));
        if !self.effect_fits(&effect, 0, &[])? {
            return Ok((WorkStatus::Blocked, Capabilities::new()));
        }
        if !budget.try_spend(blocks.len()) {
            return Ok((WorkStatus::Requeue, Capabilities::new()));
        }
        for block in blocks {
            self.chain.da.mark_da_vote_reserved(block.header().clone());
        }
        let capabilities = self.reserve_effect_prechecked(effect)?;
        self.pipeline.da_vote_reserved_through = self.durable.state.cursor;
        Ok((WorkStatus::Requeue, capabilities))
    }

    /// Reserves the signing `effect` into `capabilities` when it fits and returns whether it did.
    fn try_reserve_sign(
        &mut self,
        effect: DurableEffect<V, H::Digest>,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<bool, StepError> {
        if !self.effect_fits(&effect, 0, &[])? {
            return Ok(false);
        }
        capabilities.extend(self.reserve_effect(effect)?);
        Ok(true)
    }

    pub(super) fn drive_view_component(&mut self, budget: &mut Budget) -> WorkResult<V, H::Digest> {
        let mut capabilities = self.views.take_capabilities();
        let local_leader = matches!(
            self.profile.role(),
            Role::Validator(me) if me == self.profile.protocol().leader(self.durable.state.view)
        );
        if let Some(view) = self
            .views
            .missing_nullification(self.durable.state.view, local_leader)
            && let Some(job) = self.request_resolution(view)?
        {
            capabilities.push(Capability::Resolver(ResolverCommand::Resolve(job)));
        }

        let status = self.drive_votes(budget, &mut capabilities)?;
        if status != WorkStatus::Complete {
            return Ok((status, capabilities));
        }
        let status = self.drive_certificates(budget, &mut capabilities)?;
        if status != WorkStatus::Complete {
            return Ok((status, capabilities));
        }
        let status = self.drive_exit(budget, &mut capabilities)?;
        if status != WorkStatus::Complete {
            return Ok((status, capabilities));
        }
        if let Some(request) = self.views.post_vote_nullify(self.durable.state.view)
            && self.try_reserve_sign(DurableEffect::sign(request), &mut capabilities)?
        {
            return Ok((WorkStatus::Requeue, capabilities));
        }
        let status = self.drive_deferred_certificate(budget, &mut capabilities)?;
        Ok((status, capabilities))
    }

    /// Reserves the current view's cutoff vote, timeout, or regular vote.
    fn drive_votes(
        &mut self,
        budget: &mut Budget,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<WorkStatus, StepError> {
        if let Some(request) = self.views.cutoff_vote(self.durable.state.view)
            && self.try_reserve_sign(DurableEffect::sign(request), capabilities)?
        {
            return Ok(WorkStatus::Requeue);
        }
        if let Some(requests) = self.views.timeout_requests(self.durable.state.view)
            && self
                .try_reserve_sign(DurableEffect::Sign(SignEffect::new(requests)), capabilities)?
        {
            return Ok(WorkStatus::Requeue);
        }
        // Vote with the DA frontier the background pass has already advanced instead of reserving
        // a fresh DA vote on the critical path, so the ordinary vote never waits on the
        // data-availability plane. The background reservation (reserve_ready_da_votes) advances
        // the endorsed frontier between views.
        let regular = self.views.drive_regular_sign_request::<H>(
            &self.profile,
            self.durable.state.view,
            &self.chain,
            budget
                .remaining()
                .saturating_mul(SIGN_PASS_CHAINS_PER_CREDIT),
        )?;
        budget.spend(regular.processed.div_ceil(SIGN_PASS_CHAINS_PER_CREDIT));
        if !regular.complete {
            return Ok(WorkStatus::Requeue);
        }
        let Some(request) = regular.output else {
            return Ok(WorkStatus::Complete);
        };
        Ok(
            if self.try_reserve_sign(DurableEffect::sign(request), capabilities)? {
                WorkStatus::Requeue
            } else {
                WorkStatus::Complete
            },
        )
    }

    /// Drives certificate assembly for the current view.
    fn drive_certificates(
        &mut self,
        budget: &mut Budget,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<WorkStatus, StepError> {
        if budget.remaining() == 0 {
            return Ok(WorkStatus::Requeue);
        }
        let drive = self.views.drive_view_certificates::<H>(
            self.durable.state.generation,
            self.durable.state.view,
            usize::from(self.view_proof_artifact_slots() > 0),
            budget.remaining(),
        )?;
        budget.spend(drive.processed);
        capabilities.extend(self.views.take_capabilities());
        Ok(if drive.complete {
            WorkStatus::Complete
        } else {
            WorkStatus::Requeue
        })
    }

    /// Stages the current view's exit, or the forwarding it waits on.
    fn drive_exit(
        &mut self,
        budget: &mut Budget,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<WorkStatus, StepError> {
        // The exit reads the durable forwarding fact for the current view, and a staged change
        // applies to durable state immediately. Deriving the exit again after staging that fact
        // keeps the committee's next leader from waiting for another service cycle, and puts
        // both events in one persistence range.
        loop {
            let held = self
                .durable
                .state
                .forwarded_vqcs
                .get(&self.durable.state.view)
                .or_else(|| {
                    self.durable
                        .state
                        .forwarded_nullifications
                        .get(&self.durable.state.view)
                })
                .cloned();
            let derived = held.is_some();
            if let Some(exit) =
                held.and_then(|proof| self.views.exit(self.durable.state.view, proof))
            {
                if let Some(leader) = exit.rescue {
                    let body = self.chain.vote_body::<H>(&leader)?;
                    if self.try_reserve_sign(
                        DurableEffect::sign(SignRequest::Vote(body)),
                        capabilities,
                    )? {
                        return Ok(WorkStatus::Requeue);
                    }
                } else {
                    let proof = exit.proof.id::<H>();
                    let next = self
                        .durable
                        .state
                        .view
                        .get()
                        .checked_add(1)
                        .ok_or(StepError::IdentifierExhausted)?;
                    let floor = self
                        .retention_floor_at(View::new(next))
                        .max(self.durable.state.retired_view);
                    let retired = self.obligations_retired_by_floor(floor);
                    capabilities.extend(self.reserve_change(Change::ViewAdvanced {
                        proof,
                        floor,
                        retired_publications: retired,
                    })?);
                    return Ok(WorkStatus::Requeue);
                }
            }

            let Some(change) = self.next_artifact_forwarding(None)? else {
                return Ok(WorkStatus::Complete);
            };
            // Only the current view's proof unblocks the derivation above, and only while that
            // pass held none. Any other forwarding ends the cycle.
            let unblocks = !derived
                && matches!(&change, Change::ArtifactForwarded { artifact, .. }
                    if artifact.view() == Some(self.durable.state.view))
                && budget.try_spend(1);
            capabilities.extend(self.reserve_change(change)?);
            if !unblocks {
                return Ok(WorkStatus::Requeue);
            }
        }
    }

    /// Drives certificate assembly for a view the DA component found deferred, when it asked for
    /// it.
    fn drive_deferred_certificate(
        &mut self,
        budget: &mut Budget,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<WorkStatus, StepError> {
        if self.view_certificates != ViewCertificates::WithDeferred {
            return Ok(WorkStatus::Complete);
        }
        let Some(view) = self
            .views
            .deferred_certificate_view(self.durable.state.view)
        else {
            return Ok(WorkStatus::Complete);
        };
        if budget.remaining() == 0 {
            return Ok(WorkStatus::Requeue);
        }
        let before = self.views.certificate_reservations();
        let drive = self.views.drive_view_certificates::<H>(
            self.durable.state.generation,
            view,
            self.view_proof_slots(),
            budget.remaining(),
        )?;
        budget.spend(drive.processed);
        if self.views.certificate_reservations() > before {
            self.view_certificates = ViewCertificates::CurrentOnly;
        }
        capabilities.extend(self.views.take_capabilities());
        Ok(if drive.complete {
            WorkStatus::Complete
        } else {
            WorkStatus::Requeue
        })
    }

    /// Returns the durable signing floor's view, or zero before any floor is recorded.
    pub(crate) fn signing_floor_view(&self) -> View {
        self.durable
            .state
            .signing_floor
            .as_deref()
            .and_then(|artifact| match artifact {
                Artifact::Lqc(certificate) => Some(certificate.view()),
                _ => None,
            })
            .unwrap_or_else(View::zero)
    }

    /// Returns whether this node holds an exit for a view above the one it can act in.
    ///
    /// Views advance one durable exit at a time, so a certificate above the current view proves
    /// the committee left views whose exit proofs every peer has already retired. Ordinary
    /// advance can never close that gap; only a covering L-QC can.
    pub(super) fn stranded(&self) -> bool {
        let current = self.durable.state.view;
        if self.durable.state.vqc_forwarded(current)
            || self.durable.state.nullification_forwarded(current)
        {
            return false;
        }
        let beyond = |exits: &BTreeMap<View, Arc<Artifact<V, H::Digest>>>| {
            exits
                .last_key_value()
                .is_some_and(|(view, _)| *view > current)
        };
        beyond(&self.durable.state.forwarded_vqcs)
            || beyond(&self.durable.state.forwarded_nullifications)
    }

    /// Returns the view whose resolution could raise a lagging finality floor.
    ///
    /// No peer pushes an L-QC, so this is the only way a node without finality for a leader
    /// learns the outcome. A stranded node holds exits above the view it can act in and none for
    /// that view, so it asks for the current view: its own store cannot answer, and any peer whose
    /// finality passed that view serves a covering L-QC. It probes until the resolution lands,
    /// even while a local aggregate is pending, because that aggregate may wait on verification
    /// work the node cannot complete while stranded. A node whose finality floor trails its view
    /// by more than the future-view horizon exited those views on V-QCs or nullifications without
    /// settling their leaders; it asks for the view after the floor once per view advance, and
    /// skips the probe while a pool of its own already reached finality above the floor, since
    /// that aggregate settles the same view without a round trip. One request per view is
    /// outstanding at a time because the resolution index admits one job per view.
    fn floor_resolution_view(&self) -> Option<View> {
        let floor = self.signing_floor_view();
        if self.finality.signing_floor_candidate(floor).is_some() {
            return None;
        }
        if self.stranded() {
            return Some(self.durable.state.view);
        }
        let next = floor.get().checked_add(1).map(View::new)?;
        let horizon = self.profile.resources().max_future_view_distance();
        let lagging = self.durable.state.view.get().saturating_sub(floor.get()) > horizon
            && self.resolution.floor_probe_view < self.durable.state.view
            && !self.finality.assembling_above(floor);
        lagging.then_some(next)
    }

    pub(crate) fn next_finality_floor_change(&self) -> Option<Change<V, H::Digest>> {
        let proof = self
            .finality
            .signing_floor_candidate(self.signing_floor_view())?;
        let Artifact::Lqc(certificate) = proof.as_ref() else {
            unreachable!("the finality index admits only L-QCs")
        };
        let view = certificate.view();
        Some(Change::FinalityFloorAdvanced {
            proof,
            retired_signing: self.obsolete_consensus_signing_effects(view),
            retired_publications: self.obligations_retired_by_floor(view),
        })
    }

    pub(super) fn next_artifact_forwarding(
        &self,
        required: Option<&Lqc<V, H::Digest>>,
    ) -> Result<Option<Change<V, H::Digest>>, StepError> {
        let Some(artifact) = self.views.next_forward() else {
            return Ok(None);
        };
        if required.is_some_and(|required| {
            !matches!(artifact.as_ref(), Artifact::Vqc(certificate)
                if required.equivalent_vqc(certificate))
        }) {
            return Ok(None);
        }
        let effect = DurableEffect::broadcast(Arc::clone(&artifact));
        let retired =
            self.obligations_retired_by_exit(artifact.view().expect("exit proof has a view"));
        if !self.effect_fits(&effect, 0, &retired)? {
            return Ok(None);
        }
        if self.durable.state.forwarded_count()
            >= self.profile.resources().max_forwarded_certificates()
        {
            return Err(StepError::ForwardingHistoryFull);
        }
        Ok(Some(Change::ArtifactForwarded {
            publication: self.next_effect_id()?,
            retired_publications: retired,
            artifact,
        }))
    }

    /// Makes the all-vote V-QC carried by an L-QC visible to the normal forwarding selector.
    ///
    /// Reusing the L-QC aggregate preserves the original observation order without another
    /// cryptographic job.
    fn observe_derived_vqc(
        &mut self,
        certificate: &Arc<Artifact<V, H::Digest>>,
        observation: Observation,
    ) -> Result<(), StepError> {
        let derived = self
            .finality
            .finality_anchor(certificate)
            .ok_or(StepError::ViewInvariant)?;
        let artifact = Arc::clone(derived.artifact.arc());
        let id = derived.artifact_id;
        let validated = derived.validated.clone();
        self.views
            .observe::<H>(id, observation, &artifact, Some(validated))?;
        Ok(())
    }

    pub(crate) fn obsolete_consensus_signing_effects(&self, floor: View) -> Vec<EffectId> {
        self.durable
            .state
            .signing_reservations
            .iter()
            .filter_map(|(id, effect)| {
                effect
                    .requests()
                    .iter()
                    .all(|request| request.consensus_view().is_some_and(|view| view <= floor))
                    .then_some(*id)
            })
            .collect()
    }

    fn advance_da_certificate(
        &mut self,
        capabilities: &mut Capabilities<V, H::Digest>,
    ) -> Result<bool, StepError> {
        // The frontier only picks between advanceable chains, so a floor no certificate exceeds
        // makes the sweep pure overhead.
        if !self
            .chain
            .da
            .has_certificate_above(&self.durable.state.certified_tips)
        {
            return Ok(false);
        }
        let preferred = self
            .chain
            .selected_da_chain(|chain, height| !self.da_vote_extends_durable_safety(chain, height));
        let Some(artifact) = self.next_durable_da_certificate(preferred) else {
            return Ok(false);
        };
        let Artifact::DaCertificate(certificate) = artifact.as_ref() else {
            return Err(StepError::ChainInvariant);
        };
        let retired = self
            .obligations_retired_by_da(certificate.header().chain(), certificate.header().height());
        let owns_chain = matches!(
            self.profile.role(),
            Role::Validator(participant)
                if self.profile.protocol().producer(certificate.header().chain())
                    == Some(participant)
        );
        let anchor = owns_chain.then(|| certificate.header().height());
        let publication = if retired.is_empty() || !owns_chain {
            None
        } else {
            Some(self.next_effect_id()?)
        };
        let change = Change::DaCertificateAdvanced {
            publication,
            retired_publications: retired,
            artifact,
        };
        capabilities.extend(self.reserve_change(change)?);
        self.da_order = DaOrder::ChainFirst;
        // A remote or leader-carried certificate can advance the own anchor; tell the task so it
        // prunes the settled pool.
        if let Some(height) = anchor {
            capabilities.push(Capability::OwnChainDa(ChainCommand::AnchorAdvanced(height)));
        }
        Ok(true)
    }

    fn next_durable_da_certificate(
        &self,
        preferred: Option<ChainId>,
    ) -> Option<Arc<Artifact<V, H::Digest>>> {
        self.chain
            .da
            .next_certificate_above(&self.durable.state.certified_tips, preferred)
            .map(|certificate| Arc::new(Artifact::DaCertificate(certificate)))
    }

    fn da_vote_extends_durable_safety(&self, chain: ChainId, height: Height) -> bool {
        self.durable
            .state
            .da_safety_heights
            .get(chain.get() as usize)
            .and_then(|safe| safe.get().checked_add(1))
            == Some(height.get())
    }

    /// Returns whether the machine still needs evidence crossing the requested view.
    pub(super) fn resolution_needed(&self, view: View) -> bool {
        !self.has_exit_for(view) || self.floor_resolution_view() == Some(view)
    }

    fn has_exit_for(&self, view: View) -> bool {
        self.store.by_view.get(&view).is_some_and(|ids| {
            ids.iter()
                .filter_map(|id| self.store.artifacts.get(id))
                .any(|entry| {
                    matches!(entry.state, ArtifactState::Ready)
                        && matches!(
                            entry.artifact.as_ref(),
                            Artifact::Nullification(_) | Artifact::Vqc(_)
                        )
                })
        })
    }

    pub(super) fn retract_unneeded_resolutions(&mut self) {
        let views = self.resolution.keys().collect::<Vec<_>>();
        for view in views {
            if !self.resolution_needed(view) {
                self.cancel_resolution(view);
            }
        }
    }

    pub(super) fn cancel_resolution(&mut self, view: View) {
        if let Some(job) = self.resolution.resolved(view) {
            self.resolution
                .capabilities
                .push(Capability::Resolver(ResolverCommand::Cancel(job)));
        }
    }

    pub(super) fn fail_resolution_verification(
        &mut self,
        artifact: ArtifactId<H::Digest>,
    ) -> Vec<ResolutionJob> {
        let failed = self.resolution.verification_failed(artifact);
        if !failed.is_empty() {
            self.wake_components();
        }
        for job in &failed {
            self.resolution
                .capabilities
                .push(Capability::Resolver(ResolverCommand::Reject(*job)));
        }
        failed
    }

    pub(super) fn rearm_failed_resolutions(
        &mut self,
        failed: impl IntoIterator<Item = ResolutionJob>,
    ) -> Result<(), StepError> {
        for failed in failed {
            let view = failed.view();
            if self.resolution_needed(view)
                && let Some(retry) = self.request_resolution(view)?
            {
                self.resolution
                    .capabilities
                    .push(Capability::Resolver(ResolverCommand::Resolve(retry)));
            }
        }
        Ok(())
    }

    pub(super) fn request_resolution(
        &mut self,
        view: View,
    ) -> Result<Option<ResolutionJob>, StepError> {
        Ok(self.resolution.request(
            self.durable.state.generation,
            view,
            self.profile.resources().max_dependency_waiters(),
        )?)
    }
}
