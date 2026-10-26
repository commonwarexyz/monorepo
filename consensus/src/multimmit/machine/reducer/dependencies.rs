//! Verification verdicts, dependency waits, readiness, and self-admission.

use super::{
    machine::{Lifecycle, Machine},
    store::{ArtifactEntry, ArtifactState, FloorPosition},
};
use crate::{
    Epochable, Viewable,
    multimmit::{
        algebra::{CertificateDerivations, ValidatedLqc, ValidatedVqc},
        machine::{
            artifact::Dependency,
            capability::Capability,
            durability::Retained,
            input::{Step, StepError, StepStatus},
            util::remove_indexed,
            verification::{Observation, Verdict},
        },
        types::{Anchor, Artifact, ArtifactId},
    },
    types::Participant,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use core::mem::take;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// An artifact identity a completion already derived off-thread.
#[derive(Copy, Clone)]
pub(super) struct DerivedIdentity<D: Digest> {
    pub(super) id: ArtifactId<D>,
    pub(super) encoded_len: usize,
}

/// A certificate transcript a verification or aggregation job already validated off-thread.
pub(super) enum ValidatedCertificate<V: Variant, D: Digest> {
    Vqc(ValidatedVqc<D>),
    Lqc(ValidatedLqc<V, D>),
}

/// A validated certificate split by the state that consumes it.
struct ValidatedParts<V: Variant, D: Digest> {
    /// Attested votes and tips for the finality pool.
    derivations: Option<CertificateDerivations<V, D>>,
    /// V-QC ordering data for the view state.
    vqc: Option<ValidatedVqc<D>>,
}

impl<V: Variant, D: Digest> From<Option<ValidatedCertificate<V, D>>> for ValidatedParts<V, D> {
    fn from(validated: Option<ValidatedCertificate<V, D>>) -> Self {
        match validated {
            Some(ValidatedCertificate::Vqc(mut vqc)) => Self {
                derivations: Some(CertificateDerivations::from(&mut vqc)),
                vqc: Some(vqc),
            },
            Some(ValidatedCertificate::Lqc(lqc)) => Self {
                derivations: Some(CertificateDerivations::from(lqc)),
                vqc: None,
            },
            None => Self {
                derivations: None,
                vqc: None,
            },
        }
    }
}

/// Which dependencies are available, who provides them, and which artifacts wait on them.
pub(crate) struct DependencyIndex<D: Digest> {
    /// Dependencies some retained or genesis artifact already provides.
    pub(in crate::multimmit::machine) available: BTreeSet<Dependency<D>>,
    /// Retained artifacts providing each dependency.
    pub(in crate::multimmit::machine) providers: BTreeMap<Dependency<D>, BTreeSet<ArtifactId<D>>>,
    /// Artifacts waiting on each missing dependency.
    pub(in crate::multimmit::machine) waiters: BTreeMap<Dependency<D>, BTreeSet<ArtifactId<D>>>,
    /// Dependencies whose only providers failed verification.
    pub(in crate::multimmit::machine) invalid: BTreeSet<Dependency<D>>,
    /// Set once the record of invalid dependencies reached its bound.
    pub(in crate::multimmit::machine) rejections_saturated: bool,
    /// Bounded dependency-waiter slots in use.
    pub(in crate::multimmit::machine) slots: usize,
}

impl<D: Digest> DependencyIndex<D> {
    /// Returns an index where only `available` is provided.
    pub(super) const fn new(available: BTreeSet<Dependency<D>>) -> Self {
        Self {
            available,
            providers: BTreeMap::new(),
            waiters: BTreeMap::new(),
            invalid: BTreeSet::new(),
            rejections_saturated: false,
            slots: 0,
        }
    }

    /// Records `id` as a retained provider of each of `provisions`.
    pub(super) fn add_provider(&mut self, id: ArtifactId<D>, provisions: &[Dependency<D>]) {
        for provision in provisions.iter().copied() {
            self.providers.entry(provision).or_default().insert(id);
        }
    }

    /// Removes `id` as a provider of `provision`, returning whether that left no retained
    /// provider.
    pub(super) fn remove_provider(
        &mut self,
        provision: &Dependency<D>,
        id: &ArtifactId<D>,
    ) -> bool {
        remove_indexed(&mut self.providers, provision, id)
    }

    /// Returns whether a retained artifact provides `dependency`.
    pub(super) fn has_provider(&self, dependency: &Dependency<D>) -> bool {
        self.providers.contains_key(dependency)
    }

    /// Records `id` as waiting on the missing `dependency`.
    pub(super) fn add_waiter(&mut self, dependency: Dependency<D>, id: ArtifactId<D>) {
        self.waiters.entry(dependency).or_default().insert(id);
    }

    /// Removes `id` from the artifacts waiting on `dependency`.
    pub(super) fn remove_waiter(&mut self, dependency: &Dependency<D>, id: &ArtifactId<D>) {
        remove_indexed(&mut self.waiters, dependency, id);
    }

    /// Makes `dependency` available and returns the artifacts that waited on it, or `None` if
    /// it already was.
    pub(super) fn make_available(
        &mut self,
        dependency: Dependency<D>,
    ) -> Option<BTreeSet<ArtifactId<D>>> {
        if !self.available.insert(dependency) {
            return None;
        }
        self.waiters.remove(&dependency)
    }

    /// Forgets `dependency`: it is no longer available and no retained artifact provides it.
    pub(super) fn forget(&mut self, dependency: &Dependency<D>) {
        self.available.remove(dependency);
        self.providers.remove(dependency);
    }

    /// Takes one bounded dependency-waiter slot.
    pub(super) const fn claim_slot(&mut self) {
        self.slots += 1;
    }

    /// Returns one bounded dependency-waiter slot.
    pub(super) const fn release_slot(&mut self) {
        self.slots -= 1;
    }
}

/// A promoted artifact: its observation, the artifact, and the dependencies it provides.
struct ReadyArtifact<V: Variant, D: Digest> {
    observation: Observation,
    artifact: Arc<Artifact<V, D>>,
    provisions: Arc<[Dependency<D>]>,
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    pub(super) fn apply_verification_verdict(
        &mut self,
        verdict: Verdict<H::Digest>,
        validated: Option<ValidatedCertificate<V, H::Digest>>,
        da_equivocator: Option<Participant>,
    ) -> Result<Option<bool>, StepError> {
        let ticket = verdict.ticket();
        let current = matches!(
            self.store.artifacts.get(&ticket.artifact()).map(|entry| &entry.state),
            Some(ArtifactState::Pending(expected)) if *expected == ticket
        );
        if !current {
            return Ok(None);
        }
        if verdict.valid() {
            let (observation, artifact) = {
                let entry = &self.store.artifacts[&ticket.artifact()];
                (entry.observation, Arc::clone(&entry.artifact))
            };
            // The compute pool already expanded and hashed every attested vote; hand the finality
            // pool those derivations instead of recomputing them on this thread.
            let ValidatedParts {
                derivations: prepared,
                vqc: validated_vqc,
            } = validated.into();
            let mut proven = self
                .accountability
                .observe::<H, V>(&artifact, prepared.as_ref());
            if let Some(participant) = da_equivocator
                && self.accountability.record_fault(participant)
            {
                proven.push(participant);
            }
            self.quarantine.extend(proven);
            if self.exceeds_fork_bound(&artifact) {
                self.remove_terminal_artifact(ticket.artifact())?;
                return Ok(Some(true));
            }
            self.validate_finality(ticket.artifact(), observation, &artifact, prepared)?;
            if matches!(artifact.as_ref(), Artifact::Vote(_)) {
                self.views
                    .observe::<H>(ticket.artifact(), observation, &artifact, None)?;
                self.store
                    .artifacts
                    .get_mut(&ticket.artifact())
                    .expect("verified artifact remains retained")
                    .view_observed = true;
            }
            self.authenticate(ticket.artifact(), validated_vqc)?;
            return Ok(Some(true));
        }

        let failed = self.fail_resolution_verification(ticket.artifact());
        let artifact = Arc::clone(
            &self
                .store
                .artifacts
                .get(&ticket.artifact())
                .expect("issued verification ticket must retain its artifact")
                .artifact,
        );
        self.chain
            .reject_unverified::<H>(ticket.artifact(), &artifact)?;
        let invalid_dependency = self.store.artifacts[&ticket.artifact()]
            .provisions
            .iter()
            .copied()
            .find(|dependency| matches!(dependency, Dependency::Vqc(_)));
        self.remove_terminal_artifact(ticket.artifact())?;
        self.rearm_failed_resolutions(failed)?;
        if let Some(dependency) = invalid_dependency {
            self.reject_dependency(dependency)?;
        }
        Ok(Some(false))
    }

    pub(super) fn finish_verification_prefix(
        &mut self,
        valid: usize,
        invalid: usize,
    ) -> Result<Step<V, H::Digest>, StepError> {
        self.discard_chain_artifacts()?;
        self.wake_components();
        self.forget_retired_artifacts()?;
        let capabilities = if self.quarantine.is_empty() {
            Vec::new()
        } else {
            vec![Capability::Quarantine(take(&mut self.quarantine))]
        };
        Ok(Step::new(
            StepStatus::Verified { valid, invalid },
            capabilities,
        ))
    }

    pub(super) fn authenticate(
        &mut self,
        id: ArtifactId<H::Digest>,
        validated_vqc: Option<ValidatedVqc<H::Digest>>,
    ) -> Result<(), StepError> {
        let entry = &self.store.artifacts[&id];
        let dependency_protected = entry.dependency_protected;
        let dependency = entry
            .artifact
            .dependency()
            .filter(|dependency| !self.dependencies.available.contains(dependency));

        let Some(dependency) = dependency else {
            return self.make_ready(id, validated_vqc);
        };
        debug_assert!(
            validated_vqc.is_none(),
            "only V-QCs carry validation derivations"
        );
        if !dependency_protected
            && (self.dependencies.invalid.contains(&dependency)
                || self.dependencies.rejections_saturated
                    && !self.has_retained_provider(dependency))
        {
            self.remove_terminal_artifact(id)?;
            return Ok(());
        }
        self.wait_on(id, dependency);
        self.note_retirement_candidate(id);
        Ok(())
    }

    fn reject_dependency(&mut self, dependency: Dependency<H::Digest>) -> Result<(), StepError> {
        let reject_all = !self.dependencies.rejections_saturated
            && !self.dependencies.invalid.contains(&dependency)
            && self.dependencies.invalid.len() >= self.profile.resources().max_dependency_waiters();
        if reject_all {
            self.dependencies.rejections_saturated = true;
            self.dependencies.invalid.clear();
        } else if !self.dependencies.rejections_saturated {
            self.dependencies.invalid.insert(dependency);
        }

        let waiters = if reject_all {
            self.dependencies
                .waiters
                .values()
                .flat_map(|waiters| waiters.iter().copied())
                .filter(|waiter| self.orphaned_waiter(waiter))
                .collect::<BTreeSet<_>>()
        } else {
            self.dependencies
                .waiters
                .get(&dependency)
                .into_iter()
                .flatten()
                .copied()
                .filter(|waiter| {
                    self.store
                        .artifacts
                        .get(waiter)
                        .is_some_and(|entry| !entry.dependency_protected)
                })
                .collect()
        };
        for waiter in waiters {
            let Some(entry) = self.store.artifacts.get(&waiter) else {
                continue;
            };
            if !matches!(entry.state, ArtifactState::Waiting(_)) {
                continue;
            }
            self.remove_terminal_artifact(waiter)?;
        }
        Ok(())
    }

    /// Returns whether `artifact` is a verified producer block its position has no room for.
    ///
    /// Accountability has already seen the block, so a fork beyond the bound still proves its
    /// producer faulty.
    fn exceeds_fork_bound(&self, artifact: &Artifact<V, H::Digest>) -> bool {
        matches!(artifact, Artifact::TransactionBlock(block)
            if self
                .store
                .verified_blocks_full((block.header().chain(), block.header().height())))
    }

    fn has_retained_provider(&self, dependency: Dependency<H::Digest>) -> bool {
        self.dependencies.has_provider(&dependency)
    }

    /// Returns whether an unprotected artifact waits on a dependency no retained artifact provides.
    fn orphaned_waiter(&self, id: &ArtifactId<H::Digest>) -> bool {
        let Some(entry) = self.store.artifacts.get(id) else {
            return false;
        };
        let ArtifactState::Waiting(missing) = &entry.state else {
            return false;
        };
        !entry.dependency_protected && !self.has_retained_provider(*missing)
    }

    /// Evicts one refetchable future-view artifact to admit a self-certifying view proof.
    ///
    /// The farthest-ahead gossip goes first: it is the least likely to become actionable
    /// before redelivery. When only view proofs remain, the lowest-view proof goes: every
    /// higher retained proof re-anchors at least as far. Returns whether an entry was evicted.
    pub(super) fn evict_future_gossip(&mut self) -> Result<bool, StepError> {
        let victim = self
            .store
            .future
            .iter()
            .rev()
            .find(|(_, id)| {
                self.store
                    .artifacts
                    .get(id)
                    .is_some_and(|entry| !entry.artifact.self_certifying_view())
            })
            .or_else(|| self.store.future.iter().next())
            .map(|(_, id)| *id);
        let Some(id) = victim else {
            return Ok(false);
        };
        self.remove_terminal_artifact(id)?;
        Ok(true)
    }

    pub(super) fn remove_terminal_artifact(
        &mut self,
        id: ArtifactId<H::Digest>,
    ) -> Result<(), StepError> {
        let mut pending = BTreeSet::from([id]);
        let mut failed_resolutions = Vec::new();
        while let Some(id) = pending.pop_first() {
            failed_resolutions.extend(self.fail_resolution_verification(id));
            let Some(entry) = self.remove_entry(id) else {
                continue;
            };
            self.reject_finality(id, entry.observation, &entry.artifact)?;
            self.views.reject(id, &entry.artifact);

            for provision in entry.provisions.iter().copied() {
                self.dependencies.remove_provider(&provision, &id);
                if !self.dependencies.rejections_saturated || self.has_retained_provider(provision)
                {
                    continue;
                }
                let waiters = self
                    .dependencies
                    .waiters
                    .get(&provision)
                    .cloned()
                    .unwrap_or_default();
                pending.extend(
                    waiters
                        .into_iter()
                        .filter(|waiter| self.orphaned_waiter(waiter)),
                );
            }
        }
        self.retract_unneeded_resolutions();
        self.rearm_failed_resolutions(failed_resolutions)
    }

    fn make_ready(
        &mut self,
        first: ArtifactId<H::Digest>,
        mut validated_vqc: Option<ValidatedVqc<H::Digest>>,
    ) -> Result<(), StepError> {
        let mut ready = BTreeSet::from([first]);
        while let Some(id) = ready.pop_first() {
            let ready_vqc = if id == first {
                validated_vqc.take()
            } else {
                None
            };
            let ReadyArtifact {
                observation,
                artifact,
                provisions,
            } = self.promote(id, ready_vqc.as_ref())?;
            if self.lifecycle == Lifecycle::Live {
                self.observe_ready(id, observation, &artifact, ready_vqc)?;
            }
            self.release_waiters(&provisions, &mut ready);
        }
        self.discard_chain_artifacts()?;
        self.retract_unneeded_resolutions();
        self.forget_retired_artifacts()?;
        Ok(())
    }

    /// Marks `id` ready, indexes a ready V-QC by its certificate identifier, and frees its
    /// dependency slot.
    ///
    /// Returns the artifact's observation, the artifact, and the dependencies it provides.
    fn promote(
        &mut self,
        id: ArtifactId<H::Digest>,
        validated_vqc: Option<&ValidatedVqc<H::Digest>>,
    ) -> Result<ReadyArtifact<V, H::Digest>, StepError> {
        let entry = self.store.artifacts.get_mut(&id).expect("artifact exists");
        let promoted = !matches!(entry.state, ArtifactState::Ready);
        entry.state = ArtifactState::Ready;
        let ready = ReadyArtifact {
            observation: entry.observation,
            artifact: Arc::clone(&entry.artifact),
            provisions: Arc::clone(&entry.provisions),
        };
        self.release_dependency_slot(id);
        let ReadyArtifact {
            observation,
            artifact,
            ..
        } = &ready;
        if promoted {
            if let Artifact::TransactionBlock(block) = artifact.as_ref() {
                self.store
                    .note_verified_block((block.header().chain(), block.header().height()), id);
            }
            if self.retired(artifact) {
                self.store.retirement_pending.push(id);
            }
            self.store
                .newly_ready
                .push((*observation, id, Arc::clone(artifact)));
        }
        if let Artifact::Vqc(certificate) = artifact.as_ref() {
            let certificate = validated_vqc
                .map(|validated| validated.id())
                .unwrap_or_else(|| certificate.id::<H>());
            if self
                .store
                .vqcs
                .insert(certificate, id)
                .is_some_and(|existing| existing != id)
            {
                return Err(StepError::ViewInvariant);
            }
        }
        Ok(ready)
    }

    /// Hands a newly ready artifact to resolution, the chain partition, and the view partition.
    fn observe_ready(
        &mut self,
        id: ArtifactId<H::Digest>,
        observation: Observation,
        artifact: &Arc<Artifact<V, H::Digest>>,
        validated_vqc: Option<ValidatedVqc<H::Digest>>,
    ) -> Result<(), StepError> {
        for key in self.resolution.verification_ready(id) {
            self.cancel_resolution(key);
        }
        match artifact.as_ref() {
            Artifact::Nullification(certificate) => {
                self.cancel_resolution(certificate.view());
            }
            Artifact::Vqc(certificate) => {
                self.cancel_resolution(certificate.view());
            }
            Artifact::Lqc(certificate) => {
                let covered = self
                    .resolution
                    .keys()
                    .filter(|view| *view <= certificate.view())
                    .collect::<Vec<_>>();
                for key in covered {
                    self.cancel_resolution(key);
                }
            }
            _ => {}
        }
        self.chain.observe::<H>(id, observation, artifact)?;
        if matches!(artifact.as_ref(), Artifact::TransactionBlock(_)) {
            self.views.observe_attested_header(self.durable.state.view);
        }
        if let Artifact::LeaderBlock(block) = artifact.as_ref() {
            let anchors =
                block
                    .block()
                    .proposals()
                    .iter()
                    .filter_map(|proposal| match proposal.anchor() {
                        Anchor::Certificate(certificate) => Some(certificate.clone()),
                        Anchor::Tip(_) => None,
                    });
            self.chain.da.install_anchors::<H>(anchors)?;
        }
        if !self.store.artifacts[&id].view_observed {
            self.views
                .observe::<H>(id, observation, artifact, validated_vqc)?;
            self.store
                .artifacts
                .get_mut(&id)
                .expect("artifact exists")
                .view_observed = true;
        }
        Ok(())
    }

    /// Makes `provisions` available and queues every artifact that waited only on one of them.
    fn release_waiters(
        &mut self,
        provisions: &[Dependency<H::Digest>],
        ready: &mut BTreeSet<ArtifactId<H::Digest>>,
    ) {
        for provision in provisions.iter().copied() {
            let Some(waiters) = self.dependencies.make_available(provision) else {
                continue;
            };
            for waiter in waiters {
                if matches!(
                    self.store.artifacts.get(&waiter).map(|entry| &entry.state),
                    Some(ArtifactState::Waiting(missing)) if *missing == provision
                ) {
                    ready.insert(waiter);
                }
            }
        }
    }

    fn discard_chain_artifacts(&mut self) -> Result<(), StepError> {
        for id in self.chain.da.take_discarded_certificates() {
            self.remove_terminal_artifact(id)?;
        }
        Ok(())
    }

    pub(super) fn restore_durable_artifacts(&mut self) -> Result<(), StepError> {
        // A block awaiting a data-availability vote is held by its signing reservation, not the
        // artifact cache.
        let mut artifacts = Vec::new();
        self.durable.state.visit_retained(|_, retained| {
            if !matches!(retained, Retained::DaVoteBlock(_)) {
                artifacts.push(retained.to_artifact());
            }
        });

        for artifact in artifacts {
            let id = self.validate_self_admission(&artifact, None)?;
            self.self_admit(artifact, id)?;
        }
        Ok(())
    }

    /// Checks that a locally constructed artifact may be self-admitted and returns its identifier.
    ///
    /// A completion that already derived the identifier and encoded length off-thread passes them
    /// as `derived`; otherwise both are computed here, after the cheap context and size checks.
    /// The admission cohort is checked as well, so the [`Self::self_admit`] that follows staging
    /// cannot fail.
    pub(super) fn validate_self_admission(
        &mut self,
        artifact: &Artifact<V, H::Digest>,
        derived: Option<DerivedIdentity<H::Digest>>,
    ) -> Result<ArtifactId<H::Digest>, StepError> {
        let encoded_len =
            derived.map_or_else(|| artifact.encoded_len(), |derived| derived.encoded_len);
        if artifact.epoch() != self.profile.protocol().epoch() {
            return Err(StepError::EffectMismatch);
        }
        if encoded_len > self.profile.resources().max_artifact_bytes() {
            return Err(StepError::LocalArtifactTooLarge);
        }
        let id = match derived {
            Some(derived) => derived.id,
            None => artifact.id_with_scratch::<H>(&mut self.store.id_scratch),
        };
        if let Some(existing) = self.store.artifacts.get(&id) {
            debug_assert!(
                existing.artifact.as_ref() == artifact,
                "two artifacts encode to one identifier"
            );
            return Ok(id);
        }
        // Live construction consumes capacity reserved before its work began, while recovery
        // reconstructs a snapshot already validated against the hard cache bound. The partition
        // governs work authorization; replacement and reconstruction use the physical ceiling.
        if self.store.artifacts.len() >= self.profile.resources().max_cached_artifacts() {
            return Err(StepError::LocalArtifactReservation);
        }
        if self.store.next_cohort.checked_add(1).is_none() {
            return Err(StepError::IdentifierExhausted);
        }
        Ok(id)
    }

    pub(super) fn self_admit(
        &mut self,
        artifact: Arc<Artifact<V, H::Digest>>,
        id: ArtifactId<H::Digest>,
    ) -> Result<(), StepError> {
        if let Some(existing) = self.store.artifacts.get(&id) {
            return self.self_admit_at(artifact, id, existing.observation, None);
        }
        let cohort = self.store.next_cohort;
        self.store.next_cohort = self
            .store
            .next_cohort
            .checked_add(1)
            .expect("local admission identifier was prevalidated");
        let observation = Observation::new(cohort, 0);
        self.self_admit_at(artifact, id, observation, None)
    }

    pub(super) fn self_admit_at(
        &mut self,
        artifact: Arc<Artifact<V, H::Digest>>,
        id: ArtifactId<H::Digest>,
        observation: Observation,
        validated: Option<ValidatedCertificate<V, H::Digest>>,
    ) -> Result<(), StepError> {
        let ValidatedParts {
            derivations,
            vqc: mut validated_vqc,
        } = validated.into();
        if let Some(existing) = self.store.artifacts.get(&id) {
            debug_assert!(
                existing.artifact.as_ref() == artifact.as_ref(),
                "two artifacts encode to one identifier"
            );
            let state = {
                let existing = self.store.artifacts.get_mut(&id).expect("artifact exists");
                let ready = matches!(existing.state, ArtifactState::Ready);
                if observation < existing.observation {
                    existing.observation = observation;
                    if ready && self.lifecycle == Lifecycle::Live {
                        self.views.observe::<H>(
                            id,
                            observation,
                            &artifact,
                            validated_vqc.take(),
                        )?;
                    }
                }
                existing.dependency_protected = true;
                existing.state.clone()
            };
            self.release_dependency_slot(id);
            let observation = self.store.artifacts[&id].observation;
            self.validate_finality(id, observation, &artifact, derivations)?;
            if matches!(state, ArtifactState::Ready | ArtifactState::Waiting(_)) {
                return Ok(());
            }
            return self.authenticate(id, validated_vqc);
        }
        let future = artifact
            .view()
            .is_some_and(|view| view > self.durable.state.view);
        self.claim_finality(id, observation, Arc::clone(&artifact))?;
        self.validate_finality(id, observation, &artifact, derivations)?;
        let provisions = Arc::<[_]>::from(artifact.provisions::<H>());
        self.dependencies.add_provider(id, &provisions);
        let position = self.floor_position(&artifact);
        self.retain_entry(
            id,
            ArtifactEntry {
                artifact,
                provisions,
                observation,
                state: ArtifactState::Dropped,
                dependency_protected: true,
                future,
                view_observed: false,
                dependency_slot: false,
            },
            position,
        );
        self.authenticate(id, validated_vqc)
    }

    /// Retains `entry` under `id`, taking a dependency-waiter slot when the entry holds one.
    pub(super) fn retain_entry(
        &mut self,
        id: ArtifactId<H::Digest>,
        entry: ArtifactEntry<V, H::Digest>,
        position: FloorPosition,
    ) {
        if entry.dependency_slot {
            self.dependencies.claim_slot();
        }
        self.store.insert(id, entry, position);
    }

    /// Removes the artifact retained under `id`, returning its dependency-waiter slot and
    /// dropping its waiter registration.
    pub(super) fn remove_entry(
        &mut self,
        id: ArtifactId<H::Digest>,
    ) -> Option<ArtifactEntry<V, H::Digest>> {
        let entry = self.store.remove(id)?;
        if entry.dependency_slot {
            self.dependencies.release_slot();
        }
        if let ArtifactState::Waiting(missing) = &entry.state {
            self.dependencies.remove_waiter(missing, &id);
        }
        Some(entry)
    }

    /// Returns the dependency-waiter slot the retained artifact `id` holds, if any.
    fn release_dependency_slot(&mut self, id: ArtifactId<H::Digest>) {
        let entry = self.store.artifacts.get_mut(&id).expect("artifact exists");
        if take(&mut entry.dependency_slot) {
            self.dependencies.release_slot();
        }
    }

    /// Parks the retained artifact `id` until `dependency` becomes available.
    fn wait_on(&mut self, id: ArtifactId<H::Digest>, dependency: Dependency<H::Digest>) {
        self.dependencies.add_waiter(dependency, id);
        self.store
            .artifacts
            .get_mut(&id)
            .expect("artifact exists")
            .state = ArtifactState::Waiting(dependency);
    }

    pub(super) fn needs_dependency_slot(&self, artifact: &Artifact<V, H::Digest>) -> bool {
        artifact
            .dependency()
            .is_some_and(|dependency| !self.dependencies.available.contains(&dependency))
    }
}
