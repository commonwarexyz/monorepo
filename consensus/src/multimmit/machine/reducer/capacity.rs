//! Artifact, reservation, and outbox occupancy checks.

use super::machine::Machine;
use crate::{
    Viewable,
    multimmit::{
        machine::{
            durability::{DurableEffect, EffectId, Publication},
            input::StepError,
        },
        types::{Artifact, ArtifactId},
    },
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::BTreeMap, sync::Arc};

/// Per-artifact durable reference changes: references released and references added.
type ReferenceChanges<D> = BTreeMap<ArtifactId<D>, (usize, usize)>;

/// The durable artifact-cache footprint: the artifacts durable state references and the signing
/// reservations that each promise one more.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct Occupancy {
    artifacts: usize,
    reservations: usize,
}

impl Occupancy {
    /// Returns the slots the footprint occupies.
    const fn total(self) -> Option<usize> {
        self.artifacts.checked_add(self.reservations)
    }

    /// Returns the footprint after `changes` to per-artifact reference counts, where `held`
    /// reports an artifact's current count, and after releasing and adding signing reservations.
    fn after<D: Digest>(
        self,
        changes: ReferenceChanges<D>,
        held: impl Fn(&ArtifactId<D>) -> usize,
        released_reservations: usize,
        added_reservations: usize,
    ) -> Option<Self> {
        let mut artifacts = self.artifacts;
        for (id, (released, added)) in changes {
            let before = held(&id);
            let after = before.checked_sub(released)?.checked_add(added)?;
            match (before == 0, after == 0) {
                (true, false) => artifacts = artifacts.checked_add(1)?,
                (false, true) => artifacts = artifacts.checked_sub(1)?,
                _ => {}
            }
        }
        let reservations = self
            .reservations
            .checked_sub(released_reservations)?
            .checked_add(added_reservations)?;
        Some(Self {
            artifacts,
            reservations,
        })
    }
}

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns whether `effect` fits every capacity bound once the effects `retired` release their
    /// references and `consumed_build_credits` volatile build reservations turn into it.
    ///
    /// Capacity pressure reports `false`; any other rejection is an error.
    pub(super) fn effect_fits(
        &self,
        effect: &DurableEffect<V, H::Digest>,
        consumed_build_credits: usize,
        retired: &[EffectId],
    ) -> Result<bool, StepError> {
        match self.check_effect_capacity(effect, consumed_build_credits, retired) {
            Ok(()) => Ok(true),
            Err(StepError::OutboxFull | StepError::LocalArtifactReservation) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Checks that `effect` fits every capacity bound once the effects `retired` release their
    /// references and `consumed_build_credits` volatile build reservations turn into it.
    pub(super) fn check_effect_capacity(
        &self,
        effect: &DurableEffect<V, H::Digest>,
        consumed_build_credits: usize,
        retired: &[EffectId],
    ) -> Result<(), StepError> {
        self.ensure_live()?;
        let promised = self
            .pending_artifact_reservations()
            .checked_sub(consumed_build_credits)
            .filter(|_| consumed_build_credits <= self.chain.build_reservations())
            .ok_or(StepError::LocalArtifactReservation)?;
        let effects = self
            .durable_effect_count()
            .checked_sub(retired.len())
            .ok_or(StepError::OutboxFull)?;
        if effects + promised >= self.profile.resources().max_outbox_effects() {
            return Err(StepError::OutboxFull);
        }
        if !effect.authorized::<H>(&self.profile) {
            return Err(StepError::UnauthorizedEffect);
        }
        let artifact_capacity = self.effect_artifact_capacity(effect);
        let reservations = effect.reservations();
        if self.store.artifacts.len() + self.local_artifact_reservations() + reservations
            - consumed_build_credits
            > artifact_capacity
        {
            return Err(StepError::LocalArtifactReservation);
        }
        let mut added = Vec::new();
        effect.visit_references::<H>(|id| added.push(id));
        let occupancy = if retired.is_empty() {
            self.durable_occupancy_after(&added, 0, reservations)
        } else {
            self.durable_occupancy_after_retiring(&added, reservations, retired)
        };
        if occupancy
            .and_then(|occupancy| occupancy.checked_add(promised))
            .is_none_or(|occupancy| occupancy > artifact_capacity)
        {
            return Err(StepError::LocalArtifactReservation);
        }
        Ok(())
    }

    fn effect_artifact_capacity(&self, effect: &DurableEffect<V, H::Digest>) -> usize {
        let resources = self.profile.resources();
        match effect {
            DurableEffect::Publish(Publication::Broadcast(artifacts)) if matches!(artifacts.as_ref(), [artifact] if artifact.self_certifying_view()) => {
                resources.max_cached_artifacts()
            }
            _ => resources.local_artifact_capacity(),
        }
    }

    /// Returns durable occupancy after retiring `retired` and adding one effect's `added`
    /// references and `added_reservations` signing reservations.
    pub(crate) fn durable_occupancy_after_retiring(
        &self,
        added: &[ArtifactId<H::Digest>],
        added_reservations: usize,
        retired: &[EffectId],
    ) -> Option<usize> {
        let (mut changes, released_reservations) = self.released_effect_references(retired)?;
        for artifact in added {
            let added = &mut changes.entry(*artifact).or_default().1;
            *added = added.checked_add(1)?;
        }
        self.occupancy_after(changes, released_reservations, added_reservations)
    }

    pub(super) fn can_reserve_build_credit(&self) -> bool {
        let capacity = self.profile.resources().local_artifact_capacity();
        self.durable_effect_count() + self.pending_artifact_reservations()
            < self.profile.resources().max_outbox_effects()
            && self.store.artifacts.len() + self.local_artifact_reservations() < capacity
            && self
                .promised_durable_occupancy()
                .is_some_and(|occupancy| occupancy < capacity)
    }

    pub(super) fn view_proof_slots(&self) -> usize {
        self.view_proof_artifact_slots()
            .min(self.certificate_outbox_slots())
    }

    /// Returns how many locally created certificates fit the artifact bounds.
    pub(super) fn certificate_artifact_slots(&self) -> usize {
        self.artifact_slots(self.profile.resources().local_artifact_capacity())
    }

    /// Returns how many view proofs fit the artifact bounds, which reach the whole cache.
    pub(super) fn view_proof_artifact_slots(&self) -> usize {
        self.artifact_slots(self.profile.resources().max_cached_artifacts())
    }

    /// Returns how many more local artifacts fit `capacity` in both the volatile cache and the
    /// promised durable occupancy.
    fn artifact_slots(&self, capacity: usize) -> usize {
        let volatile = capacity
            .saturating_sub(self.store.artifacts.len() + self.local_artifact_reservations());
        let durable = self
            .promised_durable_occupancy()
            .map_or(0, |occupancy| capacity.saturating_sub(occupancy));
        volatile.min(durable)
    }

    pub(super) fn certificate_outbox_slots(&self) -> usize {
        self.profile
            .resources()
            .max_outbox_effects()
            .saturating_sub(self.durable_effect_count() + self.pending_artifact_reservations())
    }

    pub(crate) fn durable_effect_count(&self) -> usize {
        self.durable.state.effect_count()
    }

    /// Returns an owned copy of the outstanding effect `id`, sharing its payload.
    pub(super) fn durable_effect(&self, id: EffectId) -> Option<DurableEffect<V, H::Digest>> {
        self.durable
            .state
            .signing(&id)
            .cloned()
            .map(DurableEffect::Sign)
            .or_else(|| {
                self.durable
                    .state
                    .publication(&id)
                    .cloned()
                    .map(DurableEffect::Publish)
            })
    }

    pub(crate) fn contains_durable_effect(&self, id: EffectId) -> bool {
        self.durable.state.contains_effect(&id)
    }

    /// Returns the artifacts local work has promised but not yet created: durable signing
    /// reservations plus the volatile ones.
    pub(crate) fn local_artifact_reservations(&self) -> usize {
        self.durable.signing_reservations + self.pending_artifact_reservations()
    }

    /// Returns the artifacts volatile local work has promised: builds, view certificates and
    /// L-QC aggregations in flight.
    fn pending_artifact_reservations(&self) -> usize {
        self.chain.build_reservations()
            + self.views.certificate_reservations()
            + self.finality.aggregate_reservations()
    }

    /// Returns the durable footprint.
    fn durable_occupancy(&self) -> Occupancy {
        Occupancy {
            artifacts: self.durable.artifact_references.len(),
            reservations: self.durable.signing_reservations,
        }
    }

    /// Returns the durable footprint plus the artifacts volatile local work has promised.
    fn promised_durable_occupancy(&self) -> Option<usize> {
        self.durable_occupancy()
            .total()?
            .checked_add(self.pending_artifact_reservations())
    }

    /// Returns durable occupancy after adding references to `artifacts` and changing the signing
    /// reservations.
    pub(crate) fn durable_occupancy_after(
        &self,
        artifacts: &[ArtifactId<H::Digest>],
        released_reservations: usize,
        added_reservations: usize,
    ) -> Option<usize> {
        let current = self.durable_occupancy();
        // Effects carry at most one DA-vote run, so counting the distinct newcomers against the
        // slice itself stays cheaper than building a set for a handful of identifiers.
        let mut added = 0usize;
        for (index, id) in artifacts.iter().enumerate() {
            if self.durable.artifact_references.contains_key(id) || artifacts[..index].contains(id)
            {
                continue;
            }
            added = added.checked_add(1)?;
        }
        Occupancy {
            artifacts: current.artifacts.checked_add(added)?,
            reservations: current
                .reservations
                .checked_sub(released_reservations)?
                .checked_add(added_reservations)?,
        }
        .total()
    }

    pub(crate) fn finality_floor_occupancy(
        &self,
        retired: &[EffectId],
        proof: ArtifactId<H::Digest>,
        proposal_anchor: Option<ArtifactId<H::Digest>>,
    ) -> Option<usize> {
        let (mut changes, released_reservations) = self.released_effect_references(retired)?;
        if let Some(previous) = self.durable.state.signing_floor.as_ref() {
            changes.entry(previous.id::<H>()).or_default().0 += 1;
        }
        changes.entry(proof).or_default().1 += 1;
        if let Some(anchor) = proposal_anchor {
            if let Some(previous) = self.durable.state.proposal_anchor.as_ref() {
                changes.entry(previous.id::<H>()).or_default().0 += 1;
            }
            changes.entry(anchor).or_default().1 += 1;
        }

        self.occupancy_after(changes, released_reservations, 0)
    }

    /// Returns whether a finality floor raised to `proof` fits the artifact cache once it retires
    /// `retired_signing`.
    pub(super) fn finality_floor_fits(
        &self,
        proof: &Arc<Artifact<V, H::Digest>>,
        retired_signing: &[EffectId],
    ) -> Result<bool, StepError> {
        let Artifact::Lqc(certificate) = proof.as_ref() else {
            return Err(StepError::ViewInvariant);
        };
        let anchor = self
            .finality
            .finality_anchor(proof)
            .ok_or(StepError::ViewInvariant)?;
        let proposal_anchor = (certificate.view() >= self.durable.state.proposal_anchor_view())
            .then_some(anchor.artifact_id);
        let occupancy = self
            .finality_floor_occupancy(retired_signing, proof.id::<H>(), proposal_anchor)
            .and_then(|occupancy| occupancy.checked_add(self.pending_artifact_reservations()));

        Ok(occupancy
            .is_some_and(|occupancy| occupancy <= self.profile.resources().max_cached_artifacts()))
    }

    fn released_effect_references(
        &self,
        retired: &[EffectId],
    ) -> Option<(ReferenceChanges<H::Digest>, usize)> {
        let mut changes = ReferenceChanges::new();
        let mut reservations = 0usize;
        for id in retired {
            let effect = self.durable_effect(*id)?;
            match self.durable.effect_ids.get(id) {
                Some(ids) => {
                    for artifact in ids.iter().copied() {
                        changes.entry(artifact).or_default().0 += 1;
                    }
                }
                None => effect.visit_references::<H>(|artifact| {
                    changes.entry(artifact).or_default().0 += 1;
                }),
            }
            reservations = reservations.checked_add(effect.reservations())?;
        }
        Some((changes, reservations))
    }

    /// Returns the durable occupancy after `changes` to reference counts and the given changes to
    /// signing reservations.
    fn occupancy_after(
        &self,
        changes: ReferenceChanges<H::Digest>,
        released_reservations: usize,
        added_reservations: usize,
    ) -> Option<usize> {
        self.durable_occupancy()
            .after(
                changes,
                |id| {
                    self.durable
                        .artifact_references
                        .get(id)
                        .copied()
                        .unwrap_or(0)
                },
                released_reservations,
                added_reservations,
            )?
            .total()
    }
}
