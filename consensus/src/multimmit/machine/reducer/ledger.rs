//! Applied durable state and the artifact references it holds.

use crate::multimmit::{
    machine::durability::{DurableState, EffectId, ReplayError, TransitionReason},
    types::ArtifactId,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::collections::BTreeMap;

/// Durable state as of the newest staged event, with the artifact references it holds.
///
/// The references are derived from the state and kept in step with every applied transition, so
/// occupancy checks never re-hash the retained artifacts. An identifier hashes a full encoding, so
/// each outstanding effect's identifiers are computed once, when it is queued.
pub(crate) struct DurableLedger<V: Variant, D: Digest> {
    /// The durable state.
    pub(in crate::multimmit::machine) state: DurableState<V, D>,
    /// Durable references held per artifact.
    references: BTreeMap<ArtifactId<D>, usize>,
    /// The artifact identifiers each outstanding effect retains.
    effect_ids: BTreeMap<EffectId, Vec<ArtifactId<D>>>,
}

impl<V: Variant, D: Digest> DurableLedger<V, D> {
    /// Derives the ledger of `state`.
    pub(super) fn new<H: Hasher<Digest = D>>(state: DurableState<V, D>) -> Self {
        let references = state.artifact_references::<H>();
        let mut effect_ids = BTreeMap::new();
        for (id, effect) in &state.signing_reservations {
            let mut ids = Vec::new();
            effect.visit_retained(|retained| ids.push(retained.id::<H>()));
            effect_ids.insert(*id, ids);
        }
        for (id, entry) in &state.outbox {
            let mut ids = Vec::new();
            entry
                .publication()
                .visit_retained(|retained| ids.push(retained.id::<H>()));
            effect_ids.insert(*id, ids);
        }
        Self {
            state,
            references,
            effect_ids,
        }
    }

    /// Returns the artifact cache slots durable state occupies: one per referenced artifact plus
    /// one per signing result a reservation promises.
    pub(crate) fn occupancy(&self) -> usize {
        self.references.len() + self.state.signing_reservations()
    }

    /// Returns the occupancy after references to `added` are taken, references to `released`
    /// are dropped, and the promised signing results change by the given counts.
    pub(crate) fn occupancy_after(
        &self,
        added: &[ArtifactId<D>],
        released: &[ArtifactId<D>],
        reservations_added: usize,
        reservations_released: usize,
    ) -> Option<usize> {
        let mut delta = BTreeMap::<ArtifactId<D>, isize>::new();
        for id in added {
            *delta.entry(*id).or_default() += 1;
        }
        for id in released {
            *delta.entry(*id).or_default() -= 1;
        }
        let mut artifacts = self.references.len();
        for (id, change) in delta {
            let before = self.references.get(&id).copied().unwrap_or(0);
            let after = before.checked_add_signed(change)?;
            match (before == 0, after == 0) {
                (true, false) => artifacts = artifacts.checked_add(1)?,
                (false, true) => artifacts = artifacts.checked_sub(1)?,
                _ => {}
            }
        }
        artifacts
            .checked_add(self.state.signing_reservations())?
            .checked_add(reservations_added)?
            .checked_sub(reservations_released)
    }

    /// Returns the identifiers the outstanding effect `id` retains.
    pub(crate) fn effect_ids(&self, id: &EffectId) -> Option<&[ArtifactId<D>]> {
        self.effect_ids.get(id).map(Vec::as_slice)
    }

    /// Returns whether durable state references `id`.
    pub(crate) fn references(&self, id: &ArtifactId<D>) -> bool {
        self.references.contains_key(id)
    }

    /// Takes one durable reference to `id`.
    pub(crate) fn retain(&mut self, id: ArtifactId<D>) -> Result<(), ReplayError> {
        let references = self.references.entry(id).or_default();
        *references = references
            .checked_add(1)
            .ok_or(ReplayError::Transition(TransitionReason::References))?;
        Ok(())
    }

    /// Drops one durable reference to `id`.
    pub(crate) fn release(&mut self, id: ArtifactId<D>) -> Result<(), ReplayError> {
        let references = self
            .references
            .get_mut(&id)
            .and_then(|references| references.checked_sub(1).map(|left| (references, left)));
        let Some((references, left)) = references else {
            return Err(ReplayError::Transition(TransitionReason::References));
        };
        *references = left;
        if left == 0 {
            self.references.remove(&id);
        }
        Ok(())
    }

    /// Takes the references of the newly queued effect `id`, which retains `ids`.
    pub(crate) fn admit_effect(
        &mut self,
        id: EffectId,
        ids: Vec<ArtifactId<D>>,
    ) -> Result<(), ReplayError> {
        for artifact in &ids {
            self.retain(*artifact)?;
        }
        self.effect_ids.insert(id, ids);
        Ok(())
    }

    /// Drops the references of the retired effect `id`.
    pub(crate) fn release_effect(&mut self, id: EffectId) -> Result<(), ReplayError> {
        let ids = self
            .effect_ids
            .remove(&id)
            .ok_or(ReplayError::Transition(TransitionReason::References))?;
        for artifact in ids {
            self.release(artifact)?;
        }
        Ok(())
    }
}
