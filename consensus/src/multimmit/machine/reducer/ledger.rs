//! Durable state and the reference ledgers derived from it.

use crate::multimmit::{
    machine::durability::{DurableState, EffectId},
    types::ArtifactId,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::collections::BTreeMap;

/// Applied durable state with the artifact references and signing reservations it holds.
///
/// The ledgers are derived from the state and kept in step with every applied transition, so
/// occupancy checks read them instead of re-deriving references from the state.
pub(crate) struct DurableLedger<V: Variant, D: Digest> {
    /// The durable state as of the newest staged event.
    pub(in crate::multimmit::machine) state: DurableState<V, D>,
    /// Durable references held per artifact.
    pub(in crate::multimmit::machine) artifact_references: BTreeMap<ArtifactId<D>, usize>,
    /// Artifact identifiers carried by every live outbox effect.
    ///
    /// An identifier hashes the full encoded artifact, so each effect's set is computed once at
    /// admission and reused for release and occupancy accounting instead of re-hashing multi-
    /// kilobyte certificates on every durable transition.
    pub(in crate::multimmit::machine) effect_ids: BTreeMap<EffectId, Vec<ArtifactId<D>>>,
    /// Artifacts the durable signing reservations promise.
    pub(in crate::multimmit::machine) signing_reservations: usize,
}

impl<V: Variant, D: Digest> DurableLedger<V, D> {
    pub(super) const fn new(state: DurableState<V, D>) -> Self {
        Self {
            state,
            artifact_references: BTreeMap::new(),
            effect_ids: BTreeMap::new(),
            signing_reservations: 0,
        }
    }
}
