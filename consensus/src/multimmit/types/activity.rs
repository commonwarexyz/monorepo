//! Non-authoritative telemetry emitted by the Multimmit machine.

use crate::{
    multimmit::{
        machine::{Artifact, ArtifactId, FinalityFact},
        types::TipRecord,
    },
    types::View,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// A contextually admitted or durably committed Multimmit fact.
///
/// Activities are idempotent, best-effort observations. They do not acknowledge delivery,
/// authorize protocol progress, or control retention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activity<V: Variant, D: Digest> {
    /// A leader obtained its first direct finality quorum.
    LeaderFinalized {
        /// Exact producer-chain tips included by the finalized leader.
        fact: FinalityFact<D>,
    },
    /// An authenticated artifact entered the machine's contextually ready set.
    ProtocolAccepted {
        /// Stable identifier for the exact canonical artifact.
        artifact_id: ArtifactId<D>,
        /// Exact admitted artifact.
        artifact: Arc<Artifact<V, D>>,
    },
    /// An authenticated leader exposed its exact safe-tip history opening for peer seeding.
    HistoryAccepted {
        /// View of the leader that committed the opening.
        view: View,
        /// Commitment carried by the leader.
        commitment: D,
        /// Exact opening reconstructed from the retained parent state.
        record: Arc<TipRecord<D>>,
    },
}
