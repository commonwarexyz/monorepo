//! Non-authoritative telemetry emitted by the Multimmit machine.

use crate::{
    multimmit::{
        machine::{Artifact, ArtifactId, FinalityFact},
        types::{BlockRef, TipRecord},
    },
    types::View,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// A local proposal, contextually admitted artifact, or consensus finality observation.
///
/// Activities are idempotent, best-effort observations. They do not acknowledge delivery,
/// authorize protocol progress, or control retention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activity<V: Variant, D: Digest> {
    /// A local transaction block has been signed, before its publication is persisted.
    ///
    /// This is not evidence of dissemination or finality. Retries may report the same block.
    TransactionProposed {
        /// Exact identity of the signed producer block.
        block: BlockRef<D>,
    },
    /// A leader obtained its first direct finality quorum.
    LeaderFinalized {
        /// Exact producer-chain tips supported by the first direct finality quorum.
        fact: FinalityFact<D>,
    },
    /// An already-finalized leader's direct finality projection advanced.
    LeaderFinalityUpdated {
        /// Exact producer-chain tips supported by the updated direct finality pool.
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
