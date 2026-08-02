//! Non-authoritative telemetry emitted by the Multimmit machine.

use crate::multimmit::machine::{Artifact, ArtifactId};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::sync::Arc;

/// A contextually admitted or durably committed Multimmit fact.
///
/// Activities are idempotent telemetry. They do not acknowledge delivery, authorize protocol
/// progress, or control retention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activity<V: Variant, D: Digest> {
    /// An authenticated artifact entered the machine's contextually ready set.
    ProtocolAccepted {
        /// Stable identifier for the exact canonical artifact.
        artifact_id: ArtifactId<D>,
        /// Exact admitted artifact.
        artifact: Arc<Artifact<V, D>>,
    },
}
