//! Consensus integration for the example chain.
//!
//! This module owns the glue between `commonware_consensus::simplex` (threshold-simplex) and the
//! application logic. The consensus engine orders opaque digests; the application is responsible
//! for producing/verifying blocks and providing out-of-band block broadcast/fetch.

mod ingress;

use crate::types::{block_id, Block};
use commonware_cryptography::{ed25519, sha256, Hasher as _, Sha256};
pub use ingress::{ConsensusRequest, Mailbox};

pub type ConsensusDigest = sha256::Digest;
pub type PublicKey = ed25519::PublicKey;
pub type FinalizationEvent = (u32, ConsensusDigest);

pub(crate) fn digest_for_block(block: &Block) -> ConsensusDigest {
    let mut hasher = Sha256::default();
    let id = block_id(block);
    hasher.update(id.0.as_slice());
    hasher.finalize()
}
