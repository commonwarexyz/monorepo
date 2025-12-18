//! Consensus integration for the example chain.
//!
//! This module owns the glue between `commonware_consensus::simplex` (threshold-simplex) and the
//! application logic.
//!
//! Threshold-simplex orders opaque digests. Full blocks are disseminated by `commonware-consensus`
//! marshal (see `commonware_consensus::marshal`) and verified by the application.

use crate::types::{block_id, Block};
use commonware_cryptography::{ed25519, sha256, Hasher as _, Sha256};

pub type ConsensusDigest = sha256::Digest;
pub type PublicKey = ed25519::PublicKey;
pub type FinalizationEvent = (u32, ConsensusDigest);

/// Compute the digest ordered by threshold-simplex for a given block.
///
/// This example uses a two-step identifier:
/// - `BlockId = keccak256(Encode(Block))` (Ethereum-ish block id)
/// - `ConsensusDigest = sha256(BlockId)` (ordered by consensus)
pub(crate) fn digest_for_block(block: &Block) -> ConsensusDigest {
    let mut hasher = Sha256::default();
    let id = block_id(block);
    hasher.update(id.0.as_slice());
    hasher.finalize()
}
