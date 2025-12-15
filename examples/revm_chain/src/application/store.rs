//! In-memory chain storage for the example.
//!
//! This store is intentionally simple:
//! - It keeps verified blocks keyed by the digest that consensus orders.
//! - It also stores an `InMemoryDB` snapshot per digest so validators can deterministically
//!   re-execute proposals on the correct parent state.
//!
//! This is not intended to be a production storage layer.

use crate::{
    consensus::ConsensusDigest,
    types::{Block, BlockId},
};
use alloy_evm::revm::{database::InMemoryDB, primitives::B256};
use std::collections::BTreeMap;

/// Verified block and its post-execution EVM state snapshot.
#[derive(Clone, Debug)]
pub(super) struct BlockEntry {
    pub(super) block: Block,
    pub(super) db: InMemoryDB,
    /// Seed hash tracked from consensus activity (notarization/finalization).
    pub(super) seed: Option<B256>,
}

/// Per-node in-memory store for verified blocks.
#[derive(Clone, Debug, Default)]
pub(super) struct ChainStore {
    by_digest: BTreeMap<ConsensusDigest, BlockEntry>,
    // Reserved for convenience in future extensions (not used by the current example).
    by_id: BTreeMap<BlockId, ConsensusDigest>,
}

impl ChainStore {
    pub(super) fn insert(&mut self, digest: ConsensusDigest, entry: BlockEntry) {
        self.by_id.insert(entry.block.id(), digest);
        self.by_digest.insert(digest, entry);
    }

    pub(super) fn get_by_digest(&self, digest: &ConsensusDigest) -> Option<&BlockEntry> {
        self.by_digest.get(digest)
    }

    pub(super) fn get_by_id(&self, id: &BlockId) -> Option<&BlockEntry> {
        self.by_id
            .get(id)
            .and_then(|digest| self.by_digest.get(digest))
    }

    pub(super) fn get_by_digest_mut(
        &mut self,
        digest: &ConsensusDigest,
    ) -> Option<&mut BlockEntry> {
        self.by_digest.get_mut(digest)
    }
}
