use crate::types::{Block, BlockId};
use alloy_evm::revm::database::InMemoryDB;
use std::collections::BTreeMap;

use crate::consensus::ConsensusDigest;

#[derive(Clone, Debug)]
pub(super) struct BlockEntry {
    pub(super) block: Block,
    pub(super) db: InMemoryDB,
}

#[derive(Clone, Debug, Default)]
pub(super) struct ChainStore {
    by_digest: BTreeMap<ConsensusDigest, BlockEntry>,
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
}
