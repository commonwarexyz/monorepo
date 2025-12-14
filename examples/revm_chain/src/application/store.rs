use crate::{
    consensus::ConsensusDigest,
    types::{Block, BlockId},
};
use alloy_evm::revm::{database::InMemoryDB, primitives::B256};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub(super) struct BlockEntry {
    pub(super) block: Block,
    pub(super) db: InMemoryDB,
    pub(super) seed: Option<B256>,
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

    pub(super) fn get_by_digest_mut(
        &mut self,
        digest: &ConsensusDigest,
    ) -> Option<&mut BlockEntry> {
        self.by_digest.get_mut(digest)
    }
}
