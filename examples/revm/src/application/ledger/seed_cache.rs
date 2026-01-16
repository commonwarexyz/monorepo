use crate::ConsensusDigest;
use alloy_evm::revm::primitives::B256;
use std::collections::BTreeMap;

#[derive(Clone)]
pub(crate) struct SeedCache(BTreeMap<ConsensusDigest, B256>);

impl SeedCache {
    pub(crate) fn new(genesis_digest: ConsensusDigest) -> Self {
        let mut seeds = BTreeMap::new();
        seeds.insert(genesis_digest, B256::ZERO);
        Self(seeds)
    }

    pub(crate) fn get(&self, digest: &ConsensusDigest) -> Option<B256> {
        self.0.get(digest).copied()
    }

    pub(crate) fn insert(&mut self, digest: ConsensusDigest, seed: B256) {
        self.0.insert(digest, seed);
    }
}
