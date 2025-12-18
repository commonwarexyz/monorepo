//! Node-local state for the REVM chain example.
//!
//! Threshold-simplex orders only block digests. Full blocks are verified by the application and
//! disseminated/backfilled by `commonware_consensus::marshal`. This module holds the minimal
//! shared state needed by the example:
//! - a mempool of submitted transactions,
//! - per-block execution snapshots (`InMemoryDB`) keyed by the consensus digest, and
//! - a per-digest seed hash used to populate the next block's `prevrandao`.
//!
//! The deterministic simulation queries this state through `crate::application::NodeHandle`.

use crate::{
    consensus::{digest_for_block, ConsensusDigest},
    types::{Block, StateRoot, Tx, TxId},
};
use alloy_evm::revm::{
    database::InMemoryDB,
    primitives::{Address, B256, U256},
    state::AccountInfo,
    Database as _,
};
use futures::lock::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Clone)]
pub(crate) struct Shared {
    inner: Arc<Mutex<State>>,
    genesis_block: Block,
}

struct State {
    mempool: BTreeMap<TxId, Tx>,
    blocks: BTreeMap<ConsensusDigest, BlockState>,
    seeds: BTreeMap<ConsensusDigest, B256>,
}

#[derive(Clone)]
pub(crate) struct BlockState {
    pub(crate) block: Block,
    pub(crate) db: InMemoryDB,
}

impl Shared {
    pub(crate) fn new(genesis_alloc: Vec<(Address, U256)>) -> Self {
        let genesis_block = Block {
            parent: crate::BlockId(B256::ZERO),
            height: 0,
            prevrandao: B256::ZERO,
            state_root: StateRoot(B256::ZERO),
            txs: Vec::new(),
        };
        let genesis_digest = digest_for_block(&genesis_block);

        let mut db = InMemoryDB::default();
        for (address, balance) in genesis_alloc {
            db.insert_account_info(
                address,
                AccountInfo {
                    balance,
                    nonce: 0,
                    ..Default::default()
                },
            );
        }

        let mut blocks = BTreeMap::new();
        blocks.insert(
            genesis_digest,
            BlockState {
                block: genesis_block.clone(),
                db,
            },
        );

        let mut seeds = BTreeMap::new();
        seeds.insert(genesis_digest, B256::ZERO);

        Self {
            inner: Arc::new(Mutex::new(State {
                mempool: BTreeMap::new(),
                blocks,
                seeds,
            })),
            genesis_block,
        }
    }

    pub(crate) fn genesis_block(&self) -> Block {
        self.genesis_block.clone()
    }

    pub(crate) async fn submit_tx(&self, tx: Tx) -> bool {
        let mut inner = self.inner.lock().await;
        inner.mempool.insert(tx.id(), tx).is_none()
    }

    pub(crate) async fn query_balance(
        &self,
        digest: ConsensusDigest,
        address: Address,
    ) -> Option<U256> {
        let mut inner = self.inner.lock().await;
        inner
            .blocks
            .get_mut(&digest)?
            .db
            .basic(address)
            .ok()
            .flatten()
            .map(|info| info.balance)
    }

    pub(crate) async fn query_state_root(&self, digest: ConsensusDigest) -> Option<StateRoot> {
        let inner = self.inner.lock().await;
        inner
            .blocks
            .get(&digest)
            .map(|state| state.block.state_root)
    }

    pub(crate) async fn query_seed(&self, digest: ConsensusDigest) -> Option<B256> {
        let inner = self.inner.lock().await;
        inner.seeds.get(&digest).copied()
    }

    pub(crate) async fn seed_for_parent(&self, parent: &ConsensusDigest) -> Option<B256> {
        let inner = self.inner.lock().await;
        inner.seeds.get(parent).copied()
    }

    pub(crate) async fn set_seed(&self, digest: ConsensusDigest, seed_hash: B256) {
        let mut inner = self.inner.lock().await;
        inner.seeds.insert(digest, seed_hash);
    }

    pub(crate) async fn parent_state(&self, parent: &ConsensusDigest) -> Option<BlockState> {
        let inner = self.inner.lock().await;
        inner.blocks.get(parent).cloned()
    }

    pub(crate) async fn insert_verified(
        &self,
        digest: ConsensusDigest,
        block: Block,
        db: InMemoryDB,
    ) {
        let mut inner = self.inner.lock().await;
        inner.blocks.insert(digest, BlockState { block, db });
    }

    pub(crate) async fn prune_mempool(&self, txs: &[Tx]) {
        let mut inner = self.inner.lock().await;
        for tx in txs {
            inner.mempool.remove(&tx.id());
        }
    }

    pub(crate) async fn build_txs(&self, max_txs: usize, excluded: &BTreeSet<TxId>) -> Vec<Tx> {
        let inner = self.inner.lock().await;
        inner
            .mempool
            .iter()
            .filter(|(tx_id, _)| !excluded.contains(tx_id))
            .take(max_txs)
            .map(|(_, tx)| tx.clone())
            .collect()
    }
}
