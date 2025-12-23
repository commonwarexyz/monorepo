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
    types::{Block, StateRoot, Tx, TxId},
    ConsensusDigest,
};
use alloy_evm::revm::{
    database::InMemoryDB,
    primitives::{Address, B256, U256},
    state::AccountInfo,
    Database as _,
};
use commonware_cryptography::Committable as _;
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
    snapshots: BTreeMap<ConsensusDigest, ExecutionSnapshot>,
    seeds: BTreeMap<ConsensusDigest, B256>,
}

#[derive(Clone)]
pub(crate) struct ExecutionSnapshot {
    pub(crate) db: InMemoryDB,
    pub(crate) state_root: StateRoot,
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
        let genesis_digest = genesis_block.commitment();

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

        let mut snapshots = BTreeMap::new();
        snapshots.insert(
            genesis_digest,
            ExecutionSnapshot {
                db,
                state_root: genesis_block.state_root,
            },
        );

        let mut seeds = BTreeMap::new();
        seeds.insert(genesis_digest, B256::ZERO);

        Self {
            inner: Arc::new(Mutex::new(State {
                mempool: BTreeMap::new(),
                snapshots,
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
            .snapshots
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
            .snapshots
            .get(&digest)
            .map(|snapshot| snapshot.state_root)
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

    pub(crate) async fn parent_snapshot(
        &self,
        parent: &ConsensusDigest,
    ) -> Option<ExecutionSnapshot> {
        let inner = self.inner.lock().await;
        inner.snapshots.get(parent).cloned()
    }

    pub(crate) async fn insert_snapshot(
        &self,
        digest: ConsensusDigest,
        db: InMemoryDB,
        root: StateRoot,
    ) {
        let mut inner = self.inner.lock().await;
        inner.snapshots.insert(
            digest,
            ExecutionSnapshot {
                db,
                state_root: root,
            },
        );
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
