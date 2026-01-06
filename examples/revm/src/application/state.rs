//! Node-local state for the REVM chain example.
//!
//! Threshold-simplex orders only block digests. Full blocks are verified by the application and
//! disseminated/backfilled by `commonware_consensus::marshal`. This module holds the minimal
//! shared state needed by the example:
//! - a mempool of submitted transactions,
//! - per-block execution snapshots (CacheDB overlay over QMDB) keyed by the consensus digest, and
//! - a per-digest seed hash used to populate the next block's `prevrandao`.
//!
//! The simulation harness queries this state through `crate::application::NodeHandle`.

use crate::{
    qmdb::{QmdbChanges, QmdbConfig, QmdbState, RevmDb},
    types::{Block, StateRoot, Tx, TxId},
    ConsensusDigest,
};
use alloy_evm::revm::{primitives::{Address, B256, U256}, Database as _};
use commonware_cryptography::Committable as _;
use commonware_runtime::{buffer::PoolRef, tokio};
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
    qmdb: QmdbState,
    persisted: BTreeSet<ConsensusDigest>,
}

#[derive(Clone)]
pub(crate) struct ExecutionSnapshot {
    pub(crate) db: RevmDb,
    pub(crate) state_root: StateRoot,
    pub(crate) qmdb_changes: QmdbChanges,
}

impl Shared {
    pub(crate) async fn init(
        context: tokio::Context,
        buffer_pool: PoolRef,
        partition_prefix: String,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> anyhow::Result<Self> {
        let genesis_block = Block {
            parent: crate::BlockId(B256::ZERO),
            height: 0,
            prevrandao: B256::ZERO,
            state_root: StateRoot(B256::ZERO),
            txs: Vec::new(),
        };
        let genesis_digest = genesis_block.commitment();

        let qmdb = QmdbState::init(
            context.with_label("qmdb"),
            QmdbConfig::new(partition_prefix, buffer_pool),
            genesis_alloc,
        )
        .await?;
        let db = RevmDb::new(qmdb.database()?);

        let mut snapshots = BTreeMap::new();
        snapshots.insert(
            genesis_digest,
            ExecutionSnapshot {
                db,
                state_root: genesis_block.state_root,
                qmdb_changes: QmdbChanges::default(),
            },
        );

        let mut seeds = BTreeMap::new();
        seeds.insert(genesis_digest, B256::ZERO);

        Ok(Self {
            inner: Arc::new(Mutex::new(State {
                mempool: BTreeMap::new(),
                snapshots,
                seeds,
                qmdb,
                persisted: BTreeSet::new(),
            })),
            genesis_block,
        })
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
        db: RevmDb,
        root: StateRoot,
        qmdb_changes: QmdbChanges,
    ) {
        let mut inner = self.inner.lock().await;
        inner.snapshots.insert(
            digest,
            ExecutionSnapshot {
                db,
                state_root: root,
                qmdb_changes,
            },
        );
    }

    pub(crate) async fn persist_snapshot(&self, digest: ConsensusDigest) -> anyhow::Result<()> {
        let (qmdb, changes, already_persisted) = {
            let inner = self.inner.lock().await;
            let already = inner.persisted.contains(&digest);
            let snapshot = inner
                .snapshots
                .get(&digest)
                .ok_or_else(|| anyhow::anyhow!("missing snapshot for digest"))?;
            (
                inner.qmdb.clone(),
                snapshot.qmdb_changes.clone(),
                already,
            )
        };

        if already_persisted {
            return Ok(());
        }

        qmdb.apply_changes(&changes).await?;

        let mut inner = self.inner.lock().await;
        inner.persisted.insert(digest);
        Ok(())
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
