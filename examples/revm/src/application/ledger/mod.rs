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

mod mempool;
mod seed_cache;
mod snapshot_store;

use crate::{
    domain::{Block, LedgerEvent, LedgerEvents, StateRoot, Tx, TxId},
    qmdb::{QmdbChangeSet, QmdbConfig, QmdbLedger, RevmDb},
    ConsensusDigest,
};
use alloy_evm::revm::{
    primitives::{Address, B256, U256},
    Database as _,
};
use commonware_cryptography::Committable as _;
use commonware_runtime::{buffer::PoolRef, tokio, Metrics};
use futures::{channel::mpsc::UnboundedReceiver, lock::Mutex};
use mempool::Mempool;
use seed_cache::SeedCache;
use snapshot_store::{LedgerSnapshot, SnapshotStore};
use std::{collections::BTreeSet, sync::Arc};
#[derive(Clone)]
/// Ledger view that owns the mutexed execution state.
pub(crate) struct LedgerView {
    /// Mutex-protected running state.
    inner: Arc<Mutex<LedgerState>>,
    /// Genesis block stored so the automaton can replay from height 0.
    genesis_block: Block,
}

/// Internal ledger state guarded by the mutex inside `LedgerView`.
pub(crate) struct LedgerState {
    /// Pending transactions that are not yet included in finalized blocks.
    mempool: Mempool,
    /// Execution snapshots indexed by digest so we can replay ancestors.
    snapshots: SnapshotStore,
    /// Cached seeds for each digest used to compute prevrandao.
    seeds: SeedCache,
    /// Underlying QMDB ledger service for persistence.
    qmdb: QmdbLedger,
}

/// Minimal mempool helper that avoids duplicating logics across services.
impl LedgerView {
    pub(crate) async fn init(
        context: tokio::Context,
        buffer_pool: PoolRef,
        partition_prefix: String,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> anyhow::Result<Self> {
        let qmdb = QmdbLedger::init(
            context.with_label("qmdb"),
            QmdbConfig::new(partition_prefix, buffer_pool),
            genesis_alloc,
        )
        .await?;
        let genesis_root = qmdb.root().await?;

        let genesis_block = Block {
            parent: crate::BlockId(B256::ZERO),
            height: 0,
            prevrandao: B256::ZERO,
            state_root: genesis_root,
            txs: Vec::new(),
        };
        let genesis_digest = genesis_block.commitment();
        let db = RevmDb::new(qmdb.database()?);

        Ok(Self {
            inner: Arc::new(Mutex::new(LedgerState {
                mempool: Mempool::new(),
                snapshots: SnapshotStore::new(
                    genesis_digest,
                    LedgerSnapshot {
                        parent: None,
                        db,
                        state_root: genesis_block.state_root,
                        qmdb_changes: QmdbChangeSet::default(),
                    },
                ),
                seeds: SeedCache::new(genesis_digest),
                qmdb,
            })),
            genesis_block,
        })
    }

    pub(crate) fn genesis_block(&self) -> Block {
        self.genesis_block.clone()
    }

    pub(crate) async fn submit_tx(&self, tx: Tx) -> bool {
        let mut inner = self.inner.lock().await;
        inner.mempool.insert(tx)
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
        inner.seeds.get(&digest)
    }

    pub(crate) async fn seed_for_parent(&self, parent: ConsensusDigest) -> Option<B256> {
        let inner = self.inner.lock().await;
        inner.seeds.get(&parent)
    }

    pub(crate) async fn set_seed(&self, digest: ConsensusDigest, seed_hash: B256) {
        let mut inner = self.inner.lock().await;
        inner.seeds.insert(digest, seed_hash);
    }

    pub(crate) async fn parent_snapshot(&self, parent: ConsensusDigest) -> Option<LedgerSnapshot> {
        let inner = self.inner.lock().await;
        inner.snapshots.get(&parent).cloned()
    }

    pub(crate) async fn insert_snapshot(
        &self,
        digest: ConsensusDigest,
        parent: ConsensusDigest,
        db: RevmDb,
        root: StateRoot,
        qmdb_changes: QmdbChangeSet,
    ) {
        let mut inner = self.inner.lock().await;
        inner.snapshots.insert(
            digest,
            LedgerSnapshot {
                parent: Some(parent),
                db,
                state_root: root,
                qmdb_changes,
            },
        );
    }

    pub(crate) async fn compute_qmdb_root(
        &self,
        parent: ConsensusDigest,
        changes: QmdbChangeSet,
    ) -> anyhow::Result<StateRoot> {
        // Get the handle and release the lock before awaiting
        let (changes, qmdb) = {
            let inner = self.inner.lock().await;
            let changes = inner.merged_changes_from(parent, changes)?;
            (changes, inner.qmdb.clone())
        };
        qmdb.compute_root(changes).await.map_err(Into::into)
    }

    pub(crate) async fn persist_snapshot(&self, digest: ConsensusDigest) -> anyhow::Result<bool> {
        let (changes, qmdb, chain) = {
            let mut inner = self.inner.lock().await;
            let (chain, changes) = inner.snapshots.merged_changes_for_persist(digest)?;
            if chain.is_empty() {
                return Ok(false);
            }
            if !inner.snapshots.can_persist_chain(&chain) {
                return Ok(false);
            }
            inner.snapshots.mark_persisting_chain(&chain);
            (changes, inner.qmdb.clone(), chain)
        };

        let result = qmdb.commit_changes(changes).await;
        let mut inner = self.inner.lock().await;
        inner.snapshots.clear_persisting_chain(&chain);
        match result {
            Ok(_) => {
                inner.snapshots.mark_persisted_chain(&chain);
                Ok(true)
            }
            Err(err) => Err(err.into()),
        }
    }

    pub(crate) async fn prune_mempool(&self, txs: &[Tx]) {
        let mut inner = self.inner.lock().await;
        inner.mempool.prune(txs);
    }

    pub(crate) async fn build_txs(&self, max_txs: usize, excluded: &BTreeSet<TxId>) -> Vec<Tx> {
        let inner = self.inner.lock().await;
        inner.mempool.build(max_txs, excluded)
    }
}

impl LedgerState {
    fn merged_changes_from(
        &self,
        parent: ConsensusDigest,
        changes: QmdbChangeSet,
    ) -> anyhow::Result<QmdbChangeSet> {
        self.snapshots.merged_changes_from(parent, changes)
    }
}

#[derive(Clone)]
/// Domain service that exposes high-level ledger commands.
pub(crate) struct LedgerService {
    view: LedgerView,
    events: LedgerEvents,
}

#[cfg(test)]
mod tests {
    use super::{LedgerService, LedgerView};
    use crate::{
        application::execution::{evm_env, execute_txs},
        domain::{Block, Tx},
    };
    use alloy_evm::revm::primitives::{Address, Bytes, B256, U256};
    use commonware_cryptography::Committable as _;
    use commonware_runtime::{buffer::PoolRef, tokio};
    use commonware_utils::{NZU16, NZUsize};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PARTITION_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn next_partition(prefix: &str) -> String {
        let id = PARTITION_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{id}")
    }

    fn buffer_pool() -> PoolRef {
        PoolRef::new(NZU16!(16_384), NZUsize!(10_000))
    }

    fn transfer(from: Address, to: Address, value: u64) -> Tx {
        Tx {
            from,
            to,
            value: U256::from(value),
            gas_limit: 21_000,
            data: Bytes::new(),
        }
    }

    #[test]
    fn test_persist_snapshot_merges_unpersisted_ancestors() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            let from = addr(0x11);
            let to = addr(0x22);
            let ledger = LedgerView::init(
                context,
                buffer_pool(),
                next_partition("revm-ledger-merge"),
                vec![(from, U256::from(1_000_000u64)), (to, U256::ZERO)],
            )
            .await
            .expect("init ledger");
            let service = LedgerService::new(ledger.clone());

            let genesis = service.genesis_block();
            let genesis_digest = genesis.commitment();
            let parent_snapshot = service
                .parent_snapshot(genesis_digest)
                .await
                .expect("genesis snapshot");

            let tx1 = transfer(from, to, 10);
            let (db1, out1) =
                execute_txs(parent_snapshot.db, evm_env(1, B256::ZERO), &[tx1.clone()])
                    .expect("execute tx1");
            let root1 = service
                .compute_root(genesis_digest, out1.qmdb_changes.clone())
                .await
                .expect("compute root1");
            let block1 = Block {
                parent: genesis.id(),
                height: 1,
                prevrandao: B256::ZERO,
                state_root: root1,
                txs: vec![tx1],
            };
            let digest1 = block1.commitment();
            service
                .insert_snapshot(digest1, genesis_digest, db1, root1, out1.qmdb_changes)
                .await;

            let parent_snapshot = service
                .parent_snapshot(digest1)
                .await
                .expect("parent snapshot");
            let tx2 = transfer(from, to, 5);
            let (db2, out2) =
                execute_txs(parent_snapshot.db, evm_env(2, B256::ZERO), &[tx2.clone()])
                    .expect("execute tx2");
            let root2 = service
                .compute_root(digest1, out2.qmdb_changes.clone())
                .await
                .expect("compute root2");
            let block2 = Block {
                parent: block1.id(),
                height: 2,
                prevrandao: B256::ZERO,
                state_root: root2,
                txs: vec![tx2],
            };
            let digest2 = block2.commitment();
            service
                .insert_snapshot(digest2, digest1, db2, root2, out2.qmdb_changes)
                .await;

            let persisted = ledger
                .persist_snapshot(digest2)
                .await
                .expect("persist snapshot");
            assert!(persisted, "expected merged persistence");

            let qmdb = {
                let inner = ledger.inner.lock().await;
                inner.qmdb.clone()
            };
            let persisted_root = qmdb.root().await.expect("qmdb root");
            assert_eq!(persisted_root, root2);

            let inner = ledger.inner.lock().await;
            assert!(inner.snapshots.is_persisted(&digest1));
            assert!(inner.snapshots.is_persisted(&digest2));
        });
    }

    #[test]
    fn test_persist_snapshot_duplicate_is_noop() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            let from = addr(0x33);
            let to = addr(0x44);
            let ledger = LedgerView::init(
                context,
                buffer_pool(),
                next_partition("revm-ledger-dup"),
                vec![(from, U256::from(500_000u64)), (to, U256::ZERO)],
            )
            .await
            .expect("init ledger");
            let service = LedgerService::new(ledger.clone());

            let genesis = service.genesis_block();
            let genesis_digest = genesis.commitment();
            let parent_snapshot = service
                .parent_snapshot(genesis_digest)
                .await
                .expect("genesis snapshot");

            let tx = transfer(from, to, 1);
            let (db, out) =
                execute_txs(parent_snapshot.db, evm_env(1, B256::ZERO), &[tx.clone()])
                    .expect("execute tx");
            let root = service
                .compute_root(genesis_digest, out.qmdb_changes.clone())
                .await
                .expect("compute root");
            let block = Block {
                parent: genesis.id(),
                height: 1,
                prevrandao: B256::ZERO,
                state_root: root,
                txs: vec![tx],
            };
            let digest = block.commitment();
            service
                .insert_snapshot(digest, genesis_digest, db, root, out.qmdb_changes)
                .await;

            let first = ledger
                .persist_snapshot(digest)
                .await
                .expect("persist snapshot");
            assert!(first);

            let second = ledger
                .persist_snapshot(digest)
                .await
                .expect("persist snapshot");
            assert!(!second, "duplicate persist should be a no-op");
        });
    }
}

impl LedgerService {
    pub(crate) fn new(view: LedgerView) -> Self {
        Self {
            view,
            events: LedgerEvents::new(),
        }
    }

    fn publish(&self, event: LedgerEvent) {
        self.events.publish(event);
    }

    #[allow(dead_code)]
    pub(crate) fn subscribe(&self) -> UnboundedReceiver<LedgerEvent> {
        self.events.subscribe()
    }

    pub(crate) fn genesis_block(&self) -> Block {
        self.view.genesis_block()
    }

    pub(crate) async fn submit_tx(&self, tx: Tx) -> bool {
        let tx_id = tx.id();
        let inserted = self.view.submit_tx(tx).await;
        if inserted {
            self.publish(LedgerEvent::TransactionSubmitted(tx_id));
        }
        inserted
    }

    pub(crate) async fn query_balance(
        &self,
        digest: ConsensusDigest,
        address: Address,
    ) -> Option<U256> {
        self.view.query_balance(digest, address).await
    }

    pub(crate) async fn query_state_root(&self, digest: ConsensusDigest) -> Option<StateRoot> {
        self.view.query_state_root(digest).await
    }

    pub(crate) async fn query_seed(&self, digest: ConsensusDigest) -> Option<B256> {
        self.view.query_seed(digest).await
    }

    pub(crate) async fn seed_for_parent(&self, parent: ConsensusDigest) -> Option<B256> {
        self.view.seed_for_parent(parent).await
    }

    pub(crate) async fn set_seed(&self, digest: ConsensusDigest, seed_hash: B256) {
        self.view.set_seed(digest, seed_hash).await;
        self.publish(LedgerEvent::SeedUpdated(digest, seed_hash));
    }

    pub(crate) async fn parent_snapshot(&self, parent: ConsensusDigest) -> Option<LedgerSnapshot> {
        self.view.parent_snapshot(parent).await
    }

    pub(crate) async fn insert_snapshot(
        &self,
        digest: ConsensusDigest,
        parent: ConsensusDigest,
        db: RevmDb,
        root: StateRoot,
        changes: QmdbChangeSet,
    ) {
        self.view
            .insert_snapshot(digest, parent, db, root, changes)
            .await;
    }

    pub(crate) async fn compute_root(
        &self,
        parent: ConsensusDigest,
        changes: QmdbChangeSet,
    ) -> anyhow::Result<StateRoot> {
        self.view.compute_qmdb_root(parent, changes).await
    }

    pub(crate) async fn persist_snapshot(&self, digest: ConsensusDigest) -> anyhow::Result<()> {
        let persisted = self.view.persist_snapshot(digest).await?;
        if persisted {
            self.publish(LedgerEvent::SnapshotPersisted(digest));
        }
        Ok(())
    }

    pub(crate) async fn prune_mempool(&self, txs: &[Tx]) {
        self.view.prune_mempool(txs).await;
    }

    pub(crate) async fn build_txs(&self, max_txs: usize, excluded: &BTreeSet<TxId>) -> Vec<Tx> {
        self.view.build_txs(max_txs, excluded).await
    }
}
