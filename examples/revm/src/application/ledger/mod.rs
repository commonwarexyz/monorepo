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
use commonware_runtime::{buffer::paged::CacheRef, tokio, Metrics};
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
        page_cache: CacheRef,
        partition_prefix: String,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> anyhow::Result<Self> {
        let qmdb = QmdbLedger::init(
            context.with_label("qmdb"),
            QmdbConfig::new(partition_prefix, page_cache),
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

    /// Compute a preview root as if all unpersisted ancestors plus `changes` were applied.
    ///
    /// Note: QMDB roots include commit metadata, so persisted roots can differ from this preview.
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

    /// Persist `digest` and any missing ancestors to QMDB.
    ///
    /// Returns `Ok(true)` if a new commit happened, or `Ok(false)` if the digest is already
    /// persisted or currently being persisted by another task.
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

#[cfg(test)]
mod tests {
    use super::{snapshot_store::LedgerSnapshot, LedgerService, LedgerView};
    use crate::{
        application::execution::{evm_env, execute_txs},
        domain::{Block, Tx},
        qmdb::RevmDb,
        ConsensusDigest,
    };
    use alloy_evm::revm::{
        primitives::{Address, Bytes, B256, U256},
        Database as _,
    };
    use commonware_cryptography::Committable as _;
    use commonware_runtime::{buffer::paged::CacheRef, tokio, Runner};
    use commonware_utils::{NZUsize, NZU16};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PARTITION_COUNTER: AtomicUsize = AtomicUsize::new(0);

    const BUFFER_BLOCK_BYTES: u16 = 16_384;
    const BUFFER_BLOCK_COUNT: usize = 10_000;
    const GENESIS_BALANCE: u64 = 1_000_000;
    const DUPLICATE_BALANCE: u64 = 500_000;
    const TRANSFER_ONE: u64 = 10;
    const TRANSFER_TWO: u64 = 5;
    const TRANSFER_DUPLICATE: u64 = 1;
    const GAS_LIMIT_TRANSFER: u64 = 21_000;
    const HEIGHT_ONE: u64 = 1;
    const HEIGHT_TWO: u64 = 2;
    const PREVRANDAO: B256 = B256::ZERO;
    const FROM_BYTE_A: u8 = 0x11;
    const TO_BYTE_A: u8 = 0x22;
    const FROM_BYTE_B: u8 = 0x33;
    const TO_BYTE_B: u8 = 0x44;

    struct LedgerSetup {
        ledger: LedgerView,
        service: LedgerService,
        genesis: Block,
        genesis_digest: ConsensusDigest,
    }

    struct BuiltBlock {
        block: Block,
        digest: ConsensusDigest,
    }

    fn address_from_byte(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn next_partition(prefix: &str) -> String {
        let id = PARTITION_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{id}")
    }

    fn test_page_cache() -> CacheRef {
        CacheRef::new(NZU16!(BUFFER_BLOCK_BYTES), NZUsize!(BUFFER_BLOCK_COUNT))
    }

    fn transfer_tx(from: Address, to: Address, value: u64) -> Tx {
        Tx {
            from,
            to,
            value: U256::from(value),
            gas_limit: GAS_LIMIT_TRANSFER,
            data: Bytes::new(),
        }
    }

    async fn setup_ledger(
        context: tokio::Context,
        partition_prefix: &str,
        allocations: Vec<(Address, U256)>,
    ) -> LedgerSetup {
        let ledger = LedgerView::init(
            context,
            test_page_cache(),
            next_partition(partition_prefix),
            allocations,
        )
        .await
        .expect("init ledger");
        let service = LedgerService::new(ledger.clone());
        let genesis = service.genesis_block();
        let genesis_digest = genesis.commitment();
        LedgerSetup {
            ledger,
            service,
            genesis,
            genesis_digest,
        }
    }

    async fn build_block_snapshot(
        service: &LedgerService,
        parent: &Block,
        parent_snapshot: LedgerSnapshot,
        height: u64,
        txs: Vec<Tx>,
    ) -> BuiltBlock {
        let (db, outcome) = execute_txs(parent_snapshot.db, evm_env(height, PREVRANDAO), &txs)
            .expect("execute txs");
        let parent_digest = parent.commitment();
        let root = service
            .compute_root(parent_digest, outcome.qmdb_changes.clone())
            .await
            .expect("compute root");
        let block = Block {
            parent: parent.id(),
            height,
            prevrandao: PREVRANDAO,
            state_root: root,
            txs,
        };
        let digest = block.commitment();
        service
            .insert_snapshot(digest, parent_digest, db, root, outcome.qmdb_changes)
            .await;
        BuiltBlock { block, digest }
    }

    #[test]
    fn persist_snapshot_merges_unpersisted_ancestors() {
        // Tokio runtime required for WrapDatabaseAsync in the QMDB adapter.
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            // Arrange
            let from = address_from_byte(FROM_BYTE_A);
            let to = address_from_byte(TO_BYTE_A);
            let setup = setup_ledger(
                context,
                "revm-ledger-merge",
                vec![(from, U256::from(GENESIS_BALANCE)), (to, U256::ZERO)],
            )
            .await;
            let parent_snapshot = setup
                .service
                .parent_snapshot(setup.genesis_digest)
                .await
                .expect("genesis snapshot");
            let block1 = build_block_snapshot(
                &setup.service,
                &setup.genesis,
                parent_snapshot,
                HEIGHT_ONE,
                vec![transfer_tx(from, to, TRANSFER_ONE)],
            )
            .await;
            let parent_snapshot = setup
                .service
                .parent_snapshot(block1.digest)
                .await
                .expect("parent snapshot");
            let block2 = build_block_snapshot(
                &setup.service,
                &block1.block,
                parent_snapshot,
                HEIGHT_TWO,
                vec![transfer_tx(from, to, TRANSFER_TWO)],
            )
            .await;

            // Act
            let persisted = setup
                .ledger
                .persist_snapshot(block2.digest)
                .await
                .expect("persist snapshot");

            // Assert
            assert!(persisted, "expected merged persistence");

            let qmdb = {
                let inner = setup.ledger.inner.lock().await;
                inner.qmdb.clone()
            };
            qmdb.root().await.expect("qmdb root");

            let mut persisted_db = RevmDb::new(qmdb.database().expect("qmdb db"));
            let from_info = persisted_db.basic(from).expect("sender account");
            let to_info = persisted_db.basic(to).expect("recipient account");
            let expected_from = GENESIS_BALANCE - TRANSFER_ONE - TRANSFER_TWO;
            let expected_to = TRANSFER_ONE + TRANSFER_TWO;
            assert_eq!(
                from_info.expect("sender exists").balance,
                U256::from(expected_from)
            );
            assert_eq!(
                to_info.expect("recipient exists").balance,
                U256::from(expected_to)
            );

            let inner = setup.ledger.inner.lock().await;
            assert!(inner.snapshots.is_persisted(&block1.digest));
            assert!(inner.snapshots.is_persisted(&block2.digest));
        });
    }

    #[test]
    fn persist_snapshot_duplicate_is_noop() {
        // Tokio runtime required for WrapDatabaseAsync in the QMDB adapter.
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            // Arrange
            let from = address_from_byte(FROM_BYTE_B);
            let to = address_from_byte(TO_BYTE_B);
            let setup = setup_ledger(
                context,
                "revm-ledger-dup",
                vec![(from, U256::from(DUPLICATE_BALANCE)), (to, U256::ZERO)],
            )
            .await;
            let parent_snapshot = setup
                .service
                .parent_snapshot(setup.genesis_digest)
                .await
                .expect("genesis snapshot");
            let block = build_block_snapshot(
                &setup.service,
                &setup.genesis,
                parent_snapshot,
                HEIGHT_ONE,
                vec![transfer_tx(from, to, TRANSFER_DUPLICATE)],
            )
            .await;

            // Act
            let first = setup
                .ledger
                .persist_snapshot(block.digest)
                .await
                .expect("persist snapshot");
            assert!(first);

            let second = setup
                .ledger
                .persist_snapshot(block.digest)
                .await
                .expect("persist snapshot");

            // Assert
            assert!(!second, "duplicate persist should be a no-op");
        });
    }
}
