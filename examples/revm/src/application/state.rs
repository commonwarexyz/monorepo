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
use alloy_evm::revm::{
    primitives::{Address, B256, U256},
    Database as _,
};
use commonware_cryptography::Committable as _;
use commonware_runtime::{buffer::PoolRef, tokio, Metrics};
use futures::{
    channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender},
    lock::Mutex,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex as StdMutex},
};

/// Events published by the ledger aggregate when domain actions occur.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) enum DomainEvent {
    #[allow(dead_code)]
    TransactionSubmitted(TxId),
    #[allow(dead_code)]
    SnapshotPersisted(ConsensusDigest),
    #[allow(dead_code)]
    SeedUpdated(ConsensusDigest, B256),
}

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
    /// Underlying QMDB tracker for persistence.
    qmdb: QmdbState,
}

#[derive(Clone)]
/// Captures a REVM execution result tied to a consensus digest.
pub(crate) struct LedgerSnapshot {
    /// Parent digest that produced this snapshot (if any).
    pub(crate) parent: Option<ConsensusDigest>,
    /// REVM execution database representing this snapshot.
    pub(crate) db: RevmDb,
    /// Corresponding state root for the snapshot.
    pub(crate) state_root: StateRoot,
    /// QMDB changes captured during the execution that produced this snapshot.
    pub(crate) qmdb_changes: QmdbChanges,
}

/// Minimal mempool helper that avoids duplicating logics across services.
#[derive(Default, Clone)]
struct Mempool(BTreeMap<TxId, Tx>);

impl Mempool {
    const fn new() -> Self {
        Self(BTreeMap::new())
    }

    fn insert(&mut self, tx: Tx) -> bool {
        self.0.insert(tx.id(), tx).is_none()
    }

    fn build(&self, max_txs: usize, excluded: &BTreeSet<TxId>) -> Vec<Tx> {
        self.0
            .iter()
            .filter(|(tx_id, _)| !excluded.contains(tx_id))
            .take(max_txs)
            .map(|(_, tx)| tx.clone())
            .collect()
    }

    fn prune(&mut self, txs: &[Tx]) {
        for tx in txs {
            self.0.remove(&tx.id());
        }
    }
}

/// Storage for cached snapshots and the set of persisted digests.
#[derive(Clone)]
struct SnapshotStore {
    snapshots: BTreeMap<ConsensusDigest, LedgerSnapshot>,
    persisted: BTreeSet<ConsensusDigest>,
}

impl SnapshotStore {
    fn new(genesis_digest: ConsensusDigest, genesis_snapshot: LedgerSnapshot) -> Self {
        let mut snapshots = BTreeMap::new();
        snapshots.insert(genesis_digest, genesis_snapshot);
        let persisted = BTreeSet::from([genesis_digest]);
        Self {
            snapshots,
            persisted,
        }
    }

    fn get(&self, digest: &ConsensusDigest) -> Option<&LedgerSnapshot> {
        self.snapshots.get(digest)
    }

    fn get_mut(&mut self, digest: &ConsensusDigest) -> Option<&mut LedgerSnapshot> {
        self.snapshots.get_mut(digest)
    }

    fn insert(&mut self, digest: ConsensusDigest, snapshot: LedgerSnapshot) {
        self.snapshots.insert(digest, snapshot);
    }

    fn mark_persisted(&mut self, digest: ConsensusDigest) {
        self.persisted.insert(digest);
    }

    fn is_persisted(&self, digest: &ConsensusDigest) -> bool {
        self.persisted.contains(digest)
    }

    fn merged_changes_from(
        &self,
        mut parent: ConsensusDigest,
        changes: QmdbChanges,
    ) -> anyhow::Result<QmdbChanges> {
        let mut chain = Vec::new();
        while !self.persisted.contains(&parent) {
            let snapshot = self
                .snapshots
                .get(&parent)
                .ok_or_else(|| anyhow::anyhow!("missing snapshot"))?;
            let Some(next) = snapshot.parent else {
                return Err(anyhow::anyhow!("missing parent snapshot"));
            };
            chain.push(snapshot.qmdb_changes.clone());
            parent = next;
        }

        let mut merged = QmdbChanges::default();
        for delta in chain.into_iter().rev() {
            merged.merge(delta);
        }
        merged.merge(changes);
        Ok(merged)
    }
}

/// Small cache for per-digest seed hashes.
#[derive(Clone)]
struct SeedCache(BTreeMap<ConsensusDigest, B256>);

impl SeedCache {
    fn new(genesis_digest: ConsensusDigest) -> Self {
        let mut seeds = BTreeMap::new();
        seeds.insert(genesis_digest, B256::ZERO);
        Self(seeds)
    }

    fn get(&self, digest: &ConsensusDigest) -> Option<B256> {
        self.0.get(digest).copied()
    }

    fn insert(&mut self, digest: ConsensusDigest, seed: B256) {
        self.0.insert(digest, seed);
    }
}

impl LedgerView {
    pub(crate) async fn init(
        context: tokio::Context,
        buffer_pool: PoolRef,
        partition_prefix: String,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> anyhow::Result<Self> {
        let qmdb = QmdbState::init(
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
                        qmdb_changes: QmdbChanges::default(),
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
        qmdb_changes: QmdbChanges,
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

    pub(crate) async fn preview_qmdb_root(
        &self,
        parent: ConsensusDigest,
        changes: QmdbChanges,
    ) -> anyhow::Result<StateRoot> {
        // Get the handle and release the lock before awaiting
        let (changes, qmdb) = {
            let inner = self.inner.lock().await;
            let changes = inner.merged_changes_from(parent, changes)?;
            (changes, inner.qmdb.clone())
        };
        qmdb.preview_root(changes).await.map_err(Into::into)
    }

    pub(crate) async fn persist_snapshot(&self, digest: ConsensusDigest) -> anyhow::Result<()> {
        let (changes, qmdb) = {
            let inner = self.inner.lock().await;
            if inner.snapshots.is_persisted(&digest) {
                return Ok(());
            }
            let snapshot = inner
                .snapshots
                .get(&digest)
                .ok_or_else(|| anyhow::anyhow!("missing snapshot"))?;
            (snapshot.qmdb_changes.clone(), inner.qmdb.clone())
        };
        qmdb.commit_changes(changes).await?;
        let mut inner = self.inner.lock().await;
        inner.snapshots.mark_persisted(digest);
        Ok(())
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
        changes: QmdbChanges,
    ) -> anyhow::Result<QmdbChanges> {
        self.snapshots.merged_changes_from(parent, changes)
    }
}

#[derive(Clone)]
/// Domain service that exposes high-level ledger commands.
pub(crate) struct LedgerService {
    view: LedgerView,
    listeners: Arc<StdMutex<Vec<UnboundedSender<DomainEvent>>>>,
}

impl LedgerService {
    pub(crate) fn new(view: LedgerView) -> Self {
        Self {
            view,
            listeners: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn publish(&self, event: DomainEvent) {
        let mut guard = self.listeners.lock().unwrap();
        guard.retain(|sender| sender.unbounded_send(event.clone()).is_ok());
    }

    #[allow(dead_code)]
    pub(crate) fn subscribe(&self) -> UnboundedReceiver<DomainEvent> {
        let (sender, receiver) = unbounded();
        self.listeners.lock().unwrap().push(sender);
        receiver
    }

    pub(crate) fn genesis_block(&self) -> Block {
        self.view.genesis_block()
    }

    pub(crate) async fn submit_tx(&self, tx: Tx) -> bool {
        let tx_id = tx.id();
        let inserted = self.view.submit_tx(tx).await;
        if inserted {
            self.publish(DomainEvent::TransactionSubmitted(tx_id));
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
        self.publish(DomainEvent::SeedUpdated(digest, seed_hash));
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
        changes: QmdbChanges,
    ) {
        self.view
            .insert_snapshot(digest, parent, db, root, changes)
            .await;
    }

    pub(crate) async fn preview_root(
        &self,
        parent: ConsensusDigest,
        changes: QmdbChanges,
    ) -> anyhow::Result<StateRoot> {
        self.view.preview_qmdb_root(parent, changes).await
    }

    pub(crate) async fn persist_snapshot(&self, digest: ConsensusDigest) -> anyhow::Result<()> {
        let result = self.view.persist_snapshot(digest).await;
        self.publish(DomainEvent::SnapshotPersisted(digest));
        result
    }

    pub(crate) async fn prune_mempool(&self, txs: &[Tx]) {
        self.view.prune_mempool(txs).await;
    }

    pub(crate) async fn build_txs(&self, max_txs: usize, excluded: &BTreeSet<TxId>) -> Vec<Tx> {
        self.view.build_txs(max_txs, excluded).await
    }
}
