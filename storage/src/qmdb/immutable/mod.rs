//! An authenticated database that only supports adding new keyed values (no updates or
//! deletions), where values can have varying sizes.

use crate::{
    index::{unordered::Index, Unordered as _},
    journal::{
        authenticated,
        contiguous::variable::{self, Config as JournalConfig},
    },
    kv,
    mmr::{
        journaled::{Config as MmrConfig, Mmr},
        Location, Position, Proof, StandardHasher as Standard,
    },
    qmdb::{
        any::VariableValue, build_snapshot_from_log, DurabilityState, Durable, Error,
        MerkleizationState, Merkleized, NonDurable, Unmerkleized,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::{DigestOf, Hasher as CHasher};
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
};
use tracing::warn;

mod operation;
pub use operation::Operation;

type Journal<E, K, V, H, S> =
    authenticated::Journal<E, variable::Journal<E, Operation<K, V>>, H, S>;

pub mod sync;

/// Configuration for an [Immutable] authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// The name of the [RStorage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [RStorage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [RStorage] partition used to persist the log of operations.
    pub log_partition: String,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of items to put in each section of the journal.
    pub log_items_per_section: NonZeroU64,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

/// An authenticated database that only supports adding new keyed values (no updates or
/// deletions), where values can have varying sizes.
pub struct Immutable<
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: CHasher,
    T: Translator,
    M: MerkleizationState<DigestOf<H>> + Send + Sync = Merkleized<H>,
    D: DurabilityState = Durable,
> {
    /// Authenticated journal of operations.
    journal: Journal<E, K, V, H, M>,

    /// A map from each active key to the location of the operation that set its value.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [Operation::Set].
    snapshot: Index<T, Location>,

    /// The location of the last commit operation.
    last_commit_loc: Location,

    /// Marker for the durability state.
    _durable: core::marker::PhantomData<D>,
}

// Functionality shared across all DB states.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: CHasher,
        T: Translator,
        M: MerkleizationState<DigestOf<H>> + Send + Sync,
        D: DurabilityState,
    > Immutable<E, K, V, H, T, M, D>
{
    /// Return the oldest location that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Location {
        self.journal
            .oldest_retained_loc()
            .expect("at least one operation should exist")
    }

    /// Get the value of `key` in the db, or None if it has no value or its corresponding operation
    /// has been pruned.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        let oldest = self.oldest_retained_loc();
        let iter = self.snapshot.get(key);
        for &loc in iter {
            if loc < oldest {
                continue;
            }
            if let Some(v) = self.get_from_loc(key, loc).await? {
                return Ok(Some(v));
            }
        }

        Ok(None)
    }

    /// Get the value of the operation with location `loc` in the db if it matches `key`. Returns
    /// [Error::OperationPruned] if loc precedes the oldest retained location. The location is
    /// otherwise assumed valid.
    async fn get_from_loc(&self, key: &K, loc: Location) -> Result<Option<V>, Error> {
        if loc < self.oldest_retained_loc() {
            return Err(Error::OperationPruned(loc));
        }

        let Operation::Set(k, v) = self.journal.read(loc).await? else {
            return Err(Error::UnexpectedData(loc));
        };

        if k != *key {
            Ok(None)
        } else {
            Ok(Some(v))
        }
    }

    /// Get the number of operations that have been applied to this db, including those that are not
    /// yet committed.
    pub fn op_count(&self) -> Location {
        self.journal.size()
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V>, Error> {
        let last_commit_loc = self.last_commit_loc;
        let Operation::Commit(metadata) = self.journal.read(last_commit_loc).await? else {
            unreachable!("no commit operation at location of last commit {last_commit_loc}");
        };

        Ok(metadata)
    }
}

// Functionality shared across Merkleized states.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: CHasher,
        T: Translator,
        D: DurabilityState,
    > Immutable<E, K, V, H, T, Merkleized<H>, D>
{
    /// Return the root of the db.
    pub const fn root(&self) -> H::Digest {
        self.journal.root()
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the db in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    pub async fn proof(
        &self,
        start_index: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        let op_count = self.op_count();
        self.historical_proof(op_count, start_index, max_ops).await
    }

    /// Analogous to proof but with respect to the state of the database when it had `op_count`
    /// operations.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `op_count` or `start_loc` >
    /// [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `op_count` > number of operations, or
    /// if `start_loc` >= `op_count`.
    /// Returns [`Error::OperationPruned`] if `start_loc` has been pruned.
    pub async fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        Ok(self
            .journal
            .historical_proof(op_count, start_loc, max_ops)
            .await?)
    }

    /// Prune historical operations prior to `prune_loc`. This does not affect the db's root or
    /// current snapshot.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [crate::mmr::Error::LocationOverflow] if `prune_loc` > [crate::mmr::MAX_LOCATION].
    pub async fn prune(&mut self, loc: Location) -> Result<(), Error> {
        if loc > self.last_commit_loc {
            return Err(Error::PruneBeyondMinRequired(loc, self.last_commit_loc));
        }
        self.journal.prune(loc).await?;

        Ok(())
    }
}

// Functionality specific to (Merkleized, Durable) state.
impl<E: RStorage + Clock + Metrics, K: Array, V: VariableValue, H: CHasher, T: Translator>
    Immutable<E, K, V, H, T, Merkleized<H>, Durable>
{
    /// Returns an [Immutable] qmdb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: Config<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mmr_cfg = MmrConfig {
            journal_partition: cfg.mmr_journal_partition,
            metadata_partition: cfg.mmr_metadata_partition,
            items_per_blob: cfg.mmr_items_per_blob,
            write_buffer: cfg.mmr_write_buffer,
            thread_pool: cfg.thread_pool,
            buffer_pool: cfg.buffer_pool.clone(),
        };

        let journal_cfg = JournalConfig {
            partition: cfg.log_partition,
            items_per_section: cfg.log_items_per_section,
            compression: cfg.log_compression,
            codec_config: cfg.log_codec_config,
            buffer_pool: cfg.buffer_pool.clone(),
            write_buffer: cfg.log_write_buffer,
        };

        let mut journal = Journal::new(
            context.clone(),
            mmr_cfg,
            journal_cfg,
            Operation::<K, V>::is_commit,
        )
        .await?;

        if journal.size() == 0 {
            warn!("Authenticated log is empty, initialized new db.");
            journal.append(Operation::Commit(None)).await?;
            journal.sync().await?;
        }

        let mut snapshot = Index::new(context.with_label("snapshot"), cfg.translator.clone());

        // Get the start of the log.
        let start_loc = journal.pruning_boundary();

        // Build snapshot from the log.
        build_snapshot_from_log(start_loc, &journal.journal, &mut snapshot, |_, _| {}).await?;

        let last_commit_loc = journal.size().checked_sub(1).expect("commit should exist");

        Ok(Self {
            journal,
            snapshot,
            last_commit_loc,
            _durable: core::marker::PhantomData,
        })
    }

    /// The number of operations to apply to the MMR in a single batch.
    const APPLY_BATCH_SIZE: u64 = 1 << 16;

    /// Returns an [Immutable] built from the config and sync data in `cfg`.
    #[allow(clippy::type_complexity)]
    pub async fn init_synced(
        context: E,
        cfg: sync::Config<E, K, V, T, H::Digest, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mut hasher = Standard::new();

        // Initialize MMR for sync
        let mmr = Mmr::init_sync(
            context.with_label("mmr"),
            crate::mmr::journaled::SyncConfig {
                config: MmrConfig {
                    journal_partition: cfg.db_config.mmr_journal_partition,
                    metadata_partition: cfg.db_config.mmr_metadata_partition,
                    items_per_blob: cfg.db_config.mmr_items_per_blob,
                    write_buffer: cfg.db_config.mmr_write_buffer,
                    thread_pool: cfg.db_config.thread_pool.clone(),
                    buffer_pool: cfg.db_config.buffer_pool.clone(),
                },
                range: Position::try_from(cfg.range.start)?
                    ..Position::try_from(cfg.range.end.saturating_add(1))?,
                pinned_nodes: cfg.pinned_nodes,
            },
            &mut hasher,
        )
        .await?;

        let journal = Journal::<_, _, _, _, Merkleized<H>>::from_components(
            mmr,
            cfg.log,
            hasher,
            Self::APPLY_BATCH_SIZE,
        )
        .await?;

        let mut snapshot: Index<T, Location> = Index::new(
            context.with_label("snapshot"),
            cfg.db_config.translator.clone(),
        );

        // Get the start of the log.
        let start_loc = journal.pruning_boundary();

        // Build snapshot from the log
        build_snapshot_from_log(start_loc, &journal.journal, &mut snapshot, |_, _| {}).await?;

        let last_commit_loc = journal.size().checked_sub(1).expect("commit should exist");

        let mut db = Self {
            journal,
            snapshot,
            last_commit_loc,
            _durable: core::marker::PhantomData,
        };

        db.sync().await?;
        Ok(db)
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&mut self) -> Result<(), Error> {
        Ok(self.journal.sync().await?)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        Ok(self.journal.destroy().await?)
    }

    /// Convert this database into a mutable state for batched updates.
    pub fn into_mutable(self) -> Immutable<E, K, V, H, T, Unmerkleized, NonDurable> {
        Immutable {
            journal: self.journal.into_dirty(),
            snapshot: self.snapshot,
            last_commit_loc: self.last_commit_loc,
            _durable: core::marker::PhantomData,
        }
    }
}

// Functionality specific to (Unmerkleized, Durable) state.
impl<E: RStorage + Clock + Metrics, K: Array, V: VariableValue, H: CHasher, T: Translator>
    Immutable<E, K, V, H, T, Unmerkleized, Durable>
{
    /// Convert this database into a mutable state for batched updates.
    pub fn into_mutable(self) -> Immutable<E, K, V, H, T, Unmerkleized, NonDurable> {
        Immutable {
            journal: self.journal,
            snapshot: self.snapshot,
            last_commit_loc: self.last_commit_loc,
            _durable: core::marker::PhantomData,
        }
    }

    /// Convert to merkleized state.
    pub fn into_merkleized(self) -> Immutable<E, K, V, H, T, Merkleized<H>, Durable> {
        Immutable {
            journal: self.journal.merkleize(),
            snapshot: self.snapshot,
            last_commit_loc: self.last_commit_loc,
            _durable: core::marker::PhantomData,
        }
    }
}

// Functionality specific to (Merkleized, NonDurable) state.
impl<E: RStorage + Clock + Metrics, K: Array, V: VariableValue, H: CHasher, T: Translator>
    Immutable<E, K, V, H, T, Merkleized<H>, NonDurable>
{
    /// Convert this database into a mutable state for batched updates.
    pub fn into_mutable(self) -> Immutable<E, K, V, H, T, Unmerkleized, NonDurable> {
        Immutable {
            journal: self.journal.into_dirty(),
            snapshot: self.snapshot,
            last_commit_loc: self.last_commit_loc,
            _durable: core::marker::PhantomData,
        }
    }
}

// Functionality specific to (Unmerkleized, NonDurable) state - the mutable state.
impl<E: RStorage + Clock + Metrics, K: Array, V: VariableValue, H: CHasher, T: Translator>
    Immutable<E, K, V, H, T, Unmerkleized, NonDurable>
{
    /// Update the operations MMR with the given operation, and append the operation to the log. The
    /// `commit` method must be called to make any applied operation persistent & recoverable.
    pub(super) async fn apply_op(&mut self, op: Operation<K, V>) -> Result<(), Error> {
        self.journal.append(op).await?;

        Ok(())
    }

    /// Sets `key` to have value `value`, assuming `key` hasn't already been assigned. The operation
    /// is reflected in the snapshot, but will be subject to rollback until the next successful
    /// `commit`. Attempting to set an already-set key results in undefined behavior.
    ///
    /// Any keys that have been pruned and map to the same translated key will be dropped
    /// during this call.
    pub async fn set(&mut self, key: K, value: V) -> Result<(), Error> {
        let op_count = self.op_count();
        let oldest = self.oldest_retained_loc();
        self.snapshot
            .insert_and_prune(&key, op_count, |v| *v < oldest);

        let op = Operation::Set(key, value);
        self.apply_op(op).await
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Caller can associate an arbitrary `metadata` value with the commit.
    /// Returns the committed database and the range of committed locations. Note that even if no
    /// operations were added since the last commit, this is a root-state changing operation.
    pub async fn commit(
        mut self,
        metadata: Option<V>,
    ) -> Result<
        (
            Immutable<E, K, V, H, T, Unmerkleized, Durable>,
            Range<Location>,
        ),
        Error,
    > {
        let loc = self.journal.append(Operation::Commit(metadata)).await?;
        self.journal.commit().await?;
        self.last_commit_loc = loc;
        let range = loc..self.op_count();

        let db = Immutable {
            journal: self.journal,
            snapshot: self.snapshot,
            last_commit_loc: self.last_commit_loc,
            _durable: core::marker::PhantomData,
        };

        Ok((db, range))
    }

    /// Convert to merkleized state without committing (for read-only merkle operations).
    pub fn into_merkleized(self) -> Immutable<E, K, V, H, T, Merkleized<H>, NonDurable> {
        Immutable {
            journal: self.journal.merkleize(),
            snapshot: self.snapshot,
            last_commit_loc: self.last_commit_loc,
            _durable: core::marker::PhantomData,
        }
    }
}

impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: CHasher,
        T: Translator,
        M: MerkleizationState<DigestOf<H>> + Send + Sync,
        D: DurabilityState,
    > kv::Gettable for Immutable<E, K, V, H, T, M, D>
{
    type Key = K;
    type Value = V;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(key).await
    }
}

impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: CHasher,
        T: Translator,
        M: MerkleizationState<DigestOf<H>> + Send + Sync,
        D: DurabilityState,
    > crate::qmdb::store::LogStore for Immutable<E, K, V, H, T, M, D>
{
    type Value = V;

    fn op_count(&self) -> Location {
        self.op_count()
    }

    // All unpruned operations are active in an immutable store.
    fn inactivity_floor_loc(&self) -> Location {
        self.journal.pruning_boundary()
    }

    fn is_empty(&self) -> bool {
        self.op_count() == 0
    }

    async fn get_metadata(&self) -> Result<Option<V>, Error> {
        self.get_metadata().await
    }
}

impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: CHasher,
        T: Translator,
        D: DurabilityState,
    > crate::qmdb::store::MerkleizedStore for Immutable<E, K, V, H, T, Merkleized<H>, D>
{
    type Digest = H::Digest;
    type Operation = Operation<K, V>;

    fn root(&self) -> Self::Digest {
        self.root()
    }

    async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error> {
        self.historical_proof(historical_size, start_loc, max_ops)
            .await
    }
}

impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: VariableValue,
        H: CHasher,
        T: Translator,
        D: DurabilityState,
    > crate::qmdb::store::PrunableStore for Immutable<E, K, V, H, T, Merkleized<H>, D>
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{qmdb::verify_proof, translator::TwoCap};
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{self},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);
    const ITEMS_PER_SECTION: u64 = 5;

    pub(crate) fn db_config(
        suffix: &str,
    ) -> Config<TwoCap, (commonware_codec::RangeCfg<usize>, ())> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_{suffix}"),
            log_items_per_section: NZU64!(ITEMS_PER_SECTION),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_write_buffer: NZUsize!(1024),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Return an [Immutable] database initialized with a fixed config.
    async fn open_db(
        context: deterministic::Context,
    ) -> Immutable<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap> {
        Immutable::init(context, db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.with_label("first")).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.oldest_retained_loc(), Location::new_unchecked(0));
            assert!(db.get_metadata().await.unwrap().is_none());

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let k1 = Sha256::fill(1u8);
            let v1 = vec![4, 5, 6, 7];
            let root = db.root();
            let mut db = db.into_mutable();
            db.set(k1, v1).await.unwrap();
            drop(db); // Simulate failed commit
            let db = open_db(context.with_label("second")).await;
            assert_eq!(db.root(), root);
            assert_eq!(db.op_count(), 1);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            let db = db.into_mutable();
            let (durable_db, _) = db.commit(None).await.unwrap();
            let db = durable_db.into_merkleized();
            assert_eq!(db.op_count(), 2); // commit op added
            let root = db.root();
            drop(db);

            let db = open_db(context.with_label("third")).await;
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_immutable_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 keys.
            let db = open_db(context.with_label("first")).await;

            let k1 = Sha256::fill(1u8);
            let k2 = Sha256::fill(2u8);
            let v1 = vec![1, 2, 3];
            let v2 = vec![4, 5, 6, 7, 8];

            assert!(db.get(&k1).await.unwrap().is_none());
            assert!(db.get(&k2).await.unwrap().is_none());

            // Set the first key.
            let mut db = db.into_mutable();
            db.set(k1, v1.clone()).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get(&k2).await.unwrap().is_none());
            assert_eq!(db.op_count(), 2);
            // Commit the first key.
            let metadata = Some(vec![99, 100]);
            let (durable_db, _) = db.commit(metadata.clone()).await.unwrap();
            let db = durable_db.into_merkleized();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get(&k2).await.unwrap().is_none());
            assert_eq!(db.op_count(), 3);
            assert_eq!(db.get_metadata().await.unwrap(), metadata.clone());
            // Set the second key.
            let mut db = db.into_mutable();
            db.set(k2, v2.clone()).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);
            assert_eq!(db.op_count(), 4);

            // Make sure we can still get metadata.
            assert_eq!(db.get_metadata().await.unwrap(), metadata);

            // Commit the second key.
            let (durable_db, _) = db.commit(None).await.unwrap();
            let db = durable_db.into_merkleized();
            assert_eq!(db.op_count(), 5);
            assert_eq!(db.get_metadata().await.unwrap(), None);

            // Capture state.
            let root = db.root();

            // Add an uncommitted op then simulate failure.
            let k3 = Sha256::fill(3u8);
            let v3 = vec![9, 10, 11];
            let mut db = db.into_mutable();
            db.set(k3, v3).await.unwrap();
            assert_eq!(db.op_count(), 6);

            // Reopen, make sure state is restored to last commit point.
            drop(db); // Simulate failed commit
            let db = open_db(context.with_label("second")).await;
            assert!(db.get(&k3).await.unwrap().is_none());
            assert_eq!(db.op_count(), 5);
            assert_eq!(db.root(), root);
            assert_eq!(db.get_metadata().await.unwrap(), None);

            // Cleanup.
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        // Build a db with `ELEMENTS` key/value pairs and prove ranges over them.
        const ELEMENTS: u64 = 2_000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let db = open_db(context.with_label("first")).await;
            let mut db = db.into_mutable();

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS + 1);

            let (durable_db, _) = db.commit(None).await.unwrap();
            let db = durable_db.into_merkleized();
            assert_eq!(db.op_count(), ELEMENTS + 2);

            // Drop & reopen the db, making sure it has exactly the same state.
            let root = db.root();
            drop(db);

            let db = open_db(context.with_label("second")).await;
            assert_eq!(root, db.root());
            assert_eq!(db.op_count(), ELEMENTS + 2);
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                assert_eq!(db.get(&k).await.unwrap().unwrap(), v);
            }

            // Make sure all ranges of 5 operations are provable, including truncated ranges at the
            // end.
            let max_ops = NZU64!(5);
            for i in 0..*db.op_count() {
                let (proof, log) = db.proof(Location::new_unchecked(i), max_ops).await.unwrap();
                assert!(verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(i),
                    &log,
                    &root
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_recovery_from_failed_mmr_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;
            let db = open_db(context.with_label("first")).await;
            let mut db = db.into_mutable();

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS + 1);
            let (durable_db, _) = db.commit(None).await.unwrap();
            let mut db = durable_db.into_merkleized();
            db.sync().await.unwrap();
            let halfway_root = db.root();

            // Insert another 1000 keys then simulate a failed close and test recovery.
            let mut db = db.into_mutable();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            // Commit without merkleizing the MMR, then drop to simulate failure.
            // The commit persists the data to the journal, but the MMR is not synced.
            let (durable_db, _) = db.commit(None).await.unwrap();
            drop(durable_db); // Drop before merkleizing

            // Recovery should replay the log to regenerate the MMR.
            // op_count = 1002 (first batch + commit) + 1000 (second batch) + 1 (second commit) = 2003
            let db = open_db(context.with_label("second")).await;
            assert_eq!(db.op_count(), 2003);
            let root = db.root();
            assert_ne!(root, halfway_root);

            // Drop & reopen could preserve the final commit.
            drop(db);
            let db = open_db(context.with_label("third")).await;
            assert_eq!(db.op_count(), 2003);
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_recovery_from_failed_log_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("first")).await.into_mutable();

            // Insert a single key and then commit to create a first commit point.
            let k1 = Sha256::fill(1u8);
            let v1 = vec![1, 2, 3];
            db.set(k1, v1).await.unwrap();
            let (durable_db, _) = db.commit(None).await.unwrap();
            let db = durable_db.into_merkleized();
            let first_commit_root = db.root();

            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;

            let mut db = db.into_mutable();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS + 3);

            // Insert another 1000 keys then simulate a failed close and test recovery.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            // Simulate failure.
            drop(db);

            // Recovery should back up to previous commit point.
            let db = open_db(context.with_label("second")).await;
            assert_eq!(db.op_count(), 3);
            let root = db.root();
            assert_eq!(root, first_commit_root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_pruning() {
        let executor = deterministic::Runner::default();
        // Build a db with `ELEMENTS` key/value pairs then prune some of them.
        const ELEMENTS: u64 = 2_000;
        executor.start(|context| async move {
            let db = open_db(context.with_label("first")).await;
            let mut db = db.into_mutable();

            for i in 1u64..ELEMENTS+1 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS + 1);

            let (durable_db, _) = db.commit(None).await.unwrap();
            let mut db = durable_db.into_merkleized();
            assert_eq!(db.op_count(), ELEMENTS + 2);

            // Prune the db to the first half of the operations.
            db.prune(Location::new_unchecked((ELEMENTS+2) / 2))
                .await
                .unwrap();
            assert_eq!(db.op_count(), ELEMENTS + 2);

            // items_per_section is 5, so half should be exactly at a blob boundary, in which case
            // the actual pruning location should match the requested.
            let oldest_retained_loc = db.oldest_retained_loc();
            assert_eq!(oldest_retained_loc, Location::new_unchecked(ELEMENTS / 2));

            // Try to fetch a pruned key.
            let pruned_loc = oldest_retained_loc - 1;
            let pruned_key = Sha256::hash(&pruned_loc.to_be_bytes());
            assert!(db.get(&pruned_key).await.unwrap().is_none());

            // Try to fetch unpruned key.
            let unpruned_key = Sha256::hash(&oldest_retained_loc.to_be_bytes());
            assert!(db.get(&unpruned_key).await.unwrap().is_some());

            // Drop & reopen the db, making sure it has exactly the same state.
            let root = db.root();
            db.sync().await.unwrap();
            drop(db);

            let mut db = open_db(context.with_label("second")).await;
            assert_eq!(root, db.root());
            assert_eq!(db.op_count(), ELEMENTS + 2);
            let oldest_retained_loc = db.oldest_retained_loc();
            assert_eq!(oldest_retained_loc, Location::new_unchecked(ELEMENTS / 2));

            // Prune to a non-blob boundary.
            let loc = Location::new_unchecked(ELEMENTS / 2 + (ITEMS_PER_SECTION * 2 - 1));
            db.prune(loc).await.unwrap();
            // Actual boundary should be a multiple of 5.
            let oldest_retained_loc = db.oldest_retained_loc();
            assert_eq!(
                oldest_retained_loc,
                Location::new_unchecked(ELEMENTS / 2 + ITEMS_PER_SECTION)
            );

            // Confirm boundary persists across restart.
            db.sync().await.unwrap();
            drop(db);
            let db = open_db(context.with_label("third")).await;
            let oldest_retained_loc = db.oldest_retained_loc();
            assert_eq!(
                oldest_retained_loc,
                Location::new_unchecked(ELEMENTS / 2 + ITEMS_PER_SECTION)
            );

            // Try to fetch a pruned key.
            let pruned_loc = oldest_retained_loc - 3;
            let pruned_key = Sha256::hash(&pruned_loc.to_be_bytes());
            assert!(db.get(&pruned_key).await.unwrap().is_none());

            // Try to fetch unpruned key.
            let unpruned_key = Sha256::hash(&oldest_retained_loc.to_be_bytes());
            assert!(db.get(&unpruned_key).await.unwrap().is_some());

            // Confirm behavior of trying to create a proof of pruned items is as expected.
            let pruned_pos = ELEMENTS / 2;
            let proof_result = db
                .proof(
                    Location::new_unchecked(pruned_pos),
                    NZU64!(pruned_pos + 100),
                )
                .await;
            assert!(matches!(proof_result, Err(Error::Journal(crate::journal::Error::ItemPruned(pos))) if pos == pruned_pos));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    pub fn test_immutable_db_prune_beyond_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("test")).await;

            // Test pruning empty database (no commits)
            let result = db.prune(Location::new_unchecked(1)).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, commit_loc))
                    if prune_loc == Location::new_unchecked(1) && commit_loc == Location::new_unchecked(0))
            );

            // Add key-value pairs and commit
            let k1 = Digest::from(*b"12345678901234567890123456789012");
            let k2 = Digest::from(*b"abcdefghijklmnopqrstuvwxyz123456");
            let k3 = Digest::from(*b"99999999999999999999999999999999");
            let v1 = vec![1u8; 16];
            let v2 = vec![2u8; 16];
            let v3 = vec![3u8; 16];

            let mut db = db.into_mutable();
            db.set(k1, v1.clone()).await.unwrap();
            db.set(k2, v2.clone()).await.unwrap();
            let (durable_db, _) = db.commit(None).await.unwrap();
            let db = durable_db.into_merkleized();
            let mut db = db.into_mutable();
            db.set(k3, v3.clone()).await.unwrap();

            // op_count is 5 (initial_commit, k1, k2, commit, k3), last_commit is at location 3
            assert_eq!(*db.last_commit_loc, 3);

            // Test valid prune (at last commit) - need Merkleized state for prune
            let (durable_db, _) = db.commit(None).await.unwrap();
            let mut db = durable_db.into_merkleized();
            assert!(db.prune(Location::new_unchecked(3)).await.is_ok());

            // Test pruning beyond last commit
            let new_last_commit = db.last_commit_loc;
            let beyond = new_last_commit + 1;
            let result = db.prune(beyond).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, commit_loc))
                    if prune_loc == beyond && commit_loc == new_last_commit)
            );

            db.destroy().await.unwrap();
        });
    }

    use crate::{
        kv::tests::{assert_gettable, assert_send},
        qmdb::store::tests::{assert_log_store, assert_merkleized_store, assert_prunable_store},
    };

    type MerkleizedDb =
        Immutable<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap, Merkleized<Sha256>>;
    type MutableDb = Immutable<
        deterministic::Context,
        Digest,
        Vec<u8>,
        Sha256,
        TwoCap,
        Unmerkleized,
        NonDurable,
    >;

    #[allow(dead_code)]
    fn assert_merkleized_db_futures_are_send(db: &mut MerkleizedDb, key: Digest, loc: Location) {
        assert_gettable(db, &key);
        assert_log_store(db);
        assert_prunable_store(db, loc);
        assert_merkleized_store(db, loc);
        assert_send(db.sync());
    }

    #[allow(dead_code)]
    fn assert_mutable_db_futures_are_send(db: &mut MutableDb, key: Digest, value: Vec<u8>) {
        assert_gettable(db, &key);
        assert_log_store(db);
        assert_send(db.set(key, value));
    }

    #[allow(dead_code)]
    fn assert_mutable_db_commit_is_send(db: MutableDb) {
        assert_send(db.commit(None));
    }
}
