//! A mutable key-value database that supports variable-sized values, but without authentication.
//!
//! ## Mutation via Batches
//!
//! All mutations go through a [`Batch`]:
//!
//! ```ignore
//! let cs = db.new_batch()
//!     .write_batch([(key, Some(value))])
//!     .finalize(metadata);
//! let range = db.commit(cs).await?;
//! ```
//!
//! The batch borrows the database immutably, buffering writes in memory.
//! [`Batch::finalize`] produces a [`Changeset`] without I/O.
//! [`Db::commit`] atomically applies the changeset and persists to disk.
//!
//! # Example
//!
//! ```rust
//! use commonware_storage::{
//!     qmdb::store::db::{Config, Db},
//!     translator::TwoCap,
//! };
//! use commonware_utils::{NZUsize, NZU16, NZU64};
//! use commonware_cryptography::{blake3::Digest, Digest as _};
//! use commonware_math::algebra::Random;
//! use commonware_runtime::{buffer::paged::CacheRef, deterministic::Runner, Metrics, Runner as _};
//!
//! use std::num::NonZeroU16;
//! const PAGE_SIZE: NonZeroU16 = NZU16!(8192);
//! const PAGE_CACHE_SIZE: usize = 100;
//!
//! let executor = Runner::default();
//! executor.start(|mut ctx| async move {
//!     let config = Config {
//!         log_partition: "test-partition".into(),
//!         log_write_buffer: NZUsize!(64 * 1024),
//!         log_compression: None,
//!         log_codec_config: ((), ()),
//!         log_items_per_section: NZU64!(4),
//!         translator: TwoCap,
//!         page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
//!     };
//!     let mut db =
//!         Db::<_, Digest, Digest, TwoCap>::init(ctx.with_label("store"), config)
//!             .await
//!             .unwrap();
//!
//!     // Insert a key-value pair
//!     let k = Digest::random(&mut ctx);
//!     let v = Digest::random(&mut ctx);
//!     let cs = db.new_batch()
//!         .write_batch([(k, Some(v))])
//!         .finalize(Some(Digest::random(&mut ctx)));
//!     let _ = TestStore::commit(&mut db, cs).await.unwrap();
//!
//!     // Fetch the value
//!     let fetched_value = db.get(&k).await.unwrap();
//!     assert_eq!(fetched_value.unwrap(), v);
//!
//!     // Delete the key's value
//!     let cs = db.new_batch()
//!         .write_batch([(k, None)])
//!         .finalize(None);
//!     let _ = TestStore::commit(&mut db, cs).await.unwrap();
//!
//!     // Fetch the value
//!     let fetched_value = db.get(&k).await.unwrap();
//!     assert!(fetched_value.is_none());
//!
//!     // Destroy the store
//!     db.destroy().await.unwrap();
//! });
//! ```

use crate::{
    index::{unordered::Index, Unordered as _},
    journal::contiguous::{
        variable::{Config as JournalConfig, Journal},
        Mutable as _, Reader,
    },
    mmr::Location,
    qmdb::{
        any::{
            unordered::{variable::Operation, Update},
            VariableValue,
        },
        build_snapshot_from_log, delete_key,
        operation::{Committable as _, Operation as _},
        store::{LogStore, PrunableStore},
        update_key, Error, FloorHelper,
    },
    translator::Translator,
    Persistable,
};
use commonware_codec::Read;
use commonware_runtime::{buffer::paged::CacheRef, Clock, Metrics, Storage};
use commonware_utils::Array;
use core::ops::Range;
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::{debug, warn};

/// Configuration for initializing a [Db].
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// The name of the [Storage] partition used to persist the log of operations.
    pub log_partition: String,

    /// The size of the write buffer to use for each blob in the [Journal].
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of operations to store in each section of the [Journal].
    pub log_items_per_section: NonZeroU64,

    /// The [Translator] used by the [Index].
    pub translator: T,

    /// The [CacheRef] to use for caching data.
    pub page_cache: CacheRef,
}

/// An unauthenticated key-value database based off of an append-only [Journal] of operations.
pub struct Db<E, K, V, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    /// A log of all [Operation]s that have been applied to the store.
    ///
    /// # Invariants
    ///
    /// - There is always at least one commit operation in the log.
    /// - The log is never pruned beyond the inactivity floor.
    log: Journal<E, Operation<K, V>>,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location containing its most recent update.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [Operation::Update].
    snapshot: Index<T, Location>,

    /// The number of active keys in the store.
    active_keys: usize,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    pub inactivity_floor_loc: Location,

    /// The location of the last commit operation.
    pub last_commit_loc: Location,
}

/// A buffered batch of mutations against a [`Db`].
///
/// Created via [`Db::new_batch`]. Supports chaining:
/// ```ignore
/// let cs = db.new_batch()
///     .write_batch(writes)
///     .finalize(metadata);
/// ```
pub struct Batch<'a, E, K, V, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    _db: &'a Db<E, K, V, T>,
    writes: Vec<(K, Option<V>)>,
}

/// The result of [`Batch::finalize`], ready to be committed via [`Db::commit`].
pub struct Changeset<K, V> {
    writes: Vec<(K, Option<V>)>,
    metadata: Option<V>,
}

impl<E, K, V, T> Db<E, K, V, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        for &loc in self.snapshot.get(key) {
            let Operation::Update(Update(k, v)) = self.get_op(loc).await? else {
                unreachable!("location ({loc}) does not reference update operation");
            };

            if &k == key {
                return Ok(Some(v));
            }
        }

        Ok(None)
    }

    /// Whether the db currently has no active keys.
    pub const fn is_empty(&self) -> bool {
        self.active_keys == 0
    }

    /// Gets a [Operation] from the log at the given location. Returns [Error::OperationPruned]
    /// if the location precedes the oldest retained location. The location is otherwise assumed
    /// valid.
    async fn get_op(&self, loc: Location) -> Result<Operation<K, V>, Error> {
        let reader = self.log.reader().await;
        assert!(*loc < reader.bounds().end);
        reader.read(*loc).await.map_err(|e| match e {
            crate::journal::Error::ItemPruned(_) => Error::OperationPruned(loc),
            e => Error::Journal(e),
        })
    }

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and newest
    /// retained operations respectively.
    pub async fn bounds(&self) -> std::ops::Range<Location> {
        let bounds = self.log.reader().await.bounds();
        Location::new_unchecked(bounds.start)..Location::new_unchecked(bounds.end)
    }

    /// Return the Location of the next operation appended to this db.
    pub async fn size(&self) -> Location {
        Location::new_unchecked(self.log.size().await)
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    pub const fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V>, Error> {
        let Operation::CommitFloor(metadata, _) =
            self.log.reader().await.read(*self.last_commit_loc).await?
        else {
            unreachable!("last commit should be a commit floor operation");
        };

        Ok(metadata)
    }

    /// Prune historical operations prior to `prune_loc`. This does not affect the db's root
    /// or current snapshot.
    pub async fn prune(&self, prune_loc: Location) -> Result<(), Error> {
        if prune_loc > self.inactivity_floor_loc {
            return Err(Error::PruneBeyondMinRequired(
                prune_loc,
                self.inactivity_floor_loc,
            ));
        }

        // Prune the log. The log will prune at section boundaries, so the actual oldest retained
        // location may be less than requested.
        if !self.log.prune(*prune_loc).await? {
            return Ok(());
        }

        let bounds = self.log.reader().await.bounds();
        let log_size = Location::new_unchecked(bounds.end);
        let oldest_retained_loc = Location::new_unchecked(bounds.start);
        debug!(
            ?log_size,
            ?oldest_retained_loc,
            ?prune_loc,
            "pruned inactive ops"
        );

        Ok(())
    }

    /// Initializes a new [Db] with the given configuration.
    pub async fn init(
        context: E,
        cfg: Config<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mut log = Journal::<E, Operation<K, V>>::init(
            context.with_label("log"),
            JournalConfig {
                partition: cfg.log_partition,
                items_per_section: cfg.log_items_per_section,
                compression: cfg.log_compression,
                codec_config: cfg.log_codec_config,
                page_cache: cfg.page_cache,
                write_buffer: cfg.log_write_buffer,
            },
        )
        .await?;

        // Rewind log to remove uncommitted operations.
        if log.rewind_to(|op| op.is_commit()).await? == 0 {
            warn!("Log is empty, initializing new db");
            log.append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                .await?;
        }

        // Sync the log to avoid having to repeat any recovery that may have been performed on next
        // startup.
        log.sync().await?;

        let last_commit_loc = Location::new_unchecked(
            log.size()
                .await
                .checked_sub(1)
                .expect("commit should exist"),
        );

        // Build the snapshot.
        let mut snapshot = Index::new(context.with_label("snapshot"), cfg.translator);
        let (inactivity_floor_loc, active_keys) = {
            let reader = log.reader().await;
            let op = reader.read(*last_commit_loc).await?;
            let inactivity_floor_loc = op.has_floor().expect("last op should be a commit");
            let active_keys =
                build_snapshot_from_log(inactivity_floor_loc, &reader, &mut snapshot, |_, _| {})
                    .await?;
            (inactivity_floor_loc, active_keys)
        };

        Ok(Self {
            log,
            snapshot,
            active_keys,
            inactivity_floor_loc,
            last_commit_loc,
        })
    }

    /// Create a batch for buffering mutations.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let cs = db.new_batch()
    ///     .write_batch([(key, Some(value))])
    ///     .finalize(metadata);
    /// let range = db.commit(cs).await?;
    /// ```
    pub const fn new_batch(&self) -> Batch<'_, E, K, V, T> {
        Batch {
            _db: self,
            writes: Vec::new(),
        }
    }

    const fn as_floor_helper(
        &mut self,
    ) -> FloorHelper<'_, Index<T, Location>, Journal<E, Operation<K, V>>> {
        FloorHelper {
            snapshot: &mut self.snapshot,
            log: &mut self.log,
        }
    }

    /// Commit a changeset, persisting all changes to disk.
    pub async fn commit(&mut self, changeset: Changeset<K, V>) -> Result<Range<Location>, Error> {
        let start_loc = self.last_commit_loc + 1;

        // Apply writes.
        let mut steps: u64 = 0;
        for (key, value) in changeset.writes {
            if let Some(value) = value {
                let updated = {
                    let reader = self.log.reader().await;
                    let new_loc = reader.bounds().end;
                    update_key(
                        &mut self.snapshot,
                        &reader,
                        &key,
                        Location::new_unchecked(new_loc),
                    )
                    .await?
                };
                if updated.is_some() {
                    steps += 1;
                } else {
                    self.active_keys += 1;
                }
                self.log
                    .append(Operation::Update(Update(key, value)))
                    .await?;
            } else {
                let deleted = {
                    let reader = self.log.reader().await;
                    delete_key(&mut self.snapshot, &reader, &key).await?
                };
                if deleted.is_some() {
                    self.log.append(Operation::Delete(key)).await?;
                    steps += 1;
                    self.active_keys -= 1;
                }
            }
        }

        // Raise the inactivity floor by taking `steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        if self.is_empty() {
            self.inactivity_floor_loc = self.size().await;
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = steps + 1;
            for _ in 0..steps_to_take {
                let loc = self.inactivity_floor_loc;
                self.inactivity_floor_loc = self.as_floor_helper().raise_floor(loc).await?;
            }
        }

        // Apply the commit operation with the new inactivity floor.
        self.last_commit_loc = Location::new_unchecked(
            self.log
                .append(Operation::CommitFloor(
                    changeset.metadata,
                    self.inactivity_floor_loc,
                ))
                .await?,
        );

        let range = start_loc..self.size().await;

        // Commit the log to ensure durability.
        self.log.commit().await?;

        Ok(range)
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&self) -> Result<(), Error> {
        self.log.sync().await.map_err(Into::into)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await.map_err(Into::into)
    }
}

impl<'a, E, K, V, T> Batch<'a, E, K, V, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    /// Buffer writes into this batch.
    pub fn write_batch(mut self, iter: impl IntoIterator<Item = (K, Option<V>)>) -> Self {
        self.writes.extend(iter);
        self
    }

    /// Finalize this batch into a [`Changeset`].
    pub fn finalize(self, metadata: Option<V>) -> Changeset<K, V> {
        Changeset {
            writes: self.writes,
            metadata,
        }
    }
}

impl<E, K, V, T> Persistable for Db<E, K, V, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    type Error = Error;

    async fn commit(&self) -> Result<(), Error> {
        // No-op, DB already in recoverable state.
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        self.sync().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

impl<E, K, V, T> LogStore for Db<E, K, V, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    type Value = V;

    async fn bounds(&self) -> std::ops::Range<Location> {
        self.bounds().await
    }

    async fn get_metadata(&self) -> Result<Option<V>, Error> {
        self.get_metadata().await
    }
}

impl<E, K, V, T> PrunableStore for Db<E, K, V, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        Self::prune(self, prune_loc).await
    }

    async fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }
}

impl<E, K, V, T> crate::kv::Gettable for Db<E, K, V, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    type Key = K;
    type Value = V;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(key).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        kv::tests::{assert_gettable, assert_send},
        qmdb::store::tests::{assert_log_store, assert_prunable_store},
        translator::TwoCap,
    };
    use commonware_cryptography::{
        blake3::{Blake3, Digest},
        Hasher as _,
    };
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    /// The type of the store used in tests.
    type TestStore = Db<deterministic::Context, Digest, Vec<u8>, TwoCap>;

    async fn create_test_store(context: deterministic::Context) -> TestStore {
        let cfg = Config {
            log_partition: "journal".into(),
            log_write_buffer: NZUsize!(64 * 1024),
            log_compression: None,
            log_codec_config: ((), ((0..=10000).into(), ())),
            log_items_per_section: NZU64!(7),
            translator: TwoCap,
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        };
        TestStore::init(context, cfg).await.unwrap()
    }

    #[test_traced("DEBUG")]
    pub fn test_store_construct_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let db = create_test_store(context.with_label("store_0")).await;
            assert_eq!(db.bounds().await.end, 1);
            assert_eq!(db.log.bounds().await.start, 0);
            assert_eq!(db.inactivity_floor_loc(), 0);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            assert!(matches!(
                db.prune(Location::new_unchecked(1)).await,
                Err(Error::PruneBeyondMinRequired(_, _))
            ));
            assert!(db.get_metadata().await.unwrap().is_none());

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = Digest::random(&mut context);
            let v1 = vec![1, 2, 3];
            let _cs = db.new_batch().write_batch([(d1, Some(v1))]).finalize(None);
            // Don't commit - simulates crash
            drop(db);

            let mut db = create_test_store(context.with_label("store_1")).await;
            assert_eq!(db.bounds().await.end, 1);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            let metadata = vec![1, 2, 3];
            let cs = db.new_batch().finalize(Some(metadata.clone()));
            let range = TestStore::commit(&mut db, cs).await.unwrap();
            assert_eq!(range.start, 1);
            assert_eq!(range.end, 2);
            assert_eq!(db.bounds().await.end, 2);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));

            let mut db = create_test_store(context.with_label("store_2")).await;
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits on a
            // non-empty db.
            let cs = db
                .new_batch()
                .write_batch([(Digest::random(&mut context), Some(vec![1, 2, 3]))])
                .finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();
            for _ in 1..100 {
                let cs = db.new_batch().finalize(None);
                TestStore::commit(&mut db, cs).await.unwrap();
                // Distance should equal 3 after the second commit, with inactivity_floor
                // referencing the previous commit operation.
                assert!(db.bounds().await.end - db.inactivity_floor_loc <= 3);
                assert!(db.get_metadata().await.unwrap().is_none());
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_construct_basic() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let db = create_test_store(ctx.with_label("store_0")).await;

            // Ensure the store is empty
            assert_eq!(db.bounds().await.end, 1);
            assert_eq!(db.inactivity_floor_loc, 0);

            let key = Digest::random(&mut ctx);
            let value = vec![2, 3, 4, 5];

            // Attempt to get a key that does not exist
            let result = db.get(&key).await;
            assert!(result.unwrap().is_none());

            // Insert a key-value pair and commit
            let cs = db
                .new_batch()
                .write_batch([(key, Some(value.clone()))])
                .finalize(None);
            // Check state before commit (batch doesn't modify db)
            assert_eq!(db.bounds().await.end, 1);
            assert_eq!(db.inactivity_floor_loc, 0);

            // Simulate commit failure by dropping the changeset.
            drop(cs);

            // Re-open the store
            let mut db = create_test_store(ctx.with_label("store_1")).await;

            // Ensure the re-opened store removed the uncommitted operations
            assert_eq!(db.bounds().await.end, 1);
            assert_eq!(db.inactivity_floor_loc, 0);
            assert!(db.get_metadata().await.unwrap().is_none());

            // Insert a key-value pair
            let metadata = vec![99, 100];
            let cs = db
                .new_batch()
                .write_batch([(key, Some(value.clone()))])
                .finalize(Some(metadata.clone()));
            let range = TestStore::commit(&mut db, cs).await.unwrap();
            assert_eq!(range.start, 1);
            assert_eq!(range.end, 4);
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));

            // Even though the store was pruned, the inactivity floor was raised by 2, and
            // the old operations remain in the same blob as an active operation, so they're
            // retained.
            assert_eq!(db.bounds().await.end, 4);
            assert_eq!(db.inactivity_floor_loc, 2);

            // Re-open the store
            let mut db = create_test_store(ctx.with_label("store_2")).await;

            // Ensure the re-opened store retained the committed operations
            assert_eq!(db.bounds().await.end, 4);
            assert_eq!(db.inactivity_floor_loc, 2);

            // Fetch the value, ensuring it is still present
            let fetched_value = db.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Insert two new k/v pairs to force pruning of the first section.
            let (k1, v1) = (Digest::random(&mut ctx), vec![2, 3, 4, 5, 6]);
            let (k2, v2) = (Digest::random(&mut ctx), vec![6, 7, 8]);

            // Make sure we can still get metadata.
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

            let cs = db
                .new_batch()
                .write_batch([(k1, Some(v1.clone()))])
                .write_batch([(k2, Some(v2.clone()))])
                .finalize(None);
            let range = TestStore::commit(&mut db, cs).await.unwrap();
            assert_eq!(range.start, 4);
            assert_eq!(range.end, db.bounds().await.end);
            assert_eq!(db.get_metadata().await.unwrap(), None);

            assert_eq!(db.bounds().await.end, 8);
            assert_eq!(db.inactivity_floor_loc, 3);

            // Ensure all keys can be accessed, despite the first section being pruned.
            assert_eq!(db.get(&key).await.unwrap().unwrap(), value);
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            // Update existing key with modified value.
            let mut v1_updated = db.get(&k1).await.unwrap().unwrap();
            v1_updated.push(7);
            let cs = db
                .new_batch()
                .write_batch([(k1, Some(v1_updated))])
                .finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), vec![2, 3, 4, 5, 6, 7]);

            // Create new key.
            let k3 = Digest::random(&mut ctx);
            let cs = db
                .new_batch()
                .write_batch([(k3, Some(vec![8]))])
                .finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();
            assert_eq!(db.get(&k3).await.unwrap().unwrap(), vec![8]);

            // Destroy the store
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_log_replay() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.with_label("store_0")).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Digest::random(&mut ctx);
            let mut batch = db.new_batch();
            for _ in 0..UPDATES {
                let v = vec![1, 2, 3, 4, 5];
                batch = batch.write_batch([(k, Some(v.clone()))]);
            }
            let cs = batch.finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();

            let iter = db.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            db.sync().await.unwrap();
            drop(db);

            // Re-open the store, prune it, then ensure it replays the log correctly.
            let db = create_test_store(ctx.with_label("store_1")).await;
            db.prune(db.inactivity_floor_loc()).await.unwrap();

            let iter = db.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            // 100 operations were applied, each triggering one step, plus the commit op.
            assert_eq!(db.bounds().await.end, UPDATES * 2 + 2);
            // Only the highest `Update` operation is active, plus the commit operation above it.
            let expected_floor = UPDATES * 2;
            assert_eq!(db.inactivity_floor_loc, expected_floor);

            // All blobs prior to the inactivity floor are pruned, so the oldest retained location
            // is the first in the last retained blob.
            assert_eq!(
                db.log.bounds().await.start,
                expected_floor - expected_floor % 7
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_build_snapshot_keys_with_shared_prefix() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.with_label("store_0")).await;

            let (k1, v1) = (Digest::random(&mut ctx), vec![1, 2, 3, 4, 5]);
            let (mut k2, v2) = (Digest::random(&mut ctx), vec![6, 7, 8, 9, 10]);

            // Ensure k2 shares 2 bytes with k1 (test DB uses `TwoCap` translator.)
            k2.0[0..2].copy_from_slice(&k1.0[0..2]);

            let cs = db
                .new_batch()
                .write_batch([(k1, Some(v1.clone()))])
                .write_batch([(k2, Some(v2.clone()))])
                .finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();

            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            db.sync().await.unwrap();
            drop(db);

            // Re-open the store to ensure it builds the snapshot for the conflicting
            // keys correctly.
            let db = create_test_store(ctx.with_label("store_1")).await;

            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_delete() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.with_label("store_0")).await;

            // Insert a key-value pair
            let k = Digest::random(&mut ctx);
            let v = vec![1, 2, 3, 4, 5];
            let cs = db
                .new_batch()
                .write_batch([(k, Some(v.clone()))])
                .finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();

            // Fetch the value
            let fetched_value = db.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Delete the key
            assert!(db.get(&k).await.unwrap().is_some());
            let cs = db.new_batch().write_batch([(k, None)]).finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();

            // Ensure the key is no longer present
            let fetched_value = db.get(&k).await.unwrap();
            assert!(fetched_value.is_none());
            assert!(db.get(&k).await.unwrap().is_none());

            // Re-open the store and ensure the key is still deleted
            let mut db = create_test_store(ctx.with_label("store_1")).await;
            let fetched_value = db.get(&k).await.unwrap();
            assert!(fetched_value.is_none());

            // Re-insert the key
            let cs = db
                .new_batch()
                .write_batch([(k, Some(v.clone()))])
                .finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();
            let fetched_value = db.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Re-open the store and ensure the snapshot restores the key, after processing
            // the delete and the subsequent set.
            let mut db = create_test_store(ctx.with_label("store_2")).await;
            let fetched_value = db.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Delete a non-existent key (no-op)
            let k_n = Digest::random(&mut ctx);
            let cs = db.new_batch().write_batch([(k_n, None)]).finalize(None);
            let range = TestStore::commit(&mut db, cs).await.unwrap();
            assert_eq!(range.start, 9);
            assert_eq!(range.end, 11);

            assert!(db.get(&k_n).await.unwrap().is_none());
            // Make sure k is still there
            assert!(db.get(&k).await.unwrap().is_some());

            db.destroy().await.unwrap();
        });
    }

    /// Tests the pruning example in the module documentation.
    #[test_traced("DEBUG")]
    fn test_store_pruning() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.with_label("store")).await;

            let k_a = Digest::random(&mut ctx);
            let k_b = Digest::random(&mut ctx);

            let v_a = vec![1];
            let v_b = vec![];
            let v_c = vec![4, 5, 6];

            let cs = db
                .new_batch()
                .write_batch([(k_a, Some(v_a.clone()))])
                .write_batch([(k_b, Some(v_b.clone()))])
                .finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();
            assert_eq!(db.bounds().await.end, 5);
            assert_eq!(db.inactivity_floor_loc, 2);
            assert_eq!(db.get(&k_a).await.unwrap().unwrap(), v_a);

            let cs = db
                .new_batch()
                .write_batch([(k_b, Some(v_a.clone()))])
                .write_batch([(k_a, Some(v_c.clone()))])
                .finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();
            assert_eq!(db.bounds().await.end, 11);
            assert_eq!(db.inactivity_floor_loc, 8);
            assert_eq!(db.get(&k_a).await.unwrap().unwrap(), v_c);
            assert_eq!(db.get(&k_b).await.unwrap().unwrap(), v_a);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_store_db_recovery() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let db = create_test_store(context.with_label("store_0")).await;

            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Blake3::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                batch = batch.write_batch([(k, Some(v.clone()))]);
            }
            // Simulate a failed commit by dropping the changeset.
            let _cs = batch.finalize(None);
            drop(db);

            let mut db = create_test_store(context.with_label("store_1")).await;
            assert_eq!(db.bounds().await.end, 1);

            // re-apply the updates and commit them this time.
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Blake3::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                batch = batch.write_batch([(k, Some(v.clone()))]);
            }
            let cs = batch.finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();
            let op_count = db.bounds().await.end;

            // Update every 3rd key
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Blake3::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                batch = batch.write_batch([(k, Some(v.clone()))]);
            }

            // Simulate a failed commit and test that we rollback to the previous root.
            let _cs = batch.finalize(None);
            drop(db);
            let mut db = create_test_store(context.with_label("store_2")).await;
            assert_eq!(db.bounds().await.end, op_count);

            // Re-apply updates for every 3rd key and commit them this time.
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Blake3::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                batch = batch.write_batch([(k, Some(v.clone()))]);
            }
            let cs = batch.finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();
            let op_count = db.bounds().await.end;
            assert_eq!(op_count, 1673);
            assert_eq!(db.snapshot.items(), 1000);

            // Delete every 7th key
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Blake3::hash(&i.to_be_bytes());
                batch = batch.write_batch([(k, None)]);
            }

            // Simulate a failed commit and test that we rollback to the previous root.
            let _cs = batch.finalize(None);
            drop(db);
            let db = create_test_store(context.with_label("store_3")).await;
            assert_eq!(db.bounds().await.end, op_count);

            // Sync and reopen the store to ensure the final commit is preserved.
            db.sync().await.unwrap();
            drop(db);
            let mut db = create_test_store(context.with_label("store_4")).await;
            assert_eq!(db.bounds().await.end, op_count);

            // Re-delete every 7th key and commit this time.
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Blake3::hash(&i.to_be_bytes());
                batch = batch.write_batch([(k, None)]);
            }
            let cs = batch.finalize(None);
            TestStore::commit(&mut db, cs).await.unwrap();

            assert_eq!(db.bounds().await.end, 1961);
            assert_eq!(db.inactivity_floor_loc, 756);

            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.log.bounds().await.start, 756 /*- 756 % 7 == 0*/);
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_batch() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let db = create_test_store(ctx.with_label("store_0")).await;

            // Ensure the store is empty
            assert_eq!(db.bounds().await.end, 1);
            assert_eq!(db.inactivity_floor_loc, 0);

            let key = Digest::random(&mut ctx);
            let value = vec![2, 3, 4, 5];

            // Create a batch with an insert, but don't commit
            let cs = db
                .new_batch()
                .write_batch([(key, Some(value.clone()))])
                .finalize(None);

            assert_eq!(db.bounds().await.end, 1); // The batch is not applied yet
            assert_eq!(db.inactivity_floor_loc, 0);

            // Drop the changeset without committing
            drop(cs);
            drop(db);

            // Re-open the store
            let mut db = create_test_store(ctx.with_label("store_1")).await;

            // Ensure the batch was not applied since we didn't commit.
            assert_eq!(db.bounds().await.end, 1);
            assert_eq!(db.inactivity_floor_loc, 0);
            assert!(db.get_metadata().await.unwrap().is_none());

            // Insert a key-value pair and persist the changes
            let metadata = vec![99, 100];
            let cs = db
                .new_batch()
                .write_batch([(key, Some(value.clone()))])
                .finalize(Some(metadata.clone()));
            let range = TestStore::commit(&mut db, cs).await.unwrap();
            assert_eq!(range.start, 1);
            assert_eq!(range.end, 4);
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));
            drop(db);

            // Re-open the store
            let db = create_test_store(ctx.with_label("store_2")).await;

            // Ensure the re-opened store retained the committed operations
            assert_eq!(db.bounds().await.end, 4);
            assert_eq!(db.inactivity_floor_loc, 2);

            // Fetch the value, ensuring it is still present
            let fetched_value = db.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Destroy the store
            db.destroy().await.unwrap();
        });
    }

    #[allow(dead_code)]
    fn assert_futures_are_send(db: &mut TestStore, key: Digest, loc: Location) {
        assert_log_store(db);
        assert_prunable_store(db, loc);
        assert_gettable(db, &key);
        assert_send(db.sync());
    }

    #[allow(dead_code)]
    fn assert_commit_is_send(db: &mut TestStore) {
        let cs = db.new_batch().finalize(None);
        assert_send(TestStore::commit(db, cs));
    }
}
