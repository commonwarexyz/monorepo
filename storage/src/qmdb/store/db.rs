//! A mutable key-value database that supports variable-sized values, but without authentication.
//!
//! # Example
//!
//! ```rust
//! use commonware_storage::{
//!     journal::contiguous::variable::Config as JournalConfig,
//!     qmdb::store::db::{Config, Db},
//!     translator::TwoCap,
//! };
//! use commonware_utils::{NZUsize, NZU16, NZU64};
//! use commonware_cryptography::{blake3::Digest, Digest as _};
//! use commonware_math::algebra::Random;
//! use commonware_runtime::{
//!     buffer::paged::CacheRef, deterministic::Runner, Metrics, Runner as _, Supervisor as _,
//! };
//!
//! use std::num::NonZeroU16;
//! const PAGE_SIZE: NonZeroU16 = NZU16!(8192);
//! const PAGE_CACHE_SIZE: usize = 100;
//!
//! let executor = Runner::default();
//! executor.start(|mut ctx| async move {
//!     let config = Config {
//!         log: JournalConfig {
//!             partition: "test-partition".into(),
//!             write_buffer: NZUsize!(64 * 1024),
//!             compression: None,
//!             codec_config: ((), ()),
//!             items_per_section: NZU64!(4),
//!             page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
//!         },
//!         translator: TwoCap,
//!     };
//!     let mut db =
//!         Db::<_, Digest, Digest, TwoCap>::init(ctx.child("store"), config)
//!             .await
//!             .unwrap();
//!
//!     // Insert a key-value pair
//!     let k = Digest::random(&mut ctx);
//!     let v = Digest::random(&mut ctx);
//!     let metadata = Some(Digest::random(&mut ctx));
//!     db.apply_batch(db.new_batch().update(k, v).finalize(metadata)).await.unwrap();
//!     db.commit().await.unwrap();
//!
//!     // Fetch the value
//!     let fetched_value = db.get(&k).await.unwrap();
//!     assert_eq!(fetched_value.unwrap(), v);
//!
//!     // Delete the key's value
//!     db.apply_batch(db.new_batch().delete(k).finalize(None)).await.unwrap();
//!     db.commit().await.unwrap();
//!
//!     // Fetch the value
//!     let fetched_value = db.get(&k).await.unwrap();
//!     assert!(fetched_value.is_none());
//!
//!     // Destroy the store
//!     db.destroy().await.unwrap();
//! });
//! ```
//!
//! ```ignore
//! // Advanced mode: while the previous batch is being committed, build exactly
//! // one child batch from the newly published state.
//! db.apply_batch(db.new_batch().update(key_a, value_a).finalize(None)).await?;
//!
//! let (child_finalized, commit_result) = futures::join!(
//!     async { db.new_batch().update(key_b, value_b).finalize(None) },
//!     db.commit(),
//! );
//! commit_result?;
//!
//! db.apply_batch(child_finalized).await?;
//! db.commit().await?;
//! ```

use crate::{
    index::{unordered::Index, Unordered as _},
    journal::contiguous::{
        variable::{Config as JournalConfig, Journal},
        Mutable as _, Reader,
    },
    merkle::mmr::Location,
    qmdb::{
        any::{
            unordered::{variable::Operation, Update},
            VariableValue,
        },
        build_snapshot_from_log, delete_key,
        operation::{Committable as _, Key, Operation as _},
        update_key, FloorHelper,
    },
    translator::Translator,
    Context, Persistable,
};
use commonware_codec::{CodecShared, Read};
use commonware_utils::Array;
use core::ops::Range;
use std::collections::BTreeMap;
use tracing::{debug, warn};

type Error = crate::qmdb::Error<crate::mmr::Family>;

/// Configuration for initializing a [Db].
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// Configuration for the variable-size operations log journal.
    pub log: JournalConfig<C>,

    /// The [Translator] used by the [Index].
    pub translator: T,
}

/// A finalized batch of writes and deletes ready to be applied to the store.
pub struct Changeset<K: Key, V: CodecShared + Clone> {
    diff: BTreeMap<K, Option<V>>,
    metadata: Option<V>,
}

impl<K: Key, V: CodecShared + Clone> Changeset<K, V> {
    fn into_parts(self) -> (BTreeMap<K, Option<V>>, Option<V>) {
        (self.diff, self.metadata)
    }
}

impl<K: Key, V: CodecShared + Clone> FromIterator<(K, Option<V>)> for Changeset<K, V> {
    fn from_iter<TIter: IntoIterator<Item = (K, Option<V>)>>(iter: TIter) -> Self {
        Self {
            diff: iter.into_iter().collect(),
            metadata: None,
        }
    }
}

impl<K: Key, V: CodecShared + Clone, const N: usize> From<[(K, Option<V>); N]> for Changeset<K, V> {
    fn from(items: [(K, Option<V>); N]) -> Self {
        items.into_iter().collect()
    }
}

/// A mutable batch of writes and deletes staged against the current store state.
pub struct Batch<'a, E, K, V, T>
where
    E: Context,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    db: &'a Db<E, K, V, T>,
    diff: BTreeMap<K, Option<V>>,
}

impl<'a, E, K, V, T> Batch<'a, E, K, V, T>
where
    E: Context,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    const fn new(db: &'a Db<E, K, V, T>) -> Self {
        Self {
            db,
            diff: BTreeMap::new(),
        }
    }

    /// Finalize the batch into a changeset that can be applied to the store.
    pub fn finalize(self, metadata: Option<V>) -> Changeset<K, V> {
        Changeset {
            diff: self.diff,
            metadata,
        }
    }

    /// Get the value of `key` in the batch, or the value in the store if it has
    /// not been modified by the batch.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        if let Some(value) = self.diff.get(key) {
            return Ok(value.clone());
        }
        self.db.get(key).await
    }

    /// Update the value of `key` in the batch.
    pub fn update(mut self, key: K, value: V) -> Self {
        self.diff.insert(key, Some(value));
        self
    }

    /// Delete the value of `key` in the batch.
    pub fn delete(mut self, key: K) -> Self {
        self.diff.insert(key, None);
        self
    }
}

/// An unauthenticated key-value database based off of an append-only [Journal] of operations.
pub struct Db<E, K, V, T>
where
    E: Context,
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
    log: Journal<E, Operation<crate::mmr::Family, K, V>>,

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

    /// The number of _steps_ to raise the inactivity floor. Each step involves moving exactly one
    /// active operation to tip.
    pub steps: u64,
}

impl<E, K, V, T> Db<E, K, V, T>
where
    E: Context,
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

    /// Returns a new empty batch of changes.
    pub const fn new_batch(&self) -> Batch<'_, E, K, V, T> {
        Batch::new(self)
    }

    /// Whether the db currently has no active keys.
    pub const fn is_empty(&self) -> bool {
        self.active_keys == 0
    }

    /// Gets a [Operation] from the log at the given location. Returns [Error::OperationPruned]
    /// if the location precedes the oldest retained location. The location is otherwise assumed
    /// valid.
    async fn get_op(&self, loc: Location) -> Result<Operation<crate::mmr::Family, K, V>, Error> {
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
        Location::new(bounds.start)..Location::new(bounds.end)
    }

    /// Return the Location of the next operation appended to this db.
    pub async fn size(&self) -> Location {
        Location::new(self.log.size().await)
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
        let log_size = Location::new(bounds.end);
        let oldest_retained_loc = Location::new(bounds.start);
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
        cfg: Config<T, <Operation<crate::mmr::Family, K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mut log =
            Journal::<E, Operation<crate::mmr::Family, K, V>>::init(context.child("log"), cfg.log)
                .await?;

        // Rewind log to remove uncommitted operations.
        if log.rewind_to(|op| op.is_commit()).await? == 0 {
            warn!("Log is empty, initializing new db");
            log.append(&Operation::CommitFloor(None, Location::new(0)))
                .await?;
        }

        // Sync the log to avoid having to repeat any recovery that may have been performed on next
        // startup.
        log.sync().await?;

        let last_commit_loc = Location::new(
            log.size()
                .await
                .checked_sub(1)
                .expect("commit should exist"),
        );

        // Build the snapshot.
        let mut snapshot = Index::new(context.child("snapshot"), cfg.translator);
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
            steps: 0,
        })
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

    #[allow(clippy::type_complexity)]
    const fn as_floor_helper(
        &mut self,
    ) -> FloorHelper<
        '_,
        crate::mmr::Family,
        Index<T, Location>,
        Journal<E, Operation<crate::mmr::Family, K, V>>,
    > {
        FloorHelper {
            snapshot: &mut self.snapshot,
            log: &mut self.log,
        }
    }

    /// Applies a finalized batch to the in-memory database state and appends its operations to the
    /// journal, returning the range of written locations.
    ///
    /// This publishes the batch to the in-memory database state and appends it to the journal, but
    /// does not durably persist it. Call [`Db::commit`] or [`Db::sync`] to guarantee durability.
    pub async fn apply_batch(&mut self, batch: Changeset<K, V>) -> Result<Range<Location>, Error> {
        let start_loc = self.last_commit_loc + 1;
        let (diff, metadata) = batch.into_parts();

        for (key, value) in diff {
            if let Some(value) = value {
                let updated = {
                    let reader = self.log.reader().await;
                    let new_loc = reader.bounds().end;
                    update_key::<crate::mmr::Family, _, _>(
                        &mut self.snapshot,
                        &reader,
                        &key,
                        Location::new(new_loc),
                    )
                    .await?
                };
                if updated.is_some() {
                    self.steps += 1;
                } else {
                    self.active_keys += 1;
                }
                self.log
                    .append(&Operation::Update(Update(key, value)))
                    .await?;
            } else {
                let deleted = {
                    let reader = self.log.reader().await;
                    delete_key::<crate::mmr::Family, _, _>(&mut self.snapshot, &reader, &key)
                        .await?
                };
                if deleted.is_some() {
                    self.log.append(&Operation::Delete(key)).await?;
                    self.steps += 1;
                    self.active_keys -= 1;
                }
            }
        }

        // Raise the inactivity floor by `self.steps` steps, plus 1 to account for the previous
        // commit becoming inactive.
        if self.is_empty() {
            self.inactivity_floor_loc = self.size().await;
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = self.steps + 1;
            for _ in 0..steps_to_take {
                let loc = self.inactivity_floor_loc;
                self.inactivity_floor_loc = self.as_floor_helper().raise_floor(loc).await?;
            }
        }

        // Append the commit operation with the new inactivity floor.
        self.last_commit_loc = Location::new(
            self.log
                .append(&Operation::CommitFloor(metadata, self.inactivity_floor_loc))
                .await?,
        );

        self.steps = 0;

        let end_loc = self.size().await;
        Ok(start_loc..end_loc)
    }

    /// Durably commit the journal state published by prior [`Db::apply_batch`] calls.
    pub async fn commit(&self) -> Result<(), Error> {
        self.log.commit().await.map_err(Into::into)
    }
}

impl<E, K, V, T> Persistable for Db<E, K, V, T>
where
    E: Context,
    K: Array,
    V: VariableValue,
    T: Translator,
{
    type Error = Error;

    async fn commit(&self) -> Result<(), Error> {
        Self::commit(self).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.sync().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::translator::TwoCap;
    use commonware_cryptography::{
        blake3::{Blake3, Digest},
        Hasher as _,
    };
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner, Supervisor as _};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    /// The type of the store used in tests.
    type TestStore = Db<deterministic::Context, Digest, Vec<u8>, TwoCap>;

    async fn create_test_store(context: deterministic::Context) -> TestStore {
        let cfg = Config {
            log: JournalConfig {
                partition: "journal".into(),
                write_buffer: NZUsize!(64 * 1024),
                compression: None,
                codec_config: ((), ((0..=10000).into(), ())),
                items_per_section: NZU64!(7),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            },
            translator: TwoCap,
        };
        TestStore::init(context, cfg).await.unwrap()
    }

    async fn apply_entries(
        db: &mut TestStore,
        iter: impl IntoIterator<Item = (Digest, Option<Vec<u8>>)> + Send,
    ) -> Range<Location> {
        db.apply_batch(iter.into_iter().collect()).await.unwrap()
    }

    #[test_traced("DEBUG")]
    pub fn test_store_construct_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut db = create_test_store(context.child("store").with_attribute("index", 0)).await;
            assert_eq!(db.bounds().await.end, 1);
            assert_eq!(db.log.bounds().await.start, 0);
            assert_eq!(db.inactivity_floor_loc(), 0);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            assert!(matches!(
                db.prune(Location::new(1)).await,
                Err(Error::PruneBeyondMinRequired(_, _))
            ));
            assert!(db.get_metadata().await.unwrap().is_none());

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = Digest::random(&mut context);
            let v1 = vec![1, 2, 3];
            apply_entries(&mut db, [(d1, Some(v1))]).await;
            drop(db);

            let mut db = create_test_store(context.child("store").with_attribute("index", 1)).await;
            assert_eq!(db.bounds().await.end, 1);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            let metadata = vec![1, 2, 3];
            let batch = db.new_batch().finalize(Some(metadata.clone()));
            let range = db.apply_batch(batch).await.unwrap();
            assert_eq!(range.start, 1);
            assert_eq!(range.end, 2);
            db.commit().await.unwrap();
            assert_eq!(db.bounds().await.end, 2);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));

            let mut db = create_test_store(context.child("store").with_attribute("index", 2)).await;
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits on a
            // non-empty db.
            apply_entries(
                &mut db,
                [(Digest::random(&mut context), Some(vec![1, 2, 3]))],
            )
            .await;
            db.commit().await.unwrap();
            for _ in 1..100 {
                db.apply_batch(db.new_batch().finalize(None)).await.unwrap();
                db.commit().await.unwrap();
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
            let mut db = create_test_store(ctx.child("store").with_attribute("index", 0)).await;

            // Ensure the store is empty
            assert_eq!(db.bounds().await.end, 1);
            assert_eq!(db.inactivity_floor_loc, 0);

            let key = Digest::random(&mut ctx);
            let value = vec![2, 3, 4, 5];

            // Attempt to get a key that does not exist
            let result = db.get(&key).await;
            assert!(result.unwrap().is_none());

            // Insert a key-value pair. apply_batch writes the Update, a floor-raise move, and a
            // CommitFloor: 3 new ops on top of the initial commit.
            apply_entries(&mut db, [(key, Some(value.clone()))]).await;

            assert_eq!(*db.bounds().await.end, 4);
            assert_eq!(*db.inactivity_floor_loc, 2);

            // Fetch the value
            let fetched_value = db.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Simulate commit failure: drop without commit. The small batch fits in a single
            // journal section so it is not auto-synced.
            drop(db);

            // Re-open the store
            let mut db = create_test_store(ctx.child("store").with_attribute("index", 1)).await;

            // Ensure the re-opened store removed the uncommitted operations
            assert_eq!(*db.bounds().await.end, 1);
            assert_eq!(*db.inactivity_floor_loc, 0);
            assert!(db.get_metadata().await.unwrap().is_none());

            // Insert a key-value pair and persist with metadata.
            let metadata = vec![99, 100];
            let range = db
                .apply_batch(
                    db.new_batch()
                        .update(key, value.clone())
                        .finalize(Some(metadata.clone())),
                )
                .await
                .unwrap();
            assert_eq!(*range.start, 1);
            assert_eq!(*range.end, 4);
            db.commit().await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));

            assert_eq!(*db.bounds().await.end, 4);
            assert_eq!(*db.inactivity_floor_loc, 2);

            // Re-open the store
            let mut db = create_test_store(ctx.child("store").with_attribute("index", 2)).await;

            // Ensure the re-opened store retained the committed operations
            assert_eq!(*db.bounds().await.end, 4);
            assert_eq!(*db.inactivity_floor_loc, 2);

            // Fetch the value, ensuring it is still present
            let fetched_value = db.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Insert two new k/v pairs to force pruning of the first section.
            let (k1, v1) = (Digest::random(&mut ctx), vec![2, 3, 4, 5, 6]);
            let (k2, v2) = (Digest::random(&mut ctx), vec![6, 7, 8]);
            apply_entries(&mut db, [(k1, Some(v1.clone()))]).await;
            apply_entries(&mut db, [(k2, Some(v2.clone()))]).await;

            assert_eq!(*db.bounds().await.end, 10);
            assert_eq!(*db.inactivity_floor_loc, 5);

            // Each apply_entries writes a CommitFloor with None metadata, replacing
            // the previously committed metadata.
            assert_eq!(db.get_metadata().await.unwrap(), None);

            db.commit().await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), None);

            // commit() is just an fsync now, so bounds and floor are unchanged.
            assert_eq!(*db.bounds().await.end, 10);
            assert_eq!(*db.inactivity_floor_loc, 5);

            // Ensure all keys can be accessed, despite the first section being pruned.
            assert_eq!(db.get(&key).await.unwrap().unwrap(), value);
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            // Update existing key with modified value.
            let mut v1_updated = db.get(&k1).await.unwrap().unwrap();
            v1_updated.push(7);
            apply_entries(&mut db, [(k1, Some(v1_updated))]).await;
            db.commit().await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), vec![2, 3, 4, 5, 6, 7]);

            // Create new key.
            let k3 = Digest::random(&mut ctx);
            apply_entries(&mut db, [(k3, Some(vec![8]))]).await;
            db.commit().await.unwrap();
            assert_eq!(db.get(&k3).await.unwrap().unwrap(), vec![8]);

            // Destroy the store
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_log_replay() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.child("store").with_attribute("index", 0)).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Digest::random(&mut ctx);
            for _ in 0..UPDATES {
                let v = vec![1, 2, 3, 4, 5];
                apply_entries(&mut db, [(k, Some(v.clone()))]).await;
            }

            let iter = db.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            db.commit().await.unwrap();
            db.sync().await.unwrap();
            drop(db);

            // Re-open the store, prune it, then ensure it replays the log correctly.
            let db = create_test_store(ctx.child("store").with_attribute("index", 1)).await;
            db.prune(db.inactivity_floor_loc()).await.unwrap();

            let iter = db.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            // First apply_entries: Update + 1 move + CommitFloor = 3 ops. Subsequent 99: Update + 2
            // moves + CommitFloor = 4 ops each. Total: 1 (init) + 3 + 99*4 = 400.
            assert_eq!(*db.bounds().await.end, 400);
            // Only the last Update and CommitFloor are active → floor = 398.
            assert_eq!(*db.inactivity_floor_loc, 398);
            let floor = db.inactivity_floor_loc;

            // All blobs prior to the inactivity floor are pruned, so the oldest retained location
            // is the first in the last retained blob.
            assert_eq!(db.log.bounds().await.start, *floor - *floor % 7);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_build_snapshot_keys_with_shared_prefix() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.child("store").with_attribute("index", 0)).await;

            let (k1, v1) = (Digest::random(&mut ctx), vec![1, 2, 3, 4, 5]);
            let (mut k2, v2) = (Digest::random(&mut ctx), vec![6, 7, 8, 9, 10]);

            // Ensure k2 shares 2 bytes with k1 (test DB uses `TwoCap` translator.)
            k2.0[0..2].copy_from_slice(&k1.0[0..2]);

            apply_entries(&mut db, [(k1, Some(v1.clone()))]).await;
            apply_entries(&mut db, [(k2, Some(v2.clone()))]).await;

            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            db.commit().await.unwrap();
            db.sync().await.unwrap();
            drop(db);

            // Re-open the store to ensure it builds the snapshot for the conflicting
            // keys correctly.
            let db = create_test_store(ctx.child("store").with_attribute("index", 1)).await;

            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_delete() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.child("store").with_attribute("index", 0)).await;

            // Insert a key-value pair
            let k = Digest::random(&mut ctx);
            let v = vec![1, 2, 3, 4, 5];
            apply_entries(&mut db, [(k, Some(v.clone()))]).await;
            db.commit().await.unwrap();

            // Fetch the value
            let fetched_value = db.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Delete the key
            assert!(db.get(&k).await.unwrap().is_some());
            apply_entries(&mut db, [(k, None)]).await;

            // Ensure the key is no longer present
            let fetched_value = db.get(&k).await.unwrap();
            assert!(fetched_value.is_none());
            assert!(db.get(&k).await.unwrap().is_none());

            // Commit the changes
            db.commit().await.unwrap();

            // Re-open the store and ensure the key is still deleted
            let mut db = create_test_store(ctx.child("store").with_attribute("index", 1)).await;
            let fetched_value = db.get(&k).await.unwrap();
            assert!(fetched_value.is_none());

            // Re-insert the key
            apply_entries(&mut db, [(k, Some(v.clone()))]).await;
            let fetched_value = db.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Commit the changes
            db.commit().await.unwrap();

            // Re-open the store and ensure the snapshot restores the key, after processing
            // the delete and the subsequent set.
            let mut db = create_test_store(ctx.child("store").with_attribute("index", 2)).await;
            let fetched_value = db.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Delete a non-existent key (no-op)
            let k_n = Digest::random(&mut ctx);
            let range = apply_entries(&mut db, [(k_n, None)]).await;
            assert_eq!(range.start, 9);
            assert_eq!(range.end, 11);
            db.commit().await.unwrap();

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
            let mut db = create_test_store(ctx.child("store")).await;

            let k_a = Digest::random(&mut ctx);
            let k_b = Digest::random(&mut ctx);

            let v_a = vec![1];
            let v_b = vec![];
            let v_c = vec![4, 5, 6];

            apply_entries(&mut db, [(k_a, Some(v_a.clone()))]).await;
            apply_entries(&mut db, [(k_b, Some(v_b.clone()))]).await;

            db.commit().await.unwrap();
            assert_eq!(*db.bounds().await.end, 7);
            assert_eq!(*db.inactivity_floor_loc, 3);
            assert_eq!(db.get(&k_a).await.unwrap().unwrap(), v_a);

            apply_entries(&mut db, [(k_b, Some(v_a.clone()))]).await;
            apply_entries(&mut db, [(k_a, Some(v_c.clone()))]).await;

            db.commit().await.unwrap();
            assert_eq!(*db.bounds().await.end, 15);
            assert_eq!(*db.inactivity_floor_loc, 12);
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
            let db = create_test_store(context.child("store").with_attribute("index", 0)).await;

            // Simulate building batches but not applying them (data is not persisted).
            {
                let mut batch = db.new_batch();
                for i in 0u64..ELEMENTS {
                    let k = Blake3::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                    batch = batch.update(k, v);
                }
                // Drop the batch without applying -- simulates a failure before apply.
            }
            drop(db);
            let mut db = create_test_store(context.child("store").with_attribute("index", 1)).await;
            assert_eq!(*db.bounds().await.end, 1);

            // Apply the updates and commit them.
            for i in 0u64..ELEMENTS {
                let k = Blake3::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                apply_entries(&mut db, [(k, Some(v.clone()))]).await;
            }
            db.commit().await.unwrap();

            // Update every 3rd key and commit.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Blake3::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                apply_entries(&mut db, [(k, Some(v.clone()))]).await;
            }
            db.commit().await.unwrap();
            assert_eq!(db.snapshot.items(), 1000);

            // Delete every 7th key and commit.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Blake3::hash(&i.to_be_bytes());
                apply_entries(&mut db, [(k, None)]).await;
            }
            db.commit().await.unwrap();
            let final_count = db.bounds().await.end;
            let final_floor = db.inactivity_floor_loc;

            // Sync and reopen the store to ensure the state is preserved.
            db.sync().await.unwrap();
            drop(db);
            let db = create_test_store(context.child("store").with_attribute("index", 2)).await;
            assert_eq!(db.bounds().await.end, final_count);
            assert_eq!(db.inactivity_floor_loc, final_floor);

            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.log.bounds().await.start, *final_floor - *final_floor % 7);
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_batch() {
        let executor = deterministic::Runner::default();

        executor.start(|mut ctx| async move {
            let mut db = create_test_store(ctx.child("store").with_attribute("index", 0)).await;

            // Ensure the store is empty
            assert_eq!(db.bounds().await.end, 1);
            assert_eq!(db.inactivity_floor_loc, 0);

            let key = Digest::random(&mut ctx);
            let value = vec![2, 3, 4, 5];

            let batch = db.new_batch();

            // Attempt to get a key that does not exist
            let result = batch.get(&key).await;
            assert!(result.unwrap().is_none());

            // Insert a key-value pair
            let batch = batch.update(key, value.clone());

            assert_eq!(db.bounds().await.end, 1); // The batch is not applied yet
            assert_eq!(db.inactivity_floor_loc, 0);

            // Fetch the value
            let fetched_value = batch.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);
            db.apply_batch(batch.finalize(None)).await.unwrap();
            drop(db);

            // Re-open the store
            let mut db = create_test_store(ctx.child("store").with_attribute("index", 1)).await;

            // Ensure the batch was not applied since we didn't commit.
            assert_eq!(db.bounds().await.end, 1);
            assert_eq!(db.inactivity_floor_loc, 0);
            assert!(db.get_metadata().await.unwrap().is_none());

            // Insert a key-value pair and persist the change.
            let metadata = vec![99, 100];
            let range = db
                .apply_batch(
                    db.new_batch()
                        .update(key, value.clone())
                        .finalize(Some(metadata.clone())),
                )
                .await
                .unwrap();
            assert_eq!(range.start, 1);
            assert_eq!(range.end, 4);
            db.commit().await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));
            drop(db);

            // Re-open the store
            let db = create_test_store(ctx.child("store").with_attribute("index", 2)).await;

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

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_read_futures_are_send(db: &mut TestStore, key: Digest, loc: Location) {
        is_send(db.get(&key));
        is_send(db.get_metadata());
        is_send(db.prune(loc));
        is_send(db.sync());
    }

    #[allow(dead_code)]
    fn assert_write_futures_are_send(
        db: &mut Db<deterministic::Context, Digest, Vec<u8>, TwoCap>,
        key: Digest,
        value: Vec<u8>,
    ) {
        is_send(db.get(&key));
        is_send(db.apply_batch(Changeset::from([(key, Some(value))])));
        is_send(db.apply_batch(Changeset::from([(key, None)])));
        let batch = db.new_batch();
        is_send(batch.get(&key));
    }

    #[allow(dead_code)]
    fn assert_commit_is_send(db: &Db<deterministic::Context, Digest, Vec<u8>, TwoCap>) {
        is_send(db.commit());
    }
}
