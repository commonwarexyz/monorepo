//! A mutable key-value database that supports variable-sized values, but without authentication.
//!
//! # Example
//!
//! ```rust
//! use commonware_storage::{
//!     journal::contiguous::variable::Config as JournalConfig,
//!     qmdb::{
//!         floor::Proportional,
//!         store::db::{Config, Db},
//!     },
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
//!             replay_buffer: NZUsize!(64 * 1024),
//!             compression: None,
//!             codec_config: ((), ()),
//!             items_per_section: NZU64!(4),
//!             page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
//!         },
//!         translator: TwoCap,
//!         init_cache: Some(NZUsize!(1 << 16)),
//!         init_buffer: NZUsize!(1 << 21),
//!     };
//!     let db =
//!         Db::<_, Digest, Digest, TwoCap>::init(ctx.child("store"), config, None)
//!             .await
//!             .unwrap();
//!
//!     // Insert a key-value pair
//!     let k = Digest::random(&mut ctx);
//!     let v = Digest::random(&mut ctx);
//!     let metadata = Some(Digest::random(&mut ctx));
//!     let batch = db.new_batch().update(k, v).finalize(metadata);
//!     let (db, _) = db.apply_batch(batch, &mut Proportional).await.unwrap();
//!     let db = db.commit().await.unwrap();
//!
//!     // Fetch the value
//!     let fetched_value = db.get(&k).await.unwrap();
//!     assert_eq!(fetched_value.unwrap(), v);
//!
//!     // Delete the key's value
//!     let batch = db.new_batch().delete(k).finalize(None);
//!     let (db, _) = db.apply_batch(batch, &mut Proportional).await.unwrap();
//!     let db = db.commit().await.unwrap();
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
//! // Apply a batch and commit it, then build a child batch from the newly published state
//! // and apply it. Each mutation takes the database and returns it, so committing and
//! // building run in sequence on the threaded handle.
//! let batch = db.new_batch().update(key_a, value_a).finalize(None);
//! let (db, _) = db.apply_batch(batch, &mut Proportional).await?;
//! let db = db.commit().await?;
//!
//! let child = db.new_batch().update(key_b, value_b).finalize(None);
//! let (db, _) = db.apply_batch(child, &mut Proportional).await?;
//! let db = db.commit().await?;
//! ```

use crate::{
    Context,
    index::{Cursor as _, Unordered as _, unordered::Index},
    journal::{
        authenticated::{Backing as _, BackingRecovery as _},
        contiguous::{
            Contiguous, Many,
            variable::{Config as JournalConfig, Journal},
        },
    },
    merkle::mmr::Location,
    qmdb::{
        any::{
            BITMAP_CHUNK_BYTES, VariableValue,
            unordered::{Update, variable::Operation},
        },
        bitmap::fill_from,
        build_snapshot_from_log, delete_known_loc,
        floor::{Action, Entry, Limits, Policy, Walk},
        operation::{Committable as _, Floored as _, Key, Operation as _},
        update_known_loc,
    },
    translator::Translator,
};
use commonware_codec::{CodecShared, Read};
use commonware_macros::boxed;
use commonware_runtime::Handle;
use commonware_utils::{Widen, bitmap};
use core::{num::NonZeroUsize, ops::Range};
use std::collections::{BTreeMap, HashMap};
use tracing::{debug, warn};

type Error = crate::qmdb::Error<crate::mmr::Family>;

/// Configuration for initializing a [Db].
#[derive(Clone)]
pub struct Config<T: Translator, C> {
    /// Configuration for the variable-size operations log journal.
    pub log: JournalConfig<C>,

    /// The [Translator] used by the [Index].
    pub translator: T,

    /// Maximum number of entries in the `(location -> key)` cache used during init to resolve
    /// snapshot collisions without re-reading the log; `None` disables it.
    pub init_cache: Option<NonZeroUsize>,

    /// Size (in bytes) of the read buffer used to replay the log during init.
    pub init_buffer: NonZeroUsize,
}

/// A finalized batch of writes and deletes ready to be applied to the store.
pub struct Changeset<K: Key, V: CodecShared + Clone> {
    diff: BTreeMap<K, Option<V>>,
    metadata: Option<V>,
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
    K: Key,
    V: VariableValue,
    T: Translator,
{
    db: &'a Db<E, K, V, T>,
    diff: BTreeMap<K, Option<V>>,
}

impl<'a, E, K, V, T> Batch<'a, E, K, V, T>
where
    E: Context,
    K: Key,
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
    K: Key,
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

    /// Activity status of each retained operation.
    ///
    /// # Invariants
    ///
    /// - `bitmap.len() == log.size()`.
    /// - Bit `i` is set iff location `i` holds the current update of an active key, or is the
    ///   last commit.
    bitmap: bitmap::Prunable<BITMAP_CHUNK_BYTES>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    inactivity_floor_loc: Location,
}

impl<E, K, V, T> std::fmt::Debug for Db<E, K, V, T>
where
    E: Context,
    K: Key,
    V: VariableValue,
    T: Translator,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("bounds", &self.bounds())
            .field("inactivity_floor_loc", &self.inactivity_floor_loc())
            .finish_non_exhaustive()
    }
}

impl<E, K, V, T> Db<E, K, V, T>
where
    E: Context,
    K: Key,
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
        assert!(*loc < self.log.bounds().end);
        self.log.read(*loc).await.map_err(|e| match e {
            crate::journal::Error::ItemPruned(_) => Error::OperationPruned(loc),
            e => Error::Journal(e),
        })
    }

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and newest
    /// retained operations respectively.
    pub fn bounds(&self) -> std::ops::Range<Location> {
        let bounds = self.log.bounds();
        Location::new(bounds.start)..Location::new(bounds.end)
    }

    /// Return the Location of the next operation appended to this db.
    pub fn size(&self) -> Location {
        Location::new(self.log.size())
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    pub const fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V>, Error> {
        // The log always ends with a commit operation.
        let Operation::CommitFloor(metadata, _) = self.log.read(*self.size() - 1).await? else {
            unreachable!("last commit should be a commit floor operation");
        };

        Ok(metadata)
    }

    /// Prune historical operations prior to `prune_loc`. This does not affect the db's root
    /// or current snapshot.
    ///
    /// `prune` requires no prior commit. After a crash, the database remains recoverable;
    /// uncommitted operations are not guaranteed to survive.
    #[boxed]
    pub async fn prune(mut self, prune_loc: Location) -> Result<Self, Error> {
        if prune_loc > self.inactivity_floor_loc {
            return Err(Error::PruneBeyondMinRequired(
                prune_loc,
                self.inactivity_floor_loc,
            ));
        }

        // The floor justifying the boundary may exist only in buffered operations (it
        // advances before its batch is durable), and pruning does not guarantee buffered
        // appends are durable. Commit so the justification survives the prune.
        self.log = self.log.commit().await?;

        // Prune the log. The log will prune at section boundaries, so the actual oldest retained
        // location may be less than requested.
        let pruned;
        (self.log, pruned) = self.log.prune(*prune_loc).await?;
        if !pruned {
            return Ok(self);
        }

        let bounds = self.log.bounds();
        self.bitmap.prune_to_bit(bounds.start);
        let log_size = Location::new(bounds.end);
        let oldest_retained_loc = Location::new(bounds.start);
        debug!(
            ?log_size,
            ?oldest_retained_loc,
            ?prune_loc,
            "pruned inactive ops"
        );

        Ok(self)
    }

    /// Initializes a new [Db] with the given configuration.
    /// `Some(max_size)` selects the latest retained commit with at most `max_size` operations.
    /// `None` selects the latest retained state.
    #[boxed]
    pub async fn init(
        context: E,
        cfg: Config<T, <Operation<crate::mmr::Family, K, V> as Read>::Cfg>,
        max_size: Option<Location>,
    ) -> Result<Self, Error> {
        // Variable-journal recovery rebuilds item offsets before selecting a commit. Keep the
        // recovery owner unpublished until that commit and its replay floor are validated.
        crate::qmdb::validate_initialization_bound(max_size)?;
        let pending = Journal::<E, Operation<crate::mmr::Family, K, V>>::recover(
            context.child("log"),
            cfg.log,
            max_size.map(|size| *size),
        )
        .await?;
        let size = pending
            .last_matching(max_size.map_or(u64::MAX, |size| *size), |op| op.is_commit())
            .await?;
        let bounds = pending.bounds();
        let commit = if size == 0 {
            None
        } else {
            Some(pending.read(size - 1).await?)
        };
        crate::qmdb::validate_initialization_commit(
            bounds.start,
            size,
            bounds == (0..0),
            commit.as_ref(),
            true,
        )?;

        // Finishing recovery publishes the selected offset prefix before releasing later
        // value bytes.
        if size < bounds.end {
            warn!(
                journal_size = bounds.end,
                rewound_items = bounds.end - size,
                "rewinding journal items"
            );
        }
        let mut log = pending.finish(size).await?;
        if size == 0 {
            warn!("Log is empty, initializing new db");
            (log, _) = log
                .append(&Operation::CommitFloor(None, Location::new(0)))
                .await?;
        }

        // Persist recovery repairs and any genesis commit so the next startup need not repeat them.
        let log = log.sync().await?;

        let last_commit_loc =
            Location::new(log.size().checked_sub(1).expect("commit should exist"));

        // Build the snapshot only from the durable selected prefix.
        let cache_size = cfg.init_cache;
        let init_buffer = cfg.init_buffer;
        let mut snapshot = Index::new(context.child("snapshot"), cfg.translator);
        let op = log.read(*last_commit_loc).await?;
        let inactivity_floor_loc = op.has_floor().expect("last op should be a commit");

        // Seed the bitmap so its pruned prefix matches the retained log boundary. Operations
        // below the inactivity floor are inactive.
        let bounds = log.bounds();
        let pruned_chunks =
            (bounds.start / bitmap::Prunable::<BITMAP_CHUNK_BYTES>::CHUNK_SIZE_BITS) as usize;
        let mut bitmap = bitmap::Prunable::new_with_pruned_chunks(pruned_chunks)
            .expect("pruned chunk count fits in u64 bits");
        bitmap.extend_to(*inactivity_floor_loc);

        // Replay the log from the floor, appending each operation's status and clearing the bit
        // of any location it supersedes. The state after the last operation is each location's
        // final status.
        let active_keys = build_snapshot_from_log(
            inactivity_floor_loc,
            &log,
            &mut snapshot,
            init_buffer,
            cache_size,
            |is_active, old_loc| {
                bitmap.push(is_active);
                if let Some(loc) = old_loc {
                    bitmap.set_bit(*loc, false);
                }
            },
        )
        .await?;
        assert_eq!(bitmap.len(), bounds.end);

        Ok(Self {
            log,
            snapshot,
            active_keys,
            bitmap,
            inactivity_floor_loc,
        })
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    #[boxed]
    pub async fn sync(mut self) -> Result<Self, Error> {
        self.log = self.log.sync().await?;
        Ok(self)
    }

    /// Destroy the db, removing all data from disk.
    #[boxed]
    pub async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await.map_err(Into::into)
    }

    /// Applies a finalized batch to the in-memory database state and appends its operations to the
    /// journal, returning the range of written locations.
    ///
    /// This publishes the batch to the in-memory database state and appends it to the journal.
    /// Call [`Db::commit`] or [`Db::sync`], or await the handle returned by [`Db::start_sync`], to
    /// make the applied state durable.
    ///
    /// After its writes and before its commit operation, the batch walks the inactivity floor
    /// with [`Policy`]. If the batch leaves the store empty, the floor moves to its commit.
    ///
    /// When every batch since the initial commit uses
    /// [`Proportional`](crate::qmdb::floor::Proportional), each batch leaves the database's size at
    /// most `3 * n + 1` operations past its floor, for `n` active keys.
    #[boxed]
    pub async fn apply_batch<P>(
        mut self,
        batch: Changeset<K, V>,
        policy: &mut P,
    ) -> Result<(Self, Range<Location>), Error>
    where
        P: Policy<crate::mmr::Family, K, V>,
    {
        let start_loc = self.size();
        let Changeset { diff, metadata } = batch;

        let mut resolved = {
            // Resolve each written key to its applied update, if any, by reading its
            // translated-key bucket in rounds sized by the bucket's unresolved batch keys: a
            // sparse write stops at its matching update, while a batch covering the bucket reads
            // all its updates together.
            //
            // Keys sharing a translated key see the same bucket in the same order, so the
            // bucket's first location identifies it. Each source pairs a bucket's unread
            // locations with the number of its batch keys still unresolved. A key with an empty
            // bucket is absent and needs no read.
            let mut buckets = HashMap::<Location, usize>::new();
            let mut sources: Vec<(_, usize)> = Vec::new();
            for key in diff.keys() {
                let mut locations = self.snapshot.get(key);
                let Some(&first) = locations.next() else {
                    continue;
                };
                if let Some(&index) = buckets.get(&first) {
                    sources[index].1 += 1;
                } else {
                    buckets.insert(first, sources.len());
                    sources.push((core::iter::once(first).chain(locations.copied()), 1));
                }
            }

            // A round takes from every live source as many unread locations as it has
            // unresolved keys and reads them in one ascending batch. A source that yields
            // nothing has run out, so its remaining keys are absent, and it leaves at the next
            // round.
            let mut resolved = HashMap::new();
            let mut candidates = Vec::new();
            loop {
                candidates.clear();
                sources.retain(|(_, pending)| *pending > 0);
                for (index, (locations, pending)) in sources.iter_mut().enumerate() {
                    let before = candidates.len();
                    candidates.extend(locations.by_ref().take(*pending).map(|loc| (loc, index)));
                    if candidates.len() == before {
                        *pending = 0;
                    }
                }
                if candidates.is_empty() {
                    break;
                }
                candidates.sort_unstable_by_key(|(loc, _)| *loc);
                let positions: Vec<_> = candidates.iter().map(|(loc, _)| **loc).collect();
                let read = self.log.read_many(&positions).await?;

                // A read update resolves its key when the batch writes that key; a collision
                // sibling the batch leaves alone is passed over.
                for ((loc, index), op) in candidates.iter().zip(read) {
                    let key = op.into_key().expect("snapshot operation has key");
                    if diff.contains_key(&key) {
                        resolved.insert(key, *loc);
                        sources[*index].1 -= 1;
                    }
                }
            }
            resolved
        };

        // Generate operations in key order. Earlier writes can change a bucket's layout, but
        // each surviving original update still has its resolved location.
        let mut ops: Vec<Operation<crate::mmr::Family, K, V>> = Vec::with_capacity(diff.len() + 1);
        let mut made_inactive = 0usize;
        for (key, value) in diff {
            let new_loc = Location::new(*start_loc + Widen::widen(ops.len()));
            let old_loc = resolved.remove(&key);
            let matches = |loc: &Location| Some(*loc) == old_loc;
            if let Some(value) = value {
                if let Some(mut cursor) = self.snapshot.get_mut_or_insert(&key, new_loc) {
                    if cursor.find(matches) {
                        cursor.update(new_loc);
                    } else {
                        cursor.insert(new_loc);
                    }
                }
                if let Some(old_loc) = old_loc {
                    self.bitmap.set_bit(*old_loc, false);
                    made_inactive += 1;
                } else {
                    self.active_keys += 1;
                }
                self.bitmap.push(true);
                ops.push(Operation::Update(Update(key, value)));
            } else if let Some(old_loc) = old_loc {
                delete_known_loc(&mut self.snapshot, &key, old_loc);
                self.bitmap.set_bit(*old_loc, false);
                self.bitmap.push(false);
                ops.push(Operation::Delete(key));
                made_inactive += 2;
                self.active_keys -= 1;
            }
        }

        // The previous commit becomes inactive.
        self.bitmap.set_bit(*start_loc - 1, false);

        // Walk the floor toward the tip the writes reached, under the limits the policy sets for
        // the operations they made inactive.
        let tip = Location::new(*start_loc + Widen::widen(ops.len()));
        let Limits { entries, skips } = policy.limits(made_inactive);
        let mut walk = Walk::new(self.inactivity_floor_loc, tip, entries, skips);
        self.walk(&mut walk, policy, &mut ops).await?;
        self.inactivity_floor_loc = walk.floor;

        // The writes or the policy's evictions may leave the store empty.
        if self.is_empty() {
            self.inactivity_floor_loc = Location::new(*start_loc + Widen::widen(ops.len()));
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        }

        // Append the batch's operations and its commit with the new inactivity floor.
        self.bitmap.push(true);
        ops.push(Operation::CommitFloor(metadata, self.inactivity_floor_loc));
        (self.log, _) = self.log.append_many(Many::Flat(&ops)).await?;

        let end_loc = self.size();
        Ok((self, start_loc..end_loc))
    }

    /// Advance `walk` over the active updates below its end, deciding each one with `policy`.
    /// Each decision applies at once: the snapshot, the bitmap, and the key count change with it,
    /// and the update it writes or the delete it appends joins `ops`.
    ///
    /// `ops` holds the unappended operations starting at `log.size()`, and the bitmap covers them
    /// with the previous commit inactive.
    async fn walk<P>(
        &mut self,
        walk: &mut Walk<crate::mmr::Family>,
        policy: &mut P,
        ops: &mut Vec<Operation<crate::mmr::Family, K, V>>,
    ) -> Result<(), Error>
    where
        P: Policy<crate::mmr::Family, K, V>,
    {
        // The bitmap is exact after the writes, so the set bits from the floor are the active
        // updates the walk may decide, and which of them its limits let it reach is arithmetic
        // over their locations. Only those are read, though a policy may stop the walk before it
        // decides them all. Candidates in the batch's own region already have their operations
        // in memory.
        let start = self.log.size();
        let mut candidates = Vec::<u64>::with_capacity(walk.entries.min(self.active_keys));
        fill_from(
            &self.bitmap,
            *walk.floor,
            *walk.end,
            walk.entries,
            &mut candidates,
        );
        let reachable = walk.reachable(&candidates);

        // Each reached update appends at most one operation, and the commit follows.
        ops.reserve(reachable + 1);

        // Candidates ascend, so the reachable ones below `start` form a prefix the log serves in
        // one read; the rest are this batch's own writes, already in `ops`.
        let logged = candidates[..reachable].partition_point(|&loc| loc < start);
        let mut reads = self.log.read_many(&candidates[..logged]).await?.into_iter();

        // Decide the reachable candidates in location order, taking each update from the read
        // or from `ops`. A write relocates the key to the tip and an eviction removes it; either
        // way the candidate's own location becomes inactive. A stop leaves the update active at
        // the floor, where a later walk starts.
        for &loc in &candidates[..reachable] {
            let reached = walk.reach(Location::new(loc));
            assert!(reached, "candidate within the walk's reach");
            let op = if loc < start {
                reads.next().expect("one read per logged candidate")
            } else {
                ops[(loc - start) as usize].clone()
            };
            let Operation::Update(Update(key, value)) = op else {
                unreachable!("active candidate must be an update");
            };
            let new_loc = Location::new(start + Widen::widen(ops.len()));
            let action = policy
                .decide(Entry::new(Location::new(loc), &key, value))
                .into_action();
            let op = match action {
                Action::Write(value) => {
                    update_known_loc(&mut self.snapshot, &key, Location::new(loc), new_loc);
                    self.bitmap.push(true);
                    Operation::Update(Update(key, value))
                }
                Action::Evict => {
                    delete_known_loc(&mut self.snapshot, &key, Location::new(loc));
                    self.active_keys -= 1;
                    self.bitmap.push(false);
                    Operation::Delete(key)
                }
                Action::Stop => return Ok(()),
            };
            self.bitmap.set_bit(loc, false);
            ops.push(op);
            walk.decide();
        }

        // The first candidate the walk cannot reach ends it with the floor advanced by the
        // remaining skips. Without one, the window holds no further active update.
        match candidates.get(reachable) {
            Some(&beyond) => {
                let reached = walk.reach(Location::new(beyond));
                assert!(!reached, "candidate beyond the walk's reach");
            }
            None if walk.entries > 0 => walk.exhaust(),
            None => {}
        }
        Ok(())
    }

    /// Begin durably persisting the journal state published by prior [`Db::apply_batch`] calls.
    ///
    /// Awaiting the returned [Handle] provides the same durability guarantee as [Self::commit],
    /// plus a best-effort attempt to bound the recovery needed on startup. Use [Self::sync] to
    /// guarantee none is needed. A new sync waits for the prior sync before starting. Failures
    /// of the deferred durability work surface on the returned handle. A failed data sync also
    /// fails the next durability operation. A failed offsets or recovery-watermark sync is not
    /// observed by [Self::commit] and resurfaces on the next [Self::sync].
    #[boxed]
    pub async fn start_sync(mut self) -> Result<(Self, Handle<()>), Error> {
        let handle;
        (self.log, handle) = self.log.start_sync().await?;
        Ok((self, handle))
    }

    /// Durably commit the journal state published by prior [`Db::apply_batch`] calls.
    #[boxed]
    pub async fn commit(mut self) -> Result<Self, Error> {
        self.log = self.log.commit().await?;
        Ok(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        qmdb::{
            any::{
                batch::tests::{CountedValue, Evict, Growing},
                test::{
                    Choice, Script, assert_bits, assert_bound, churn, colliding_digest, counter,
                    keep, keys_after, randomized_churn, replay, walk_model,
                },
            },
            floor::{Bounded, Hold, Proportional},
        },
        translator::{OneCap, TwoCap},
    };
    use commonware_cryptography::{
        Hasher as _, Sha256,
        blake3::{Blake3, Digest},
        sha256,
    };
    use commonware_macros::{test_collect_traces, test_traced};
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner, Spawner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs},
        reschedule,
        telemetry::traces::collector::TraceStorage,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, test_rng};
    use core::{future::Future, hash::BuildHasher};
    use futures::FutureExt as _;
    use rand::RngExt as _;
    use rstest::rstest;
    use std::{
        cell::Cell,
        collections::BTreeSet,
        num::{NonZeroU16, NonZeroUsize},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    /// The type of the store used in tests.
    type TestStore = Db<deterministic::Context, Digest, Vec<u8>, TwoCap>;

    fn test_config(
        context: &deterministic::Context,
    ) -> Config<TwoCap, <Operation<crate::mmr::Family, Digest, Vec<u8>> as Read>::Cfg> {
        Config {
            log: JournalConfig {
                partition: "journal".into(),
                write_buffer: NZUsize!(64 * 1024),
                replay_buffer: NZUsize!(64 * 1024),
                compression: None,
                codec_config: ((), ((0..=10000).into(), ())),
                items_per_section: NZU64!(7),
                page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
            },
            translator: TwoCap,
            init_cache: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
        }
    }

    async fn create_test_store(context: deterministic::Context) -> TestStore {
        let cfg = test_config(&context);
        TestStore::init(context, cfg, None).await.unwrap()
    }

    async fn apply_entries(
        db: TestStore,
        iter: impl IntoIterator<Item = (Digest, Option<Vec<u8>>)> + Send,
    ) -> (TestStore, Range<Location>) {
        db.apply_batch(iter.into_iter().collect(), &mut Proportional)
            .await
            .unwrap()
    }

    #[test_traced]
    fn test_store_bounded_initialization_commit_selection() {
        for cap_case in 0..4 {
            deterministic::Runner::default().start(move |context| async move {
                // Persist two commits with distinct metadata and key state.
                let cfg = test_config(&context);
                let db = TestStore::init(context.child("seed"), cfg.clone(), None)
                    .await
                    .unwrap();
                let a = Blake3::hash(&[b"a"], &Sequential);
                let b = Blake3::hash(&[b"b"], &Sequential);
                let c = Blake3::hash(&[b"c"], &Sequential);
                let batch = db
                    .new_batch()
                    .update(a, vec![1])
                    .update(b, vec![2])
                    .finalize(Some(vec![10]));
                let (db, _) = db.apply_batch(batch, &mut Proportional).await.unwrap();
                let first_size = db.size();
                let batch = db
                    .new_batch()
                    .update(a, vec![3])
                    .delete(b)
                    .update(c, vec![4])
                    .finalize(Some(vec![20]));
                let (db, _) = db.apply_batch(batch, &mut Proportional).await.unwrap();
                let latest_size = db.size();
                _ = db.sync().await.unwrap();

                // Exact, in-between, equal-tip, and above-tip caps must select the latest commit at
                // or below the bound.
                let cap = match cap_case {
                    0 => first_size,
                    1 => first_size + 1,
                    2 => latest_size,
                    _ => Location::new(u64::MAX),
                };
                assert!(first_size + 1 < latest_size);
                let old = cap_case < 2;
                let expected_size = if old { first_size } else { latest_size };
                let db = TestStore::init(context.child("cap"), cfg.clone(), Some(cap))
                    .await
                    .unwrap();
                assert_eq!(db.size(), expected_size);
                assert_bitmap_consistent(&db).await;
                assert_eq!(
                    db.get_metadata().await.unwrap(),
                    Some(vec![if old { 10 } else { 20 }])
                );
                assert_eq!(
                    db.get(&a).await.unwrap(),
                    Some(vec![if old { 1 } else { 3 }])
                );
                assert_eq!(db.get(&b).await.unwrap(), old.then(|| vec![2]));
                assert_eq!(db.get(&c).await.unwrap(), (!old).then(|| vec![4]));

                // Selection is durable, and future appends continue from the selected commit.
                drop(db);
                let db = TestStore::init(context.child("reopen"), cfg.clone(), None)
                    .await
                    .unwrap();
                assert_eq!(db.size(), expected_size);
                assert_bitmap_consistent(&db).await;
                assert_eq!(
                    db.get(&a).await.unwrap(),
                    Some(vec![if old { 1 } else { 3 }])
                );
                assert_eq!(db.get(&b).await.unwrap(), old.then(|| vec![2]));
                assert_eq!(db.get(&c).await.unwrap(), (!old).then(|| vec![4]));
                let batch = db
                    .new_batch()
                    .update(a, vec![5])
                    .update(c, vec![6])
                    .finalize(None);
                let (db, _) = db.apply_batch(batch, &mut Proportional).await.unwrap();
                let appended_size = db.size();
                assert!(appended_size > expected_size);
                drop(db.commit().await.unwrap());
                let db = TestStore::init(context.child("after_append"), cfg, None)
                    .await
                    .unwrap();
                assert_eq!(db.size(), appended_size);
                assert_bitmap_consistent(&db).await;
                assert_eq!(db.get(&a).await.unwrap(), Some(vec![5]));
                assert_eq!(db.get(&b).await.unwrap(), old.then(|| vec![2]));
                assert_eq!(db.get(&c).await.unwrap(), Some(vec![6]));
            });
        }
    }

    #[test_traced]
    fn test_store_bounded_initialization_rejects_zero() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = test_config(&context);
            let db = TestStore::init(context.child("seed"), cfg.clone(), None)
                .await
                .unwrap();
            let key = Blake3::hash(&[b"key"], &Sequential);
            let (db, _) = apply_entries(db, [(key, Some(vec![1]))]).await;
            let size = db.size();
            _ = db.sync().await.unwrap();
            assert!(matches!(
                TestStore::init(context.child("zero"), cfg.clone(), Some(Location::new(0))).await,
                Err(Error::InvalidInitializationBound)
            ));
            let db = TestStore::init(context.child("unchanged"), cfg, None)
                .await
                .unwrap();
            assert_eq!(db.size(), size);
            assert_eq!(db.get(&key).await.unwrap(), Some(vec![1]));
        });
    }

    #[test_traced]
    fn test_store_bounded_initialization_rejects_pruned_floor() {
        deterministic::Runner::default().start(|context| async move {
            const KEYS: u64 = 64;
            let cfg = test_config(&context);
            let mut db = TestStore::init(context.child("seed"), cfg.clone(), None)
                .await
                .unwrap();
            let key = |i: u64| Blake3::hash(&[&i.to_be_bytes()], &Sequential);
            for value in [1, 2] {
                (db, _) = apply_entries(db, (0..KEYS).map(|i| (key(i), Some(vec![value])))).await;
            }
            let target = db.size();
            let target_floor = db.inactivity_floor_loc();
            let prune_loc = target_floor + KEYS / 2;
            assert!(prune_loc < target);
            let mut value = 2;
            while db.inactivity_floor_loc() < prune_loc {
                value += 1;
                assert!(value <= 10);
                (db, _) = apply_entries(db, (0..KEYS).map(|i| (key(i), Some(vec![value])))).await;
            }
            let db = db.prune(prune_loc).await.unwrap();
            let bounds = db.bounds();
            assert!(bounds.start > *target_floor && bounds.start < *target);
            _ = db.sync().await.unwrap();
            assert!(matches!(
                TestStore::init(context.child("cap"), cfg.clone(), Some(target)).await,
                Err(Error::HistoricalFloorPruned(size)) if size == target
            ));
            let db = TestStore::init(context.child("unchanged"), cfg, None)
                .await
                .unwrap();
            assert_eq!(db.bounds(), bounds);
            for i in 0..KEYS {
                assert_eq!(db.get(&key(i)).await.unwrap(), Some(vec![value]));
            }
        });
    }

    /// A store over a delayed-sync storage backend.
    type DelayedStore = Db<DelayedSyncContext<deterministic::Context>, Digest, Vec<u8>, TwoCap>;

    /// Open a [DelayedStore] whose blob syncs park on `pending`.
    ///
    /// Init durably persists the recovered database, so while syncs park the returned future
    /// must be driven with [drive_pending_syncs] (or the mock unblocked first). The journal
    /// uses large pages and sections: an apply that fills the write buffer or rolls the blob
    /// over waits for the in-flight sync, so mid-sync applies must stay clear of both.
    fn open_delayed_store(
        context: deterministic::Context,
        suffix: &str,
        pending: &PendingSyncs,
    ) -> impl Future<Output = Result<DelayedStore, Error>> {
        let cfg = Config {
            log: JournalConfig {
                partition: format!("journal-{suffix}"),
                write_buffer: NZUsize!(64 * 1024),
                replay_buffer: NZUsize!(64 * 1024),
                compression: None,
                codec_config: ((), ((0..=10000).into(), ())),
                items_per_section: NZU64!(1000),
                page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8)),
            },
            translator: TwoCap,
            init_cache: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
        };
        DelayedStore::init(
            DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            },
            cfg,
            None,
        )
    }

    /// Apply a single-key batch writing `key -> value`.
    async fn apply_write(db: DelayedStore, key: Digest, value: Vec<u8>) -> DelayedStore {
        let (db, _) = db
            .apply_batch([(key, Some(value))].into(), &mut Proportional)
            .await
            .unwrap();
        db
    }

    /// A sync handle must not block database use while the backend sync is pending.
    #[test_traced]
    fn test_store_start_sync_overlaps_work() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_store(ctx.child("delayed"), "start-sync-overlap", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            let key0 = Blake3::hash(&[&0u64.to_be_bytes()], &Sequential);
            let value0 = vec![1u8; 8];
            db = apply_write(db, key0, value0.clone()).await;

            let starts_before = pending.starts();
            let entered_before = pending.entered();
            let completions_before = pending.completions();
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(pending.starts() > starts_before);
            assert_eq!(pending.completions(), completions_before);

            // Observe the sync while the database keeps working.
            let waiter = ctx
                .child("await_sync")
                .spawn(|_| async move { handle.await.unwrap() });
            while pending.entered() == entered_before {
                reschedule().await;
            }

            // Reads and applies complete before the sync does.
            assert_eq!(db.get(&key0).await.unwrap(), Some(value0));
            let key1 = Blake3::hash(&[&1u64.to_be_bytes()], &Sequential);
            let value1 = vec![2u8; 8];
            db = apply_write(db, key1, value1.clone()).await;
            assert_eq!(
                pending.completions(),
                completions_before,
                "the database made progress while the sync was still in flight"
            );

            pending.unblock();
            waiter.await.unwrap();

            // The mid-sync batch is durable after the next start_sync completes.
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            handle.await.unwrap();
            let size = db.size();
            drop(db);

            let db = open_delayed_store(ctx.child("reopen"), "start-sync-overlap", &pending)
                .await
                .unwrap();
            assert_eq!(db.size(), size);
            assert_eq!(db.get(&key1).await.unwrap(), Some(value1));
            db.destroy().await.unwrap();
        });
    }

    /// A sync begun by `start_sync` that fails in flight surfaces the error through both the
    /// returned handle and the next durability operation.
    #[test_traced]
    fn test_store_start_sync_failure_propagates() {
        deterministic::Runner::default().start(|ctx| async move {
            // Pass syncs through so opening the database doesn't park.
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db = open_delayed_store(ctx.child("delayed"), "start-sync-fail", &pending)
                .await
                .unwrap();
            db = apply_write(
                db,
                Blake3::hash(&[&0u64.to_be_bytes()], &Sequential),
                vec![1u8; 8],
            )
            .await;

            // Arm all future syncs to resolve to an injected error.
            pending.arm_fail();

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(
                handle.await.is_err(),
                "the sync handle surfaces the failure"
            );
            let starts_before = pending.starts();
            // A failed mutable method consumes the database per the failures-are-fatal contract.
            assert!(
                db.commit().await.is_err(),
                "the next durability op surfaces the failed in-flight sync"
            );
            assert_eq!(
                pending.starts(),
                starts_before,
                "the surfaced error is the retained failure, not a fresh sync's"
            );
        });
    }

    #[test_collect_traces("WARN")]
    fn test_store_recovery_warns_when_discarding_uncommitted_suffix(traces: TraceStorage) {
        deterministic::Runner::default().start(|context| async move {
            let mut db = create_test_store(context.child("seed")).await;
            let key = Blake3::hash(&[b"uncommitted"], &Sequential);

            // A crash during apply_batch can persist an update before its trailing commit.
            (db.log, _) = db
                .log
                .append(&Operation::Update(Update(key, vec![7])))
                .await
                .unwrap();
            db.log = db.log.sync().await.unwrap();
            drop(db);

            let db = create_test_store(context.child("recover")).await;
            assert_eq!(*db.size(), 1);
            assert_eq!(db.get(&key).await.unwrap(), None);
        });
        traces
            .get_by_level(tracing::Level::WARN)
            .expect_event(|event| {
                let metadata = &event.metadata;
                metadata.content == "rewinding journal items"
                    && metadata.expect_field_exact("journal_size", "2").is_ok()
                    && metadata.expect_field_exact("rewound_items", "1").is_ok()
            })
            .unwrap();
    }

    /// State persisted via an awaited start_sync handle is recovered on reopen.
    #[test_traced]
    fn test_store_start_sync_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db = open_delayed_store(ctx.child("delayed"), "start-sync-recovery", &pending)
                .await
                .unwrap();
            let key = Blake3::hash(&[&0u64.to_be_bytes()], &Sequential);
            let value = vec![1u8; 8];
            db = apply_write(db, key, value.clone()).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            handle.await.unwrap();
            let size = db.size();
            drop(db);

            let db = open_delayed_store(ctx.child("reopen"), "start-sync-recovery", &pending)
                .await
                .unwrap();
            assert_eq!(db.size(), size);
            assert_eq!(db.get(&key).await.unwrap(), Some(value));
            db.destroy().await.unwrap();
        });
    }

    /// Pruning drains the in-flight sync before mutating storage.
    #[test_traced]
    fn test_store_start_sync_prune_waits() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_store(ctx.child("delayed"), "start-sync-prune", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            // Two batches so the floor walks leave a non-trivial prune target.
            db = apply_write(
                db,
                Blake3::hash(&[&0u64.to_be_bytes()], &Sequential),
                vec![1u8; 8],
            )
            .await;
            db = apply_write(
                db,
                Blake3::hash(&[&1u64.to_be_bytes()], &Sequential),
                vec![2u8; 8],
            )
            .await;

            let starts_before = pending.starts();
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(pending.starts() > starts_before);

            let floor = db.inactivity_floor_loc();
            assert!(*floor > 0);
            let db = {
                let mut prune = std::pin::pin!(db.prune(floor));
                assert!(
                    prune.as_mut().now_or_never().is_none(),
                    "prune proceeded while the started sync was pending"
                );
                pending.unblock();
                prune.await.unwrap()
            };
            handle.await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_store_construct_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let db = create_test_store(context.child("store").with_attribute("index", 0)).await;
            assert_eq!(db.bounds().end, 1);
            assert_eq!(db.log.bounds().start, 0);
            assert_eq!(db.inactivity_floor_loc(), 0);
            assert!(db.get_metadata().await.unwrap().is_none());
            let floor = db.inactivity_floor_loc();
            let db = db.prune(floor).await.unwrap();
            assert!(matches!(
                db.prune(Location::new(1)).await,
                Err(Error::PruneBeyondMinRequired(_, _))
            ));

            let db = create_test_store(context.child("store").with_attribute("index", 3)).await;

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = Digest::random(&mut context);
            let v1 = vec![1, 2, 3];
            let (db, _) = apply_entries(db, [(d1, Some(v1))]).await;
            drop(db);

            let db = create_test_store(context.child("store").with_attribute("index", 1)).await;
            assert_eq!(db.bounds().end, 1);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            let metadata = vec![1, 2, 3];
            let batch = db.new_batch().finalize(Some(metadata.clone()));
            let (db, range) = db.apply_batch(batch, &mut Proportional).await.unwrap();
            assert_eq!(range.start, 1);
            assert_eq!(range.end, 2);
            let db = db.commit().await.unwrap();
            assert_eq!(db.bounds().end, 2);
            let floor = db.inactivity_floor_loc();
            let db = db.prune(floor).await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));

            drop(db);
            let db = create_test_store(context.child("store").with_attribute("index", 2)).await;
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits on a
            // non-empty db.
            let (db, _) =
                apply_entries(db, [(Digest::random(&mut context), Some(vec![1, 2, 3]))]).await;
            let mut db = db.commit().await.unwrap();
            for _ in 1..100 {
                let merkleized = db.new_batch().finalize(None);
                (db, _) = db.apply_batch(merkleized, &mut Proportional).await.unwrap();
                db = db.commit().await.unwrap();
                // Distance should equal 3 after the second commit, with inactivity_floor
                // referencing the previous commit operation.
                assert!(db.bounds().end - db.inactivity_floor_loc <= 3);
                assert!(db.get_metadata().await.unwrap().is_none());
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_construct_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|mut ctx| async move {
            let db = create_test_store(ctx.child("store").with_attribute("index", 0)).await;

            // Ensure the store is empty
            assert_eq!(db.bounds().end, 1);
            assert_eq!(db.inactivity_floor_loc, 0);

            let key = Digest::random(&mut ctx);
            let value = vec![2, 3, 4, 5];

            // Attempt to get a key that does not exist
            let result = db.get(&key).await;
            assert!(result.unwrap().is_none());

            // Insert a key-value pair. apply_batch writes the Update, the floor walk's move, and
            // a CommitFloor: 3 new ops on top of the initial commit.
            let (db, _) = apply_entries(db, [(key, Some(value.clone()))]).await;

            assert_eq!(*db.bounds().end, 4);
            assert_eq!(*db.inactivity_floor_loc, 2);

            // Fetch the value
            let fetched_value = db.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Simulate commit failure: drop without commit.
            drop(db);

            // Re-open the store
            let db = create_test_store(ctx.child("store").with_attribute("index", 1)).await;

            // Ensure the re-opened store removed the uncommitted operations
            assert_eq!(*db.bounds().end, 1);
            assert_eq!(*db.inactivity_floor_loc, 0);
            assert!(db.get_metadata().await.unwrap().is_none());

            // Insert a key-value pair and persist with metadata.
            let metadata = vec![99, 100];
            let batch = db
                .new_batch()
                .update(key, value.clone())
                .finalize(Some(metadata.clone()));
            let (db, range) = db.apply_batch(batch, &mut Proportional).await.unwrap();
            assert_eq!(*range.start, 1);
            assert_eq!(*range.end, 4);
            let db = db.commit().await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));

            assert_eq!(*db.bounds().end, 4);
            assert_eq!(*db.inactivity_floor_loc, 2);

            // Re-open the store
            drop(db);
            let db = create_test_store(ctx.child("store").with_attribute("index", 2)).await;

            // Ensure the re-opened store retained the committed operations
            assert_eq!(*db.bounds().end, 4);
            assert_eq!(*db.inactivity_floor_loc, 2);

            // Fetch the value, ensuring it is still present
            let fetched_value = db.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Insert two new k/v pairs to force pruning of the first section.
            let (k1, v1) = (Digest::random(&mut ctx), vec![2, 3, 4, 5, 6]);
            let (k2, v2) = (Digest::random(&mut ctx), vec![6, 7, 8]);
            let (db, _) = apply_entries(db, [(k1, Some(v1.clone()))]).await;
            let (db, _) = apply_entries(db, [(k2, Some(v2.clone()))]).await;

            assert_eq!(*db.bounds().end, 10);
            assert_eq!(*db.inactivity_floor_loc, 5);

            // Each apply_entries writes a CommitFloor with None metadata, replacing
            // the previously committed metadata.
            assert_eq!(db.get_metadata().await.unwrap(), None);

            let db = db.commit().await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), None);

            // commit() is just an fsync now, so bounds and floor are unchanged.
            assert_eq!(*db.bounds().end, 10);
            assert_eq!(*db.inactivity_floor_loc, 5);

            // Ensure all keys can be accessed, despite the first section being pruned.
            assert_eq!(db.get(&key).await.unwrap().unwrap(), value);
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            // Update existing key with modified value.
            let mut v1_updated = db.get(&k1).await.unwrap().unwrap();
            v1_updated.push(7);
            let (db, _) = apply_entries(db, [(k1, Some(v1_updated))]).await;
            let db = db.commit().await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), vec![2, 3, 4, 5, 6, 7]);

            // Create new key.
            let k3 = Digest::random(&mut ctx);
            let (db, _) = apply_entries(db, [(k3, Some(vec![8]))]).await;
            let db = db.commit().await.unwrap();
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
                (db, _) = apply_entries(db, [(k, Some(v.clone()))]).await;
            }

            let iter = db.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            let db = db.commit().await.unwrap();
            db.sync().await.unwrap();

            // Re-open the store, prune it, then ensure it replays the log correctly.
            let db = create_test_store(ctx.child("store").with_attribute("index", 1)).await;
            let floor = db.inactivity_floor_loc();
            let db = db.prune(floor).await.unwrap();

            let iter = db.snapshot.get(&k);
            assert_eq!(iter.count(), 1);

            // Each apply_entries appends the Update, one move of it, and a CommitFloor. The walk
            // ends at the tip the writes reached, so it does not reach the moved Update. Total:
            // 1 (init) + 100 * 3 = 301.
            assert_eq!(*db.bounds().end, 301);

            // Only the last moved Update and CommitFloor are active, so the floor is 299.
            assert_eq!(*db.inactivity_floor_loc, 299);
            let floor = db.inactivity_floor_loc;

            // All blobs prior to the inactivity floor are pruned, so the oldest retained location
            // is the first in the last retained blob.
            assert_eq!(db.log.bounds().start, *floor - *floor % 7);

            db.destroy().await.unwrap();
        });
    }

    /// Each round of a batch's key resolution reads as many locations from a collision bucket, in
    /// bucket order, as the bucket has unresolved keys, independent of the bucket's size. The
    /// proportional walk then reads the updates it reaches.
    ///
    /// Each case rewrites the keys at `positions` of a bucket of `count` keys and expects the
    /// bucket's reads, the walk's reads, and the floor after the batch.
    #[rstest]
    // A head-key match reads one update; the proportional walk reads its two moves.
    #[case::head_of_8(8, &[0], 1, 2, 4, 4096)]
    #[case::head_of_64(64, &[0], 1, 2, 4, 4096)]
    // A key at position 5 resolves in the sixth round, each reading one location.
    #[case::sixth(8, &[5], 6, 2, 4, 1)]
    // The first round reads positions 0..3 and resolves two keys. The second reads position 3
    // and resolves the last.
    #[case::two_rounds(8, &[1, 2, 3], 4, 4, 9, 1)]
    // Rounds of three, three, and two locations read the whole bucket.
    #[case::whole_bucket(8, &[5, 6, 7], 8, 4, 6, 1)]
    #[test_traced("WARN")]
    fn test_store_collision_reads(
        #[case] count: u64,
        #[case] positions: &'static [usize],
        #[case] bucket_reads: u64,
        #[case] walk_reads: u64,
        #[case] floor: u64,
        #[case] value_len: usize,
    ) {
        deterministic::Runner::default().start(move |context| async move {
            let db = create_test_store(context.child("store")).await;
            let keys: Vec<_> = (0..count)
                .map(|i| {
                    let mut bytes = [0u8; 32];
                    bytes[..2].copy_from_slice(&[0xa5, 0x5a]);
                    bytes[24..].copy_from_slice(&i.to_be_bytes());
                    Digest::from(bytes)
                })
                .collect();
            let writes = keys
                .iter()
                .zip(0u8..)
                .map(|(key, i)| (*key, Some(vec![i; value_len])));
            let (db, _) = apply_entries(db, writes).await;

            // The keys lie at 1..count + 1 in key order. The previous commit's entry moves the
            // first to count + 1 in place, so the bucket lists it first and the rest by position.
            let bucket: Vec<_> = db.snapshot.get(&keys[0]).map(|loc| **loc).collect();
            let expected: Vec<_> = std::iter::once(count + 1).chain(2..=count).collect();
            assert_eq!(bucket, expected);
            assert_eq!(*db.inactivity_floor_loc(), 2);

            // The walk has one entry per rewrite plus one for the previous commit, and every
            // update it reaches lies below the batch.
            assert_eq!(walk_reads, Widen::widen(positions.len()) + 1);
            let before = counter(&context, "log_items_read_total");
            let writes = positions
                .iter()
                .map(|i| (keys[*i], Some(vec![0xff; value_len])));
            let (db, _) = apply_entries(db, writes).await;
            let reads = counter(&context, "log_items_read_total") - before;
            assert_eq!(reads, bucket_reads + walk_reads);
            assert_eq!(*db.inactivity_floor_loc(), floor);
            assert_eq!(db.active_keys, count as usize);
            for (i, key) in keys.iter().enumerate() {
                let value = if positions.contains(&i) {
                    0xff
                } else {
                    i as u8
                };
                assert_eq!(db.get(key).await.unwrap(), Some(vec![value; value_len]));
            }
            assert_bitmap_consistent(&db).await;
            drop(db.commit().await.unwrap());
            let db = create_test_store(context.child("reopened")).await;
            assert_eq!(
                db.get(&keys[positions[0]]).await.unwrap(),
                Some(vec![0xff; value_len])
            );
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_build_snapshot_keys_with_shared_prefix() {
        let executor = deterministic::Runner::default();
        executor.start(|mut ctx| async move {
            let db = create_test_store(ctx.child("store").with_attribute("index", 0)).await;

            let (k1, v1) = (Digest::random(&mut ctx), vec![1, 2, 3, 4, 5]);
            let (mut k2, v2) = (Digest::random(&mut ctx), vec![6, 7, 8, 9, 10]);

            // Ensure k2 shares 2 bytes with k1 (test DB uses `TwoCap` translator.)
            k2.0[0..2].copy_from_slice(&k1.0[0..2]);

            let (db, _) = apply_entries(db, [(k1, Some(v1.clone()))]).await;
            let (db, _) = apply_entries(db, [(k2, Some(v2.clone()))]).await;

            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            let db = db.commit().await.unwrap();
            db.sync().await.unwrap();

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
            let db = create_test_store(ctx.child("store").with_attribute("index", 0)).await;

            // Insert a key-value pair
            let k = Digest::random(&mut ctx);
            let v = vec![1, 2, 3, 4, 5];
            let (db, _) = apply_entries(db, [(k, Some(v.clone()))]).await;
            let db = db.commit().await.unwrap();

            // Fetch the value
            let fetched_value = db.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Delete the key
            assert!(db.get(&k).await.unwrap().is_some());
            let (db, _) = apply_entries(db, [(k, None)]).await;

            // Ensure the key is no longer present
            let fetched_value = db.get(&k).await.unwrap();
            assert!(fetched_value.is_none());
            assert!(db.get(&k).await.unwrap().is_none());

            // Commit the changes
            db.commit().await.unwrap();

            // Re-open the store and ensure the key is still deleted
            let db = create_test_store(ctx.child("store").with_attribute("index", 1)).await;
            let fetched_value = db.get(&k).await.unwrap();
            assert!(fetched_value.is_none());

            // Re-insert the key
            let (db, _) = apply_entries(db, [(k, Some(v.clone()))]).await;
            let fetched_value = db.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Commit the changes
            db.commit().await.unwrap();

            // Re-open the store and ensure the snapshot restores the key, after processing
            // the delete and the subsequent set.
            let db = create_test_store(ctx.child("store").with_attribute("index", 2)).await;
            let fetched_value = db.get(&k).await.unwrap();
            assert_eq!(fetched_value.unwrap(), v);

            // Delete a non-existent key (no-op)
            let k_n = Digest::random(&mut ctx);
            let (db, range) = apply_entries(db, [(k_n, None)]).await;
            assert_eq!(range.start, 9);
            assert_eq!(range.end, 11);
            let db = db.commit().await.unwrap();

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
            let db = create_test_store(ctx.child("store")).await;

            let k_a = Digest::random(&mut ctx);
            let k_b = Digest::random(&mut ctx);

            let v_a = vec![1];
            let v_b = vec![];
            let v_c = vec![4, 5, 6];

            let (db, _) = apply_entries(db, [(k_a, Some(v_a.clone()))]).await;
            let (db, _) = apply_entries(db, [(k_b, Some(v_b.clone()))]).await;

            let db = db.commit().await.unwrap();
            assert_eq!(*db.bounds().end, 7);
            assert_eq!(*db.inactivity_floor_loc, 3);
            assert_eq!(db.get(&k_a).await.unwrap().unwrap(), v_a);

            let (db, _) = apply_entries(db, [(k_b, Some(v_a.clone()))]).await;
            let (db, _) = apply_entries(db, [(k_a, Some(v_c.clone()))]).await;

            let db = db.commit().await.unwrap();
            assert_eq!(*db.bounds().end, 15);
            assert_eq!(*db.inactivity_floor_loc, 12);
            assert_eq!(db.get(&k_a).await.unwrap().unwrap(), v_c);
            assert_eq!(db.get(&k_b).await.unwrap().unwrap(), v_a);

            db.destroy().await.unwrap();
        });
    }

    /// Apply `writes` as one proportional batch and replay its operations into `live`.
    ///
    /// Asserts that the batch moves each update at most once. A key the batch writes may appear
    /// twice: its write and one move of that write.
    ///
    /// Asserts that the replayed keys are the keys of `live` with `writes` applied, and that the
    /// applied state satisfies [`assert_bound`]. Every batch since the initial commit must go
    /// through this function.
    async fn bounded(
        db: TestStore,
        live: &mut BTreeMap<Digest, Location>,
        writes: &[(Digest, Option<Vec<u8>>)],
    ) -> TestStore {
        let expected = keys_after(live, writes);
        let (db, range) = apply_entries(db, writes.iter().cloned()).await;
        let written: BTreeSet<_> = writes.iter().map(|(key, _)| *key).collect();
        let mut updated = BTreeMap::new();
        for loc in *range.start..*range.end {
            let loc = Location::new(loc);
            match db.get_op(loc).await.unwrap() {
                Operation::Update(Update(key, _)) => {
                    let count = updated.entry(key).or_insert(0usize);
                    *count += 1;
                    let limit = 1 + usize::from(written.contains(&key));
                    assert!(*count <= limit, "the batch moves an update of {key} twice");
                    live.insert(key, loc);
                }
                Operation::Delete(key) => {
                    live.remove(&key);
                }
                _ => {}
            }
        }
        assert_eq!(live.keys().copied().collect::<BTreeSet<_>>(), expected);
        assert_eq!(live.len(), db.active_keys);
        assert_bound(db.inactivity_floor_loc(), db.size(), live);
        db
    }

    /// Every batch of [`churn`], or of [`randomized_churn`] under `seed`, keeps the size at most
    /// `3 * n + 1` operations past the floor for `n` live keys.
    #[rstest]
    #[case::churn(None)]
    #[case::seed_0(Some(0))]
    #[case::seed_1(Some(1))]
    #[case::seed_7(Some(7))]
    #[case::seed_5133(Some(0x5133))]
    #[test_traced("WARN")]
    fn test_store_floor_bound(#[case] seed: Option<u64>) {
        let executor = seed.map_or_else(
            deterministic::Runner::default,
            deterministic::Runner::seeded,
        );
        executor.start(move |mut context| async move {
            let key = |i: u64| Blake3::hash(&[&i.to_be_bytes()], &Sequential);
            let value = |i: u64| i.to_be_bytes().to_vec();
            let db = create_test_store(context.child("store")).await;
            let db = match seed {
                None => churn(db, key, value, bounded).await,
                Some(_) => randomized_churn(&mut context, db, key, value, bounded).await,
            };
            assert_bitmap_consistent(&db).await;
            db.destroy().await.unwrap();
        });
    }

    /// A proportional batch has one entry for each operation it makes inactive: one for each
    /// update it supersedes, two for each delete (itself and the update it supersedes), and one
    /// for its previous commit. Its walk moves updates, including the batch's own written updates,
    /// and passes its own deletes up to the tip its writes reached. A custom policy with
    /// proportional limits (`scripted`) moves the same updates without deciding one.
    ///
    /// Each case seeds `n` keys with a held or proportional floor, writes `writes` (a seed index
    /// and a new value, or `None` to delete), and expects the batch's range, its floor, and the
    /// seed indices of the updates the walk moves, in order.
    #[rstest]
    // The deletes lie at 23..28 in key order. Their 2 * 5 entries and the previous commit's entry
    // move the updates at 2..13 to 28..39, so the commit at 39 records the floor 13.
    #[case::delete_first_and_last_four(
        20,
        false,
        vec![(0, None), (16, None), (17, None), (18, None), (19, None)],
        23..40,
        13,
        (1..12).collect(),
    )]
    // The 19 deletes lie at 23..42. The walk keeps the survivor, moving it to 42, and passes every
    // delete, so the commit at 43 records the floor 42, 2 operations below the size.
    #[case::delete_all_but_first(20, false, (1..20).map(|i| (i, None)).collect(), 23..44, 42, vec![0])]
    // Over six held updates at 1..7, two updates and a delete make four operations inactive, so
    // with the previous commit the walk moves five updates between the writes and the commit:
    // the three remaining seed updates and the two written updates. The floor ends past the last
    // written update, at 11.
    #[case::update_delete_update(
        6,
        true,
        vec![(0, Some(200)), (1, None), (2, Some(202))],
        8..17,
        11,
        vec![3, 4, 5, 0, 2],
    )]
    #[test_traced("WARN")]
    fn test_store_proportional_entries(
        #[case] n: u64,
        #[case] held: bool,
        #[case] writes: Vec<(usize, Option<u64>)>,
        #[case] range: Range<u64>,
        #[case] floor: u64,
        #[case] moved: Vec<usize>,
        #[values(false, true)] scripted: bool,
    ) {
        deterministic::Runner::default().start(move |context| async move {
            let db = open(context.child("store"), "proportional").await;
            let seed = seed(n);
            let db = if held {
                apply(db, seed.clone(), &mut Hold).await.0
            } else {
                // Seed 20 keys in key order at 1..21. The previous commit's entry moves the first
                // update to 21, and the commit lies at 22.
                let (db, _) = apply(db, seed.clone(), &mut Proportional).await;
                assert_eq!((*db.inactivity_floor_loc(), *db.size()), (2, 23));
                db
            };

            let writes: Vec<_> = writes
                .iter()
                .map(|&(i, value)| (seed[i].0, value.map(digest)))
                .collect();
            let (db, r) = if scripted {
                let mut policy = Script::proportional(|_: &sha256::Digest| Choice::Keep);
                apply(db, writes.clone(), &mut policy).await
            } else {
                apply(db, writes.clone(), &mut Proportional).await
            };
            assert_eq!(*r.start..*r.end, range);
            assert_eq!((*db.inactivity_floor_loc(), *db.size()), (floor, range.end));

            // The batch appends its writes in key order, the updates its walk moves with their
            // latest values, and its commit.
            let value = |i: usize| {
                writes
                    .iter()
                    .find(|(key, _)| *key == seed[i].0)
                    .map_or(seed[i].1, |(_, value)| *value)
            };
            let expected: Vec<_> = writes
                .iter()
                .map(|&(key, value)| {
                    value.map_or(Operation::Delete(key), |value| {
                        Operation::Update(Update(key, value))
                    })
                })
                .chain(
                    moved
                        .iter()
                        .map(|&i| Operation::Update(Update(seed[i].0, value(i).unwrap()))),
                )
                .chain([Operation::CommitFloor(None, Location::new(floor))])
                .collect();
            assert_eq!(Widen::widen(expected.len()), range.end - range.start);
            for (loc, op) in range.zip(expected) {
                assert_eq!(db.get_op(Location::new(loc)).await.unwrap(), op);
            }

            // The survivors keep their latest values.
            let mut active = 0;
            for (i, (key, _)) in seed.iter().enumerate() {
                let value = value(i);
                active += usize::from(value.is_some());
                assert_eq!(db.get(key).await.unwrap(), value);
            }
            assert_eq!(db.active_keys, active);
            assert_bitmap_consistent(&db).await;
            db.destroy().await.unwrap();
        });
    }

    /// Pruning to a floor advanced by applied-but-uncommitted entries must not durably outrun
    /// the last durable commit: after a crash, the recovered floor would lie below the pruned
    /// boundary and the store could never reopen.
    #[test_traced("WARN")]
    pub fn test_store_db_prune_after_unsynced_floor_recovery() {
        let executor = deterministic::Runner::default();
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut db = create_test_store(context.child("store").with_attribute("index", 0)).await;

            // Establish a durable state whose last commit declares an early inactivity floor.
            for i in 0u64..ELEMENTS {
                let k = Blake3::hash(&[&i.to_be_bytes()], &Sequential);
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                (db, _) = apply_entries(db, [(k, Some(v))]).await;
            }
            let mut db = db.commit().await.unwrap();
            let durable_floor = db.inactivity_floor_loc;

            // Apply (but do not commit) entries that advance the in-memory floor past the
            // durable commit's floor.
            for i in 0u64..ELEMENTS {
                let k = Blake3::hash(&[&i.to_be_bytes()], &Sequential);
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                (db, _) = apply_entries(db, [(k, Some(v))]).await;
            }
            let unsynced_floor = db.inactivity_floor_loc;
            assert!(unsynced_floor > durable_floor);

            // Prune to the in-memory floor, then crash before any further commit.
            let db = db.prune(unsynced_floor).await.unwrap();
            let op_count = db.bounds().end;
            drop(db);

            // Reopening must succeed: prune committed the buffered operations first, so the
            // replayed log reproduces the advanced floor.
            let db = create_test_store(context.child("store").with_attribute("index", 1)).await;
            assert_eq!(db.bounds().end, op_count);
            assert_eq!(db.inactivity_floor_loc, unsynced_floor);
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
                    let k = Blake3::hash(&[&i.to_be_bytes()], &Sequential);
                    let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                    batch = batch.update(k, v);
                }
                // Drop the batch without applying -- simulates a failure before apply.
            }
            drop(db);
            let mut db = create_test_store(context.child("store").with_attribute("index", 1)).await;
            assert_eq!(*db.bounds().end, 1);

            // Apply the updates and commit them.
            for i in 0u64..ELEMENTS {
                let k = Blake3::hash(&[&i.to_be_bytes()], &Sequential);
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                (db, _) = apply_entries(db, [(k, Some(v.clone()))]).await;
            }
            let mut db = db.commit().await.unwrap();

            // Update every 3rd key and commit.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Blake3::hash(&[&i.to_be_bytes()], &Sequential);
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                (db, _) = apply_entries(db, [(k, Some(v.clone()))]).await;
            }
            let mut db = db.commit().await.unwrap();
            assert_eq!(db.snapshot.items(), 1000);

            // Delete every 7th key and commit.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Blake3::hash(&[&i.to_be_bytes()], &Sequential);
                (db, _) = apply_entries(db, [(k, None)]).await;
            }
            let db = db.commit().await.unwrap();
            let final_count = db.bounds().end;
            let final_floor = db.inactivity_floor_loc;

            // Sync and reopen the store to ensure the state is preserved.
            db.sync().await.unwrap();
            let db = create_test_store(context.child("store").with_attribute("index", 2)).await;
            assert_eq!(db.bounds().end, final_count);
            assert_eq!(db.inactivity_floor_loc, final_floor);

            let floor = db.inactivity_floor_loc();
            let db = db.prune(floor).await.unwrap();
            assert_eq!(db.log.bounds().start, *final_floor - *final_floor % 7);
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_store_commit_after_sync_recovers_without_second_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = create_test_store(context.child("store").with_attribute("index", 0)).await;
            let key0 = Blake3::hash(&[&0u64.to_be_bytes()], &Sequential);
            let key1 = Blake3::hash(&[&1u64.to_be_bytes()], &Sequential);
            let value0 = vec![0, 1, 2];
            let value1 = vec![3, 4, 5, 6];

            // Commit and sync an initial update so restart recovery has an older watermark.
            let (db, _) = apply_entries(db, [(key0, Some(value0.clone()))]).await;
            let db = db.commit().await.unwrap();
            let db = db.sync().await.unwrap();

            // Persist a later commit without syncing; recovery must replay it after reopen.
            let (db, _) = apply_entries(db, [(key1, Some(value1.clone()))]).await;
            let db = db.commit().await.unwrap();
            let committed_end = db.bounds().end;
            let committed_floor = db.inactivity_floor_loc();
            drop(db);

            let db = create_test_store(context.child("store").with_attribute("index", 1)).await;
            assert_eq!(db.bounds().end, committed_end);
            assert_eq!(db.inactivity_floor_loc(), committed_floor);
            assert_eq!(db.get(&key0).await.unwrap(), Some(value0));
            assert_eq!(db.get(&key1).await.unwrap(), Some(value1));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_store_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|mut ctx| async move {
            let db = create_test_store(ctx.child("store").with_attribute("index", 0)).await;

            // Ensure the store is empty
            assert_eq!(db.bounds().end, 1);
            assert_eq!(db.inactivity_floor_loc, 0);

            let key = Digest::random(&mut ctx);
            let value = vec![2, 3, 4, 5];

            let batch = db.new_batch();

            // Attempt to get a key that does not exist
            let result = batch.get(&key).await;
            assert!(result.unwrap().is_none());

            // Insert a key-value pair
            let batch = batch.update(key, value.clone());

            assert_eq!(db.bounds().end, 1); // The batch is not applied yet
            assert_eq!(db.inactivity_floor_loc, 0);

            // Fetch the value
            let fetched_value = batch.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);
            let changeset = batch.finalize(None);
            db.apply_batch(changeset, &mut Proportional).await.unwrap();

            // Re-open the store
            let db = create_test_store(ctx.child("store").with_attribute("index", 1)).await;

            // Ensure the batch was not applied since we didn't commit.
            assert_eq!(db.bounds().end, 1);
            assert_eq!(db.inactivity_floor_loc, 0);
            assert!(db.get_metadata().await.unwrap().is_none());

            // Insert a key-value pair and persist the change.
            let metadata = vec![99, 100];
            let batch = db
                .new_batch()
                .update(key, value.clone())
                .finalize(Some(metadata.clone()));
            let (db, range) = db.apply_batch(batch, &mut Proportional).await.unwrap();
            assert_eq!(range.start, 1);
            assert_eq!(range.end, 4);
            let db = db.commit().await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata.clone()));
            drop(db);

            // Re-open the store
            let db = create_test_store(ctx.child("store").with_attribute("index", 2)).await;

            // Ensure the re-opened store retained the committed operations
            assert_eq!(db.bounds().end, 4);
            assert_eq!(db.inactivity_floor_loc, 2);

            // Fetch the value, ensuring it is still present
            let fetched_value = db.get(&key).await.unwrap();
            assert_eq!(fetched_value.unwrap(), value);

            // Destroy the store
            db.destroy().await.unwrap();
        });
    }

    /// A [Db] keyed by variable-length byte keys.
    type VecKeyStore = Db<deterministic::Context, Vec<u8>, Vec<u8>, TwoCap>;

    #[test_traced("DEBUG")]
    fn test_store_variable_length_keys() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Configure the operation codec for variable-length keys.
            let cfg = Config {
                log: JournalConfig {
                    partition: "journal".into(),
                    write_buffer: NZUsize!(64 * 1024),
                    replay_buffer: NZUsize!(64 * 1024),
                    compression: None,
                    codec_config: (((0..=64).into(), ()), ((0..=10000).into(), ())),
                    items_per_section: NZU64!(7),
                    page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                },
                translator: TwoCap,
                init_cache: Some(NZUsize!(1024)),
                init_buffer: NZUsize!(1 << 21),
            };

            // Commit two keys of different lengths that share a translated prefix.
            let db = VecKeyStore::init(
                context.child("store").with_attribute("index", 0),
                cfg.clone(),
                None,
            )
            .await
            .unwrap();
            let short = b"key".to_vec();
            let long = b"key-extended".to_vec();
            let batch = db
                .new_batch()
                .update(short.clone(), vec![1])
                .update(long.clone(), vec![2])
                .finalize(None);
            let (db, _) = db.apply_batch(batch, &mut Proportional).await.unwrap();
            let db = db.commit().await.unwrap();
            assert_eq!(db.get(&short).await.unwrap(), Some(vec![1]));
            assert_eq!(db.get(&long).await.unwrap(), Some(vec![2]));
            drop(db);

            // Reopen the store and verify both committed values.
            let db =
                VecKeyStore::init(context.child("store").with_attribute("index", 1), cfg, None)
                    .await
                    .unwrap();
            assert_eq!(db.get(&short).await.unwrap(), Some(vec![1]));
            assert_eq!(db.get(&long).await.unwrap(), Some(vec![2]));
            db.destroy().await.unwrap();
        });
    }

    /// A store keyed by SHA-256 digests whose translator buckets keys by their first byte.
    type PolicyStore<V> = Db<deterministic::Context, sha256::Digest, V, OneCap>;

    async fn open<V: VariableValue + Read<Cfg = ()>>(
        context: deterministic::Context,
        partition: &str,
    ) -> PolicyStore<V> {
        let cfg = Config {
            log: JournalConfig {
                partition: partition.into(),
                write_buffer: NZUsize!(64 * 1024),
                replay_buffer: NZUsize!(64 * 1024),
                compression: None,
                codec_config: ((), ()),
                items_per_section: NZU64!(7),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            },
            translator: OneCap,
            init_cache: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
        };
        PolicyStore::init(context, cfg, None).await.unwrap()
    }

    fn digest(i: u64) -> sha256::Digest {
        Sha256::hash(&[&i.to_be_bytes()], &Sequential)
    }

    /// Return writes of `n` keys in ascending order. The `i`th write has the value
    /// `digest(100 + i)`.
    fn seed(n: u64) -> Vec<(sha256::Digest, Option<sha256::Digest>)> {
        let mut keys: Vec<_> = (0..n).map(digest).collect();
        keys.sort();
        (100..)
            .zip(keys)
            .map(|(i, key)| (key, Some(digest(i))))
            .collect()
    }

    /// Apply `writes` with `policy` and without metadata.
    async fn apply<V, P>(
        db: PolicyStore<V>,
        writes: impl IntoIterator<Item = (sha256::Digest, Option<V>)>,
        policy: &mut P,
    ) -> (PolicyStore<V>, Range<Location>)
    where
        V: VariableValue,
        P: Policy<crate::mmr::Family, sha256::Digest, V>,
    {
        db.apply_batch(writes.into_iter().collect(), policy)
            .await
            .unwrap()
    }

    /// [`Hold`] keeps the inherited floor while the batch's writes apply, and moves it to the new
    /// commit location when the batch empties the store.
    #[test_traced("WARN")]
    fn test_store_policy_hold() {
        deterministic::Runner::default().start(|context| async move {
            // Seed four updates with a held floor.
            let db = open(context.child("store"), "hold").await;
            let seed = seed(4);
            let (db, _) = apply(db, seed.clone(), &mut Hold).await;
            let floor = db.inactivity_floor_loc();

            // Hold the floor for a batch that updates, deletes, and creates keys.
            let created = digest(4);
            let writes = [
                (seed[0].0, Some(digest(200))),
                (seed[1].0, None),
                (created, Some(digest(104))),
            ];
            let (db, _) = apply(db, writes, &mut Hold).await;

            // The writes apply and the untouched keys keep their values.
            assert_eq!(db.inactivity_floor_loc(), floor);
            let expected = [
                (seed[0].0, Some(digest(200))),
                (seed[1].0, None),
                seed[2],
                seed[3],
                (created, Some(digest(104))),
            ];
            for (key, value) in expected {
                assert_eq!(db.get(&key).await.unwrap(), value);
            }

            // Deleting every key moves the floor to the new commit location.
            let deletes = [seed[0].0, seed[2].0, seed[3].0, created].map(|key| (key, None));
            let (db, _) = apply(db, deletes, &mut Hold).await;
            assert!(db.is_empty());
            assert_eq!(db.inactivity_floor_loc(), db.size() - 1);
            db.destroy().await.unwrap();
        });
    }

    /// A policy that stops at the first active update leaves the floor at its location and the
    /// update in place. The next batch's policy decides that update without spending a skip.
    #[test_traced("WARN")]
    fn test_store_policy_stop() {
        deterministic::Runner::default().start(|context| async move {
            // Seed four updates in key order at 1..5 with a held floor.
            let db = open(context.child("store"), "stop").await;
            let seed = seed(4);
            let (db, _) = apply(db, seed.clone(), &mut Hold).await;
            let (key, value) = (seed[0].0, seed[0].1.unwrap());

            // Pass the initial commit and stop at the first update.
            let mut policy = Script::new(usize::MAX, u64::MAX, |_: &sha256::Digest| Choice::Stop);
            let (db, range) = apply(db, [], &mut policy).await;
            let first = Location::new(1);
            assert_eq!(policy.visited, [(first, key, value)]);

            // The batch appends only its commit and moves the floor to the stopped update's
            // location.
            assert_eq!(*range.start..*range.end, 6..7);
            assert_eq!(db.inactivity_floor_loc(), first);

            // A policy of the next batch decides the stopped update without spending a skip.
            let mut policy = Script::new(1, 0, keep);
            let (db, _) = apply(db, [], &mut policy).await;
            assert_eq!(policy.visited, [(first, key, value)]);
            assert_eq!(*db.inactivity_floor_loc(), 2);
            for (key, value) in seed {
                assert_eq!(db.get(&key).await.unwrap(), value);
            }
            assert_bitmap_consistent(&db).await;
            db.destroy().await.unwrap();
        });
    }

    /// A proportional move probes the snapshot index once, when it rewrites the update's slot.
    #[test_traced("WARN")]
    fn test_store_proportional_probes_snapshot_once() {
        // A translator that counts its key transforms, one per snapshot probe.
        #[derive(Clone)]
        struct CountingTranslator(Arc<AtomicUsize>);

        impl Translator for CountingTranslator {
            type Key = u8;

            fn transform(&self, key: &[u8]) -> u8 {
                self.0.fetch_add(1, Ordering::Relaxed);
                OneCap.transform(key)
            }
        }

        impl BuildHasher for CountingTranslator {
            type Hasher = <OneCap as BuildHasher>::Hasher;

            fn build_hasher(&self) -> Self::Hasher {
                OneCap.build_hasher()
            }
        }

        deterministic::Runner::default().start(|context| async move {
            type CountedStore = Db<deterministic::Context, Digest, Vec<u8>, CountingTranslator>;
            let lookups = Arc::new(AtomicUsize::new(0));
            let cfg = test_config(&context);
            let db = CountedStore::init(
                context,
                Config {
                    log: cfg.log,
                    translator: CountingTranslator(lookups.clone()),
                    init_cache: cfg.init_cache,
                    init_buffer: cfg.init_buffer,
                },
                None,
            )
            .await
            .unwrap();

            // Seed three keys in one translated-key bucket at 1..4 with a held floor.
            let writes = (0..3).map(|i| {
                let mut key = [0xAA; 32];
                key[31] = i;
                (Digest::from(key), Some(vec![i]))
            });
            let (db, _) = db.apply_batch(writes.collect(), &mut Hold).await.unwrap();

            // An empty batch moves one update for its previous commit.
            lookups.store(0, Ordering::Relaxed);
            let (db, range) = db
                .apply_batch(core::iter::empty().collect(), &mut Proportional)
                .await
                .unwrap();
            assert_eq!(*range.end - *range.start, 2);
            assert_eq!(lookups.load(Ordering::Relaxed), 1);
            assert_bitmap_consistent(&db).await;
            db.destroy().await.unwrap();
        });
    }

    /// A policy that replaces an update writes its value for the key at the tip.
    #[test_traced("WARN")]
    fn test_store_policy_replace() {
        deterministic::Runner::default().start(|context| async move {
            // Seed three updates in key order at 1..4 with a held floor.
            let db = open(context.child("store"), "replace").await;
            let seed = seed(3);
            let (db, _) = apply(db, seed.clone(), &mut Hold).await;
            let tip = db.size();

            // Keep the first and last updates and replace the second.
            let (replaced, value) = (seed[1].0, digest(201));
            let mut policy = Script::new(usize::MAX, u64::MAX, move |key: &sha256::Digest| {
                if *key == replaced {
                    Choice::Replace(value)
                } else {
                    Choice::Keep
                }
            });
            let (db, range) = apply(db, [], &mut policy).await;
            assert_eq!(policy.locations(), [1, 2, 3].map(Location::new));
            assert_eq!(db.inactivity_floor_loc(), tip);

            // The replacement takes the second update's place among the moves to the tip.
            assert_eq!(*range.start..*range.end, 5..9);
            let writes = [seed[0], (replaced, Some(value)), seed[2]];
            for (loc, (key, value)) in (5..).zip(writes) {
                let op = db.get_op(Location::new(loc)).await.unwrap();
                assert_eq!(op, Operation::Update(Update(key, value.unwrap())));
                assert_eq!(db.get(&key).await.unwrap(), value);
            }
            assert_bitmap_consistent(&db).await;
            db.destroy().await.unwrap();
        });
    }

    /// A policy that evicts every update it reaches receives the previously applied,
    /// colliding-key, and batch-written updates in location order. Values read from the log
    /// arrive with no clone, and the batch's own value is cloned once. The evictions empty the
    /// store.
    #[test_traced("WARN")]
    fn test_store_policy_evicts_owned() {
        deterministic::Runner::default().start(|context| async move {
            let colliding = |i| colliding_digest(0xAA, i);
            let other = colliding_digest(0xBB, 0);

            // Seed three keys in one translated-key bucket and one other key at 1..5 with a held
            // floor.
            let db = open(context.child("store"), "evict").await;
            let seed = [colliding(0), colliding(1), colliding(2), other]
                .into_iter()
                .zip(0u8..)
                .map(|(key, tag)| (key, Some(CountedValue::new(tag))));
            let (db, _) = apply(db, seed, &mut Hold).await;

            // The batch rewrites the first colliding key at 6, and the policy evicts every active
            // update, including that write.
            let mut policy = Evict::default();
            let write = (colliding(0), Some(CountedValue::new(20)));
            let (db, range) = apply(db, [write], &mut policy).await;

            // Evictions arrive in location order. Values read from the log move out of the reads,
            // and the batch's own value is copied once from its unappended operation.
            let evicted: Vec<_> = policy
                .evicted
                .iter()
                .map(|(loc, key, value, before, after)| (**loc, *key, value.0, *before, *after))
                .collect();
            assert_eq!(
                evicted,
                [
                    (2, colliding(1), 1, 0, 0),
                    (3, colliding(2), 2, 0, 0),
                    (4, other, 3, 0, 0),
                    (6, colliding(0), 20, 1, 1),
                ]
            );

            // The batch appends its write, a delete of each evicted key, and its commit. The
            // empty store commits the commit's own location as the floor.
            assert_eq!(*range.start..*range.end, 6..12);
            let Operation::Update(Update(key, value)) = db.get_op(Location::new(6)).await.unwrap()
            else {
                panic!("expected the write at 6");
            };
            assert_eq!((key, value.0), (colliding(0), 20));
            for (loc, evicted) in (7..).zip([colliding(1), colliding(2), other, colliding(0)]) {
                let op = db.get_op(Location::new(loc)).await.unwrap();
                assert!(matches!(op, Operation::Delete(key) if key == evicted));
            }
            let op = db.get_op(Location::new(11)).await.unwrap();
            assert!(matches!(op, Operation::CommitFloor(None, floor) if *floor == 11));

            // Every key reads `None`.
            for (_, key, ..) in &policy.evicted {
                assert!(db.get(key).await.unwrap().is_none());
            }
            assert!(db.is_empty());
            assert_bitmap_consistent(&db).await;
            db.destroy().await.unwrap();
        });
    }

    /// A walk leaves the value of a batch write it cannot reach uncloned. On a fresh store with
    /// no skips, the write at 1 lies inside the window but past the inactive commit at 0.
    #[test_traced("WARN")]
    fn test_store_unreachable_own_write_is_not_cloned() {
        deterministic::Runner::default().start(|context| async move {
            let db = open::<CountedValue>(context.child("store"), "unreachable-clone").await;
            let value = CountedValue::new(7);
            let witness = value.clone();
            assert_eq!(witness.clones(), 1);

            // The window ends at min(2, 0 + 0 + 2) = 2, so the write at 1 is a candidate, but
            // reaching it costs the skip the policy lacks: the floor stays at 0 and nothing is
            // decided. The walk copies only the operations of candidates it reaches, so the count
            // stays at the witness's own clone.
            let mut policy = Bounded {
                entries: 2,
                skips: 0,
            };
            let (db, range) = apply(db, [(digest(0), Some(value))], &mut policy).await;
            assert_eq!(*range.start..*range.end, 1..3);
            assert_eq!(*db.inactivity_floor_loc(), 0);
            assert_eq!(witness.clones(), 1);

            // The batch appends only its write and its commit.
            let Operation::Update(Update(key, value)) = db.get_op(Location::new(1)).await.unwrap()
            else {
                panic!("expected the write at 1");
            };
            assert_eq!((key, value.0), (digest(0), 7));
            let op = db.get_op(Location::new(2)).await.unwrap();
            assert!(matches!(op, Operation::CommitFloor(None, floor) if *floor == 0));
            assert_bitmap_consistent(&db).await;
            db.destroy().await.unwrap();
        });
    }

    /// A policy in a batch with writes passes the locations the writes supersede as inactive,
    /// keeps or evicts the previously applied updates it reaches, and decides the batch's own
    /// updates. The result survives commit, reopen, and prune.
    #[test_traced("WARN")]
    fn test_store_policy_keep_evict_and_recover() {
        deterministic::Runner::default().start(|context| async move {
            // Seed four updates in key order at 1..5 with a held floor.
            let child = |index| context.child("store").with_attribute("index", index);
            let db = open(child(0), "recover").await;
            let seed = seed(4);
            let (db, _) = apply(db, seed.clone(), &mut Hold).await;
            assert_eq!(*db.size(), 6);

            // The batch updates the second key, deletes the third, and creates a fifth. Its
            // operations follow key order from 6, so its updates lie at 6 and 7 and its delete at 8.
            let created = digest(4);
            let writes = [
                (seed[1].0, Some(digest(201))),
                (seed[2].0, None),
                (created, Some(digest(104))),
            ];
            let mut written = [writes[0], writes[2]];
            written.sort();
            assert!(written.iter().all(|(key, _)| *key < seed[2].0));

            // The policy spends its four skips on the initial commit, the two locations the writes
            // supersede, and the seed commit. It keeps the first update, evicts the last seeded
            // update, and keeps both updates the batch wrote.
            let evicted = seed[3].0;
            let mut policy = Script::new(usize::MAX, 4, move |key: &sha256::Digest| {
                if *key == evicted {
                    Choice::Evict
                } else {
                    Choice::Keep
                }
            });
            let (db, _) = apply(db, writes, &mut policy).await;
            let visited: Vec<_> = [(1, seed[0]), (4, seed[3]), (6, written[0]), (7, written[1])]
                .into_iter()
                .map(|(loc, (key, value))| (Location::new(loc), key, value.unwrap()))
                .collect();
            assert_eq!(policy.visited, visited);

            // No skip remains for the batch's delete at 8, so the floor stops there, one short of
            // the tip the writes reached.
            assert_eq!(*db.inactivity_floor_loc(), 8);
            let expected = [
                seed[0],
                (seed[1].0, Some(digest(201))),
                (seed[2].0, None),
                (evicted, None),
                (created, Some(digest(104))),
            ];
            for (key, value) in expected {
                assert_eq!(db.get(&key).await.unwrap(), value);
            }

            // The state survives commit and reopen.
            let db = db.commit().await.unwrap();
            let (size, floor) = (db.size(), db.inactivity_floor_loc());
            drop(db);
            let db: PolicyStore<sha256::Digest> = open(child(1), "recover").await;
            assert_eq!((db.size(), db.inactivity_floor_loc()), (size, floor));
            for (key, value) in expected {
                assert_eq!(db.get(&key).await.unwrap(), value);
            }

            // The state survives prune and reopen.
            let db = db.prune(floor).await.unwrap();
            drop(db);
            let db: PolicyStore<sha256::Digest> = open(child(2), "recover").await;
            assert_eq!((db.size(), db.inactivity_floor_loc()), (size, floor));
            for (key, value) in expected {
                assert_eq!(db.get(&key).await.unwrap(), value);
            }
            assert_bitmap_consistent(&db).await;
            db.destroy().await.unwrap();
        });
    }

    /// The Store's walk reads only the candidates its limits let it reach, a stricter bound than
    /// the [`Policy`] contract's window. Candidates in the batch's own writes are already in
    /// memory, so a batch without writes reads at most the updates it reaches, and a policy that
    /// keeps every update it is offered reads each of them exactly once.
    ///
    /// Each case seeds `n` keys and then rewrites every `step`th key in each of `rounds` batches,
    /// all with a held floor, leaving the active updates at `active` and the size at `tip`. Each
    /// pair of `entries` and `skips` runs on a fresh store with that layout.
    #[rstest]
    // Seed 100 updates at 1..101, then rewrite every fourth key at 102..127.
    #[case::sparse(
        100,
        4,
        1,
        (1..101).filter(|loc| loc % 4 != 1).chain(102..127).collect(),
        128,
        &[0, 1, 10, 74, 75, 100, 200],
        &[0, 1, 2, 5, 30, u64::MAX],
    )]
    // Rewrite one key 19 times. The log holds the initial commit at 0, superseded updates and
    // commits at 1..39, the only active update at 39, and a commit at 40.
    #[case::long_gap(1, 1, 19, vec![39], 41, &[0, 1, 2], &[0, 1, 38, 39, 40, u64::MAX])]
    #[test_traced("WARN")]
    fn test_store_policy_reads_reached_candidates(
        #[case] n: u64,
        #[case] step: usize,
        #[case] rounds: usize,
        #[case] active: Vec<u64>,
        #[case] tip: u64,
        #[case] entries: &'static [usize],
        #[case] skips: &'static [u64],
    ) {
        deterministic::Runner::default().start(move |context| async move {
            let reads = || counter(&context, "log_items_read_total");
            let child = |index| context.child("store").with_attribute("index", index);
            let seed = seed(n);
            let rewrites: Vec<_> = seed
                .iter()
                .step_by(step)
                .map(|(key, _)| (*key, Some(digest(500))))
                .collect();
            let mut trial = 0;
            for &entries in entries {
                for &skips in skips {
                    let mut db = open(child(trial), &format!("reached-{trial}")).await;
                    trial += 1;
                    (db, _) = apply(db, seed.clone(), &mut Hold).await;
                    for _ in 0..rounds {
                        (db, _) = apply(db, rewrites.clone(), &mut Hold).await;
                    }
                    assert_eq!(*db.size(), tip);

                    // The walk decides and reaches what [`walk_model`] predicts, and reads each
                    // update it decides once.
                    let before = reads();
                    let mut policy = Script::new(entries, skips, keep);
                    let (db, _) = apply(db, [], &mut policy).await;
                    let read = reads() - before;
                    let (floor, decided) = walk_model(&active, 0, tip, entries, skips, &[]);
                    assert_eq!(
                        read,
                        Widen::widen(decided.len()),
                        "entries={entries} skips={skips}"
                    );
                    let decided: Vec<_> = decided.into_iter().map(Location::new).collect();
                    assert_eq!(
                        policy.locations(),
                        decided,
                        "entries={entries} skips={skips}"
                    );
                    assert_eq!(*db.inactivity_floor_loc(), floor);
                    db.destroy().await.unwrap();
                }
            }
        });
    }

    /// Under every pair of limits, a policy in a batch without writes, and in one that updates,
    /// deletes, and creates keys, decides the updates and reaches the floor that [`walk_model`]
    /// predicts over the active updates below the tip of the batch's writes, including the
    /// updates the batch wrote. Each decided update moves to the tip with its value.
    #[test_traced("WARN")]
    fn test_store_policy_limits() {
        deterministic::Runner::default().start(|context| async move {
            // Lay out the initial commit at 0, superseded updates at 1..4, active updates at
            // 4..7, the seed commit at 7, active updates at 8..11, and the last commit at 11.
            let seed = seed(6);
            let updates: Vec<_> = (200..)
                .zip(&seed[..3])
                .map(|(i, (key, _))| (*key, Some(digest(i))))
                .collect();
            let applied: Vec<(u64, sha256::Digest, sha256::Digest)> = (4..7)
                .chain(8..11)
                .zip(seed[3..].iter().chain(&updates))
                .map(|(loc, (key, value))| (loc, *key, value.unwrap()))
                .collect();

            // The batch with writes updates the keys at 4 and 8, deletes the key at 5, and
            // creates two keys. Its five operations follow key order from 12, so the tip its
            // writes reach is 17.
            let mut writes = vec![
                (seed[3].0, Some(digest(300))),
                (seed[0].0, Some(digest(301))),
                (seed[4].0, None),
                (digest(6), Some(digest(302))),
                (digest(7), Some(digest(303))),
            ];
            writes.sort();

            let mut trial = 0;
            for writes in [Vec::new(), writes] {
                // The active updates below the tip are the applied updates of keys the batch does
                // not write and the batch's own updates.
                let tip = 12 + Widen::widen(writes.len());
                let mut live: BTreeMap<u64, (sha256::Digest, sha256::Digest)> = applied
                    .iter()
                    .filter(|(_, key, _)| writes.iter().all(|(written, _)| written != key))
                    .map(|(loc, key, value)| (*loc, (*key, *value)))
                    .collect();
                for (loc, (key, value)) in (12..).zip(&writes) {
                    if let Some(value) = value {
                        live.insert(loc, (*key, *value));
                    }
                }
                let active: Vec<u64> = live.keys().copied().collect();
                assert_eq!(active.len(), 6 + usize::from(!writes.is_empty()));

                for entries in 0..=8 {
                    for skips in (0..=12).chain([u64::MAX]) {
                        let child = context.child("store").with_attribute("index", trial);
                        let db = open(child, &format!("limits-{trial}")).await;
                        trial += 1;
                        let (db, _) = apply(db, seed.clone(), &mut Hold).await;
                        let (db, _) = apply(db, updates.clone(), &mut Hold).await;
                        assert_eq!((*db.inactivity_floor_loc(), *db.size()), (0, 12));

                        // The floor and the decided updates match [`walk_model`].
                        let (expected, decisions) =
                            walk_model(&active, 0, tip, entries, skips, &[]);
                        let decided: Vec<_> = decisions
                            .iter()
                            .map(|loc| (Location::new(*loc), live[loc].0, live[loc].1))
                            .collect();
                        let mut policy = Script::new(entries, skips, keep);
                        let (db, range) = apply(db, writes.clone(), &mut policy).await;
                        let limits =
                            format!("writes={} entries={entries} skips={skips}", writes.len());
                        assert_eq!(policy.visited, decided, "{limits}");
                        assert_eq!(*db.inactivity_floor_loc(), expected, "{limits}");

                        // Each decided update moves to the tip with its value after the writes
                        // and before the commit.
                        assert_eq!(
                            *range.start..*range.end,
                            12..tip + 1 + Widen::widen(decided.len())
                        );
                        for (loc, (_, key, value)) in (tip..).zip(&decided) {
                            let op = db.get_op(Location::new(loc)).await.unwrap();
                            assert_eq!(op, Operation::Update(Update(*key, *value)));
                        }
                        for (key, value) in live.values() {
                            assert_eq!(db.get(key).await.unwrap(), Some(*value));
                        }
                        for (key, _) in writes.iter().filter(|(_, value)| value.is_none()) {
                            assert_eq!(db.get(key).await.unwrap(), None);
                        }
                        assert_eq!(db.active_keys, live.len());
                        assert_bitmap_consistent(&db).await;
                        db.destroy().await.unwrap();
                    }
                }
            }
        });
    }

    /// A policy decides the batch's own updates like applied ones: keeping one moves it to the
    /// tip, replacing one writes the policy's value at the tip, evicting one deletes its key even
    /// when the batch created it, and stopping at one leaves the floor at its location.
    #[test_traced("WARN")]
    fn test_store_policy_decides_own_writes() {
        deterministic::Runner::default().start(|context| async move {
            let key = |i: u8| sha256::Digest::from([i; 32]);
            let child = |index| context.child("store").with_attribute("index", index);

            // Seed four keys at 1..5 with a held floor. The seed commit lies at 5.
            let db = open(child(0), "own").await;
            let seed = [1, 2, 4, 5].map(|i| (key(i), Some(digest(u64::from(i)))));
            let (db, _) = apply(db, seed, &mut Hold).await;
            assert_eq!(*db.size(), 6);

            // The batch rewrites every seeded key and creates key 3. In key order its updates lie
            // at 6..11, and they supersede 1..5.
            let written = |i: u8| digest(100 + u64::from(i));
            let writes = [1, 2, 3, 4, 5].map(|i| (key(i), Some(written(i))));

            // The policy spends its six skips on 0..6, then keeps key 1, replaces key 2, evicts
            // keys 3 and 4, and stops at key 5.
            let replacement = digest(200);
            let mut policy = Script::new(usize::MAX, 6, move |k: &sha256::Digest| {
                if *k == key(1) {
                    Choice::Keep
                } else if *k == key(2) {
                    Choice::Replace(replacement)
                } else if *k == key(5) {
                    Choice::Stop
                } else {
                    Choice::Evict
                }
            });
            let (db, range) = apply(db, writes, &mut policy).await;
            let visited: Vec<_> = (6..)
                .zip(1..=5)
                .map(|(loc, i)| (Location::new(loc), key(i), written(i)))
                .collect();
            assert_eq!(policy.visited, visited);
            assert_eq!(*db.inactivity_floor_loc(), 10);

            // The decisions follow the writes in decision order. The stopped update stays at 10.
            assert_eq!(*range.start..*range.end, 6..16);
            let expected = [
                Operation::Update(Update(key(1), written(1))),
                Operation::Update(Update(key(2), replacement)),
                Operation::Delete(key(3)),
                Operation::Delete(key(4)),
                Operation::CommitFloor(None, Location::new(10)),
            ];
            for (loc, expected) in (11..).zip(expected) {
                assert_eq!(db.get_op(Location::new(loc)).await.unwrap(), expected);
            }
            let values = [
                (key(1), Some(written(1))),
                (key(2), Some(replacement)),
                (key(3), None),
                (key(4), None),
                (key(5), Some(written(5))),
            ];
            for (key, value) in values {
                assert_eq!(db.get(&key).await.unwrap(), value);
            }
            assert_eq!(db.active_keys, 3);
            assert_bitmap_consistent(&db).await;

            // The state survives commit and reopen, and the next batch's policy decides the
            // stopped update without spending a skip.
            let db = db.commit().await.unwrap();
            drop(db);
            let db: PolicyStore<sha256::Digest> = open(child(1), "own").await;
            assert_eq!((*db.size(), *db.inactivity_floor_loc()), (16, 10));
            for (key, value) in values {
                assert_eq!(db.get(&key).await.unwrap(), value);
            }
            assert_bitmap_consistent(&db).await;
            let mut policy = Script::new(1, 0, keep);
            let (db, _) = apply(db, [], &mut policy).await;
            assert_eq!(policy.visited, [(Location::new(10), key(5), written(5))]);
            assert_eq!(*db.inactivity_floor_loc(), 11);
            db.destroy().await.unwrap();
        });
    }

    /// A batch reads its policy's limits once.
    #[test_traced("WARN")]
    fn test_store_policy_reads_limits_once() {
        deterministic::Runner::default().start(|context| async move {
            // Seed four updates with a held floor.
            let db = open(context.child("store"), "limits").await;
            let (db, _) = apply(db, seed(4), &mut Hold).await;

            // A policy that allows one entry on its only limits read decides one update.
            let mut policy = Growing {
                exact: 1,
                reads: Cell::new(0),
                decided: 0,
            };
            let (db, _) = apply(db, [], &mut policy).await;
            assert_eq!(policy.reads.get(), 1);
            assert_eq!(policy.decided, 1);
            db.destroy().await.unwrap();
        });
    }

    /// Assert that the activity bitmap, the snapshot, and the active key count of `db` are exact
    /// against a replay of its retained log.
    ///
    /// The bitmap covers the log and has pruned only whole chunks below the log's start. Every
    /// unpruned bit is set if and only if its location holds a live update or the last commit,
    /// and every live update lies at or above the inactivity floor. The snapshot maps each live
    /// key to its update and holds no other entry.
    async fn assert_bitmap_consistent<E, K, V, T>(db: &Db<E, K, V, T>)
    where
        E: Context,
        K: Key,
        V: VariableValue,
        T: Translator,
    {
        let bounds = db.log.bounds();
        assert_eq!(db.bitmap.len(), bounds.end);
        let chunk_bits = bitmap::Prunable::<BITMAP_CHUNK_BYTES>::CHUNK_SIZE_BITS;
        assert_eq!(
            db.bitmap.pruned_bits(),
            bounds.start / chunk_bits * chunk_bits
        );
        let positions: Vec<u64> = (bounds.start..bounds.end).collect();
        let ops = db.log.read_many(&positions).await.unwrap();
        let mut live = BTreeMap::new();
        replay(&mut live, Location::new(bounds.start), &ops);
        let floor = db.inactivity_floor_loc();
        assert!(
            live.values().all(|loc| *loc >= floor),
            "a live update lies below the floor {floor}",
        );
        assert_bits(&db.bitmap, &live);
        assert_eq!(db.active_keys, live.len());
        assert_eq!(db.snapshot.items(), live.len());
        for (key, loc) in &live {
            assert!(
                db.snapshot.get(key).any(|entry| entry == loc),
                "snapshot misses the live update at {loc}",
            );
        }
    }

    /// Over random batches of updates, deletes, and recreations of colliding keys, each followed by
    /// an empty batch whose policy keeps, replaces, evicts, or stops, the log replay matches the
    /// bitmap and the snapshot, and the store serves the modeled values. Pruning to the floor and
    /// reopening after a commit preserve that.
    #[test_traced]
    fn test_store_bitmap_tracks_activity() {
        struct BitmapPolicy<'a> {
            action: usize,
            expected: &'a mut BTreeMap<Digest, Vec<u8>>,
            decisions: &'a mut [usize; 4],
        }

        impl Policy<crate::mmr::Family, Digest, Vec<u8>> for BitmapPolicy<'_> {
            fn evicts(&self) -> bool {
                true
            }

            fn limits(&self, _: usize) -> Limits {
                Limits {
                    entries: 3,
                    skips: u64::MAX,
                }
            }

            fn decide<'a>(
                &mut self,
                entry: Entry<'a, crate::mmr::Family, Digest, Vec<u8>>,
            ) -> crate::qmdb::floor::Decision<'a, Vec<u8>> {
                self.decisions[self.action] += 1;
                match self.action {
                    0 => entry.keep(),
                    1 => {
                        let value = vec![0xFF];
                        self.expected.insert(*entry.key(), value.clone());
                        entry.replace(value)
                    }
                    2 => {
                        self.expected.remove(entry.key());
                        entry.evict().0
                    }
                    _ => entry.stop(),
                }
            }
        }

        deterministic::Runner::default().start(|context| async move {
            let mut rng = test_rng();
            let mut db = create_test_store(context.child("store").with_attribute("index", 0)).await;

            // A small key universe whose keys share 3 translated prefixes, so batches routinely
            // update, delete, and recreate colliding keys.
            let keys: Vec<Digest> = (0u8..24)
                .map(|i| {
                    let mut key = Blake3::hash(&[&[i]], &Sequential);
                    key.0[0..2].copy_from_slice(&[0, i % 3]);
                    key
                })
                .collect();
            let mut expected = BTreeMap::new();
            let mut decisions = [0; 4];

            // After each phase, the log replay matches the bitmap and the snapshot, and the store
            // serves exactly the modeled values.
            let assert_state = async |db: &TestStore, expected: &BTreeMap<Digest, Vec<u8>>| {
                assert_bitmap_consistent(db).await;
                assert_eq!(db.active_keys, expected.len());
                for key in &keys {
                    assert_eq!(db.get(key).await.unwrap(), expected.get(key).cloned());
                }
            };
            for round in 0..60u64 {
                let mut changes = Vec::new();
                for _ in 0..rng.random_range(0..12) {
                    let key = keys[rng.random_range(0..keys.len())];
                    if rng.random_bool(0.3) {
                        changes.push((key, None));
                        expected.remove(&key);
                    } else {
                        let value = round.to_be_bytes().to_vec();
                        changes.push((key, Some(value.clone())));
                        expected.insert(key, value);
                    }
                }
                (db, _) = apply_entries(db, changes).await;
                assert_state(&db, &expected).await;
                let mut policy = BitmapPolicy {
                    action: round as usize % 4,
                    expected: &mut expected,
                    decisions: &mut decisions,
                };
                (db, _) = db
                    .apply_batch(core::iter::empty().collect(), &mut policy)
                    .await
                    .unwrap();
                assert_state(&db, &expected).await;

                if round % 10 == 9 {
                    let floor = db.inactivity_floor_loc();
                    db = db.prune(floor).await.unwrap();
                    assert_state(&db, &expected).await;
                }
                if round % 20 == 19 {
                    db.commit().await.unwrap().sync().await.unwrap();
                    db = create_test_store(
                        context.child("store").with_attribute("index", round + 1),
                    )
                    .await;
                    assert_state(&db, &expected).await;
                }
            }
            assert!(decisions.into_iter().all(|count| count > 0));
            db.destroy().await.unwrap();
        });
    }

    /// Pruning past a whole bitmap chunk drops it, and reopening rebuilds the same unpruned bits
    /// and values.
    #[test_traced("WARN")]
    fn test_store_bitmap_chunk_prune_recovery() {
        deterministic::Runner::default().start(|context| async move {
            // Seed 300 keys at 1..301 and rewrite them at 302..602 with a held floor. An empty
            // batch with unlimited limits passes 0..302, keeps the rewrites by moving them to
            // 603..903, and reaches the tip of its writes, 603. Its commit lies at 903.
            let db = open(context.child("seed"), "bitmap-chunk").await;
            let writes = seed(300);
            let (db, _) = apply(db, writes.clone(), &mut Hold).await;
            let rewrites: Vec<_> = writes
                .iter()
                .map(|(key, _)| (*key, Some(digest(500))))
                .collect();
            let (db, _) = apply(db, rewrites, &mut Hold).await;
            let mut policy = Bounded {
                entries: usize::MAX,
                skips: u64::MAX,
            };
            let (db, _) = apply(db, [], &mut policy).await;
            assert_eq!((*db.inactivity_floor_loc(), *db.size()), (603, 904));

            // Pruning to the floor retains the log section starting at 602 and drops the bitmap's
            // first 512-bit chunk.
            let db = db.commit().await.unwrap();
            let floor = db.inactivity_floor_loc();
            let db = db.prune(floor).await.unwrap();
            assert_eq!(db.log.bounds().start, 602);
            assert_eq!(db.bitmap.pruned_bits(), 512);
            assert_bitmap_consistent(&db).await;
            let bits: Vec<_> = (512..904).map(|loc| db.bitmap.get_bit(loc)).collect();
            drop(db);

            // Reopening prunes the same chunk and rebuilds the same bits and values.
            let db: PolicyStore<sha256::Digest> =
                open(context.child("reopen"), "bitmap-chunk").await;
            assert_eq!(db.bitmap.pruned_bits(), 512);
            assert_eq!(db.bitmap.len(), 904);
            let reopened: Vec<_> = (512..904).map(|loc| db.bitmap.get_bit(loc)).collect();
            assert_eq!(reopened, bits);
            assert_bitmap_consistent(&db).await;
            for (key, _) in writes {
                assert_eq!(db.get(&key).await.unwrap(), Some(digest(500)));
            }
            db.destroy().await.unwrap();
        });
    }

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_read_futures_are_send(db: TestStore, key: Digest, loc: Location) {
        is_send(db.get(&key));
        is_send(db.get_metadata());
        is_send(db.prune(loc));
    }

    #[allow(dead_code)]
    fn assert_sync_is_send(db: TestStore) {
        is_send(db.sync());
    }

    #[allow(dead_code)]
    fn assert_write_futures_are_send(
        db: Db<deterministic::Context, Digest, Vec<u8>, TwoCap>,
        key: Digest,
        value: Vec<u8>,
    ) {
        is_send(db.get(&key));
        let batch = db.new_batch();
        is_send(batch.get(&key));
        is_send(db.apply_batch(Changeset::from([(key, Some(value))]), &mut Proportional));
    }

    #[allow(dead_code)]
    fn assert_commit_is_send(db: Db<deterministic::Context, Digest, Vec<u8>, TwoCap>) {
        is_send(db.commit());
    }
}
