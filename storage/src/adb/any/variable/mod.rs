//! An authenticated database (ADB) that provides succinct proofs of _any_ value ever associated
//! with a key, where values can have varying sizes.
//!
//! _If the values you wish to store all have the same size, use the dbs in [crate::adb::any::fixed]
//! instead for better performance._

use crate::{
    adb::{
        operation::variable::Operation,
        store::{self, Db},
        Error,
    },
    index::{Cursor, Index as _, Unordered as Index},
    journal::contiguous::variable::{Config as JournalConfig, Journal},
    mmr::{
        journaled::{Config as MmrConfig, Mmr},
        Location, Position, Proof, StandardHasher as Standard,
    },
    translator::Translator,
};
use commonware_codec::{Codec, Encode as _, Read};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage, ThreadPool};
use commonware_utils::{Array, NZUsize};
use futures::{future::TryFutureExt, pin_mut, try_join, StreamExt};
use std::{
    collections::HashMap,
    num::{NonZeroU64, NonZeroUsize},
};
use tracing::{debug, warn};

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot.
const SNAPSHOT_READ_BUFFER_SIZE: usize = 1 << 16;

/// Configuration for an `Any` authenticated db.
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

/// A key-value ADB based on an MMR over its log of operations, supporting authentication of any
/// value ever associated with a key.
pub struct Any<E: RStorage + Clock + Metrics, K: Array, V: Codec, H: CHasher, T: Translator> {
    /// An MMR over digests of the operations applied to the db.
    ///
    /// # Invariant
    ///
    /// The number of leaves in this MMR always equals the number of operations in the unpruned
    /// `log`.
    mmr: Mmr<E, H>,

    /// A (pruned) log of all operations applied to the db in order of occurrence.
    log: Journal<E, Operation<K, V>>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    inactivity_floor_loc: Location,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location in the log containing its most recent update.
    ///
    /// # Invariant
    ///
    /// Only references operations of type Operation::Update.
    pub(super) snapshot: Index<T, Location>,

    /// The number of _steps_ to raise the inactivity floor. Each step involves moving exactly one
    /// active operation to tip.
    pub(crate) steps: u64,

    /// The location of the last commit operation (if any exists).
    pub(crate) last_commit: Option<Location>,

    /// Cryptographic hasher to re-use within mutable operations requiring digest computation.
    pub(super) hasher: Standard<H>,
}

impl<E: RStorage + Clock + Metrics, K: Array, V: Codec, H: CHasher, T: Translator>
    Any<E, K, V, H, T>
{
    /// Returns a [Any] adb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: Config<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mut hasher = Standard::<H>::new();

        let mmr = Mmr::init(
            context.with_label("mmr"),
            &mut hasher,
            MmrConfig {
                journal_partition: cfg.mmr_journal_partition,
                metadata_partition: cfg.mmr_metadata_partition,
                items_per_blob: cfg.mmr_items_per_blob,
                write_buffer: cfg.mmr_write_buffer,
                thread_pool: cfg.thread_pool,
                buffer_pool: cfg.buffer_pool.clone(),
            },
        )
        .await?;

        let log = Journal::init(
            context.with_label("log"),
            JournalConfig {
                partition: cfg.log_partition,
                items_per_section: cfg.log_items_per_section,
                compression: cfg.log_compression,
                codec_config: cfg.log_codec_config,
                buffer_pool: cfg.buffer_pool,
                write_buffer: cfg.log_write_buffer,
            },
        )
        .await?;

        // Build snapshot from the log
        let snapshot = Index::init(context.with_label("snapshot"), cfg.translator);

        let db = Self {
            mmr,
            log,
            inactivity_floor_loc: Location::new_unchecked(0),
            steps: 0,
            last_commit: None,
            snapshot,
            hasher,
        };

        db.build_snapshot_from_log().await
    }

    /// Builds the database's `snapshot` by replaying the log from inception, while also:
    ///   - trimming any uncommitted operations from the log,
    ///   - adding log operations to the MMR if they are missing,
    ///   - removing any elements from the MMR that don't remain in the log after trimming.
    ///
    /// # Post-condition
    ///
    /// * The number of operations in the log and the number of leaves in the MMR are equal.
    /// * `last_commit` is set to the location of the last commit operation.
    /// * `inactivity_floor_loc` is set to the inactivity floor.
    async fn build_snapshot_from_log(mut self) -> Result<Self, Error> {
        // The number of leaves (operations) in the MMR.
        let mut mmr_leaves = self.mmr.leaves();
        // The first location in the log.
        let start_loc = match self.log.oldest_retained_pos() {
            Some(loc) => loc,
            None => self.log.size(),
        };
        // The number of operations in the log.
        let mut log_size = Location::new_unchecked(start_loc);
        // The location of the first operation to follow the last known commit point.
        let mut after_last_commit: Option<Location> = None;
        // The set of operations that have not yet been committed.
        let mut uncommitted_ops = HashMap::new();
        // The inactivity floor location from the last commit.
        let mut inactivity_floor_loc = Location::new_unchecked(0);

        // Replay the log from the start to build the snapshot, keeping track of any uncommitted
        // operations that must be rolled back, and any log operations that need to be re-added to the MMR.
        {
            let stream = self
                .log
                .replay(start_loc, NZUsize!(SNAPSHOT_READ_BUFFER_SIZE))
                .await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                let (loc, op) = result?;

                let loc = Location::new_unchecked(loc); // location of the current operation.
                if after_last_commit.is_none() {
                    after_last_commit = Some(loc);
                }

                log_size = loc + 1;

                if log_size > mmr_leaves {
                    warn!(?loc, "operation was missing from MMR");
                    self.mmr.add(&mut self.hasher, &op.encode()).await?;
                    mmr_leaves += 1;
                }

                match op {
                    Operation::Delete(key) => {
                        let result = self.get_key_loc(&key).await?;
                        if let Some(old_loc) = result {
                            uncommitted_ops.insert(key, (Some(old_loc), None));
                        } else {
                            uncommitted_ops.remove(&key);
                        }
                    }
                    Operation::Update(key, _) => {
                        let result = self.get_key_loc(&key).await?;
                        if let Some(old_loc) = result {
                            uncommitted_ops.insert(key, (Some(old_loc), Some(loc)));
                        } else {
                            uncommitted_ops.insert(key, (None, Some(loc)));
                        }
                    }
                    Operation::CommitFloor(_, floor_loc) => {
                        inactivity_floor_loc = floor_loc;

                        // Apply all uncommitted operations.
                        for (key, (old_loc, new_loc)) in uncommitted_ops.iter() {
                            if let Some(old_loc) = old_loc {
                                if let Some(new_loc) = new_loc {
                                    Self::update_loc(&mut self.snapshot, key, *old_loc, *new_loc);
                                } else {
                                    Self::delete_loc(&mut self.snapshot, key, *old_loc);
                                }
                            } else {
                                assert!(new_loc.is_some());
                                self.snapshot.insert(key, new_loc.unwrap());
                            }
                        }
                        uncommitted_ops.clear();
                        after_last_commit = None;
                    }
                    _ => unreachable!("unexpected operation type at location {loc}"),
                }
            }
        }

        // Rewind the operations log if necessary.
        if let Some(end_loc) = after_last_commit {
            assert!(!uncommitted_ops.is_empty());
            warn!(
                op_count = uncommitted_ops.len(),
                log_size = *end_loc,
                "rewinding over uncommitted operations at end of log"
            );
            self.log.rewind(*end_loc).await?;
            self.log.sync().await?;
            log_size = end_loc;
        }

        // Pop any MMR elements that are ahead of the last log commit point.
        if mmr_leaves > log_size {
            let leaves_to_pop = (*mmr_leaves - *log_size) as usize;
            warn!(leaves_to_pop, "popping uncommitted MMR operations");
            self.mmr.pop(leaves_to_pop).await?;
        }

        // Confirm post-conditions hold.
        assert_eq!(log_size, Location::try_from(self.mmr.size()).unwrap());
        assert_eq!(*log_size, self.log.size());

        // Update the inactivity floor location and last commit
        self.inactivity_floor_loc = inactivity_floor_loc;
        self.last_commit = log_size.checked_sub(1);

        debug!(?log_size, "build_snapshot_from_log complete");

        Ok(self)
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        let iter = self.snapshot.get(key);
        for &loc in iter {
            if let Some(v) = self.get_from_loc(key, loc).await? {
                return Ok(Some(v));
            }
        }

        Ok(None)
    }

    /// Get the value of the operation with location `loc` in the db.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [Error::LocationOutOfBounds] if `loc` >= [Self::op_count].
    /// Returns [Error::OperationPruned] if the location precedes the oldest retained location.
    pub async fn get_loc(&self, loc: Location) -> Result<Option<V>, Error> {
        if !loc.is_valid() {
            return Err(Error::Mmr(crate::mmr::Error::LocationOverflow(loc)));
        }
        let op_count = self.op_count();
        if loc >= op_count {
            return Err(Error::LocationOutOfBounds(loc, op_count));
        }
        let pruning_boundary = match self.oldest_retained_loc() {
            Some(oldest) => oldest,
            None => op_count,
        };
        if loc < pruning_boundary {
            return Err(Error::OperationPruned(loc));
        }

        let op = self.log.read(*loc).await.map_err(Error::Journal)?;
        Ok(op.into_value())
    }

    /// Returns the location of the operation that set the key's current value, or None if the key
    /// isn't currently assigned any value.
    pub async fn get_key_loc(&self, key: &K) -> Result<Option<Location>, Error> {
        let iter = self.snapshot.get(key);
        for &loc in iter {
            if self.get_from_loc(key, loc).await?.is_some() {
                return Ok(Some(loc));
            }
        }

        Ok(None)
    }

    /// Remove the location `delete_loc` from the snapshot if it's associated with `key`.
    fn delete_loc(snapshot: &mut Index<T, Location>, key: &K, delete_loc: Location) {
        let Some(mut cursor) = snapshot.get_mut(key) else {
            return;
        };

        if cursor.find(|&loc| loc == delete_loc) {
            cursor.delete();
        }
    }

    /// Update the location associated with `key` with value `old_loc` to `new_loc`. If there is no
    /// such key or value, this is a no-op.
    fn update_loc(
        snapshot: &mut Index<T, Location>,
        key: &K,
        old_loc: Location,
        new_loc: Location,
    ) {
        let Some(mut cursor) = snapshot.get_mut(key) else {
            return;
        };

        if cursor.find(|&loc| loc == old_loc) {
            cursor.update(new_loc);
        }
    }

    /// Get the value of the operation with location `loc` in the db if it matches `key`.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [Error::LocationOutOfBounds] if `loc` >= [Self::op_count].
    /// Returns [Error::UnexpectedData] if the location does not reference an Update operation.
    async fn get_from_loc(&self, key: &K, loc: Location) -> Result<Option<V>, Error> {
        if !loc.is_valid() {
            return Err(Error::Mmr(crate::mmr::Error::LocationOverflow(loc)));
        }
        let op_count = self.op_count();
        if loc >= op_count {
            return Err(Error::LocationOutOfBounds(loc, op_count));
        }

        let op = self.log.read(*loc).await?;
        let Operation::Update(k, v) = op else {
            return Err(Error::UnexpectedData(loc));
        };
        if k != *key {
            return Ok(None);
        }
        Ok(Some(v))
    }

    /// Get the number of operations that have been applied to this db, including those that are not
    /// yet committed.
    pub fn op_count(&self) -> Location {
        Location::new_unchecked(self.log.size())
    }

    /// Whether the db currently has no active keys.
    pub fn is_empty(&self) -> bool {
        self.snapshot.keys() == 0
    }

    /// Return the oldest location that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Option<Location> {
        self.log.oldest_retained_pos().map(Location::new_unchecked)
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive.
    pub fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc
    }

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        let new_loc = self.op_count();
        if let Some(old_loc) = self.get_key_loc(&key).await? {
            Self::update_loc(&mut self.snapshot, &key, old_loc, new_loc);
            self.steps += 1;
        } else {
            self.snapshot.insert(&key, new_loc);
        };

        let op = Operation::Update(key, value);
        self.apply_op(op).await?;

        Ok(())
    }

    /// Updates the value associated with the given key in the store, inserting a default value if
    /// the key does not already exist.
    ///
    /// The operation is immediately visible in the snapshot for subsequent queries, but remains
    /// uncommitted until `commit` is called. Uncommitted operations will be rolled back if the db
    /// is closed without committing.
    pub async fn upsert(&mut self, key: K, update: impl FnOnce(&mut V)) -> Result<(), Error>
    where
        V: Default,
    {
        let mut value = self.get(&key).await?.unwrap_or_default();
        update(&mut value);

        self.update(key, value).await
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`.
    pub async fn delete(&mut self, key: K) -> Result<(), Error> {
        let Some(old_loc) = self.get_key_loc(&key).await? else {
            return Ok(());
        };

        Self::delete_loc(&mut self.snapshot, &key, old_loc);
        self.apply_op(Operation::Delete(key)).await?;
        self.steps += 1;

        Ok(())
    }

    /// Return the root of the db.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub fn root(&self, hasher: &mut Standard<H>) -> H::Digest {
        self.mmr.root(hasher)
    }

    /// Update the operations MMR with the given operation, and append the operation to the log. The
    /// `commit` method must be called to make any applied operation persistent & recoverable.
    pub(super) async fn apply_op(&mut self, op: Operation<K, V>) -> Result<(), Error> {
        let encoded_op = op.encode();

        // Create a future that appends the operation to the log
        let log_fut = async {
            self.log.append(op).await.map_err(Error::Journal)?;
            Ok::<(), Error>(())
        };

        // Run the log update future in parallel with adding the operation to the MMR.
        try_join!(
            log_fut,
            self.mmr
                .add_batched(&mut self.hasher, &encoded_op)
                .map_err(Error::Mmr),
        )?;

        Ok(())
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the db in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= [Self::op_count].
    /// Returns [crate::mmr::Error::ElementPruned] if some element needed to generate the proof has been pruned.
    ///
    /// # Panics
    ///
    /// Panics if there are uncommitted operations.
    pub async fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        self.historical_proof(self.op_count(), start_loc, max_ops)
            .await
    }

    /// Analogous to proof, but with respect to the state of the MMR when it had `op_count`
    /// operations.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `op_count` or `start_loc` >
    /// [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `op_count` or `start_loc` >
    /// self.op_count().
    /// Returns [crate::mmr::Error::ElementPruned] if some element needed to generate the proof
    /// has been pruned.
    ///
    /// # Panics
    ///
    /// Panics if there are uncommitted operations.
    pub async fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        if op_count > self.op_count() {
            return Err(crate::mmr::Error::RangeOutOfBounds(op_count).into());
        }
        if start_loc >= op_count {
            return Err(crate::mmr::Error::RangeOutOfBounds(start_loc).into());
        }
        let mmr_size = Position::try_from(op_count)?;
        let end_loc = std::cmp::min(op_count, start_loc.saturating_add(max_ops.get()));
        let proof = self
            .mmr
            .historical_range_proof(mmr_size, start_loc..end_loc)
            .await?;
        let mut ops = Vec::with_capacity((*end_loc - *start_loc) as usize);
        for loc in *start_loc..*end_loc {
            let op = self.log.read(loc).await?;
            ops.push(op);
        }

        Ok((proof, ops))
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule. Caller can
    /// associate an arbitrary `metadata` value with the commit.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    pub async fn commit(&mut self, metadata: Option<V>) -> Result<(), Error> {
        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        if self.is_empty() {
            self.inactivity_floor_loc = self.op_count();
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = self.steps + 1;
            for _ in 0..steps_to_take {
                self.raise_floor().await?;
            }
        }
        self.steps = 0;

        // Apply the commit operation with the new inactivity floor.
        self.apply_op(Operation::CommitFloor(metadata, self.inactivity_floor_loc))
            .await?;
        let op_count = self.op_count();
        self.last_commit = Some(op_count - 1);

        // Sync the log and merkleize the MMR updates in parallel.
        let mmr_fut = async {
            self.mmr.merkleize(&mut self.hasher);
            Ok::<(), Error>(())
        };
        try_join!(self.log.sync_data().map_err(Error::Journal), mmr_fut)?;

        debug!(log_size = ?op_count, "commit complete");

        Ok(())
    }

    /// Get the location and metadata associated with the last commit, or None if no commit has been
    /// made.
    ///
    /// # Errors
    ///
    /// Returns Error if there is some underlying storage failure.
    pub async fn get_metadata(&self) -> Result<Option<(Location, Option<V>)>, Error> {
        let Some(last_commit) = self.last_commit else {
            return Ok(None);
        };

        let Operation::CommitFloor(metadata, _) = self.log.read(*last_commit).await? else {
            unreachable!("last commit should be a commit floor operation");
        };

        Ok(Some((last_commit, metadata)))
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&mut self) -> Result<(), Error> {
        try_join!(
            self.mmr.sync(&mut self.hasher).map_err(Error::Mmr),
            self.log.sync().map_err(Error::Journal),
        )?;

        Ok(())
    }

    // Moves the given operation to the tip of the log if it is active, rendering its old location
    // inactive. If the operation was not active, then this is a no-op. Returns the old location
    // of the operation if it was active.
    pub(super) async fn move_op_if_active(
        &mut self,
        op: Operation<K, V>,
        old_loc: Location,
    ) -> Result<Option<Location>, Error> {
        // If the translated key is not in the snapshot, get a cursor to look for the key.
        let Some(key) = op.key() else {
            // `op` is not a key-related operation, so it is not active.
            return Ok(None);
        };
        let new_loc = self.op_count();
        let Some(mut cursor) = self.snapshot.get_mut(key) else {
            return Ok(None);
        };

        // Iterate over all conflicting keys in the snapshot.
        while let Some(&loc) = cursor.next() {
            if loc == old_loc {
                // Update the location of the operation in the snapshot.
                cursor.update(new_loc);
                drop(cursor);

                // Apply the moved operation.
                self.apply_op(op).await?;
                return Ok(Some(old_loc));
            }
        }

        // The operation is not active, so this is a no-op.
        Ok(None)
    }

    /// Raise the inactivity floor by taking one _step_, which involves searching for the first
    /// active operation above the inactivity floor, moving it to tip, and then setting the
    /// inactivity floor to the location following the moved operation. This method is therefore
    /// guaranteed to raise the floor by at least one.
    ///
    /// # Errors
    ///
    /// Expects there is at least one active operation above the inactivity floor, and returns Error
    /// otherwise.
    async fn raise_floor(&mut self) -> Result<(), Error> {
        // Search for the first active operation above the inactivity floor and move it to tip.
        //
        // TODO(https://github.com/commonwarexyz/monorepo/issues/1829): optimize this w/ a bitmap.
        let mut op = self.log.read(*self.inactivity_floor_loc).await?;
        while self
            .move_op_if_active(op, self.inactivity_floor_loc)
            .await?
            .is_none()
        {
            self.inactivity_floor_loc += 1;
            op = self.log.read(*self.inactivity_floor_loc).await?;
        }

        // Increment the floor to the next operation since we know the current one is inactive.
        self.inactivity_floor_loc += 1;

        Ok(())
    }

    /// Prune historical operations. This does not affect the db's root or current snapshot.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `target_prune_loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [Error::PruneBeyondInactivityFloor] if `target_prune_loc` > inactivity floor.
    pub async fn prune(&mut self, target_prune_loc: Location) -> Result<(), Error> {
        if target_prune_loc > self.inactivity_floor_loc {
            return Err(Error::PruneBeyondInactivityFloor(
                target_prune_loc,
                self.inactivity_floor_loc,
            ));
        }
        let pruning_boundary = match self.oldest_retained_loc() {
            Some(oldest) => oldest,
            None => self.op_count(),
        };
        if target_prune_loc <= pruning_boundary {
            return Ok(());
        }

        // Sync the mmr before pruning the log, otherwise the MMR tip could end up behind the log's
        // pruning boundary on restart from an unclean shutdown, and there would be no way to replay
        // the operations between the MMR tip and the log pruning boundary.
        self.mmr.sync(&mut self.hasher).await?;

        // Prune the log up to the requested location. The log will prune at section boundaries,
        // so the actual oldest retained location may be less than requested. We always prune the
        // log first, and then prune the MMR based on the log's actual pruning boundary. This
        // procedure ensures all log operations always have corresponding MMR entries, even in the
        // event of failures, with no need for special recovery.
        self.log
            .prune(*target_prune_loc)
            .await
            .map_err(Error::Journal)?;

        let oldest_retained_loc = match self.log.oldest_retained_pos() {
            Some(oldest) => Location::new_unchecked(oldest),
            None => self.op_count(),
        };

        // Prune the MMR up to the oldest retained item in the log after pruning.
        self.mmr
            .prune_to_pos(&mut self.hasher, Position::try_from(oldest_retained_loc)?)
            .await?;

        debug!(?target_prune_loc, ?oldest_retained_loc, "pruned database");

        Ok(())
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(mut self) -> Result<(), Error> {
        try_join!(
            self.mmr.close(&mut self.hasher).map_err(Error::Mmr),
            self.log.close().map_err(Error::Journal),
        )?;

        Ok(())
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        try_join!(
            self.log.destroy().map_err(Error::Journal),
            self.mmr.destroy().map_err(Error::Mmr),
        )?;

        Ok(())
    }

    /// Simulate an unclean shutdown by consuming the db without syncing (or only partially syncing)
    /// the log and/or mmr. When _not_ fully syncing the mmr, the `write_limit` parameter dictates
    /// how many mmr nodes to write during a partial sync (can be 0).
    #[cfg(any(test, feature = "fuzzing"))]
    pub async fn simulate_failure(
        mut self,
        sync_log: bool,
        sync_mmr: bool,
        write_limit: usize,
    ) -> Result<(), Error> {
        if sync_log {
            self.log.sync().await?;
        }
        if sync_mmr {
            assert_eq!(write_limit, 0);
            self.mmr.sync(&mut self.hasher).await?;
        } else if write_limit > 0 {
            self.mmr
                .simulate_partial_sync(&mut self.hasher, write_limit)
                .await?;
        }

        Ok(())
    }
}

impl<E, K, V, H, T> Db<E, K, V, T> for Any<E, K, V, H, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: Codec,
    H: CHasher,
    T: Translator,
{
    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get(&self, key: &K) -> Result<Option<V>, store::Error> {
        self.get(key).await.map_err(Into::into)
    }

    async fn update(&mut self, key: K, value: V) -> Result<(), store::Error> {
        self.update(key, value).await.map_err(Into::into)
    }

    async fn delete(&mut self, key: K) -> Result<(), store::Error> {
        self.delete(key).await.map_err(Into::into)
    }

    async fn commit(&mut self) -> Result<(), store::Error> {
        self.commit(None).await.map_err(Into::into)
    }

    async fn sync(&mut self) -> Result<(), store::Error> {
        self.sync().await.map_err(Into::into)
    }

    async fn prune(&mut self, target_prune_loc: Location) -> Result<(), store::Error> {
        self.prune(target_prune_loc).await.map_err(Into::into)
    }

    async fn close(self) -> Result<(), store::Error> {
        self.close().await.map_err(Into::into)
    }

    async fn destroy(self) -> Result<(), store::Error> {
        self.destroy().await.map_err(Into::into)
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{adb::verify_proof, mmr::mem::Mmr as MemMmr, translator::TwoCap};
    use commonware_cryptography::{sha256::Digest, Digest as _, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::NZU64;
    use std::collections::HashMap;

    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;

    fn db_config(suffix: &str) -> Config<TwoCap, (commonware_codec::RangeCfg<usize>, ())> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_items_per_section: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// A type alias for the concrete [Any] type used in these unit tests.
    type AnyTest = Any<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AnyTest {
        AnyTest::init(context, db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_commit_on_empty_db() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));

            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = Standard::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.oldest_retained_loc(), None);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            let empty_root = db.root(&mut hasher);
            assert_eq!(empty_root, MemMmr::default().root(&mut hasher));
            assert!(db.get_metadata().await.unwrap().is_none());

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = Sha256::fill(1u8);
            let v1 = vec![1u8; 8];
            db.update(d1, v1).await.unwrap();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), empty_root);
            assert_eq!(db.op_count(), 0);

            let empty_proof = Proof::default();
            assert!(verify_proof(
                &mut hasher,
                &empty_proof,
                Location::new_unchecked(0),
                &[] as &[Operation<Digest, Digest>],
                &empty_root
            ));

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 1); // floor op added
            let root = db.root(&mut hasher);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));

            // Re-opening the DB without a clean shutdown should still recover the correct state.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.root(&mut hasher), root);

            // Empty proof should no longer verify.
            assert!(!verify_proof(
                &mut hasher,
                &empty_proof,
                Location::new_unchecked(0),
                &[] as &[Operation<Digest, Digest>],
                &root
            ));

            // Single op proof should verify.
            let (proof, ops) = db
                .proof(Location::new_unchecked(0), NZU64!(1))
                .await
                .unwrap();
            assert!(verify_proof(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
                &ops,
                &root
            ));

            // Add one more op.
            db.commit(None).await.unwrap();
            // Historical proof from larger db should match proof from smaller db.
            let (proof2, ops2) = db
                .historical_proof(
                    Location::new_unchecked(1),
                    Location::new_unchecked(0),
                    NZU64!(1),
                )
                .await
                .unwrap();
            assert_eq!(proof, proof2);
            assert_eq!(ops, ops2);

            // Proof will not verify against the root of the bigger db.
            let root2 = db.root(&mut hasher);
            assert!(!verify_proof(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
                &ops,
                &root2
            ));

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits on a
            // non-empty db.
            db.update(d1, vec![2u8; 20]).await.unwrap();
            for _ in 1..100 {
                db.commit(None).await.unwrap();
                // Distance should equal 3 after the second commit, with inactivity_floor
                // referencing the previous commit operation.
                assert!(db.op_count() - db.inactivity_floor_loc <= 3);
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 keys and make sure updates and deletions of those keys work as
            // expected.
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let d1 = Sha256::fill(1u8);
            let d2 = Sha256::fill(2u8);
            let v1 = vec![1u8; 8];
            let v2 = vec![2u8; 20];

            assert!(db.get(&d1).await.unwrap().is_none());
            assert!(db.get(&d2).await.unwrap().is_none());

            db.update(d1, v1.clone()).await.unwrap();
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), v1);
            assert!(db.get(&d2).await.unwrap().is_none());

            db.update(d2, v1.clone()).await.unwrap();
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), v1);

            db.delete(d1).await.unwrap();
            assert!(db.get(&d1).await.unwrap().is_none());
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), v1);

            db.update(d1, v2.clone()).await.unwrap();
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), v2);

            db.update(d2, v1.clone()).await.unwrap();
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), v1);

            assert_eq!(db.op_count(), 5); // 4 updates, 1 deletion.
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(0));
            db.commit(None).await.unwrap();

            // Should have moved 3 active operations to tip, leading to floor of 6.
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(6));
            assert_eq!(db.op_count(), 9); // floor of 6 + 2 active keys + 1 commit.

            // Delete all keys.
            db.delete(d1).await.unwrap();
            db.delete(d2).await.unwrap();
            assert!(db.get(&d1).await.unwrap().is_none());
            assert!(db.get(&d2).await.unwrap().is_none());
            assert_eq!(db.op_count(), 11); // 2 new delete ops.
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(6));

            db.commit(None).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(11));
            assert_eq!(db.op_count(), 12); // only commit should remain.

            // Multiple deletions of the same key should be a no-op.
            db.delete(d1).await.unwrap();
            assert_eq!(db.op_count(), 12);

            // Deletions of non-existent keys should be a no-op.
            let d3 = Sha256::fill(3u8);
            db.delete(d3).await.unwrap();
            assert_eq!(db.op_count(), 12);

            // Make sure closing/reopening gets us back to the same state.
            let metadata = Some(vec![99, 100]);
            db.commit(metadata.clone()).await.unwrap();
            assert_eq!(db.op_count(), 13);
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 13);
            assert_eq!(db.root(&mut hasher), root);

            // Make sure we can still get the metadata.
            assert_eq!(
                db.get_metadata().await.unwrap(),
                Some((Location::new_unchecked(12), metadata))
            );

            // Re-activate the keys by updating them.
            db.update(d1, v1.clone()).await.unwrap();
            db.update(d2, v2.clone()).await.unwrap();
            db.delete(d1).await.unwrap();
            db.update(d2, v1.clone()).await.unwrap();
            db.update(d1, v2.clone()).await.unwrap();
            assert_eq!(db.snapshot.keys(), 2);

            // Make sure last_commit is updated by changing the metadata back to None.
            db.commit(None).await.unwrap();
            let metadata = db.get_metadata().await.unwrap();
            assert_eq!(metadata, Some((Location::new_unchecked(21), None)));

            // Confirm close/reopen gets us back to the same state.
            assert_eq!(db.op_count(), 22);
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;

            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.op_count(), 22);
            let metadata = db.get_metadata().await.unwrap();
            assert_eq!(metadata, Some((Location::new_unchecked(21), None)));

            // Commit will raise the inactivity floor, which won't affect state but will affect the
            // root.
            db.commit(None).await.unwrap();

            assert!(db.root(&mut hasher) != root);

            // Pruning inactive ops should not affect current state or root
            let root = db.root(&mut hasher);
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the db matches that of an identically updated hashmap.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let mut map = HashMap::<Digest, Vec<u8>>::default();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
                map.insert(k, v);
            }

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
                map.remove(&k);
            }

            assert_eq!(db.op_count(), 1477);
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(0));
            assert_eq!(
                db.oldest_retained_loc().unwrap(),
                Location::new_unchecked(0)
            ); // no pruning yet
            assert_eq!(db.snapshot.items(), 857);

            // Test that commit will raise the activity floor.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 1956);
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(837));
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(
                db.oldest_retained_loc().unwrap(),
                Location::new_unchecked(833),
            );
            assert_eq!(db.snapshot.items(), 857);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), 1956);
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(837));
            assert_eq!(db.snapshot.items(), 857);

            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(837));
            assert_eq!(db.op_count(), 1956);
            assert_eq!(db.snapshot.items(), 857);

            // Confirm the db's state matches that of the separate map we computed independently.
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                if let Some(map_value) = map.get(&k) {
                    let Some(db_value) = db.get(&k).await.unwrap() else {
                        panic!("key not found in db: {k}");
                    };
                    assert_eq!(*map_value, db_value);
                } else {
                    assert!(db.get(&k).await.unwrap().is_none());
                }
            }

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = NZU64!(4);
            let end_loc = db.op_count();
            let start_pos = db.mmr.pruned_to_pos();
            let start_loc = Location::try_from(start_pos).unwrap();
            // Raise the inactivity floor and make sure historical inactive operations are still provable.
            db.commit(None).await.unwrap();

            let root = db.root(&mut hasher);
            assert!(start_loc < db.inactivity_floor_loc);

            for loc in *start_loc..*end_loc {
                let (proof, log) = db
                    .proof(Location::new_unchecked(loc), max_ops)
                    .await
                    .unwrap();
                assert!(verify_proof(
                    &mut hasher,
                    &proof,
                    Location::new_unchecked(loc),
                    &log,
                    &root
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    // Test that replaying multiple updates of the same key on startup doesn't leave behind old data
    // in the snapshot.
    #[test_traced("WARN")]
    pub fn test_any_db_log_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Update the same key many times.
            const UPDATES: u64 = 100;
            let k = Sha256::hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = vec![(i % 255) as u8; ((i % 7) + 3) as usize];
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);
            db.close().await.unwrap();

            // Simulate a failed commit and test that the log replay doesn't leave behind old data.
            let db = open_db(context.clone()).await;
            let iter = db.snapshot.get(&k);
            assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_db_multiple_commits_delete_gets_replayed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let mut map = HashMap::<Digest, Vec<u8>>::default();
            const ELEMENTS: u64 = 10;
            // insert & commit multiple batches to ensure repeated inactivity floor raising.
            for j in 0u64..ELEMENTS {
                for i in 0u64..ELEMENTS {
                    let k = Sha256::hash(&(j * 1000 + i).to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 7) + 3) as usize];
                    db.update(k, v.clone()).await.unwrap();
                    map.insert(k, v);
                }
                db.commit(None).await.unwrap();
            }
            let k = Sha256::hash(&((ELEMENTS - 1) * 1000 + (ELEMENTS - 1)).to_be_bytes());

            // Do one last delete operation which will be above the inactivity
            // floor, to make sure it gets replayed on restart.
            db.delete(k).await.unwrap();
            db.commit(None).await.unwrap();
            assert!(db.get(&k).await.unwrap().is_none());

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert!(db.get(&k).await.unwrap().is_none());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_variable_db_recovery() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;
            let root = db.root(&mut hasher);

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // re-apply the updates and commit them this time.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply updates for every 3rd key and commit them this time.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }

            // Simulate a failure and test that we rollback to the previous root.
            db.simulate_failure(false, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-delete every 7th key and commit this time.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }
            db.commit(None).await.unwrap();

            let root = db.root(&mut hasher);
            assert_eq!(db.op_count(), 1960);
            assert_eq!(
                Location::try_from(db.mmr.size()).ok(),
                Some(Location::new_unchecked(1960))
            );
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(755));
            db.sync().await.unwrap(); // test pruning boundary after sync w/ prune
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(
                db.oldest_retained_loc().unwrap(),
                Location::new_unchecked(749)
            );
            assert_eq!(db.snapshot.items(), 857);

            // Confirm state is preserved after close and reopen.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), 1960);
            assert_eq!(
                Location::try_from(db.mmr.size()).ok(),
                Some(Location::new_unchecked(1960))
            );
            assert_eq!(db.inactivity_floor_loc, Location::new_unchecked(755));
            assert_eq!(
                db.oldest_retained_loc().unwrap(),
                Location::new_unchecked(749)
            );
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_any_variable_non_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Insert 1000 keys then sync.
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            let root = db.root(&mut hasher);
            let op_count = db.op_count();
            let inactivity_floor_loc = db.inactivity_floor_loc();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            async fn apply_more_ops(
                db: &mut Any<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>,
            ) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 8) as usize];
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit, then simulate failure, syncing nothing.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time sync the log.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time sync mmr.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false, true, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time partially sync mmr.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false, false, 10).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            apply_more_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_more_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > op_count);
            assert_ne!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_ne!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_any_variable_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize an empty db.
            let mut hasher = Standard::<Sha256>::new();
            let db = open_db(context.clone()).await;
            let root = db.root(&mut hasher);

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            async fn apply_ops(
                db: &mut Any<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>,
            ) {
                for i in 0u64..1000 {
                    let k = Sha256::hash(&i.to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 13) + 8) as usize];
                    db.update(k, v).await.unwrap();
                }
            }

            // Insert operations without commit then simulate failure (partially sync mmr).
            apply_ops(&mut db).await;
            db.simulate_failure(false, false, 1).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Insert another 1000 keys then simulate failure (sync only the log).
            apply_ops(&mut db).await;
            db.simulate_failure(true, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Insert another 1000 keys then simulate failure (sync only the mmr).
            apply_ops(&mut db).await;
            db.simulate_failure(false, true, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // One last check that re-open without proper shutdown still recovers the correct state.
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            apply_ops(&mut db).await;
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > 0);
            assert_ne!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_db_get_loc_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut db = open_db(context.clone()).await;

            // Test getting from empty database
            let result = db.get_loc(Location::new_unchecked(0)).await;
            assert!(
                matches!(result, Err(Error::LocationOutOfBounds(loc, size)) if loc == Location::new_unchecked(0) && size == Location::new_unchecked(0))
            );

            // Add some operations
            db.update(Digest::random(&mut context), vec![10]).await.unwrap();
            db.update(Digest::random(&mut context), vec![20]).await.unwrap();
            db.update(Digest::random(&mut context), vec![30]).await.unwrap();
            db.commit(None).await.unwrap();

            // Test getting valid locations succeeds
            assert!(db.get_loc(Location::new_unchecked(0)).await.unwrap().is_some());
            assert!(db.get_loc(Location::new_unchecked(1)).await.unwrap().is_some());
            assert!(db.get_loc(Location::new_unchecked(2)).await.unwrap().is_some());

            // Test getting exactly at boundary
            let op_count = *db.op_count();
            let result = db.get_loc(Location::new_unchecked(op_count)).await;
            assert!(
                matches!(result, Err(Error::LocationOutOfBounds(loc, size))
                    if loc == Location::new_unchecked(op_count) && size == Location::new_unchecked(op_count))
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_db_get_from_loc_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut db = open_db(context.clone()).await;

            let key = Digest::random(&mut context);

            // Test getting from empty database
            let result = db.get_from_loc(&key, Location::new_unchecked(0)).await;
            assert!(
                matches!(result, Err(Error::LocationOutOfBounds(loc, size)) if loc == Location::new_unchecked(0) && size == Location::new_unchecked(0))
            );

            // Add some operations
            db.update(key, vec![10]).await.unwrap();
            db.update(Digest::random(&mut context), vec![20]).await.unwrap();
            db.update(Digest::random(&mut context), vec![30]).await.unwrap();
            db.commit(None).await.unwrap();

            // Test getting valid locations succeeds
            assert!(db.get_from_loc(&key, Location::new_unchecked(0)).await.unwrap().is_some());

            // Test getting exactly at boundary
            let op_count = *db.op_count();
            let result = db.get_from_loc(&key, Location::new_unchecked(op_count)).await;
            assert!(
                matches!(result, Err(Error::LocationOutOfBounds(loc, size))
                    if loc == Location::new_unchecked(op_count) && size == Location::new_unchecked(op_count))
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_db_prune_beyond_inactivity_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut db = open_db(context.clone()).await;

            // Add some operations
            let key1 = Digest::random(&mut context);
            let key2 = Digest::random(&mut context);
            let key3 = Digest::random(&mut context);

            db.update(key1, vec![10]).await.unwrap();
            db.update(key2, vec![20]).await.unwrap();
            db.update(key3, vec![30]).await.unwrap();
            db.commit(None).await.unwrap();

            // inactivity_floor should be at some location < op_count
            let inactivity_floor = db.inactivity_floor_loc();
            let beyond_floor = Location::new_unchecked(*inactivity_floor + 1);

            // Try to prune beyond the inactivity floor
            let result = db.prune(beyond_floor).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondInactivityFloor(loc, floor))
                    if loc == beyond_floor && floor == inactivity_floor)
            );

            db.destroy().await.unwrap();
        });
    }
}
