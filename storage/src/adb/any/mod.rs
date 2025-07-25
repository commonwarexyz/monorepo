//! An authenticated database (ADB) that provides succinct proofs of _any_ value ever associated
//! with a key. Its implementation is based on an [Mmr] over a log of state-change operations backed
//! by a [Journal].
//!
//! In the [Any] db, it is not possible to prove whether the value of a key is the currently active
//! one, only that it was associated with the key at some point in the past. This type of
//! authenticated database is most useful for applications involving keys that are given values once
//! and cannot be updated after.

use crate::{
    adb::{operation::Fixed, Error},
    index::Index,
    journal::fixed::{Config as JConfig, Journal},
    mmr::{
        bitmap::Bitmap,
        hasher::Standard,
        iterator::{leaf_num_to_pos, leaf_pos_to_num},
        journaled::{Config as MmrConfig, Mmr},
        verification::Proof,
    },
    translator::Translator,
};
use commonware_codec::Encode as _;
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage, ThreadPool};
use commonware_utils::Array;
use futures::{
    future::{try_join_all, TryFutureExt},
    pin_mut, try_join, StreamExt,
};
use tracing::{debug, warn};

pub mod sync;

/// Indicator that the generic parameter N is unused by the call. N is only
/// needed if the caller is providing the optional bitmap.
const UNUSED_N: usize = 0;

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot.
const SNAPSHOT_READ_BUFFER_SIZE: usize = 1 << 16;

/// Configuration for an `Any` authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator> {
    /// The name of the [RStorage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: u64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: usize,

    /// The name of the [RStorage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [RStorage] partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: u64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: usize,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,

    /// The number of operations to keep below the inactivity floor before pruning.
    /// This creates a gap between the inactivity floor and the pruning boundary,
    /// which is useful for serving state sync clients, who may request operations
    /// below the inactivity floor.
    pub pruning_delay: u64,
}

/// Configuration for syncing an [Any] to a pruned target state.
pub struct SyncConfig<E: RStorage + Metrics, K: Array, V: Array, T: Translator, D: Digest> {
    /// Database configuration.
    pub db_config: Config<T>,

    /// The [Any]'s log of operations. It has elements from `lower_bound` to `upper_bound`, inclusive.
    /// Reports `lower_bound` as its pruning boundary (oldest retained operation index).
    pub log: Journal<E, Fixed<K, V>>,

    /// Sync lower boundary (inclusive) - operations below this index are pruned.
    pub lower_bound: u64,

    /// Sync upper boundary (inclusive) - operations above this index are not synced.
    pub upper_bound: u64,

    /// The pinned nodes the MMR needs at the pruning boundary given by
    /// `lower_bound`, in the order specified by [Proof::nodes_to_pin].
    /// If `None`, the pinned nodes will be computed from the MMR's journal and metadata,
    /// which are expected to have the necessary pinned nodes.
    pub pinned_nodes: Option<Vec<D>>,

    /// The maximum number of operations to keep in memory
    /// before committing the database while applying operations.
    /// Higher value will cause more memory usage during sync.
    pub apply_batch_size: usize,
}

/// A key-value ADB based on an MMR over its log of operations, supporting authentication of any
/// value ever associated with a key.
pub struct Any<E: RStorage + Clock + Metrics, K: Array, V: Array, H: CHasher, T: Translator> {
    /// An MMR over digests of the operations applied to the db.
    ///
    /// # Invariant
    ///
    /// The number of leaves in this MMR always equals the number of operations in the unpruned
    /// `log`.
    pub(super) ops: Mmr<E, H>,

    /// A (pruned) log of all operations applied to the db in order of occurrence. The position of
    /// each operation in the log is called its _location_, which is a stable identifier. Pruning is
    /// indicated by a non-zero value for `pruned_loc`, which provides the location of the first
    /// operation in the log.
    ///
    /// # Invariant
    ///
    /// An operation's location is always equal to the number of the MMR leaf storing the digest of
    /// the operation.
    pub(super) log: Journal<E, Fixed<K, V>>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    pub(super) inactivity_floor_loc: u64,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location in the log containing its most recent update.
    ///
    /// # Invariant
    ///
    /// Only references operations of type Operation::Update.
    pub(super) snapshot: Index<T, u64>,

    /// The number of operations that are pending commit.
    pub(super) uncommitted_ops: u64,

    /// Cryptographic hasher to re-use within mutable operations requiring digest computation.
    pub(super) hasher: Standard<H>,

    /// The number of operations to keep below the inactivity floor before pruning.
    /// This creates a gap between the inactivity floor and the pruning boundary,
    /// which is useful for serving state sync clients, who may request operations
    /// below the inactivity floor.
    pub(super) pruning_delay: u64,
}

/// The result of a database `update` operation.
pub enum UpdateResult {
    /// Tried to set a key to its current value.
    NoOp,
    /// Key was not previously in the snapshot & its new loc is the wrapped value.
    Inserted(u64),
    /// Key was previously in the snapshot & its (old, new) loc pair is wrapped.
    Updated(u64, u64),
}

impl<E: RStorage + Clock + Metrics, K: Array, V: Array, H: CHasher, T: Translator>
    Any<E, K, V, H, T>
{
    /// Returns an [Any] adb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config<T>) -> Result<Self, Error> {
        let mut snapshot: Index<T, u64> =
            Index::init(context.with_label("snapshot"), cfg.translator.clone());
        let mut hasher = Standard::<H>::new();
        let pruning_delay = cfg.pruning_delay;
        let (mmr, log) = Self::init_mmr_and_log(context, cfg, &mut hasher).await?;

        let start_leaf_num = leaf_pos_to_num(mmr.pruned_to_pos()).unwrap();
        let inactivity_floor_loc = Self::build_snapshot_from_log(
            start_leaf_num,
            &log,
            &mut snapshot,
            None::<&mut Bitmap<H, UNUSED_N>>,
        )
        .await?;

        let db = Any {
            ops: mmr,
            log,
            snapshot,
            inactivity_floor_loc,
            uncommitted_ops: 0,
            hasher,
            pruning_delay,
        };

        Ok(db)
    }

    /// Returns an [Any] initialized from sync data in `cfg` for use in state sync.
    ///
    /// # Behavior
    ///
    /// This method handles different initialization scenarios based on existing data:
    /// - If the MMR journal is empty or the last item is before `lower_bound`, it creates a
    ///   fresh MMR from the provided `pinned_nodes`
    /// - If the MMR journal has data but is incomplete (< `upper_bound`), missing operations
    ///   from the log are applied to bring it up to the target state
    /// - If the MMR journal has data beyond the `upper_bound`, it is rewound to match the sync target
    ///
    /// # Returns
    ///
    /// An [Any] db populated with the state from `cfg.lower_bound` to `cfg.upper_bound`, inclusive.
    /// The pruning boundary is set to `cfg.lower_bound`.
    pub(super) async fn init_synced(
        context: E,
        cfg: SyncConfig<E, K, V, T, H::Digest>,
    ) -> Result<Self, Error> {
        let mut mmr = Mmr::init_sync(
            context.with_label("mmr"),
            crate::mmr::journaled::SyncConfig {
                config: crate::mmr::journaled::Config {
                    journal_partition: cfg.db_config.mmr_journal_partition,
                    metadata_partition: cfg.db_config.mmr_metadata_partition,
                    items_per_blob: cfg.db_config.mmr_items_per_blob,
                    write_buffer: cfg.db_config.mmr_write_buffer,
                    thread_pool: cfg.db_config.thread_pool.clone(),
                    buffer_pool: cfg.db_config.buffer_pool.clone(),
                },
                lower_bound: leaf_num_to_pos(cfg.lower_bound),
                // The last node of an MMR with `cfg.upper_bound` + 1 operations is at the position
                // right before where the next leaf goes.
                upper_bound: leaf_num_to_pos(cfg.upper_bound + 1) - 1,
                pinned_nodes: cfg.pinned_nodes,
            },
        )
        .await
        .map_err(Error::MmrError)?;

        // Convert MMR size to number of operations.
        let Some(mmr_ops) = leaf_pos_to_num(mmr.size()) else {
            return Err(Error::MmrError(crate::mmr::Error::InvalidSize(mmr.size())));
        };

        // Apply the missing operations from the log to the MMR.
        let mut hasher = Standard::<H>::new();
        let log_size = cfg.log.size().await?;
        for i in mmr_ops..log_size {
            let op = cfg.log.read(i).await?;
            mmr.add_batched(&mut hasher, &op.encode()).await?;
            if i % cfg.apply_batch_size as u64 == 0 {
                // Periodically sync the MMR to avoid memory bloat.
                // Since the first value i takes may not be a multiple of `cfg.apply_batch_size`,
                // the first sync may occur before `apply_batch_size` operations are applied.
                // This is fine.
                mmr.sync(&mut hasher).await?;
            }
        }

        // Build the snapshot from the log.
        let mut snapshot = Index::init(
            context.with_label("snapshot"),
            cfg.db_config.translator.clone(),
        );
        let inactivity_floor_loc = Any::<E, K, V, H, T>::build_snapshot_from_log::<
            0, /* UNUSED_N */
        >(cfg.lower_bound, &cfg.log, &mut snapshot, None)
        .await?;

        let mut db = Any {
            ops: mmr,
            log: cfg.log,
            snapshot,
            inactivity_floor_loc,
            uncommitted_ops: 0,
            hasher: Standard::<H>::new(),
            pruning_delay: cfg.db_config.pruning_delay,
        };
        db.sync().await?;
        Ok(db)
    }

    /// Initialize and return the mmr and log from the given config, correcting any inconsistencies
    /// between them. Any uncommitted operations in the log will be rolled back and the state of the
    /// db will be as of the last committed operation.
    pub(super) async fn init_mmr_and_log(
        context: E,
        cfg: Config<T>,
        hasher: &mut Standard<H>,
    ) -> Result<(Mmr<E, H>, Journal<E, Fixed<K, V>>), Error> {
        let mut mmr = Mmr::init(
            context.with_label("mmr"),
            hasher,
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

        let mut log = Journal::init(
            context.with_label("log"),
            JConfig {
                partition: cfg.log_journal_partition,
                items_per_blob: cfg.log_items_per_blob,
                write_buffer: cfg.log_write_buffer,
                buffer_pool: cfg.buffer_pool,
            },
        )
        .await?;

        // Back up over / discard any uncommitted operations in the log.
        let mut log_size = log.size().await?;
        let mut rewind_leaf_num = log_size;
        while rewind_leaf_num > 0 {
            if let Fixed::Commit(_) = log.read(rewind_leaf_num - 1).await? {
                break;
            }
            rewind_leaf_num -= 1;
        }
        if rewind_leaf_num != log_size {
            let op_count = log_size - rewind_leaf_num;
            warn!(op_count, "rewinding over uncommitted log operations");
            log.rewind(rewind_leaf_num).await?;
            log_size = rewind_leaf_num;
        }

        // Pop any MMR elements that are ahead of the last log commit point.
        let mut next_mmr_leaf_num = leaf_pos_to_num(mmr.size()).unwrap();
        if next_mmr_leaf_num > log_size {
            let op_count = next_mmr_leaf_num - log_size;
            warn!(op_count, "popping uncommitted MMR operations");
            mmr.pop(op_count as usize).await?;
            next_mmr_leaf_num = log_size;
        }

        // If the MMR is behind, replay log operations to catch up.
        if next_mmr_leaf_num < log_size {
            let op_count = log_size - next_mmr_leaf_num;
            warn!(op_count, "MMR lags behind log, replaying log to catch up");
            while next_mmr_leaf_num < log_size {
                let op = log.read(next_mmr_leaf_num).await?;
                mmr.add_batched(hasher, &op.encode()).await?;
                next_mmr_leaf_num += 1;
            }
            mmr.sync(hasher).await.map_err(Error::MmrError)?;
        }

        // At this point the MMR and log should be consistent.
        assert_eq!(log.size().await?, leaf_pos_to_num(mmr.size()).unwrap());

        Ok((mmr, log))
    }

    /// Builds the database's snapshot by replaying the log starting at `start_leaf_num`.
    ///
    /// If a bitmap is provided, then a bit is appended for each operation in the operation log,
    /// with its value reflecting its activity status. The bitmap is expected to already have a
    /// number of bits corresponding to the portion of the database below the inactivity floor, and
    /// this method will panic otherwise. The caller is responsible for syncing any changes made to
    /// the bitmap.
    pub(super) async fn build_snapshot_from_log<const N: usize>(
        start_leaf_num: u64,
        log: &Journal<E, Fixed<K, V>>,
        snapshot: &mut Index<T, u64>,
        mut bitmap: Option<&mut Bitmap<H, N>>,
    ) -> Result<u64, Error> {
        let mut inactivity_floor_loc = start_leaf_num;
        if let Some(ref bitmap) = bitmap {
            assert_eq!(start_leaf_num, bitmap.bit_count());
        }

        let stream = log
            .replay(SNAPSHOT_READ_BUFFER_SIZE, start_leaf_num)
            .await?;
        pin_mut!(stream);
        while let Some(result) = stream.next().await {
            match result {
                Err(e) => {
                    return Err(Error::JournalError(e));
                }
                Ok((i, op)) => {
                    match op {
                        Fixed::Deleted(key) => {
                            let result =
                                Any::<E, K, V, H, T>::delete_key(snapshot, log, &key, i).await?;
                            if let Some(ref mut bitmap) = bitmap {
                                // Mark previous location (if any) of the deleted key as inactive.
                                if let Some(old_loc) = result {
                                    bitmap.set_bit(old_loc, false);
                                }
                            }
                        }
                        Fixed::Update(key, _) => {
                            let result =
                                Any::<E, K, V, H, T>::update_loc(snapshot, log, &key, None, i)
                                    .await?;
                            if let Some(ref mut bitmap) = bitmap {
                                match result {
                                    UpdateResult::NoOp => unreachable!("unexpected no-op update"),
                                    UpdateResult::Inserted(_) => bitmap.append(true),
                                    UpdateResult::Updated(old_loc, _) => {
                                        bitmap.set_bit(old_loc, false);
                                        bitmap.append(true);
                                    }
                                }
                            }
                        }
                        Fixed::Commit(loc) => inactivity_floor_loc = loc,
                    }
                    if let Some(ref mut bitmap) = bitmap {
                        // If we reach this point and a bit hasn't been added for the operation, then it's
                        // an inactive operation and we need to tag it as such in the bitmap.
                        if bitmap.bit_count() == i {
                            bitmap.append(false);
                        }
                    }
                }
            }
        }

        Ok(inactivity_floor_loc)
    }

    /// Update the location of `key` to `new_loc` in the snapshot and return its old location, or
    /// insert it if the key isn't already present. If a `value` is provided, then it is used to see
    /// if the key is already assigned that value, in which case there is no update and
    /// UpdateResult::NoOp is returned.
    async fn update_loc(
        snapshot: &mut Index<T, u64>,
        log: &Journal<E, Fixed<K, V>>,
        key: &K,
        value: Option<&V>,
        new_loc: u64,
    ) -> Result<UpdateResult, Error> {
        // If the translated key is not in the snapshot, insert the new location. Otherwise, get a
        // cursor to look for the key.
        let Some(mut cursor) = snapshot.get_mut_or_insert(key, new_loc) else {
            return Ok(UpdateResult::Inserted(new_loc));
        };

        // Iterate over conflicts in the snapshot.
        while let Some(&loc) = cursor.next() {
            let (k, v) = Self::get_update_op(log, loc).await?;
            if k == *key {
                // Found the key in the snapshot.
                if let Some(value) = value {
                    if v == *value {
                        // The key value is the same as the previous one: treat as a no-op.
                        return Ok(UpdateResult::NoOp);
                    }
                }

                // Update its location to the given one.
                assert!(new_loc > loc);
                cursor.update(new_loc);
                return Ok(UpdateResult::Updated(loc, new_loc));
            }
        }

        // The key wasn't in the snapshot, so add it to the cursor.
        cursor.insert(new_loc);
        Ok(UpdateResult::Inserted(new_loc))
    }

    /// Get the update operation corresponding to a location from the snapshot.
    ///
    /// # Warning
    ///
    /// Panics if the location does not reference an update operation. This should never happen
    /// unless the snapshot is buggy, or this method is being used to look up an operation
    /// independent of the snapshot contents.
    async fn get_update_op(log: &Journal<E, Fixed<K, V>>, loc: u64) -> Result<(K, V), Error> {
        let Fixed::Update(k, v) = log.read(loc).await? else {
            panic!("location does not reference update operation. loc={loc}");
        };

        Ok((k, v))
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        Ok(self.get_with_loc(key).await?.map(|(v, _)| v))
    }

    /// Get the value & location of the active operation for `key` in the db, or None if it has no
    /// value.
    pub(super) async fn get_with_loc(&self, key: &K) -> Result<Option<(V, u64)>, Error> {
        for &loc in self.snapshot.get(key) {
            let (k, v) = Self::get_update_op(&self.log, loc).await?;
            if k == *key {
                return Ok(Some((v, loc)));
            }
        }

        Ok(None)
    }

    /// Get the number of operations that have been applied to this db, including those that are not
    /// yet committed.
    pub fn op_count(&self) -> u64 {
        leaf_pos_to_num(self.ops.size()).unwrap()
    }

    /// Return the oldest location that remains readable & provable.
    pub fn oldest_retained_loc(&self) -> Option<u64> {
        self.ops
            .oldest_retained_pos()
            .map(|pos| leaf_pos_to_num(pos).unwrap())
    }

    /// Return the inactivity floor location.
    /// This is the location before which all operations are inactive.
    pub fn inactivity_floor_loc(&self) -> u64 {
        self.inactivity_floor_loc
    }

    /// Updates `key` to have value `value`. If the key already has this same value, then this is a
    /// no-op. The operation is reflected in the snapshot, but will be subject to rollback until the
    /// next successful `commit`.
    pub async fn update(&mut self, key: K, value: V) -> Result<UpdateResult, Error> {
        let new_loc = self.op_count();
        let res = Any::<_, _, _, H, T>::update_loc(
            &mut self.snapshot,
            &self.log,
            &key,
            Some(&value),
            new_loc,
        )
        .await?;
        match res {
            UpdateResult::NoOp => {
                // The key already has this value, so this is a no-op.
                return Ok(res);
            }
            UpdateResult::Inserted(_) => (),
            UpdateResult::Updated(_, _) => (),
        }

        let op = Fixed::Update(key, value);
        self.apply_op(op).await?;

        Ok(res)
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns the location of the deleted value for the key (if any).
    pub async fn delete(&mut self, key: K) -> Result<Option<u64>, Error> {
        let loc = self.op_count();
        let r = Self::delete_key(&mut self.snapshot, &self.log, &key, loc).await?;
        if r.is_some() {
            self.apply_op(Fixed::Deleted(key)).await?;
        };

        Ok(r)
    }

    /// Delete `key` from the snapshot if it exists, returning the location that was previously
    /// associated with it.
    async fn delete_key(
        snapshot: &mut Index<T, u64>,
        log: &Journal<E, Fixed<K, V>>,
        key: &K,
        delete_loc: u64,
    ) -> Result<Option<u64>, Error> {
        // If the translated key is in the snapshot, get a cursor to look for the key.
        let Some(mut cursor) = snapshot.get_mut(key) else {
            return Ok(None);
        };
        // Iterate over all conflicting keys in the snapshot.
        while let Some(&loc) = cursor.next() {
            let (k, _) = Self::get_update_op(log, loc).await?;
            if k == *key {
                // The key is in the snapshot, so delete it.
                //
                // If there are no longer any conflicting keys in the cursor, it will
                // automatically be removed from the snapshot.
                assert!(loc < delete_loc);
                cursor.delete();
                return Ok(Some(loc));
            }
        }

        // The key isn't in the conflicting keys, so this is a no-op.
        Ok(None)
    }

    /// Return the root of the db.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub fn root(&self, hasher: &mut Standard<H>) -> H::Digest {
        self.ops.root(hasher)
    }

    /// Update the operations MMR with the given operation, and append the operation to the log. The
    /// `commit` method must be called to make any applied operation persistent & recoverable.
    pub(super) async fn apply_op(&mut self, op: Fixed<K, V>) -> Result<u64, Error> {
        // Update the ops MMR.
        self.ops.add_batched(&mut self.hasher, &op.encode()).await?;
        self.uncommitted_ops += 1;

        // Append the operation to the log.
        self.log.append(op).await.map_err(Error::JournalError)
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the db in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub async fn proof(
        &self,
        start_loc: u64,
        max_ops: u64,
    ) -> Result<(Proof<H::Digest>, Vec<Fixed<K, V>>), Error> {
        self.historical_proof(self.op_count(), start_loc, max_ops)
            .await
    }

    /// Analogous to proof, but with respect to the state of the MMR when it had `size` elements.
    pub async fn historical_proof(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: u64,
    ) -> Result<(Proof<H::Digest>, Vec<Fixed<K, V>>), Error> {
        let start_pos = leaf_num_to_pos(start_loc);
        let end_loc = std::cmp::min(
            size.saturating_sub(1),
            start_loc.saturating_add(max_ops).saturating_sub(1),
        );
        let end_pos = leaf_num_to_pos(end_loc);
        let mmr_size = leaf_num_to_pos(size);

        let proof = self
            .ops
            .historical_range_proof(mmr_size, start_pos, end_pos)
            .await?;
        let mut ops = Vec::with_capacity((end_loc - start_loc + 1) as usize);
        let futures = (start_loc..=end_loc)
            .map(|i| self.log.read(i))
            .collect::<Vec<_>>();
        try_join_all(futures)
            .await?
            .into_iter()
            .for_each(|op| ops.push(op));

        Ok((proof, ops))
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
    /// the log with the provided root.
    pub fn verify_proof(
        hasher: &mut Standard<H>,
        proof: &Proof<H::Digest>,
        start_loc: u64,
        ops: &[Fixed<K, V>],
        root: &H::Digest,
    ) -> bool {
        let start_pos = leaf_num_to_pos(start_loc);

        let elements = ops.iter().map(|op| op.encode()).collect::<Vec<_>>();

        proof.verify_range_inclusion(hasher, &elements, start_pos, root)
    }

    /// Commit any pending operations to the db, ensuring they are persisted to disk & recoverable
    /// upon return from this function. Also raises the inactivity floor according to the schedule,
    /// and prunes those operations below it. Batch operations will be parallelized if a thread pool
    /// is provided.
    pub async fn commit(&mut self) -> Result<(), Error> {
        // Raise the inactivity floor by the # of uncommitted operations, plus 1 to account for the
        // commit op that will be appended.
        self.raise_inactivity_floor(self.uncommitted_ops + 1)
            .await?;
        self.uncommitted_ops = 0;
        self.sync().await?;

        // TODO: Make the frequency with which we prune known inactive items configurable in case
        // this turns out to be a significant part of commit overhead, or the user wants to ensure
        // the log is backed up externally before discarding.
        self.prune_inactive().await
    }

    /// Sync the db to disk ensuring the current state is persisted. Batch operations will be
    /// parallelized if a thread pool is provided.
    pub(super) async fn sync(&mut self) -> Result<(), Error> {
        try_join!(
            self.log.sync().map_err(Error::JournalError),
            self.ops.sync(&mut self.hasher).map_err(Error::MmrError),
        )?;

        Ok(())
    }

    // Moves the given operation to the tip of the log if it is active, rendering its old location
    // inactive. If the operation was not active, then this is a no-op. Returns the old location
    // of the operation if it was active.
    pub(super) async fn move_op_if_active(
        &mut self,
        op: Fixed<K, V>,
        old_loc: u64,
    ) -> Result<Option<u64>, Error> {
        // If the translated key is not in the snapshot, get a cursor to look for the key.
        let Some(key) = op.to_key() else {
            // `op` is a commit
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

                // Update the MMR with the operation.
                self.apply_op(op).await?;
                return Ok(Some(old_loc));
            }
        }

        // The operation is not active, so this is a no-op.
        Ok(None)
    }

    /// Raise the inactivity floor by exactly `max_steps` steps, followed by applying a commit
    /// operation. Each step either advances over an inactive operation, or re-applies an active
    /// operation to the tip and then advances over it.
    ///
    /// This method does not change the state of the db's snapshot, but it always changes the root
    /// since it applies at least one operation.
    pub(super) async fn raise_inactivity_floor(&mut self, max_steps: u64) -> Result<(), Error> {
        for _ in 0..max_steps {
            if self.inactivity_floor_loc == self.op_count() {
                break;
            }
            let op = self.log.read(self.inactivity_floor_loc).await?;
            self.move_op_if_active(op, self.inactivity_floor_loc)
                .await?;
            self.inactivity_floor_loc += 1;
        }

        self.apply_op(Fixed::Commit(self.inactivity_floor_loc))
            .await?;

        Ok(())
    }

    /// Prune historical operations that are > `pruning_delay` steps behind the inactivity floor.
    /// This does not affect the db's root or current snapshot.
    pub(super) async fn prune_inactive(&mut self) -> Result<(), Error> {
        let Some(oldest_retained_loc) = self.log.oldest_retained_pos().await? else {
            return Ok(());
        };

        // Calculate the target pruning position: inactivity_floor_loc - pruning_delay
        let target_prune_loc = self.inactivity_floor_loc.saturating_sub(self.pruning_delay);
        let ops_to_prune = target_prune_loc.saturating_sub(oldest_retained_loc);
        if ops_to_prune == 0 {
            return Ok(());
        }
        debug!(ops_to_prune, target_prune_loc, "pruning inactive ops");

        // Prune the MMR, whose pruning boundary serves as the "source of truth" for proving.
        let prune_to_pos = leaf_num_to_pos(target_prune_loc);
        self.ops
            .prune_to_pos(&mut self.hasher, prune_to_pos)
            .await?;

        // Because the log's pruning boundary will be blob-size aligned, we cannot use it as a
        // source of truth for the min provable element.
        self.log.prune(target_prune_loc).await?;

        Ok(())
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(mut self) -> Result<(), Error> {
        if self.uncommitted_ops > 0 {
            warn!(
                op_count = self.uncommitted_ops,
                "closing db with uncommitted operations"
            );
        }

        try_join!(
            self.log.close().map_err(Error::JournalError),
            self.ops.close(&mut self.hasher).map_err(Error::MmrError),
        )?;

        Ok(())
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await?;
        self.ops.destroy().await?;

        Ok(())
    }

    /// Simulate a failed commit that successfully writes the log to the commit point, but without
    /// fully committing the MMR's cached elements to trigger MMR node recovery on reopening.
    #[cfg(test)]
    pub async fn simulate_failed_commit_mmr(mut self, write_limit: usize) -> Result<(), Error> {
        self.apply_op(Fixed::Commit(self.inactivity_floor_loc))
            .await?;
        self.log.close().await?;
        self.ops
            .simulate_partial_sync(&mut self.hasher, write_limit)
            .await?;

        Ok(())
    }

    /// Simulate a failed commit that successfully writes the MMR to the commit point, but without
    /// fully committing the log, requiring rollback of the MMR and log upon reopening.
    #[cfg(test)]
    pub async fn simulate_failed_commit_log(mut self) -> Result<(), Error> {
        self.apply_op(Fixed::Commit(self.inactivity_floor_loc))
            .await?;
        self.ops.close(&mut self.hasher).await?;
        // Rewind the operation log over the commit op to force rollback to the previous commit.
        self.log.rewind(self.log.size().await? - 1).await?;
        self.log.close().await?;

        Ok(())
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        mmr::{hasher::Standard, mem::Mmr as MemMmr},
        translator::TwoCap,
    };
    use commonware_codec::{DecodeExt, FixedSize};
    use commonware_cryptography::{hash, sha256::Digest, Digest as _, Hasher as CHasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{self, Context},
        Runner as _,
    };
    use futures::future::join_all;
    use rand::{
        rngs::{OsRng, StdRng},
        RngCore, SeedableRng,
    };
    use std::collections::{HashMap, HashSet};

    const SHA256_SIZE: usize = <Sha256 as CHasher>::Digest::SIZE;
    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;

    fn any_db_config(suffix: &str) -> Config<TwoCap> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: 11,
            mmr_write_buffer: 1024,
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: 7,
            log_write_buffer: 1024,
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            pruning_delay: 10,
        }
    }

    /// A type alias for the concrete [Any] type used in these unit tests.
    type AnyTest = Any<deterministic::Context, Digest, Digest, Sha256, TwoCap>;

    /// Return an `Any` database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AnyTest {
        AnyTest::init(context, any_db_config("partition"))
            .await
            .unwrap()
    }

    fn create_test_config(seed: u64) -> Config<TwoCap> {
        Config {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: 1024,
            mmr_write_buffer: 64,
            log_journal_partition: format!("log_journal_{seed}"),
            log_items_per_blob: 1024,
            log_write_buffer: 64,
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            pruning_delay: 10,
        }
    }

    /// Create a test database with unique partition names
    pub(crate) async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        AnyTest::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    /// create_test_ops(n') is a suffix of create_test_ops(n) for n' > n.
    pub(crate) fn create_test_ops(n: usize) -> Vec<Fixed<Digest, Digest>> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(Fixed::Deleted(prev_key));
            } else {
                let value = Digest::random(&mut rng);
                ops.push(Fixed::Update(key, value));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    pub(crate) async fn apply_ops(db: &mut AnyTest, ops: Vec<Fixed<Digest, Digest>>) {
        for op in ops {
            match op {
                Fixed::Update(key, value) => {
                    db.update(key, value).await.unwrap();
                }
                Fixed::Deleted(key) => {
                    db.delete(key).await.unwrap();
                }
                Fixed::Commit(_) => {
                    db.commit().await.unwrap();
                }
            }
        }
    }

    #[test_traced("WARN")]
    pub fn test_any_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = Standard::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.oldest_retained_loc(), None);
            assert!(matches!(db.prune_inactive().await, Ok(())));
            assert_eq!(db.root(&mut hasher), MemMmr::default().root(&mut hasher));

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = Sha256::fill(1u8);
            let d2 = Sha256::fill(2u8);
            let root = db.root(&mut hasher);
            db.update(d1, d2).await.unwrap();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.op_count(), 0);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 1); // floor op added
            let root = db.root(&mut hasher);
            assert!(matches!(db.prune_inactive().await, Ok(())));
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
            for _ in 1..100 {
                db.commit().await.unwrap();
                assert_eq!(db.op_count() - 1, db.inactivity_floor_loc);
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 keys and make sure updates and deletions of those keys work as
            // expected.
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let d1 = Sha256::fill(1u8);
            let d2 = Sha256::fill(2u8);

            assert!(db.get(&d1).await.unwrap().is_none());
            assert!(db.get(&d2).await.unwrap().is_none());

            assert!(matches!(
                db.update(d1, d2).await.unwrap(),
                UpdateResult::Inserted(0)
            ));
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), d2);
            assert!(db.get(&d2).await.unwrap().is_none());

            assert!(matches!(
                db.update(d2, d1).await.unwrap(),
                UpdateResult::Inserted(1)
            ));
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), d2);
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), d1);

            assert!(matches!(db.delete(d1).await.unwrap(), Some(0)));
            assert!(db.get(&d1).await.unwrap().is_none());
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), d1);

            assert!(matches!(
                db.update(d1, d1).await.unwrap(),
                UpdateResult::Inserted(3)
            ));
            assert_eq!(db.get(&d1).await.unwrap().unwrap(), d1);

            assert!(matches!(
                db.update(d2, d2).await.unwrap(),
                UpdateResult::Updated(1, 4)
            ));
            assert_eq!(db.get(&d2).await.unwrap().unwrap(), d2);

            assert_eq!(db.log.size().await.unwrap(), 5); // 4 updates, 1 deletion.
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.inactivity_floor_loc, 0);
            db.sync().await.unwrap();

            // Advance over 3 inactive operations.
            db.raise_inactivity_floor(3).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, 3);
            assert_eq!(db.log.size().await.unwrap(), 6); // 4 updates, 1 deletion, 1 commit
            db.sync().await.unwrap();
            let root = db.root(&mut hasher);

            // Multiple assignments of the same value should be a no-op.
            assert!(matches!(
                db.update(d1, d1).await.unwrap(),
                UpdateResult::NoOp
            ));
            assert!(matches!(
                db.update(d2, d2).await.unwrap(),
                UpdateResult::NoOp
            ));
            // Log and root should be unchanged.
            assert_eq!(db.log.size().await.unwrap(), 6);
            assert_eq!(db.root(&mut hasher), root);

            // Delete all keys.
            assert!(matches!(db.delete(d1).await.unwrap(), Some(3)));
            assert!(matches!(db.delete(d2).await.unwrap(), Some(4)));
            assert!(db.get(&d1).await.unwrap().is_none());
            assert!(db.get(&d2).await.unwrap().is_none());
            assert_eq!(db.log.size().await.unwrap(), 8); // 4 updates, 3 deletions, 1 commit
            assert_eq!(db.inactivity_floor_loc, 3);

            db.sync().await.unwrap();
            let root = db.root(&mut hasher);

            // Multiple deletions of the same key should be a no-op.
            assert!(db.delete(d1).await.unwrap().is_none());
            assert_eq!(db.log.size().await.unwrap(), 8);
            assert_eq!(db.root(&mut hasher), root);

            // Deletions of non-existent keys should be a no-op.
            let d3 = <Sha256 as CHasher>::Digest::decode(vec![2u8; SHA256_SIZE].as_ref()).unwrap();
            assert!(db.delete(d3).await.unwrap().is_none());
            assert_eq!(db.log.size().await.unwrap(), 8);
            db.sync().await.unwrap();
            assert_eq!(db.root(&mut hasher), root);

            // Make sure closing/reopening gets us back to the same state.
            db.commit().await.unwrap();
            assert_eq!(db.log.size().await.unwrap(), 9);
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.log.size().await.unwrap(), 9);
            assert_eq!(db.root(&mut hasher), root);

            // Since this db no longer has any active keys, we should be able to raise the
            // inactivity floor to the tip (only the inactive commit op remains).
            db.raise_inactivity_floor(100).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, db.op_count() - 1);

            // Re-activate the keys by updating them.
            db.update(d1, d1).await.unwrap();
            db.update(d2, d2).await.unwrap();
            db.delete(d1).await.unwrap();
            db.update(d2, d1).await.unwrap();
            db.update(d1, d2).await.unwrap();
            assert_eq!(db.snapshot.keys(), 2);

            // Confirm close/reopen gets us back to the same state.
            db.commit().await.unwrap();
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.snapshot.keys(), 2);

            // Commit will raise the inactivity floor, which won't affect state but will affect the
            // root.
            db.commit().await.unwrap();

            assert!(db.root(&mut hasher) != root);

            // Pruning inactive ops should not affect current state or root
            let root = db.root(&mut hasher);
            db.prune_inactive().await.unwrap();
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(
                db.inactivity_floor_loc.saturating_sub(db.pruning_delay),
                db.oldest_retained_loc().unwrap()
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the db matches that of an identically updated hashmap.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let mut map = HashMap::<Digest, Digest>::default();
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                let v = hash(&((i + 1) * 10000).to_be_bytes());
                db.update(k, v).await.unwrap();
                map.insert(k, v);
            }

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
                map.remove(&k);
            }

            assert_eq!(db.op_count(), 1477);
            assert_eq!(db.inactivity_floor_loc, 0);
            assert_eq!(db.log.size().await.unwrap(), 1477);
            assert_eq!(db.oldest_retained_loc().unwrap(), 0); // no pruning yet
            assert_eq!(db.snapshot.items(), 857);

            // Test that commit will raise the activity floor.
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 2336);
            assert_eq!(
                db.oldest_retained_loc().unwrap(),
                1478_u64.saturating_sub(10)
            ); // 1478 - pruning_delay
            assert_eq!(db.inactivity_floor_loc, 1478);
            assert_eq!(db.snapshot.items(), 857);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), 2336);
            assert_eq!(db.inactivity_floor_loc, 1478);
            assert_eq!(db.snapshot.items(), 857);

            // Raise the inactivity floor to the point where all inactive operations can be pruned.
            db.raise_inactivity_floor(3000).await.unwrap();
            db.prune_inactive().await.unwrap();
            assert_eq!(db.inactivity_floor_loc, 4478);
            // Inactivity floor should be 858 operations from tip since 858 operations are active
            // (counting the floor op itself).
            assert_eq!(db.op_count(), 4478 + 858);
            assert_eq!(db.snapshot.items(), 857);

            // Confirm the db's state matches that of the separate map we computed independently.
            for i in 0u64..1000 {
                let k = hash(&i.to_be_bytes());
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
            let max_ops = 4;
            let end_loc = db.op_count();
            let start_pos = db.ops.pruned_to_pos();
            let start_loc = leaf_pos_to_num(start_pos).unwrap();
            // Raise the inactivity floor and make sure historical inactive operations are still provable.
            db.raise_inactivity_floor(100).await.unwrap();
            db.sync().await.unwrap();
            let root = db.root(&mut hasher);
            assert!(start_loc < db.inactivity_floor_loc);

            for i in start_loc..end_loc {
                let (proof, log) = db.proof(i, max_ops).await.unwrap();
                assert!(AnyTest::verify_proof(&mut hasher, &proof, i, &log, &root));
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_any_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
            }
            db.sync().await.unwrap();
            let halfway_root = db.root(&mut hasher);

            // Insert another 1000 keys then simulate a failed close and test recovery.
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&((i + 1) * 10000).to_be_bytes());
                db.update(k, v).await.unwrap();
            }

            // We partially write 101 of the cached MMR nodes to simulate a failure that leaves the
            // MMR in a state with an orphaned leaf.
            db.simulate_failed_commit_mmr(101).await.unwrap();

            // Journaled MMR recovery should read the orphaned leaf & its parents, then log
            // replaying will restore the rest.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2001);
            let root = db.root(&mut hasher);
            assert_ne!(root, halfway_root);

            // Write some additional nodes, simulate failed log commit, and test we recover to the previous commit point.
            for i in 0u64..100 {
                let k = hash(&i.to_be_bytes());
                let v = hash(&((i + 2) * 10000).to_be_bytes());
                db.update(k, v).await.unwrap();
            }
            db.simulate_failed_commit_log().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2001);
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();

            // Recreate the database without any failures and make sure the roots match.
            let mut new_db = open_db(context.clone()).await;
            assert_eq!(new_db.op_count(), 0);
            // Insert 1000 keys then sync.
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&(i * 1000).to_be_bytes());
                new_db.update(k, v).await.unwrap();
            }
            assert_eq!(new_db.op_count(), 1000);
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&((i + 1) * 10000).to_be_bytes());
                new_db.update(k, v).await.unwrap();
            }
            new_db
                .apply_op(Fixed::Commit(new_db.inactivity_floor_loc))
                .await
                .unwrap();
            new_db.sync().await.unwrap();
            assert_eq!(new_db.op_count(), 2001);
            assert_eq!(new_db.root(&mut hasher), root);

            new_db.destroy().await.unwrap();
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
            let k = hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
            }
            db.commit().await.unwrap();
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

            let mut map = HashMap::<Digest, Digest>::default();
            const ELEMENTS: u64 = 10;
            // insert & commit multiple batches to ensure repeated inactivity floor raising.
            for j in 0u64..ELEMENTS {
                for i in 0u64..ELEMENTS {
                    let k = hash(&(j * 1000 + i).to_be_bytes());
                    let v = hash(&(i * 1000).to_be_bytes());
                    db.update(k, v).await.unwrap();
                    map.insert(k, v);
                }
                db.commit().await.unwrap();
            }
            let k = hash(&((ELEMENTS - 1) * 1000 + (ELEMENTS - 1)).to_be_bytes());

            // Do one last delete operation which will be above the inactivity
            // floor, to make sure it gets replayed on restart.
            db.delete(k).await.unwrap();
            db.commit().await.unwrap();
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

    /// This test builds a random database, and makes sure that its state can be replayed by
    /// `build_snapshot_from_log` with a bitmap to correctly capture the active operations.
    #[test_traced("WARN")]
    pub fn test_any_db_build_snapshot_with_bitmap() {
        // Number of elements to initially insert into the db.
        const ELEMENTS: u64 = 1000;

        // Use a non-deterministic rng seed to ensure each run is different.
        let rng_seed = OsRng.next_u64();
        // Log the seed with high visibility to make failures reproducible.
        warn!("rng_seed={}", rng_seed);
        let mut rng = StdRng::seed_from_u64(rng_seed);

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = hash(&rng.next_u32().to_be_bytes());
                db.update(k, v).await.unwrap();
            }

            // Randomly update / delete them. We use a delete frequency that is 1/7th of the update
            // frequency.
            for _ in 0u64..ELEMENTS * 10 {
                let rand_key = hash(&(rng.next_u64() % ELEMENTS).to_be_bytes());
                if rng.next_u32() % 7 == 0 {
                    db.delete(rand_key).await.unwrap();
                    continue;
                }
                let v = hash(&rng.next_u32().to_be_bytes());
                db.update(rand_key, v).await.unwrap();
                if rng.next_u32() % 20 == 0 {
                    // Commit every ~20 updates.
                    db.commit().await.unwrap();
                }
            }
            db.commit().await.unwrap();

            // Close the db, then replay its operations with a bitmap.
            let root = db.root(&mut hasher);
            // Create a bitmap based on the current db's pruned/inactive state.
            let mut bitmap = Bitmap::<_, SHA256_SIZE>::new();
            let pruning_boundary = db.oldest_retained_loc().unwrap();
            for _ in 0..pruning_boundary {
                bitmap.append(false);
            }
            bitmap.sync(&mut hasher).await.unwrap();
            assert_eq!(bitmap.bit_count(), pruning_boundary);
            db.close().await.unwrap();

            // Initialize the db's mmr/log.
            let cfg = any_db_config("partition");
            let pruning_delay = cfg.pruning_delay;
            let (mmr, log) = AnyTest::init_mmr_and_log(context.clone(), cfg, &mut hasher)
                .await
                .unwrap();
            let start_leaf_num = leaf_pos_to_num(mmr.pruned_to_pos()).unwrap();

            // Replay log to populate the bitmap. Use a TwoCap instead of EightCap here so we exercise some collisions.
            let mut snapshot: Index<TwoCap, u64> =
                Index::init(context.with_label("snapshot"), TwoCap);
            let inactivity_floor_loc = AnyTest::build_snapshot_from_log::<SHA256_SIZE>(
                start_leaf_num,
                &log,
                &mut snapshot,
                Some(&mut bitmap),
            )
            .await
            .unwrap();

            // Check the recovered state is correct.
            let db = AnyTest {
                ops: mmr,
                log,
                snapshot,
                inactivity_floor_loc,
                uncommitted_ops: 0,
                hasher: Standard::<Sha256>::new(),
                pruning_delay,
            };
            assert_eq!(db.root(&mut hasher), root);

            // Check the bitmap state matches that of the snapshot.
            let items = db.log.size().await.unwrap();
            assert_eq!(bitmap.bit_count(), items);
            let mut active_positions = HashSet::new();
            // This loop checks that the expected true bits are true in the bitmap.
            for pos in db.inactivity_floor_loc..items {
                let item = db.log.read(pos).await.unwrap();
                let Some(item_key) = item.to_key() else {
                    // `item` is a commit
                    continue;
                };
                let iter = db.snapshot.get(item_key);
                for loc in iter {
                    if *loc == pos {
                        // Found an active op.
                        active_positions.insert(pos);
                        assert!(bitmap.get_bit(pos));
                        break;
                    }
                }
            }
            // This loop checks that the expected false bits are false in the bitmap.
            for pos in db.inactivity_floor_loc..items {
                if !active_positions.contains(&pos) {
                    assert!(!bitmap.get_bit(pos));
                }
            }

            db.destroy().await.unwrap();
        });
    }

    /// Test `init_synced` with an empty source database (nothing persisted) syncing to
    /// an empty target database.
    #[test_traced("WARN")]
    pub fn test_any_db_init_synced_empty_to_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let log = Journal::<Context, Fixed<Digest, Digest>>::init(
                context.clone(),
                JConfig {
                    partition: "sync_basic_log".into(),
                    items_per_blob: 1000,
                    write_buffer: 1024,
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                },
            )
            .await
            .unwrap();
            let sync_config: SyncConfig<Context, Digest, Digest, TwoCap, Digest> = SyncConfig {
                db_config: any_db_config("sync_basic"),
                lower_bound: 0,
                upper_bound: 0,
                pinned_nodes: None,
                log,
                apply_batch_size: 1024,
            };
            let mut synced_db: Any<_, Digest, Digest, Sha256, TwoCap> =
                Any::init_synced(context.clone(), sync_config)
                    .await
                    .unwrap();

            // Verify database state
            assert_eq!(synced_db.op_count(), 0);
            assert_eq!(synced_db.inactivity_floor_loc, 0);
            assert_eq!(synced_db.log.size().await.unwrap(), 0);
            assert_eq!(synced_db.ops.size(), 0);

            // Test that we can perform operations on the synced database
            let key1 = hash(&1u64.to_be_bytes());
            let value1 = hash(&10u64.to_be_bytes());
            let key2 = hash(&2u64.to_be_bytes());
            let value2 = hash(&20u64.to_be_bytes());

            synced_db.update(key1, value1).await.unwrap();
            synced_db.update(key2, value2).await.unwrap();
            synced_db.commit().await.unwrap();

            // Verify the operations worked
            assert_eq!(synced_db.get(&key1).await.unwrap(), Some(value1));
            assert_eq!(synced_db.get(&key2).await.unwrap(), Some(value2));
            assert!(synced_db.op_count() > 0);

            synced_db.destroy().await.unwrap();
        });
    }

    /// Test `init_synced` with an empty source database (nothing persisted) syncing to
    /// a non-empty target database.
    #[test]
    fn test_any_db_init_synced_empty_to_nonempty() {
        const NUM_OPS: usize = 100;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate a source database
            let mut source_db = create_test_db(context.clone()).await;
            let ops = create_test_ops(NUM_OPS);
            apply_ops(&mut source_db, ops.clone()).await;
            source_db.commit().await.unwrap();

            let lower_bound_ops = source_db.inactivity_floor_loc;
            let upper_bound_ops = source_db.op_count() - 1;

            // Get pinned nodes and target hash before moving source_db
            let pinned_nodes_pos = Proof::<Digest>::nodes_to_pin(leaf_num_to_pos(lower_bound_ops));
            let pinned_nodes =
                join_all(pinned_nodes_pos.map(|pos| source_db.ops.get_node(pos))).await;
            let pinned_nodes = pinned_nodes
                .iter()
                .map(|node| node.as_ref().unwrap().unwrap())
                .collect::<Vec<_>>();
            let mut hasher = Standard::<Sha256>::new();
            let target_hash = source_db.root(&mut hasher);

            // Create log with operations
            let mut log = Journal::<_, Fixed<Digest, Digest>>::init_sync(
                context.clone().with_label("ops_log"),
                JConfig {
                    partition: format!("ops_log_{}", context.next_u64()),
                    items_per_blob: 1024,
                    write_buffer: 64,
                    buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                },
                lower_bound_ops,
                upper_bound_ops,
            )
            .await
            .unwrap();

            // Populate log with operations from source db
            for i in lower_bound_ops..=upper_bound_ops {
                let op = source_db.log.read(i).await.unwrap();
                log.append(op).await.unwrap();
            }

            let db = Any::init_synced(
                context.clone(),
                SyncConfig {
                    db_config: create_test_config(context.next_u64()),
                    log,
                    lower_bound: lower_bound_ops,
                    upper_bound: upper_bound_ops,
                    pinned_nodes: Some(pinned_nodes),
                    apply_batch_size: 1024,
                },
            )
            .await
            .unwrap();

            // Verify database state
            assert_eq!(db.op_count(), upper_bound_ops + 1);
            assert_eq!(db.inactivity_floor_loc, lower_bound_ops);
            assert_eq!(db.oldest_retained_loc(), Some(lower_bound_ops));
            assert_eq!(db.ops.size(), source_db.ops.size());
            assert_eq!(db.ops.pruned_to_pos(), leaf_num_to_pos(lower_bound_ops));
            assert_eq!(
                db.log.size().await.unwrap(),
                source_db.log.size().await.unwrap()
            );

            // Verify the root digest matches the target
            assert_eq!(db.root(&mut hasher), target_hash);

            // Verify state matches the source operations
            let mut expected_kvs = HashMap::new();
            let mut deleted_keys = HashSet::new();
            for op in &ops {
                if let Fixed::Update(key, value) = op {
                    expected_kvs.insert(*key, *value);
                    deleted_keys.remove(key);
                } else if let Fixed::Deleted(key) = op {
                    expected_kvs.remove(key);
                    deleted_keys.insert(*key);
                }
            }
            for (key, value) in expected_kvs {
                let synced_value = db.get(&key).await.unwrap().unwrap();
                assert_eq!(synced_value, value);
            }
            // Verify that deleted keys are absent
            for key in deleted_keys {
                assert!(db.get(&key).await.unwrap().is_none(),);
            }

            db.destroy().await.unwrap();
            source_db.destroy().await.unwrap();
        });
    }

    /// Test `init_synced` with an empty source database syncing to a non-empty target database
    /// with different pruning boundaries.
    #[test]
    fn test_any_db_init_synced_empty_to_nonempty_different_pruning_boundaries() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate a source database
            let mut source_db = create_test_db(context.clone()).await;
            let ops = create_test_ops(200);
            apply_ops(&mut source_db, ops.clone()).await;
            source_db.commit().await.unwrap();

            let total_ops = source_db.op_count();

            // Test different pruning boundaries
            for lower_bound in [0, 50, 100, 150] {
                let upper_bound = std::cmp::min(lower_bound + 49, total_ops - 1);

                // Create log with operations
                let mut log = Journal::<_, Fixed<Digest, Digest>>::init_sync(
                    context.clone().with_label("boundary_log"),
                    JConfig {
                        partition: format!("boundary_log_{}_{}", lower_bound, context.next_u64()),
                        items_per_blob: 1024,
                        write_buffer: 64,
                        buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    },
                    lower_bound,
                    upper_bound,
                )
                .await
                .unwrap();
                log.sync().await.unwrap();

                for i in lower_bound..=upper_bound {
                    let op = source_db.log.read(i).await.unwrap();
                    log.append(op).await.unwrap();
                }
                log.sync().await.unwrap();

                let pinned_nodes = Proof::<Digest>::nodes_to_pin(leaf_num_to_pos(lower_bound))
                    .map(|pos| source_db.ops.get_node(pos));
                let pinned_nodes = join_all(pinned_nodes).await;
                let pinned_nodes = pinned_nodes
                    .iter()
                    .map(|node| node.as_ref().unwrap().unwrap())
                    .collect::<Vec<_>>();

                let db: AnyTest = Any::init_synced(
                    context.clone(),
                    SyncConfig {
                        db_config: create_test_config(context.next_u64()),
                        log,
                        lower_bound,
                        upper_bound,
                        pinned_nodes: Some(pinned_nodes),
                        apply_batch_size: 1024,
                    },
                )
                .await
                .unwrap();

                // Verify database state
                let expected_op_count = upper_bound + 1;
                assert_eq!(db.log.size().await.unwrap(), expected_op_count);
                assert_eq!(db.ops.size(), leaf_num_to_pos(expected_op_count));
                assert_eq!(db.op_count(), expected_op_count);
                assert_eq!(db.inactivity_floor_loc, lower_bound);
                assert_eq!(db.oldest_retained_loc(), Some(lower_bound));
                assert_eq!(db.ops.pruned_to_pos(), leaf_num_to_pos(lower_bound));

                // Verify state matches the source operations
                let mut expected_kvs = HashMap::new();
                let mut deleted_keys = HashSet::new();
                for op in &ops[lower_bound as usize..=upper_bound as usize] {
                    if let Fixed::Update(key, value) = op {
                        expected_kvs.insert(*key, *value);
                        deleted_keys.remove(key);
                    } else if let Fixed::Deleted(key) = op {
                        expected_kvs.remove(key);
                        deleted_keys.insert(*key);
                    }
                }
                for (key, value) in expected_kvs {
                    assert_eq!(db.get(&key).await.unwrap().unwrap(), value,);
                }
                // Verify that deleted keys are absent
                for key in deleted_keys {
                    assert!(db.get(&key).await.unwrap().is_none());
                }

                db.destroy().await.unwrap();
            }
            source_db.destroy().await.unwrap();
        });
    }

    // Test `init_synced` where the database has some but not all of the operations in the target
    // database.
    #[test]
    fn test_any_db_init_synced_nonempty_to_nonempty_partial_match() {
        const NUM_OPS: usize = 100;
        const NUM_ADDITIONAL_OPS: usize = 5;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate two databases.
            let mut target_db = create_test_db(context.clone()).await;
            let sync_db_config = create_test_config(context.next_u64());
            let mut sync_db: AnyTest = Any::init(context.clone(), sync_db_config.clone())
                .await
                .unwrap();
            let original_ops = create_test_ops(NUM_OPS);
            apply_ops(&mut target_db, original_ops.clone()).await;
            target_db.commit().await.unwrap();
            apply_ops(&mut sync_db, original_ops.clone()).await;
            sync_db.commit().await.unwrap();
            let sync_db_original_size = sync_db.op_count();

            // Get pinned nodes before closing the database
            let pinned_nodes_map = sync_db.ops.get_pinned_nodes();
            let pinned_nodes =
                Proof::<Digest>::nodes_to_pin(leaf_num_to_pos(sync_db_original_size))
                    .map(|pos| *pinned_nodes_map.get(&pos).unwrap())
                    .collect::<Vec<_>>();

            // Close the sync db
            sync_db.close().await.unwrap();

            // Add one more operation to the target db
            let more_ops = create_test_ops(NUM_ADDITIONAL_OPS);
            apply_ops(&mut target_db, more_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture target db state for comparison
            let target_db_op_count = target_db.op_count();
            let target_db_inactivity_floor_loc = target_db.inactivity_floor_loc;
            let target_db_log_size = target_db.log.size().await.unwrap();
            let target_db_mmr_size = target_db.ops.size();

            let sync_lower_bound = target_db.inactivity_floor_loc;
            let sync_upper_bound = target_db.op_count() - 1;

            let mut hasher = Standard::<Sha256>::new();
            let target_hash = target_db.root(&mut hasher);

            let AnyTest { ops, log, .. } = target_db;

            // Re-open `sync_db`
            let sync_db = Any::init_synced(
                context.clone(),
                SyncConfig {
                    db_config: sync_db_config,
                    log,
                    lower_bound: sync_lower_bound,
                    upper_bound: sync_upper_bound,
                    pinned_nodes: Some(pinned_nodes),
                    apply_batch_size: 1024,
                },
            )
            .await
            .unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), target_db_op_count);
            assert_eq!(sync_db.inactivity_floor_loc, target_db_inactivity_floor_loc);
            assert_eq!(sync_db.oldest_retained_loc(), Some(sync_lower_bound));
            assert_eq!(sync_db.log.size().await.unwrap(), target_db_log_size);
            assert_eq!(sync_db.ops.size(), target_db_mmr_size);
            assert_eq!(
                sync_db.ops.pruned_to_pos(),
                leaf_num_to_pos(sync_lower_bound)
            );

            // Verify the root digest matches the target
            assert_eq!(sync_db.root(&mut hasher), target_hash);

            // Verify state matches the source operations
            let mut expected_kvs = HashMap::new();
            let mut deleted_keys = HashSet::new();
            for op in &original_ops {
                if let Fixed::Update(key, value) = op {
                    expected_kvs.insert(*key, *value);
                    deleted_keys.remove(key);
                } else if let Fixed::Deleted(key) = op {
                    expected_kvs.remove(key);
                    deleted_keys.insert(*key);
                }
            }
            for (key, value) in expected_kvs {
                let synced_value = sync_db.get(&key).await.unwrap().unwrap();
                assert_eq!(synced_value, value);
            }
            // Verify that deleted keys are absent
            for key in deleted_keys {
                assert!(sync_db.get(&key).await.unwrap().is_none(),);
            }

            sync_db.destroy().await.unwrap();
            ops.destroy().await.unwrap();
        });
    }

    // Test `init_synced` where the database has all of the operations in the target range.
    #[test]
    fn test_any_db_init_synced_nonempty_to_nonempty_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let db_config = create_test_config(context.next_u64());
            let mut db = Any::init(context.clone(), db_config.clone()).await.unwrap();
            let ops = create_test_ops(100);
            apply_ops(&mut db, ops.clone()).await;
            db.commit().await.unwrap();

            let sync_lower_bound = db.inactivity_floor_loc;
            let sync_upper_bound = db.op_count() - 1;
            let target_db_op_count = db.op_count();
            let target_db_inactivity_floor_loc = db.inactivity_floor_loc;
            let target_db_log_size = db.log.size().await.unwrap();
            let target_db_mmr_size = db.ops.size();

            let AnyTest { ops, log, .. } = db;

            // When we re-open the database, the MMR is closed and the log is opened.
            let mut hasher = Standard::<Sha256>::new();
            ops.close(&mut hasher).await.unwrap();

            let sync_db: AnyTest = Any::init_synced(
                context.clone(),
                SyncConfig {
                    db_config,
                    log,
                    lower_bound: sync_lower_bound,
                    upper_bound: sync_upper_bound,
                    pinned_nodes: None,
                    apply_batch_size: 1024,
                },
            )
            .await
            .unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), target_db_op_count);
            assert_eq!(sync_db.inactivity_floor_loc, target_db_inactivity_floor_loc);
            assert_eq!(sync_db.oldest_retained_loc(), Some(sync_lower_bound));
            assert_eq!(sync_db.log.size().await.unwrap(), target_db_log_size);
            assert_eq!(sync_db.ops.size(), target_db_mmr_size);
            assert_eq!(
                sync_db.ops.pruned_to_pos(),
                leaf_num_to_pos(sync_lower_bound)
            );

            sync_db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_db_historical_proof_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(20);
            apply_ops(&mut db, ops.clone()).await;
            db.commit().await.unwrap();
            let mut hasher = Standard::<Sha256>::new();
            let root_hash = db.root(&mut hasher);
            let original_op_count = db.op_count();

            // Historical proof should match "regular" proof when historical size == current database size
            let (historical_proof, historical_ops) =
                db.historical_proof(original_op_count, 5, 10).await.unwrap();
            let (regular_proof, regular_ops) = db.proof(5, 10).await.unwrap();

            assert_eq!(historical_proof.size, regular_proof.size);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert_eq!(historical_ops, ops[5..15]);
            assert!(AnyTest::verify_proof(
                &mut hasher,
                &historical_proof,
                5,
                &historical_ops,
                &root_hash
            ));

            // Add more operations to the database
            let more_ops = create_test_ops(5);
            apply_ops(&mut db, more_ops.clone()).await;
            db.commit().await.unwrap();

            // Historical proof should remain the same even though database has grown
            let (historical_proof, historical_ops) =
                db.historical_proof(original_op_count, 5, 10).await.unwrap();
            assert_eq!(historical_proof.size, leaf_num_to_pos(original_op_count));
            assert_eq!(historical_proof.size, regular_proof.size);
            assert_eq!(historical_ops.len(), 10);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert!(AnyTest::verify_proof(
                &mut hasher,
                &historical_proof,
                5,
                &historical_ops,
                &root_hash
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_db_historical_proof_edge_cases() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(50);
            apply_ops(&mut db, ops.clone()).await;
            db.commit().await.unwrap();

            let mut hasher = Standard::<Sha256>::new();

            // Test singleton database
            let (single_proof, single_ops) = db.historical_proof(1, 0, 1).await.unwrap();
            assert_eq!(single_proof.size, leaf_num_to_pos(1));
            assert_eq!(single_ops.len(), 1);

            // Create historical database with single operation
            let mut single_db = create_test_db(context.clone()).await;
            apply_ops(&mut single_db, ops[0..1].to_vec()).await;
            // Don't commit - this changes the root due to commit operations
            single_db.sync().await.unwrap();
            let single_root = single_db.root(&mut hasher);

            assert!(AnyTest::verify_proof(
                &mut hasher,
                &single_proof,
                0,
                &single_ops,
                &single_root
            ));

            // Test requesting more operations than available in historical position
            let (_limited_proof, limited_ops) = db.historical_proof(10, 5, 20).await.unwrap();
            assert_eq!(limited_ops.len(), 5); // Should be limited by historical position
            assert_eq!(limited_ops, ops[5..10]);

            // Test proof at minimum historical position
            let (min_proof, min_ops) = db.historical_proof(3, 0, 3).await.unwrap();
            assert_eq!(min_proof.size, leaf_num_to_pos(3));
            assert_eq!(min_ops.len(), 3);
            assert_eq!(min_ops, ops[0..3]);

            single_db.destroy().await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_db_historical_proof_different_historical_sizes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(100);
            apply_ops(&mut db, ops.clone()).await;
            db.commit().await.unwrap();

            let mut hasher = Standard::<Sha256>::new();

            // Test historical proof generation for several historical states.
            let start_loc = 20;
            let max_ops = 10;
            for end_loc in 31..50 {
                let (historical_proof, historical_ops) = db
                    .historical_proof(end_loc, start_loc, max_ops)
                    .await
                    .unwrap();

                assert_eq!(historical_proof.size, leaf_num_to_pos(end_loc));

                // Create  reference database at the given historical size
                let mut ref_db = create_test_db(context.clone()).await;
                apply_ops(&mut ref_db, ops[0..end_loc as usize].to_vec()).await;
                // Sync to process dirty nodes but don't commit - commit changes the root due to commit operations
                ref_db.sync().await.unwrap();

                let (ref_proof, ref_ops) = ref_db.proof(start_loc, max_ops).await.unwrap();
                assert_eq!(ref_proof.size, historical_proof.size);
                assert_eq!(ref_ops, historical_ops);
                assert_eq!(ref_proof.digests, historical_proof.digests);
                let end_loc = std::cmp::min(start_loc + max_ops, end_loc);
                assert_eq!(ref_ops, ops[start_loc as usize..end_loc as usize]);

                // Verify proof against reference root
                let ref_root = ref_db.root(&mut hasher);
                assert!(AnyTest::verify_proof(
                    &mut hasher,
                    &historical_proof,
                    start_loc,
                    &historical_ops,
                    &ref_root
                ),);

                ref_db.destroy().await.unwrap();
            }

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_db_historical_proof_size_too_large() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(10);
            apply_ops(&mut db, ops).await;
            db.commit().await.unwrap();
            let op_count = db.op_count();

            // Historical size > current database size is invalid
            let result = db.historical_proof(op_count + 1, op_count, 5).await;
            match result {
                Err(Error::MmrError(crate::mmr::Error::HistoricalSizeTooLarge(
                    requested,
                    actual,
                ))) => {
                    assert_eq!(requested, leaf_num_to_pos(op_count + 1));
                    assert_eq!(actual, leaf_num_to_pos(op_count));
                }
                _ => panic!("expected HistoricalSizeTooLarge error"),
            }

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_db_historical_proof_size_too_small() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(10);
            apply_ops(&mut db, ops).await;
            db.commit().await.unwrap();
            let op_count = db.op_count();

            // Historical size == start location is invalid
            let result = db.historical_proof(op_count, op_count, 5).await;
            match result {
                Err(Error::MmrError(crate::mmr::Error::HistoricalSizeTooSmall(
                    size,
                    start_loc,
                ))) => {
                    assert_eq!(size, leaf_num_to_pos(op_count));
                    assert_eq!(start_loc, leaf_num_to_pos(op_count));
                }
                _ => panic!("expected HistoricalSizeTooSmall error"),
            }

            // Historical size < start location is invalid
            let result = db.historical_proof(op_count, op_count + 1, 5).await;
            match result {
                Err(Error::MmrError(crate::mmr::Error::HistoricalSizeTooSmall(
                    size,
                    start_loc,
                ))) => {
                    assert_eq!(size, leaf_num_to_pos(op_count));
                    assert_eq!(start_loc, leaf_num_to_pos(op_count + 1));
                }
                _ => panic!("expected HistoricalSizeTooSmall error"),
            }

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_db_historical_proof_invalid() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(10);
            apply_ops(&mut db, ops).await;
            db.commit().await.unwrap();

            let (proof, ops) = db.historical_proof(5, 1, 10).await.unwrap();
            assert_eq!(proof.size, leaf_num_to_pos(5));
            assert_eq!(ops.len(), 4);

            let mut hasher = Standard::<Sha256>::new();

            // Changing the proof digests should cause verification to fail
            {
                let mut proof = proof.clone();
                proof.digests[0] = hash(b"invalid");
                let root_hash = db.root(&mut hasher);
                assert!(!AnyTest::verify_proof(
                    &mut hasher,
                    &proof,
                    0,
                    &ops,
                    &root_hash
                ));
            }
            {
                let mut proof = proof.clone();
                proof.digests.push(hash(b"invalid"));
                let root_hash = db.root(&mut hasher);
                assert!(!AnyTest::verify_proof(
                    &mut hasher,
                    &proof,
                    0,
                    &ops,
                    &root_hash
                ));
            }

            // Changing the ops should cause verification to fail
            {
                let mut ops = ops.clone();
                ops[0] = Fixed::Update(hash(b"key1"), hash(b"value1"));
                let root_hash = db.root(&mut hasher);
                assert!(!AnyTest::verify_proof(
                    &mut hasher,
                    &proof,
                    0,
                    &ops,
                    &root_hash
                ));
            }
            {
                let mut ops = ops.clone();
                ops.push(Fixed::Update(hash(b"key1"), hash(b"value1")));
                let root_hash = db.root(&mut hasher);
                assert!(!AnyTest::verify_proof(
                    &mut hasher,
                    &proof,
                    0,
                    &ops,
                    &root_hash
                ));
            }

            // Changing the start location should cause verification to fail
            {
                let root_hash = db.root(&mut hasher);
                assert!(!AnyTest::verify_proof(
                    &mut hasher,
                    &proof,
                    1,
                    &ops,
                    &root_hash
                ));
            }

            // Changing the root digest should cause verification to fail
            {
                assert!(!AnyTest::verify_proof(
                    &mut hasher,
                    &proof,
                    0,
                    &ops,
                    &hash(b"invalid")
                ));
            }

            // Changing the proof size should cause verification to fail
            {
                let mut proof = proof.clone();
                proof.size = 100;
                let root_hash = db.root(&mut hasher);
                assert!(!AnyTest::verify_proof(
                    &mut hasher,
                    &proof,
                    0,
                    &ops,
                    &root_hash
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    // Test that the`pruning_delay` works as expected.
    #[test_traced("WARN")]
    fn test_any_db_pruning_delay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create database with enough operations to trigger pruning
            let mut hasher = Standard::<Sha256>::new();
            let db_config = any_db_config("pruning_boundary_test");

            let mut db = AnyTest::init(context.clone(), db_config.clone())
                .await
                .unwrap();

            const NUM_OPERATIONS: u64 = 500;
            for i in 0..NUM_OPERATIONS {
                let key = hash(&i.to_be_bytes());
                let value = hash(&(i * 1000).to_be_bytes());
                db.update(key, value).await.unwrap();

                // Commit periodically to advance the inactivity floor
                if i % 100 == 99 {
                    db.commit().await.unwrap();
                }
            }

            // Final commit to establish the inactivity floor
            db.commit().await.unwrap();

            // Get the root digest
            let original_root = db.root(&mut hasher);

            // Verify the pruning boundary is correct
            let oldest_retained = db.oldest_retained_loc().unwrap();
            let inactivity_floor = db.inactivity_floor_loc;
            assert_eq!(
                oldest_retained,
                inactivity_floor.saturating_sub(db_config.pruning_delay)
            );

            // Get proof of items below inactivity floor but after pruning boundary
            let proof_start = oldest_retained;
            let proof_end = std::cmp::min(inactivity_floor, oldest_retained + 10);
            let max_ops = proof_end - proof_start;

            let (original_proof, original_ops) = db.proof(proof_start, max_ops).await.unwrap();

            // Verify the proof works
            assert!(AnyTest::verify_proof(
                &mut hasher,
                &original_proof,
                proof_start,
                &original_ops,
                &original_root
            ));

            // Close and reopen the database
            db.close().await.unwrap();
            let db = AnyTest::init(context.clone(), db_config).await.unwrap();

            // Confirm root is identical after restart
            let reopened_root = db.root(&mut hasher);
            assert_eq!(original_root, reopened_root,);

            // Get proof of items below inactivity floor again
            let (reopened_proof, reopened_ops) = db.proof(proof_start, max_ops).await.unwrap();

            // Verify the proof still works and is identical
            assert_eq!(original_proof.size, reopened_proof.size);
            assert_eq!(original_proof.digests, reopened_proof.digests);
            assert_eq!(original_ops, reopened_ops);

            assert!(AnyTest::verify_proof(
                &mut hasher,
                &reopened_proof,
                proof_start,
                &reopened_ops,
                &reopened_root
            ));

            db.destroy().await.unwrap();
        });
    }

    // Test that databases with different `pruning_delay` values generate the same root.
    #[test_traced("WARN")]
    fn test_any_db_different_pruning_delays_same_root() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();

            // Create two databases with different pruning delays
            let mut db_config_no_delay = any_db_config("no_delay_test");
            db_config_no_delay.pruning_delay = 0;

            let mut db_config_max_delay = any_db_config("max_delay_test");
            db_config_max_delay.pruning_delay = u64::MAX;

            let mut db_no_delay = AnyTest::init(context.clone(), db_config_no_delay.clone())
                .await
                .unwrap();
            let mut db_max_delay = AnyTest::init(context.clone(), db_config_max_delay.clone())
                .await
                .unwrap();

            // Apply identical operations to both databases
            const NUM_OPERATIONS: u64 = 200;
            for i in 0..NUM_OPERATIONS {
                let key = hash(&i.to_be_bytes());
                let value = hash(&(i * 1000).to_be_bytes());

                db_no_delay.update(key, value).await.unwrap();
                db_max_delay.update(key, value).await.unwrap();

                // Commit periodically
                if i % 50 == 49 {
                    db_no_delay.commit().await.unwrap();
                    db_max_delay.commit().await.unwrap();
                }
            }

            // Final commit
            db_no_delay.commit().await.unwrap();
            db_max_delay.commit().await.unwrap();
            let inactivity_floor = db_no_delay.inactivity_floor_loc;

            // Get roots from both databases
            let root_no_delay = db_no_delay.root(&mut hasher);
            let root_max_delay = db_max_delay.root(&mut hasher);

            // Verify they generate the same roots
            assert_eq!(root_no_delay, root_max_delay,);

            // Verify different pruning behaviors
            let oldest_no_delay = db_no_delay.oldest_retained_loc().unwrap();
            let oldest_max_delay = db_max_delay.oldest_retained_loc().unwrap();

            // With pruning_delay=0, more operations should be pruned
            // With pruning_delay=u64::MAX, no operations should be pruned (oldest retained should be 0)
            assert_eq!(oldest_no_delay, inactivity_floor);
            assert_eq!(oldest_max_delay, 0);

            // Close both databases
            db_no_delay.close().await.unwrap();
            db_max_delay.close().await.unwrap();

            // Restart both databases
            let db_no_delay = AnyTest::init(context.clone(), db_config_no_delay)
                .await
                .unwrap();
            let db_max_delay = AnyTest::init(context.clone(), db_config_max_delay)
                .await
                .unwrap();

            // Get roots after restart
            let root_no_delay_restart = db_no_delay.root(&mut hasher);
            let root_max_delay_restart = db_max_delay.root(&mut hasher);

            // Ensure roots still match after restart
            assert_eq!(root_no_delay, root_no_delay_restart);
            assert_eq!(root_max_delay, root_max_delay_restart);

            // Verify pruning boundaries are still different
            let oldest_no_delay_restart = db_no_delay.oldest_retained_loc().unwrap();
            let oldest_max_delay_restart = db_max_delay.oldest_retained_loc().unwrap();

            assert_eq!(oldest_no_delay_restart, inactivity_floor);
            assert_eq!(oldest_max_delay_restart, 0);

            db_no_delay.destroy().await.unwrap();
            db_max_delay.destroy().await.unwrap();
        });
    }
}
