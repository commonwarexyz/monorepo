//! An authenticated database (ADB) that provides succinct proofs of _any_ value ever associated
//! with a key, where values can have varying sizes.
//!
//! _If the values you wish to store all have the same size, use the [crate::adb::any::fixed::Any]
//! db instead._

use crate::{
    adb::{align_mmr_and_locations, Error},
    index::Index,
    journal::{
        fixed::{Config as FConfig, Journal as FJournal},
        variable::{Config as VConfig, Journal as VJournal},
    },
    mmr::{
        iterator::{leaf_num_to_pos, leaf_pos_to_num},
        journaled::{Config as MmrConfig, Mmr},
        Proof, StandardHasher as Standard,
    },
    store::operation::Variable as Operation,
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

pub mod sync;

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

    /// The name of the [RStorage] partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of items to put in each section of the journal.
    pub log_items_per_section: NonZeroU64,

    /// The name of the [RStorage] partition used for the location map.
    pub locations_journal_partition: String,

    /// The number of items to put in each blob in the location map.
    pub locations_items_per_blob: NonZeroU64,

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

    /// A (pruned) log of all operations applied to the db in order of occurrence. The position of
    /// each operation in the log is called its _location_, which is a stable identifier. Pruning is
    /// indicated by a non-zero value for `pruned_loc`, which provides the location of the first
    /// operation in the log.
    ///
    /// # Invariant
    ///
    /// An operation's location is always equal to the number of the MMR leaf storing the digest of
    /// the operation.
    log: VJournal<E, Operation<K, V>>,

    /// The number of operations that have been appended to the log (which must equal the number of
    /// leaves in the MMR).
    log_size: u64,

    /// The number of items to put in each section of the journal.
    log_items_per_section: u64,

    /// A fixed-length journal that maps an operation's location to its offset within its respective
    /// section of the log. (The section number is derived from location.)
    locations: FJournal<E, u32>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    inactivity_floor_loc: u64,

    /// The location of the oldest operation in the log that remains readable.
    oldest_retained_loc: u64,

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
        let snapshot: Index<T, u64> =
            Index::init(context.with_label("snapshot"), cfg.translator.clone());
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

        let log = VJournal::init(
            context.with_label("log"),
            VConfig {
                partition: cfg.log_journal_partition,
                compression: cfg.log_compression,
                codec_config: cfg.log_codec_config,
                buffer_pool: cfg.buffer_pool.clone(),
                write_buffer: cfg.log_write_buffer,
            },
        )
        .await?;

        let locations = FJournal::init(
            context.with_label("locations"),
            FConfig {
                partition: cfg.locations_journal_partition,
                items_per_blob: cfg.locations_items_per_blob,
                write_buffer: cfg.log_write_buffer,
                buffer_pool: cfg.buffer_pool,
            },
        )
        .await?;

        let db = Self {
            mmr,
            log,
            log_size: 0,
            inactivity_floor_loc: 0,
            oldest_retained_loc: 0,
            locations,
            log_items_per_section: cfg.log_items_per_section.get(),
            uncommitted_ops: 0,
            snapshot,
            hasher,
        };

        db.build_snapshot_from_log().await
    }

    /// Builds the database's snapshot by replaying the log from inception, while also:
    ///   - trimming any uncommitted operations from the log,
    ///   - adding log operations to the MMR & location map if they are missing,
    ///   - removing any elements from the MMR & location map that don't remain in the log after
    ///     trimming.
    ///
    /// # Post-condition
    ///
    /// The number of operations in the log, locations, and the number of leaves in the MMR are
    /// equal.
    async fn build_snapshot_from_log(mut self) -> Result<Self, Error> {
        // Align the mmr with the location map. Any elements we remove here that are still in the
        // log will be re-added later.
        let mut mmr_leaves = align_mmr_and_locations(&mut self.mmr, &mut self.locations).await?;

        // The location and blob-offset of the first operation to follow the last known commit point.
        let mut after_last_commit = None;
        // The set of operations that have not yet been committed.
        let mut uncommitted_ops = HashMap::new();
        let mut oldest_retained_loc_found = false;

        // Replay the log from inception to build the snapshot, keeping track of any uncommitted
        // operations, and any log operations that need to be re-added to the MMR & locations.
        {
            let stream = self
                .log
                .replay(0, 0, NZUsize!(SNAPSHOT_READ_BUFFER_SIZE))
                .await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Err(e) => {
                        return Err(Error::Journal(e));
                    }
                    Ok((section, offset, _, op)) => {
                        if !oldest_retained_loc_found {
                            self.log_size = section * self.log_items_per_section;
                            self.oldest_retained_loc = self.log_size;
                            oldest_retained_loc_found = true;
                        }

                        let loc = self.log_size; // location of the current operation.
                        if after_last_commit.is_none() {
                            after_last_commit = Some((loc, offset));
                        }

                        self.log_size += 1;

                        // Consistency check: confirm the provided section matches what we expect from this operation's
                        // index.
                        let expected = loc / self.log_items_per_section;
                        assert_eq!(section, expected,
                                "given section {section} did not match expected section {expected} from location {loc}");

                        if self.log_size > mmr_leaves {
                            warn!(
                                section,
                                offset, "operation was missing from MMR/location map"
                            );
                            self.mmr.add(&mut self.hasher, &op.encode()).await?;
                            self.locations.append(offset).await?;
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
                            Operation::CommitFloor(_, loc) => {
                                self.inactivity_floor_loc = loc;

                                // Apply all uncommitted operations.
                                for (key, (old_loc, new_loc)) in uncommitted_ops.iter() {
                                    if let Some(old_loc) = old_loc {
                                        if let Some(new_loc) = new_loc {
                                            Self::update_loc(
                                                &mut self.snapshot,
                                                key,
                                                *old_loc,
                                                *new_loc,
                                            );
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
                            _ => unreachable!(
                                "unexpected operation type at offset {offset} of section {section}"
                            ),
                        }
                    }
                }
            }
        }

        // Rewind the operations log if necessary.
        if let Some((end_loc, end_offset)) = after_last_commit {
            assert!(!uncommitted_ops.is_empty());
            warn!(
                op_count = uncommitted_ops.len(),
                log_size = end_loc,
                end_offset,
                "rewinding over uncommitted operations at end of log"
            );
            let prune_to_section = end_loc / self.log_items_per_section;
            self.log
                .rewind_to_offset(prune_to_section, end_offset)
                .await?;
            self.log.sync(prune_to_section).await?;
            self.log_size = end_loc;
        }

        // Pop any MMR elements that are ahead of the last log commit point.
        if mmr_leaves > self.log_size {
            self.locations.rewind(self.log_size).await?;
            self.locations.sync().await?;

            let op_count = mmr_leaves - self.log_size;
            warn!(op_count, "popping uncommitted MMR operations");
            self.mmr.pop(op_count as usize).await?;
        }

        // Confirm post-conditions hold.
        assert_eq!(self.log_size, leaf_pos_to_num(self.mmr.size()).unwrap());
        assert_eq!(self.log_size, self.locations.size().await?);

        debug!(log_size = self.log_size, "build_snapshot_from_log complete");

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

    /// Get the value of the operation with location `loc` in the db. Returns [Error::OperationPruned]
    /// if loc precedes the oldest retained location. The location is otherwise assumed valid.
    ///
    /// # Panics
    ///
    /// Panics if `loc` is greater than or equal to the number of operations in the log.
    pub async fn get_loc(&self, loc: u64) -> Result<Option<V>, Error> {
        assert!(loc < self.op_count());
        if loc < self.oldest_retained_loc {
            return Err(Error::OperationPruned(loc));
        }

        let offset = self.locations.read(loc).await?;
        let section = loc / self.log_items_per_section;
        let op = self.log.get(section, offset).await?;

        Ok(op.into_value())
    }

    /// Returns the location of the operation that set the key's current value, or None if the key
    /// isn't currently assigned any value.
    pub async fn get_key_loc(&self, key: &K) -> Result<Option<u64>, Error> {
        let iter = self.snapshot.get(key);
        for &loc in iter {
            if self.get_from_loc(key, loc).await?.is_some() {
                return Ok(Some(loc));
            }
        }

        Ok(None)
    }

    /// Remove the location `delete_loc` from the snapshot if it's associated with `key`.
    fn delete_loc(snapshot: &mut Index<T, u64>, key: &K, delete_loc: u64) {
        let Some(mut cursor) = snapshot.get_mut(key) else {
            return;
        };

        while let Some(&loc) = cursor.next() {
            if loc == delete_loc {
                cursor.delete();
                return;
            }
        }
    }

    /// Update the location associated with `key` with value `old_loc` to `new_loc`. If there is no
    /// such key or value, this is a no-op.
    fn update_loc(snapshot: &mut Index<T, u64>, key: &K, old_loc: u64, new_loc: u64) {
        let Some(mut cursor) = snapshot.get_mut(key) else {
            return;
        };

        while let Some(&loc) = cursor.next() {
            if loc == old_loc {
                cursor.update(new_loc);
                return;
            }
        }
    }

    /// Get the value of the operation with location `loc` in the db if it matches `key`. The
    /// location is assumed valid.
    ///
    /// # Panics
    ///
    /// Panics if `loc` is greater than or equal to the number of operations in the log.
    pub async fn get_from_loc(&self, key: &K, loc: u64) -> Result<Option<V>, Error> {
        assert!(loc < self.op_count());

        match self.locations.read(loc).await {
            Ok(offset) => {
                return self.get_from_offset(key, loc, offset).await;
            }
            Err(e) => Err(Error::Journal(e)),
        }
    }

    /// Get the operation at location `loc` in the log.
    async fn get_op(&self, loc: u64) -> Result<Operation<K, V>, Error> {
        match self.locations.read(loc).await {
            Ok(offset) => {
                let section = loc / self.log_items_per_section;
                self.log.get(section, offset).await.map_err(Error::Journal)
            }
            Err(e) => Err(Error::Journal(e)),
        }
    }

    /// Get the value of the operation with location `loc` and offset `offset` in the log if it
    /// matches `key`.
    async fn get_from_offset(&self, key: &K, loc: u64, offset: u32) -> Result<Option<V>, Error> {
        let section = loc / self.log_items_per_section;
        let Operation::Update(k, v) = self.log.get(section, offset).await? else {
            panic!("didn't find Update operation at location {loc} and offset {offset}");
        };

        if k != *key {
            Ok(None)
        } else {
            Ok(Some(v))
        }
    }

    /// Get the number of operations that have been applied to this db, including those that are not
    /// yet committed.
    pub fn op_count(&self) -> u64 {
        self.log_size
    }

    /// Returns the section of the log where we are currently writing new items.
    fn current_section(&self) -> u64 {
        self.log_size / self.log_items_per_section
    }

    /// Return the oldest location that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Option<u64> {
        if self.log_size == 0 {
            None
        } else {
            Some(self.oldest_retained_loc)
        }
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive.
    pub fn inactivity_floor_loc(&self) -> u64 {
        self.inactivity_floor_loc
    }

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        let new_loc = self.op_count();
        if let Some(old_loc) = self.get_key_loc(&key).await? {
            Self::update_loc(&mut self.snapshot, &key, old_loc, new_loc);
        } else {
            self.snapshot.insert(&key, new_loc);
        };

        let op = Operation::Update(key, value);
        self.apply_op(op).await?;

        Ok(())
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
        let section = self.current_section();

        // Create a future that appends the operation to the log, then puts its resulting offset
        // into locations.
        let log_fut = async {
            let (offset, _) = self.log.append(section, op).await?;
            self.locations.append(offset).await?;

            Ok::<(), Error>(())
        };

        // Run the log update future in parallel with adding the operation to the MMR.
        try_join!(
            log_fut,
            self.mmr
                .add_batched(&mut self.hasher, &encoded_op)
                .map_err(Error::Mmr),
        )?;
        self.uncommitted_ops += 1;
        self.log_size += 1;

        // Maintain invariant that all filled sections are synced and immutable.
        if self.current_section() != section {
            self.log.sync(section).await?;
        }

        Ok(())
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
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        self.historical_proof(self.op_count(), start_loc, max_ops)
            .await
    }

    /// Analogous to proof, but with respect to the state of the MMR when it had `size` elements.
    ///
    /// # Panics
    ///
    /// - Panics if `start_loc` greater than or equal to `size`.
    /// - Panics if `size` is greater than the number of operations.
    pub async fn historical_proof(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: u64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
        assert!(size <= self.op_count());
        assert!(start_loc < size);

        let start_pos = leaf_num_to_pos(start_loc);
        let end_index = std::cmp::min(size - 1, start_loc + max_ops - 1);
        let end_pos = leaf_num_to_pos(end_index);
        let mmr_size = leaf_num_to_pos(size);

        let proof = self
            .mmr
            .historical_range_proof(mmr_size, start_pos, end_pos)
            .await?;
        let mut ops = Vec::with_capacity((end_index - start_loc + 1) as usize);
        for loc in start_loc..=end_index {
            let section = loc / self.log_items_per_section;
            let offset = self.locations.read(loc).await?;
            let op = self.log.get(section, offset).await?;
            ops.push(op);
        }

        Ok((proof, ops))
    }

    /// Commit any pending operations to the database, ensuring their durability
    /// upon return from this function. Also raises the inactivity floor
    /// according to the schedule. Caller can associate an arbitrary `metadata`
    /// value with the commit.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require
    /// reprocessing to recover the database on restart.
    pub async fn commit(&mut self, metadata: Option<V>) -> Result<(), Error> {
        // Raise the inactivity floor by the # of uncommitted operations, plus 1 to account for the
        // commit op that will be appended.
        self.raise_inactivity_floor(metadata, self.uncommitted_ops + 1)
            .await?;

        // Sync the log and process the updates to the MMR in parallel.
        let section = self.current_section();
        let mmr_fut = async {
            self.mmr.process_updates(&mut self.hasher);
            Ok::<(), Error>(())
        };
        try_join!(self.log.sync(section).map_err(Error::Journal), mmr_fut)?;

        debug!(log_size = self.log_size, "commit complete");
        self.uncommitted_ops = 0;

        Ok(())
    }

    /// Get the location and metadata associated with the last commit, or None if no commit has been
    /// made.
    pub async fn get_metadata(&self) -> Result<Option<(u64, Option<V>)>, Error> {
        let mut last_commit = self.op_count() - self.uncommitted_ops;
        if last_commit == 0 {
            return Ok(None);
        }
        last_commit -= 1;
        let section = last_commit / self.log_items_per_section;
        let offset = self.locations.read(last_commit).await?;
        let Operation::CommitFloor(metadata, _) = self.log.get(section, offset).await? else {
            unreachable!("no commit operation at location of last commit {last_commit}");
        };

        Ok(Some((last_commit, metadata)))
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let section = self.current_section();
        try_join!(
            self.mmr.sync(&mut self.hasher).map_err(Error::Mmr),
            self.log.sync(section).map_err(Error::Journal),
            self.locations.sync().map_err(Error::Journal),
        )?;

        Ok(())
    }

    // Moves the given operation to the tip of the log if it is active, rendering its old location
    // inactive. If the operation was not active, then this is a no-op. Returns the old location
    // of the operation if it was active.
    pub(super) async fn move_op_if_active(
        &mut self,
        op: Operation<K, V>,
        old_loc: u64,
    ) -> Result<Option<u64>, Error> {
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

    /// Raise the inactivity floor by exactly `max_steps` steps, followed by applying a commit
    /// operation. Each step either advances over an inactive operation, or re-applies an active
    /// operation to the tip and then advances over it.
    ///
    /// This method does not change the state of the db's snapshot, but it always changes the root
    /// since it applies at least one operation.
    async fn raise_inactivity_floor(
        &mut self,
        metadata: Option<V>,
        max_steps: u64,
    ) -> Result<(), Error> {
        for _ in 0..max_steps {
            if self.inactivity_floor_loc == self.op_count() {
                break;
            }
            let op = self.get_op(self.inactivity_floor_loc).await?;
            self.move_op_if_active(op, self.inactivity_floor_loc)
                .await?;
            self.inactivity_floor_loc += 1;
        }

        self.apply_op(Operation::CommitFloor(metadata, self.inactivity_floor_loc))
            .await?;

        Ok(())
    }

    /// Prune historical operations. This does not affect the db's root or current snapshot.
    ///
    /// # Panics
    ///
    /// Panics if `target_prune_loc` is greater than the inactivity floor.
    pub async fn prune(&mut self, target_prune_loc: u64) -> Result<(), Error> {
        assert!(target_prune_loc <= self.inactivity_floor_loc);
        if target_prune_loc <= self.oldest_retained_loc {
            return Ok(());
        }

        // Sync the mmr before pruning the log, otherwise the MMR tip could end up behind the log's
        // pruning boundary on restart from an unclean shutdown, and there would be no way to replay
        // the operations between the MMR tip and the log pruning boundary.
        // TODO(https://github.com/commonwarexyz/monorepo/issues/1554): We currently sync locations
        // as well, but this could be avoided by extending recovery.
        try_join!(
            self.mmr.sync(&mut self.hasher).map_err(Error::Mmr),
            self.locations.sync().map_err(Error::Journal),
        )?;

        // Prune the log up to the section containing the requested pruning location. We always
        // prune the log first, and then prune the MMR+locations structures based on the log's
        // actual pruning boundary. This procedure ensures all log operations always have
        // corresponding MMR & location entries, even in the event of failures, with no need for
        // special recovery.
        let section_with_target = target_prune_loc / self.log_items_per_section;
        if !self.log.prune(section_with_target).await? {
            return Ok(());
        }
        self.oldest_retained_loc = section_with_target * self.log_items_per_section;

        debug!(
            log_size = self.log_size,
            oldest_retained_loc = self.oldest_retained_loc,
            "pruned inactive ops"
        );

        // Prune the MMR & locations map up to the oldest retained item in the log after pruning.
        try_join!(
            self.locations
                .prune(self.oldest_retained_loc)
                .map_err(Error::Journal),
            self.mmr
                .prune_to_pos(&mut self.hasher, leaf_num_to_pos(self.oldest_retained_loc))
                .map_err(Error::Mmr),
        )?;

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
            self.mmr.close(&mut self.hasher).map_err(Error::Mmr),
            self.log.close().map_err(Error::Journal),
            self.locations.close().map_err(Error::Journal),
        )?;

        Ok(())
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        try_join!(
            self.log.destroy().map_err(Error::Journal),
            self.mmr.destroy().map_err(Error::Mmr),
            self.locations.destroy().map_err(Error::Journal),
        )?;

        Ok(())
    }

    /// Simulate an unclean shutdown by consuming the db without syncing (or only partially syncing)
    /// the log and/or locations and/or mmr. When _not_ fully syncing the mmr, the `write_limit`
    /// parameter dictates how many mmr nodes to write during a partial sync (can be 0).
    #[cfg(test)]
    pub(super) async fn simulate_failure(
        mut self,
        sync_log: bool,
        sync_locations: bool,
        sync_mmr: bool,
        write_limit: usize,
    ) -> Result<(), Error> {
        let section = self.current_section();
        if sync_log {
            self.log.sync(section).await?;
        }
        if sync_locations {
            self.locations.sync().await?;
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

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{adb::verify_proof, mmr::mem::Mmr as MemMmr, translator::TwoCap};
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::NZU64;
    use std::collections::HashMap;

    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;

    fn db_config(suffix: &str) -> Config<TwoCap, (commonware_codec::RangeCfg, ())> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_section: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            locations_journal_partition: format!("locations_journal_{suffix}"),
            locations_items_per_blob: NZU64!(7),
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
    pub fn test_any_variable_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = Standard::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.oldest_retained_loc(), None);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            assert_eq!(db.root(&mut hasher), MemMmr::default().root(&mut hasher));

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let d1 = Sha256::fill(1u8);
            let v1 = vec![1u8; 8];
            let root = db.root(&mut hasher);
            db.update(d1, v1).await.unwrap();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.op_count(), 0);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 1); // floor op added
            let root = db.root(&mut hasher);
            assert!(matches!(db.prune(db.inactivity_floor_loc()).await, Ok(())));
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);

            // Confirm the inactivity floor doesn't fall endlessly behind with multiple commits.
            for _ in 1..100 {
                db.commit(None).await.unwrap();
                assert_eq!(db.op_count() - 1, db.inactivity_floor_loc);
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
            assert_eq!(db.inactivity_floor_loc, 0);
            db.sync().await.unwrap();

            // Advance over 3 inactive operations.
            db.raise_inactivity_floor(None, 3).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, 3);
            assert_eq!(db.op_count(), 6); // 4 updates, 1 deletion, 1 commit
            db.sync().await.unwrap();

            // Delete all keys.
            db.delete(d1).await.unwrap();
            db.delete(d2).await.unwrap();
            assert!(db.get(&d1).await.unwrap().is_none());
            assert!(db.get(&d2).await.unwrap().is_none());
            assert_eq!(db.op_count(), 8); // 4 updates, 3 deletions, 1 commit
            assert_eq!(db.inactivity_floor_loc, 3);

            db.sync().await.unwrap();

            // Multiple deletions of the same key should be a no-op.
            db.delete(d1).await.unwrap();
            assert_eq!(db.op_count(), 8);

            // Deletions of non-existent keys should be a no-op.
            let d3 = Sha256::fill(3u8);
            db.delete(d3).await.unwrap();
            assert_eq!(db.op_count(), 8);

            // Make sure closing/reopening gets us back to the same state.
            let metadata = Some(vec![99, 100]);
            db.commit(metadata.clone()).await.unwrap();
            assert_eq!(db.op_count(), 9);
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 9);
            assert_eq!(db.root(&mut hasher), root);

            // Since this db no longer has any active keys, we should be able to raise the
            // inactivity floor to the tip (only the inactive commit op remains).
            db.raise_inactivity_floor(None, 100).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, db.op_count() - 1);

            // Make sure we can still get the metadata.
            assert_eq!(db.get_metadata().await.unwrap(), Some((8, metadata)));

            // Re-activate the keys by updating them.
            db.update(d1, v1.clone()).await.unwrap();
            db.update(d2, v2.clone()).await.unwrap();
            db.delete(d1).await.unwrap();
            db.update(d2, v1.clone()).await.unwrap();
            db.update(d1, v2.clone()).await.unwrap();
            assert_eq!(db.snapshot.keys(), 2);

            // Confirm close/reopen gets us back to the same state.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 19);
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.snapshot.keys(), 2);
            assert_eq!(db.op_count(), 19);
            assert_eq!(db.get_metadata().await.unwrap(), Some((18, None)));

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
            assert_eq!(db.inactivity_floor_loc, 0);
            assert_eq!(db.oldest_retained_loc().unwrap(), 0); // no pruning yet
            assert_eq!(db.snapshot.items(), 857);

            // Test that commit will raise the activity floor.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 2336);
            assert_eq!(db.inactivity_floor_loc, 1478);
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.oldest_retained_loc().unwrap(), 1477);
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
            db.raise_inactivity_floor(None, 3000).await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, 4478);
            // Inactivity floor should be 858 operations from tip since 858 operations are active
            // (counting the floor op itself).
            assert_eq!(db.op_count(), 4478 + 858);
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
            let max_ops = 4;
            let end_loc = db.op_count();
            let start_pos = db.mmr.pruned_to_pos();
            let start_loc = leaf_pos_to_num(start_pos).unwrap();
            // Raise the inactivity floor and make sure historical inactive operations are still provable.
            db.raise_inactivity_floor(None, 100).await.unwrap();
            db.sync().await.unwrap();
            let root = db.root(&mut hasher);
            assert!(start_loc < db.inactivity_floor_loc);

            for i in start_loc..end_loc {
                let (proof, log) = db.proof(i, max_ops).await.unwrap();
                assert!(verify_proof(&mut hasher, &proof, i, &log, &root));
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
            db.simulate_failure(false, false, false, 0).await.unwrap();
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
            db.simulate_failure(false, false, false, 0).await.unwrap();
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
            db.simulate_failure(false, false, false, 0).await.unwrap();
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
            assert_eq!(db.op_count(), 2787);
            assert_eq!(leaf_pos_to_num(db.mmr.size()), Some(2787));
            assert_eq!(db.locations.size().await.unwrap(), 2787);
            assert_eq!(db.inactivity_floor_loc, 1480);
            db.sync().await.unwrap(); // test pruning boundary after sync w/ prune
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.oldest_retained_loc().unwrap(), 1477);
            assert_eq!(db.snapshot.items(), 857);
            db.close().await.unwrap();

            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), 2787);
            assert_eq!(leaf_pos_to_num(db.mmr.size()), Some(2787));
            assert_eq!(db.locations.size().await.unwrap(), 2787);
            assert_eq!(db.inactivity_floor_loc, 1480);
            assert_eq!(db.oldest_retained_loc().unwrap(), 1477);
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
            db.simulate_failure(false, false, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time sync the log.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true, false, false, 10).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time only fully sync locations.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false, true, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time only fully sync mmr.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false, false, true, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);

            // Repeat, though this time fully sync log + mmr.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true, false, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);

            // Repeat, though this time fully sync log + locations.
            apply_more_ops(&mut db).await;
            db.simulate_failure(true, true, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);

            // Repeat, though this time fully sync only locations + mmr.
            apply_more_ops(&mut db).await;
            db.simulate_failure(false, true, true, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);

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
            db.simulate_failure(false, false, false, 1).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Insert another 1000 keys then simulate failure (sync only the log).
            apply_ops(&mut db).await;
            db.simulate_failure(true, false, false, 0).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            // Insert another 1000 keys then simulate failure (sync only the mmr).
            apply_ops(&mut db).await;
            db.simulate_failure(false, true, false, 0).await.unwrap();
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
}
