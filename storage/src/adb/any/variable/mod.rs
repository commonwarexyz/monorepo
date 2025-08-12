//! An authenticated database (ADB) that provides succinct proofs of _any_ value ever associated
//! with a key, where values can have varying sizes.
//!
//! _If the values you wish to store all have the same size, use the [crate::adb::any::fixed::Any]
//! db instead._

use crate::{
    adb::Error,
    index::Index,
    journal::{
        fixed::{Config as FConfig, Journal as FJournal},
        variable::{Config as VConfig, Journal as VJournal},
    },
    mmr::{
        hasher::Standard,
        iterator::{leaf_num_to_pos, leaf_pos_to_num},
        journaled::{Config as MmrConfig, Mmr},
        verification::Proof,
    },
    store::operation::Variable as Operation,
    translator::Translator,
};
use commonware_codec::{Codec, Encode as _, Read};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage, ThreadPool};
use commonware_utils::{sequence::U32, Array, NZUsize};
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
    locations: FJournal<E, U32>,

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
        let mut mmr_leaves = leaf_pos_to_num(self.mmr.size()).unwrap();
        let locations_size = self.locations.size().await?;
        if locations_size > mmr_leaves {
            warn!(
                mmr_leaves,
                locations_size, "rewinding misaligned locations map"
            );
            self.locations.rewind(mmr_leaves).await?;
        } else if mmr_leaves > locations_size {
            warn!(mmr_leaves, locations_size, "rewinding misaligned mmr");
            self.mmr.pop((mmr_leaves - locations_size) as usize).await?;
            mmr_leaves = locations_size;
        }

        // The size of the log at the last commit point (including the commit operation), or 0 if
        // none.
        let mut end_loc = 0;
        // The offset into the log at the end_loc.
        let mut end_offset = 0;
        // The set of operations that have not yet been committed.
        let mut uncommitted_ops = HashMap::new();
        let mut oldest_retained_loc_found = false;

        // Replay the log from inception to build the snapshot, keeping track of any uncommitted
        // operations, and any log operations that need to be re-added to the MMR & locations.
        {
            let stream = self.log.replay(NZUsize!(SNAPSHOT_READ_BUFFER_SIZE)).await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Err(e) => {
                        return Err(Error::Journal(e));
                    }
                    Ok((section, offset, size, op)) => {
                        if !oldest_retained_loc_found {
                            self.log_size = section * self.log_items_per_section;
                            self.oldest_retained_loc = self.log_size;
                            oldest_retained_loc_found = true;
                        }
                        let loc = self.log_size; // location of the current operation.
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
                            self.locations.append(offset.into()).await?;
                            mmr_leaves += 1;
                        }

                        match op {
                            Operation::Delete(key) => {
                                let result = self.get_loc(&key).await?;
                                if let Some(old_loc) = result {
                                    uncommitted_ops.insert(key, (Some(old_loc), None));
                                } else {
                                    uncommitted_ops.remove(&key);
                                }
                            }
                            Operation::Update(key, _) => {
                                let result = self.get_loc(&key).await?;
                                if let Some(old_loc) = result {
                                    uncommitted_ops.insert(key, (Some(old_loc), Some(loc)));
                                } else {
                                    uncommitted_ops.insert(key, (None, Some(loc)));
                                }
                            }
                            Operation::CommitFloor(loc) => {
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
                                end_loc = self.log_size;
                                end_offset = offset + size;
                            }
                            _ => unreachable!(
                                "unexpected operation type at offset {offset} of section {section}"
                            ),
                        }
                    }
                }
            }
        }
        if end_loc < self.log_size {
            warn!(
                op_count = uncommitted_ops.len(),
                log_size = end_loc,
                "rewinding over uncommitted operations at end of log"
            );
            // We use saturating_sub below for the case where end_loc == 0, which happens when there
            // are no committed operations at all remaining.
            let prune_to_section = end_loc.saturating_sub(1) / self.log_items_per_section;
            self.log
                .rewind_to_offset(prune_to_section, end_offset)
                .await?;
            self.log.sync(prune_to_section).await?;
            self.log_size = end_loc;
        }

        // Pop any MMR elements that are ahead of the last log commit point.
        if mmr_leaves > self.log_size {
            self.locations.rewind(self.log_size).await?;

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

    /// Returns the location of the operation that set the key's current value, or None if the key isn't currently assigned any value.
    pub async fn get_loc(&self, key: &K) -> Result<Option<u64>, Error> {
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
    pub async fn get_from_loc(&self, key: &K, loc: u64) -> Result<Option<V>, Error> {
        match self.locations.read(loc).await {
            Ok(offset) => {
                return self.get_from_offset(key, loc, offset.into()).await;
            }
            Err(e) => Err(Error::Journal(e)),
        }
    }

    /// Get the operation at location `loc` in the log.
    async fn get_op(&self, loc: u64) -> Result<Option<Operation<K, V>>, Error> {
        match self.locations.read(loc).await {
            Ok(offset) => {
                let section = loc / self.log_items_per_section;
                self.log
                    .get(section, offset.into())
                    .await
                    .map_err(Error::Journal)
            }
            Err(e) => Err(Error::Journal(e)),
        }
    }

    /// Get the value of the operation with location `loc` and offset `offset` in the log if it
    /// matches `key`.
    async fn get_from_offset(&self, key: &K, loc: u64, offset: u32) -> Result<Option<V>, Error> {
        let section = loc / self.log_items_per_section;
        let Some(Operation::Update(k, v)) = self.log.get(section, offset).await? else {
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

    /// Return the inactivity floor location.
    /// This is the location before which all operations are inactive.
    pub fn inactivity_floor_loc(&self) -> u64 {
        self.inactivity_floor_loc
    }

    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        let new_loc = self.op_count();
        if let Some(old_loc) = self.get_loc(&key).await? {
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
        let Some(old_loc) = self.get_loc(&key).await? else {
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
        // Update the ops MMR.
        self.mmr.add_batched(&mut self.hasher, &op.encode()).await?;
        self.uncommitted_ops += 1;

        let section = self.current_section();
        let (offset, _) = self.log.append(section, op).await?;
        self.log_size += 1;
        self.locations.append(offset.into()).await?;

        if section != self.current_section() {
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
    pub async fn historical_proof(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: u64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V>>), Error> {
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
            let offset = self.locations.read(loc).await?.into();
            let Some(op) = self.log.get(section, offset).await? else {
                panic!("no log item at location {loc}");
            };
            ops.push(op);
        }

        Ok((proof, ops))
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
        debug!(log_size = self.log_size, "commit complete");

        // TODO: Make the frequency with which we prune known inactive items configurable in case
        // this turns out to be a significant part of commit overhead, or the user wants to ensure
        // the log is backed up externally before discarding.
        self.prune_inactive().await?;

        Ok(())
    }

    /// Sync the db to disk ensuring the current state is persisted. Batch operations will be
    /// parallelized if a thread pool is provided.
    pub(super) async fn sync(&mut self) -> Result<(), Error> {
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
        let Some(key) = op.to_key() else {
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
            let Some(op) = self.get_op(self.inactivity_floor_loc).await? else {
                panic!("no operation at location {}", self.inactivity_floor_loc);
            };
            self.move_op_if_active(op, self.inactivity_floor_loc)
                .await?;
            self.inactivity_floor_loc += 1;
        }

        self.apply_op(Operation::CommitFloor(self.inactivity_floor_loc))
            .await?;

        Ok(())
    }

    /// Prune historical operations that are behind the inactivity floor. This does not affect the
    /// db's root or current snapshot.
    pub(super) async fn prune_inactive(&mut self) -> Result<(), Error> {
        let Some(oldest_retained_loc) = self.oldest_retained_loc() else {
            return Ok(());
        };

        // Calculate the target pruning position: inactivity_floor_loc.
        let target_prune_loc = self.inactivity_floor_loc;
        let ops_to_prune = target_prune_loc.saturating_sub(oldest_retained_loc);
        if ops_to_prune == 0 {
            return Ok(());
        }
        debug!(
            log_size = self.log_size,
            ops_to_prune, target_prune_loc, "pruning inactive ops"
        );

        // Prune the log up to the section containing the requested pruning location. We always
        // prune the log first, and then prune the MMR+locations structures based on the log's
        // actual pruning boundary. This procedure ensures all log operations always have
        // corresponding MMR & location entries, even in the event of failures, with no need for
        // special recovery.
        let section_with_target = target_prune_loc / self.log_items_per_section;
        self.log.prune(section_with_target).await?;
        self.oldest_retained_loc = section_with_target * self.log_items_per_section;

        // Prune the MMR & locations map up to the oldest retained item in the log after pruning.
        self.locations.prune(self.oldest_retained_loc).await?;
        self.mmr
            .prune_to_pos(&mut self.hasher, leaf_num_to_pos(self.oldest_retained_loc))
            .await
            .map_err(Error::Mmr)
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(mut self) -> Result<(), Error> {
        if self.uncommitted_ops > 0 {
            warn!(
                op_count = self.uncommitted_ops,
                "closing db with uncommitted operations"
            );
        }

        let section = self.current_section();
        try_join!(
            self.mmr.sync(&mut self.hasher).map_err(Error::Mmr),
            self.log.sync(section).map_err(Error::Journal),
            self.locations.sync().map_err(Error::Journal),
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

    #[cfg(test)]
    pub(super) async fn simulate_failure(
        mut self,
        sync_mmr: bool,
        sync_locations: bool,
        sync_log: bool,
    ) -> Result<(), Error> {
        let section = self.current_section();
        if sync_mmr {
            self.mmr.sync(&mut self.hasher).await?;
        }
        if sync_log {
            self.log.sync(section).await?;
        }
        if sync_locations {
            self.locations.sync().await?;
        }
        Ok(())
    }
}

impl<E: RStorage + Metrics, V: Codec> VJournal<E, V> {
    /// Initialize a Variable journal for use in state sync.
    ///
    /// The bounds are item locations (not section numbers). This function prepares the
    /// on-disk journal so that subsequent appends go to the correct physical location for the
    /// requested range.
    ///
    /// Behavior by existing on-disk state:
    /// - Fresh (no data): returns an empty journal.
    /// - Stale (all data strictly before `lower_bound`): destroys existing data and returns an
    ///   empty journal.
    /// - Overlap within [`lower_bound`, `upper_bound`]:
    ///   - Prunes sections strictly below `lower_bound / items_per_section` (section-aligned).
    ///   - Removes any sections strictly greater than `upper_bound / items_per_section`.
    ///   - Truncates the final retained section so that no item with location greater
    ///     than `upper_bound` remains.
    ///
    /// Note that lower-bound pruning is section-aligned. This means the first retained section may
    /// still contain items whose locations are < `lower_bound`. Callers should ignore these.
    ///
    /// # Arguments
    /// - `context`: storage context
    /// - `cfg`: journal configuration
    /// - `lower_bound`: first item location to retain (inclusive)
    /// - `upper_bound`: last item location to retain (inclusive)
    /// - `items_per_section`: number of items per section
    ///
    /// # Returns
    /// A journal whose sections satisfy:
    /// - No section index < `lower_bound / items_per_section` exists.
    /// - No section index > `upper_bound / items_per_section` exists.
    /// - The last retained section is truncated so that its last item’s location is `<= upper_bound`.
    pub async fn init_sync(
        context: E,
        cfg: VConfig<V::Cfg>,
        lower_bound: u64,
        upper_bound: u64,
        items_per_section: NonZeroU64,
    ) -> Result<Self, crate::journal::Error> {
        use std::ops::Bound;
        use tracing::debug;

        if lower_bound > upper_bound {
            return Err(crate::journal::Error::InvalidSyncRange(
                lower_bound,
                upper_bound,
            ));
        }

        // Calculate the section ranges based on item locations
        let items_per_section = items_per_section.get();
        let lower_section = lower_bound / items_per_section;
        let upper_section = upper_bound / items_per_section;

        debug!(
            lower_bound,
            upper_bound,
            lower_section,
            upper_section,
            items_per_section = items_per_section,
            "initializing variable journal"
        );

        // Initialize the base journal to see what existing data we have
        let mut journal = Self::init(context.clone(), cfg.clone()).await?;

        let last_section = journal.blobs.last_key_value().map(|(&s, _)| s);

        // No existing data
        let Some(last_section) = last_section else {
            debug!("no existing journal data, creating fresh journal");
            return Ok(journal);
        };

        // If all existing data is before our sync range, destroy and recreate fresh
        if last_section < lower_section {
            debug!(
                last_section,
                lower_section, "existing journal data is stale, re-initializing"
            );
            journal.destroy().await?;
            return Self::init(context, cfg).await;
        }

        // Prune sections below the lower bound.
        if lower_section > 0 {
            journal.prune(lower_section).await?;
        }

        // Remove any sections beyond the upper bound
        if last_section > upper_section {
            debug!(
                last_section,
                lower_section,
                upper_section,
                "existing journal data exceeds sync range, removing sections beyond upper bound"
            );

            let sections_to_remove: Vec<u64> = journal
                .blobs
                .range((Bound::Excluded(upper_section), Bound::Unbounded))
                .map(|(&section, _)| section)
                .collect();

            for section in sections_to_remove {
                debug!(section, "removing section beyond upper bound");
                if let Some(blob) = journal.blobs.remove(&section) {
                    drop(blob);
                    let name = section.to_be_bytes();
                    journal
                        .context
                        .remove(&journal.cfg.partition, Some(&name))
                        .await?;
                    journal.tracked.dec();
                }
            }
        }

        // Remove any items beyond upper_bound
        Self::truncate_upper_section(&mut journal, upper_bound, items_per_section).await?;

        Ok(journal)
    }

    /// Remove items beyond the `upper_bound` location (inclusive).
    /// Assumes each section contains `items_per_section` items.
    async fn truncate_upper_section(
        journal: &mut VJournal<E, V>,
        upper_bound: u64,
        items_per_section: u64,
    ) -> Result<(), crate::journal::Error> {
        // Find which section contains the upper_bound item
        let upper_section = upper_bound / items_per_section;
        let Some(blob) = journal.blobs.get(&upper_section) else {
            return Ok(()); // Section doesn't exist, nothing to truncate
        };

        // Calculate the logical item range for this section
        let section_start = upper_section * items_per_section;
        let section_end = section_start + items_per_section - 1;

        // If upper_bound is at the very end of the section, no truncation needed
        if upper_bound >= section_end {
            return Ok(());
        }

        // Calculate how many items to keep (upper_bound is inclusive)
        let items_to_keep = (upper_bound - section_start + 1) as u32;
        debug!(
            upper_section,
            upper_bound,
            section_start,
            section_end,
            items_to_keep,
            "truncating section to remove items beyond upper_bound"
        );

        // Find where to rewind to (after the last item we want to keep)
        let target_byte_size = Self::compute_offset(
            blob,
            &journal.cfg.codec_config,
            journal.cfg.compression.is_some(),
            items_to_keep,
        )
        .await?;

        // Rewind to the appropriate position to remove items beyond the upper bound
        journal
            .rewind_section(upper_section, target_byte_size)
            .await?;

        debug!(
            upper_section,
            items_to_keep, target_byte_size, "section truncated"
        );

        Ok(())
    }

    /// Return the byte offset of the next element after `items_count` elements of `blob`.
    async fn compute_offset(
        blob: &commonware_runtime::buffer::Append<E::Blob>,
        codec_config: &V::Cfg,
        compressed: bool,
        items_count: u32,
    ) -> Result<u64, crate::journal::Error> {
        use crate::journal::variable::{Journal, ITEM_ALIGNMENT};

        if items_count == 0 {
            return Ok(0);
        }

        let mut current_offset = 0u32;

        // Read through items one by one to find where each one ends
        for _ in 0..items_count {
            match Journal::<E, V>::read(compressed, codec_config, blob, current_offset).await {
                Ok((next_slot, _item_len, _item)) => {
                    current_offset = next_slot;
                }
                Err(crate::journal::Error::Runtime(
                    commonware_runtime::Error::BlobInsufficientLength,
                )) => {
                    // This section has fewer than `items_count` items.
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        Ok((current_offset as u64) * ITEM_ALIGNMENT)
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        adb::verify_proof,
        journal::variable::ITEM_ALIGNMENT,
        mmr::{hasher::Standard, mem::Mmr as MemMmr},
        translator::TwoCap,
    };
    use commonware_cryptography::{hash, sha256::Digest, Sha256};
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
            assert!(matches!(db.prune_inactive().await, Ok(())));
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
            db.raise_inactivity_floor(3).await.unwrap();
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
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 9);
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 9);
            assert_eq!(db.root(&mut hasher), root);

            // Since this db no longer has any active keys, we should be able to raise the
            // inactivity floor to the tip (only the inactive commit op remains).
            db.raise_inactivity_floor(100).await.unwrap();
            assert_eq!(db.inactivity_floor_loc, db.op_count() - 1);

            // Re-activate the keys by updating them.
            db.update(d1, v1.clone()).await.unwrap();
            db.update(d2, v2.clone()).await.unwrap();
            db.delete(d1).await.unwrap();
            db.update(d2, v1.clone()).await.unwrap();
            db.update(d1, v2.clone()).await.unwrap();
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
                let k = hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
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
            assert_eq!(db.oldest_retained_loc().unwrap(), 0); // no pruning yet
            assert_eq!(db.snapshot.items(), 857);

            // Test that commit will raise the activity floor.
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 2336);
            assert_eq!(db.oldest_retained_loc().unwrap(), 1477);
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
            let start_pos = db.mmr.pruned_to_pos();
            let start_loc = leaf_pos_to_num(start_pos).unwrap();
            // Raise the inactivity floor and make sure historical inactive operations are still provable.
            db.raise_inactivity_floor(100).await.unwrap();
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
            let k = hash(&UPDATES.to_be_bytes());
            for i in 0u64..UPDATES {
                let v = vec![(i % 255) as u8; ((i % 7) + 3) as usize];
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

            let mut map = HashMap::<Digest, Vec<u8>>::default();
            const ELEMENTS: u64 = 10;
            // insert & commit multiple batches to ensure repeated inactivity floor raising.
            for j in 0u64..ELEMENTS {
                for i in 0u64..ELEMENTS {
                    let k = hash(&(j * 1000 + i).to_be_bytes());
                    let v = vec![(i % 255) as u8; ((i % 7) + 3) as usize];
                    db.update(k, v.clone()).await.unwrap();
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
                let k = hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failed commit and test that we rollback to the previous root.
            db.simulate_failure(false, false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // re-apply the updates and commit them this time.
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit().await.unwrap();
            let root = db.root(&mut hasher);

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }

            // Simulate a failed commit and test that we rollback to the previous root.
            db.simulate_failure(false, false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply updates for every 3rd key and commit them this time.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                let v = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.update(k, v.clone()).await.unwrap();
            }
            db.commit().await.unwrap();
            let root = db.root(&mut hasher);

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }

            // Simulate a failed commit and test that we rollback to the previous root.
            db.simulate_failure(false, false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-delete every 7th key and commit this time.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
            }
            db.commit().await.unwrap();

            assert_eq!(db.op_count(), 2787);
            assert_eq!(db.inactivity_floor_loc, 1480);
            assert_eq!(db.oldest_retained_loc().unwrap(), 1477);
            assert_eq!(db.snapshot.items(), 857);

            db.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when there is no existing data on disk.
    #[test_traced]
    fn test_init_sync_no_existing_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_fresh_start".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Initialize journal with sync boundaries when no existing data exists
            let lower_bound = 10;
            let upper_bound = 25;
            let items_per_section = NZU64!(5);
            let mut journal = VJournal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with sync boundaries");

            // Verify the journal is ready for sync items
            assert!(journal.blobs.is_empty()); // No sections created yet
            assert_eq!(journal.oldest_allowed, None); // No pruning applied

            // Verify that items can be appended starting from the sync position
            let lower_section = lower_bound / items_per_section; // 10/5 = 2

            // Append an element
            let (offset, _) = journal.append(lower_section, 42u64).await.unwrap();
            assert_eq!(offset, 0); // First item in section

            // Verify the item can be retrieved
            let retrieved = journal.get(lower_section, offset).await.unwrap();
            assert_eq!(retrieved, Some(42u64));

            // Append another element
            let (offset2, _) = journal.append(lower_section, 43u64).await.unwrap();
            assert_eq!(
                journal.get(lower_section, offset2).await.unwrap(),
                Some(43u64)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when there is existing data that overlaps with the sync target range.
    #[test_traced]
    fn test_init_sync_existing_data_overlap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_overlap".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with data in multiple sections
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            let items_per_section = NZU64!(5);

            // Add data to sections 0, 1, 2, 3 (simulating items 0-19 with items_per_section=5)
            for section in 0..4 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 10 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries that overlap with existing data
            // lower_bound: 8 (section 1), upper_bound: 30 (section 6)
            let lower_bound = 8;
            let upper_bound = 30;
            let mut journal = VJournal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with overlap");

            // Verify pruning: sections before lower_section are pruned
            let lower_section = lower_bound / items_per_section; // 8/5 = 1
            assert_eq!(lower_section, 1);
            assert_eq!(journal.oldest_allowed, Some(lower_section));

            // Verify section 0 is pruned (< lower_section), section 1+ are retained (>= lower_section)
            assert!(!journal.blobs.contains_key(&0)); // Section 0 should be pruned
            assert!(journal.blobs.contains_key(&1)); // Section 1 should be retained (contains item 8)
            assert!(journal.blobs.contains_key(&2)); // Section 2 should be retained
            assert!(journal.blobs.contains_key(&3)); // Section 3 should be retained
            assert!(!journal.blobs.contains_key(&4)); // Section 4 should not exist

            // Verify data integrity: existing data in retained sections is accessible
            let item = journal.get(1, 0).await.unwrap();
            assert_eq!(item, Some(10)); // First item in section 1 (1*10+0)
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, Some(11)); // Second item in section 1 (1*10+1)
            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, Some(20)); // First item in section 2 (2*10+0)
            let last_element_section = 19 / items_per_section;
            let last_element_offset = (19 % items_per_section.get()) as u32;
            let item = journal
                .get(last_element_section, last_element_offset)
                .await
                .unwrap();
            assert_eq!(item, Some(34)); // Last item in section 3 (3*10+4)
            let next_element_section = 20 / items_per_section;
            let next_element_offset = (20 % items_per_section.get()) as u32;
            let item = journal
                .get(next_element_section, next_element_offset)
                .await
                .unwrap();
            assert_eq!(item, None); // Next element should not exist

            // Assert journal can accept new items
            let (offset, _) = journal.append(next_element_section, 999).await.unwrap();
            assert_eq!(
                journal.get(next_element_section, offset).await.unwrap(),
                Some(999)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` with invalid parameters.
    #[test_traced]
    fn test_init_sync_invalid_parameters() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_invalid".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Test invalid bounds: lower > upper
            let result = VJournal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                10,        // lower_bound
                5,         // upper_bound (invalid: < lower_bound)
                NZU64!(5), // items_per_section
            )
            .await;
            assert!(matches!(
                result,
                Err(crate::journal::Error::InvalidSyncRange(10, 5))
            ));
        });
    }

    /// Test `init_sync` when existing data exactly matches the sync range.
    #[test_traced]
    fn test_init_sync_existing_data_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_exact_match".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with data exactly matching sync range
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data to sections 1, 2, 3 (operations 5-19 with items_per_section=5)
            let items_per_section = NZU64!(5);
            for section in 1..4 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 100 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries that exactly match existing data
            let lower_bound = 5; // section 1
            let upper_bound = 19; // section 3
            let journal = VJournal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with exact match");

            // Verify pruning to lower bound
            let lower_section = lower_bound / items_per_section; // 5/5 = 1
            assert_eq!(journal.oldest_allowed, Some(lower_section));

            // Verify section 0 is pruned, sections 1-3 are retained
            assert!(!journal.blobs.contains_key(&0)); // Section 0 should be pruned
            assert!(journal.blobs.contains_key(&1)); // Section 1 should be retained (contains operation 5)
            assert!(journal.blobs.contains_key(&2)); // Section 2 should be retained
            assert!(journal.blobs.contains_key(&3)); // Section 3 should be retained

            // Verify data integrity: existing data in retained sections is accessible
            let item = journal.get(1, 0).await.unwrap();
            assert_eq!(item, Some(100)); // First item in section 1 (1*100+0)
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, Some(101)); // Second item in section 1 (1*100+1)
            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, Some(200)); // First item in section 2 (2*100+0)
            let last_element_section = 19 / items_per_section;
            let last_element_offset = (19 % items_per_section.get()) as u32;
            let item = journal
                .get(last_element_section, last_element_offset)
                .await
                .unwrap();
            assert_eq!(item, Some(304)); // Last item in section 3 (3*100+4)
            let next_element_section = 20 / items_per_section;
            let next_element_offset = (20 % items_per_section.get()) as u32;
            let item = journal
                .get(next_element_section, next_element_offset)
                .await
                .unwrap();
            assert_eq!(item, None); // Next element should not exist

            // Assert journal can accept new operations
            let mut journal = journal;
            let (offset, _) = journal.append(next_element_section, 999).await.unwrap();
            assert_eq!(
                journal.get(next_element_section, offset).await.unwrap(),
                Some(999)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when existing data exceeds the sync target range.
    #[test_traced]
    fn test_init_sync_existing_data_with_rewind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_rewind".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with data beyond sync range
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data to sections 0-5 (operations 0-29 with items_per_section=5)
            let items_per_section = NZU64!(5);
            for section in 0..6 {
                for item in 0..items_per_section.get() {
                    journal
                        .append(section, section * 1000 + item)
                        .await
                        .unwrap();
                }
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries that are exceeded by existing data
            let lower_bound = 8; // section 1
            let upper_bound = 17; // section 3
            let mut journal = VJournal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with rewind");

            // Verify pruning to lower bound and rewinding beyond upper bound
            let lower_section = lower_bound / items_per_section; // 8/5 = 1
            assert_eq!(journal.oldest_allowed, Some(lower_section));

            // Verify section 0 is pruned (< lower_section)
            assert!(!journal.blobs.contains_key(&0));

            // Verify sections within sync range exist (lower_section <= section <= upper_section)
            assert!(journal.blobs.contains_key(&1)); // Section 1 (contains operation 8)
            assert!(journal.blobs.contains_key(&2)); // Section 2
            assert!(journal.blobs.contains_key(&3)); // Section 3 (contains operation 17)

            // Verify sections beyond upper bound are removed (> upper_section)
            assert!(!journal.blobs.contains_key(&4)); // Section 4 should be removed
            assert!(!journal.blobs.contains_key(&5)); // Section 5 should be removed

            // Verify data integrity in retained sections
            let item = journal.get(1, 0).await.unwrap();
            assert_eq!(item, Some(1000)); // First item in section 1 (1*1000+0)
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, Some(1001)); // Second item in section 1 (1*1000+1)
            let item = journal.get(3, 0).await.unwrap();
            assert_eq!(item, Some(3000)); // First item in section 3 (3*1000+0)
            let last_element_section = 17 / items_per_section;
            let last_element_offset = (17 % items_per_section.get()) as u32;
            let item = journal
                .get(last_element_section, last_element_offset)
                .await
                .unwrap();
            assert_eq!(item, Some(3002)); // Last item in section 3 (3*1000+2)

            // Verify that section 3 was properly truncated
            let section_3_size = journal.size(3).await.unwrap();
            assert_eq!(section_3_size, 3 * ITEM_ALIGNMENT);

            // Verify that operations beyond upper_bound (17) are not accessible
            // Reading beyond the truncated section should return an error
            let result = journal.get(3, 3).await;
            assert!(result.is_err()); // Operation 18 should be inaccessible (beyond upper_bound=17)

            // Assert journal can accept new operations
            let (offset, _) = journal.append(3, 999).await.unwrap();
            assert_eq!(journal.get(3, offset).await.unwrap(), Some(999));

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when all existing data is stale (before lower bound).
    #[test_traced]
    fn test_init_sync_existing_data_stale() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_stale".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with stale data
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data to sections 0, 1 (operations 0-9 with items_per_section=5)
            let items_per_section = NZU64!(5);
            for section in 0..2 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 100 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Initialize with sync boundaries beyond all existing data
            let lower_bound = 15; // section 3
            let upper_bound = 25; // section 5
            let journal = VJournal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with stale data");

            // Verify fresh journal (all old data destroyed)
            assert!(journal.blobs.is_empty());
            assert_eq!(journal.oldest_allowed, None);

            // Verify old sections don't exist
            assert!(!journal.blobs.contains_key(&0));
            assert!(!journal.blobs.contains_key(&1));

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` with section boundary edge cases.
    #[test_traced]
    fn test_init_sync_section_boundaries() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_boundaries".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create journal with data at section boundaries
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            let items_per_section = NZU64!(5);

            // Add data to sections 0, 1, 2, 3, 4
            for section in 0..5 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 100 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Test sync boundaries exactly at section boundaries
            let lower_bound = 10; // Exactly at section boundary (10/5 = 2)
            let upper_bound = 19; // Exactly at section boundary (19/5 = 3)
            let mut journal = VJournal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal at boundaries");

            // Verify correct section range
            let lower_section = lower_bound / items_per_section; // 2
            assert_eq!(journal.oldest_allowed, Some(lower_section));

            // Verify sections 2, 3, 4 exist, others don't
            assert!(!journal.blobs.contains_key(&0));
            assert!(!journal.blobs.contains_key(&1));
            assert!(journal.blobs.contains_key(&2));
            assert!(journal.blobs.contains_key(&3));
            assert!(!journal.blobs.contains_key(&4)); // Section 4 should not exist

            // Verify data integrity in retained sections
            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, Some(200)); // First item in section 2
            let item = journal.get(3, 4).await.unwrap();
            assert_eq!(item, Some(304)); // Last element
            let next_element_section = 4;
            let item = journal.get(next_element_section, 0).await.unwrap();
            assert_eq!(item, None); // Next element should not exist

            // Assert journal can accept new operations
            let (offset, _) = journal.append(next_element_section, 999).await.unwrap();
            assert_eq!(
                journal.get(next_element_section, offset).await.unwrap(),
                Some(999)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when lower_bound and upper_bound are in the same section.
    #[test_traced]
    fn test_init_sync_same_section_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_same_section".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create journal with data in multiple sections
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            let items_per_section = NZU64!(5);

            // Add data to sections 0, 1, 2
            for section in 0..3 {
                for item in 0..items_per_section.get() {
                    journal.append(section, section * 100 + item).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Test sync boundaries within the same section
            let lower_bound = 6; // operation 6 (section 1: 6/5 = 1)
            let upper_bound = 8; // operation 8 (section 1: 8/5 = 1)
            let journal = VJournal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                items_per_section,
            )
            .await
            .expect("Failed to initialize journal with same-section bounds");

            // Both operations are in section 1, so section 0 should be pruned, section 1+ retained
            let target_section = lower_bound / items_per_section; // 6/5 = 1
            assert_eq!(journal.oldest_allowed, Some(target_section));

            // Verify pruning and retention
            assert!(!journal.blobs.contains_key(&0)); // Section 0 should be pruned
            assert!(journal.blobs.contains_key(&1)); // Section 1 should be retained
            assert!(!journal.blobs.contains_key(&2)); // Section 2 should be removed (> upper_section)

            // Verify data integrity
            let item = journal.get(1, 0).await.unwrap();
            assert_eq!(item, Some(100)); // First item in section 1
            let item = journal.get(1, 1).await.unwrap();
            assert_eq!(item, Some(101)); // Second item in section 1 (1*100+1)
            let item = journal.get(1, 3).await.unwrap();
            assert_eq!(item, Some(103)); // Item at offset 3 in section 1 (1*100+3)

            // Verify that section 1 was properly truncated
            let section_1_size = journal.size(1).await.unwrap();
            assert_eq!(section_1_size, 64); // Should be 4 operations * 16 bytes = 64 bytes

            // Verify that operation beyond upper_bound (8) is not accessible
            let result = journal.get(1, 4).await;
            assert!(result.is_err()); // Operation 9 should be inaccessible (beyond upper_bound=8)

            let item = journal.get(2, 0).await.unwrap();
            assert_eq!(item, None); // Section 2 was removed, so no items

            // Assert journal can accept new operations
            let mut journal = journal;
            let (offset, _) = journal.append(target_section, 999).await.unwrap();
            assert_eq!(
                journal.get(target_section, offset).await.unwrap(),
                Some(999)
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test `compute_offset` correctly calculates byte boundaries for variable-sized items.
    #[test_traced]
    fn test_compute_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_compute_offset".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create a journal and populate a section with 5 operations
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create journal");

            let section = 0;
            for i in 0..5 {
                journal.append(section, i as u64).await.unwrap();
            }
            journal.sync(section).await.unwrap();

            let blob = journal.blobs.get(&section).unwrap();

            // Helper function to compute byte size for N operations
            let compute_offset = |operations_count: u32| async move {
                VJournal::<deterministic::Context, u64>::compute_offset(
                    blob,
                    &journal.cfg.codec_config,
                    journal.cfg.compression.is_some(),
                    operations_count,
                )
                .await
                .unwrap()
            };

            // Test various operation counts (each u64 operation takes 16 bytes when aligned)
            assert_eq!(compute_offset(0).await, 0); // 0 operations = 0 bytes
            assert_eq!(compute_offset(1).await, 16); // 1 operation = 16 bytes
            assert_eq!(compute_offset(3).await, 48); // 3 operations = 48 bytes
            assert_eq!(compute_offset(5).await, 80); // 5 operations = 80 bytes

            // Test requesting more operations than available (should return size of all available)
            assert_eq!(compute_offset(10).await, 80); // Still 80 bytes (capped at available)

            journal.destroy().await.unwrap();
        });
    }

    /// Test `truncate_upper_section` correctly removes items beyond sync boundaries.
    #[test_traced]
    fn test_truncate_section_to_upper_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_truncate_section".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };
            let items_per_section = 5;

            // Helper to create a fresh journal with test data
            let create_journal = || async {
                let mut journal =
                    VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                        .await
                        .expect("Failed to create journal");

                // Add operations to sections 0, 1, 2
                for section in 0..3 {
                    for i in 0..items_per_section {
                        journal.append(section, section * 100 + i).await.unwrap();
                    }
                    journal.sync(section).await.unwrap();
                }
                journal
            };

            // Test 1: No truncation needed (upper_bound at section end)
            {
                let mut journal = create_journal().await;
                let upper_bound = 9; // End of section 1 (section 1: ops 5-9)
                VJournal::<deterministic::Context, u64>::truncate_upper_section(
                    &mut journal,
                    upper_bound,
                    items_per_section,
                )
                .await
                .unwrap();

                // Section 1 should remain unchanged (5 operations = 80 bytes)
                let section_1_size = journal.size(1).await.unwrap();
                assert_eq!(section_1_size, 80);
                journal.destroy().await.unwrap();
            }

            // Test 2: Truncation needed (upper_bound mid-section)
            {
                let mut journal = create_journal().await;
                let upper_bound = 7; // Middle of section 1 (keep ops 5, 6, 7)
                VJournal::<deterministic::Context, u64>::truncate_upper_section(
                    &mut journal,
                    upper_bound,
                    items_per_section,
                )
                .await
                .unwrap();

                // Section 1 should now have only 3 operations (48 bytes)
                let section_1_size = journal.size(1).await.unwrap();
                assert_eq!(section_1_size, 48);

                // Verify the remaining operations are accessible
                assert_eq!(journal.get(1, 0).await.unwrap(), Some(100)); // section 1, offset 0 = 1*100+0
                assert_eq!(journal.get(1, 1).await.unwrap(), Some(101)); // section 1, offset 1 = 1*100+1
                assert_eq!(journal.get(1, 2).await.unwrap(), Some(102)); // section 1, offset 2 = 1*100+2

                // Verify truncated operations are not accessible
                let result = journal.get(1, 3).await;
                assert!(result.is_err()); // op at logical loc 8 should be gone
                journal.destroy().await.unwrap();
            }

            // Test 3: Non-existent section (should not error)
            {
                let mut journal = create_journal().await;
                VJournal::<deterministic::Context, u64>::truncate_upper_section(
                    &mut journal,
                    99, // upper_bound that would be in a non-existent section
                    items_per_section,
                )
                .await
                .unwrap(); // Should not error
                journal.destroy().await.unwrap();
            }

            // Test 4: Upper bound beyond section (no truncation)
            {
                let mut journal = create_journal().await;
                let upper_bound = 15; // Beyond section 2
                let original_section_2_size = journal.size(2).await.unwrap();
                VJournal::<deterministic::Context, u64>::truncate_upper_section(
                    &mut journal,
                    upper_bound,
                    items_per_section,
                )
                .await
                .unwrap();

                // Section 2 should remain unchanged
                let section_2_size = journal.size(2).await.unwrap();
                assert_eq!(section_2_size, original_section_2_size);
                journal.destroy().await.unwrap();
            }
        });
    }

    /// Test intra-section truncation.
    #[test_traced]
    fn test_truncate_section_mid_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = VConfig {
                partition: "test_truncation_integration".into(),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
            };
            let items_per_section = 3;

            // Create journal with data across multiple sections
            let mut journal =
                VJournal::<deterministic::Context, u64>::init(context.clone(), cfg.clone())
                    .await
                    .expect("Failed to create journal");

            // Section 0: items 0, 1, 2
            // Section 1: items 3, 4, 5
            // Section 2: items 6, 7, 8
            for section in 0..3 {
                for i in 0..items_per_section {
                    let op_value = section * items_per_section + i;
                    journal.append(section, op_value).await.unwrap();
                }
            }
            journal.close().await.unwrap();

            // Test sync with upper_bound in middle of section 1 (upper_bound = 4)
            // Should keep: items 2, 3, 4 (sections 0 partially removed, 1 truncated, 2 removed)
            let lower_bound = 2;
            let upper_bound = 4;
            let mut journal = VJournal::<deterministic::Context, u64>::init_sync(
                context.clone(),
                cfg.clone(),
                lower_bound,
                upper_bound,
                NZU64!(items_per_section),
            )
            .await
            .expect("Failed to initialize synced journal");

            // Verify section 0 is partially present (only item 2)
            assert!(journal.blobs.contains_key(&0));
            assert_eq!(journal.get(0, 2).await.unwrap(), Some(2));

            // Verify section 1 is truncated (items 3, 4 only)
            assert!(journal.blobs.contains_key(&1));
            assert_eq!(journal.get(1, 0).await.unwrap(), Some(3));
            assert_eq!(journal.get(1, 1).await.unwrap(), Some(4));

            // item 5 should be inaccessible (truncated)
            let result = journal.get(1, 2).await;
            assert!(result.is_err());

            // Verify section 2 is completely removed
            assert!(!journal.blobs.contains_key(&2));

            // Test that new appends work correctly after truncation
            let (offset, _) = journal.append(1, 999).await.unwrap();
            assert_eq!(journal.get(1, offset).await.unwrap(), Some(999));

            journal.destroy().await.unwrap();
        });
    }
}
