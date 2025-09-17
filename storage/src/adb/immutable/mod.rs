//! An authenticated database (ADB) that only supports adding new keyed values (no updates or
//! deletions), where values can have varying sizes.

use crate::{
    adb::{any::fixed::sync::init_journal, Error},
    index::Index,
    journal::{fixed, variable},
    mmr::{
        iterator::{leaf_num_to_pos, leaf_pos_to_num},
        journaled::{Config as MmrConfig, Mmr},
        Proof, StandardHasher as Standard,
    },
    store::operation::Variable,
    translator::Translator,
};
use commonware_codec::{Codec, Encode as _, Read};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage, ThreadPool};
use commonware_utils::{Array, NZUsize};
use futures::{future::TryFutureExt, pin_mut, try_join, StreamExt};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::{debug, warn};

pub mod sync;

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot. The exact value does not impact performance significantly as long as it is large
/// enough, so we don't make it configurable.
const SNAPSHOT_READ_BUFFER_SIZE: usize = 1 << 16;

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

/// An authenticatable key-value database based on an MMR that does not allow updates or deletions
/// of previously set keys.
pub struct Immutable<E: RStorage + Clock + Metrics, K: Array, V: Codec, H: CHasher, T: Translator> {
    /// An MMR over digests of the operations applied to the db.
    ///
    /// # Invariant
    ///
    /// The number of leaves in this MMR always equals the number of operations in the unpruned
    /// `log` and `locations`.
    mmr: Mmr<E, H>,

    /// A log of all operations applied to the db in order of occurrence. The _location_ of an
    /// operation is its order of occurrence with respect to this log, and corresponds to its leaf
    /// number in the MMR.
    log: variable::Journal<E, Variable<K, V>>,

    /// The number of operations that have been appended to the log (which must equal the number of
    /// leaves in the MMR).
    log_size: u64,

    /// The number of items to put in each section of the journal.
    log_items_per_section: u64,

    /// A fixed-length journal that maps an operation's location to its offset within its respective
    /// section of the log. (The section number is derived from location.)
    locations: fixed::Journal<E, u32>,

    /// The location of the oldest retained operation, or 0 if no operations have been added.
    oldest_retained_loc: u64,

    /// A map from each active key to the location of the operation that set its value.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [Variable::Set].
    snapshot: Index<T, u64>,

    /// Cryptographic hasher to re-use within mutable operations requiring digest computation.
    hasher: Standard<H>,

    /// The location of the last commit operation, or None if no commit has been made.
    last_commit: Option<u64>,
}

impl<E: RStorage + Clock + Metrics, K: Array, V: Codec, H: CHasher, T: Translator>
    Immutable<E, K, V, H, T>
{
    /// Returns an [Immutable] adb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: Config<T, <Variable<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mut hasher = Standard::<H>::new();

        let mut mmr = Mmr::init(
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

        let mut log = variable::Journal::init(
            context.with_label("log"),
            variable::Config {
                partition: cfg.log_journal_partition,
                compression: cfg.log_compression,
                codec_config: cfg.log_codec_config,
                buffer_pool: cfg.buffer_pool.clone(),
                write_buffer: cfg.log_write_buffer,
            },
        )
        .await?;

        let mut locations = fixed::Journal::init(
            context.with_label("locations"),
            fixed::Config {
                partition: cfg.locations_journal_partition,
                items_per_blob: cfg.locations_items_per_blob,
                write_buffer: cfg.log_write_buffer,
                buffer_pool: cfg.buffer_pool,
            },
        )
        .await?;

        let mut snapshot: Index<T, u64> =
            Index::init(context.with_label("snapshot"), cfg.translator.clone());
        let (log_size, oldest_retained_loc) = Self::build_snapshot_from_log(
            &mut hasher,
            cfg.log_items_per_section,
            &mut mmr,
            &mut log,
            &mut locations,
            &mut snapshot,
        )
        .await?;

        let last_commit = log_size.checked_sub(1);

        Ok(Immutable {
            mmr,
            log,
            log_size,
            oldest_retained_loc,
            locations,
            log_items_per_section: cfg.log_items_per_section.get(),
            snapshot,
            hasher,
            last_commit,
        })
    }

    /// Returns an [Immutable] built from the config and sync data in `cfg`.
    #[allow(clippy::type_complexity)]
    pub async fn init_synced(
        context: E,
        mut cfg: sync::Config<E, K, V, T, H::Digest, <Variable<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        // Initialize MMR for sync
        let mut mmr = Mmr::init_sync(
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
                lower_bound: leaf_num_to_pos(cfg.lower_bound),
                upper_bound: leaf_num_to_pos(cfg.upper_bound + 1) - 1,
                pinned_nodes: cfg.pinned_nodes,
            },
        )
        .await?;

        // Initialize locations journal for sync
        let mut locations = init_journal(
            context.with_label("locations"),
            fixed::Config {
                partition: cfg.db_config.locations_journal_partition,
                items_per_blob: cfg.db_config.locations_items_per_blob,
                write_buffer: cfg.db_config.log_write_buffer,
                buffer_pool: cfg.db_config.buffer_pool.clone(),
            },
            cfg.lower_bound,
            cfg.upper_bound,
        )
        .await?;

        // Build snapshot from the log
        let mut snapshot = Index::init(
            context.with_label("snapshot"),
            cfg.db_config.translator.clone(),
        );
        let (log_size, oldest_retained_loc) = Self::build_snapshot_from_log(
            &mut Standard::<H>::new(),
            cfg.db_config.log_items_per_section,
            &mut mmr,
            &mut cfg.log,
            &mut locations,
            &mut snapshot,
        )
        .await?;

        let last_commit = log_size.checked_sub(1);

        let mut db = Immutable {
            mmr,
            log: cfg.log,
            log_size,
            oldest_retained_loc,
            locations,
            log_items_per_section: cfg.db_config.log_items_per_section.get(),
            snapshot,
            hasher: Standard::<H>::new(),
            last_commit,
        };

        db.sync().await?;
        Ok(db)
    }

    /// Builds the database's snapshot by replaying the log from inception, while also:
    ///   - trimming any uncommitted operations from the log,
    ///   - adding log operations to the MMR & location map if they are missing,
    ///   - removing any elements from the MMR & location map that don't remain in the log after
    ///     trimming.
    ///
    /// Returns the number of operations in the log and the oldest retained location.
    ///
    /// # Post-condition
    ///
    /// The number of operations in the log, locations, and the number of leaves in the MMR are
    /// equal.
    pub(super) async fn build_snapshot_from_log(
        hasher: &mut Standard<H>,
        log_items_per_section: NonZeroU64,
        mmr: &mut Mmr<E, H>,
        log: &mut variable::Journal<E, Variable<K, V>>,
        locations: &mut fixed::Journal<E, u32>,
        snapshot: &mut Index<T, u64>,
    ) -> Result<(u64, u64), Error> {
        // Align the mmr with the location map.
        let mut mmr_leaves = super::align_mmr_and_locations(mmr, locations).await?;

        // The number of operations in the log.
        let mut log_size = 0;
        // The location and blob-offset of the first operation to follow the last known commit point.
        let mut after_last_commit = None;
        // A list of uncommitted operations that must be rolled back, in order of their locations.
        let mut uncommitted_ops = Vec::new();
        let mut oldest_retained_loc = None;

        // Replay the log from inception to build the snapshot, keeping track of any uncommitted
        // operations that must be rolled back, and any log operations that need to be re-added to
        // the MMR & locations.
        {
            let stream = log
                .replay(0, 0, NZUsize!(SNAPSHOT_READ_BUFFER_SIZE))
                .await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Err(e) => {
                        return Err(Error::Journal(e));
                    }
                    Ok((section, offset, _, op)) => {
                        if oldest_retained_loc.is_none() {
                            log_size = section * log_items_per_section.get();
                            oldest_retained_loc = Some(log_size);
                        }

                        let loc = log_size; // location of the current operation.
                        if after_last_commit.is_none() {
                            after_last_commit = Some((loc, offset));
                        }

                        log_size += 1;

                        // Consistency check: confirm the provided section matches what we expect from this operation's
                        // index.
                        let expected = loc / log_items_per_section.get();
                        assert_eq!(section, expected,
                                "section {section} did not match expected session {expected} from location {loc}");

                        if log_size > mmr_leaves {
                            debug!(
                                section,
                                offset, "operation was missing from MMR/location map"
                            );
                            mmr.add(hasher, &op.encode()).await?;
                            locations.append(offset).await?;
                            mmr_leaves += 1;
                        }
                        match op {
                            Variable::Set(key, _) => {
                                uncommitted_ops.push((key, loc));
                            }
                            Variable::Commit(_) => {
                                for (key, loc) in uncommitted_ops.iter() {
                                    snapshot.insert(key, *loc);
                                }
                                uncommitted_ops.clear();
                                after_last_commit = None;
                            }
                            _ => {
                                unreachable!(
                                    "unsupported operation at offset {offset} in section {section}"
                                );
                            }
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
            let prune_to_section = end_loc / log_items_per_section.get();
            log.rewind_to_offset(prune_to_section, end_offset).await?;
            log.sync(prune_to_section).await?;
            log_size = end_loc;
        }

        // Pop any MMR elements that are ahead of the last log commit point.
        if mmr_leaves > log_size {
            locations.rewind(log_size).await?;
            locations.sync().await?;

            let op_count = mmr_leaves - log_size;
            warn!(op_count, "popping uncommitted MMR operations");
            mmr.pop(op_count as usize).await?;
        }

        // Confirm post-conditions hold.
        assert_eq!(log_size, leaf_pos_to_num(mmr.size()).unwrap());
        assert_eq!(log_size, locations.size().await?);

        Ok((log_size, oldest_retained_loc.unwrap_or(0)))
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

    /// Prunes the db of up to all operations that have location less than `loc`. The actual number
    /// pruned may be fewer than requested due to blob boundaries.
    ///
    /// # Panics
    ///
    /// Panics if `loc` is beyond the last commit point.
    pub async fn prune(&mut self, loc: u64) -> Result<(), Error> {
        assert!(loc <= self.last_commit.unwrap_or(0));

        // Prune the log up to the section containing the requested pruning location. We always
        // prune the log first, and then prune the MMR+locations structures based on the log's
        // actual pruning boundary. This procedure ensures all log operations always have
        // corresponding MMR & location entries, even in the event of failures, with no need for
        // special recovery.
        let section = loc / self.log_items_per_section;
        self.log.prune(section).await?;
        self.oldest_retained_loc = section * self.log_items_per_section;

        // Prune the MMR & locations map up to the oldest retained item in the log after pruning.
        self.locations.prune(self.oldest_retained_loc).await?;
        self.mmr
            .prune_to_pos(&mut self.hasher, leaf_num_to_pos(self.oldest_retained_loc))
            .await?;
        Ok(())
    }

    /// Get the value of `key` in the db, or None if it has no value or its corresponding operation
    /// has been pruned.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        let iter = self.snapshot.get(key);
        for &loc in iter {
            if loc < self.oldest_retained_loc {
                continue;
            }
            if let Some(v) = self.get_from_loc(key, loc).await? {
                return Ok(Some(v));
            }
        }

        Ok(None)
    }

    /// Get the value of the operation with location `loc` in the db. Returns [Error::OperationPruned]
    /// if loc precedes the oldest retained location. The location is otherwise assumed valid.
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

    /// Get the value of the operation with location `loc` in the db if it matches `key`. Returns
    /// [Error::OperationPruned] if loc precedes the oldest retained location. The location is
    /// otherwise assumed valid.
    pub async fn get_from_loc(&self, key: &K, loc: u64) -> Result<Option<V>, Error> {
        if loc < self.oldest_retained_loc {
            return Err(Error::OperationPruned(loc));
        }

        match self.locations.read(loc).await {
            Ok(offset) => {
                return self.get_from_offset(key, loc, offset).await;
            }
            Err(e) => Err(Error::Journal(e)),
        }
    }

    /// Get the value of the operation with location `loc` and offset `offset` in the log if it
    /// matches `key`, or return [Error::OperationPruned] if the location precedes the oldest
    /// retained.
    async fn get_from_offset(&self, key: &K, loc: u64, offset: u32) -> Result<Option<V>, Error> {
        if loc < self.oldest_retained_loc {
            return Err(Error::OperationPruned(loc));
        }

        let section = loc / self.log_items_per_section;
        let Variable::Set(k, v) = self.log.get(section, offset).await? else {
            panic!("didn't find Set operation at location {loc} and offset {offset}");
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

    /// Sets `key` to have value `value`, assuming `key` hasn't already been assigned. The operation
    /// is reflected in the snapshot, but will be subject to rollback until the next successful
    /// `commit`. Attempting to set an already-set key results in undefined behavior.
    ///
    /// Any keys that have been pruned and map to the same translated key will be dropped
    /// during this call.
    pub async fn set(&mut self, key: K, value: V) -> Result<(), Error> {
        let loc = self.log_size;
        self.snapshot
            .insert_and_prune(&key, loc, |v| *v < self.oldest_retained_loc);

        let op = Variable::Set(key, value);
        self.apply_op(op).await
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
    pub(super) async fn apply_op(&mut self, op: Variable<K, V>) -> Result<(), Error> {
        let section = self.current_section();
        let encoded_op = op.encode();

        // Create a future that updates the MMR.
        let mmr_fut = async {
            self.mmr.add_batched(&mut self.hasher, &encoded_op).await?;
            Ok::<(), Error>(())
        };

        // Create a future that appends the operation to the log and writes the resulting offset
        // locations.
        let log_fut = async {
            let (offset, _) = self.log.append(section, op).await?;
            self.locations.append(offset).await?;
            Ok::<(), Error>(())
        };

        // Run the 2 futures in parallel.
        try_join!(mmr_fut, log_fut)?;
        self.log_size += 1;

        // Maintain invariant that all filled sections are synced and immutable.
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
        start_index: u64,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Variable<K, V>>), Error> {
        self.historical_proof(self.op_count(), start_index, max_ops)
            .await
    }

    /// Analogous to proof but with respect to the state of the MMR when it had `size` elements.
    pub async fn historical_proof(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Variable<K, V>>), Error> {
        if start_loc < self.oldest_retained_loc {
            return Err(Error::OperationPruned(start_loc));
        }

        let start_pos = leaf_num_to_pos(start_loc);
        let end_loc = std::cmp::min(size - 1, start_loc + max_ops.get() - 1);
        let end_pos = leaf_num_to_pos(end_loc);
        let mmr_size = leaf_num_to_pos(size);

        let proof = self
            .mmr
            .historical_range_proof(mmr_size, start_pos, end_pos)
            .await?;
        let mut ops = Vec::with_capacity((end_loc - start_loc + 1) as usize);
        for loc in start_loc..=end_loc {
            let section = loc / self.log_items_per_section;
            let offset = self.locations.read(loc).await?;
            let op = self.log.get(section, offset).await?;
            ops.push(op);
        }

        Ok((proof, ops))
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Caller can associate an arbitrary `metadata` value with the commit.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    pub async fn commit(&mut self, metadata: Option<V>) -> Result<(), Error> {
        self.last_commit = Some(self.log_size);
        let op = Variable::<K, V>::Commit(metadata);
        let encoded_op = op.encode();
        let section = self.current_section();

        // Create a future that updates the MMR.
        let mmr_fut = async {
            self.mmr.add_batched(&mut self.hasher, &encoded_op).await?;
            self.mmr.process_updates(&mut self.hasher);
            Ok::<(), Error>(())
        };

        // Create a future that appends the operation to the log, syncs it, and writes the resulting
        // offset locations.
        let log_fut = async {
            let (offset, _) = self.log.append(section, op).await?;
            // Sync the log and update locations in parallel.
            try_join!(
                self.log.sync(section).map_err(Error::Journal),
                self.locations.append(offset).map_err(Error::Journal),
            )?;
            Ok::<(), Error>(())
        };

        // Run the 2 futures in parallel.
        try_join!(mmr_fut, log_fut)?;
        self.log_size += 1;

        Ok(())
    }

    /// Get the location and metadata associated with the last commit, or None if no commit has been
    /// made.
    pub async fn get_metadata(&self) -> Result<Option<(u64, Option<V>)>, Error> {
        let Some(last_commit) = self.last_commit else {
            return Ok(None);
        };
        let section = last_commit / self.log_items_per_section;
        let offset = self.locations.read(last_commit).await?;
        let Variable::Commit(metadata) = self.log.get(section, offset).await? else {
            unreachable!("no commit operation at location of last commit {last_commit}");
        };

        Ok(Some((last_commit, metadata)))
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub(super) async fn sync(&mut self) -> Result<(), Error> {
        let section = self.current_section();
        try_join!(
            self.mmr.sync(&mut self.hasher).map_err(Error::Mmr),
            self.log.sync(section).map_err(Error::Journal),
            self.locations.sync().map_err(Error::Journal),
        )?;

        Ok(())
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(mut self) -> Result<(), Error> {
        try_join!(
            self.log.close().map_err(Error::Journal),
            self.mmr.close(&mut self.hasher).map_err(Error::Mmr),
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

    /// Simulate a failed commit that successfully writes the log to the commit point, but without
    /// fully committing the MMR's cached elements to trigger MMR node recovery on reopening.
    #[cfg(test)]
    pub async fn simulate_failed_commit_mmr(mut self, write_limit: usize) -> Result<(), Error>
    where
        V: Default,
    {
        self.apply_op(Variable::Commit(None)).await?;
        self.log.close().await?;
        self.locations.close().await?;
        self.mmr
            .simulate_partial_sync(&mut self.hasher, write_limit)
            .await?;

        Ok(())
    }

    /// Simulate a failed commit that successfully writes the MMR to the commit point, but without
    /// fully committing the log, requiring rollback of the MMR and log upon reopening.
    #[cfg(test)]
    pub async fn simulate_failed_commit_log(mut self) -> Result<(), Error>
    where
        V: Default,
    {
        self.apply_op(Variable::Commit(None)).await?;
        let mut section = self.current_section();

        self.mmr.close(&mut self.hasher).await?;
        // Rewind the operation log over the commit op to force rollback to the previous commit.
        let mut size = self.log.size(section).await?;
        if size == 0 {
            section -= 1;
            size = self.log.size(section).await?;
        }
        self.log.rewind(section, size - 1).await?;
        self.log.close().await?;

        Ok(())
    }

    /// Simulate a failed commit that successfully writes the log to the commit point, but without
    /// fully committing the locations.
    #[cfg(test)]
    pub async fn simulate_failed_commit_locations(
        mut self,
        operations_to_trim: u64,
    ) -> Result<(), Error>
    where
        V: Default,
    {
        self.apply_op(Variable::Commit(None)).await?;
        let op_count = self.op_count();
        assert!(op_count >= operations_to_trim);

        self.log.close().await?;
        self.mmr.close(&mut self.hasher).await?;
        self.locations.rewind(op_count - operations_to_trim).await?;
        self.locations.close().await?;

        Ok(())
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{adb::verify_proof, mmr::mem::Mmr as MemMmr, translator::TwoCap};
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{self},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU64};

    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;
    const ITEMS_PER_SECTION: u64 = 5;

    pub(crate) fn db_config(suffix: &str) -> Config<TwoCap, (commonware_codec::RangeCfg, ())> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_section: NZU64!(ITEMS_PER_SECTION),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_write_buffer: NZUsize!(1024),
            locations_journal_partition: format!("locations_journal_{suffix}"),
            locations_items_per_blob: NZU64!(7),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// A type alias for the concrete [Immutable] type used in these unit tests.
    type ImmutableTest = Immutable<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    /// Return an [Immutable] database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> ImmutableTest {
        ImmutableTest::init(context, db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = Standard::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.oldest_retained_loc(), None);
            assert_eq!(db.root(&mut hasher), MemMmr::default().root(&mut hasher));
            assert!(db.get_metadata().await.unwrap().is_none());

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let k1 = Sha256::fill(1u8);
            let v1 = vec![4, 5, 6, 7];
            let root = db.root(&mut hasher);
            db.set(k1, v1).await.unwrap();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.op_count(), 0);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 1); // commit op added
            let root = db.root(&mut hasher);
            db.close().await.unwrap();

            let db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_immutable_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 keys.
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let k1 = Sha256::fill(1u8);
            let k2 = Sha256::fill(2u8);
            let v1 = vec![1, 2, 3];
            let v2 = vec![4, 5, 6, 7, 8];

            assert!(db.get(&k1).await.unwrap().is_none());
            assert!(db.get(&k2).await.unwrap().is_none());

            // Set the first key.
            db.set(k1, v1.clone()).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get(&k2).await.unwrap().is_none());
            assert_eq!(db.op_count(), 1);
            // Commit the first key.
            let metadata = Some(vec![99, 100]);
            db.commit(metadata.clone()).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get(&k2).await.unwrap().is_none());
            assert_eq!(db.op_count(), 2);
            assert_eq!(
                db.get_metadata().await.unwrap(),
                Some((1, metadata.clone()))
            );
            // Set the second key.
            db.set(k2, v2.clone()).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);
            assert_eq!(db.op_count(), 3);

            // Make sure we can still get metadata.
            assert_eq!(db.get_metadata().await.unwrap(), Some((1, metadata)));

            // Commit the second key.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 4);
            assert_eq!(db.get_metadata().await.unwrap(), Some((3, None)));

            // Capture state.
            let root = db.root(&mut hasher);

            // Add an uncommitted op then close the db.
            let k3 = Sha256::fill(3u8);
            let v3 = vec![9, 10, 11];
            db.set(k3, v3).await.unwrap();
            assert_eq!(db.op_count(), 5);
            assert_ne!(db.root(&mut hasher), root);

            // Close & reopen, make sure state is restored to last commit point.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.get(&k3).await.unwrap().is_none());
            assert_eq!(db.op_count(), 4);
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.get_metadata().await.unwrap(), Some((3, None)));

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
            let mut db = open_db(context.clone()).await;

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS);

            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), ELEMENTS + 1);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), ELEMENTS + 1);
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                assert_eq!(db.get(&k).await.unwrap().unwrap(), v);
            }

            // Make sure all ranges of 5 operations are provable, including truncated ranges at the
            // end.
            let max_ops = NZU64!(5);
            for i in 0..db.op_count() {
                let (proof, log) = db.proof(i, max_ops).await.unwrap();
                assert!(verify_proof(&mut hasher, &proof, i, &log, &root));
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
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS);
            db.sync().await.unwrap();
            let halfway_root = db.root(&mut hasher);

            // Insert another 1000 keys then simulate a failed close and test recovery.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            // We partially write only 101 of the cached MMR nodes to simulate a failure.
            db.simulate_failed_commit_mmr(101).await.unwrap();

            // Recovery should replay the log to regenerate the mmr.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2001);
            let root = db.root(&mut hasher);
            assert_ne!(root, halfway_root);

            // Close & reopen could preserve the final commit.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2001);
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_recovery_from_failed_locations_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS);
            db.sync().await.unwrap();
            let halfway_root = db.root(&mut hasher);

            // Insert another 1000 keys then simulate a failed close and test recovery.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            // Simulate failure to write the full locations map.
            db.simulate_failed_commit_locations(101).await.unwrap();

            // Recovery should replay the log to regenerate the locations map.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2001);
            let root = db.root(&mut hasher);
            assert_ne!(root, halfway_root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_recovery_from_failed_log_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Insert a single key and then commit to create a first commit point.
            let k1 = Sha256::fill(1u8);
            let v1 = vec![1, 2, 3];
            db.set(k1, v1).await.unwrap();
            db.commit(None).await.unwrap();
            let first_commit_root = db.root(&mut hasher);

            // Insert 1000 keys then sync.
            const ELEMENTS: u64 = 1000;

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS + 2);
            db.sync().await.unwrap();

            // Insert another 1000 keys then simulate a failed close and test recovery.
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            // Simulate failure to write the full locations map.
            db.simulate_failed_commit_log().await.unwrap();

            // Recovery should back up to previous commit point.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2);
            let root = db.root(&mut hasher);
            assert_eq!(root, first_commit_root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_immutable_db_pruning() {
        let executor = deterministic::Runner::default();
        // Build a db with `ELEMENTS` key/value pairs and prove ranges over them.
        const ELEMENTS: u64 = 2_000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS);

            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), ELEMENTS + 1);

            // Prune the db to the first half of the operations.
            db.prune(ELEMENTS / 2).await.unwrap();
            assert_eq!(db.op_count(), ELEMENTS + 1);

            // items_per_section is 5, so half should be exactly at a blob boundary, in which case
            // the actual pruning location should match the requested.
            let oldest_retained_loc = db.oldest_retained_loc().unwrap();
            assert_eq!(oldest_retained_loc, ELEMENTS / 2);

            // Try to fetch a pruned key.
            let pruned_loc = oldest_retained_loc - 1;
            let pruned_key = Sha256::hash(&pruned_loc.to_be_bytes());
            assert!(db.get(&pruned_key).await.unwrap().is_none());

            // Try to fetch unpruned key.
            let unpruned_key = Sha256::hash(&oldest_retained_loc.to_be_bytes());
            assert!(db.get(&unpruned_key).await.unwrap().is_some());

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), ELEMENTS + 1);
            let oldest_retained_loc = db.oldest_retained_loc().unwrap();
            assert_eq!(oldest_retained_loc, ELEMENTS / 2);

            // Prune to a non-blob boundary.
            db.prune(ELEMENTS / 2 + (ITEMS_PER_SECTION * 2 - 1))
                .await
                .unwrap();
            // Actual boundary should be a multiple of 5.
            let oldest_retained_loc = db.oldest_retained_loc().unwrap();
            assert_eq!(oldest_retained_loc, ELEMENTS / 2 + ITEMS_PER_SECTION);

            // Confirm boundary persists across restart.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            let oldest_retained_loc = db.oldest_retained_loc().unwrap();
            assert_eq!(oldest_retained_loc, ELEMENTS / 2 + ITEMS_PER_SECTION);

            // Try to fetch a pruned key.
            let pruned_loc = oldest_retained_loc - 3;
            let pruned_key = Sha256::hash(&pruned_loc.to_be_bytes());
            assert!(db.get(&pruned_key).await.unwrap().is_none());

            // Try to fetch unpruned key.
            let unpruned_key = Sha256::hash(&oldest_retained_loc.to_be_bytes());
            assert!(db.get(&unpruned_key).await.unwrap().is_some());

            // Confirm behavior of trying to create a proof of pruned items is as expected.
            let pruned_pos = ELEMENTS / 2;
            let proof_result = db.proof(pruned_pos, NZU64!(pruned_pos + 100)).await;
            assert!(matches!(proof_result, Err(Error::OperationPruned(pos)) if pos == pruned_pos));

            db.destroy().await.unwrap();
        });
    }
}
