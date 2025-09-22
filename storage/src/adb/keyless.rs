//! The [Keyless] adb allows for append-only storage of arbitrary variable-length data that can
//! later be retrieved by its location.
//!
//! The implementation consists of an `mmr` over the operations applied to the database, an
//! operations `log` storing these operations, and a `locations` journal storing the offset of its
//! respective operation in its section of the operations log.
//!
//! The state of the operations log up until the last commit point is the "source of truth". In the
//! event of unclean shutdown, the mmr and locations structures will be brought back into alignment
//! with the log on startup.

use crate::{
    adb::{align_mmr_and_locations, Error},
    journal::{
        fixed::{Config as FConfig, Journal as FJournal},
        variable::{Config as VConfig, Journal as VJournal},
    },
    mmr::{
        iterator::leaf_loc_to_pos,
        journaled::{Config as MmrConfig, Mmr},
        Proof, StandardHasher as Standard,
    },
    store::operation::Keyless as Operation,
};
use commonware_codec::{Codec, Encode as _};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage, ThreadPool};
use commonware_utils::NZUsize;
use futures::{future::TryFutureExt, pin_mut, try_join, StreamExt as _};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::{debug, warn};

/// The size of the read buffer to use for replaying the operations log during recovery.
const REPLAY_BUFFER_SIZE: NonZeroUsize = NZUsize!(1 << 14);

/// Configuration for a [Keyless] authenticated db.
#[derive(Clone)]
pub struct Config<C> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the operations log.
    pub log_journal_partition: String,

    /// The size of the write buffer to use with the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding the operations log.
    pub log_codec_config: C,

    /// The max number of operations to put in each section of the operations log.
    pub log_items_per_section: NonZeroU64,

    /// The name of the [Storage] partition used for the location map.
    pub locations_journal_partition: String,

    /// The number of items to put in each blob in the locations journal.
    pub locations_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use with the locations journal.
    pub locations_write_buffer: NonZeroUsize,

    /// An optional thread pool to use for parallelizing batch MMR operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

/// A keyless ADB for variable length data.
pub struct Keyless<E: Storage + Clock + Metrics, V: Codec, H: CHasher> {
    /// An MMR over digests of the operations applied to the db.
    ///
    /// # Invariant
    ///
    /// The number of leaves in this MMR always equals the number of operations in the unpruned
    /// `locations` journal.
    mmr: Mmr<E, H>,

    /// A journal of all operations ever applied to the db.
    log: VJournal<E, Operation<V>>,

    /// The total number of operations appended (including those that have been pruned).  The next
    /// appended operation will have this value as its location.
    size: u64,

    /// The number of operations to put in each section of the operations log.
    log_items_per_section: u64,

    /// A fixed-length journal that maps an appended value's location to its offset within its
    /// respective section of the log journal. (The section number is derived from location.)
    ///
    /// The locations structure provides the "source of truth" for the db's pruning boundaries and
    /// overall size, should there be any discrepancies.
    locations: FJournal<E, u32>,

    /// Cryptographic hasher to re-use within mutable operations requiring digest computation.
    hasher: Standard<H>,

    /// The location of the last commit, if any.
    last_commit_loc: Option<u64>,
}

impl<E: Storage + Clock + Metrics, V: Codec, H: CHasher> Keyless<E, V, H> {
    /// Find the last valid log operation that has a corresponding location entry.
    ///
    /// Accepts the `aligned_size` of the MMR and locations journal and the `log_items_per_section` of a [Keyless] instance.
    /// Returns the index of the last operation and its offset in the section it belongs to.
    async fn find_last_operation(
        locations: &FJournal<E, u32>,
        log: &VJournal<E, Operation<V>>,
        aligned_size: u64,
        log_items_per_section: u64,
    ) -> Result<(u64, Option<(u64, u32)>), Error> {
        let mut valid_size = aligned_size;
        let mut section_offset = None;

        while valid_size > 0 {
            let loc = valid_size - 1;
            let offset = locations.read(loc).await?;
            let section = loc / log_items_per_section;
            match log.get(section, offset).await {
                Ok(_) => {
                    section_offset = Some((section, offset));
                    break;
                }
                Err(e) => {
                    warn!(loc, err=?e, "log operation missing");
                }
            };
            warn!(loc, offset, section, "walking back locations");
            valid_size -= 1;
        }

        Ok((valid_size, section_offset))
    }

    /// Replay log operations from a given position and sync MMR and locations.
    ///
    /// Returns None if the log is empty (for initial replay), otherwise returns
    /// the offset and the last operation processed.
    async fn replay_operations(
        mmr: &mut Mmr<E, H>,
        hasher: &mut Standard<H>,
        locations: &mut FJournal<E, u32>,
        log: &VJournal<E, Operation<V>>,
        section_offset: Option<(u64, u32)>,
    ) -> Result<Option<(u32, Operation<V>)>, Error> {
        // Initialize stream from section_offset
        let (section, offset, skip_first) = match section_offset {
            Some((s, o)) => (s, o, true),
            None => (0, 0, false),
        };
        let stream = log.replay(section, offset, REPLAY_BUFFER_SIZE).await?;
        pin_mut!(stream);

        // Get first operation and handle empty log case
        let first_op = stream.next().await;
        let (mut last_offset, mut last_op) = if skip_first {
            // We expect the first operation to exist (already processed)
            let first_op = first_op.expect("operation known to exist")?;
            (offset, first_op.3)
        } else {
            // Check if log is empty
            let Some(first_op) = first_op else {
                debug!("no starting log operation found, returning empty db");
                return Ok(None);
            };
            let first_op = first_op?;
            let encoded_op = first_op.3.encode();

            // Add first operation to mmr and locations
            mmr.add_batched(hasher, &encoded_op).await?;
            locations.append(first_op.1).await?;
            (first_op.1, first_op.3)
        };

        // Process remaining operations
        while let Some(result) = stream.next().await {
            let (section, offset, _, next_op) = result?;
            let encoded_op = next_op.encode();
            last_offset = offset;
            last_op = next_op;
            warn!(
                location = mmr.leaves(),
                section, offset, "adding missing operation to MMR/location map"
            );
            mmr.add_batched(hasher, &encoded_op).await?;
            locations.append(offset).await?;
        }

        // Sync if needed
        if mmr.is_dirty() {
            mmr.sync(hasher).await?;
            locations.sync().await?;
        }

        Ok(Some((last_offset, last_op)))
    }

    /// Find the last commit point and rewind to it if necessary.
    ///
    /// Accepts the `op_count` of the MMR, the `last_offset` of the last log operation, and the `log_items_per_section` of a [Keyless] instance.
    /// Returns the index of the last operation after rewinding.
    async fn rewind_to_last_commit(
        mmr: &mut Mmr<E, H>,
        locations: &mut FJournal<E, u32>,
        log: &mut VJournal<E, Operation<V>>,
        last_log_op: Operation<V>,
        op_count: u64,
        last_offset: u32,
        log_items_per_section: u64,
    ) -> Result<u64, Error> {
        let mut first_uncommitted: Option<(u64, u32)> = None;
        let mut op_index = op_count - 1;
        let mut op = last_log_op;
        let mut offset = last_offset;
        let oldest_retained_loc = locations
            .oldest_retained_pos()
            .await?
            .expect("location should be nonempty");

        // Walk backwards through the log until we find the last commit point.
        loop {
            match op {
                Operation::Commit(_) => {
                    break;
                }
                Operation::Append(_) => {
                    // Track the earliest uncommitted append (index, offset) encountered while
                    // walking backwards. If none is found before we hit a Commit, there is
                    // nothing to rewind.
                    first_uncommitted = Some((op_index, offset));
                }
            }
            if op_index == oldest_retained_loc {
                assert_eq!(op_index, 0, "no commit operation found");
                break;
            }
            op_index -= 1;
            offset = locations.read(op_index).await?;
            let section = op_index / log_items_per_section;
            op = log.get(section, offset).await?;
        }

        // If there are no uncommitted operations, exit early.
        let Some((rewind_size, rewind_offset)) = first_uncommitted else {
            return Ok(op_index + 1);
        };

        // Rewind the log and MMR to the last commit point.
        let ops_to_rewind = (op_count - rewind_size) as usize;
        warn!(ops_to_rewind, rewind_size, "rewinding log to last commit");
        locations.rewind(rewind_size).await?;
        locations.sync().await?;
        mmr.pop(ops_to_rewind).await?; // sync is handled by pop
        let section = rewind_size / log_items_per_section;
        log.rewind_to_offset(section, rewind_offset).await?;
        log.sync(section).await?;

        Ok(rewind_size)
    }

    /// Returns a [Keyless] adb initialized from `cfg`. Any uncommitted operations will be discarded
    /// and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
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

        let mut locations = FJournal::init(
            context.with_label("locations"),
            FConfig {
                partition: cfg.locations_journal_partition,
                items_per_blob: cfg.locations_items_per_blob,
                write_buffer: cfg.locations_write_buffer,
                buffer_pool: cfg.buffer_pool.clone(),
            },
        )
        .await?;

        // Align the sizes of locations and mmr.
        let aligned_size = align_mmr_and_locations(&mut mmr, &mut locations).await?;

        let mut log = VJournal::<E, Operation<V>>::init(
            context.with_label("log"),
            VConfig {
                partition: cfg.log_journal_partition,
                compression: cfg.log_compression,
                codec_config: cfg.log_codec_config,
                buffer_pool: cfg.buffer_pool,
                write_buffer: cfg.log_write_buffer,
            },
        )
        .await?;

        // Find the location of the most recent log operation that is at an index less than or equal to the `aligned_size`.
        let log_items_per_section = cfg.log_items_per_section.get();
        let (valid_size, section_offset) =
            Self::find_last_operation(&locations, &log, aligned_size, log_items_per_section)
                .await?;

        // Trim any locations/mmr elements that do not have corresponding operations in log.
        if aligned_size != valid_size {
            warn!(
                size = aligned_size,
                new_size = valid_size,
                "trimming locations & mmr elements ahead of log"
            );
            locations.rewind(valid_size).await?;
            locations.sync().await?;
            mmr.pop((aligned_size - valid_size) as usize).await?;
        }
        assert_eq!(mmr.leaves(), locations.size().await?);

        // Apply operations from the log at indices beyond the `aligned_size` to the MMR and locations journal.
        //
        // Because we don't sync the MMR and locations journal during commit, it is possible that they are (far) behind
        // the log.
        let replay_result =
            Self::replay_operations(&mut mmr, &mut hasher, &mut locations, &log, section_offset)
                .await?;
        let Some((last_offset, last_op)) = replay_result else {
            // Empty database
            return Ok(Self {
                mmr,
                log,
                size: 0,
                locations,
                log_items_per_section,
                hasher,
                last_commit_loc: None,
            });
        };

        // Find the last commit point and rewind to it (if necessary).
        let op_count = mmr.leaves();
        let size = Self::rewind_to_last_commit(
            &mut mmr,
            &mut locations,
            &mut log,
            last_op,
            op_count,
            last_offset,
            log_items_per_section,
        )
        .await?;
        assert_eq!(size, mmr.leaves());
        assert_eq!(size, locations.size().await?);

        Ok(Self {
            mmr,
            log,
            size,
            locations,
            log_items_per_section,
            hasher,
            last_commit_loc: size.checked_sub(1),
        })
    }

    /// Get the value at location `loc` in the database.
    pub async fn get(&self, loc: u64) -> Result<Option<V>, Error> {
        assert!(loc < self.size);
        let offset = self.locations.read(loc).await?;

        let section = loc / self.log_items_per_section;
        let op = self.log.get(section, offset).await?;

        Ok(op.into_value())
    }

    /// Get the number of operations (appends + commits) that have been applied to the db since
    /// inception.
    pub fn op_count(&self) -> u64 {
        self.size
    }

    /// Returns the location of the last commit, if any.
    pub fn last_commit_loc(&self) -> Option<u64> {
        self.last_commit_loc
    }

    /// Returns the section of the operations log where we are currently writing new operations.
    fn current_section(&self) -> u64 {
        self.size / self.log_items_per_section
    }

    /// Return the oldest location that remains retrievable.
    pub async fn oldest_retained_loc(&self) -> Result<Option<u64>, Error> {
        if let Some(oldest_section) = self.log.oldest_section() {
            Ok(Some(oldest_section * self.log_items_per_section))
        } else {
            Ok(None)
        }
    }

    /// Prunes the db of up to all operations that have location less than `loc`. The actual number
    /// pruned may be fewer than requested due to blob boundaries in the underlying journals.
    ///
    /// # Panics
    ///
    /// Panics if `loc` is beyond the last commit point.
    pub async fn prune(&mut self, loc: u64) -> Result<(), Error> {
        assert!(loc <= self.last_commit_loc.unwrap_or(0));

        // Sync the mmr before pruning the log, otherwise the MMR tip could end up behind the log's
        // pruning boundary on restart from an unclean shutdown, and there would be no way to replay
        // the operations between the MMR tip and the log pruning boundary.
        // TODO(https://github.com/commonwarexyz/monorepo/issues/1554): We currently sync locations
        // as well, but this could be avoided by extending recovery.
        try_join!(
            self.mmr.sync(&mut self.hasher).map_err(Error::Mmr),
            self.locations.sync().map_err(Error::Journal),
        )?;

        // Prune the log first since it's always the source of truth.
        let section = loc / self.log_items_per_section;
        if !self.log.prune(section).await? {
            return Ok(());
        }

        let prune_loc = section * self.log_items_per_section;
        debug!(size = self.size, loc = prune_loc, "pruned log");

        // Prune locations and the MMR to the corresponding positions.
        try_join!(
            self.mmr
                .prune_to_pos(&mut self.hasher, leaf_loc_to_pos(prune_loc))
                .map_err(Error::Mmr),
            self.locations.prune(prune_loc).map_err(Error::Journal),
        )?;

        Ok(())
    }

    /// Append a value to the db, returning its location which can be used to retrieve it.
    pub async fn append(&mut self, value: V) -> Result<u64, Error> {
        let loc = self.size;
        let section = self.current_section();
        let operation = Operation::Append(value);
        let encoded_operation = operation.encode();

        // Create a future that appends the operation to the log and updates locations with the
        // resulting offset.
        let log_loc_fut = async {
            let (offset, _) = self.log.append(section, operation).await?;
            self.locations.append(offset).await?;
            Ok::<(), Error>(())
        };

        // Create a future that updates the MMR.
        let mmr_fut = async {
            self.mmr
                .add_batched(&mut self.hasher, &encoded_operation)
                .await?;
            Ok::<(), Error>(())
        };

        // Run the 2 futures in parallel.
        try_join!(log_loc_fut, mmr_fut)?;
        self.size += 1;

        // Maintain invariant that all filled sections are synced and immutable.
        if section != self.current_section() {
            self.log.sync(section).await?;
        }

        Ok(loc)
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Caller can associate an arbitrary `metadata` value with the commit.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    pub async fn commit(&mut self, metadata: Option<V>) -> Result<u64, Error> {
        let loc = self.size;
        let section = self.current_section();
        self.last_commit_loc = Some(loc);

        let operation = Operation::Commit(metadata);
        let encoded_operation = operation.encode();

        // Create a future that updates and syncs the log, and updates locations with the resulting
        // offset.
        let log_loc_fut = async {
            let (offset, _) = self.log.append(section, operation).await?;
            // Sync the log and update locations in parallel.
            try_join!(
                self.log.sync(section).map_err(Error::Journal),
                self.locations.append(offset).map_err(Error::Journal),
            )?;

            Ok::<(), Error>(())
        };

        // Create a future that adds the commit operation to the MMR and processes all updates.
        let mmr_fut = async {
            self.mmr
                .add_batched(&mut self.hasher, &encoded_operation)
                .await?;
            self.mmr.process_updates(&mut self.hasher);

            Ok::<(), Error>(())
        };

        // Run the 2 futures in parallel.
        try_join!(log_loc_fut, mmr_fut)?;
        self.size += 1;

        debug!(size = self.size, "committed db");

        Ok(loc)
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let section = self.current_section();
        try_join!(
            self.locations.sync().map_err(Error::Journal),
            self.mmr.sync(&mut self.hasher).map_err(Error::Mmr),
            self.log.sync(section).map_err(Error::Journal),
        )?;

        Ok(())
    }

    /// Get the location and metadata associated with the last commit, or None if no commit has been
    /// made.
    pub async fn get_metadata(&self) -> Result<Option<(u64, Option<V>)>, Error> {
        let Some(loc) = self.last_commit_loc else {
            return Ok(None);
        };
        let offset = self.locations.read(loc).await?;
        let section = loc / self.log_items_per_section;
        let op = self.log.get(section, offset).await?;
        let Operation::Commit(metadata) = op else {
            return Ok(None);
        };

        Ok(Some((loc, metadata)))
    }

    /// Return the root of the db.
    ///
    /// # Warning
    ///
    /// Panics if there are uncommitted operations.
    pub fn root(&self, hasher: &mut Standard<H>) -> H::Digest {
        self.mmr.root(hasher)
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
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<V>>), Error> {
        self.historical_proof(self.size, start_loc, max_ops).await
    }

    /// Analogous to proof, but with respect to the state of the MMR when it had `op_count`
    /// operations.
    pub async fn historical_proof(
        &self,
        op_count: u64,
        start_loc: u64,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<V>>), Error> {
        let end_loc = std::cmp::min(op_count, start_loc + max_ops.get());
        let mmr_size = leaf_loc_to_pos(op_count);
        let proof = self
            .mmr
            .historical_range_proof(mmr_size, start_loc..end_loc)
            .await?;
        let mut ops = Vec::with_capacity((end_loc - start_loc) as usize);
        for loc in start_loc..end_loc {
            let offset = self.locations.read(loc).await?;
            let section = loc / self.log_items_per_section;
            let value = self.log.get(section, offset).await?;
            ops.push(value);
        }

        Ok((proof, ops))
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(mut self) -> Result<(), Error> {
        // Close the locations journal first to make sure it's synced first (see `sync` for why this
        // is important).
        self.locations.close().await?;

        try_join!(
            self.mmr.close(&mut self.hasher).map_err(Error::Mmr),
            self.log.close().map_err(Error::Journal),
        )?;

        Ok(())
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        try_join!(
            self.mmr.destroy().map_err(Error::Mmr),
            self.log.destroy().map_err(Error::Journal),
            self.locations.destroy().map_err(Error::Journal),
        )?;

        Ok(())
    }

    #[cfg(test)]
    /// Simulate failure by consuming the db but without syncing / closing the various structures.
    pub(super) async fn simulate_failure(
        mut self,
        sync_log: bool,
        sync_locations: bool,
        sync_mmr: bool,
    ) -> Result<(), Error> {
        if sync_log {
            let section = self.current_section();
            self.log.sync(section).await?;
        }
        if sync_locations {
            self.locations.sync().await?;
        }
        if sync_mmr {
            self.mmr.sync(&mut self.hasher).await?;
        }

        Ok(())
    }

    #[cfg(test)]
    /// Simulate pruning failure by consuming the db and abandoning pruning operation mid-flight.
    pub(super) async fn simulate_prune_failure(mut self, loc: u64) -> Result<(), Error> {
        assert!(loc <= self.last_commit_loc.unwrap_or(0));
        // Perform the same steps as pruning except "crash" right after the log is pruned.
        try_join!(
            self.mmr.sync(&mut self.hasher).map_err(Error::Mmr),
            self.locations.sync().map_err(Error::Journal),
        )?;
        let section = loc / self.log_items_per_section;
        assert!(
            self.log.prune(section).await?,
            "nothing was pruned, so could not simulate failure"
        );

        // "fail" before mmr/locations are pruned.
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{adb::verify_proof, mmr::mem::Mmr as MemMmr};
    use commonware_cryptography::Sha256;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU64};

    // Use some weird sizes here to test boundary conditions.
    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 11;

    fn db_config(suffix: &str) -> Config<(commonware_codec::RangeCfg, ())> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("log_journal_{suffix}"),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_items_per_section: NZU64!(7),
            locations_journal_partition: format!("locations_journal_{suffix}"),
            locations_items_per_blob: NZU64!(13),
            locations_write_buffer: NZUsize!(1024),
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// A type alias for the concrete [Any] type used in these unit tests.
    type Db = Keyless<deterministic::Context, Vec<u8>, Sha256>;

    /// Return a [Keyless] database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> Db {
        Db::init(context, db_config("partition")).await.unwrap()
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = Standard::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.oldest_retained_loc().await.unwrap(), None);
            assert_eq!(db.root(&mut hasher), MemMmr::default().root(&mut hasher));
            assert_eq!(db.get_metadata().await.unwrap(), None);
            assert_eq!(db.last_commit_loc(), None);

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let v1 = vec![1u8; 8];
            let root = db.root(&mut hasher);
            db.append(v1).await.unwrap();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.get_metadata().await.unwrap(), None);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            let metadata = Some(vec![3u8; 10]);
            db.commit(metadata.clone()).await.unwrap();
            assert_eq!(db.op_count(), 1); // commit op
            assert_eq!(
                db.get_metadata().await.unwrap(),
                Some((0, metadata.clone()))
            );
            assert_eq!(db.get(0).await.unwrap(), metadata); // the commit op
            let root = db.root(&mut hasher);

            // Commit op should remain after reopen even without clean shutdown.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1); // commit op should remain after re-open.
            assert_eq!(db.get_metadata().await.unwrap(), Some((0, metadata)));
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.last_commit_loc(), Some(0));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_keyless_db_build_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Build a db with 2 values and make sure we can get them back.
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            let v1 = vec![1u8; 8];
            let v2 = vec![2u8; 20];

            let loc1 = db.append(v1.clone()).await.unwrap();
            assert_eq!(db.get(loc1).await.unwrap().unwrap(), v1);

            let loc2 = db.append(v2.clone()).await.unwrap();
            assert_eq!(db.get(loc2).await.unwrap().unwrap(), v2);

            // Make sure closing/reopening gets us back to the same state.
            db.commit(None).await.unwrap();
            assert_eq!(db.op_count(), 3); // 2 appends, 1 commit
            assert_eq!(db.get_metadata().await.unwrap(), Some((2, None)));
            assert_eq!(db.get(2).await.unwrap(), None); // the commit op
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 3);
            assert_eq!(db.root(&mut hasher), root);

            assert_eq!(db.get(loc1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(loc2).await.unwrap().unwrap(), v2);

            db.append(v2).await.unwrap();
            db.append(v1).await.unwrap();

            // Make sure uncommitted items get rolled back.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 3);
            assert_eq!(db.root(&mut hasher), root);

            // Make sure commit operation remains after close/reopen.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 3);
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_keyless_db_recovery() {
        let executor = deterministic::Runner::default();
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;
            let root = db.root(&mut hasher);

            for i in 0u64..ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.append(v.clone()).await.unwrap();
            }

            // Simulate a failure before committing and test that we rollback to the previous root.
            db.simulate_failure(false, false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // re-apply the updates and commit them this time.
            for i in 0u64..ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.append(v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);

            // Append even more values.
            for i in ELEMENTS..2 * ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                db.append(v.clone()).await.unwrap();
            }

            // Simulate a failure (mode 1) and test that we rollback to the previous root.
            db.simulate_failure(false, false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply the updates and simulate different failure mode (mode 2).
            for i in ELEMENTS..2 * ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                db.append(v.clone()).await.unwrap();
            }
            db.simulate_failure(true, false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply the updates and simulate different failure mode (mode 3).
            for i in ELEMENTS..2 * ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                db.append(v.clone()).await.unwrap();
            }
            db.simulate_failure(true, true, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply the updates and simulate different failure mode (mode 4).
            for i in ELEMENTS..2 * ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                db.append(v.clone()).await.unwrap();
            }
            db.simulate_failure(true, false, true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply the updates and simulate different failure mode (mode 5).
            for i in ELEMENTS..2 * ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                db.append(v.clone()).await.unwrap();
            }
            db.simulate_failure(false, true, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply the updates and simulate different failure mode (mode 6).
            for i in ELEMENTS..2 * ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                db.append(v.clone()).await.unwrap();
            }
            db.simulate_failure(false, false, true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply the updates and simulate different failure mode (mode 7).
            for i in ELEMENTS..2 * ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                db.append(v.clone()).await.unwrap();
            }
            db.simulate_failure(false, true, true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply the updates and commit them this time.
            for i in ELEMENTS..2 * ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                db.append(v.clone()).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);

            // Make sure we can close/reopen and get back to the same state.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2 * ELEMENTS + 2);
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_keyless_db_non_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Append many values then commit.
            const ELEMENTS: u64 = 200;
            for i in 0u64..ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                db.append(v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            db.prune(10).await.unwrap();
            let root = db.root(&mut hasher);
            let op_count = db.op_count();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.last_commit_loc(), Some(op_count - 1));
            db.close().await.unwrap();

            async fn apply_more_ops(db: &mut Db) {
                for i in 0..ELEMENTS {
                    let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                    db.append(v).await.unwrap();
                }
            }

            // Insert many operations without commit, then simulate various types of failures.
            async fn recover_from_failure(
                context: deterministic::Context,
                root: <Sha256 as CHasher>::Digest,
                hasher: &mut Standard<Sha256>,
                op_count: u64,
            ) {
                let mut db = open_db(context.clone()).await;
                apply_more_ops(&mut db).await;
                db.simulate_failure(false, false, false).await.unwrap();
                let mut db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(hasher), root);

                apply_more_ops(&mut db).await;
                db.simulate_failure(true, false, false).await.unwrap();
                let mut db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(hasher), root);

                apply_more_ops(&mut db).await;
                db.simulate_failure(false, true, false).await.unwrap();
                let mut db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(hasher), root);

                apply_more_ops(&mut db).await;
                db.simulate_failure(false, false, true).await.unwrap();
                let mut db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(hasher), root);

                apply_more_ops(&mut db).await;
                db.simulate_failure(true, true, false).await.unwrap();
                let mut db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(hasher), root);

                apply_more_ops(&mut db).await;
                db.simulate_failure(true, false, true).await.unwrap();
                let mut db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(hasher), root);

                apply_more_ops(&mut db).await;
                db.simulate_failure(false, true, true).await.unwrap();
                let db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(hasher), root);
                assert_eq!(db.last_commit_loc(), Some(op_count - 1));
            }

            recover_from_failure(context.clone(), root, &mut hasher, op_count).await;

            // Simulate a failure during pruning and ensure we recover.
            let db = open_db(context.clone()).await;
            let last_commit_loc = db.last_commit_loc().unwrap();
            db.simulate_prune_failure(last_commit_loc).await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(&mut hasher), root);
            db.close().await.unwrap();

            // Repeat recover_from_failure tests after successfully pruning to the last commit.
            let mut db = open_db(context.clone()).await;
            db.prune(db.last_commit_loc().unwrap()).await.unwrap();
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(&mut hasher), root);
            db.close().await.unwrap();

            recover_from_failure(context.clone(), root, &mut hasher, op_count).await;

            // Apply the ops one last time but fully commit them this time, then clean up.
            let mut db = open_db(context.clone()).await;
            apply_more_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > op_count);
            assert_ne!(db.root(&mut hasher), root);
            assert_eq!(db.last_commit_loc(), Some(db.op_count() - 1));

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating an empty DB recover to the empty
    /// DB on re-open.
    #[test_traced("WARN")]
    fn test_keyless_db_empty_db_recovery() {
        const ELEMENTS: u64 = 1000;
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let db = open_db(context.clone()).await;
            let root = db.root(&mut hasher);

            // Reopen DB without clean shutdown and make sure the state is the same.
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            async fn apply_ops(db: &mut Db) {
                for i in 0..ELEMENTS {
                    let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                    db.append(v).await.unwrap();
                }
            }

            // Simulate various failure types after inserting operations without a commit.
            apply_ops(&mut db).await;
            db.simulate_failure(false, false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            apply_ops(&mut db).await;
            db.simulate_failure(true, false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            apply_ops(&mut db).await;
            db.simulate_failure(false, true, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            apply_ops(&mut db).await;
            db.simulate_failure(false, false, true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            apply_ops(&mut db).await;
            db.simulate_failure(true, true, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            apply_ops(&mut db).await;
            db.simulate_failure(true, false, true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            apply_ops(&mut db).await;
            db.simulate_failure(false, true, true).await.unwrap();
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
            assert_eq!(db.last_commit_loc(), None);

            // Apply the ops one last time but fully commit them this time, then clean up.
            apply_ops(&mut db).await;
            db.commit(None).await.unwrap();
            let db = open_db(context.clone()).await;
            assert!(db.op_count() > 0);
            assert_ne!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_proof_generation_and_verification() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Build a db with some values
            const ELEMENTS: u64 = 100;
            let mut values = Vec::new();
            for i in 0u64..ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                values.push(v.clone());
                db.append(v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);

            // Test proof generation for various ranges
            let test_cases = vec![
                (0, 10),           // First 10 operations
                (10, 5),           // Middle range
                (50, 20),          // Larger range
                (90, 15),          // Range that extends beyond end (should be limited)
                (0, 1),            // Single operation
                (ELEMENTS - 1, 1), // Last append operation
                (ELEMENTS, 1),     // The commit operation
            ];

            for (start_loc, max_ops) in test_cases {
                let (proof, ops) = db.proof(start_loc, NZU64!(max_ops)).await.unwrap();

                // Verify the proof
                assert!(
                    verify_proof(&mut hasher, &proof, start_loc, &ops, &root),
                    "Failed to verify proof for range starting at {start_loc} with max {max_ops} ops",
                );

                // Check that we got the expected number of operations
                let expected_ops = std::cmp::min(max_ops, db.op_count() - start_loc);
                assert_eq!(
                    ops.len() as u64,
                    expected_ops,
                    "Expected {expected_ops} operations, got {}",
                    ops.len(),
                );

                // Verify operation types
                for (i, op) in ops.iter().enumerate() {
                    let loc = start_loc + i as u64;
                    if loc < ELEMENTS {
                        // Should be an Append operation
                        assert!(
                            matches!(op, Operation::Append(_)),
                            "Expected Append operation at location {loc}, got {op:?}",
                        );
                    } else if loc == ELEMENTS {
                        // Should be a Commit operation
                        assert!(
                            matches!(op, Operation::Commit(_)),
                            "Expected Commit operation at location {loc}, got {op:?}",
                        );
                    }
                }

                // Verify that proof fails with wrong root
                let wrong_root = Sha256::hash(&[0xFF; 32]);
                assert!(
                    !verify_proof(&mut hasher, &proof, start_loc, &ops, &wrong_root),
                    "Proof should fail with wrong root"
                );

                // Verify that proof fails with wrong start location
                if start_loc > 0 {
                    assert!(
                        !verify_proof(&mut hasher, &proof, start_loc - 1, &ops, &root),
                        "Proof should fail with wrong start location"
                    );
                }
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_proof_with_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Build a db with some values
            const ELEMENTS: u64 = 100;
            let mut values = Vec::new();
            for i in 0u64..ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                values.push(v.clone());
                db.append(v).await.unwrap();
            }
            db.commit(None).await.unwrap();

            // Add more elements and commit again
            for i in ELEMENTS..ELEMENTS * 2 {
                let v = vec![(i % 255) as u8; ((i % 17) + 5) as usize];
                values.push(v.clone());
                db.append(v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);

            println!("last commit loc: {}", db.last_commit_loc.unwrap());

            // Prune the first 30 operations
            const PRUNE_LOC: u64 = 30;
            db.prune(PRUNE_LOC).await.unwrap();

            // Verify pruning worked
            let oldest_retained = db.oldest_retained_loc().await.unwrap();
            assert!(
                oldest_retained.is_some(),
                "Should have oldest retained location after pruning"
            );

            // Root should remain the same after pruning
            assert_eq!(
                db.root(&mut hasher),
                root,
                "Root should not change after pruning"
            );

            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.op_count(), 2 * ELEMENTS + 2);
            assert!(db.oldest_retained_loc().await.unwrap().unwrap() <= PRUNE_LOC);

            // Test that we can't get pruned values
            for i in 0..oldest_retained.unwrap() {
                let result = db.get(i).await;
                // Should either return None (for commit ops) or encounter pruned data
                match result {
                    Ok(None) => {} // Commit operation or pruned
                    Ok(Some(_)) => {
                        panic!("Should not be able to get pruned value at location {i}")
                    }
                    Err(_) => {} // Expected error for pruned data
                }
            }

            // Test proof generation after pruning - should work for non-pruned ranges
            let test_cases = vec![
                (oldest_retained.unwrap(), 10), // Starting from oldest retained
                (50, 20),                       // Middle range (if not pruned)
                (150, 10),                      // Later range
                (190, 15),                      // Near the end
            ];

            for (start_loc, max_ops) in test_cases {
                // Skip if start_loc is before oldest retained
                if start_loc < oldest_retained.unwrap() {
                    continue;
                }

                let (proof, ops) = db.proof(start_loc, NZU64!(max_ops)).await.unwrap();

                // Verify the proof still works
                assert!(
                    verify_proof(&mut hasher, &proof, start_loc, &ops, &root),
                    "Failed to verify proof for range starting at {start_loc} with max {max_ops} ops after pruning",
                );

                // Check that we got operations
                let expected_ops = std::cmp::min(max_ops, db.op_count() - start_loc);
                assert_eq!(
                    ops.len() as u64,
                    expected_ops,
                    "Expected {expected_ops} operations, got {}",
                    ops.len(),
                );
            }

            // Test pruning more aggressively
            const AGGRESSIVE_PRUNE: u64 = 150;
            db.prune(AGGRESSIVE_PRUNE).await.unwrap();

            let new_oldest = db.oldest_retained_loc().await.unwrap().unwrap();
            assert!(new_oldest <= AGGRESSIVE_PRUNE);

            // Can still generate proofs for the remaining data
            let (proof, ops) = db.proof(new_oldest, NZU64!(20)).await.unwrap();
            assert!(
                verify_proof(&mut hasher, &proof, new_oldest, &ops, &root),
                "Proof should still verify after aggressive pruning"
            );

            // Test edge case: prune everything except the last few operations
            let almost_all = db.op_count() - 5;
            db.prune(almost_all).await.unwrap();

            let final_oldest = db.oldest_retained_loc().await.unwrap().unwrap();

            // Should still be able to prove the remaining operations
            if final_oldest < db.op_count() {
                let (final_proof, final_ops) = db.proof(final_oldest, NZU64!(10)).await.unwrap();
                assert!(
                    verify_proof(&mut hasher, &final_proof, final_oldest, &final_ops, &root),
                    "Should be able to prove remaining operations after extensive pruning"
                );
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_keyless_db_replay_with_trailing_appends() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();

            // Create initial database with committed data
            let mut db = open_db(context.clone()).await;

            // Add some initial operations and commit
            for i in 0..10 {
                let v = vec![i as u8; 10];
                db.append(v).await.unwrap();
            }
            db.commit(None).await.unwrap();
            let committed_root = db.root(&mut hasher);
            let committed_size = db.op_count();

            // Add exactly one more append (uncommitted)
            let uncommitted_value = vec![99u8; 20];
            db.append(uncommitted_value.clone()).await.unwrap();

            // Sync only the log (not MMR or locations)
            db.simulate_failure(true, false, false).await.unwrap();

            // Reopen database
            let mut db = open_db(context.clone()).await;

            // Verify correct recovery
            assert_eq!(
                db.op_count(),
                committed_size,
                "Should rewind to last commit"
            );
            assert_eq!(
                db.root(&mut hasher),
                committed_root,
                "Root should match last commit"
            );
            assert_eq!(
                db.last_commit_loc(),
                Some(committed_size - 1),
                "Last commit location should be correct"
            );

            // Verify the uncommitted append was properly discarded
            // We should be able to append new data without issues
            let new_value = vec![77u8; 15];
            let loc = db.append(new_value.clone()).await.unwrap();
            assert_eq!(
                loc, committed_size,
                "New append should get the expected location"
            );

            // Verify we can read the new value
            assert_eq!(db.get(loc).await.unwrap(), Some(new_value));

            // Test with multiple trailing appends to ensure robustness
            db.commit(None).await.unwrap();
            let new_committed_root = db.root(&mut hasher);
            let new_committed_size = db.op_count();

            // Add multiple uncommitted appends
            for i in 0..5 {
                let v = vec![(200 + i) as u8; 10];
                db.append(v).await.unwrap();
            }

            // Simulate the same partial failure scenario
            db.simulate_failure(true, false, false).await.unwrap();

            // Reopen and verify correct recovery
            let db = open_db(context.clone()).await;
            assert_eq!(
                db.op_count(),
                new_committed_size,
                "Should rewind to last commit with multiple trailing appends"
            );
            assert_eq!(
                db.root(&mut hasher),
                new_committed_root,
                "Root should match last commit after multiple appends"
            );
            assert_eq!(
                db.last_commit_loc(),
                Some(new_committed_size - 1),
                "Last commit location should be correct after multiple appends"
            );

            db.destroy().await.unwrap();
        });
    }
}
