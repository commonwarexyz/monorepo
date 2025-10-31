//! The [Keyless] adb allows for append-only storage of arbitrary variable-length data that can
//! later be retrieved by its location.
//!
//! The implementation consists of an `mmr` over the operations applied to the database and an
//! operations `log` storing these operations.
//!
//! The state of the operations log up until the last commit point is the "source of truth". In the
//! event of unclean shutdown, the mmr will be brought back into alignment with the log on startup.

use crate::{
    adb::{operation::keyless::Operation, Error},
    journal::contiguous::variable::{Config as JournalConfig, Journal},
    mmr::{
        journaled::{Config as MmrConfig, Mmr},
        Location, Position, Proof, StandardHasher as Standard,
    },
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
    pub log_partition: String,

    /// The size of the write buffer to use with the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding the operations log.
    pub log_codec_config: C,

    /// The max number of operations to put in each section of the operations log.
    pub log_items_per_section: NonZeroU64,

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
    /// The number of leaves in this MMR always equals the number of operations in the unpruned log.
    mmr: Mmr<E, H>,

    /// A journal of all operations ever applied to the db.
    log: Journal<E, Operation<V>>,

    /// Cryptographic hasher to re-use within mutable operations requiring digest computation.
    hasher: Standard<H>,

    /// The location of the last commit, if any.
    last_commit_loc: Option<Location>,
}

impl<E: Storage + Clock + Metrics, V: Codec, H: CHasher> Keyless<E, V, H> {
    /// Walk backwards and removes uncommited operations after the last commit.
    ///
    /// Returns the log size after rewinding.
    async fn rewind_uncommitted(log: &mut Journal<E, Operation<V>>) -> Result<u64, Error> {
        let log_size = log.size();
        if log_size == 0 {
            return Ok(0);
        }
        let Some(oldest_retained_loc) = log.oldest_retained_pos() else {
            // Log is fully pruned
            return Ok(log_size);
        };

        // Walk backwards to find last commit
        let mut first_uncommitted = None;
        let mut loc = log_size - 1;

        loop {
            let op = log.read(loc).await?;
            match op {
                Operation::Commit(_) => break,
                Operation::Append(_) => {
                    first_uncommitted = Some(loc);
                }
            }
            if loc == oldest_retained_loc {
                break;
            }
            loc -= 1;
        }

        // Rewind operations after the last commit
        if let Some(rewind_loc) = first_uncommitted {
            let ops_to_rewind = log_size - rewind_loc;
            warn!(ops_to_rewind, ?rewind_loc, "rewinding log to last commit");
            log.rewind(rewind_loc).await?;
            log.sync().await?;
            Ok(rewind_loc)
        } else {
            Ok(log_size)
        }
    }

    /// Align `mmr` with `log` by either popping excess operations or replaying missing ones.
    async fn align_mmr_with_log(
        mmr: &mut Mmr<E, H>,
        hasher: &mut Standard<H>,
        log: &Journal<E, Operation<V>>,
    ) -> Result<(), Error> {
        let mmr_size = *mmr.leaves();
        let log_size = log.size();

        if mmr_size > log_size {
            // MMR is ahead - pop excess
            let ops_to_pop = (mmr_size - log_size) as usize;
            warn!(ops_to_pop, "popping excess MMR operations");
            mmr.pop(ops_to_pop).await?;
        } else if mmr_size < log_size {
            // Should never happen because in `prune` we sync mmr before pruning log.
            assert!(
                log.oldest_retained_pos().is_some(),
                "log is fully pruned but mmr_size ({mmr_size}) < log_size ({log_size})"
            );

            // MMR is behind - replay missing operations
            let stream = log.replay(mmr_size, REPLAY_BUFFER_SIZE).await?;
            pin_mut!(stream);

            while let Some(result) = stream.next().await {
                let (_pos, op) = result?;
                let encoded_op = op.encode();
                warn!(location = ?mmr.leaves(), "adding missing operation to MMR");
                mmr.add_batched(hasher, &encoded_op).await?;
            }
        }

        if mmr.is_dirty() {
            mmr.sync(hasher).await?;
        }

        Ok(())
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

        let mut log = Journal::<E, Operation<V>>::init(
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

        // Rewind log to remove uncommitted operations
        Self::rewind_uncommitted(&mut log).await?;

        // Align MMR with log
        Self::align_mmr_with_log(&mut mmr, &mut hasher, &log).await?;
        let log_size = Location::new_unchecked(log.size());
        assert_eq!(
            mmr.leaves(),
            log_size,
            "MMR size should match log size after alignment"
        );

        Ok(Self {
            mmr,
            log,
            hasher,
            last_commit_loc: log_size.checked_sub(1),
        })
    }

    /// Get the value at location `loc` in the database.
    ///
    /// # Errors
    ///
    /// Returns [Error::LocationOutOfBounds] if `loc` >= `self.op_count()`.
    pub async fn get(&self, loc: Location) -> Result<Option<V>, Error> {
        let op_count = self.op_count();
        if loc >= op_count {
            return Err(Error::LocationOutOfBounds(loc, op_count));
        }
        let op = self.log.read(*loc).await?;

        Ok(op.into_value())
    }

    /// Get the number of operations (appends + commits) that have been applied to the db since
    /// inception.
    pub fn op_count(&self) -> Location {
        Location::new_unchecked(self.log.size())
    }

    /// Returns the location of the last commit, if any.
    pub fn last_commit_loc(&self) -> Option<Location> {
        self.last_commit_loc
    }

    /// Return the oldest location that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Option<Location> {
        self.log.oldest_retained_pos().map(Location::new_unchecked)
    }

    /// Prunes the db of up to all operations that have location less than `loc`. The actual number
    /// pruned may be fewer than requested due to blob boundaries in the underlying journals.
    ///
    /// # Errors
    ///
    /// Returns [Error::PruneBeyondCommit] if `loc` is beyond the last commit point.
    pub async fn prune(&mut self, loc: Location) -> Result<(), Error> {
        let last_commit = self.last_commit_loc.unwrap_or(Location::new_unchecked(0));
        if loc > last_commit {
            return Err(Error::PruneBeyondCommit(loc, last_commit));
        }

        // Sync the mmr before pruning the log, otherwise the MMR tip could end up behind the log's
        // pruning boundary on restart from an unclean shutdown, and there would be no way to replay
        // the operations between the MMR tip and the log pruning boundary.
        self.mmr.sync(&mut self.hasher).await?;

        // Prune the log first since it's always the source of truth. The log will prune at section boundaries,
        // so the actual oldest retained location may be less than requested. We always prune the
        // log first, and then prune the MMR based on the log's actual pruning boundary. This
        // procedure ensures all log operations always have corresponding MMR entries, even in the
        // event of failures, with no need for special recovery.
        self.log.prune(*loc).await?;

        let oldest_retained_loc = match self.log.oldest_retained_pos() {
            Some(oldest) => Location::new_unchecked(oldest),
            None => self.op_count(),
        };

        debug!(size = ?self.op_count(), loc = ?oldest_retained_loc, "pruned log");

        // Prune the MMR up to the oldest retained item in the log after pruning.
        self.mmr
            .prune_to_pos(&mut self.hasher, Position::try_from(oldest_retained_loc)?)
            .await?;

        Ok(())
    }

    /// Append a value to the db, returning its location which can be used to retrieve it.
    pub async fn append(&mut self, value: V) -> Result<Location, Error> {
        let loc = Location::new_unchecked(self.log.size());
        let operation = Operation::Append(value);
        let encoded_operation = operation.encode();

        // Create a future that appends the operation to the log.
        let log_fut = async {
            self.log.append(operation).await?;
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
        try_join!(log_fut, mmr_fut)?;

        Ok(loc)
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Caller can associate an arbitrary `metadata` value with the commit.
    ///
    /// Failures after commit (but before `sync` or `close`) may still require reprocessing to
    /// recover the database on restart.
    pub async fn commit(&mut self, metadata: Option<V>) -> Result<Location, Error> {
        let loc = Location::new_unchecked(self.log.size());
        self.last_commit_loc = Some(loc);

        let operation = Operation::Commit(metadata);
        let encoded_operation = operation.encode();

        // Create a future that updates and syncs the log.
        let log_fut = async {
            self.log.append(operation).await?;
            self.log.sync_data().await?;
            Ok::<(), Error>(())
        };

        // Create a future that adds the commit operation to the MMR and merkleizes all updates.
        let mmr_fut = async {
            self.mmr
                .add_batched(&mut self.hasher, &encoded_operation)
                .await?;
            self.mmr.merkleize(&mut self.hasher);

            Ok::<(), Error>(())
        };

        // Run the 2 futures in parallel.
        try_join!(log_fut, mmr_fut)?;

        debug!(size = ?self.op_count(), "committed db");

        Ok(loc)
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

    /// Get the location and metadata associated with the last commit, or None if no commit has been
    /// made.
    pub async fn get_metadata(&self) -> Result<Option<(Location, Option<V>)>, Error> {
        let Some(loc) = self.last_commit_loc else {
            return Ok(None);
        };
        let op = self.log.read(*loc).await?;
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
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<V>>), Error> {
        self.historical_proof(self.op_count(), start_loc, max_ops)
            .await
    }

    /// Analogous to proof, but with respect to the state of the MMR when it had `op_count`
    /// operations.
    ///
    /// # Errors
    ///
    /// - Returns [crate::mmr::Error::LocationOverflow] if `op_count` or `start_loc` >
    ///   [crate::mmr::MAX_LOCATION].
    /// - Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= `op_count` or `op_count` >
    ///   number of operations.
    pub async fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<V>>), Error> {
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
            let value = self.log.read(loc).await?;
            ops.push(value);
        }

        Ok((proof, ops))
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
            self.mmr.destroy().map_err(Error::Mmr),
            self.log.destroy().map_err(Error::Journal),
        )?;

        Ok(())
    }

    #[cfg(any(test, feature = "fuzzing"))]
    /// Simulate failure by consuming the db but without syncing / closing the various structures.
    pub async fn simulate_failure(mut self, sync_log: bool, sync_mmr: bool) -> Result<(), Error> {
        if sync_log {
            self.log.sync().await?;
        }
        if sync_mmr {
            self.mmr.sync(&mut self.hasher).await?;
        }

        Ok(())
    }

    #[cfg(test)]
    /// Simulate pruning failure by consuming the db and abandoning pruning operation mid-flight.
    pub(super) async fn simulate_prune_failure(mut self, loc: Location) -> Result<(), Error> {
        let last_commit = self.last_commit_loc.unwrap_or(Location::new_unchecked(0));
        if loc > last_commit {
            return Err(Error::PruneBeyondCommit(loc, last_commit));
        }
        // Perform the same steps as pruning except "crash" right after the log is pruned.
        self.mmr.sync(&mut self.hasher).await?;
        assert!(
            self.log.prune(*loc).await?,
            "nothing was pruned, so could not simulate failure"
        );

        // "fail" before mmr is pruned.
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
    use rand::Rng;

    // Use some weird sizes here to test boundary conditions.
    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 11;

    fn db_config(suffix: &str) -> Config<(commonware_codec::RangeCfg<usize>, ())> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_items_per_section: NZU64!(7),
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
            assert_eq!(db.oldest_retained_loc(), None);
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
                Some((Location::new_unchecked(0), metadata.clone()))
            );
            assert_eq!(db.get(Location::new_unchecked(0)).await.unwrap(), metadata); // the commit op
            let root = db.root(&mut hasher);

            // Commit op should remain after reopen even without clean shutdown.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 1); // commit op should remain after re-open.
            assert_eq!(
                db.get_metadata().await.unwrap(),
                Some((Location::new_unchecked(0), metadata))
            );
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.last_commit_loc(), Some(Location::new_unchecked(0)));

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
            assert_eq!(
                db.get_metadata().await.unwrap(),
                Some((Location::new_unchecked(2), None))
            );
            assert_eq!(db.get(Location::new_unchecked(2)).await.unwrap(), None); // the commit op
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

    // Helper function to append random elements to a database.
    async fn append_elements<T: Rng>(db: &mut Db, rng: &mut T, num_elements: usize) {
        for _ in 0..num_elements {
            let value = vec![(rng.next_u32() % 255) as u8, (rng.next_u32() % 255) as u8];
            db.append(value).await.unwrap();
        }
    }

    #[test_traced("WARN")]
    pub fn test_keyless_db_recovery() {
        let executor = deterministic::Runner::default();
        const ELEMENTS: usize = 1000;
        executor.start(|mut context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;
            let root = db.root(&mut hasher);

            append_elements(&mut db, &mut context, ELEMENTS).await;

            // Simulate a failure before committing.
            db.simulate_failure(false, false).await.unwrap();
            // Should rollback to the previous root.
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply the updates and commit them this time.
            append_elements(&mut db, &mut context, ELEMENTS).await;
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);

            // Append more values.
            append_elements(&mut db, &mut context, ELEMENTS).await;

            // Simulate a failure.
            db.simulate_failure(false, false).await.unwrap();
            // Should rollback to the previous root.
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply the updates.
            append_elements(&mut db, &mut context, ELEMENTS).await;
            // Simulate a failure after syncing log but not MMR.
            db.simulate_failure(true, false).await.unwrap();
            // Should rollback to the previous root.
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply the updates.
            append_elements(&mut db, &mut context, ELEMENTS).await;
            // Simulate a failure after syncing MMR but not log.
            db.simulate_failure(false, true).await.unwrap();
            // Should rollback to the previous root.
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // Re-apply the updates and commit them this time.
            append_elements(&mut db, &mut context, ELEMENTS).await;
            db.commit(None).await.unwrap();
            let root = db.root(&mut hasher);

            // Make sure we can close/reopen and get back to the same state.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 2 * ELEMENTS as u64 + 2);
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    /// Test that various types of unclean shutdown while updating a non-empty DB recover to the
    /// empty DB on re-open.
    #[test_traced("WARN")]
    fn test_keyless_db_non_empty_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            // Append many values then commit.
            const ELEMENTS: usize = 200;
            append_elements(&mut db, &mut context, ELEMENTS).await;
            db.commit(None).await.unwrap();
            db.prune(Location::new_unchecked(10)).await.unwrap();
            let root = db.root(&mut hasher);
            let op_count = db.op_count();

            // Reopen DB without clean shutdown and make sure the state is the same.
            let db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), op_count);
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.last_commit_loc(), Some(op_count - 1));
            db.close().await.unwrap();

            // Insert many operations without commit, then simulate various types of failures.
            async fn recover_from_failure(
                mut context: deterministic::Context,
                root: <Sha256 as CHasher>::Digest,
                hasher: &mut Standard<Sha256>,
                op_count: Location,
            ) {
                let mut db = open_db(context.clone()).await;

                // Append operations and simulate failure.
                append_elements(&mut db, &mut context, ELEMENTS).await;
                db.simulate_failure(false, false).await.unwrap();
                let mut db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(hasher), root);

                // Append operations and simulate failure after syncing log but not MMR.
                append_elements(&mut db, &mut context, ELEMENTS).await;
                db.simulate_failure(true, false).await.unwrap();
                let mut db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(hasher), root);

                // Append operations and simulate failure after syncing MMR but not log.
                append_elements(&mut db, &mut context, ELEMENTS).await;
                db.simulate_failure(false, true).await.unwrap();
                let db = open_db(context.clone()).await;
                assert_eq!(db.op_count(), op_count);
                assert_eq!(db.root(hasher), root);
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
            append_elements(&mut db, &mut context, ELEMENTS).await;
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
            db.simulate_failure(false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            apply_ops(&mut db).await;
            db.simulate_failure(true, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            apply_ops(&mut db).await;
            db.simulate_failure(false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            apply_ops(&mut db).await;
            db.simulate_failure(false, true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            apply_ops(&mut db).await;
            db.simulate_failure(true, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            apply_ops(&mut db).await;
            db.simulate_failure(true, true).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.root(&mut hasher), root);

            apply_ops(&mut db).await;
            db.simulate_failure(false, true).await.unwrap();
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

            // Test that historical proof fails with op_count > number of operations
            assert!(matches!(
                db.historical_proof(db.op_count() + 1, Location::new_unchecked(5), NZU64!(10))
                    .await,
                Err(Error::Mmr(crate::mmr::Error::RangeOutOfBounds(_)))
            ));

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
                let (proof, ops) = db.proof(Location::new_unchecked(start_loc), NZU64!(max_ops)).await.unwrap();

                // Verify the proof
                assert!(
                    verify_proof(&mut hasher, &proof, Location::new_unchecked(start_loc), &ops, &root),
                    "Failed to verify proof for range starting at {start_loc} with max {max_ops} ops",
                );

                // Check that we got the expected number of operations
                let expected_ops = std::cmp::min(max_ops, *db.op_count() - start_loc);
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
                    !verify_proof(&mut hasher, &proof, Location::new_unchecked(start_loc), &ops, &wrong_root),
                    "Proof should fail with wrong root"
                );

                // Verify that proof fails with wrong start location
                if start_loc > 0 {
                    assert!(
                        !verify_proof(&mut hasher, &proof, Location::new_unchecked(start_loc - 1), &ops, &root),
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
            db.prune(Location::new_unchecked(PRUNE_LOC)).await.unwrap();

            // Verify pruning worked
            let oldest_retained = db.oldest_retained_loc();
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
            assert!(db.oldest_retained_loc().unwrap() <= PRUNE_LOC);

            // Test that we can't get pruned values
            for i in 0..*oldest_retained.unwrap() {
                let result = db.get(Location::new_unchecked(i)).await;
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
                (Location::new_unchecked(50), 20),                       // Middle range (if not pruned)
                (Location::new_unchecked(150), 10),                      // Later range
                (Location::new_unchecked(190), 15),                      // Near the end
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
                let expected_ops = std::cmp::min(max_ops, *db.op_count() - *start_loc);
                assert_eq!(
                    ops.len() as u64,
                    expected_ops,
                    "Expected {expected_ops} operations, got {}",
                    ops.len(),
                );
            }

            // Test pruning more aggressively
            const AGGRESSIVE_PRUNE: Location = Location::new_unchecked(150);
            db.prune(AGGRESSIVE_PRUNE).await.unwrap();

            let new_oldest = db.oldest_retained_loc().unwrap();
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

            let final_oldest = db.oldest_retained_loc().unwrap();

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

            // Sync only the log (not MMR)
            db.simulate_failure(true, false).await.unwrap();

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
            db.simulate_failure(true, false).await.unwrap();

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

    #[test_traced("INFO")]
    pub fn test_keyless_db_get_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            // Test getting from empty database
            let result = db.get(Location::new_unchecked(0)).await;
            assert!(
                matches!(result, Err(Error::LocationOutOfBounds(loc, size)) if loc == Location::new_unchecked(0) && size == Location::new_unchecked(0))
            );

            // Add some values
            let v1 = vec![1u8; 8];
            let v2 = vec![2u8; 8];
            db.append(v1.clone()).await.unwrap();
            db.append(v2.clone()).await.unwrap();
            db.commit(None).await.unwrap();

            // Test getting valid locations - should succeed
            assert_eq!(db.get(Location::new_unchecked(0)).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(Location::new_unchecked(1)).await.unwrap().unwrap(), v2);

            // Test getting out of bounds location
            let result = db.get(Location::new_unchecked(3)).await;
            assert!(
                matches!(result, Err(Error::LocationOutOfBounds(loc, size)) if loc == Location::new_unchecked(3) && size == Location::new_unchecked(3))
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    pub fn test_keyless_db_prune_beyond_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;

            // Test pruning empty database (no commits)
            let result = db.prune(Location::new_unchecked(1)).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondCommit(prune_loc, commit_loc))
                    if prune_loc == Location::new_unchecked(1) && commit_loc == Location::new_unchecked(0))
            );

            // Add values and commit
            let v1 = vec![1u8; 8];
            let v2 = vec![2u8; 8];
            let v3 = vec![3u8; 8];
            db.append(v1.clone()).await.unwrap();
            db.append(v2.clone()).await.unwrap();
            db.commit(None).await.unwrap();
            db.append(v3.clone()).await.unwrap();

            // op_count is 4 (v1, v2, commit, v3), last_commit_loc is 2
            let last_commit = db.last_commit_loc().unwrap();
            assert_eq!(last_commit, Location::new_unchecked(2));

            // Test valid prune (at last commit)
            assert!(db.prune(last_commit).await.is_ok());

            // Add more and commit again
            db.commit(None).await.unwrap();
            let new_last_commit = db.last_commit_loc().unwrap();

            // Test pruning beyond last commit
            let beyond = Location::new_unchecked(*new_last_commit + 1);
            let result = db.prune(beyond).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondCommit(prune_loc, commit_loc))
                    if prune_loc == beyond && commit_loc == new_last_commit)
            );

            db.destroy().await.unwrap();
        });
    }
}
