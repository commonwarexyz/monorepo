//! The [Keyless] adb allows for append-only storage of arbitrary variable-length data that can
//! later be retrieved by its location.
//!
//! The implementation consists of an `mmr` over the operations applied to the database, an
//! operations `log` storing these operations, and a `locations` journal storing the offset of its
//! respective operation in its section of the operations log.

use crate::{
    adb::Error,
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
    store::operation::Keyless as Operation,
};
use commonware_codec::{Codec, Encode as _};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage, ThreadPool};
use futures::{future::TryFutureExt, try_join};
use std::num::{NonZeroU64, NonZeroUsize};
use tracing::warn;

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
}

impl<E: Storage + Clock + Metrics, V: Codec, H: CHasher> Keyless<E, V, H> {
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

        // Align the size of the locations journal with the MMR.
        let mut locations_size = locations.size().await?;
        let mmr_leaves = leaf_pos_to_num(mmr.size()).expect("invalid mmr size");
        if locations_size > mmr_leaves {
            warn!(
                mmr_leaves,
                locations_size, "rewinding misaligned locations journal"
            );
            locations.rewind(mmr_leaves).await?;
            locations_size = mmr_leaves;
        } else if mmr_leaves > locations_size {
            warn!(mmr_leaves, locations_size, "rewinding misaligned mmr");
            mmr.pop((mmr_leaves - locations_size) as usize).await?;
        }

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

        // Rewind to the last commit point if necessary.
        let mut op_index = locations_size;
        // The most recent commit point (if any).
        let mut last_commit_loc = None;
        // The location of the first append operation to follow the last known commit, and the
        // offset it wraps.
        let mut rewind_point = None;
        while op_index > 0 {
            op_index -= 1;
            let offset = locations.read(op_index).await?;
            let section = op_index / cfg.log_items_per_section.get();
            let op = log.get(section, offset).await?.expect("no operation found");
            match op {
                Operation::Commit => {
                    last_commit_loc = Some(op_index);
                    break;
                }
                Operation::Append(_) => {
                    rewind_point = Some((op_index, offset));
                }
            }
        }
        if let Some(last_commit_loc) = last_commit_loc {
            if last_commit_loc != locations_size - 1 {
                // There's at least one append operation to rewind.
                warn!(
                    old_size = locations_size,
                    new_size = last_commit_loc + 1,
                    "rewinding to last commit point"
                );
                locations.rewind(last_commit_loc + 1).await?;
                mmr.pop((locations_size - last_commit_loc - 1) as usize)
                    .await?;
                locations_size = last_commit_loc + 1;
                // Rewind the operations log last to ensure the locations journal always references
                // valid data in the event of failures.
                let rewind_point = rewind_point.expect("no rewind point found");
                let section = rewind_point.0 / cfg.log_items_per_section.get();
                log.rewind_to_offset(section, rewind_point.1).await?;
            }
        } else if locations_size > 0 {
            warn!(
                old_size = locations_size,
                "no commit point found, rewinding to start"
            );
            locations.rewind(0).await?;
            mmr.pop(locations_size as usize).await?;
            locations_size = 0;
            log.rewind_section(0, 0).await?;
        }

        Ok(Self {
            mmr,
            log,
            size: locations_size,
            locations,
            log_items_per_section: cfg.log_items_per_section.get(),
            hasher,
        })
    }

    /// Get the value at location `loc` in the database. Returns None if the location is valid but
    /// does not correspond to an append.
    pub async fn get(&self, loc: u64) -> Result<Option<V>, Error> {
        let offset = self.locations.read(loc).await?;

        let section = loc / self.log_items_per_section;
        let Some(op) = self.log.get(section, offset).await? else {
            panic!("didn't find operation at location {loc} and offset {offset}");
        };
        let Operation::Append(value) = op else {
            return Ok(None);
        };

        Ok(Some(value))
    }

    /// Get the number of appends + commits that have been applied to the db.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the section of the operations log where we are currently writing new operations.
    fn current_section(&self) -> u64 {
        self.size / self.log_items_per_section
    }

    /// Return the oldest location that remains retrievable.
    pub async fn oldest_retained_loc(&self) -> Result<Option<u64>, Error> {
        self.locations
            .oldest_retained_pos()
            .await
            .map_err(Error::Journal)
    }

    /// Prunes the db of up to all operations that have location less than `loc`. The actual number
    /// pruned may be fewer than requested due to blob boundaries in the underlying journals.
    ///
    /// # Panics
    ///
    /// Panics if `loc` is greater than the current size of the database.
    pub async fn prune(&mut self, loc: u64) -> Result<(), Error> {
        assert!(loc <= self.size);

        // Prune the locations journal first. This ensures that if pruning fails, we never have
        // location entries without corresponding data in the other structures.
        self.locations.prune(loc).await?;

        // Prune the MMR and operations log to the corresponding positions.
        let prune_to_section = loc / self.log_items_per_section;
        try_join!(
            self.mmr
                .prune_to_pos(&mut self.hasher, leaf_num_to_pos(loc))
                .map_err(Error::Mmr),
            self.log.prune(prune_to_section).map_err(Error::Journal),
        )?;

        Ok(())
    }

    /// Append a value to the db, returning its location which can be used to retrieve it.
    pub async fn append(&mut self, value: V) -> Result<u64, Error> {
        let loc = self.size;
        let section = self.current_section();
        let operation = Operation::Append(value);
        let encoded_operation = operation.encode();
        let (offset, _) = self.log.append(section, operation).await?;
        self.locations.append(offset).await?;
        self.mmr
            .add_batched(&mut self.hasher, &encoded_operation)
            .await?;

        self.size += 1;
        if section != self.current_section() {
            self.log.sync(section).await?;
        }

        Ok(loc)
    }

    /// Commit any pending operations to the db, ensuring they are persisted to disk & recoverable.
    pub async fn commit(&mut self) -> Result<u64, Error> {
        let loc = self.size;
        let section = self.current_section();
        let operation = Operation::Commit;

        // We must update & sync the operations log before writing the commit operation to locations
        // to ensure all committed locations will reference valid data in the event of a failure.
        let encoded_operation = operation.encode();
        let (offset, _) = self.log.append(section, operation).await?;
        self.log.sync(section).await?;

        self.locations.append(offset).await?;
        self.size += 1;

        self.mmr
            .add_batched(&mut self.hasher, &encoded_operation)
            .await?;

        try_join!(
            self.locations.sync().map_err(Error::Journal),
            self.mmr.sync(&mut self.hasher).map_err(Error::Mmr),
        )?;

        Ok(loc)
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
        max_ops: u64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<V>>), Error> {
        self.historical_proof(self.size, start_loc, max_ops).await
    }

    /// Analogous to proof, but with respect to the state of the MMR when it had `size` elements.
    pub async fn historical_proof(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: u64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<V>>), Error> {
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
            let offset = self.locations.read(loc).await?;
            let section = loc / self.log_items_per_section;
            let value = self
                .log
                .get(section, offset)
                .await?
                .expect("no value found");
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
    /// Simulate failures during commit.
    pub(super) async fn simulate_failure(
        mut self,
        sync_log: bool,
        sync_mmr: bool,
        sync_locations: bool,
    ) -> Result<(), Error> {
        let operation = Operation::Commit;

        // We must update & sync the operations log before writing the commit operation to locations
        // to ensure all committed locations will reference valid data in the event of a failure.
        let encoded_operation = operation.encode();
        let offset = if sync_log {
            let section = self.current_section();
            let (offset, _) = self.log.append(section, operation).await?;
            self.log.sync(section).await?;
            offset
        } else {
            assert!(!sync_mmr, "can't sync mmr without syncing log");
            assert!(!sync_locations, "can't sync locations without syncing log");
            0
        };

        if sync_mmr {
            self.mmr
                .add_batched(&mut self.hasher, &encoded_operation)
                .await?;
            self.mmr.sync(&mut self.hasher).await?;
        }
        if sync_locations {
            self.locations.append(offset).await?;
            self.locations.sync().await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        adb::verify_proof,
        mmr::{hasher::Standard, mem::Mmr as MemMmr},
    };
    use commonware_cryptography::{hash, Sha256};
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
            locations_items_per_blob: NZU64!(7),
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
            assert_eq!(db.size(), 0);
            assert_eq!(db.oldest_retained_loc().await.unwrap(), None);
            assert_eq!(db.root(&mut hasher), MemMmr::default().root(&mut hasher));

            // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
            let v1 = vec![1u8; 8];
            let root = db.root(&mut hasher);
            db.append(v1).await.unwrap();
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);
            assert_eq!(db.size(), 0);

            // Test calling commit on an empty db which should make it (durably) non-empty.
            db.commit().await.unwrap();
            assert_eq!(db.size(), 1); // floor op added
            let root = db.root(&mut hasher);
            let db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);

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
            db.commit().await.unwrap();
            assert_eq!(db.size(), 3); // 2 appends, 1 commit
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(db.size(), 3);
            assert_eq!(db.root(&mut hasher), root);

            assert_eq!(db.get(loc1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(loc2).await.unwrap().unwrap(), v2);

            db.append(v2).await.unwrap();
            db.append(v1).await.unwrap();

            // Make sure uncommitted items get rolled back.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);

            // Make sure commit operation remains after close/reopen.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.size(), 3);
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

            // Simulate a failed commit and test that we rollback to the previous empty-db root.
            db.simulate_failure(false, false, false).await.unwrap();
            let mut db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));

            // re-apply the updates and commit them this time.
            for i in 0u64..ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.append(v.clone()).await.unwrap();
            }
            db.commit().await.unwrap();
            let root = db.root(&mut hasher);

            // Append even more values.
            for i in ELEMENTS..2 * ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                db.append(v.clone()).await.unwrap();
            }

            // Simulate a failed commit (mode 1) and test that we rollback to the previous root.
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

            // Re-apply the updates and commit them this time.
            for i in ELEMENTS..2 * ELEMENTS {
                let v = vec![(i % 255) as u8; ((i % 17) + 13) as usize];
                db.append(v.clone()).await.unwrap();
            }
            db.commit().await.unwrap();
            let root = db.root(&mut hasher);

            // Make sure we can close/reopen and get back to the same state.
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(db.size(), 2 * ELEMENTS + 2);
            assert_eq!(db.root(&mut hasher), root);

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
            db.commit().await.unwrap();
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
                let (proof, ops) = db.proof(start_loc, max_ops).await.unwrap();

                // Verify the proof
                assert!(
                    verify_proof(&mut hasher, &proof, start_loc, &ops, &root),
                    "Failed to verify proof for range starting at {start_loc} with max {max_ops} ops",
                );

                // Check that we got the expected number of operations
                let expected_ops = std::cmp::min(max_ops, db.size() - start_loc);
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
                            matches!(op, Operation::Commit),
                            "Expected Commit operation at location {loc}, got {op:?}",
                        );
                    }
                }

                // Verify that proof fails with wrong root
                let wrong_root = hash(&[0xFF; 32]);
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
            db.commit().await.unwrap();

            // Add more elements and commit again
            for i in ELEMENTS..ELEMENTS * 2 {
                let v = vec![(i % 255) as u8; ((i % 17) + 5) as usize];
                values.push(v.clone());
                db.append(v).await.unwrap();
            }
            db.commit().await.unwrap();
            let root = db.root(&mut hasher);

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
            assert_eq!(db.size(), 2 * ELEMENTS + 2);
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

                let (proof, ops) = db.proof(start_loc, max_ops).await.unwrap();

                // Verify the proof still works
                assert!(
                    verify_proof(&mut hasher, &proof, start_loc, &ops, &root),
                    "Failed to verify proof for range starting at {start_loc} with max {max_ops} ops after pruning",
                );

                // Check that we got operations
                let expected_ops = std::cmp::min(max_ops, db.size() - start_loc);
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
            let (proof, ops) = db.proof(new_oldest, 20).await.unwrap();
            assert!(
                verify_proof(&mut hasher, &proof, new_oldest, &ops, &root),
                "Proof should still verify after aggressive pruning"
            );

            // Test edge case: prune everything except the last few operations
            let almost_all = db.size() - 5;
            db.prune(almost_all).await.unwrap();

            let final_oldest = db.oldest_retained_loc().await.unwrap().unwrap();

            // Should still be able to prove the remaining operations
            if final_oldest < db.size() {
                let (final_proof, final_ops) = db.proof(final_oldest, 10).await.unwrap();
                assert!(
                    verify_proof(&mut hasher, &final_proof, final_oldest, &final_ops, &root),
                    "Should be able to prove remaining operations after extensive pruning"
                );
            }

            db.destroy().await.unwrap();
        });
    }
}
