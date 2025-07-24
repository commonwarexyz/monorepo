//! An authenticated database (ADB) that only supports adding new keyed values (no updates or
//! deletions), where values can have varying sizes.

use crate::{
    adb::{operation::Variable, Error},
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
    translator::Translator,
};
use commonware_codec::{Codec, Encode as _, Read};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage, ThreadPool};
use commonware_utils::{array::U32, Array};
use futures::{future::TryFutureExt, pin_mut, try_join, StreamExt};
use tracing::warn;

/// The size of the read buffer to use for replaying the operations log when rebuilding the
/// snapshot. The exact value does not impact performance significantly as long as it is large
/// enough, so we don't make it configurable.
const SNAPSHOT_READ_BUFFER_SIZE: usize = 1 << 16;

/// Configuration for an [Append] only authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator, C> {
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

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: usize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of items to put in each section of the journal.
    pub log_items_per_section: u64,

    /// The name of the [RStorage] partition used for the location map.
    pub locations_map_journal_partition: String,

    /// The number of items to put in each blob in the location map.
    pub locations_map_items_per_blob: u64,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

/// An append-only key-value ADB based on an MMR over its log of operations, supporting
/// authentication of key-value pairs.
pub struct Append<E: RStorage + Clock + Metrics, K: Array, V: Codec, H: CHasher, T: Translator> {
    /// An MMR over digests of the operations applied to the db.
    ///
    /// # Invariant
    ///
    /// The number of leaves in this MMR always equals the number of operations in the unpruned
    /// `log` and `locations_map`.
    mmr: Mmr<E, H>,

    /// A log of all operations applied to the db in order of occurrence. The _location_ of an
    /// operation is its order of occurrence with respect to this log, and corresponds to its leaf
    /// number in the MMR.
    log: VJournal<E, Variable<K, V>>,

    /// The number of operations that have been appended to the log (which must equal the number of
    /// leaves in the MMR).
    log_size: u64,

    /// The number of items to put in each section of the journal.
    log_items_per_section: u64,

    /// A fixed-length journal that maps an operation's location to its offset within its respective
    /// section of the log. (The section number is derived from location.)
    locations_map: FJournal<E, U32>,

    /// A map from each active key to the location of the operation that set its value.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [Variable::Set].
    snapshot: Index<T, u64>,

    /// Cryptographic hasher to re-use within mutable operations requiring digest computation.
    hasher: Standard<H>,
}

impl<E: RStorage + Clock + Metrics, K: Array, V: Codec, H: CHasher, T: Translator>
    Append<E, K, V, H, T>
{
    /// Returns an [Append] adb initialized from `cfg`. Any uncommitted log operations will be
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

        let mut log = VJournal::init(
            context.with_label("log"),
            VConfig {
                partition: cfg.log_journal_partition,
                compression: cfg.log_compression,
                codec_config: cfg.log_codec_config,
                write_buffer: cfg.log_write_buffer,
            },
        )
        .await?;

        let mut locations_map = FJournal::init(
            context.with_label("locations_map"),
            FConfig {
                partition: cfg.locations_map_journal_partition,
                items_per_blob: cfg.locations_map_items_per_blob,
                write_buffer: cfg.log_write_buffer,
                buffer_pool: cfg.buffer_pool.clone(),
            },
        )
        .await?;

        let mut snapshot: Index<T, u64> =
            Index::init(context.with_label("snapshot"), cfg.translator.clone());
        let log_size = Self::build_snapshot_from_log(
            &mut hasher,
            cfg.log_items_per_section,
            &mut mmr,
            &mut log,
            &mut locations_map,
            &mut snapshot,
        )
        .await?;

        let db = Append {
            mmr,
            log,
            log_size,
            locations_map,
            log_items_per_section: cfg.log_items_per_section,
            snapshot,
            hasher,
        };

        Ok(db)
    }

    /// Builds the database's snapshot by replaying the log from inception, while also:
    ///   - trimming any uncommitted operations from the log,
    ///   - adding log operations to the MMR & location map if they are missing,
    ///   - removing any elements from the MMR & location map that don't remain in the log after
    ///     trimming.
    ///
    /// Returns the number of operations in the log.
    ///
    /// # Post-condition
    ///
    /// The number of operations in the log, locations_map, and the number of leaves in the MMR are
    /// equal.
    pub(super) async fn build_snapshot_from_log(
        hasher: &mut Standard<H>,
        log_items_per_section: u64,
        mmr: &mut Mmr<E, H>,
        log: &mut VJournal<E, Variable<K, V>>,
        locations_map: &mut FJournal<E, U32>,
        snapshot: &mut Index<T, u64>,
    ) -> Result<u64, Error> {
        // Align the mmr with the location map. Any elements we remove here that are still in the
        // log will be re-added later.
        let mut mmr_leaves = leaf_pos_to_num(mmr.size()).unwrap();
        let locations_map_size = locations_map.size().await?;
        if locations_map_size > mmr_leaves {
            warn!(
                mmr_leaves,
                locations_map_size, "rewinding misaligned locations map"
            );
            locations_map.rewind(mmr_leaves).await?;
        }
        if mmr_leaves > locations_map_size {
            warn!(mmr_leaves, locations_map_size, "rewinding misaligned mmr");
            mmr.pop((mmr_leaves - locations_map_size) as usize).await?;
        }

        // The number of operations in the log.
        let mut log_size = 0;
        // The size of the log at the last commit point (or 0 if none).
        let mut end_loc = 0;
        // The offset into the log at the end_loc.
        let mut end_offset = 0;
        // A list of uncommitted operations that must be rolled back, in order of their locations.
        let mut uncommitted_ops = Vec::new();

        // Replay the log from inception to build the snapshot, keeping track of any uncommitted
        // operations that must be rolled back, and any log operations that need to be re-added to
        // the MMR & locations_map.
        {
            let stream = log.replay(SNAPSHOT_READ_BUFFER_SIZE).await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Err(e) => {
                        return Err(Error::JournalError(e));
                    }
                    Ok((section, offset, _, op)) => {
                        let loc = log_size; // location of the current operation.
                        log_size += 1;

                        // Consistency check: confirm the provided section matches what we expect from this operation's
                        // index.
                        let expected = loc / log_items_per_section;
                        assert_eq!(section, expected,
                                "section {section} did not match expected session {expected} from location {loc}");

                        if log_size > mmr_leaves {
                            warn!(
                                section,
                                offset, "operation was missing from MMR/location map"
                            );
                            mmr.add(hasher, &op.encode()).await?;
                            locations_map.append(offset.into()).await?;
                            mmr_leaves += 1;
                        }
                        match op {
                            Variable::Set(key, _) => {
                                uncommitted_ops.push((key, loc));
                            }
                            Variable::Commit() => {
                                for (key, loc) in uncommitted_ops.iter() {
                                    Append::<E, K, V, H, T>::set_loc(snapshot, key, *loc).await?;
                                }
                                uncommitted_ops.clear();
                                end_loc = log_size;
                                end_offset = offset;
                            }
                        }
                    }
                }
            }
        }
        if !uncommitted_ops.is_empty() {
            warn!(
                op_count = uncommitted_ops.len(),
                "rewinding over uncommitted operations at end of log"
            );
            let new_last_section = end_loc / log_items_per_section;
            log.rewind_to_offset(new_last_section, end_offset).await?;
            log.sync(new_last_section).await?;
            log_size = end_loc;
        }

        // Pop any MMR elements that are ahead of the last log commit point.
        if mmr_leaves > log_size {
            locations_map.rewind(log_size).await?;

            let op_count = mmr_leaves - log_size;
            warn!(op_count, "popping uncommitted MMR operations");
            mmr.pop(op_count as usize).await?;
        }

        // Confirm post-conditions hold.
        assert_eq!(log_size, leaf_pos_to_num(mmr.size()).unwrap());
        assert_eq!(log_size, locations_map.size().await?);

        Ok(log_size)
    }

    /// Returns the section of the log where we are currently writing new items.
    pub fn current_section(&self) -> u64 {
        self.log_size / self.log_items_per_section
    }

    /// Set the index of `key` in the snapshot. Assumes the key has not already been previously set
    /// and does not check for duplicates.
    async fn set_loc(snapshot: &mut Index<T, u64>, key: &K, index: u64) -> Result<(), Error> {
        // If the translated key is not in the snapshot, insert its location.
        let Some(mut cursor) = snapshot.get_mut_or_insert(key, index) else {
            return Ok(());
        };

        // Translated key is already in the snapshot (key conflict). Add the location to the cursor.
        cursor.next();
        cursor.insert(index);

        Ok(())
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

    /// Get the value of the operation with location `loc` in the db if it matches `key`. The
    /// location is assumed valid and this function panics otherwise.
    pub async fn get_from_loc(&self, key: &K, loc: u64) -> Result<Option<V>, Error> {
        match self.locations_map.read(loc).await {
            Ok(offset) => {
                return self.get_from_offset(key, loc, offset.to_u32()).await;
            }
            Err(e) => Err(Error::JournalError(e)),
        }
    }

    /// Get the value of the operation with location `loc` and offset `offset` in the log if it
    /// matches `key`. The location is assumed valid and this function panics otherwise.
    async fn get_from_offset(&self, key: &K, loc: u64, offset: u32) -> Result<Option<V>, Error> {
        let section = loc / self.log_items_per_section;
        let Some(Variable::Set(k, v)) = self.log.get(section, offset).await? else {
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

    /// Return the oldest location that remains readable & provable.
    pub fn oldest_retained_loc(&self) -> Option<u64> {
        self.mmr
            .oldest_retained_pos()
            .map(|pos| leaf_pos_to_num(pos).unwrap())
    }

    /// Sets `key` to have value `value`, assuming `key` hasn't already been assigned. The operation
    /// is reflected in the snapshot, but will be subject to rollback until the next successful
    /// `commit`. Attempting to set an already-set key results in undefined behavior.
    pub async fn set(&mut self, key: K, value: V) -> Result<(), Error> {
        let loc = self.log_size;
        Append::<E, K, V, H, T>::set_loc(&mut self.snapshot, &key, loc).await?;

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
        self.mmr.add_batched(&mut self.hasher, &op.encode()).await?;

        let section = self.current_section();
        self.log_size += 1;
        let new_section = self.current_section();
        let (offset, _) = self.log.append(section, op).await?;
        self.locations_map.append(offset.into()).await?;
        if section != new_section {
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
        max_ops: u64,
    ) -> Result<(Proof<H::Digest>, Vec<Variable<K, V>>), Error> {
        self.historical_proof(self.op_count(), start_index, max_ops)
            .await
    }

    /// Analogous to proof but with respect to the state of the MMR when it had `size` elements.
    pub async fn historical_proof(
        &self,
        size: u64,
        start_index: u64,
        max_ops: u64,
    ) -> Result<(Proof<H::Digest>, Vec<Variable<K, V>>), Error> {
        let start_pos = leaf_num_to_pos(start_index);
        let end_index = std::cmp::min(size - 1, start_index + max_ops - 1);
        let end_pos = leaf_num_to_pos(end_index);
        let mmr_size = leaf_num_to_pos(size);

        let proof = self
            .mmr
            .historical_range_proof(mmr_size, start_pos, end_pos)
            .await?;
        let mut ops = Vec::with_capacity((end_index - start_index + 1) as usize);
        for index in start_index..=end_index {
            let section = index / self.log_items_per_section;
            let offset = self.locations_map.read(index).await?.to_u32();
            let Some(op) = self.log.get(section, offset).await? else {
                panic!("no log item at index {index}");
            };
            ops.push(op);
        }

        Ok((proof, ops))
    }

    /// Return true if the given sequence of `ops` were applied starting at the operation with
    /// insertion order `start_loc` in the database with the provided root.
    pub fn verify_proof(
        hasher: &mut Standard<H>,
        proof: &Proof<H::Digest>,
        start_loc: u64,
        ops: &[Variable<K, V>],
        root_digest: &H::Digest,
    ) -> bool {
        let start_pos = leaf_num_to_pos(start_loc);

        let elements = ops.iter().map(|op| op.encode()).collect::<Vec<_>>();

        proof.verify_range_inclusion(hasher, &elements, start_pos, root_digest)
    }

    /// Commit any pending operations to the db, ensuring they are persisted to disk & recoverable
    /// upon return from this function. Batch operations will be parallelized if a thread pool
    /// is provided.
    pub async fn commit(&mut self) -> Result<(), Error> {
        self.apply_op(Variable::Commit()).await?;
        self.sync().await
    }

    /// Sync the db to disk ensuring the current state is persisted. Batch operations will be
    /// parallelized if a thread pool is provided.
    pub(super) async fn sync(&mut self) -> Result<(), Error> {
        let section = self.current_section();
        try_join!(
            self.mmr.sync(&mut self.hasher).map_err(Error::MmrError),
            self.log.sync(section).map_err(Error::JournalError),
            self.locations_map.sync().map_err(Error::JournalError),
        )?;

        Ok(())
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(mut self) -> Result<(), Error> {
        try_join!(
            self.log.close().map_err(Error::JournalError),
            self.mmr.close(&mut self.hasher).map_err(Error::MmrError),
            self.locations_map.close().map_err(Error::JournalError),
        )?;

        Ok(())
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        try_join!(
            self.log.destroy().map_err(Error::JournalError),
            self.mmr.destroy().map_err(Error::MmrError),
            self.locations_map.destroy().map_err(Error::JournalError),
        )?;

        Ok(())
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{mmr::mem::Mmr as MemMmr, translator::TwoCap};
    use commonware_cryptography::{hash, sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{self},
        Runner as _,
    };

    const PAGE_SIZE: usize = 77;
    const PAGE_CACHE_SIZE: usize = 9;

    fn db_config(suffix: &str) -> Config<TwoCap, (commonware_codec::RangeCfg, ())> {
        Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: 11,
            mmr_write_buffer: 1024,
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_section: 5,
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_write_buffer: 1024,
            locations_map_journal_partition: format!("locations_map_journal_{suffix}"),
            locations_map_items_per_blob: 7,
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// A type alias for the concrete [Any] type used in these unit tests.
    type AppendTest = Append<deterministic::Context, Digest, Vec<u8>, Sha256, TwoCap>;

    /// Return an [Append] database initialized with a fixed config.
    async fn open_db(context: deterministic::Context) -> AppendTest {
        AppendTest::init(context, db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    pub fn test_append_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.clone()).await;
            let mut hasher = Standard::<Sha256>::new();
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.oldest_retained_loc(), None);
            assert_eq!(db.root(&mut hasher), MemMmr::default().root(&mut hasher));

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
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 1); // commit op added
            let root = db.root(&mut hasher);
            db.close().await.unwrap();

            let db = open_db(context.clone()).await;
            assert_eq!(db.root(&mut hasher), root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_append_db_build_basic() {
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
            db.commit().await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get(&k2).await.unwrap().is_none());
            assert_eq!(db.op_count(), 2);
            // Set the second key.
            db.set(k2, v2.clone()).await.unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);
            assert_eq!(db.op_count(), 3);
            // Commit the second key.
            db.commit().await.unwrap();
            assert_eq!(db.op_count(), 4);

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

            // Cleanup.
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_append_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        // Build a db with `ELEMENTS` key/value pairs and prove ranges over them.
        const ELEMENTS: u64 = 2_000;
        executor.start(|context| async move {
            let mut hasher = Standard::<Sha256>::new();
            let mut db = open_db(context.clone()).await;

            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                db.set(k, v).await.unwrap();
            }

            assert_eq!(db.op_count(), ELEMENTS);

            db.commit().await.unwrap();
            assert_eq!(db.op_count(), ELEMENTS + 1);

            // Close & reopen the db, making sure the re-opened db has exactly the same state.
            let root = db.root(&mut hasher);
            db.close().await.unwrap();
            let db = open_db(context.clone()).await;
            assert_eq!(root, db.root(&mut hasher));
            assert_eq!(db.op_count(), ELEMENTS + 1);
            for i in 0u64..ELEMENTS {
                let k = hash(&i.to_be_bytes());
                let v = vec![i as u8; 100];
                assert_eq!(db.get(&k).await.unwrap().unwrap(), v);
            }

            // Make sure all ranges of 5 operations are provable, including truncated ranges at the
            // end.
            let max_ops = 5;
            for i in 0..db.op_count() {
                let (proof, log) = db.proof(i, max_ops).await.unwrap();
                assert!(AppendTest::verify_proof(
                    &mut hasher,
                    &proof,
                    i,
                    &log,
                    &root
                ));
            }

            db.destroy().await.unwrap();
        });
    }
}
