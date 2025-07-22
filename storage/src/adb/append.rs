//! An authenticated database (ADB) that only supports adding new keyed values (no updates or
//! deletions), where values can have varying sizes.

use crate::{
    adb::{operation::Variable, Error},
    index::Index,
    journal::variable::{Config as JConfig, Journal},
    mmr::{
        hasher::Standard,
        iterator::{leaf_num_to_pos, leaf_pos_to_num},
        journaled::{Config as MmrConfig, Mmr},
        verification::Proof,
    },
    translator::Translator,
};
use commonware_codec::Encode as _;
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage, ThreadPool};
use commonware_utils::Array;
use futures::{future::TryFutureExt, pin_mut, try_join, StreamExt};
use tracing::warn;

/// Where an operation is written in the operation log.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct Location {
    section: u64,
    offset: u32,
    insertion_order: u64,
}

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

    /// The codec configuration to use for encoding and decoding items.
    pub log_codec_config: C,

    /// The max number of items to put in each section of the journal.
    pub log_items_per_section: u64,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

/// A key-value ADB based on an MMR over its log of operations, supporting authentication of any
/// value ever associated with a key.
pub struct Append<E: RStorage + Clock + Metrics, K: Array, V: Codec, H: CHasher, T: Translator> {
    /// An MMR over digests of the operations applied to the db.
    ///
    /// # Invariant
    ///
    /// The number of leaves in this MMR always equals the number of operations in the unpruned
    /// `log`.
    mmr: Mmr<E, H>,

    /// A (pruned) log of all operations applied to the db in order of occurrence. The [Location] of
    /// an operation specifies where it it is written in the log, providing a stable identifier.
    ///
    /// # Invariant
    ///
    /// An operation's location is always equal to the number of the MMR leaf storing the digest of
    /// the operation.
    log: Journal<E, Variable<K, V>>,

    /// The number of operations currently written to the log (irrespective of pruning).
    log_size: u64,

    /// The max number of items to put in each section of the journal.
    log_items_per_section: u64,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location of the operation that added the key.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [Variable::Set].
    snapshot: Index<T, Location>,

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

        let mut log = Journal::init(
            context.with_label("log"),
            JConfig {
                partition: cfg.log_journal_partition,
                compression: cfg.log_compression,
                codec_config: cfg.log_codec_config,
                write_buffer: cfg.log_write_buffer,
            },
        )
        .await?;

        let mut snapshot: Index<T, Location> =
            Index::init(context.with_label("snapshot"), cfg.translator.clone());
        let log_size =
            Self::build_snapshot_from_log(&mut hasher, &mut mmr, &mut log, &mut snapshot).await?;

        let db = Append {
            mmr,
            log,
            log_size,
            log_items_per_section: cfg.log_items_per_section,
            snapshot,
            hasher,
        };

        Ok(db)
    }

    /// Builds the database's snapshot by replaying the log from inception, while also:
    /// (1) trimming any uncommitted operations from the log,
    /// (2) adding log operations to the MMR if they are missing,
    /// (3) removing any elements from the MMR that don't remain in the log after trimming.
    ///
    /// # Post-condition
    ///
    /// The number of operations in the log and the number of leaves in the MMR are equal.
    pub(super) async fn build_snapshot_from_log(
        hasher: &mut Standard<H>,
        mmr: &mut Mmr<E, H>,
        log: &mut Journal<E, Variable<K, V>>,
        snapshot: &mut Index<T, Location>,
    ) -> Result<u64, Error> {
        let mut uncommitted_ops = Vec::new();
        let mut log_size = 0;
        let mut mmr_leaves = leaf_pos_to_num(mmr.size()).unwrap();
        let mut start_loc = Location {
            section: 0,
            offset: 0,
            insertion_order: 0,
        };
        {
            let stream = log.replay(SNAPSHOT_READ_BUFFER_SIZE).await?;
            pin_mut!(stream);
            while let Some(result) = stream.next().await {
                match result {
                    Err(e) => {
                        return Err(Error::JournalError(e));
                    }
                    Ok((section, offset, size, op)) => {
                        log_size += 1;
                        if log_size > mmr_leaves {
                            warn!(section, offset, "operation was missing from MMR");
                            mmr.add(hasher, &op.encode()).await?;
                            mmr_leaves += 1;
                        }
                        match op {
                            Variable::Set(key, _) => {
                                uncommitted_ops.push((
                                    key,
                                    Location {
                                        section,
                                        offset,
                                        insertion_order: log_size - 1,
                                    },
                                ));
                            }
                            Variable::Commit() => {
                                for (key, loc) in uncommitted_ops.iter() {
                                    Append::<E, K, V, H, T>::set_loc(snapshot, key, *loc).await?;
                                }
                                uncommitted_ops.clear();
                                start_loc.section = section;
                                start_loc.offset = offset + size;
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
            log_size -= uncommitted_ops.len() as u64;
            log.rewind(start_loc.section, start_loc.offset as u64)
                .await?;
            log.sync(start_loc.section).await?;
        }

        // Pop any MMR elements that are ahead of the last log commit point.
        if mmr_leaves > log_size {
            let op_count = mmr_leaves - log_size;
            warn!(op_count, "popping uncommitted MMR operations");
            mmr.pop(op_count as usize).await?;
        }

        // Confirm post-condition holds.
        assert_eq!(log_size, leaf_pos_to_num(mmr.size()).unwrap());

        Ok(log_size)
    }

    /// Returns the section of the log where we are currently writing new items.
    pub fn current_section(&self) -> u64 {
        self.log_size / self.log_items_per_section
    }

    /// Set the location of `key` to `loc` in the snapshot. Assumes the key has not already been
    /// previously set and does not check for duplicates.
    async fn set_loc(
        snapshot: &mut Index<T, Location>,
        key: &K,
        loc: Location,
    ) -> Result<(), Error> {
        // If the translated key is not in the snapshot, insert its location.
        let Some(mut cursor) = snapshot.get_mut_or_insert(key, loc) else {
            return Ok(());
        };

        // Translated key is already in the snapshot (key conflict). Add the location to the cursor.
        cursor.insert(loc);

        Ok(())
    }

    /// Get the set operation corresponding to a location from the snapshot.
    ///
    /// # Warning
    ///
    /// Panics if the location does not reference a set operation. This should never happen unless
    /// the snapshot is buggy, or this method is being used to look up an operation independent of
    /// the snapshot contents.
    async fn get_set_op(log: &Journal<E, Variable<K, V>>, loc: Location) -> Result<(K, V), Error> {
        let Some(Variable::Set(k, v)) = log.get(loc.section, loc.offset).await? else {
            panic!("location does not reference set operation. loc={loc:?}");
        };

        Ok((k, v))
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        Ok(self.get_with_loc(key).await?.map(|(v, _)| v))
    }

    /// Get the value & location of the active operation for `key` in the db, or None if it has no
    /// value.
    pub(super) async fn get_with_loc(&self, key: &K) -> Result<Option<(V, Location)>, Error> {
        for &loc in self.snapshot.get(key) {
            let (k, v) = Self::get_set_op(&self.log, loc).await?;
            if k == *key {
                return Ok(Some((v, loc)));
            }
        }

        Ok(None)
    }

    /// Get the number of operations that have been applied to this db, including those that are not
    /// yet committed.
    pub fn op_count(&self) -> u64 {
        leaf_pos_to_num(self.mmr.size()).unwrap()
    }

    /// Return the oldest location that remains readable & provable.
    pub fn oldest_retained_loc(&self) -> Option<u64> {
        self.mmr
            .oldest_retained_pos()
            .map(|pos| leaf_pos_to_num(pos).unwrap())
    }

    /// Sets `key` to have value `value`, assuming `key` hasn't already been assigned. The operation
    /// is reflected in the snapshot, but will be subject to rollback until the next successful
    /// `commit`. Attempting to set an already-set key has undefined behavior.
    pub async fn set(&mut self, key: &K, value: V) -> Result<(), Error> {
        let op = Variable::Set(key.clone(), value);
        let loc = self.apply_op(op).await?;

        Append::<E, K, V, H, T>::set_loc(&mut self.snapshot, key, loc).await
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
    pub(super) async fn apply_op(&mut self, op: Variable<K, V>) -> Result<Location, Error> {
        self.mmr.add_batched(&mut self.hasher, &op.encode()).await?;

        let old_section = self.current_section();
        self.log_size += 1;
        let new_section = self.current_section();
        if old_section != new_section {
            self.log.sync(old_section).await?;
        }

        let (offset, _) = self.log.append(new_section, op).await?;

        Ok(Location {
            section: new_section,
            offset,
            insertion_order: self.log_size - 1,
        })
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
        max_ops: u64,
    ) -> Result<(Proof<H::Digest>, Vec<Variable<K, V>>), Error> {
        self.historical_proof(self.op_count(), start_loc, max_ops)
            .await
    }

    /// Analogous to proof but for a previous database state.
    /// Specifically, the state when the MMR had `size` elements.
    pub async fn historical_proof(
        &self,
        size: u64,
        start_loc: Location,
        max_ops: u64,
    ) -> Result<(Proof<H::Digest>, Vec<Variable<K, V>>), Error> {
        let mut fetched = 0;
        let mut loc = start_loc;
        let start_pos = loc.insertion_order;
        let mmr_size = leaf_num_to_pos(size);

        let mut ops = Vec::with_capacity(max_ops as usize);
        while fetched < max_ops {
            let Some((op, next_offset)) = self.log.get_with_next(loc.section, loc.offset).await?
            else {
                break;
            };

            fetched += 1;
            ops.push(op);

            loc.insertion_order += 1;
            if loc.insertion_order >= self.log_size {
                break;
            }

            if let Some(next_offset) = next_offset {
                loc.offset = next_offset;
            } else {
                loc.offset = 0;
                loc.section += 1;
            }
        }
        let end_pos = loc.insertion_order - 1;

        let proof = self
            .mmr
            .historical_range_proof(mmr_size, start_pos, end_pos)
            .await?;

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
        self.sync().await
    }

    /// Sync the db to disk ensuring the current state is persisted. Batch operations will be
    /// parallelized if a thread pool is provided.
    pub(super) async fn sync(&mut self) -> Result<(), Error> {
        let section = self.current_section();
        try_join!(
            self.mmr.sync(&mut self.hasher).map_err(Error::MmrError),
            self.log.sync(section).map_err(Error::JournalError),
        )?;

        Ok(())
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(mut self) -> Result<(), Error> {
        try_join!(
            self.log.close().map_err(Error::JournalError),
            self.mmr.close(&mut self.hasher).map_err(Error::MmrError),
        )?;

        Ok(())
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await?;
        self.mmr.destroy().await?;

        Ok(())
    }
}
