//! The [Keyless] adb allows for append-only storage of arbitrary data that can later be retrieved
//! by its location.

use crate::{
    adb::Error,
    journal::{
        fixed::{Config as FConfig, Journal as FJournal},
        variable::{Config as VConfig, Journal as VJournal},
    },
    mmr::{
        hasher::Standard,
        iterator::leaf_num_to_pos,
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

    /// The name of the [Storage] partition used to persist the (pruned) values.
    pub values_journal_partition: String,

    /// The size of the write buffer to use with the values journal.
    pub values_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to values data before storing.
    pub values_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding values.
    pub values_codec_config: C,

    /// The max number of values to put in each section of the values journal.
    ///
    /// Unlike the other variable-type stores, the actual number of values could be less than this
    /// amount even if the section is "full", since we don't explicitly insert anything into the
    /// section for commits.
    pub values_items_per_section: NonZeroU64,

    /// The name of the [Storage] partition used for the location map.
    pub locations_journal_partition: String,

    /// The number of items to put in each blob in the location map.
    pub locations_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use with the locations journal.
    pub locations_write_buffer: NonZeroUsize,

    /// An optional thread pool to use for parallelizing batch operations.
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
    /// `log`.
    mmr: Mmr<E, H>,

    /// A (pruned) journal of all values ever appended to the db.
    values: VJournal<E, V>,

    /// The total number of values appended (including those that have been pruned).  The next
    /// appended item will have this value as its location.
    size: u64,

    /// The number of values to put in each section of the values journal.
    values_per_section: u64,

    /// A fixed-length journal that maps an appended value's location to its offset within its
    /// respective section of the values journal. (The section number is derived from location.)
    locations: FJournal<E, Operation>,

    /// Cryptographic hasher to re-use within mutable operations requiring digest computation.
    hasher: Standard<H>,
}

impl<E: Storage + Clock + Metrics, V: Codec, H: CHasher> Keyless<E, V, H> {
    /// Returns a [Keyless] adb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
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

        let values = VJournal::<E, V>::init(
            context.with_label("values"),
            VConfig {
                partition: cfg.values_journal_partition,
                compression: cfg.values_compression,
                codec_config: cfg.values_codec_config,
                buffer_pool: cfg.buffer_pool.clone(),
                write_buffer: cfg.values_write_buffer,
            },
        )
        .await?;

        let mut locations = FJournal::init(
            context.with_label("locations"),
            FConfig {
                partition: cfg.locations_journal_partition,
                items_per_blob: cfg.locations_items_per_blob,
                write_buffer: cfg.locations_write_buffer,
                buffer_pool: cfg.buffer_pool,
            },
        )
        .await?;

        // Align the size of the locations journal with the MMR.
        let mut locations_size = locations.size().await?;
        let mmr_leaves = leaf_num_to_pos(mmr.size());
        if locations_size > mmr_leaves {
            warn!(
                mmr_leaves,
                locations_size, "rewinding misaligned locations map"
            );
            locations.rewind(mmr_leaves).await?;
            locations_size = mmr_leaves;
        } else if mmr_leaves > locations_size {
            warn!(mmr_leaves, locations_size, "rewinding misaligned mmr");
            mmr.pop((mmr_leaves - locations_size) as usize).await?;
        }

        // Rewind to the last commit point if necessary.
        let mut op_index = locations_size;
        while op_index > 0 {
            op_index -= 1;
            let op = locations.read(op_index).await?;
            if let Operation::Commit = op {
                if op_index != locations_size - 1 {
                    warn!(
                        old_size = locations_size,
                        new_size = op_index + 1,
                        "rewinding to last commit point"
                    );
                    locations.rewind(op_index + 1).await?;
                    mmr.pop((locations_size - op_index - 1) as usize).await?;
                    locations_size = op_index + 1;
                    // Note that we don't touch any data in the values journal during recovery. Instead, we'll
                    // overwrite any rolled-back data as new items get appended.
                }
                break;
            }
        }

        Ok(Self {
            mmr,
            values,
            size: locations_size,
            locations,
            values_per_section: cfg.values_items_per_section.get(),
            hasher,
        })
    }

    /// Get the value at location `loc` in the database. Returns None if the location is valid but
    /// does not correspond to an append.
    pub async fn get(&self, loc: u64) -> Result<Option<V>, Error> {
        match self.locations.read(loc).await {
            Ok(op) => {
                if let Operation::Append(offset) = op {
                    let section = loc / self.values_per_section;
                    let Some(v) = self.values.get(section, offset).await? else {
                        panic!("didn't find value at location {loc} and offset {offset}");
                    };
                    Ok(Some(v))
                } else {
                    Ok(None)
                }
            }
            Err(e) => Err(Error::Journal(e)),
        }
    }

    /// Get the number of appends + commits that have been applied to the db.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the section of the values journal where we are currently writing new items.
    fn current_section(&self) -> u64 {
        self.size / self.values_per_section
    }

    /// Return the oldest location that remains retrievable.
    pub async fn oldest_retained_loc(&self) -> Result<Option<u64>, Error> {
        self.locations
            .oldest_retained_pos()
            .await
            .map_err(Error::Journal)
    }

    /// Append a value to the db, returning its location which can be used to retrieve it.
    pub async fn append(&mut self, value: V) -> Result<u64, Error> {
        let loc = self.size;
        let section = self.current_section();
        let (offset, _) = self.values.append(section, value).await?;
        self.locations.append(Operation::Append(offset)).await?;
        self.mmr
            .add_batched(&mut self.hasher, &Operation::Append(offset).encode())
            .await?;

        self.size += 1;
        if section != self.current_section() {
            self.values.sync(section).await?;
        }

        Ok(loc)
    }

    /// Commit the current state of the db.
    ///
    /// TODO: Does commit really need to be an operation (and part of the authenticated structure)
    /// or can we just store the last-committed operation in metadata for recovery purposes only?
    pub async fn commit(&mut self) -> Result<(), Error> {
        self.mmr
            .add_batched(&mut self.hasher, &Operation::Commit.encode())
            .await?;
        self.locations.append(Operation::Commit).await?;
        self.size += 1;

        self.sync().await
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
    ) -> Result<(Proof<H::Digest>, Vec<Operation>), Error> {
        self.historical_proof(self.size, start_loc, max_ops).await
    }

    /// Analogous to proof, but with respect to the state of the MMR when it had `size` elements.
    pub async fn historical_proof(
        &self,
        size: u64,
        start_loc: u64,
        max_ops: u64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation>), Error> {
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
            ops.push(self.locations.read(loc).await?);
        }

        Ok((proof, ops))
    }

    /// Sync the db to disk ensuring the current state is persisted. Batch operations will be
    /// parallelized if a thread pool is provided.
    pub(super) async fn sync(&mut self) -> Result<(), Error> {
        // Always sync the values journal first, to ensure that the locations journal is always in a
        // state where it's referencing a valid offset to simplify recovery. In the event of a crash
        // and rollback is required, we do not need to roll back any data in the values journal,
        // instead we'll just overwrite it as appropriate.
        let section = self.current_section();
        self.values.sync(section).await?;

        try_join!(
            self.mmr.sync(&mut self.hasher).map_err(Error::Mmr),
            self.locations.sync().map_err(Error::Journal),
        )?;

        Ok(())
    }

    /// Close the db. Operations that have not been committed will be lost.
    pub async fn close(mut self) -> Result<(), Error> {
        // Close the locations journal first to make sure it's synced first (see `sync` for why this
        // is important).
        self.locations.close().await?;

        try_join!(
            self.mmr.close(&mut self.hasher).map_err(Error::Mmr),
            self.values.close().map_err(Error::Journal),
        )?;

        Ok(())
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        try_join!(
            self.mmr.destroy().map_err(Error::Mmr),
            self.values.destroy().map_err(Error::Journal),
            self.locations.destroy().map_err(Error::Journal),
        )?;

        Ok(())
    }
}
