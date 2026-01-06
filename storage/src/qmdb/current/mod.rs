//! A _Current_ authenticated database provides succinct proofs of _any_ value ever associated with
//! a key, and also whether that value is the _current_ value associated with it. The
//! implementations are based on a [crate::qmdb::any] authenticated database combined with an
//! authenticated [CleanBitMap] over the activity status of each operation.
//! The two structures are "grafted" together to minimize proof sizes.

use crate::{
    bitmap::{CleanBitMap, DirtyBitMap},
    mmr::{
        grafting::{Hasher as GraftingHasher, Storage as GraftingStorage},
        hasher::Hasher,
        journaled::Mmr,
        mem::Clean,
        StandardHasher,
    },
    qmdb::{any::FixedConfig as AConfig, Error},
    translator::Translator,
};
use commonware_cryptography::{DigestOf, Hasher as CHasher};
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage as RStorage};
use std::num::{NonZeroU64, NonZeroUsize};

pub mod ordered;
pub mod proof;
pub mod unordered;

/// Configuration for a `Current` authenticated db with fixed-size values.
#[derive(Clone)]
pub struct FixedConfig<T: Translator> {
    /// The name of the storage partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the storage partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the storage partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// The name of the storage partition used for the bitmap metadata.
    pub bitmap_metadata_partition: String,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

impl<T: Translator> FixedConfig<T> {
    /// Convert this config to an [AConfig] used to initialize the authenticated log.
    pub fn to_any_config(self) -> AConfig<T> {
        AConfig {
            mmr_journal_partition: self.mmr_journal_partition,
            mmr_metadata_partition: self.mmr_metadata_partition,
            mmr_items_per_blob: self.mmr_items_per_blob,
            mmr_write_buffer: self.mmr_write_buffer,
            log_journal_partition: self.log_journal_partition,
            log_items_per_blob: self.log_items_per_blob,
            log_write_buffer: self.log_write_buffer,
            translator: self.translator,
            thread_pool: self.thread_pool,
            buffer_pool: self.buffer_pool,
        }
    }
}

/// Return the root of the current QMDB represented by the provided mmr and bitmap.
async fn root<E: RStorage + Clock + Metrics, H: CHasher, const N: usize>(
    hasher: &mut StandardHasher<H>,
    height: u32,
    status: &CleanBitMap<H::Digest, N>,
    mmr: &Mmr<E, H::Digest, Clean<DigestOf<H>>>,
) -> Result<H::Digest, Error> {
    let grafted_mmr = GraftingStorage::<'_, H, _, _>::new(status, mmr, height);
    let mmr_root = grafted_mmr.root(hasher).await?;

    // If we are on a chunk boundary, then the mmr_root fully captures the state of the DB.
    let (last_chunk, next_bit) = status.last_chunk();
    if next_bit == CleanBitMap::<H::Digest, N>::CHUNK_SIZE_BITS {
        // Last chunk is complete, no partial chunk to add
        return Ok(mmr_root);
    }

    // There are bits in an uncommitted (partial) chunk, so we need to incorporate that information
    // into the root digest to fully capture the database state. We do so by hashing the mmr root
    // along with the number of bits within the last chunk and the digest of the last chunk.
    hasher.inner().update(last_chunk);
    let last_chunk_digest = hasher.inner().finalize();

    Ok(CleanBitMap::<H::Digest, N>::partial_chunk_root(
        hasher.inner(),
        &mmr_root,
        next_bit,
        &last_chunk_digest,
    ))
}

/// Consumes a `DirtyBitMap`, performs merkleization using the provided hasher and MMR storage,
/// and returns a `CleanBitMap` containing the merkleized result.
///
/// # Arguments
/// * `hasher` - The hasher used for merkleization.
/// * `status` - The `DirtyBitMap` to be merkleized. Ownership is taken.
/// * `mmr` - The MMR storage used for grafting.
/// * `grafting_height` - The height at which grafting occurs.
async fn merkleize_grafted_bitmap<H, const N: usize>(
    hasher: &mut StandardHasher<H>,
    status: DirtyBitMap<H::Digest, N>,
    mmr: &impl crate::mmr::storage::Storage<H::Digest>,
    grafting_height: u32,
) -> Result<CleanBitMap<H::Digest, N>, Error>
where
    H: CHasher,
{
    let mut grafter = GraftingHasher::new(hasher, grafting_height);
    grafter
        .load_grafted_digests(&status.dirty_chunks(), mmr)
        .await?;
    status.merkleize(&mut grafter).await.map_err(Into::into)
}
