//! A _Current_ authenticated database provides succinct proofs of _any_ value ever associated with
//! a key, and also whether that value is the _current_ value associated with it.
//!
//! # Examples
//!
//! ```ignore
//! // Simple mode: apply a batch, then durably commit it.
//! let merkleized = db.new_batch()
//!     .write(key, Some(value))
//!     .merkleize(None).await?;
//! let finalized = merkleized.finalize();
//! db.apply_batch(finalized).await?;
//! db.commit().await?;
//!
//! // Use `sync()` instead of `commit()` if you want the stronger durability
//! // boundary for all database state.
//! db.sync().await?;
//! ```
//!
//! ```ignore
//! // Batches can still fork before you apply them.
//! let parent = db.new_batch()
//!     .write(key_a, Some(val_a))
//!     .merkleize(None).await?;
//!
//! let child_a = parent.new_batch()
//!     .write(key_b, Some(val_b))
//!     .merkleize(None).await?;
//!
//! let child_b = parent.new_batch()
//!     .write(key_c, Some(val_c))
//!     .merkleize(None).await?;
//!
//! // Only one fork can be applied; the others become stale.
//! db.apply_batch(child_a.finalize()).await?;
//! db.commit().await?;
//! ```
//!
//! ```ignore
//! // Advanced usage: while the previous batch is being committed, concurrently build a child
//! // batch from the newly published state.
//! let parent_finalized = db.new_batch()
//!     .write(key_a, Some(val_a))
//!     .merkleize(None).await?.finalize();
//! db.apply_batch(parent_finalized).await?;
//!
//! let (child_finalized, commit_result) = futures::join!(
//!     async {
//!         db.new_batch()
//!             .write(key_b, Some(val_b))
//!             .merkleize(None).await.map(|batch| batch.finalize())
//!     },
//!     db.commit(),
//! );
//! let child_finalized = child_finalized?;
//! commit_result?;
//!
//! db.apply_batch(child_finalized).await?;
//! db.commit().await?;
//! ```
//!
//! # Motivation
//!
//! An [crate::qmdb::any] ("Any") database can prove that a key had a particular value at some
//! point, but it cannot prove that the value is still current -- some later operation may have
//! updated or deleted it. A Current database adds exactly this capability by maintaining a bitmap
//! that tracks which operations are _active_ (i.e. represent the current state of their key).
//!
//! To make this useful, a verifier needs both the operation and its activity status authenticated
//! under a single root. We achieve this by _grafting_ bitmap chunks onto the operations MMR.
//!
//! # Data structures
//!
//! A Current database ([db::Db]) wraps an Any database and adds:
//!
//! - **Status bitmap** ([BitMap]): One bit per operation in the log. Bit _i_ is 1 if
//!   operation _i_ is active, 0 otherwise. The bitmap is divided into fixed-size chunks of `N`
//!   bytes (i.e. `N * 8` bits each). `N` must be a power of two.
//!
//! - **Grafted MMR** (`Mmr<Digest>`): An in-memory MMR of digests at and above the
//!   _grafting height_ in the ops MMR. This is the core of how bitmap and ops MMR are combined
//!   into a single authenticated structure (see below).
//!
//! - **Bitmap metadata** (`Metadata`): Persists the pruning boundary and "pinned" digests needed
//!   to restore the grafted MMR after pruning old bitmap chunks.
//!
//! # Grafting: combining the activity status bitmap and the ops MMR
//!
//! ## The problem
//!
//! Naively authenticating the bitmap and ops MMR as two independent Merkle structures would
//! require two separate proofs per operation -- one for the operation's value, one for its
//! activity status. This doubles proof sizes.
//!
//! ## The solution
//!
//! We combine ("graft") the two structures at a specific height in the ops MMR called the
//! _grafting height_. The grafting height `h = log2(N * 8)` is chosen so that each subtree of
//! height `h` in the ops MMR covers exactly one bitmap chunk's worth of operations.
//!
//! At the grafting height, instead of using the ops MMR's own subtree root, we replace it with a
//! _grafted leaf_ digest that incorporates both the bitmap chunk and the ops subtree root:
//!
//! ```text
//! grafted_leaf = hash(bitmap_chunk || ops_subtree_root)   // non-zero chunk
//! grafted_leaf = ops_subtree_root                         // all-zero chunk (identity)
//! ```
//!
//! The all-zero identity means that for pruned regions (where every operation is inactive), the
//! grafted MMR is structurally identical to the ops MMR at and above the grafting height.
//!
//! Above the grafting height, internal nodes use standard MMR hashing over the grafted leaves.
//! Below the grafting height, the ops MMR is unchanged.
//!
//! ## Example
//!
//! Consider 8 operations with `N = 1` (8-bit chunks, so `h = log2(8) = 3`). But to illustrate
//! the structure more clearly, let's use a smaller example: 8 operations with chunk size 4 bits
//! (`h = 2`), yielding 2 complete bitmap chunks:
//!
//! ```text
//! Ops MMR positions (8 leaves):
//!
//!   Height
//!     3              14                    <-- peak: digest commits to ops MMR and bitmap chunks
//!                  /    \
//!                 /      \
//!                /        \
//!     2  [G]    6          13    [G]       <-- grafting height: grafted leaves
//!             /   \      /    \
//!     1      2     5    9     12           <-- below grafting height: pure ops MMR nodes
//!           / \   / \  / \   /  \
//!     0    0   1 3   4 7  8 10  11
//!          ^           ^
//!          |           |
//!      ops 0-3     ops 4-7
//!      chunk 0     chunk 1
//! ```
//!
//! Positions 6 and 13 are at the grafting height. Their digests are:
//! - `pos 6: hash(chunk_0 || ops_subtree_root(pos 6))`
//! - `pos 13: hash(chunk_1 || ops_subtree_root(pos 13))`
//!
//! Position 14 (above grafting height) is a standard MMR internal node:
//! - `pos 14: hash(14 || digest(pos 6) || digest(pos 13))`
//!
//! The grafted MMR stores positions 6, 13, and 14. The ops MMR stores everything below
//! (positions 0-5 and 7-12). Together they form a single virtual MMR whose root authenticates
//! both the operations and their activity status.
//!
//! ## Proof generation and verification
//!
//! To prove that operation _i_ is active, we provide:
//! 1. An MMR inclusion proof for the operation's leaf, using the virtual (grafted) storage.
//! 2. The bitmap chunk containing bit _i_.
//!
//! The verifier (see `grafting::Verifier`) walks the proof from leaf to root. Below the grafting
//! height, it uses standard MMR hashing. At the grafting height, it detects the boundary and
//! reconstructs the grafted leaf from the chunk and the ops subtree root. For non-zero chunks
//! the grafted leaf is `hash(chunk || ops_subtree_root)`; for all-zero chunks the grafted leaf
//! is the ops subtree root itself (identity optimization -- see `grafting::Verifier::node`).
//! Above the grafting height, it resumes standard MMR hashing. If the reconstructed root
//! matches the expected root and bit _i_ is set in the chunk, the operation is proven active.
//!
//! This is a single proof path, not two independent ones -- the bitmap chunk is embedded in the
//! proof verification at the grafting boundary.
//!
//! ## Partial chunks
//!
//! Operations arrive continuously, so the last bitmap chunk is usually incomplete (fewer than
//! `N * 8` bits). An incomplete chunk has no grafted leaf in the cache because there is no
//! corresponding complete subtree in the ops MMR. To still authenticate these bits, the partial
//! chunk's digest and bit count are folded into the canonical root hash:
//!
//! ```text
//! root = hash(ops_root || grafted_mmr_root || next_bit || hash(partial_chunk))
//! ```
//!
//! where `next_bit` is the index of the next unset position in the partial chunk and
//! `grafted_mmr_root` is the root of the grafted MMR (which covers only complete chunks).
//! When all chunks are complete, the partial chunk components are omitted.
//!
//! ## Incremental updates
//!
//! When operations are added or bits change (e.g. an operation becomes inactive during floor
//! raising), only the affected chunks are marked "dirty". During `merkleize`, only dirty grafted
//! leaves are recomputed and their ancestors are propagated upward through the cache. This avoids
//! recomputing the entire grafted tree.
//!
//! ## Pruning
//!
//! Old bitmap chunks (below the inactivity floor) can be pruned. Before pruning, the grafted
//! digest peaks covering the pruned region are persisted to metadata as "pinned nodes". On
//! recovery, these pinned nodes are loaded and serve as opaque siblings during upward propagation,
//! allowing the grafted tree to be rebuilt without the pruned chunks.
//!
//! # Root structure
//!
//! The canonical root of a `current` database is:
//!
//! ```text
//! root = hash(ops_root || grafted_mmr_root [|| next_bit || hash(partial_chunk)])
//! ```
//!
//! where `grafted_mmr_root` is the root of the grafted MMR (covering only complete
//! bitmap chunks), `next_bit` is the index of the next unset position in the partial chunk, and
//! `hash(partial_chunk)` is the digest of the incomplete trailing chunk. The partial chunk
//! components are only present when the last bitmap chunk is incomplete.
//!
//! This combines two (or three) components into a single hash:
//!
//! - **Ops root**: The root of the raw operations MMR (the inner [crate::qmdb::any] database's
//!   root). Used for state sync, where a client downloads operations and verifies each batch
//!   against this root using standard MMR range proofs.
//!
//! - **Grafted MMR root**: The root of the grafted MMR (overlaying bitmap chunks
//!   with ops subtree roots). Used for proofs about operation values and their activity status.
//!   See [RangeProof](proof::RangeProof) and [OperationProof](proof::OperationProof).
//!
//! - **Partial chunk** (optional): When operations arrive continuously, the last bitmap chunk is
//!   usually incomplete. Its digest and bit count are folded into the canonical root hash.
//!
//! The canonical root is returned by [Db](db::Db)`::`[root()](db::Db::root) and
//! [MerkleizedStore](crate::qmdb::store::MerkleizedStore)`::`[root()](crate::qmdb::store::MerkleizedStore::root).
//! The ops root is returned by the `sync::Database` trait's `root()` method, since the sync engine
//! verifies batches against the ops root, not the canonical root.
//!
//! For state sync, the sync engine targets the ops root and verifies each batch against it.
//! After sync, the bitmap and grafted MMR are reconstructed deterministically from the
//! operations, and the canonical root is computed. Validating that the ops root is part of the
//! canonical root is the caller's responsibility; the sync engine does not perform this check.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::contiguous::{fixed::Journal as FJournal, variable::Journal as VJournal},
    mmr::Location,
    qmdb::{
        any::{
            self,
            operation::{Operation, Update},
            FixedConfig as AnyFixedConfig, VariableConfig as AnyVariableConfig,
        },
        operation::{Committable, Key},
        Error,
    },
    translator::Translator,
};
use commonware_codec::{Codec, CodecFixedShared, FixedSize, Read};
use commonware_cryptography::Hasher;
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::paged::CacheRef, Clock, Metrics, Storage};
use commonware_utils::{bitmap::Prunable as BitMap, sync::AsyncMutex, Array};
use std::num::{NonZeroU64, NonZeroUsize};

pub mod batch;
pub mod db;
pub(crate) mod grafting;
pub mod ordered;
pub mod proof;
pub(crate) mod sync;
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

    /// The name of the storage partition used for the grafted MMR metadata.
    pub grafted_mmr_metadata_partition: String,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,
}

impl<T: Translator> From<FixedConfig<T>> for AnyFixedConfig<T> {
    fn from(cfg: FixedConfig<T>) -> Self {
        Self {
            mmr_journal_partition: cfg.mmr_journal_partition,
            mmr_metadata_partition: cfg.mmr_metadata_partition,
            mmr_items_per_blob: cfg.mmr_items_per_blob,
            mmr_write_buffer: cfg.mmr_write_buffer,
            log_journal_partition: cfg.log_journal_partition,
            log_items_per_blob: cfg.log_items_per_blob,
            log_write_buffer: cfg.log_write_buffer,
            translator: cfg.translator,
            thread_pool: cfg.thread_pool,
            page_cache: cfg.page_cache,
        }
    }
}

#[derive(Clone)]
pub struct VariableConfig<T: Translator, C> {
    /// The name of the storage partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the storage partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the storage partition used to persist the log of operations.
    pub log_partition: String,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for the log.
    pub log_codec_config: C,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: NonZeroU64,

    /// The name of the storage partition used for the grafted MMR metadata.
    pub grafted_mmr_metadata_partition: String,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,
}

impl<T: Translator, C> From<VariableConfig<T, C>> for AnyVariableConfig<T, C> {
    fn from(cfg: VariableConfig<T, C>) -> Self {
        Self {
            mmr_journal_partition: cfg.mmr_journal_partition,
            mmr_metadata_partition: cfg.mmr_metadata_partition,
            mmr_items_per_blob: cfg.mmr_items_per_blob,
            mmr_write_buffer: cfg.mmr_write_buffer,
            log_items_per_blob: cfg.log_items_per_blob,
            log_partition: cfg.log_partition,
            log_write_buffer: cfg.log_write_buffer,
            log_compression: cfg.log_compression,
            log_codec_config: cfg.log_codec_config,
            translator: cfg.translator,
            thread_pool: cfg.thread_pool,
            page_cache: cfg.page_cache,
        }
    }
}

/// Shared initialization logic for fixed-sized value Current [db::Db].
pub(super) async fn init_fixed<E, U, H, T, I, const N: usize, NewIndex>(
    context: E,
    config: FixedConfig<T>,
    new_index: NewIndex,
) -> Result<db::Db<E, FJournal<E, Operation<U>>, I, H, U, N>, Error>
where
    E: Storage + Clock + Metrics,
    U: Update + Send + Sync,
    U::Key: Array,
    H: Hasher,
    T: Translator,
    I: UnorderedIndex<Value = Location>,
    NewIndex: FnOnce(E, T) -> I,
    Operation<U>: CodecFixedShared + Committable,
{
    // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
    const {
        // A compile-time assertion that the chunk size is some multiple of digest size. A multiple
        // of 1 is optimal with respect to proof size, but a higher multiple allows for a smaller
        // (RAM resident) merkle tree over the structure.
        assert!(
            N.is_multiple_of(H::Digest::SIZE),
            "chunk size must be some multiple of the digest size",
        );
        // A compile-time assertion that chunk size is a power of 2, which is necessary to allow
        // the status bitmap tree to be aligned with the underlying operations MMR.
        assert!(N.is_power_of_two(), "chunk size must be a power of 2");
    }

    let thread_pool = config.thread_pool.clone();
    let metadata_partition = config.grafted_mmr_metadata_partition.clone();

    // Load bitmap metadata (pruned_chunks + pinned nodes for grafted MMR).
    let (metadata, pruned_chunks, pinned_nodes) =
        db::init_metadata(context.with_label("metadata"), &metadata_partition).await?;

    // Initialize the activity status bitmap.
    let mut status = BitMap::<N>::new_with_pruned_chunks(pruned_chunks)
        .map_err(|_| Error::DataCorrupted("pruned chunks overflow"))?;

    // Initialize the anydb with a callback that populates the status bitmap.
    let last_known_inactivity_floor = Location::new(status.len());
    let any = any::init_fixed(
        context.with_label("any"),
        config.into(),
        Some(last_known_inactivity_floor),
        |append: bool, loc: Option<Location>| {
            status.push(append);
            if let Some(loc) = loc {
                status.set_bit(*loc, false);
            }
        },
        new_index,
    )
    .await?;

    // Build the grafted MMR from the bitmap and ops MMR.
    let grafted_mmr =
        db::build_grafted_mmr::<H, N>(&status, &pinned_nodes, &any.log.mmr, thread_pool.as_ref())
            .await?;

    // Compute and cache the root.
    let storage = grafting::Storage::new(&grafted_mmr, grafting::height::<N>(), &any.log.mmr);
    let partial_chunk = db::partial_chunk(&status);
    let ops_root = any.log.root();
    let root = db::compute_db_root::<H, _, _, N>(&storage, partial_chunk, &ops_root).await?;

    Ok(db::Db {
        any,
        status,
        grafted_mmr,
        metadata: AsyncMutex::new(metadata),
        thread_pool,
        root,
    })
}

/// Shared initialization logic for variable-sized value Current [db::Db].
pub(super) async fn init_variable<E, U, H, T, I, const N: usize, NewIndex>(
    context: E,
    config: VariableConfig<T, <Operation<U> as Read>::Cfg>,
    new_index: NewIndex,
) -> Result<db::Db<E, VJournal<E, Operation<U>>, I, H, U, N>, Error>
where
    E: Storage + Clock + Metrics,
    U: Update + Send + Sync,
    U::Key: Key,
    H: Hasher,
    T: Translator,
    I: UnorderedIndex<Value = Location>,
    NewIndex: FnOnce(E, T) -> I,
    Operation<U>: Codec + Committable,
{
    // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
    const {
        // A compile-time assertion that the chunk size is some multiple of digest size. A multiple
        // of 1 is optimal with respect to proof size, but a higher multiple allows for a smaller
        // (RAM resident) merkle tree over the structure.
        assert!(
            N.is_multiple_of(H::Digest::SIZE),
            "chunk size must be some multiple of the digest size",
        );
        // A compile-time assertion that chunk size is a power of 2, which is necessary to allow
        // the status bitmap tree to be aligned with the underlying operations MMR.
        assert!(N.is_power_of_two(), "chunk size must be a power of 2");
    }

    let metadata_partition = config.grafted_mmr_metadata_partition.clone();
    let pool = config.thread_pool.clone();

    // Load bitmap metadata (pruned_chunks + pinned nodes for grafted MMR).
    let (metadata, pruned_chunks, pinned_nodes) =
        db::init_metadata(context.with_label("metadata"), &metadata_partition).await?;

    // Initialize the activity status bitmap.
    let mut status = BitMap::<N>::new_with_pruned_chunks(pruned_chunks)
        .map_err(|_| Error::DataCorrupted("pruned chunks overflow"))?;

    // Initialize the anydb with a callback that populates the activity status bitmap.
    let last_known_inactivity_floor = Location::new(status.len());
    let any = any::init_variable(
        context.with_label("any"),
        config.into(),
        Some(last_known_inactivity_floor),
        |append: bool, loc: Option<Location>| {
            status.push(append);
            if let Some(loc) = loc {
                status.set_bit(*loc, false);
            }
        },
        new_index,
    )
    .await?;

    // Build the grafted MMR from the bitmap and ops MMR.
    let grafted_mmr =
        db::build_grafted_mmr::<H, N>(&status, &pinned_nodes, &any.log.mmr, pool.as_ref()).await?;

    // Compute and cache the root.
    let storage = grafting::Storage::new(&grafted_mmr, grafting::height::<N>(), &any.log.mmr);
    let partial_chunk = db::partial_chunk(&status);
    let ops_root = any.log.root();
    let root = db::compute_db_root::<H, _, _, N>(&storage, partial_chunk, &ops_root).await?;

    Ok(db::Db {
        any,
        status,
        grafted_mmr,
        metadata: AsyncMutex::new(metadata),
        thread_pool: pool,
        root,
    })
}

/// Extension trait for Current QMDB types that exposes bitmap information for testing.
#[cfg(any(test, feature = "test-traits"))]
pub trait BitmapPrunedBits {
    /// Returns the number of bits that have been pruned from the bitmap.
    fn pruned_bits(&self) -> u64;

    /// Returns the value of the bit at the given index.
    fn get_bit(&self, index: u64) -> bool;

    /// Returns the position of the oldest retained bit.
    fn oldest_retained(&self) -> impl core::future::Future<Output = u64> + Send;
}

#[cfg(test)]
pub mod tests {
    //! Shared test utilities for Current QMDB variants.

    pub use super::BitmapPrunedBits;
    use super::{ordered, unordered, FixedConfig, VariableConfig};
    use crate::{
        qmdb::{
            any::traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
            store::{
                tests::{TestKey, TestValue},
                LogStore,
            },
            Error,
        },
        translator::Translator,
    };
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        BufferPooler, Metrics as _, Runner as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use core::future::Future;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::num::{NonZeroU16, NonZeroUsize};
    use tracing::warn;

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(88);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);

    /// Shared config factory for fixed-value Current QMDB tests.
    pub(crate) fn fixed_config<T: Translator + Default>(
        partition_prefix: &str,
        pooler: &impl BufferPooler,
    ) -> FixedConfig<T> {
        FixedConfig {
            mmr_journal_partition: format!("{partition_prefix}-journal-partition"),
            mmr_metadata_partition: format!("{partition_prefix}-metadata-partition"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("{partition_prefix}-partition-prefix"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            grafted_mmr_metadata_partition: format!(
                "{partition_prefix}-grafted-mmr-metadata-partition"
            ),
            translator: T::default(),
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Shared config factory for variable-value Current QMDB tests with unit codec config.
    pub(crate) fn variable_config<T: Translator + Default>(
        partition_prefix: &str,
        pooler: &impl BufferPooler,
    ) -> VariableConfig<T, ((), ())> {
        VariableConfig {
            mmr_journal_partition: format!("{partition_prefix}-journal-partition"),
            mmr_metadata_partition: format!("{partition_prefix}-metadata-partition"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("{partition_prefix}-partition-prefix"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((), ()),
            grafted_mmr_metadata_partition: format!(
                "{partition_prefix}-grafted-mmr-metadata-partition"
            ),
            translator: T::default(),
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Commit a set of writes as a single batch.
    async fn commit_writes<C: DbAny>(
        db: &mut C,
        writes: impl IntoIterator<Item = (C::Key, Option<<C as LogStore>::Value>)>,
    ) -> Result<(), Error> {
        let mut batch = db.new_batch();
        for (k, v) in writes {
            batch = batch.write(k, v);
        }
        let finalized = batch.merkleize(None).await?.finalize();
        db.apply_batch(finalized).await?;
        db.commit().await?;
        Ok(())
    }

    /// Apply random operations to the given db, committing them (randomly and at the end) only if
    /// `commit_changes` is true. Returns the db; callers should commit if needed.
    ///
    /// Returns a boxed future to prevent stack overflow when monomorphized across many DB variants.
    async fn apply_random_ops_inner<C>(
        num_elements: u64,
        commit_changes: bool,
        rng_seed: u64,
        mut db: C,
    ) -> Result<C, Error>
    where
        C: DbAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
    {
        // Log the seed with high visibility to make failures reproducible.
        warn!("rng_seed={}", rng_seed);
        let mut rng = StdRng::seed_from_u64(rng_seed);

        // First loop: all initial writes in one batch.
        let writes: Vec<_> = (0u64..num_elements)
            .map(|i| {
                let k = TestKey::from_seed(i);
                let v = TestValue::from_seed(rng.next_u64());
                (k, Some(v))
            })
            .collect();
        if commit_changes {
            commit_writes(&mut db, writes).await?;
        }

        // Randomly update / delete them. We use a delete frequency that is 1/7th of the update
        // frequency. Accumulate writes and commit periodically.
        let mut pending: Vec<(C::Key, Option<<C as LogStore>::Value>)> = Vec::new();
        for _ in 0u64..num_elements * 10 {
            let rand_key = TestKey::from_seed(rng.next_u64() % num_elements);
            if rng.next_u32() % 7 == 0 {
                pending.push((rand_key, None));
                continue;
            }
            let v = TestValue::from_seed(rng.next_u64());
            pending.push((rand_key, Some(v)));
            if commit_changes && rng.next_u32() % 20 == 0 {
                commit_writes(&mut db, pending.drain(..)).await?;
            }
        }
        if commit_changes {
            commit_writes(&mut db, pending).await?;
        }
        Ok(db)
    }

    pub fn apply_random_ops<C>(
        num_elements: u64,
        commit_changes: bool,
        rng_seed: u64,
        db: C,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<C, Error>>>>
    where
        C: DbAny + 'static,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
    {
        Box::pin(apply_random_ops_inner::<C>(
            num_elements,
            commit_changes,
            rng_seed,
            db,
        ))
    }

    /// Run `test_build_random_close_reopen` against a database factory.
    ///
    /// The factory should return a database when given a context and partition name.
    /// The factory will be called multiple times to test reopening.
    pub fn test_build_random_close_reopen<C, F, Fut>(mut open_db: F)
    where
        C: DbAny + 'static,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        let mut open_db_clone = open_db.clone();
        let state1 = executor.start(|mut context| async move {
            let partition = "build-random".to_string();
            let rng_seed = context.next_u64();
            let mut db: C = open_db_clone(context.with_label("first"), partition.clone()).await;
            db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db)
                .await
                .unwrap();
            let finalized = db.new_batch().merkleize(None).await.unwrap().finalize();
            db.apply_batch(finalized).await.unwrap();
            db.sync().await.unwrap();

            // Drop and reopen the db
            let root = db.root();
            drop(db);
            let db: C = open_db_clone(context.with_label("second"), partition).await;

            // Ensure the root matches
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
            context.auditor().state()
        });

        // Run again to verify determinism
        let executor = deterministic::Runner::default();
        let state2 = executor.start(|mut context| async move {
            let partition = "build-random".to_string();
            let rng_seed = context.next_u64();
            let mut db: C = open_db(context.with_label("first"), partition.clone()).await;
            db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db)
                .await
                .unwrap();
            let finalized = db.new_batch().merkleize(None).await.unwrap().finalize();
            db.apply_batch(finalized).await.unwrap();
            db.sync().await.unwrap();

            let root = db.root();
            drop(db);
            let db: C = open_db(context.with_label("second"), partition).await;
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
            context.auditor().state()
        });

        assert_eq!(state1, state2);
    }

    /// Run `test_simulate_write_failures` against a database factory.
    ///
    /// This test builds a random database and simulates recovery from different types of
    /// failure scenarios.
    pub fn test_simulate_write_failures<C, F, Fut>(mut open_db: F)
    where
        C: DbAny + 'static,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        // Box the future to prevent stack overflow when monomorphized across DB variants.
        executor.start(|mut context| {
            Box::pin(async move {
                let partition = "build-random-fail-commit".to_string();
                let rng_seed = context.next_u64();
                let mut db: C = open_db(context.with_label("first"), partition.clone()).await;
                db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db)
                    .await
                    .unwrap();
                commit_writes(&mut db, []).await.unwrap();
                let committed_root = db.root();
                let committed_op_count = db.bounds().await.end;
                let committed_inactivity_floor = db.inactivity_floor_loc().await;
                db.prune(committed_inactivity_floor).await.unwrap();

                // Perform more random operations without committing any of them.
                let db = apply_random_ops::<C>(ELEMENTS, false, rng_seed + 1, db)
                    .await
                    .unwrap();

                // SCENARIO #1: Simulate a crash that happens before any writes. Upon reopening, the
                // state of the DB should be as of the last commit.
                drop(db);
                let db: C = open_db(context.with_label("scenario1"), partition.clone()).await;
                assert_eq!(db.root(), committed_root);
                assert_eq!(db.bounds().await.end, committed_op_count);

                // Re-apply the exact same operations, this time committed.
                let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed + 1, db)
                    .await
                    .unwrap();

                // SCENARIO #2: Simulate a crash that happens after the any db has been committed, but
                // before sync/prune is called. We do this by dropping the db without calling
                // sync or prune.
                let committed_op_count = db.bounds().await.end;
                drop(db);

                // We should be able to recover, so the root should differ from the previous commit, and
                // the op count should be greater than before.
                let db: C = open_db(context.with_label("scenario2"), partition.clone()).await;
                let scenario_2_root = db.root();

                // To confirm the second committed hash is correct we'll re-build the DB in a new
                // partition, but without any failures. They should have the exact same state.
                let fresh_partition = "build-random-fail-commit-fresh".to_string();
                let mut db: C = open_db(context.with_label("fresh"), fresh_partition.clone()).await;
                db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db)
                    .await
                    .unwrap();
                commit_writes(&mut db, []).await.unwrap();
                db = apply_random_ops::<C>(ELEMENTS, true, rng_seed + 1, db)
                    .await
                    .unwrap();
                db.prune(db.inactivity_floor_loc().await).await.unwrap();
                // State from scenario #2 should match that of a successful commit.
                assert_eq!(db.bounds().await.end, committed_op_count);
                assert_eq!(db.root(), scenario_2_root);

                db.destroy().await.unwrap();
            })
        });
    }

    /// Run `test_different_pruning_delays_same_root` against a database factory.
    ///
    /// This test verifies that pruning operations do not affect the root hash - two databases
    /// with identical operations but different pruning schedules should have the same root.
    pub fn test_different_pruning_delays_same_root<C, F, Fut>(mut open_db: F)
    where
        C: DbAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        const NUM_OPERATIONS: u64 = 1000;

        let executor = deterministic::Runner::default();
        let mut open_db_clone = open_db.clone();
        executor.start(|context| async move {
            // Create two databases that are identical other than how they are pruned.
            let mut db_no_pruning: C =
                open_db_clone(context.with_label("no_pruning"), "no-pruning-test".into()).await;
            let mut db_pruning: C =
                open_db(context.with_label("pruning"), "pruning-test".into()).await;

            // Apply identical operations to both databases, but only prune one.
            // Accumulate writes between commits.
            let mut pending_no_pruning: Vec<(C::Key, Option<<C as LogStore>::Value>)> = Vec::new();
            let mut pending_pruning: Vec<(C::Key, Option<<C as LogStore>::Value>)> = Vec::new();
            for i in 0..NUM_OPERATIONS {
                let key: C::Key = TestKey::from_seed(i);
                let value: <C as LogStore>::Value = TestValue::from_seed(i * 1000);

                pending_no_pruning.push((key, Some(value.clone())));
                pending_pruning.push((key, Some(value)));

                // Commit periodically
                if i % 50 == 49 {
                    commit_writes(&mut db_no_pruning, pending_no_pruning.drain(..))
                        .await
                        .unwrap();
                    commit_writes(&mut db_pruning, pending_pruning.drain(..))
                        .await
                        .unwrap();
                    db_pruning
                        .prune(db_no_pruning.inactivity_floor_loc().await)
                        .await
                        .unwrap();
                }
            }

            // Final commit for remaining writes.
            commit_writes(&mut db_no_pruning, pending_no_pruning)
                .await
                .unwrap();
            commit_writes(&mut db_pruning, pending_pruning)
                .await
                .unwrap();

            // Get roots from both databases - they should match
            let root_no_pruning = db_no_pruning.root();
            let root_pruning = db_pruning.root();
            assert_eq!(root_no_pruning, root_pruning);

            // Also verify inactivity floors match
            assert_eq!(
                db_no_pruning.inactivity_floor_loc().await,
                db_pruning.inactivity_floor_loc().await
            );

            db_no_pruning.destroy().await.unwrap();
            db_pruning.destroy().await.unwrap();
        });
    }

    /// Run `test_sync_persists_bitmap_pruning_boundary` against a database factory.
    ///
    /// This test verifies that calling `sync()` persists the bitmap pruning boundary that was
    /// set during `commit()`. If `sync()` didn't call `write_pruned`, the
    /// `pruned_bits()` count would be 0 after reopen instead of the expected value.
    pub fn test_sync_persists_bitmap_pruning_boundary<C, F, Fut>(mut open_db: F)
    where
        C: DbAny + BitmapPrunedBits + 'static,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        const ELEMENTS: u64 = 500;

        let executor = deterministic::Runner::default();
        let mut open_db_clone = open_db.clone();
        executor.start(|mut context| async move {
            let partition = "sync-bitmap-pruning".to_string();
            let rng_seed = context.next_u64();
            let mut db: C = open_db_clone(context.with_label("first"), partition.clone()).await;

            // Apply random operations with commits to advance the inactivity floor.
            db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db).await.unwrap();
            let finalized = db.new_batch().merkleize(None).await.unwrap().finalize();
            db.apply_batch(finalized).await.unwrap();

            // The bitmap should have been pruned during commit().
            let pruned_bits_before = db.pruned_bits();
            warn!(
                "pruned_bits_before={}, inactivity_floor={}, op_count={}",
                pruned_bits_before,
                *db.inactivity_floor_loc().await,
                *db.bounds().await.end
            );

            // Verify we actually have some pruning (otherwise the test is meaningless).
            assert!(
                pruned_bits_before > 0,
                "Expected bitmap to have pruned bits after merkleization"
            );

            // Call sync() WITHOUT calling prune(). The bitmap pruning boundary was set
            // during commit(), and sync() should persist it.
            db.sync().await.unwrap();

            // Record the root before dropping.
            let root_before = db.root();
            drop(db);

            // Reopen the database.
            let db: C = open_db(context.with_label("second"), partition).await;

            // The pruned bits count should match. If sync() didn't persist the bitmap pruned
            // state, this would be 0.
            let pruned_bits_after = db.pruned_bits();
            warn!("pruned_bits_after={}", pruned_bits_after);

            assert_eq!(
                pruned_bits_after, pruned_bits_before,
                "Bitmap pruned bits mismatch after reopen - sync() may not have called write_pruned()"
            );

            // Also verify the root matches.
            assert_eq!(db.root(), root_before);

            db.destroy().await.unwrap();
        });
    }

    /// Run `test_current_db_build_big` against a database factory.
    ///
    /// This test builds a database with 1000 keys, updates some, deletes some, and verifies that
    /// the final state matches an independently computed HashMap. It also verifies that the state
    /// persists correctly after close and reopen.
    pub fn test_current_db_build_big<C, F, Fut>(mut open_db: F)
    where
        C: DbAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        let mut open_db_clone = open_db.clone();
        executor.start(|context| async move {
            let mut db: C = open_db_clone(context.with_label("first"), "build-big".into()).await;

            let mut map = std::collections::HashMap::<C::Key, <C as LogStore>::Value>::default();

            // All creates, updates, and deletes in one batch.
            let finalized = {
                let mut batch = db.new_batch();

                // Initial creates
                for i in 0u64..ELEMENTS {
                    let k: C::Key = TestKey::from_seed(i);
                    let v: <C as LogStore>::Value = TestValue::from_seed(i * 1000);
                    batch = batch.write(k, Some(v.clone()));
                    map.insert(k, v);
                }

                // Update every 3rd key
                for i in 0u64..ELEMENTS {
                    if i % 3 != 0 {
                        continue;
                    }
                    let k: C::Key = TestKey::from_seed(i);
                    let v: <C as LogStore>::Value = TestValue::from_seed((i + 1) * 10000);
                    batch = batch.write(k, Some(v.clone()));
                    map.insert(k, v);
                }

                // Delete every 7th key
                for i in 0u64..ELEMENTS {
                    if i % 7 != 1 {
                        continue;
                    }
                    let k: C::Key = TestKey::from_seed(i);
                    batch = batch.write(k, None);
                    map.remove(&k);
                }

                batch.merkleize(None).await.unwrap().finalize()
            };
            db.apply_batch(finalized).await.unwrap();

            // Sync and prune.
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc().await).await.unwrap();

            // Record root before dropping.
            let root = db.root();
            db.sync().await.unwrap();
            drop(db);

            // Reopen the db and verify it has exactly the same state.
            let db: C = open_db(context.with_label("second"), "build-big".into()).await;
            assert_eq!(root, db.root());

            // Confirm the db's state matches that of the separate map we computed independently.
            for i in 0u64..ELEMENTS {
                let k: C::Key = TestKey::from_seed(i);
                if let Some(map_value) = map.get(&k) {
                    let Some(db_value) = db.get(&k).await.unwrap() else {
                        panic!("key not found in db: {k}");
                    };
                    assert_eq!(*map_value, db_value);
                } else {
                    assert!(db.get(&k).await.unwrap().is_none());
                }
            }
        });
    }

    /// Run `test_stale_changeset_side_effect_free` against a database factory.
    ///
    /// The stale batch must be rejected without mutating the committed state.
    pub fn test_stale_changeset_side_effect_free<C, F, Fut>(mut open_db: F)
    where
        C: DbAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut,
        Fut: Future<Output = C>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db: C =
                open_db(context.with_label("db"), "stale-side-effect-free".into()).await;

            let key1 = <C::Key as TestKey>::from_seed(1);
            let key2 = <C::Key as TestKey>::from_seed(2);
            let value1 = <<C as LogStore>::Value as TestValue>::from_seed(10);
            let value2 = <<C as LogStore>::Value as TestValue>::from_seed(20);

            let changeset_a = {
                let mut batch = db.new_batch();
                batch = batch.write(key1, Some(value1.clone()));
                batch.merkleize(None).await.unwrap().finalize()
            };
            let changeset_b = {
                let mut batch = db.new_batch();
                batch = batch.write(key2, Some(value2));
                batch.merkleize(None).await.unwrap().finalize()
            };

            db.apply_batch(changeset_a).await.unwrap();
            let expected_root = db.root();
            let expected_bounds = db.bounds().await;
            let expected_metadata = db.get_metadata().await.unwrap();
            assert_eq!(db.get(&key1).await.unwrap(), Some(value1.clone()));
            assert_eq!(db.get(&key2).await.unwrap(), None);

            let result = db.apply_batch(changeset_b).await;
            assert!(
                matches!(result, Err(Error::StaleChangeset { .. })),
                "expected StaleChangeset error, got {result:?}"
            );
            assert_eq!(db.root(), expected_root);
            assert_eq!(db.bounds().await, expected_bounds);
            assert_eq!(db.get_metadata().await.unwrap(), expected_metadata);
            assert_eq!(db.get(&key1).await.unwrap(), Some(value1));
            assert_eq!(db.get(&key2).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    use crate::translator::OneCap;
    use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
    use commonware_macros::{test_group, test_traced};

    // Type aliases for all 12 variants (all use OneCap for collision coverage).
    type OrderedFixedDb = ordered::fixed::Db<Context, Digest, Digest, Sha256, OneCap, 32>;
    type OrderedVariableDb = ordered::variable::Db<Context, Digest, Digest, Sha256, OneCap, 32>;
    type UnorderedFixedDb = unordered::fixed::Db<Context, Digest, Digest, Sha256, OneCap, 32>;
    type UnorderedVariableDb = unordered::variable::Db<Context, Digest, Digest, Sha256, OneCap, 32>;
    type OrderedFixedP1Db =
        ordered::fixed::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 1, 32>;
    type OrderedVariableP1Db =
        ordered::variable::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 1, 32>;
    type UnorderedFixedP1Db =
        unordered::fixed::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 1, 32>;
    type UnorderedVariableP1Db =
        unordered::variable::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 1, 32>;
    type OrderedFixedP2Db =
        ordered::fixed::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 2, 32>;
    type OrderedVariableP2Db =
        ordered::variable::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 2, 32>;
    type UnorderedFixedP2Db =
        unordered::fixed::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 2, 32>;
    type UnorderedVariableP2Db =
        unordered::variable::partitioned::Db<Context, Digest, Digest, Sha256, OneCap, 2, 32>;

    // Helper macro to create an open_db closure for a specific variant.
    macro_rules! open_db_fn {
        ($db:ty, $cfg:ident) => {
            |ctx: Context, partition: String| async move {
                <$db>::init(ctx.clone(), $cfg::<OneCap>(&partition, &ctx))
                    .await
                    .unwrap()
            }
        };
    }

    // Defines all 12 variants. Calls $cb!($($args)*, $label, $type, $config) for each.
    macro_rules! with_all_variants {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, "of", OrderedFixedDb, fixed_config);
            $cb!($($args)*, "ov", OrderedVariableDb, variable_config);
            $cb!($($args)*, "uf", UnorderedFixedDb, fixed_config);
            $cb!($($args)*, "uv", UnorderedVariableDb, variable_config);
            $cb!($($args)*, "ofp1", OrderedFixedP1Db, fixed_config);
            $cb!($($args)*, "ovp1", OrderedVariableP1Db, variable_config);
            $cb!($($args)*, "ufp1", UnorderedFixedP1Db, fixed_config);
            $cb!($($args)*, "uvp1", UnorderedVariableP1Db, variable_config);
            $cb!($($args)*, "ofp2", OrderedFixedP2Db, fixed_config);
            $cb!($($args)*, "ovp2", OrderedVariableP2Db, variable_config);
            $cb!($($args)*, "ufp2", UnorderedFixedP2Db, fixed_config);
            $cb!($($args)*, "uvp2", UnorderedVariableP2Db, variable_config);
        };
    }

    // Defines 6 ordered variants.
    macro_rules! with_ordered_variants {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, "of", OrderedFixedDb, fixed_config);
            $cb!($($args)*, "ov", OrderedVariableDb, variable_config);
            $cb!($($args)*, "ofp1", OrderedFixedP1Db, fixed_config);
            $cb!($($args)*, "ovp1", OrderedVariableP1Db, variable_config);
            $cb!($($args)*, "ofp2", OrderedFixedP2Db, fixed_config);
            $cb!($($args)*, "ovp2", OrderedVariableP2Db, variable_config);
        };
    }

    // Defines 6 unordered variants.
    macro_rules! with_unordered_variants {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, "uf", UnorderedFixedDb, fixed_config);
            $cb!($($args)*, "uv", UnorderedVariableDb, variable_config);
            $cb!($($args)*, "ufp1", UnorderedFixedP1Db, fixed_config);
            $cb!($($args)*, "uvp1", UnorderedVariableP1Db, variable_config);
            $cb!($($args)*, "ufp2", UnorderedFixedP2Db, fixed_config);
            $cb!($($args)*, "uvp2", UnorderedVariableP2Db, variable_config);
        };
    }

    // Runner macros - receive common args followed by (label, type, config).
    macro_rules! test_simple {
        ($f:expr, $l:literal, $db:ty, $cfg:ident) => {
            Box::pin(async {
                $f(open_db_fn!($db, $cfg));
            })
            .await
        };
    }

    // Macro to run a test on DB variants.
    macro_rules! for_all_variants {
        (simple: $f:expr) => {{
            with_all_variants!(test_simple!($f));
        }};
        (ordered: $f:expr) => {{
            with_ordered_variants!(test_simple!($f));
        }};
        (unordered: $f:expr) => {{
            with_unordered_variants!(test_simple!($f));
        }};
    }

    // Wrapper functions for build_big tests with ordered/unordered expected values.
    fn test_ordered_build_big<C, F, Fut>(open_db: F)
    where
        C: DbAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        test_current_db_build_big::<C, F, Fut>(open_db);
    }

    fn test_unordered_build_big<C, F, Fut>(open_db: F)
    where
        C: DbAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        test_current_db_build_big::<C, F, Fut>(open_db);
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_build_random_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_build_random_close_reopen);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_simulate_write_failures() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_simulate_write_failures);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_different_pruning_delays_same_root() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_different_pruning_delays_same_root);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_all_variants_sync_persists_bitmap_pruning_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_sync_persists_bitmap_pruning_boundary);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_stale_changeset_side_effect_free() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_stale_changeset_side_effect_free);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_ordered_variants_build_big() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(ordered: test_ordered_build_big);
        });
    }

    #[test_group("slow")]
    #[test_traced("WARN")]
    fn test_unordered_variants_build_big() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(unordered: test_unordered_build_big);
        });
    }

    #[test_group("slow")]
    #[test_traced("DEBUG")]
    fn test_ordered_variants_build_small_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(ordered: ordered::tests::test_build_small_close_reopen);
        });
    }

    #[test_group("slow")]
    #[test_traced("DEBUG")]
    fn test_unordered_variants_build_small_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(unordered: unordered::tests::test_build_small_close_reopen);
        });
    }

    // ---- Current-level batch API tests ----
    //
    // These exercise the current wrapper's batch methods (root, ops_root,
    // MerkleizedBatch::get, batch chaining) which layer bitmap and grafted MMR
    // computation on top of the `any` batch.

    fn key(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    fn val(i: u64) -> Digest {
        Sha256::hash(&(i + 10000).to_be_bytes())
    }

    /// MerkleizedBatch::root() returns the canonical root that matches db.root()
    /// after apply. ops_root() differs from root() because the canonical root
    /// includes the bitmap/grafted MMR layers.
    #[test_traced("INFO")]
    fn test_current_batch_speculative_root() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb =
                UnorderedVariableDb::init(ctx.clone(), variable_config::<OneCap>("sr", &ctx))
                    .await
                    .unwrap();

            let mut batch = db.new_batch();
            for i in 0..10 {
                batch = batch.write(key(i), Some(val(i)));
            }
            let merkleized = batch.merkleize(None).await.unwrap();
            let speculative_root = merkleized.root();
            let ops_root = merkleized.ops_root();

            // Canonical root includes bitmap/grafted layers, so it differs from ops root.
            assert_ne!(speculative_root, ops_root);

            let finalized = merkleized.finalize();
            db.apply_batch(finalized).await.unwrap();

            // Speculative canonical root matches the committed canonical root.
            assert_eq!(db.root(), speculative_root);

            db.destroy().await.unwrap();
        });
    }

    /// MerkleizedBatch::get() at the current level reads overlay then base DB.
    #[test_traced("INFO")]
    fn test_current_batch_merkleized_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb =
                UnorderedVariableDb::init(ctx.clone(), variable_config::<OneCap>("mg", &ctx))
                    .await
                    .unwrap();

            let ka = key(0);
            let kb = key(1);
            let kc = key(2);

            // Pre-populate A.
            {
                let mut batch = db.new_batch();
                batch = batch.write(ka, Some(val(0)));
                let finalized = batch.merkleize(None).await.unwrap().finalize();
                db.apply_batch(finalized).await.unwrap();
            }

            // Batch: update A, delete nothing, create B.
            let va2 = val(100);
            let vb = val(1);
            let mut batch = db.new_batch();
            batch = batch.write(ka, Some(va2));
            batch = batch.write(kb, Some(vb));
            let merkleized = batch.merkleize(None).await.unwrap();

            assert_eq!(merkleized.get(&ka).await.unwrap(), Some(va2));
            assert_eq!(merkleized.get(&kb).await.unwrap(), Some(vb));
            assert_eq!(merkleized.get(&kc).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Batch chaining at the current level: parent -> merkleize -> child -> merkleize.
    /// Child's canonical root matches db.root() after apply.
    #[test_traced("INFO")]
    fn test_current_batch_chaining() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb =
                UnorderedVariableDb::init(ctx.clone(), variable_config::<OneCap>("ch", &ctx))
                    .await
                    .unwrap();

            // Parent batch writes keys 0..5.
            let mut parent = db.new_batch();
            for i in 0..5 {
                parent = parent.write(key(i), Some(val(i)));
            }
            let parent_m = parent.merkleize(None).await.unwrap();

            // Child batch writes keys 5..10 and overrides key 0.
            let mut child = parent_m.new_batch();
            for i in 5..10 {
                child = child.write(key(i), Some(val(i)));
            }
            child = child.write(key(0), Some(val(999)));
            let child_m = child.merkleize(None).await.unwrap();

            let child_root = child_m.root();

            // Child get reads through all layers.
            assert_eq!(child_m.get(&key(0)).await.unwrap(), Some(val(999)));
            assert_eq!(child_m.get(&key(3)).await.unwrap(), Some(val(3)));
            assert_eq!(child_m.get(&key(7)).await.unwrap(), Some(val(7)));

            let finalized = child_m.finalize();
            db.apply_batch(finalized).await.unwrap();
            assert_eq!(db.root(), child_root);

            // Verify all keys are correct.
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(999)));
            for i in 1..10 {
                assert_eq!(db.get(&key(i)).await.unwrap(), Some(val(i)));
            }

            db.destroy().await.unwrap();
        });
    }

    /// Applying without `commit()` publishes in memory but is not recovered after reopen.
    #[test_traced("INFO")]
    fn test_current_batch_apply_requires_commit_for_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "apply_requires_commit";
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb =
                UnorderedVariableDb::init(ctx.clone(), variable_config::<OneCap>(partition, &ctx))
                    .await
                    .unwrap();

            let committed_root = db.root();

            let finalized = db
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(None)
                .await
                .unwrap()
                .finalize();
            db.apply_batch(finalized).await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

            drop(db);

            let reopened: UnorderedVariableDb = UnorderedVariableDb::init(
                context.with_label("reopen"),
                variable_config::<OneCap>(partition, &context),
            )
            .await
            .unwrap();
            assert_eq!(reopened.root(), committed_root);
            assert_eq!(reopened.get(&key(0)).await.unwrap(), None);

            reopened.destroy().await.unwrap();
        });
    }

    /// One-stage pipelining lets the next batch be built while the prior batch commits.
    #[test_traced("INFO")]
    fn test_current_batch_single_stage_pipeline() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb =
                UnorderedVariableDb::init(ctx.clone(), variable_config::<OneCap>("pipe", &ctx))
                    .await
                    .unwrap();

            let parent_finalized = {
                let mut batch = db.new_batch();
                batch = batch.write(key(0), Some(val(0)));
                batch.merkleize(None).await.unwrap().finalize()
            };
            db.apply_batch(parent_finalized).await.unwrap();

            let (child_finalized, commit_result) = futures::join!(
                async {
                    assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
                    let mut child = db.new_batch();
                    child = child.write(key(1), Some(val(1)));
                    child.merkleize(None).await.map(|batch| batch.finalize())
                },
                db.commit(),
            );
            let child_finalized = child_finalized.unwrap();
            commit_result.unwrap();

            db.apply_batch(child_finalized).await.unwrap();
            db.commit().await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));

            db.destroy().await.unwrap();
        });
    }
}
