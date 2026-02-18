//! A _Current_ authenticated database provides succinct proofs of _any_ value ever associated with
//! a key, and also whether that value is the _current_ value associated with it.
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
//! - **Grafted MMR** (`CleanMmr<Digest>`): An in-memory MMR of digests at and above the
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
//! grafted_leaf = hash(bitmap_chunk || ops_subtree_root)
//! ```
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
//! reconstructs the grafted leaf by hashing `chunk || ops_subtree_root`. Above the grafting
//! height, it resumes standard MMR hashing. If the reconstructed root matches the expected root
//! and bit _i_ is set in the chunk, the operation is proven active.
//!
//! This is a single proof path, not two independent ones -- the bitmap chunk is embedded in the
//! proof verification at the grafting boundary.
//!
//! ## Partial chunks
//!
//! Operations arrive continuously, so the last bitmap chunk is usually incomplete (fewer than
//! `N * 8` bits). An incomplete chunk has no grafted leaf in the cache because there is no
//! corresponding complete subtree in the ops MMR. To still authenticate these bits, the root is
//! computed as:
//!
//! ```text
//! root = hash(mmr_root || next_bit || hash(partial_chunk))
//! ```
//!
//! where `next_bit` is the index of the next unset position in the partial chunk and `mmr_root`
//! is the root over the grafted MMR (which covers only complete chunks). When all chunks are
//! complete, `root = mmr_root` with no additional hashing.
//!
//! ## Incremental updates
//!
//! When operations are added or bits change (e.g. an operation becomes inactive during floor
//! raising), only the affected chunks are marked "dirty". During merkleization
//! (`into_merkleized`), only dirty grafted leaves are recomputed and their ancestors are
//! propagated upward through the cache. This avoids recomputing the entire grafted tree.
//!
//! ## Pruning
//!
//! Old bitmap chunks (below the inactivity floor) can be pruned. Before pruning, the grafted
//! digest peaks covering the pruned region are persisted to metadata as "pinned nodes". On
//! recovery, these pinned nodes are loaded and serve as opaque siblings during upward propagation,
//! allowing the grafted tree to be rebuilt without the pruned chunks.
//!
//! ## Pruning and metadata persistence
//!
//! The grafted MMR and bitmap have separate pruning paths that work together:
//!
//! ### Bitmap pruning (in `into_merkleized`)
//!
//! During merkleization, bitmap chunks fully below the inactivity floor are pruned
//! (`prune_to_bit`). All their bits are guaranteed to be 0 (inactive), so discarding
//! them does not lose information. This advances `pruned_chunks` but does NOT advance
//! the grafted MMR's in-memory pruning boundary.
//!
//! ### Metadata writes (in `sync` and `prune`)
//!
//! `sync_metadata()` persists two things to the metadata store:
//! - The number of pruned bitmap chunks (`PRUNED_CHUNKS_PREFIX`).
//! - The grafted MMR peak digests covering the pruned region (`NODE_PREFIX`).
//!
//! It is called by both `sync()` and `prune()`. The metadata store is cleared and
//! rewritten each time (idempotent).
//!
//! ### Grafted MMR pruning (in `prune`)
//!
//! `prune()` executes in this order:
//!
//! 1. **`sync_metadata()`** -- persist peaks before the ops log is pruned. If the
//!    process crashes after this step but before step 2, the metadata is ahead of
//!    the log, which is safe: recovery will recompute from the un-pruned log and
//!    the metadata simply records peaks that haven't been pruned yet. The reverse
//!    order (prune first, write metadata second) would be unsafe: a pruned log
//!    with stale metadata would lose peak digests permanently.
//! 2. **`any.prune()`** -- prune the ops log.
//! 3. **`status.prune_commits_before()`** -- discard historical bitmap commits
//!    whose ops have been pruned (historical proofs below the prune point are
//!    impossible).
//! 4. **Advance the grafted MMR boundary** to the oldest surviving
//!    historical commit's `pruned_chunks` B. After `prune_to_pos(B)`, the
//!    grafted MMR retains nodes >= B plus the O(log B) peaks at B (pinned).
//!    Any surviving commit has P >= B; its peaks either extend beyond B
//!    (retained) or fall within [0, B) and are peaks of B too (pinned),
//!    because MMR peaks share a common left-to-right prefix when P >= B.
//!
//! ### Recovery (`init_metadata` + `build_grafted_mmr`)
//!
//! On startup, `init_metadata` reads `pruned_chunks` and the pinned peak digests
//! from the metadata store. `build_grafted_mmr` uses these together with the
//! un-pruned bitmap chunks and the ops MMR to reconstruct the grafted MMR.
//! Historical bitmap commits (reverse diffs) are in-memory only and are lost on
//! restart, so `historical_range_proof` can only serve sizes committed since the
//! current process started.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::contiguous::{fixed::Journal as FJournal, variable::Journal as VJournal},
    mmr::{Location, StandardHasher},
    qmdb::{
        any::{
            self,
            operation::{Operation, Update},
            FixedConfig as AnyFixedConfig, ValueEncoding, VariableConfig as AnyVariableConfig,
        },
        operation::Committable,
        Durable, Error,
    },
    translator::Translator,
};
use commonware_codec::{Codec, CodecFixedShared, FixedSize, Read};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_parallel::ThreadPool;
use commonware_runtime::{buffer::paged::CacheRef, Clock, Metrics, Storage};
use commonware_utils::{
    bitmap::{historical::CleanBitMap, Prunable as BitMap},
    sync::AsyncMutex,
    Array,
};
use std::num::{NonZeroU64, NonZeroUsize};

pub mod db;
mod grafting;
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
pub(super) async fn init_fixed<E, K, V, U, H, T, I, const N: usize, NewIndex>(
    context: E,
    config: FixedConfig<T>,
    new_index: NewIndex,
) -> Result<
    db::Db<E, FJournal<E, Operation<K, V, U>>, I, H, U, N, db::Merkleized<DigestOf<H>>, Durable>,
    Error,
>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V> + Send + Sync,
    H: Hasher,
    T: Translator,
    I: UnorderedIndex<Value = Location>,
    NewIndex: FnOnce(E, T) -> I,
    Operation<K, V, U>: CodecFixedShared + Committable,
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
    let last_known_inactivity_floor = Location::new_unchecked(status.len());
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
    let mut hasher = StandardHasher::<H>::new();
    let grafted_mmr = db::build_grafted_mmr::<H, N>(
        &mut hasher,
        &status,
        &pinned_nodes,
        &any.log.mmr,
        thread_pool.as_ref(),
    )
    .await?;

    // Compute and cache the root.
    let storage = grafting::Storage::new(&grafted_mmr, grafting::height::<N>(), &any.log.mmr);
    let partial_chunk = db::partial_chunk(&status);
    let root = db::compute_root(&mut hasher, &storage, partial_chunk).await?;

    Ok(db::Db {
        any,
        status: CleanBitMap::from(status),
        grafted_mmr,
        metadata: AsyncMutex::new(metadata),
        thread_pool,
        state: db::Merkleized { root },
    })
}

/// Shared initialization logic for variable-sized value Current [db::Db].
pub(super) async fn init_variable<E, K, V, U, H, T, I, const N: usize, NewIndex>(
    context: E,
    config: VariableConfig<T, <Operation<K, V, U> as Read>::Cfg>,
    new_index: NewIndex,
) -> Result<
    db::Db<E, VJournal<E, Operation<K, V, U>>, I, H, U, N, db::Merkleized<DigestOf<H>>, Durable>,
    Error,
>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V> + Send + Sync,
    H: Hasher,
    T: Translator,
    I: UnorderedIndex<Value = Location>,
    NewIndex: FnOnce(E, T) -> I,
    Operation<K, V, U>: Codec + Committable,
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
    let last_known_inactivity_floor = Location::new_unchecked(status.len());
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
    let mut hasher = StandardHasher::<H>::new();
    let grafted_mmr = db::build_grafted_mmr::<H, N>(
        &mut hasher,
        &status,
        &pinned_nodes,
        &any.log.mmr,
        pool.as_ref(),
    )
    .await?;

    // Compute and cache the root.
    let storage = grafting::Storage::new(&grafted_mmr, grafting::height::<N>(), &any.log.mmr);
    let partial_chunk = db::partial_chunk(&status);
    let root = db::compute_root(&mut hasher, &storage, partial_chunk).await?;

    Ok(db::Db {
        any,
        status: CleanBitMap::from(status),
        grafted_mmr,
        metadata: AsyncMutex::new(metadata),
        thread_pool: pool,
        state: db::Merkleized { root },
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
        kv::Batchable as _,
        qmdb::{
            any::states::{CleanAny, MutableAny as _, UnmerkleizedDurableAny as _},
            store::{
                batch_tests::{TestKey, TestValue},
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
    ) -> VariableConfig<T, ()> {
        VariableConfig {
            mmr_journal_partition: format!("{partition_prefix}-journal-partition"),
            mmr_metadata_partition: format!("{partition_prefix}-metadata-partition"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("{partition_prefix}-partition-prefix"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: (),
            grafted_mmr_metadata_partition: format!(
                "{partition_prefix}-grafted-mmr-metadata-partition"
            ),
            translator: T::default(),
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Apply random operations to the given db, committing them (randomly and at the end) only if
    /// `commit_changes` is true. Returns a mutable db; callers should commit if needed.
    ///
    /// Returns a boxed future to prevent stack overflow when monomorphized across many DB variants.
    async fn apply_random_ops_inner<C>(
        num_elements: u64,
        commit_changes: bool,
        rng_seed: u64,
        mut db: C::Mutable,
    ) -> Result<C::Mutable, Error>
    where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
    {
        // Log the seed with high visibility to make failures reproducible.
        warn!("rng_seed={}", rng_seed);
        let mut rng = StdRng::seed_from_u64(rng_seed);

        for i in 0u64..num_elements {
            let k = TestKey::from_seed(i);
            let v = TestValue::from_seed(rng.next_u64());
            db.write_batch([(k, Some(v))]).await.unwrap();
        }

        // Randomly update / delete them. We use a delete frequency that is 1/7th of the update
        // frequency.
        for _ in 0u64..num_elements * 10 {
            let rand_key = TestKey::from_seed(rng.next_u64() % num_elements);
            if rng.next_u32() % 7 == 0 {
                db.write_batch([(rand_key, None)]).await.unwrap();
                continue;
            }
            let v = TestValue::from_seed(rng.next_u64());
            db.write_batch([(rand_key, Some(v))]).await.unwrap();
            if commit_changes && rng.next_u32() % 20 == 0 {
                // Commit every ~20 updates.
                let (durable_db, _) = db.commit(None).await?;
                let clean_db: C = durable_db.into_merkleized().await?;
                db = clean_db.into_mutable();
            }
        }
        if commit_changes {
            let (durable_db, _) = db.commit(None).await?;
            let clean_db: C = durable_db.into_merkleized().await?;
            db = clean_db.into_mutable();
        }
        Ok(db)
    }

    pub fn apply_random_ops<C>(
        num_elements: u64,
        commit_changes: bool,
        rng_seed: u64,
        db: C::Mutable,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<C::Mutable, Error>>>>
    where
        C: CleanAny + 'static,
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
    /// The factory should return a clean (Merkleized, Durable) database when given a context and
    /// partition name. The factory will be called multiple times to test reopening.
    pub fn test_build_random_close_reopen<C, F, Fut>(mut open_db: F)
    where
        C: CleanAny + 'static,
        C::Key: TestKey,
        C::Mutable: 'static,
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
            let db: C = open_db_clone(context.with_label("first"), partition.clone()).await;
            let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db: C = db.into_merkleized().await.unwrap();
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
            let db: C = open_db(context.with_label("first"), partition.clone()).await;
            let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db: C = db.into_merkleized().await.unwrap();
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
        C: CleanAny + 'static,
        C::Key: TestKey,
        C::Mutable: 'static,
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
                let db: C = open_db(context.with_label("first"), partition.clone()).await;
                let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                    .await
                    .unwrap();
                let (db, _) = db.commit(None).await.unwrap();
                let mut db: C = db.into_merkleized().await.unwrap();
                let committed_root = db.root();
                let committed_op_count = db.bounds().await.end;
                let committed_inactivity_floor = db.inactivity_floor_loc().await;
                db.prune(committed_inactivity_floor).await.unwrap();

                // Perform more random operations without committing any of them.
                let db = apply_random_ops::<C>(ELEMENTS, false, rng_seed + 1, db.into_mutable())
                    .await
                    .unwrap();

                // SCENARIO #1: Simulate a crash that happens before any writes. Upon reopening, the
                // state of the DB should be as of the last commit.
                drop(db);
                let db: C = open_db(context.with_label("scenario1"), partition.clone()).await;
                assert_eq!(db.root(), committed_root);
                assert_eq!(db.bounds().await.end, committed_op_count);

                // Re-apply the exact same uncommitted operations.
                let db = apply_random_ops::<C>(ELEMENTS, false, rng_seed + 1, db.into_mutable())
                    .await
                    .unwrap();

                // SCENARIO #2: Simulate a crash that happens after the any db has been committed, but
                // before the state of the pruned bitmap can be written to disk (i.e., before
                // into_merkleized is called). We do this by committing and then dropping the durable
                // db without calling close or into_merkleized.
                let (durable_db, _) = db.commit(None).await.unwrap();
                let committed_op_count = durable_db.bounds().await.end;
                drop(durable_db);

                // We should be able to recover, so the root should differ from the previous commit, and
                // the op count should be greater than before.
                let db: C = open_db(context.with_label("scenario2"), partition.clone()).await;
                let scenario_2_root = db.root();

                // To confirm the second committed hash is correct we'll re-build the DB in a new
                // partition, but without any failures. They should have the exact same state.
                let fresh_partition = "build-random-fail-commit-fresh".to_string();
                let db: C = open_db(context.with_label("fresh"), fresh_partition.clone()).await;
                let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                    .await
                    .unwrap();
                let (db, _) = db.commit(None).await.unwrap();
                let db = apply_random_ops::<C>(ELEMENTS, false, rng_seed + 1, db.into_mutable())
                    .await
                    .unwrap();
                let (db, _) = db.commit(None).await.unwrap();
                let mut db: C = db.into_merkleized().await.unwrap();
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
        C: CleanAny,
        C::Key: TestKey,
        C::Mutable: 'static,
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

            let mut db_no_pruning_mut = db_no_pruning.into_mutable();
            let mut db_pruning_mut = db_pruning.into_mutable();

            // Apply identical operations to both databases, but only prune one.
            for i in 0..NUM_OPERATIONS {
                let key: C::Key = TestKey::from_seed(i);
                let value: <C as LogStore>::Value = TestValue::from_seed(i * 1000);

                db_no_pruning_mut
                    .write_batch([(key, Some(value.clone()))])
                    .await
                    .unwrap();
                db_pruning_mut
                    .write_batch([(key, Some(value))])
                    .await
                    .unwrap();

                // Commit periodically
                if i % 50 == 49 {
                    let (db_1, _) = db_no_pruning_mut.commit(None).await.unwrap();
                    let clean_no_pruning: C = db_1.into_merkleized().await.unwrap();
                    let (db_2, _) = db_pruning_mut.commit(None).await.unwrap();
                    let mut clean_pruning: C = db_2.into_merkleized().await.unwrap();
                    clean_pruning
                        .prune(clean_no_pruning.inactivity_floor_loc().await)
                        .await
                        .unwrap();
                    db_no_pruning_mut = clean_no_pruning.into_mutable();
                    db_pruning_mut = clean_pruning.into_mutable();
                }
            }

            // Final commit
            let (db_1, _) = db_no_pruning_mut.commit(None).await.unwrap();
            db_no_pruning = db_1.into_merkleized().await.unwrap();
            let (db_2, _) = db_pruning_mut.commit(None).await.unwrap();
            db_pruning = db_2.into_merkleized().await.unwrap();

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
    /// set during `into_merkleized()`. If `sync()` didn't call `write_pruned`, the
    /// `pruned_bits()` count would be 0 after reopen instead of the expected value.
    pub fn test_sync_persists_bitmap_pruning_boundary<C, F, Fut>(mut open_db: F)
    where
        C: CleanAny + BitmapPrunedBits + 'static,
        C::Key: TestKey,
        C::Mutable: 'static,
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
            let db: C = open_db_clone(context.with_label("first"), partition.clone()).await;

            // Apply random operations with commits to advance the inactivity floor.
            let db = apply_random_ops::<C>(ELEMENTS, true, rng_seed, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db: C = db.into_merkleized().await.unwrap();

            // The bitmap should have been pruned during into_merkleized().
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
            // during into_merkleized(), and sync() should persist it.
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
    ///
    /// The `expected_op_count` and `expected_inactivity_floor` parameters specify the expected
    /// values after commit + merkleize + prune. These differ between ordered and unordered variants.
    pub fn test_current_db_build_big<C, F, Fut>(
        mut open_db: F,
        expected_op_count: u64,
        expected_inactivity_floor: u64,
    ) where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        use crate::mmr::Location;

        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        let mut open_db_clone = open_db.clone();
        executor.start(|context| async move {
            let mut db = open_db_clone(context.with_label("first"), "build-big".into())
                .await
                .into_mutable();

            let mut map = std::collections::HashMap::<C::Key, <C as LogStore>::Value>::default();
            for i in 0u64..ELEMENTS {
                let k: C::Key = TestKey::from_seed(i);
                let v: <C as LogStore>::Value = TestValue::from_seed(i * 1000);
                db.write_batch([(k, Some(v.clone()))]).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k: C::Key = TestKey::from_seed(i);
                let v: <C as LogStore>::Value = TestValue::from_seed((i + 1) * 10000);
                db.write_batch([(k, Some(v.clone()))]).await.unwrap();
                map.insert(k, v);
            }

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k: C::Key = TestKey::from_seed(i);
                db.write_batch([(k, None)]).await.unwrap();
                map.remove(&k);
            }

            // Test that commit + sync w/ pruning will raise the activity floor.
            let (db, _) = db.commit(None).await.unwrap();
            let mut db: C = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc().await).await.unwrap();

            // Verify expected state after prune.
            assert_eq!(
                db.bounds().await.end,
                Location::new_unchecked(expected_op_count)
            );
            assert_eq!(
                db.inactivity_floor_loc().await,
                Location::new_unchecked(expected_inactivity_floor)
            );

            // Record root before dropping.
            let root = db.root();
            db.sync().await.unwrap();
            drop(db);

            // Reopen the db and verify it has exactly the same state.
            let db: C = open_db(context.with_label("second"), "build-big".into()).await;
            assert_eq!(root, db.root());
            assert_eq!(
                db.bounds().await.end,
                Location::new_unchecked(expected_op_count)
            );
            assert_eq!(
                db.inactivity_floor_loc().await,
                Location::new_unchecked(expected_inactivity_floor)
            );

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

    // ============================================================
    // Consolidated tests for all 12 Current QMDB variants
    // ============================================================

    use crate::{
        mmr::{hasher::Hasher as _, Location, StandardHasher},
        translator::OneCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;

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

    macro_rules! test_with_db {
        ($ctx:expr, $sfx:expr, $f:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_", $sfx);
            Box::pin(async {
                $f(open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await).await
            })
            .await
        }};
    }

    // Runner macro for historical range proof tests. Receives (context, label, type, config)
    // and runs the test body with the concrete DB type. This must be a macro (not a generic
    // function) because `historical_range_proof` is an inherent method on `current::db::Db`,
    // not part of any trait, and its return type contains `[u8; N]` (a const generic).
    macro_rules! test_historical_proof {
        ($ctx:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_hp");
            Box::pin(async {
                let mut hasher = StandardHasher::<Sha256>::new();
                let db: $db = open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await;

                // Phase 1: Write 50 keys, commit, merkleize.
                let mut db = db.into_mutable();
                for i in 0u8..50 {
                    db.write_batch([(Sha256::fill(i), Some(Sha256::fill(i + 100)))])
                        .await
                        .unwrap();
                }
                let (db, _) = db.commit(None).await.unwrap();
                let db = db.into_merkleized().await.unwrap();
                let root1 = db.root();
                let size1 = db.size().await;

                // Phase 2: Write 50 more keys, commit, merkleize.
                let mut db = db.into_mutable();
                for i in 50u8..100 {
                    db.write_batch([(Sha256::fill(i), Some(Sha256::fill(i + 100)))])
                        .await
                        .unwrap();
                }
                let (db, _) = db.commit(None).await.unwrap();
                let db = db.into_merkleized().await.unwrap();
                let root2 = db.root();
                let size2 = db.size().await;

                assert_ne!(root1, root2);
                assert!(size2 > size1);

                // Historical proof at size1 verifies against root1 but not root2.
                let start = Location::new_unchecked(1);
                let max_ops = NZU64!(4);
                let (proof, ops, chunks) = db
                    .historical_range_proof(hasher.inner(), size1, start, max_ops)
                    .await
                    .unwrap();
                assert!(proof.verify(hasher.inner(), start, &ops, &chunks, &root1));
                assert!(!proof.verify(hasher.inner(), start, &ops, &chunks, &root2));

                // Historical proof at size2 verifies against root2 but not root1.
                let (proof2, ops2, chunks2) = db
                    .historical_range_proof(hasher.inner(), size2, start, max_ops)
                    .await
                    .unwrap();
                assert!(proof2.verify(hasher.inner(), start, &ops2, &chunks2, &root2));
                assert!(!proof2.verify(hasher.inner(), start, &ops2, &chunks2, &root1));

                // Nonexistent historical size should error.
                let bad_size = Location::new_unchecked(*size1 + 1);
                assert!(db
                    .historical_range_proof(hasher.inner(), bad_size, start, max_ops)
                    .await
                    .is_err());

                db.destroy().await.unwrap();
            })
            .await
        }};
    }

    // Verify that a historical proof at a partial chunk (size not aligned to 256)
    // carries a partial_chunk_digest, and that it verifies against the correct root.
    macro_rules! test_historical_proof_partial_chunk {
        ($ctx:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_hp_pc");
            Box::pin(async {
                let mut hasher = StandardHasher::<Sha256>::new();
                let db: $db = open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await;

                // 50 keys produces well under 256 ops, so the chunk is incomplete.
                let mut db = db.into_mutable();
                for i in 0u8..50 {
                    db.write_batch([(Sha256::fill(i), Some(Sha256::fill(i + 100)))])
                        .await
                        .unwrap();
                }
                let (db, _) = db.commit(None).await.unwrap();
                let db = db.into_merkleized().await.unwrap();
                let root1 = db.root();
                let size1 = db.size().await;
                assert!(*size1 % 256 != 0, "expected partial chunk");

                // Second commit to confirm the first is historical.
                let mut db = db.into_mutable();
                for i in 50u8..100 {
                    db.write_batch([(Sha256::fill(i), Some(Sha256::fill(i + 100)))])
                        .await
                        .unwrap();
                }
                let (db, _) = db.commit(None).await.unwrap();
                let db = db.into_merkleized().await.unwrap();
                let root2 = db.root();

                let start = Location::new_unchecked(0);
                let max_ops = NZU64!(10);
                let (proof, ops, chunks) = db
                    .historical_range_proof(hasher.inner(), size1, start, max_ops)
                    .await
                    .unwrap();
                assert!(proof.partial_chunk_digest.is_some());
                assert!(proof.verify(hasher.inner(), start, &ops, &chunks, &root1));
                assert!(!proof.verify(hasher.inner(), start, &ops, &chunks, &root2));

                db.destroy().await.unwrap();
            })
            .await
        }};
    }

    // Verify partial_chunk_digest is Some when size is not chunk-aligned and
    // None when it is. Checks the property across multiple commits.
    macro_rules! test_historical_proof_chunk_boundary {
        ($ctx:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_hp_cb");
            Box::pin(async {
                let mut hasher = StandardHasher::<Sha256>::new();
                let db: $db = open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await;
                let mut db = db.into_mutable();

                // 4 commits of 100 unique keys each. At least one should cross
                // a chunk boundary (256 ops), giving us both aligned and unaligned
                // snapshots to check.
                let mut snapshots = Vec::new();
                for round in 0u16..4 {
                    for j in 0u16..100 {
                        let k = (round * 100 + j) as u8;
                        db.write_batch([(Sha256::fill(k), Some(Sha256::fill(k.wrapping_add(50))))])
                            .await
                            .unwrap();
                    }
                    let (durable, _) = db.commit(None).await.unwrap();
                    let merkleized = durable.into_merkleized().await.unwrap();
                    let floor = merkleized.inactivity_floor_loc();
                    snapshots.push((merkleized.size().await, merkleized.root(), floor));
                    db = merkleized.into_mutable();
                }

                // Final commit to go back to Merkleized state.
                db.write_batch([(Sha256::fill(255), Some(Sha256::fill(0)))])
                    .await
                    .unwrap();
                let (durable, _) = db.commit(None).await.unwrap();
                let db = durable.into_merkleized().await.unwrap();

                // For each snapshot, verify partial_chunk_digest matches alignment
                // and the proof verifies against the correct root.
                for (size, root, floor) in &snapshots {
                    let start = Location::new_unchecked(core::cmp::max(**floor, 1));
                    let max_ops = NZU64!(4);
                    let (proof, ops, chunks) = db
                        .historical_range_proof(hasher.inner(), *size, start, max_ops)
                        .await
                        .unwrap();
                    let aligned = **size % 256 == 0;
                    assert_eq!(
                        proof.partial_chunk_digest.is_none(),
                        aligned,
                        "partial_chunk_digest should be None iff size ({}) is chunk-aligned",
                        **size
                    );
                    assert!(proof.verify(hasher.inner(), start, &ops, &chunks, root));
                }

                db.destroy().await.unwrap();
            })
            .await
        }};
    }

    // After 6 commits, verify each historical proof verifies only against its own root.
    macro_rules! test_historical_proof_many_commits {
        ($ctx:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_hp_mc");
            Box::pin(async {
                let mut hasher = StandardHasher::<Sha256>::new();
                let db: $db = open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await;
                let mut db = db.into_mutable();

                let mut snapshots = Vec::new();
                for round in 0u8..6 {
                    let base = round * 30;
                    for j in 0u8..30 {
                        let k = base.wrapping_add(j);
                        db.write_batch([(
                            Sha256::fill(k),
                            Some(Sha256::fill(k.wrapping_add(100))),
                        )])
                        .await
                        .unwrap();
                    }
                    let (durable, _) = db.commit(None).await.unwrap();
                    let merkleized = durable.into_merkleized().await.unwrap();
                    let floor = merkleized.inactivity_floor_loc();
                    snapshots.push((merkleized.size().await, merkleized.root(), floor));
                    db = merkleized.into_mutable();
                }

                // One more commit so we're back in Merkleized state.
                db.write_batch([(Sha256::fill(255), Some(Sha256::fill(0)))])
                    .await
                    .unwrap();
                let (durable, _) = db.commit(None).await.unwrap();
                let db = durable.into_merkleized().await.unwrap();

                // Verify each snapshot's proof against all roots. Start past
                // the inactivity floor to avoid the bitmap's pruned region.
                let max_ops = NZU64!(4);
                for (i, (size_i, root_i, floor_i)) in snapshots.iter().enumerate() {
                    let start = Location::new_unchecked(core::cmp::max(**floor_i, 1));
                    let (proof, ops, chunks) = db
                        .historical_range_proof(hasher.inner(), *size_i, start, max_ops)
                        .await
                        .unwrap();
                    assert!(
                        proof.verify(hasher.inner(), start, &ops, &chunks, root_i),
                        "proof at snapshot {i} must verify against its own root"
                    );
                    for (j, (_, root_j, _)) in snapshots.iter().enumerate() {
                        if i != j {
                            assert!(
                                !proof.verify(hasher.inner(), start, &ops, &chunks, root_j),
                                "proof at snapshot {i} must NOT verify against snapshot {j}'s root"
                            );
                        }
                    }
                }

                db.destroy().await.unwrap();
            })
            .await
        }};
    }

    // Verify max_ops=1 produces a single-operation proof at various positions.
    macro_rules! test_historical_proof_single_op {
        ($ctx:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_hp_so");
            Box::pin(async {
                let mut hasher = StandardHasher::<Sha256>::new();
                let db: $db = open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await;
                let mut db = db.into_mutable();

                for i in 0u8..50 {
                    db.write_batch([(Sha256::fill(i), Some(Sha256::fill(i + 100)))])
                        .await
                        .unwrap();
                }
                let (durable, _) = db.commit(None).await.unwrap();
                let merkleized = durable.into_merkleized().await.unwrap();
                let root = merkleized.root();
                let size = merkleized.size().await;

                // Second commit to make the first historical.
                let mut db = merkleized.into_mutable();
                db.write_batch([(Sha256::fill(200), Some(Sha256::fill(201)))])
                    .await
                    .unwrap();
                let (durable, _) = db.commit(None).await.unwrap();
                let db = durable.into_merkleized().await.unwrap();

                let max_ops = NZU64!(1);
                for offset in [0u64, 1, *size / 2, *size - 1] {
                    let start = Location::new_unchecked(offset);
                    let (proof, ops, chunks) = db
                        .historical_range_proof(hasher.inner(), size, start, max_ops)
                        .await
                        .unwrap();
                    assert_eq!(ops.len(), 1, "max_ops=1 should return exactly 1 op");
                    assert!(proof.verify(hasher.inner(), start, &ops, &chunks, &root));
                }

                db.destroy().await.unwrap();
            })
            .await
        }};
    }

    // Verify historical and current range proofs are equivalent at the latest
    // merkleized state.
    macro_rules! test_historical_proof_consistent_with_current {
        ($ctx:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_hp_cons");
            Box::pin(async {
                let mut hasher = StandardHasher::<Sha256>::new();
                let db: $db = open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await;
                let mut db = db.into_mutable();

                for i in 0u8..50 {
                    db.write_batch([(Sha256::fill(i), Some(Sha256::fill(i + 100)))])
                        .await
                        .unwrap();
                }
                let (durable, _) = db.commit(None).await.unwrap();
                let db = durable.into_merkleized().await.unwrap();
                let root = db.root();
                let size = db.size().await;

                let start = Location::new_unchecked(0);
                let max_ops = NZU64!(10);

                // Current range proof.
                let (current_proof, current_ops, current_chunks) = db
                    .range_proof(hasher.inner(), start, max_ops)
                    .await
                    .unwrap();
                assert!(current_proof.verify(
                    hasher.inner(),
                    start,
                    &current_ops,
                    &current_chunks,
                    &root
                ));

                // Historical range proof at current size should be equivalent.
                let (hist_proof, hist_ops, hist_chunks) = db
                    .historical_range_proof(hasher.inner(), size, start, max_ops)
                    .await
                    .unwrap();
                assert!(hist_proof.verify(hasher.inner(), start, &hist_ops, &hist_chunks, &root));

                // Ops and chunks must be identical.
                assert_eq!(current_ops, hist_ops);
                assert_eq!(current_chunks, hist_chunks);

                db.destroy().await.unwrap();
            })
            .await
        }};
    }

    // Verify error cases: out-of-bounds start_loc, non-commit-point historical_size,
    // and historical_size = 0.
    macro_rules! test_historical_proof_error_cases {
        ($ctx:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_hp_err");
            Box::pin(async {
                let mut hasher = StandardHasher::<Sha256>::new();
                let db: $db = open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await;
                let mut db = db.into_mutable();

                for i in 0u8..50 {
                    db.write_batch([(Sha256::fill(i), Some(Sha256::fill(i + 100)))])
                        .await
                        .unwrap();
                }
                let (durable, _) = db.commit(None).await.unwrap();
                let db = durable.into_merkleized().await.unwrap();
                let size = db.size().await;

                // start_loc == historical_size is out of bounds.
                assert!(matches!(
                    db.historical_range_proof(hasher.inner(), size, size, NZU64!(1))
                        .await,
                    Err(Error::Mmr(crate::mmr::Error::RangeOutOfBounds(_)))
                ));

                // start_loc > historical_size is out of bounds.
                let beyond = Location::new_unchecked(*size + 1);
                assert!(matches!(
                    db.historical_range_proof(hasher.inner(), size, beyond, NZU64!(1))
                        .await,
                    Err(Error::Mmr(crate::mmr::Error::RangeOutOfBounds(_)))
                ));

                // Non-commit-point historical_size returns NoBitmapCommit.
                let bad_size = Location::new_unchecked(*size + 1);
                let start = Location::new_unchecked(0);
                assert!(matches!(
                    db.historical_range_proof(hasher.inner(), bad_size, start, NZU64!(1))
                        .await,
                    Err(Error::NoBitmapCommit(_))
                ));

                // historical_size = 0 with start_loc = 0 fails (0 >= 0).
                let zero = Location::new_unchecked(0);
                assert!(matches!(
                    db.historical_range_proof(hasher.inner(), zero, zero, NZU64!(1))
                        .await,
                    Err(Error::Mmr(crate::mmr::Error::RangeOutOfBounds(_)))
                ));

                db.destroy().await.unwrap();
            })
            .await
        }};
    }

    // Verify that a range proof spanning two bitmap chunks (crossing the 256-op
    // boundary) returns chunks from both and verifies correctly.
    macro_rules! test_historical_proof_range_across_chunks {
        ($ctx:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_hp_rac");
            Box::pin(async {
                let mut hasher = StandardHasher::<Sha256>::new();
                let db: $db = open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await;
                let mut db = db.into_mutable();

                // Write keys across multiple commits until we pass 256 ops.
                let mut last_size = Location::new_unchecked(0);
                let mut last_root = None;
                let mut i = 0u16;
                while *last_size < 300 {
                    for _ in 0..50 {
                        let b = (i % 256) as u8;
                        db.write_batch([(
                            Sha256::fill(b),
                            Some(Sha256::fill(b.wrapping_add(100))),
                        )])
                        .await
                        .unwrap();
                        i += 1;
                    }
                    let (durable, _) = db.commit(None).await.unwrap();
                    let merkleized = durable.into_merkleized().await.unwrap();
                    last_size = merkleized.size().await;
                    last_root = Some(merkleized.root());
                    db = merkleized.into_mutable();
                }

                // One more commit to make the target historical.
                db.write_batch([(Sha256::fill(255), Some(Sha256::fill(0)))])
                    .await
                    .unwrap();
                let (durable, _) = db.commit(None).await.unwrap();
                let db = durable.into_merkleized().await.unwrap();

                // Request a range spanning the chunk boundary at op 256.
                let start = Location::new_unchecked(250);
                let max_ops = NZU64!(12);
                let (proof, ops, chunks) = db
                    .historical_range_proof(hasher.inner(), last_size, start, max_ops)
                    .await
                    .unwrap();
                assert_eq!(ops.len(), 12);
                assert!(
                    chunks.len() >= 2,
                    "range [250, 262) should span at least 2 bitmap chunks"
                );
                assert!(proof.verify(hasher.inner(), start, &ops, &chunks, &last_root.unwrap()));

                db.destroy().await.unwrap();
            })
            .await
        }};
    }

    // After updates and deletes, verify historical proofs at both the old and new
    // commit sizes reflect the correct activity state.
    macro_rules! test_historical_proof_updates_and_deletes {
        ($ctx:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_hp_ud");
            Box::pin(async {
                let mut hasher = StandardHasher::<Sha256>::new();
                let db: $db = open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await;

                // Phase 1: 50 unique keys.
                let mut db = db.into_mutable();
                for i in 0u8..50 {
                    db.write_batch([(Sha256::fill(i), Some(Sha256::fill(i + 100)))])
                        .await
                        .unwrap();
                }
                let (durable, _) = db.commit(None).await.unwrap();
                let merkleized = durable.into_merkleized().await.unwrap();
                let root1 = merkleized.root();
                let size1 = merkleized.size().await;

                // Phase 2: Update first 25 keys, delete next 10.
                let mut db = merkleized.into_mutable();
                for i in 0u8..25 {
                    db.write_batch([(Sha256::fill(i), Some(Sha256::fill(i + 200)))])
                        .await
                        .unwrap();
                }
                for i in 25u8..35 {
                    db.write_batch([(Sha256::fill(i), None)]).await.unwrap();
                }
                let (durable, _) = db.commit(None).await.unwrap();
                let db = durable.into_merkleized().await.unwrap();
                let root2 = db.root();
                let size2 = db.size().await;

                assert_ne!(root1, root2);

                let start = Location::new_unchecked(0);
                let max_ops = NZU64!(10);

                // Historical proof at size1 reflects the pre-update state.
                let (proof1, ops1, chunks1) = db
                    .historical_range_proof(hasher.inner(), size1, start, max_ops)
                    .await
                    .unwrap();
                assert!(proof1.verify(hasher.inner(), start, &ops1, &chunks1, &root1));
                assert!(!proof1.verify(hasher.inner(), start, &ops1, &chunks1, &root2));

                // Historical proof at size2 reflects the post-update state.
                let (proof2, ops2, chunks2) = db
                    .historical_range_proof(hasher.inner(), size2, start, max_ops)
                    .await
                    .unwrap();
                assert!(proof2.verify(hasher.inner(), start, &ops2, &chunks2, &root2));
                assert!(!proof2.verify(hasher.inner(), start, &ops2, &chunks2, &root1));

                db.destroy().await.unwrap();
            })
            .await
        }};
    }

    // After pruning, historical proofs at surviving commit sizes still verify,
    // while proofs at pruned sizes return NoBitmapCommit.
    macro_rules! test_historical_proof_survives_pruning {
        ($ctx:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_hp_sp");
            Box::pin(async {
                let mut hasher = StandardHasher::<Sha256>::new();
                let db: $db = open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await;
                let mut db = db.into_mutable();

                // 3 commits of 100 keys each.
                let mut snapshots = Vec::new();
                for round in 0u16..3 {
                    for j in 0u16..100 {
                        let k = (round * 100 + j) as u8;
                        db.write_batch([(Sha256::fill(k), Some(Sha256::fill(k.wrapping_add(50))))])
                            .await
                            .unwrap();
                    }
                    let (durable, _) = db.commit(None).await.unwrap();
                    let merkleized = durable.into_merkleized().await.unwrap();
                    snapshots.push((merkleized.size().await, merkleized.root()));
                    db = merkleized.into_mutable();
                }

                // Convert to merkleized for pruning.
                let (durable, _) = db.commit(None).await.unwrap();
                let mut db = durable.into_merkleized().await.unwrap();
                let final_root = db.root();
                let final_size = db.size().await;
                snapshots.push((final_size, final_root));

                // Prune to inactivity floor. After this, the ops MMR no longer
                // serves locations below the floor.
                let floor = db.inactivity_floor_loc();
                assert!(*floor > 0, "floor must advance to exercise pruning");
                db.prune(floor).await.unwrap();

                // All proofs must start at or after the current floor since
                // the ops MMR has been pruned to that point.
                let safe_start = Location::new_unchecked(*floor);
                let max_ops = NZU64!(4);

                // Proofs at the latest snapshot should work.
                let (proof, ops, chunks) = db
                    .historical_range_proof(hasher.inner(), final_size, safe_start, max_ops)
                    .await
                    .unwrap();
                assert!(proof.verify(hasher.inner(), safe_start, &ops, &chunks, &final_root));

                // The earliest snapshot may or may not survive pruning depending
                // on how far the inactivity floor advances (variant-dependent).
                let (size1, root1) = snapshots[0];
                match db
                    .historical_range_proof(hasher.inner(), size1, safe_start, max_ops)
                    .await
                {
                    Ok((proof, ops, chunks)) => {
                        assert!(proof.verify(hasher.inner(), safe_start, &ops, &chunks, &root1));
                    }
                    Err(Error::NoBitmapCommit(_)) => {
                        // Expected: bitmap commit for this size was discarded by prune.
                    }
                    Err(Error::Mmr(crate::mmr::Error::RangeOutOfBounds(_))) => {
                        // Expected: safe_start >= size1 (entire snapshot pruned).
                        assert!(safe_start >= size1);
                    }
                    Err(e) => panic!("unexpected error for snapshot 0: {e}"),
                }

                db.destroy().await.unwrap();
            })
            .await
        }};
    }

    // Verify historical proofs still work after enough pruning to advance
    // the grafted MMR boundary (pinned nodes cover the pruned region).
    macro_rules! test_historical_proof_prune_advances_grafted_boundary {
        ($ctx:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_hp_pgb");
            Box::pin(async {
                let mut hasher = StandardHasher::<Sha256>::new();
                let db: $db = open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await;
                let mut db = db.into_mutable();

                // 5 rounds: write 100 keys (with updates to advance the inactivity
                // floor), commit, merkleize, prune.
                let mut snapshots = Vec::new();
                for round in 0u8..5 {
                    // Fresh keys for each round, plus update some from previous
                    // rounds to deactivate old locations and advance the floor.
                    let base = round * 50;
                    for j in 0u8..50 {
                        let k = base.wrapping_add(j);
                        db.write_batch([(
                            Sha256::fill(k),
                            Some(Sha256::fill(k.wrapping_add(100))),
                        )])
                        .await
                        .unwrap();
                    }
                    // Re-write keys from the previous round to deactivate old ops.
                    if round > 0 {
                        let prev_base = (round - 1) * 50;
                        for j in 0u8..50 {
                            let k = prev_base.wrapping_add(j);
                            db.write_batch([(
                                Sha256::fill(k),
                                Some(Sha256::fill(k.wrapping_add(200))),
                            )])
                            .await
                            .unwrap();
                        }
                    }

                    let (durable, _) = db.commit(None).await.unwrap();
                    let mut merkleized = durable.into_merkleized().await.unwrap();
                    snapshots.push((merkleized.size().await, merkleized.root()));

                    // Prune to inactivity floor.
                    let floor = merkleized.inactivity_floor_loc();
                    if *floor > 0 {
                        merkleized.prune(floor).await.unwrap();
                    }
                    db = merkleized.into_mutable();
                }

                // Final commit to make the last snapshot historical.
                db.write_batch([(Sha256::fill(255), Some(Sha256::fill(0)))])
                    .await
                    .unwrap();
                let (durable, _) = db.commit(None).await.unwrap();
                let db = durable.into_merkleized().await.unwrap();

                // All proofs must start past the current inactivity floor since
                // the ops MMR has been pruned up to that point. The floor must
                // have advanced given the key re-writes in each round.
                let current_floor = db.inactivity_floor_loc();
                assert!(*current_floor > 0);
                let safe_start = Location::new_unchecked(*current_floor);
                let max_ops = NZU64!(8);

                // Each snapshot must either produce a valid proof or fail
                // with a well-defined error.
                for (size_i, root_i) in &snapshots {
                    match db
                        .historical_range_proof(hasher.inner(), *size_i, safe_start, max_ops)
                        .await
                    {
                        Ok((proof, ops, chunks)) => {
                            assert!(proof.verify(
                                hasher.inner(),
                                safe_start,
                                &ops,
                                &chunks,
                                root_i
                            ));
                        }
                        Err(Error::NoBitmapCommit(_)) => {
                            // Expected: bitmap commit for this size was discarded.
                        }
                        Err(Error::Mmr(crate::mmr::Error::RangeOutOfBounds(_))) => {
                            // Expected: safe_start >= size (entire snapshot pruned).
                            assert!(safe_start >= *size_i);
                        }
                        Err(e) => panic!("unexpected error for snapshot at size {size_i}: {e}"),
                    }
                }

                db.destroy().await.unwrap();
            })
            .await
        }};
    }

    // Verify that prune() does not discard the "transition" commit -- the commit
    // where pruned_chunks crosses the min_safe threshold during its dirty period.
    //
    // Setup:
    //   Round 1: write 256 unique keys (fills bitmap chunk 0, all active)
    //   Round 2: rewrite same 256 keys (chunk 0 becomes all-inactive, chunk 1 active)
    //            merkleize prunes chunk 0: diff.pruned_chunks=0, post-commit pruned=1
    //   Round 3: write 1 more key to create a newer commit
    //   Prune ops to inactivity floor (>= 256), so min_safe >= 1
    //
    // The round-2 commit is the transition commit. Its post-commit pruned_chunks (1)
    // meets min_safe, so it must survive pruning and produce a valid historical proof.
    macro_rules! test_historical_proof_prune_keeps_transition_commit {
        ($ctx:expr, $l:literal, $db:ty, $cfg:ident) => {{
            let p = concat!($l, "_hp_tc");
            Box::pin(async {
                let mut hasher = StandardHasher::<Sha256>::new();
                let db: $db = open_db_fn!($db, $cfg)($ctx.with_label($l), p.into()).await;
                let mut db = db.into_mutable();

                // Round 1: write 256 unique keys (fills chunk 0).
                for k in 0u16..256 {
                    let key = Sha256::fill(k as u8);
                    let value = Sha256::fill(k.wrapping_add(100) as u8);
                    db.write_batch([(key, Some(value))]).await.unwrap();
                }
                let (durable, _) = db.commit(None).await.unwrap();
                let merkleized = durable.into_merkleized().await.unwrap();
                let size1 = merkleized.size().await;

                // After round 1: record the baseline pruned_chunks and verify
                // the bitmap commit is recorded.
                let pruned_after_r1 = merkleized.status.pruned_chunks();
                assert!(
                    merkleized.status.commit_exists(*size1),
                    "round 1: bitmap commit at size1 ({size1}) should exist"
                );

                db = merkleized.into_mutable();

                // Round 2: rewrite the same 256 keys, deactivating chunk 0.
                for k in 0u16..256 {
                    let key = Sha256::fill(k as u8);
                    let value = Sha256::fill(k.wrapping_add(200) as u8);
                    db.write_batch([(key, Some(value))]).await.unwrap();
                }
                let (durable, _) = db.commit(None).await.unwrap();
                let merkleized = durable.into_merkleized().await.unwrap();
                let transition_size = merkleized.size().await;
                let transition_root = merkleized.root();

                // After round 2: rewrites deactivated the original 256 ops, so
                // pruned_chunks must have increased (chunk with those ops is now
                // all-inactive and pruned by into_merkleized).
                let pruned_after_r2 = merkleized.status.pruned_chunks();
                assert!(
                    pruned_after_r2 > pruned_after_r1,
                    "round 2: pruned_chunks should increase ({pruned_after_r2} > {pruned_after_r1})"
                );
                // The transition commit should be recorded at transition_size.
                assert!(
                    merkleized.status.commit_exists(*transition_size),
                    "round 2: bitmap commit at transition_size ({transition_size}) should exist"
                );

                db = merkleized.into_mutable();

                // Round 3: write one more key to create a newer commit.
                db.write_batch([(Sha256::fill(0), Some(Sha256::fill(42)))])
                    .await
                    .unwrap();
                let (durable, _) = db.commit(None).await.unwrap();
                let mut db = durable.into_merkleized().await.unwrap();
                let size3 = db.size().await;

                // After round 3: transition commit and round 3 commit both exist.
                assert!(
                    db.status.commit_exists(*transition_size),
                    "round 3 (pre-prune): transition commit should exist"
                );
                assert!(
                    db.status.commit_exists(*size3),
                    "round 3 (pre-prune): round 3 commit should exist"
                );

                // Prune to inactivity floor.
                let floor = db.inactivity_floor_loc();
                assert!(
                    *floor >= 256,
                    "floor ({floor}) must be >= 256 to prune chunk 0"
                );
                db.prune(floor).await.unwrap();

                // After pruning, the transition commit must survive because its
                // post-commit pruned_chunks meets min_safe.
                assert!(
                    db.status.commit_exists(*transition_size),
                    "post-prune: transition commit at {transition_size} must survive"
                );
                // Round 1 commit should be removed (its post-commit pruned_chunks
                // is below min_safe).
                assert!(
                    !db.status.commit_exists(*size1),
                    "post-prune: round 1 commit at {size1} should be removed"
                );

                // Reconstruct the bitmap at the transition commit and verify its
                // pruned_chunks matches what we observed after round 2.
                let historical = db.status.get_at_commit(*transition_size)
                    .expect("transition commit bitmap must be reconstructable");
                assert_eq!(
                    historical.pruned_chunks(), pruned_after_r2,
                    "historical bitmap pruned_chunks should match round 2 state"
                );

                // The transition commit (round 2) must produce a valid historical proof.
                let safe_start = Location::new_unchecked(*floor);
                assert!(
                    safe_start < transition_size,
                    "safe_start ({safe_start}) must be < transition_size ({transition_size})"
                );
                let max_ops = NZU64!(4);
                let (proof, ops, chunks) = db
                    .historical_range_proof(
                        hasher.inner(),
                        transition_size,
                        safe_start,
                        max_ops,
                    )
                    .await
                    .expect("transition commit should survive pruning");
                assert!(
                    proof.verify(hasher.inner(), safe_start, &ops, &chunks, &transition_root),
                    "proof at transition commit must verify"
                );

                db.destroy().await.unwrap();
            })
            .await
        }};
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
        ($ctx:expr, $sfx:expr, with_db: $f:expr) => {{
            with_all_variants!(test_with_db!($ctx, $sfx, $f));
        }};
        ($ctx:expr, historical_proof) => {{
            with_all_variants!(test_historical_proof!($ctx));
        }};
        ($ctx:expr, $macro_name:ident) => {{
            with_all_variants!($macro_name!($ctx));
        }};
    }

    // Wrapper functions for build_big tests with ordered/unordered expected values.
    fn test_ordered_build_big<C, F, Fut>(open_db: F)
    where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        test_current_db_build_big::<C, F, Fut>(open_db, 3478, 2620);
    }

    fn test_unordered_build_big<C, F, Fut>(open_db: F)
    where
        C: CleanAny,
        C::Key: TestKey,
        <C as LogStore>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        test_current_db_build_big::<C, F, Fut>(open_db, 1957, 838);
    }

    #[test_traced("WARN")]
    fn test_all_variants_build_random_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_build_random_close_reopen);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_simulate_write_failures() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_simulate_write_failures);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_different_pruning_delays_same_root() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_different_pruning_delays_same_root);
        });
    }

    #[test_traced("WARN")]
    fn test_all_variants_sync_persists_bitmap_pruning_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_sync_persists_bitmap_pruning_boundary);
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_variants_build_big() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(ordered: test_ordered_build_big);
        });
    }

    #[test_traced("WARN")]
    fn test_unordered_variants_build_big() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(unordered: test_unordered_build_big);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_steps_not_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, "snr", with_db: crate::qmdb::any::test::test_any_db_steps_not_reset);
        });
    }

    #[test_traced("DEBUG")]
    fn test_ordered_variants_build_small_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(ordered: ordered::tests::test_build_small_close_reopen);
        });
    }

    #[test_traced("DEBUG")]
    fn test_unordered_variants_build_small_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(unordered: unordered::tests::test_build_small_close_reopen);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_historical_range_proofs() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, historical_proof);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_historical_proof_partial_chunk() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, test_historical_proof_partial_chunk);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_historical_proof_chunk_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, test_historical_proof_chunk_boundary);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_historical_proof_many_commits() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, test_historical_proof_many_commits);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_historical_proof_single_op() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, test_historical_proof_single_op);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_historical_proof_consistent_with_current() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, test_historical_proof_consistent_with_current);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_historical_proof_error_cases() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, test_historical_proof_error_cases);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_historical_proof_range_across_chunks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, test_historical_proof_range_across_chunks);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_historical_proof_updates_and_deletes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, test_historical_proof_updates_and_deletes);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_historical_proof_survives_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, test_historical_proof_survives_pruning);
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_historical_proof_prune_advances_grafted_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(
                context,
                test_historical_proof_prune_advances_grafted_boundary
            );
        });
    }

    #[test_traced("DEBUG")]
    fn test_all_variants_historical_proof_prune_keeps_transition_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for_all_variants!(context, test_historical_proof_prune_keeps_transition_commit);
        });
    }
}
