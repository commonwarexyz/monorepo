//! A _Current_ authenticated database provides succinct proofs of _any_ value ever associated with
//! a key, and also whether that value is the _current_ value associated with it.
//!
//! # Examples
//!
//! See [`crate::qmdb::any`] for batch API examples (forking, sequential
//! commit, staleness). The Current layer uses the same batch API.
//!
//! # Motivation
//!
//! An [crate::qmdb::any] ("Any") database can prove that a key had a particular value at some
//! point, but it cannot prove that the value is still current -- some later operation may have
//! updated or deleted it. A Current database adds exactly this capability by maintaining a bitmap
//! that tracks which operations are _active_ (i.e. represent the current state of their key).
//!
//! To make this useful, a verifier needs both the operation and its activity status authenticated
//! under a single root. We achieve this by _grafting_ bitmap chunks onto the operations tree.
//!
//! # Data structures
//!
//! A Current database ([db::Db]) wraps an Any database and adds:
//!
//! - **Status bitmap** ([BitMap]): One bit per operation in the log. Bit _i_ is 1 if
//!   operation _i_ is active, 0 otherwise. The bitmap is divided into fixed-size chunks of `N`
//!   bytes (i.e. `N * 8` bits each). `N` must be a power of two.
//!
//! - **Grafted tree**: An in-memory Merkle structure of digests at and above the
//!   _grafting height_ in the ops tree. This is the core of how bitmap and ops state are combined
//!   into a single authenticated structure (see below).
//!
//! - **Bitmap metadata** (`Metadata`): Persists the pruning boundary and "pinned" digests needed
//!   to restore the grafted tree after pruning old bitmap chunks.
//!
//! # Grafting: combining the activity status bitmap and the ops tree
//!
//! ## The problem
//!
//! Naively authenticating the bitmap and ops tree as two independent Merkle structures would
//! require two separate proofs per operation -- one for the operation's value, one for its
//! activity status. This doubles proof sizes.
//!
//! ## The solution
//!
//! We combine ("graft") the two structures at a specific height in the ops tree called the
//! _grafting height_. The grafting height `h = log2(N * 8)` is chosen so that each subtree of
//! height `h` in the ops tree covers exactly one bitmap chunk's worth of operations.
//!
//! At the grafting height, instead of using the ops tree's own subtree root, we replace it with a
//! _grafted leaf_ digest that incorporates both the bitmap chunk and the ops subtree root:
//!
//! ```text
//! grafted_leaf = hash(bitmap_chunk || ops_subtree_root)   // non-zero chunk
//! grafted_leaf = ops_subtree_root                         // all-zero chunk (identity)
//! ```
//!
//! The all-zero identity means that for pruned regions (where every operation is inactive), the
//! grafted tree is structurally identical to the ops tree at and above the grafting height.
//!
//! Above the grafting height, internal nodes use standard hashing over the grafted leaves.
//! Below the grafting height, the ops tree is unchanged.
//!
//! ## Example
//!
//! Consider 8 operations with `N = 1` (8-bit chunks, so `h = log2(8) = 3`). But to illustrate
//! the structure more clearly, let's use a smaller example: 8 operations with chunk size 4 bits
//! (`h = 2`), yielding 2 complete bitmap chunks:
//!
//! ```text
//! Ops tree positions (8 leaves):
//!
//!   Height
//!     3              14                    <-- peak: digest commits to ops tree and bitmap chunks
//!                  /    \
//!                 /      \
//!                /        \
//!     2  [G]    6          13    [G]       <-- grafting height: grafted leaves
//!             /   \      /    \
//!     1      2     5    9     12           <-- below grafting height: pure ops tree nodes
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
//! Position 14 (above grafting height) is a standard internal node:
//! - `pos 14: hash(14 || digest(pos 6) || digest(pos 13))`
//!
//! The grafted tree stores positions 6, 13, and 14. The ops tree stores everything below
//! (positions 0-5 and 7-12). Together they form a single virtual Merkle structure whose root
//! authenticates
//! both the operations and their activity status.
//!
//! ## Proof generation and verification
//!
//! To prove that operation _i_ is active, we provide:
//! 1. An inclusion proof for the operation's leaf, using the virtual (grafted) storage.
//! 2. The bitmap chunk containing bit _i_.
//!
//! The verifier (see `grafting::Verifier`) walks the proof from leaf to root. Below the grafting
//! height, it uses standard hashing. At the grafting height, it detects the boundary and
//! reconstructs the grafted leaf from the chunk and the ops subtree root. For non-zero chunks
//! the grafted leaf is `hash(chunk || ops_subtree_root)`; for all-zero chunks the grafted leaf
//! is the ops subtree root itself (identity optimization -- see `grafting::Verifier::node`).
//! Above the grafting height, it resumes standard hashing. If the reconstructed root
//! matches the expected root and bit _i_ is set in the chunk, the operation is proven active.
//!
//! This is a single proof path, not two independent ones -- the bitmap chunk is embedded in the
//! proof verification at the grafting boundary.
//!
//! ## Partial chunks
//!
//! Operations arrive continuously, so the last bitmap chunk is usually incomplete (fewer than
//! `N * 8` bits). An incomplete chunk has no grafted leaf in the cache because there is no
//! corresponding complete subtree in the ops tree. To still authenticate these bits, the partial
//! chunk's digest and bit count are folded into the canonical root hash:
//!
//! ```text
//! root = hash(ops_root || grafted_root || next_bit || hash(partial_chunk))
//! ```
//!
//! where `next_bit` is the index of the next unset position in the partial chunk and
//! `grafted_root` is the root of the grafted tree (which covers only complete chunks).
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
//! root = hash(ops_root || grafted_root [|| next_bit || hash(partial_chunk)])
//! ```
//!
//! where `grafted_root` is the root of the grafted tree (covering only complete
//! bitmap chunks), `next_bit` is the index of the next unset position in the partial chunk, and
//! `hash(partial_chunk)` is the digest of the incomplete trailing chunk. The partial chunk
//! components are only present when the last bitmap chunk is incomplete.
//!
//! This combines two (or three) components into a single hash:
//!
//! - **Ops root**: The root of the raw operations tree (the inner [crate::qmdb::any] database's
//!   root). Used for state sync, where a client downloads operations and verifies each batch
//!   against this root using standard Merkle range proofs.
//!
//! - **Grafted root**: The root of the grafted tree (overlaying bitmap chunks
//!   with ops subtree roots). Used for proofs about operation values and their activity status.
//!   See [RangeProof](proof::RangeProof) and [OperationProof](proof::OperationProof).
//!
//! - **Partial chunk** (optional): When operations arrive continuously, the last bitmap chunk is
//!   usually incomplete. Its digest and bit count are folded into the canonical root hash.
//!
//! The canonical root is returned by [Db](db::Db)`::`[root()](db::Db::root).
//! The ops root is returned by the `sync::Database` trait's `root()` method, since the sync engine
//! verifies batches against the ops root, not the canonical root.
//!
//! For state sync, the sync engine targets the ops root and verifies each batch against it.
//! After sync, the bitmap and grafted tree are reconstructed deterministically from the
//! operations, and the canonical root is computed. Validating that the ops root is part of the
//! canonical root is the caller's responsibility; the sync engine does not perform this check.

use crate::{
    index::Factory as IndexFactory,
    journal::{
        authenticated::Inner,
        contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    },
    merkle::{self, Location},
    mmr::{journaled::Config as MmrConfig, StandardHasher},
    qmdb::{
        any::{
            self,
            operation::{Operation, Update},
            Config as AnyConfig,
        },
        operation::Committable,
    },
    translator::Translator,
    Context,
};
use commonware_codec::{CodecShared, FixedSize};
use commonware_cryptography::Hasher;
use commonware_utils::{bitmap::Prunable as BitMap, sync::AsyncMutex};
use std::sync::Arc;

pub mod batch;
pub mod db;
mod grafting;

pub mod ordered;
pub mod proof;
pub(crate) mod sync;
pub mod unordered;

/// Configuration for a `Current` authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator, J> {
    /// Configuration for the Merkle structure backing the authenticated journal.
    pub merkle_config: MmrConfig,

    /// Configuration for the operations log journal.
    pub journal_config: J,

    /// The name of the storage partition used for grafted tree metadata.
    pub grafted_metadata_partition: String,

    /// The translator used by the compressed index.
    pub translator: T,
}

impl<T: Translator, J> From<Config<T, J>> for AnyConfig<T, J> {
    fn from(cfg: Config<T, J>) -> Self {
        Self {
            merkle_config: cfg.merkle_config,
            journal_config: cfg.journal_config,
            translator: cfg.translator,
        }
    }
}

/// Configuration for a `Current` authenticated db with fixed-size values.
pub type FixedConfig<T> = Config<T, FConfig>;

/// Configuration for a `Current` authenticated db with variable-sized values.
pub type VariableConfig<T, C> = Config<T, VConfig<C>>;

/// Initialize a `Current` authenticated db from the given config.
pub(super) async fn init<F, E, U, H, T, I, J, const N: usize>(
    context: E,
    config: Config<T, J::Config>,
) -> Result<db::Db<F, E, J, I, H, U, N>, crate::qmdb::Error<F>>
where
    F: merkle::Graftable,
    E: Context,
    U: Update + Send + Sync,
    H: Hasher,
    T: Translator,
    I: IndexFactory<T, Value = Location<F>>,
    J: Inner<E, Item = Operation<F, U>>,
    Operation<F, U>: Committable + CodecShared,
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

    let thread_pool = config.merkle_config.thread_pool.clone();
    let metadata_partition = config.grafted_metadata_partition.clone();

    // Load bitmap metadata (pruned_chunks + pinned nodes for the grafted tree).
    let (metadata, pruned_chunks, pinned_nodes) =
        db::init_metadata(context.with_label("metadata"), &metadata_partition).await?;

    // Initialize the activity status bitmap.
    let mut status = BitMap::<N>::new_with_pruned_chunks(pruned_chunks)
        .map_err(|_| crate::qmdb::Error::<F>::DataCorrupted("pruned chunks overflow"))?;

    // Initialize the anydb with a callback that populates the status bitmap.
    let last_known_inactivity_floor = Location::new(status.len());
    let any = any::init(
        context.with_label("any"),
        config.into(),
        Some(last_known_inactivity_floor),
        |append: bool, loc: Option<Location<F>>| {
            status.push(append);
            if let Some(loc) = loc {
                status.set_bit(*loc, false);
            }
        },
    )
    .await?;

    // Build the grafted tree from the bitmap and ops tree.
    let hasher = StandardHasher::<H>::new();
    let grafted_tree = db::build_grafted_tree::<F, H, N>(
        &hasher,
        &status,
        &pinned_nodes,
        &any.log.merkle,
        thread_pool.as_ref(),
    )
    .await?;

    // Compute and cache the root.
    let storage = grafting::Storage::new(&grafted_tree, grafting::height::<N>(), &any.log.merkle);
    let partial_chunk = db::partial_chunk(&status);
    let ops_root = any.log.root();
    let root = db::compute_db_root(&hasher, &status, &storage, partial_chunk, &ops_root).await?;

    Ok(db::Db {
        any,
        status: batch::BitmapBatch::Base(Arc::new(status)),
        grafted_tree,
        metadata: AsyncMutex::new(metadata),
        thread_pool,
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
    use super::{ordered, unordered, FConfig, FixedConfig, MmrConfig, VConfig, VariableConfig};
    use crate::{
        merkle::{self, mmb, mmr},
        qmdb::{
            any::{
                test::colliding_digest,
                traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
            },
            store::tests::{TestKey, TestValue},
        },
        translator::Translator,
    };
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        BufferPooler, Metrics, Runner as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use core::future::Future;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::num::{NonZeroU16, NonZeroUsize};
    use tracing::warn;

    type Error<F> = crate::qmdb::Error<F>;
    type Location<F> = merkle::Location<F>;
    type WriteVec<F, C> = Vec<(<C as DbAny<F>>::Key, Option<<C as DbAny<F>>::Value>)>;

    // Janky page & cache sizes to exercise boundary conditions.
    pub(crate) const PAGE_SIZE: NonZeroU16 = NZU16!(88);
    pub(crate) const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);

    pub(crate) fn test_page_cache(ctx: &(impl BufferPooler + Metrics)) -> CacheRef {
        CacheRef::from_pooler(ctx.clone(), PAGE_SIZE, PAGE_CACHE_SIZE)
    }

    /// Shared config factory for fixed-value Current QMDB tests.
    pub(crate) fn fixed_config<T: Translator + Default>(
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> FixedConfig<T> {
        FixedConfig {
            merkle_config: MmrConfig {
                journal_partition: format!("{partition_prefix}-journal-partition"),
                metadata_partition: format!("{partition_prefix}-metadata-partition"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            journal_config: FConfig {
                partition: format!("{partition_prefix}-partition-prefix"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            grafted_metadata_partition: format!("{partition_prefix}-grafted-metadata-partition"),
            translator: T::default(),
        }
    }

    /// Shared config factory for variable-value Current QMDB tests with unit codec config.
    pub(crate) fn variable_config<T: Translator + Default>(
        partition_prefix: &str,
        page_cache: CacheRef,
    ) -> VariableConfig<T, ((), ())> {
        VariableConfig {
            merkle_config: MmrConfig {
                journal_partition: format!("{partition_prefix}-journal-partition"),
                metadata_partition: format!("{partition_prefix}-metadata-partition"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            journal_config: VConfig {
                partition: format!("{partition_prefix}-partition-prefix"),
                items_per_section: NZU64!(7),
                compression: None,
                codec_config: ((), ()),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            grafted_metadata_partition: format!("{partition_prefix}-grafted-metadata-partition"),
            translator: T::default(),
        }
    }

    /// Commit a set of writes as a single batch.
    async fn commit_writes<F: merkle::Graftable, C: DbAny<F>>(
        db: &mut C,
        writes: impl IntoIterator<Item = (C::Key, Option<<C as DbAny<F>>::Value>)>,
    ) -> Result<(), Error<F>> {
        let mut batch = db.new_batch();
        for (k, v) in writes {
            batch = batch.write(k, v);
        }
        let merkleized = batch.merkleize(db, None).await?;
        db.apply_batch(merkleized).await?;
        db.commit().await?;
        Ok(())
    }

    /// Apply random operations to the given db, committing them (randomly and at the end) only if
    /// `commit_changes` is true. Returns the db; callers should commit if needed.
    ///
    /// Returns a boxed future to prevent stack overflow when monomorphized across many DB variants.
    async fn apply_random_ops_inner<F, C>(
        num_elements: u64,
        commit_changes: bool,
        rng_seed: u64,
        mut db: C,
    ) -> Result<C, Error<F>>
    where
        F: merkle::Graftable,
        C: DbAny<F>,
        C::Key: TestKey,
        <C as DbAny<F>>::Value: TestValue,
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
        let mut pending: WriteVec<F, C> = Vec::new();
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

    pub fn apply_random_ops<F, C>(
        num_elements: u64,
        commit_changes: bool,
        rng_seed: u64,
        db: C,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<C, Error<F>>>>>
    where
        F: merkle::Graftable + 'static,
        C: DbAny<F> + 'static,
        C::Key: TestKey,
        <C as DbAny<F>>::Value: TestValue,
    {
        Box::pin(apply_random_ops_inner::<F, C>(
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
    pub fn test_build_random_close_reopen<M, C, F, Fut>(mut open_db: F)
    where
        M: merkle::Graftable + 'static,
        C: DbAny<M> + 'static,
        C::Key: TestKey,
        <C as DbAny<M>>::Value: TestValue,
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
            db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed, db)
                .await
                .unwrap();
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
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
            db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed, db)
                .await
                .unwrap();
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
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
    pub fn test_simulate_write_failures<M, C, F, Fut>(mut open_db: F)
    where
        M: merkle::Graftable + 'static,
        C: DbAny<M> + 'static,
        C::Key: TestKey,
        <C as DbAny<M>>::Value: TestValue,
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
                db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed, db)
                    .await
                    .unwrap();
                commit_writes(&mut db, []).await.unwrap();
                let committed_root = db.root();
                let committed_op_count = db.bounds().await.end;
                let committed_inactivity_floor = db.inactivity_floor_loc().await;
                db.prune(committed_inactivity_floor).await.unwrap();

                // Perform more random operations without committing any of them.
                let db = apply_random_ops::<M, C>(ELEMENTS, false, rng_seed + 1, db)
                    .await
                    .unwrap();

                // SCENARIO #1: Simulate a crash that happens before any writes. Upon reopening, the
                // state of the DB should be as of the last commit.
                drop(db);
                let db: C = open_db(context.with_label("scenario1"), partition.clone()).await;
                assert_eq!(db.root(), committed_root);
                assert_eq!(db.bounds().await.end, committed_op_count);

                // Re-apply the exact same operations, this time committed.
                let db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed + 1, db)
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
                db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed, db)
                    .await
                    .unwrap();
                commit_writes(&mut db, []).await.unwrap();
                db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed + 1, db)
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
    pub fn test_different_pruning_delays_same_root<M, C, F, Fut>(mut open_db: F)
    where
        M: merkle::Graftable,
        C: DbAny<M>,
        C::Key: TestKey,
        <C as DbAny<M>>::Value: TestValue,
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
            let mut pending_no_pruning: WriteVec<M, C> = Vec::new();
            let mut pending_pruning: WriteVec<M, C> = Vec::new();
            for i in 0..NUM_OPERATIONS {
                let key: C::Key = TestKey::from_seed(i);
                let value: <C as DbAny<M>>::Value = TestValue::from_seed(i * 1000);

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
    pub fn test_sync_persists_bitmap_pruning_boundary<M, C, F, Fut>(mut open_db: F)
    where
        M: merkle::Graftable + 'static,
        C: DbAny<M> + BitmapPrunedBits + 'static,
        C::Key: TestKey,
        <C as DbAny<M>>::Value: TestValue,
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
            db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed, db).await.unwrap();
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();

            // Prune to flatten bitmap layers and advance pruned_chunks.
            let floor = db.inactivity_floor_loc().await;
            db.prune(floor).await.unwrap();

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
                "Expected bitmap to have pruned bits after prune()"
            );

            // Call sync() to persist the bitmap pruning boundary.
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
    pub fn test_current_db_build_big<M, C, F, Fut>(mut open_db: F)
    where
        M: merkle::Graftable,
        C: DbAny<M>,
        C::Key: TestKey,
        <C as DbAny<M>>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        let mut open_db_clone = open_db.clone();
        executor.start(|context| async move {
            let mut db: C = open_db_clone(context.with_label("first"), "build-big".into()).await;

            let mut map = std::collections::HashMap::<C::Key, <C as DbAny<M>>::Value>::default();

            // All creates, updates, and deletes in one batch.
            let mut batch = db.new_batch();

            // Initial creates
            for i in 0u64..ELEMENTS {
                let k: C::Key = TestKey::from_seed(i);
                let v: <C as DbAny<M>>::Value = TestValue::from_seed(i * 1000);
                batch = batch.write(k, Some(v.clone()));
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k: C::Key = TestKey::from_seed(i);
                let v: <C as DbAny<M>>::Value = TestValue::from_seed((i + 1) * 10000);
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

            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();

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

    /// Run `test_stale_batch_side_effect_free` against a database factory.
    ///
    /// The stale batch must be rejected without mutating the committed state.
    pub fn test_stale_batch_side_effect_free<M, C, F, Fut>(mut open_db: F)
    where
        M: merkle::Graftable,
        C: DbAny<M>,
        C::Key: TestKey,
        <C as DbAny<M>>::Value: TestValue,
        F: FnMut(Context, String) -> Fut,
        Fut: Future<Output = C>,
    {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db: C =
                open_db(context.with_label("db"), "stale-side-effect-free".into()).await;

            let key1 = <C::Key as TestKey>::from_seed(1);
            let key2 = <C::Key as TestKey>::from_seed(2);
            let value1 = <<C as DbAny<M>>::Value as TestValue>::from_seed(10);
            let value2 = <<C as DbAny<M>>::Value as TestValue>::from_seed(20);

            let mut batch = db.new_batch();
            batch = batch.write(key1, Some(value1.clone()));
            let batch_a = batch.merkleize(&db, None).await.unwrap();
            let mut batch = db.new_batch();
            batch = batch.write(key2, Some(value2));
            let batch_b = batch.merkleize(&db, None).await.unwrap();

            db.apply_batch(batch_a).await.unwrap();
            let expected_root = db.root();
            let expected_bounds = db.bounds().await;
            let expected_metadata = db.get_metadata().await.unwrap();
            assert_eq!(db.get(&key1).await.unwrap(), Some(value1.clone()));
            assert_eq!(db.get(&key2).await.unwrap(), None);

            let result = db.apply_batch(batch_b).await;
            assert!(
                matches!(result, Err(Error::StaleBatch { .. })),
                "expected StaleBatch error, got {result:?}"
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

    type OrderedFixedDb =
        ordered::fixed::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 32>;
    type OrderedVariableDb =
        ordered::variable::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 32>;
    type UnorderedFixedDb =
        unordered::fixed::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 32>;
    type UnorderedVariableDb =
        unordered::variable::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 32>;
    type OrderedFixedP1Db = ordered::fixed::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
        32,
    >;
    type OrderedVariableP1Db = ordered::variable::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
        32,
    >;
    type UnorderedFixedP1Db = unordered::fixed::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
        32,
    >;
    type UnorderedVariableP1Db = unordered::variable::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
        32,
    >;
    type OrderedFixedP2Db = ordered::fixed::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
        32,
    >;
    type OrderedVariableP2Db = ordered::variable::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
        32,
    >;
    type UnorderedFixedP2Db = unordered::fixed::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
        32,
    >;
    type UnorderedVariableP2Db = unordered::variable::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
        32,
    >;

    type OrderedFixedMmbDb =
        ordered::fixed::Db<mmb::Family, Context, Digest, Digest, Sha256, OneCap, 32>;
    type OrderedVariableMmbDb =
        ordered::variable::Db<mmb::Family, Context, Digest, Digest, Sha256, OneCap, 32>;
    type UnorderedFixedMmbDb =
        unordered::fixed::Db<mmb::Family, Context, Digest, Digest, Sha256, OneCap, 32>;
    type UnorderedVariableMmbDb =
        unordered::variable::Db<mmb::Family, Context, Digest, Digest, Sha256, OneCap, 32>;
    type OrderedFixedMmbP1Db = ordered::fixed::partitioned::Db<
        mmb::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
        32,
    >;
    type OrderedVariableMmbP1Db = ordered::variable::partitioned::Db<
        mmb::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
        32,
    >;
    type UnorderedFixedMmbP1Db = unordered::fixed::partitioned::Db<
        mmb::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
        32,
    >;
    type UnorderedVariableMmbP1Db = unordered::variable::partitioned::Db<
        mmb::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
        32,
    >;
    type OrderedFixedMmbP2Db = ordered::fixed::partitioned::Db<
        mmb::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
        32,
    >;
    type OrderedVariableMmbP2Db = ordered::variable::partitioned::Db<
        mmb::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
        32,
    >;
    type UnorderedFixedMmbP2Db = unordered::fixed::partitioned::Db<
        mmb::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
        32,
    >;
    type UnorderedVariableMmbP2Db = unordered::variable::partitioned::Db<
        mmb::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
        32,
    >;

    // Helper macro to create an open_db closure for a specific variant.
    macro_rules! open_db_fn {
        ($db:ty, $cfg:ident) => {
            |ctx: Context, partition: String| async move {
                let page_cache = CacheRef::from_pooler(ctx.clone(), PAGE_SIZE, PAGE_CACHE_SIZE);
                <$db>::init(ctx.clone(), $cfg::<OneCap>(&partition, page_cache))
                    .await
                    .unwrap()
            }
        };
    }

    // Defines all variants across both supported Merkle families.
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
            $cb!($($args)*, "of-mmb", OrderedFixedMmbDb, fixed_config);
            $cb!($($args)*, "ov-mmb", OrderedVariableMmbDb, variable_config);
            $cb!($($args)*, "uf-mmb", UnorderedFixedMmbDb, fixed_config);
            $cb!($($args)*, "uv-mmb", UnorderedVariableMmbDb, variable_config);
            $cb!($($args)*, "ofp1-mmb", OrderedFixedMmbP1Db, fixed_config);
            $cb!($($args)*, "ovp1-mmb", OrderedVariableMmbP1Db, variable_config);
            $cb!($($args)*, "ufp1-mmb", UnorderedFixedMmbP1Db, fixed_config);
            $cb!($($args)*, "uvp1-mmb", UnorderedVariableMmbP1Db, variable_config);
            $cb!($($args)*, "ofp2-mmb", OrderedFixedMmbP2Db, fixed_config);
            $cb!($($args)*, "ovp2-mmb", OrderedVariableMmbP2Db, variable_config);
            $cb!($($args)*, "ufp2-mmb", UnorderedFixedMmbP2Db, fixed_config);
            $cb!($($args)*, "uvp2-mmb", UnorderedVariableMmbP2Db, variable_config);
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
            $cb!($($args)*, "of-mmb", OrderedFixedMmbDb, fixed_config);
            $cb!($($args)*, "ov-mmb", OrderedVariableMmbDb, variable_config);
            $cb!($($args)*, "ofp1-mmb", OrderedFixedMmbP1Db, fixed_config);
            $cb!($($args)*, "ovp1-mmb", OrderedVariableMmbP1Db, variable_config);
            $cb!($($args)*, "ofp2-mmb", OrderedFixedMmbP2Db, fixed_config);
            $cb!($($args)*, "ovp2-mmb", OrderedVariableMmbP2Db, variable_config);
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
            $cb!($($args)*, "uf-mmb", UnorderedFixedMmbDb, fixed_config);
            $cb!($($args)*, "uv-mmb", UnorderedVariableMmbDb, variable_config);
            $cb!($($args)*, "ufp1-mmb", UnorderedFixedMmbP1Db, fixed_config);
            $cb!($($args)*, "uvp1-mmb", UnorderedVariableMmbP1Db, variable_config);
            $cb!($($args)*, "ufp2-mmb", UnorderedFixedMmbP2Db, fixed_config);
            $cb!($($args)*, "uvp2-mmb", UnorderedVariableMmbP2Db, variable_config);
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
    fn test_ordered_build_big<M, C, F, Fut>(open_db: F)
    where
        M: merkle::Graftable,
        C: DbAny<M>,
        C::Key: TestKey,
        <C as DbAny<M>>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        test_current_db_build_big::<M, C, F, Fut>(open_db);
    }

    fn test_unordered_build_big<M, C, F, Fut>(open_db: F)
    where
        M: merkle::Graftable,
        C: DbAny<M>,
        C::Key: TestKey,
        <C as DbAny<M>>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        test_current_db_build_big::<M, C, F, Fut>(open_db);
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
    fn test_all_variants_stale_batch_side_effect_free() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_stale_batch_side_effect_free);
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
    // MerkleizedBatch::get, batch chaining) which layer bitmap and grafted tree
    // computation on top of the `any` batch.

    fn key(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    fn val(i: u64) -> Digest {
        Sha256::hash(&(i + 10000).to_be_bytes())
    }

    async fn commit_writes_with_metadata(
        db: &mut UnorderedVariableDb,
        writes: impl IntoIterator<Item = (Digest, Option<Digest>)>,
        metadata: Option<Digest>,
    ) -> std::ops::Range<Location<mmr::Family>> {
        let mut batch = db.new_batch();
        for (k, v) in writes {
            batch = batch.write(k, v);
        }
        let merkleized = batch.merkleize(db, metadata).await.unwrap();
        let range = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        range
    }

    #[test_traced("INFO")]
    fn test_current_rewind_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "current-rewind-recovery";
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>(partition, test_page_cache(&ctx)),
            )
            .await
            .unwrap();
            let initial_size = db.bounds().await.end;
            let initial_root = db.root();
            let initial_ops_root = db.ops_root();
            let initial_floor = db.inactivity_floor_loc();

            let metadata_a = val(900);
            let first_range = commit_writes_with_metadata(
                &mut db,
                [(key(0), Some(val(0))), (key(1), Some(val(1)))],
                Some(metadata_a),
            )
            .await;
            assert_eq!(first_range.start, initial_size);
            let size_before = db.bounds().await.end;
            let root_before = db.root();
            let ops_root_before = db.ops_root();
            let floor_before = db.inactivity_floor_loc();
            assert_eq!(size_before, first_range.end);

            let metadata_b = val(901);
            let second_range = commit_writes_with_metadata(
                &mut db,
                [
                    (key(0), Some(val(100))),
                    (key(1), None),
                    (key(2), Some(val(2))),
                ],
                Some(metadata_b),
            )
            .await;
            assert_eq!(second_range.start, size_before);
            assert_ne!(db.root(), root_before);
            assert_eq!(db.get_metadata().await.unwrap(), Some(val(901)));
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(100)));
            assert_eq!(db.get(&key(1)).await.unwrap(), None);
            assert_eq!(db.get(&key(2)).await.unwrap(), Some(val(2)));

            db.rewind(size_before).await.unwrap();
            assert_eq!(db.bounds().await.end, size_before);
            assert_eq!(db.root(), root_before);
            assert_eq!(db.ops_root(), ops_root_before);
            assert_eq!(db.inactivity_floor_loc(), floor_before);
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_a));
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));
            assert_eq!(db.get(&key(2)).await.unwrap(), None);

            db.commit().await.unwrap();
            drop(db);

            let reopened: UnorderedVariableDb = UnorderedVariableDb::init(
                context.with_label("reopen"),
                variable_config::<OneCap>(
                    partition,
                    test_page_cache(&context.with_label("reopen_cfg")),
                ),
            )
            .await
            .unwrap();
            assert_eq!(reopened.bounds().await.end, size_before);
            assert_eq!(reopened.root(), root_before);
            assert_eq!(reopened.ops_root(), ops_root_before);
            assert_eq!(reopened.inactivity_floor_loc(), floor_before);
            assert_eq!(reopened.get_metadata().await.unwrap(), Some(val(900)));
            assert_eq!(reopened.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(reopened.get(&key(1)).await.unwrap(), Some(val(1)));
            assert_eq!(reopened.get(&key(2)).await.unwrap(), None);

            let mut reopened = reopened;
            reopened.rewind(initial_size).await.unwrap();
            assert_eq!(reopened.bounds().await.end, initial_size);
            assert_eq!(reopened.root(), initial_root);
            assert_eq!(reopened.ops_root(), initial_ops_root);
            assert_eq!(reopened.inactivity_floor_loc(), initial_floor);
            assert_eq!(reopened.get_metadata().await.unwrap(), None);
            assert_eq!(reopened.get(&key(0)).await.unwrap(), None);
            assert_eq!(reopened.get(&key(1)).await.unwrap(), None);
            assert_eq!(reopened.get(&key(2)).await.unwrap(), None);

            reopened.commit().await.unwrap();
            drop(reopened);

            let reopened_initial: UnorderedVariableDb = UnorderedVariableDb::init(
                context.with_label("reopen_initial"),
                variable_config::<OneCap>(
                    partition,
                    test_page_cache(&context.with_label("reopen_initial_cfg")),
                ),
            )
            .await
            .unwrap();
            assert_eq!(reopened_initial.bounds().await.end, initial_size);
            assert_eq!(reopened_initial.root(), initial_root);
            assert_eq!(reopened_initial.ops_root(), initial_ops_root);
            assert_eq!(reopened_initial.inactivity_floor_loc(), initial_floor);
            assert_eq!(reopened_initial.get_metadata().await.unwrap(), None);
            assert_eq!(reopened_initial.get(&key(0)).await.unwrap(), None);
            assert_eq!(reopened_initial.get(&key(1)).await.unwrap(), None);
            assert_eq!(reopened_initial.get(&key(2)).await.unwrap(), None);

            reopened_initial.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_current_rewind_recovery_pruned_repeated_updates() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const COMMITS: u64 = 96;

            let partition = "current-rewind-pruned-recovery";
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb =
                UnorderedVariableDb::init(ctx.clone(), variable_config::<OneCap>(partition, test_page_cache(&ctx)))
                    .await
                    .unwrap();

            let key0 = key(0);
            let mut history = Vec::new();
            for round in 0..COMMITS {
                commit_writes_with_metadata(
                    &mut db,
                    [(key0, Some(val(20_000 + round)))],
                    None,
                )
                .await;
                history.push((
                    db.bounds().await.end,
                    db.inactivity_floor_loc(),
                    db.root(),
                    db.ops_root(),
                    val(20_000 + round),
                ));
            }

            // Keep most ops-log history, but force bitmap pruning so rewind uses pinned-node
            // reconstruction (`pruned_chunks > 0` path).
            db.prune(Location::new(1)).await.unwrap();
            let pruned_bits = db.pruned_bits();
            assert!(pruned_bits > 0, "expected bitmap pruning for rewind test");
            let bounds = db.bounds().await;

            let (target_size, target_root, target_ops_root, target_value) = history
                .iter()
                .enumerate()
                .find_map(|(idx, (size, floor, root, ops_root, value))| {
                    let removed_commits = history.len() - idx - 1;
                    if removed_commits >= 3 && *size > bounds.start && *floor >= pruned_bits {
                        Some((*size, *root, *ops_root, *value))
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| {
                    panic!(
                        "expected legal pruned rewind target with repeated updates; bounds={bounds:?}, pruned_bits={pruned_bits}, latest_floor={:?}, history={history:?}",
                        db.inactivity_floor_loc()
                    )
                });

            db.rewind(target_size).await.unwrap();
            assert_eq!(db.root(), target_root);
            assert_eq!(db.ops_root(), target_ops_root);
            assert_eq!(db.bounds().await.end, target_size);
            assert_eq!(db.get(&key0).await.unwrap(), Some(target_value));

            db.commit().await.unwrap();
            drop(db);

            let mut reopened: UnorderedVariableDb = UnorderedVariableDb::init(
                context.with_label("reopen_pruned_recovery"),
                variable_config::<OneCap>(
                    partition,
                    test_page_cache(&context.with_label("reopen_pruned_cfg")),
                ),
            )
            .await
            .unwrap();
            assert_eq!(reopened.root(), target_root);
            assert_eq!(reopened.ops_root(), target_ops_root);
            assert_eq!(reopened.bounds().await.end, target_size);
            assert_eq!(reopened.get(&key0).await.unwrap(), Some(target_value));

            let metadata_after_rewind = val(30_000);
            let new_key = key(1);
            let new_value = val(30_001);
            let expected_end = commit_writes_with_metadata(
                &mut reopened,
                [(new_key, Some(new_value))],
                Some(metadata_after_rewind),
            )
            .await
            .end;
            let root_after_new_write = reopened.root();
            let ops_root_after_new_write = reopened.ops_root();
            assert_eq!(reopened.bounds().await.end, expected_end);
            assert_eq!(reopened.get_metadata().await.unwrap(), Some(metadata_after_rewind));
            assert_eq!(reopened.get(&key0).await.unwrap(), Some(target_value));
            assert_eq!(reopened.get(&new_key).await.unwrap(), Some(new_value));

            drop(reopened);
            let reopened_after_new_write: UnorderedVariableDb = UnorderedVariableDb::init(
                context.with_label("reopen_pruned_after_new_write"),
                variable_config::<OneCap>(
                    partition,
                    test_page_cache(&context.with_label("reopen_after_write_cfg")),
                ),
            )
            .await
            .unwrap();
            assert_eq!(reopened_after_new_write.root(), root_after_new_write);
            assert_eq!(reopened_after_new_write.ops_root(), ops_root_after_new_write);
            assert_eq!(reopened_after_new_write.bounds().await.end, expected_end);
            assert_eq!(
                reopened_after_new_write.get_metadata().await.unwrap(),
                Some(metadata_after_rewind)
            );
            assert_eq!(reopened_after_new_write.get(&key0).await.unwrap(), Some(target_value));
            assert_eq!(
                reopened_after_new_write.get(&new_key).await.unwrap(),
                Some(new_value)
            );

            reopened_after_new_write.destroy().await.unwrap();
        });
    }

    /// Verify that reopening and proving a pruned MMB database does not panic when the pruned
    /// prefix contains sub-grafting-height peaks that require chunk regrouping.
    ///
    /// With 100 single-key commits the MMB has 301 leaves (100 writes + 100 commit floors +
    /// 101 internal nodes). The first 256 leaves span three sub-grafting-height ops peaks
    /// (128 + 64 + 64), so grafted root recomposition must regroup them as chunk 0. After
    /// pruning, chunk 0 is gone and get_chunk(0) would panic without the pruned-chunk guard.
    #[test_traced("INFO")]
    fn test_current_mmb_reopen_and_prove_after_prune_multi_peak_chunk() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const COMMITS: u64 = 100;

            let partition = "current-mmb-reopen-prove-after-prune";
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                ctx.clone(),
                variable_config::<OneCap>(partition, test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            let k = key(0);
            let mut expected = None;
            for round in 0..COMMITS {
                expected = Some(val(50_000 + round));
                let mut batch = db.new_batch();
                batch = batch.write(k, expected);
                let merkleized = batch.merkleize(&db, None).await.unwrap();
                db.apply_batch(merkleized).await.unwrap();
                db.commit().await.unwrap();
            }

            let root_before = db.root();
            assert!(
                *db.inactivity_floor_loc() >= 256,
                "expected inactivity floor past chunk 0"
            );

            db.prune(Location::<mmb::Family>::new(1)).await.unwrap();
            assert_eq!(db.pruned_bits(), 256);
            db.sync().await.unwrap();
            drop(db);

            // Reopen: compute_grafted_root must handle pruned chunk 0.
            let reopened: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                context.with_label("reopen"),
                variable_config::<OneCap>(partition, test_page_cache(&context)),
            )
            .await
            .unwrap();

            assert_eq!(reopened.root(), root_before);
            assert_eq!(reopened.get(&k).await.unwrap(), expected);

            // key_value_proof: RangeProof::new must also handle pruned chunk 0.
            let mut hasher = commonware_cryptography::Sha256::new();
            let _proof = reopened.key_value_proof(&mut hasher, k).await.unwrap();

            reopened.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_current_rewind_small_delta_large_history() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const COMMITS: u64 = 200;

            let partition = "current-rewind-small-delta";
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>(partition, test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            let key0 = key(0);
            let key1 = key(1);
            let mut history = Vec::new();

            for round in 0..COMMITS {
                let key0_value = val(40_000 + round);
                let key1_value = if round % 3 == 1 {
                    None
                } else {
                    Some(val(50_000 + round))
                };

                commit_writes_with_metadata(
                    &mut db,
                    [(key0, Some(key0_value)), (key1, key1_value)],
                    None,
                )
                .await;

                history.push((
                    db.bounds().await.end,
                    db.root(),
                    db.ops_root(),
                    key0_value,
                    key1_value,
                ));
            }

            let target = *history
                .get(history.len() - 3)
                .expect("history should contain at least three commits");
            let (target_size, target_root, target_ops_root, target_key0, target_key1) = target;

            db.rewind(target_size).await.unwrap();
            assert_eq!(db.bounds().await.end, target_size);
            assert_eq!(db.root(), target_root);
            assert_eq!(db.ops_root(), target_ops_root);
            assert_eq!(db.get(&key0).await.unwrap(), Some(target_key0));
            assert_eq!(db.get(&key1).await.unwrap(), target_key1);

            db.commit().await.unwrap();
            drop(db);

            let reopened: UnorderedVariableDb = UnorderedVariableDb::init(
                context.with_label("reopen_small_delta"),
                variable_config::<OneCap>(partition, test_page_cache(&context)),
            )
            .await
            .unwrap();
            assert_eq!(reopened.bounds().await.end, target_size);
            assert_eq!(reopened.root(), target_root);
            assert_eq!(reopened.ops_root(), target_ops_root);
            assert_eq!(reopened.get(&key0).await.unwrap(), Some(target_key0));
            assert_eq!(reopened.get(&key1).await.unwrap(), target_key1);

            reopened.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_current_rewind_pruned_target_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const KEYS: u64 = 384;

            let partition = "current-rewind-pruned";
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb =
                UnorderedVariableDb::init(ctx.clone(), variable_config::<OneCap>(partition, test_page_cache(&ctx)))
                    .await
                    .unwrap();

            let first_range = commit_writes_with_metadata(
                &mut db,
                (0..KEYS).map(|i| (key(i), Some(val(i)))),
                None,
            )
            .await;
            commit_writes_with_metadata(
                &mut db,
                (0..KEYS).map(|i| (key(i), Some(val(1000 + i)))),
                None,
            )
            .await;

            db.prune(db.inactivity_floor_loc()).await.unwrap();
            let pruned_bits = db.pruned_bits();
            assert!(
                pruned_bits > *first_range.start,
                "expected bitmap pruning boundary above rewind target: pruned_bits={pruned_bits}, target={:?}",
                first_range.start
            );

            let oldest_retained = db.bounds().await.start;
            let boundary_err = db.rewind(oldest_retained).await.unwrap_err();
            assert!(
                matches!(
                    boundary_err,
                    Error::Journal(crate::journal::Error::ItemPruned(_))
                ),
                "unexpected rewind error at retained boundary: {boundary_err:?}"
            );

            let expected_pruned_loc = *first_range.start - 1;
            let err = db.rewind(first_range.start).await.unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::Journal(crate::journal::Error::ItemPruned(loc))
                    if loc == expected_pruned_loc
                ),
                "unexpected rewind error: {err:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_current_rewind_rejects_target_below_bitmap_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const COMMITS: u64 = 96;

            let partition = "current-rewind-bitmap-floor";
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb =
                UnorderedVariableDb::init(ctx.clone(), variable_config::<OneCap>(partition, test_page_cache(&ctx)))
                    .await
                    .unwrap();

            let mut history = Vec::new();
            for round in 0..COMMITS {
                commit_writes_with_metadata(
                    &mut db,
                    [(key(0), Some(val(10_000 + round)))],
                    None,
                )
                .await;
                history.push((db.bounds().await.end, db.inactivity_floor_loc()));
            }
            assert!(db.inactivity_floor_loc() > Location::new(64));

            // Intentionally prune less than the inactivity floor: log retains older ops, but the
            // bitmap still prunes to inactivity floor.
            let prune_loc = Location::new(1);
            db.prune(prune_loc).await.unwrap();
            let pruned_bits = db.pruned_bits();
            assert!(pruned_bits > 0);
            let retained_start = db.bounds().await.start;

            // Pick a historical commit that is still within retained log bounds but whose floor is
            // below the bitmap pruning boundary.
            let rewind_target = history
                .iter()
                .find_map(|(size, floor)| {
                    if *size > *retained_start
                        && *size >= pruned_bits
                        && *floor >= *retained_start
                        && *floor < pruned_bits
                    {
                        Some(*size)
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| {
                    panic!(
                        "expected rewind target below bitmap boundary. retained_start={retained_start:?}, pruned_bits={pruned_bits}, latest_floor={:?}, history={history:?}",
                        db.inactivity_floor_loc()
                    )
                });

            let err = db.rewind(rewind_target).await.unwrap_err();
            assert!(
                matches!(err, Error::Journal(crate::journal::Error::ItemPruned(_))),
                "unexpected rewind error: {err:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    /// Verify that the speculative canonical root from a merkleized batch matches the root
    /// recomputed from committed state after sync + reopen.
    ///
    /// Uses enough operations to cross a chunk boundary (CHUNK_SIZE_BITS = N*8), which exercises
    /// the grafted root computation for newly completed chunks.
    pub fn test_speculative_root_matches_committed<M, C, F, Fut>(mut open_db: F)
    where
        M: merkle::Graftable + 'static,
        C: DbAny<M> + 'static,
        C::Key: TestKey,
        <C as DbAny<M>>::Value: TestValue,
        F: FnMut(Context, String) -> Fut + Clone,
        Fut: Future<Output = C>,
    {
        let executor = deterministic::Runner::default();
        let mut open_db_clone = open_db.clone();
        executor.start(|context| async move {
            let partition = "speculative-root".to_string();

            // Write enough operations to cross a chunk boundary. With N=32 (CHUNK_SIZE_BITS=256),
            // 260 writes + 1 CommitFloor = 261 operations, completing one chunk with 5 ops in the
            // next partial chunk. This ensures the grafted root computation must handle the
            // newly completed chunk.
            let mut db: C = open_db_clone(context.with_label("init"), partition.clone()).await;
            let mut batch = db.new_batch();
            for i in 0..260 {
                batch = batch.write(TestKey::from_seed(i), Some(TestValue::from_seed(i + 1000)));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            let speculative_root = db.root();

            // Sync, close, and reopen to get the root recomputed from committed state.
            db.sync().await.unwrap();
            drop(db);

            let db: C = open_db(context.with_label("reopen"), partition).await;
            assert_eq!(db.root(), speculative_root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_all_variants_speculative_root_matches_committed() {
        let executor = deterministic::Runner::default();
        executor.start(|_context| async move {
            for_all_variants!(simple: test_speculative_root_matches_committed);
        });
    }

    /// MerkleizedBatch::get() at the current level reads overlay then base DB.
    #[test_traced("INFO")]
    fn test_current_batch_merkleized_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("mg", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            let ka = key(0);
            let kb = key(1);
            let kc = key(2);

            // Pre-populate A.
            {
                let mut batch = db.new_batch();
                batch = batch.write(ka, Some(val(0)));
                let merkleized = batch.merkleize(&db, None).await.unwrap();
                db.apply_batch(merkleized).await.unwrap();
            }

            // Batch: update A, delete nothing, create B.
            let va2 = val(100);
            let vb = val(1);
            let mut batch = db.new_batch();
            batch = batch.write(ka, Some(va2));
            batch = batch.write(kb, Some(vb));
            let merkleized = batch.merkleize(&db, None).await.unwrap();

            assert_eq!(merkleized.get(&ka, &db).await.unwrap(), Some(va2));
            assert_eq!(merkleized.get(&kb, &db).await.unwrap(), Some(vb));
            assert_eq!(merkleized.get(&kc, &db).await.unwrap(), None);

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
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("ch", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            // Parent batch writes keys 0..5.
            let mut parent = db.new_batch();
            for i in 0..5 {
                parent = parent.write(key(i), Some(val(i)));
            }
            let parent_m = parent.merkleize(&db, None).await.unwrap();

            // Child batch writes keys 5..10 and overrides key 0.
            let mut child = parent_m.new_batch::<Sha256>();
            for i in 5..10 {
                child = child.write(key(i), Some(val(i)));
            }
            child = child.write(key(0), Some(val(999)));
            let child_m = child.merkleize(&db, None).await.unwrap();

            let child_root = child_m.root();

            // Child get reads through all layers.
            assert_eq!(child_m.get(&key(0), &db).await.unwrap(), Some(val(999)));
            assert_eq!(child_m.get(&key(3), &db).await.unwrap(), Some(val(3)));
            assert_eq!(child_m.get(&key(7), &db).await.unwrap(), Some(val(7)));

            db.apply_batch(child_m).await.unwrap();
            assert_eq!(db.root(), child_root);

            // Verify all keys are correct.
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(999)));
            for i in 1..10 {
                assert_eq!(db.get(&key(i)).await.unwrap(), Some(val(i)));
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_current_unordered_root_matches_between_pending_and_committed_paths() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedFixedDb = UnorderedFixedDb::init(
                ctx.clone(),
                fixed_config::<OneCap>("ucr", test_page_cache(&ctx)),
            )
            .await
            .unwrap();
            let key_a = colliding_digest(0xAA, 1);
            let key_b = colliding_digest(0xAA, 0);

            // Seed four colliding committed keys, then update only key_a.
            // The specific 4 / 1 / 0 shape is a concrete counterexample:
            // key_b remains outside the parent diff and is still resolved
            // through the committed snapshot in the child.
            let mut initial = db.new_batch();
            for i in 0..4 {
                initial = initial.write(colliding_digest(0xAA, i), Some(colliding_digest(0xBB, i)));
            }
            let merkleized = initial.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db.commit().await.unwrap();

            // Update only key_a so the colliding sibling key_b remains outside
            // the parent diff and must still be resolved through the committed
            // snapshot in the child.
            let parent = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xCC, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Build the child while the parent is still pending, then rebuild
            // the same logical child after committing the parent and compare
            // both canonical and ops roots.
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(&db, None)
                .await
                .unwrap();

            let pending_root = pending_child.root();
            let pending_ops_root = pending_child.ops_root();

            db.apply_batch(parent).await.unwrap();
            db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(&db, None)
                .await
                .unwrap();

            assert_eq!(pending_root, committed_child.root());
            assert_eq!(pending_ops_root, committed_child.ops_root());

            // Apply pending child onto the committed parent
            // and ensure the applied wrapper roots still match.
            db.apply_batch(pending_child).await.unwrap();
            assert_eq!(db.root(), committed_child.root());
            assert_eq!(db.ops_root(), committed_child.ops_root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_current_ordered_root_matches_between_pending_and_committed_paths() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: OrderedFixedDb = OrderedFixedDb::init(
                ctx.clone(),
                fixed_config::<OneCap>("ocr", test_page_cache(&ctx)),
            )
            .await
            .unwrap();
            let key_a = colliding_digest(0xAA, 1);
            let key_b = colliding_digest(0xAA, 0);

            // Match the unordered counterexample shape on the ordered path so
            // both wrappers exercise the same collision pattern.
            let mut initial = db.new_batch();
            for i in 0..4 {
                initial = initial.write(colliding_digest(0xAA, i), Some(colliding_digest(0xBB, i)));
            }
            let merkleized = initial.merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db.commit().await.unwrap();

            // Update only key_a so the colliding sibling key_b remains outside
            // the parent diff and must still be resolved through the committed
            // snapshot in the child.
            let parent = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xCC, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Build the child while the parent is still pending, then rebuild
            // the same logical child after committing the parent.
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(&db, None)
                .await
                .unwrap();

            let pending_root = pending_child.root();
            let pending_ops_root = pending_child.ops_root();

            db.apply_batch(parent).await.unwrap();
            db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(&db, None)
                .await
                .unwrap();

            assert_eq!(pending_root, committed_child.root());
            assert_eq!(pending_ops_root, committed_child.ops_root());

            // Apply pending child onto the committed parent
            // and compare the applied wrapper roots with the committed-path child roots.
            db.apply_batch(pending_child).await.unwrap();
            assert_eq!(db.root(), committed_child.root());
            assert_eq!(db.ops_root(), committed_child.ops_root());

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
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>(partition, test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            let committed_root = db.root();

            let merkleized = db
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(merkleized).await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

            drop(db);

            let reopened: UnorderedVariableDb = UnorderedVariableDb::init(
                context.with_label("reopen"),
                variable_config::<OneCap>(partition, test_page_cache(&context)),
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
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("pipe", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            let mut batch = db.new_batch();
            batch = batch.write(key(0), Some(val(0)));
            let parent_merkleized = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(parent_merkleized).await.unwrap();

            let (child_merkleized, commit_result) = futures::join!(
                async {
                    assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
                    let mut child = db.new_batch();
                    child = child.write(key(1), Some(val(1)));
                    child.merkleize(&db, None).await.unwrap()
                },
                db.commit(),
            );
            commit_result.unwrap();

            db.apply_batch(child_merkleized).await.unwrap();
            db.commit().await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));

            db.destroy().await.unwrap();
        });
    }

    /// Apply parent then child sequentially. Both keys
    /// present and canonical root matches a fresh single-batch build.
    #[test_traced("INFO")]
    fn test_current_sequential_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("ff", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            // Parent batch: insert key(0).
            let parent_m = db
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Child batch on parent: insert key(1).
            let child_m = parent_m
                .new_batch::<Sha256>()
                .write(key(1), Some(val(1)))
                .merkleize(&db, None)
                .await
                .unwrap();

            db.apply_batch(parent_m).await.unwrap();
            db.apply_batch(child_m).await.unwrap();

            // Both keys present.
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));

            // Build the same result via two sequential plain batches in a fresh DB
            // and verify the roots match.
            let ctx2 = context.with_label("db2");
            let mut db2: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx2.clone(),
                variable_config::<OneCap>("ff2", test_page_cache(&ctx2)),
            )
            .await
            .unwrap();
            let m1 = db2
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(&db2, None)
                .await
                .unwrap();
            db2.apply_batch(m1).await.unwrap();
            let m2 = db2
                .new_batch()
                .write(key(1), Some(val(1)))
                .merkleize(&db2, None)
                .await
                .unwrap();
            db2.apply_batch(m2).await.unwrap();

            assert_eq!(db.root(), db2.root());

            db.destroy().await.unwrap();
            db2.destroy().await.unwrap();
        });
    }

    /// to_batch() produces a MerkleizedBatch that can be used to chain further
    /// batches via new_batch().
    #[test_traced("INFO")]
    fn test_current_to_batch_then_chain() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("tb", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            // Apply an initial batch.
            let m = db
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(m).await.unwrap();

            // Get an owned batch from the committed state.
            let snapshot = db.to_batch();
            assert_eq!(snapshot.root(), db.root());

            // Chain a child batch from the snapshot.
            let child = snapshot
                .new_batch::<Sha256>()
                .write(key(1), Some(val(1)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // The child's root should differ from the snapshot.
            assert_ne!(child.root(), snapshot.root());

            // Apply child.
            db.apply_batch(child).await.unwrap();
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));

            db.destroy().await.unwrap();
        });
    }

    /// flatten() is a no-op on a freshly initialized DB (no layers to collapse).
    #[test_traced("INFO")]
    fn test_flatten_noop_on_fresh_db() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("fl-noop", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            let root_before = db.root();
            db.flatten();
            assert_eq!(db.root(), root_before);

            db.destroy().await.unwrap();
        });
    }

    /// flatten() preserves the root and data after multiple apply_batch calls.
    #[test_traced("INFO")]
    fn test_flatten_preserves_root_after_batches() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("fl-root", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            // Apply several batches to accumulate layers.
            for i in 0u64..5 {
                let m = db
                    .new_batch()
                    .write(key(i), Some(val(i)))
                    .merkleize(&db, None)
                    .await
                    .unwrap();
                db.apply_batch(m).await.unwrap();
            }

            let root_before = db.root();
            db.flatten();
            assert_eq!(db.root(), root_before);

            // Data is still readable.
            for i in 0u64..5 {
                assert_eq!(db.get(&key(i)).await.unwrap(), Some(val(i)));
            }

            db.destroy().await.unwrap();
        });
    }

    /// flatten() is idempotent: a second call is a no-op.
    #[test_traced("INFO")]
    fn test_flatten_idempotent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("fl-idem", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            let m = db
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(m).await.unwrap();

            db.flatten();
            let root_after_first = db.root();

            db.flatten();
            assert_eq!(db.root(), root_after_first);

            db.destroy().await.unwrap();
        });
    }

    /// New batches built after flatten() produce correct roots and can be applied.
    #[test_traced("INFO")]
    fn test_flatten_then_new_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("fl-then", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            // Apply a batch, flatten, then apply another.
            let m = db
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(m).await.unwrap();
            db.flatten();

            let m = db
                .new_batch()
                .write(key(1), Some(val(1)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(m).await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));

            db.destroy().await.unwrap();
        });
    }

    /// Regression: applying a batch after its ancestor Arc is dropped (without
    /// committing) must still apply the ancestor's bitmap pushes/clears and
    /// snapshot diffs.
    #[test_traced("WARN")]
    fn test_current_apply_after_ancestor_dropped() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("adrop", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            // Chain: DB <- A <- B <- C
            let mut a = db.new_batch();
            for i in 0..3 {
                a = a.write(key(i), Some(val(i)));
            }
            let a_m = a.merkleize(&db, None).await.unwrap();

            let mut b = a_m.new_batch::<Sha256>();
            for i in 3..6 {
                b = b.write(key(i), Some(val(i)));
            }
            let b_m = b.merkleize(&db, None).await.unwrap();

            let mut c = b_m.new_batch::<Sha256>();
            for i in 6..9 {
                c = c.write(key(i), Some(val(i)));
            }
            let c_m = c.merkleize(&db, None).await.unwrap();

            // Drop A and B without committing. Their Weak refs in C are now dead.
            drop(a_m);
            drop(b_m);

            // Apply only the tip. This is !skip_ancestors (DB hasn't changed).
            db.apply_batch(c_m).await.unwrap();
            db.commit().await.unwrap();

            // All nine keys must be accessible.
            for i in 0..9 {
                assert_eq!(
                    db.get(&key(i)).await.unwrap(),
                    Some(val(i)),
                    "key({i}) missing after apply_batch with dropped ancestors"
                );
            }

            db.destroy().await.unwrap();
        });
    }

    /// Regression: applying a 3-deep chain as a single batch must leave the
    /// bitmap in the same state as applying the same operations sequentially.
    /// This fails if ancestor bitmap pushes are concatenated in the wrong order
    /// (tip-to-root instead of root-to-tip), because Delete operations produce
    /// false bitmap bits, and wrong ordering puts the false at the wrong
    /// position. We detect this by building a NEW batch on top of the
    /// (possibly corrupted) bitmap and comparing its root against the
    /// sequential path.
    #[test_traced("WARN")]
    fn test_current_chain_bitmap_order_matches_sequential() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // -- Path 1: build a 3-deep chain and apply the tip directly. --
            let ctx1 = context.with_label("db1");
            let mut db1: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx1.clone(),
                variable_config::<OneCap>("ord1", test_page_cache(&ctx1)),
            )
            .await
            .unwrap();

            // Seed some committed data so there's a base bitmap to clear.
            commit_writes_with_metadata(
                &mut db1,
                [(key(10), Some(val(10))), (key(11), Some(val(11)))],
                None,
            )
            .await;

            // Chain: DB <- A <- B <- C
            // A: updates key(10) and DELETES key(11). The delete produces a
            //    false bitmap bit. If A's bits end up at B's positions (wrong
            //    order), the false bit lands at the wrong journal location.
            // B: updates key(12) and key(13). All true bits.
            // C: updates key(14). All true bits.
            let a = db1
                .new_batch()
                .write(key(10), Some(val(100)))
                .write(key(11), None) // DELETE
                .merkleize(&db1, None)
                .await
                .unwrap();

            let b = a
                .new_batch::<Sha256>()
                .write(key(12), Some(val(120)))
                .write(key(13), Some(val(130)))
                .merkleize(&db1, None)
                .await
                .unwrap();

            let c = b
                .new_batch::<Sha256>()
                .write(key(14), Some(val(140)))
                .merkleize(&db1, None)
                .await
                .unwrap();

            db1.apply_batch(c).await.unwrap();
            db1.commit().await.unwrap();

            // Build one more batch on top to exercise the bitmap state.
            let d1 = db1
                .new_batch()
                .write(key(20), Some(val(200)))
                .merkleize(&db1, None)
                .await
                .unwrap();
            let chain_then_d_root = d1.root();

            // -- Path 2: apply the same operations sequentially. --
            let ctx2 = context.with_label("db2");
            let mut db2: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx2.clone(),
                variable_config::<OneCap>("ord2", test_page_cache(&ctx2)),
            )
            .await
            .unwrap();

            commit_writes_with_metadata(
                &mut db2,
                [(key(10), Some(val(10))), (key(11), Some(val(11)))],
                None,
            )
            .await;

            let a2 = db2
                .new_batch()
                .write(key(10), Some(val(100)))
                .write(key(11), None)
                .merkleize(&db2, None)
                .await
                .unwrap();
            db2.apply_batch(a2).await.unwrap();
            db2.commit().await.unwrap();

            let b2 = db2
                .new_batch()
                .write(key(12), Some(val(120)))
                .write(key(13), Some(val(130)))
                .merkleize(&db2, None)
                .await
                .unwrap();
            db2.apply_batch(b2).await.unwrap();
            db2.commit().await.unwrap();

            let c2 = db2
                .new_batch()
                .write(key(14), Some(val(140)))
                .merkleize(&db2, None)
                .await
                .unwrap();
            db2.apply_batch(c2).await.unwrap();
            db2.commit().await.unwrap();

            let d2 = db2
                .new_batch()
                .write(key(20), Some(val(200)))
                .merkleize(&db2, None)
                .await
                .unwrap();
            let sequential_then_d_root = d2.root();

            assert_eq!(
                chain_then_d_root, sequential_then_d_root,
                "batch D's root on top of chain-applied state must match sequential state"
            );

            db1.destroy().await.unwrap();
            db2.destroy().await.unwrap();
        });
    }

    /// Regression: C's precomputed bitmap clears can target a chunk that
    /// was pruned after parent P was committed.
    ///
    /// With N=32, CHUNK_SIZE_BITS=256. Seed places key(0) at loc 255
    /// (end of chunk 0). P overwrites keys 1..254, whose floor raise
    /// moves key(0) from 255 to tip, pushing the floor past chunk 0.
    /// C is built from P and writes key(0); its base_old_loc is 255.
    /// After committing P and pruning chunk 0, C's clear at 255 targets
    /// the pruned chunk.
    #[test_traced("WARN")]
    fn test_current_stale_bitmap_clears_after_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("stale-clears", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            // Seed: 255 keys in one batch. key(0) lands at loc 255 (chunk 0).
            let mut seed = db.new_batch();
            for i in 0u64..255 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let seed_m = seed.merkleize(&db, None).await.unwrap();
            db.apply_batch(seed_m).await.unwrap();
            db.commit().await.unwrap();

            // P: overwrite keys 1..254. Does NOT touch key(0), but P's floor
            // raise moves key(0) from 255, advancing the floor past chunk 0.
            let mut p = db.new_batch();
            for i in 1u64..255 {
                p = p.write(key(i), Some(val(i + 10000)));
            }
            let p_m = p.merkleize(&db, None).await.unwrap();

            // C: built from P. Writes key(0). base_old_loc = 255 (chunk 0).
            let c_m = p_m
                .new_batch::<Sha256>()
                .write(key(0), Some(val(9999)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Commit P, prune chunk 0, then apply C.
            db.apply_batch(p_m).await.unwrap();
            db.commit().await.unwrap();

            let floor = *db.inactivity_floor_loc();
            assert!(floor >= 256, "floor must be past chunk 0: floor={floor}",);

            db.prune(db.inactivity_floor_loc()).await.unwrap();
            db.apply_batch(c_m).await.unwrap();
            db.flatten();

            db.destroy().await.unwrap();
        });
    }

    /// Apply C (grandchild of A) after only A is committed. B's data (any-layer
    /// snapshot diff + current-layer bitmap) must still be applied.
    #[test_traced("INFO")]
    fn test_current_partial_ancestor_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("pac", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            let a = db
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(&db, None)
                .await
                .unwrap();
            let b = a
                .new_batch::<Sha256>()
                .write(key(1), Some(val(1)))
                .merkleize(&db, None)
                .await
                .unwrap();
            let c = b
                .new_batch::<Sha256>()
                .write(key(2), Some(val(2)))
                .merkleize(&db, None)
                .await
                .unwrap();

            let expected_root = c.root();

            db.apply_batch(a).await.unwrap();
            db.apply_batch(c).await.unwrap();

            assert_eq!(db.root(), expected_root);
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));
            assert_eq!(db.get(&key(2)).await.unwrap(), Some(val(2)));

            db.destroy().await.unwrap();
        });
    }

    /// Regression: bitmap ancestor skip logic must correctly pair each ancestor's
    /// bitmap data with its batch_end. Requires a 3-ancestor chain (A->B->C->D)
    /// to expose ordering bugs.
    #[test_traced("INFO")]
    fn test_current_partial_ancestor_bitmap_ordering() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.with_label("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.clone(),
                variable_config::<OneCap>("bmo", test_page_cache(&ctx)),
            )
            .await
            .unwrap();

            // Build A -> B -> C -> D. Each writes a distinct key.
            let a = db
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(&db, None)
                .await
                .unwrap();
            let b = a
                .new_batch::<Sha256>()
                .write(key(1), Some(val(1)))
                .merkleize(&db, None)
                .await
                .unwrap();
            let c = b
                .new_batch::<Sha256>()
                .write(key(2), Some(val(2)))
                .merkleize(&db, None)
                .await
                .unwrap();
            let d = c
                .new_batch::<Sha256>()
                .write(key(3), Some(val(3)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Apply A only, then apply D (B and C uncommitted).
            // D has 3 ancestors: [C, B, A] (parent-first) with batch_ends [C.total, B.total, A.total].
            // Bitmap ancestors are also parent-first: [C, B, A].
            db.apply_batch(a).await.unwrap();
            db.apply_batch(d.clone()).await.unwrap();

            // Build a new batch E on top of the current state. If the bitmap was
            // corrupted by the ordering bug (A's pushes duplicated or B/C's pushes
            // missing), merkleize will compute a different root than a reference
            // that applied all ancestors sequentially.
            let e = db
                .new_batch()
                .write(key(4), Some(val(4)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(e).await.unwrap();

            // Reference: apply all five sequentially.
            let ref_ctx = context.with_label("ref");
            let mut ref_db: UnorderedVariableDb = UnorderedVariableDb::init(
                ref_ctx.clone(),
                variable_config::<OneCap>("bmo_ref", test_page_cache(&ref_ctx)),
            )
            .await
            .unwrap();
            for i in 0..5 {
                let batch = ref_db
                    .new_batch()
                    .write(key(i), Some(val(i)))
                    .merkleize(&ref_db, None)
                    .await
                    .unwrap();
                ref_db.apply_batch(batch).await.unwrap();
            }

            assert_eq!(
                db.root(),
                ref_db.root(),
                "root mismatch: bitmap ordering bug"
            );

            db.destroy().await.unwrap();
            ref_db.destroy().await.unwrap();
        });
    }
}
