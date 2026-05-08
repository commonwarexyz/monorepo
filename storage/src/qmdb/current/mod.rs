//! A _Current_ authenticated database provides succinct proofs of _any_ value ever associated with
//! a key, and also whether that value is the _current_ value associated with it.
//!
//! # Examples
//!
//! See [`crate::qmdb::any`] for batch API examples (forking, sequential
//! commit, staleness). The Current layer uses the same batch API.
//!
//! # Batch validity
//!
//! Current batches are branch-scoped views, not immutable snapshots.
//!
//! A batch remains valid only while its ancestor chain is still the committed prefix of the DB.
//! Once a non-ancestor batch is applied, that batch and all of its descendants are invalid
//! objects: do not read through them, do not build children from them, and do not attempt to
//! apply them.
//!
//! A short rule of thumb:
//! - A batch is only usable while it stays on the winning branch.
//!
//! Valid:
//! - Build `A`, apply `A`, then build `B` from `A` and read or merkleize `B`.
//! - Call [`Db::to_batch`](db::Db::to_batch) and use the returned batch only while no divergent
//!   branch has been applied.
//!
//! Invalid:
//! - Build siblings `B1` and `B2`, apply `B1`, then call `B2.get()`, `B2.new_batch()`, or
//!   `apply_batch(B2)`.
//! - Hold `snapshot = db.to_batch()`, mutate the DB through another branch, then use `snapshot`
//!   again.
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
//!   One exception by convention: the *current* `last_commit_loc` carries bit = 1 even though
//!   a CommitFloor is not an active update — earlier (intermediate) CommitFloors carry bit =
//!   0. Maintaining this makes the chunk containing the latest commit deterministic across
//!   init and `apply_batch`.
//!
//!   The bitmap lives on the inner `any::Db.bitmap`; `current::Db` reads through it for
//!   grafted-tree leaves and proofs.
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
//! tree's peak digests covering the pruned region are persisted to metadata as "pinned nodes".
//! On recovery, these pinned nodes are loaded and serve as opaque siblings during upward
//! propagation, allowing the grafted tree to be rebuilt without the pruned chunks.
//!
//! ### Delayed-merge settlement
//!
//! For families with delayed merges (e.g. MMB), pruning is slightly more conservative than
//! the inactivity floor alone would allow.
//!
//! The grafted root is computed by iterating the _ops tree's_ peaks and looking up the
//! corresponding nodes in the grafted tree. After pruning, only the grafted tree's pinned
//! peaks are available in the pruned region; interior nodes (including individual grafted
//! leaves) are discarded. If the ops tree has a peak that maps to a discarded grafted node,
//! root computation fails.
//!
//! In an MMR the ops tree's peaks within the pruned region always coincide with the grafted
//! tree's pinned peaks, so this is never a problem. In an MMB, delayed merges cause the ops
//! tree's peak structure to lag behind: a chunk pair's parent node at height `gh+1` is not
//! created until some number of leaves after the pair's last leaf. Until that merge happens,
//! the ops tree still has individual height-`gh` peaks for each chunk in the pair, and those
//! map to grafted _leaves_ (height 0 in the grafted tree), which are not pinned peaks.
//!
//! To avoid this, [`Db::prune`](db::Db::prune) defers bitmap pruning for chunks whose
//! chunk-pair parent has not yet been born in the ops tree (see
//! `Db::sync_boundary`). Once the parent is born, every ops peak within
//! the pruned region is at height `gh+1` or above, and maps to a pinned peak or an
//! ancestor of pinned peaks that can be reconstructed by hashing children (see
//! `grafting::Storage::reconstruct_grafted_node`).
//!
//! The same birth threshold also defines a _rewind floor_: rewinding the database to a size
//! where the chunk-pair parent has not been born would re-expose the individual ops peaks and
//! break reconstruction. [`Db::rewind`](db::Db::rewind) rejects targets below this floor.
//! The floor is a pure function of the pruned chunk count and the family geometry, so it does
//! not need to be persisted; it is recomputed on startup from the pruned chunk count stored
//! in metadata.
//!
//! The pruning lag is small: at most `2^(gh+1) - 1` ops beyond the chunk boundary
//! (just under 2 chunks for the default chunk size).
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
//!   against this root using ops-tree range proofs.
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
//! For state sync, the sync engine targets the ops root and verifies each batch against it. Callers
//! verifying ops proofs directly should use [`crate::qmdb::hasher`]. After sync, the bitmap and
//! grafted tree are reconstructed deterministically from the operations, and the canonical root is
//! computed.
//! [proof::OpsRootWitness] can be used to validate that a particular ops root is committed by a
//! trusted canonical root; the sync engine does not perform this check itself.

use crate::{
    index::Factory as IndexFactory,
    journal::{
        authenticated::Inner,
        contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    },
    merkle::{self, full::Config as MerkleConfig, Location},
    qmdb::{
        self,
        any::{
            self,
            operation::{Operation, Update},
            Config as AnyConfig,
        },
        bitmap::Shared,
        operation::Committable,
    },
    translator::Translator,
    Context,
};
use commonware_codec::{CodecShared, FixedSize};
use commonware_cryptography::Hasher;
use commonware_parallel::{Sequential, Strategy};
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
pub struct Config<T: Translator, J, S: Strategy = Sequential> {
    /// Configuration for the Merkle structure backing the authenticated journal.
    pub merkle_config: MerkleConfig<S>,

    /// Configuration for the operations log journal.
    pub journal_config: J,

    /// The name of the storage partition used for grafted tree metadata.
    pub grafted_metadata_partition: String,

    /// The translator used by the compressed index.
    pub translator: T,
}

impl<T: Translator, J, S: Strategy> From<Config<T, J, S>> for AnyConfig<T, J, S> {
    fn from(cfg: Config<T, J, S>) -> Self {
        Self {
            merkle_config: cfg.merkle_config,
            journal_config: cfg.journal_config,
            translator: cfg.translator,
        }
    }
}

/// Configuration for a `Current` authenticated db with fixed-size values.
pub type FixedConfig<T, S = Sequential> = Config<T, FConfig, S>;

/// Configuration for a `Current` authenticated db with variable-sized values.
pub type VariableConfig<T, C, S = Sequential> = Config<T, VConfig<C>, S>;

/// Initialize a `Current` authenticated db from the given config.
pub(super) async fn init<F, E, U, H, T, I, J, const N: usize, S>(
    context: E,
    config: Config<T, J::Config, S>,
) -> Result<db::Db<F, E, J, I, H, U, N, S>, crate::qmdb::Error<F>>
where
    F: merkle::Graftable,
    E: Context,
    U: Update + Send + Sync,
    H: Hasher,
    T: Translator,
    I: IndexFactory<T, Value = Location<F>>,
    J: Inner<E, Item = Operation<F, U>>,
    S: Strategy,
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

    let strategy = config.merkle_config.strategy.clone();
    let metadata_partition = config.grafted_metadata_partition.clone();

    // Load bitmap metadata (pruned_chunks + pinned nodes for the grafted tree).
    let (metadata, pruned_chunks, pinned_nodes) =
        db::init_metadata(context.child("metadata"), &metadata_partition).await?;

    // Pre-build the activity-status bitmap with the known pruned-chunk count from grafted
    // metadata, then hand it to `any` which becomes the sole owner. `any::init_with_bitmap`
    // populates it during snapshot rebuild.
    let bitmap = BitMap::<N>::new_with_pruned_chunks(pruned_chunks)
        .map_err(|_| crate::qmdb::Error::<F>::DataCorrupted("pruned chunks overflow"))?;
    let bitmap = Arc::new(Shared::<N>::new(bitmap));

    let any = any::init_with_bitmap(context.child("any"), config.into(), Some(bitmap)).await?;

    // Build the grafted tree from the bitmap and ops tree.
    let hasher = qmdb::hasher::<H>();
    let grafted_tree = db::build_grafted_tree::<F, H, S, N>(
        &hasher,
        any.bitmap.as_ref(),
        &pinned_nodes,
        &any.log.merkle,
        &strategy,
    )
    .await?;

    // Compute and cache the root.
    let storage = grafting::Storage::new(
        &grafted_tree,
        grafting::height::<N>(),
        &any.log.merkle,
        hasher.clone(),
    );
    let partial_chunk = db::partial_chunk(any.bitmap.as_ref());
    let ops_root = any.root();
    let root = db::compute_db_root(
        &hasher,
        any.bitmap.as_ref(),
        &storage,
        partial_chunk,
        any.inactivity_floor_loc,
        &ops_root,
    )
    .await?;

    Ok(db::Db {
        any,
        grafted_tree,
        metadata: AsyncMutex::new(metadata),
        strategy,
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
    use super::{ordered, unordered, FConfig, FixedConfig, MerkleConfig, VConfig, VariableConfig};
    use crate::{
        merkle::{self, mmb, mmr, Bagging::ForwardFold},
        qmdb::{
            self,
            any::{
                test::colliding_digest,
                traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
            },
            store::tests::{TestKey, TestValue},
        },
        translator::Translator,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        BufferPooler, Runner as _, Supervisor as _,
    };
    use commonware_utils::{bitmap::Readable, NZUsize, NZU16, NZU64};
    use core::future::Future;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::{
        num::{NonZeroU16, NonZeroUsize},
        sync::Arc,
    };
    use tracing::warn;

    type Error<F> = crate::qmdb::Error<F>;
    type Location<F> = merkle::Location<F>;
    type WriteVec<F, C> = Vec<(<C as DbAny<F>>::Key, Option<<C as DbAny<F>>::Value>)>;

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(88);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);

    /// Shared config factory for fixed-value Current QMDB tests.
    pub(crate) fn fixed_config<T: Translator + Default>(
        partition_prefix: &str,
        pooler: &impl BufferPooler,
    ) -> FixedConfig<T> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        FixedConfig {
            merkle_config: MerkleConfig {
                journal_partition: format!("{partition_prefix}-journal-partition"),
                metadata_partition: format!("{partition_prefix}-metadata-partition"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
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
        pooler: &impl BufferPooler,
    ) -> VariableConfig<T, ((), ())> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        VariableConfig {
            merkle_config: MerkleConfig {
                journal_partition: format!("{partition_prefix}-journal-partition"),
                metadata_partition: format!("{partition_prefix}-metadata-partition"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
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
            let mut db: C = open_db_clone(context.child("first"), partition.clone()).await;
            db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed, db)
                .await
                .unwrap();
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db.sync().await.unwrap();

            // Drop and reopen the db
            let root = db.root();
            drop(db);
            let db: C = open_db_clone(context.child("second"), partition).await;

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
            let mut db: C = open_db(context.child("first"), partition.clone()).await;
            db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed, db)
                .await
                .unwrap();
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            db.sync().await.unwrap();

            let root = db.root();
            drop(db);
            let db: C = open_db(context.child("second"), partition).await;
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
                let mut db: C = open_db(context.child("first"), partition.clone()).await;
                db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed, db)
                    .await
                    .unwrap();
                commit_writes(&mut db, []).await.unwrap();
                let committed_root = db.root();
                let committed_op_count = db.bounds().await.end;
                db.prune(db.sync_boundary().await).await.unwrap();

                // Perform more random operations without committing any of them.
                let db = apply_random_ops::<M, C>(ELEMENTS, false, rng_seed + 1, db)
                    .await
                    .unwrap();

                // SCENARIO #1: Simulate a crash that happens before any writes. Upon reopening, the
                // state of the DB should be as of the last commit.
                drop(db);
                let db: C = open_db(
                    context.child("scenario").with_attribute("index", 1),
                    partition.clone(),
                )
                .await;
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
                let db: C = open_db(
                    context.child("scenario").with_attribute("index", 2),
                    partition.clone(),
                )
                .await;
                let scenario_2_root = db.root();

                // To confirm the second committed hash is correct we'll re-build the DB in a new
                // partition, but without any failures. They should have the exact same state.
                let fresh_partition = "build-random-fail-commit-fresh".to_string();
                let mut db: C = open_db(context.child("fresh"), fresh_partition.clone()).await;
                db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed, db)
                    .await
                    .unwrap();
                commit_writes(&mut db, []).await.unwrap();
                db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed + 1, db)
                    .await
                    .unwrap();
                db.prune(db.sync_boundary().await).await.unwrap();
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
                open_db_clone(context.child("no_pruning"), "no-pruning-test".into()).await;
            let mut db_pruning: C = open_db(context.child("pruning"), "pruning-test".into()).await;

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
                        .prune(db_no_pruning.sync_boundary().await)
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
            let mut db: C = open_db_clone(context.child("first"), partition.clone()).await;

            // Apply random operations with commits to advance the inactivity floor.
            db = apply_random_ops::<M, C>(ELEMENTS, true, rng_seed, db).await.unwrap();
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();

            // Prune to flatten bitmap layers and advance pruned_chunks.
            db.prune(db.sync_boundary().await).await.unwrap();

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
            let db: C = open_db(context.child("second"), partition).await;

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
            let mut db: C = open_db_clone(context.child("first"), "build-big".into()).await;

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
            db.prune(db.sync_boundary().await).await.unwrap();

            // Record root before dropping.
            let root = db.root();
            db.sync().await.unwrap();
            drop(db);

            // Reopen the db and verify it has exactly the same state.
            let db: C = open_db(context.child("second"), "build-big".into()).await;
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
            let mut db: C = open_db(context.child("db"), "stale-side-effect-free".into()).await;

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
                <$db>::init(ctx.child("storage"), $cfg::<OneCap>(&partition, &ctx))
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

    async fn mmb_commit(
        db: &mut UnorderedVariableMmbDb,
        writes: impl IntoIterator<Item = (Digest, Option<Digest>)>,
    ) {
        let mut batch = db.new_batch();
        for (k, v) in writes {
            batch = batch.write(k, v);
        }
        let merkleized = batch.merkleize(db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
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
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>(partition, &ctx),
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
                context.child("reopen"),
                variable_config::<OneCap>(partition, &context),
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
                context.child("reopen_initial"),
                variable_config::<OneCap>(partition, &context),
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
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb =
                UnorderedVariableDb::init(ctx.child("storage"), variable_config::<OneCap>(partition, &ctx))
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
                context.child("reopen_pruned_recovery"),
                variable_config::<OneCap>(partition, &context),
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
                context.child("reopen_pruned_after_new_write"),
                variable_config::<OneCap>(partition, &context),
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

    /// Verify that the delayed-merge settlement guard holds `sync_boundary` at 0 during the
    /// unsettled window, so `prune` rejects any non-zero `prune_loc`.
    #[test_traced("INFO")]
    fn test_current_mmb_settlement_guard_defers_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const COMMITS: u64 = 100;

            let partition = "current-mmb-reopen-prove-after-prune";
            let ctx = context.child("db");
            let mut db: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>(partition, &ctx),
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
            assert_eq!(
                *db.sync_boundary(),
                0,
                "settlement guard should hold boundary at 0 during unsettled window"
            );

            // `prune` must reject any non-zero loc because sync_boundary is still 0.
            let result = db.prune(Location::<mmb::Family>::new(1)).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(_, _))),
                "expected PruneBeyondMinRequired, got {result:?}"
            );
            assert_eq!(db.pruned_bits(), 0);
            db.sync().await.unwrap();
            drop(db);

            // Reopen: no pruning occurred, state is unchanged.
            let reopened: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                context.child("reopen"),
                variable_config::<OneCap>(partition, &context),
            )
            .await
            .unwrap();

            assert_eq!(reopened.root(), root_before);
            assert_eq!(reopened.get(&k).await.unwrap(), expected);

            // key_value_proof: RangeProof::new must also handle pruned chunk 0.
            let hasher = crate::qmdb::hasher::<Sha256>();
            let _proof = reopened.key_value_proof(&hasher, k).await.unwrap();

            reopened.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_current_mmb_rewind_rejects_unsettled_pruned_window() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const COMMITS: u64 = 320;
            const N: usize = 32;

            let partition = "current-mmb-rewind-unsettled-window";
            let ctx = context.child("db");
            let mut db: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>(partition, &ctx),
            )
            .await
            .unwrap();

            let key0 = key(0);
            let mut history = Vec::new();
            for round in 0..COMMITS {
                let mut batch = db.new_batch();
                batch = batch.write(key0, Some(val(60_000 + round)));
                let merkleized = batch.merkleize(&db, None).await.unwrap();
                db.apply_batch(merkleized).await.unwrap();
                db.commit().await.unwrap();
                history.push((db.bounds().await.end, db.inactivity_floor_loc()));
            }

            db.prune(db.sync_boundary()).await.unwrap();
            let pruned_bits = db.pruned_bits();
            assert!(pruned_bits > 0, "expected MMB bitmap pruning to be active");
            db.sync().await.unwrap();

            let chunk_bits = commonware_utils::bitmap::BitMap::<N>::CHUNK_SIZE_BITS;
            let pruned_chunks = (pruned_bits / chunk_bits) as u64;
            let gh = super::grafting::height::<N>();
            let youngest = pruned_chunks - 1;
            let pair_chunk = youngest & !1;
            let pair_start = pair_chunk << gh;
            let pair_pos = <mmb::Family as merkle::Graftable>::subtree_root_position(
                merkle::Location::<mmb::Family>::new(pair_start),
                gh + 1,
            );
            let absorbed_after =
                <mmb::Family as merkle::Graftable>::peak_birth_size(pair_pos, gh + 1);

            let unsafe_target = history
                .iter()
                .filter_map(|(size, floor)| {
                    let s = **size;
                    if s >= pruned_bits && s < absorbed_after && **floor >= pruned_bits {
                        Some(s)
                    } else {
                        None
                    }
                })
                .max()
                .unwrap_or_else(|| {
                    panic!(
                        "expected rewind target in unsettled window: pruned_bits={pruned_bits}, absorbed_after={absorbed_after}, history={history:?}"
                    )
                });

            let err = db
                .rewind(merkle::Location::<mmb::Family>::new(unsafe_target))
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::Journal(crate::journal::Error::ItemPruned(_))),
                "unexpected rewind error for unsettled delayed-merge window: {err:?}"
            );
            drop(db);

            let reopened: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                context.child("reopen"),
                variable_config::<OneCap>(partition, &context),
            )
            .await
            .unwrap();
            reopened.destroy().await.unwrap();
        });
    }

    /// Verify that `Db::prune` never advances the ops journal past the settled bitmap
    /// pruning boundary on a delayed-merge (MMB) family. The journal's lower bound must be
    /// less than or equal to `sync_boundary()`, and the test setup must force the lag to
    /// be strictly active so the assertion is not vacuous.
    #[test_traced]
    fn test_current_mmb_prune_respects_sync_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const COMMITS: u64 = 320;

            let ctx = context.child("db");
            let mut db: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("prune-clip-mmb", &ctx),
            )
            .await
            .unwrap();

            let k = key(0);
            for round in 0..COMMITS {
                mmb_commit(&mut db, [(k, Some(val(70_000 + round)))]).await;
            }

            db.prune(db.sync_boundary()).await.unwrap();

            let boundary = db.sync_boundary();
            let floor = db.inactivity_floor_loc();
            assert!(
                boundary < floor,
                "delayed-merge lag must be strictly active: boundary={boundary}, floor={floor}"
            );
            assert!(
                db.bounds().await.start <= boundary,
                "ops journal was pruned past the settled bitmap boundary: \
                 bounds.start={}, boundary={boundary}",
                db.bounds().await.start
            );

            db.destroy().await.unwrap();
        });
    }

    /// Verify that on a non-delayed-merge (MMR) family `sync_boundary()` lags the inactivity
    /// floor only by chunk alignment (less than one chunk) — never by a delayed-merge absorption
    /// window. Guards against an accidental regression that would introduce a larger lag on
    /// families that don't need it.
    #[test_traced]
    fn test_current_mmr_prune_boundary_lag_is_only_chunk_alignment() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const COMMITS: u64 = 320;
            const N: usize = 32;

            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("prune-clip-mmr", &ctx),
            )
            .await
            .unwrap();

            for round in 0..COMMITS {
                commit_writes_with_metadata(
                    &mut db,
                    [(key(0), Some(val(80_000 + round)))],
                    None,
                )
                .await;
            }

            db.prune(db.sync_boundary()).await.unwrap();

            let boundary = db.sync_boundary();
            let floor = db.inactivity_floor_loc();
            let chunk_bits = commonware_utils::bitmap::BitMap::<N>::CHUNK_SIZE_BITS;
            assert!(
                boundary <= floor && *floor - *boundary < chunk_bits,
                "MMR lag should be only chunk alignment: boundary={boundary}, floor={floor}, chunk_bits={chunk_bits}"
            );
            assert!(
                db.bounds().await.start <= boundary,
                "ops journal bounds must be <= sync_boundary: bounds.start={}, boundary={boundary}",
                db.bounds().await.start
            );

            db.destroy().await.unwrap();
        });
    }

    /// Verify that `prune(loc)` with `loc < sync_boundary()` prunes the ops journal only as far
    /// as the caller requested.
    #[test_traced]
    fn test_current_prune_below_settled_boundary_is_honored() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const COMMITS: u64 = 100;

            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("prune-below-boundary", &ctx),
            )
            .await
            .unwrap();

            for round in 0..COMMITS {
                commit_writes_with_metadata(&mut db, [(key(0), Some(val(90_000 + round)))], None)
                    .await;
            }

            assert!(*db.inactivity_floor_loc() > 1);
            let small = Location::new(1);
            db.prune(small).await.unwrap();

            assert!(
                db.bounds().await.start <= small,
                "journal pruning exceeded the caller-supplied target: bounds.start={}, requested={small}",
                db.bounds().await.start
            );

            db.destroy().await.unwrap();
        });
    }

    /// Prune, then grow without pruning again so delayed MMB merges occur inside the
    /// already-pruned region. Verify proof + reopen correctness.
    #[test_traced]
    fn test_current_mmb_reopen_and_prove_after_prune_delayed_merge() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_ctx = context.child("db_init");
            let mut db: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                db_ctx.child("db"),
                variable_config::<OneCap>("test_prune_delayed_merge", &db_ctx),
            )
            .await
            .unwrap();

            let k = key(0);

            for round in 0..200u64 {
                mmb_commit(&mut db, [(k, Some(val(60_000 + round)))]).await;
            }

            db.prune(db.sync_boundary()).await.unwrap();
            db.sync().await.unwrap();

            // Keep growing without pruning: delayed merges now occur in the pruned region.
            for round in 200..300u64 {
                mmb_commit(&mut db, [(key(1), Some(val(round)))]).await;
            }

            let hasher = crate::qmdb::hasher::<Sha256>();
            let proof = db.key_value_proof(&hasher, k).await.unwrap();
            assert!(UnorderedVariableMmbDb::verify_key_value_proof(
                &hasher,
                k,
                val(60_000 + 199),
                &proof,
                &db.root()
            ));

            let target_root = db.root();
            drop(db);

            let reopen_ctx = context.child("db_reopen");
            let reopened: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                reopen_ctx.child("db"),
                variable_config::<OneCap>("test_prune_delayed_merge", &reopen_ctx),
            )
            .await
            .unwrap();

            assert_eq!(reopened.root(), target_root);

            let hasher = crate::qmdb::hasher::<Sha256>();
            let proof = reopened.key_value_proof(&hasher, k).await.unwrap();
            assert!(UnorderedVariableMmbDb::verify_key_value_proof(
                &hasher,
                k,
                val(60_000 + 199),
                &proof,
                &reopened.root()
            ));

            reopened.destroy().await.unwrap();
        });
    }

    /// Grow past 2 full pruned chunks, prune, reopen, verify root + value.
    #[test_traced]
    fn test_current_mmb_reopen_after_prune_two_chunks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_ctx = context.child("db");
            let mut db: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                db_ctx.child("db"),
                variable_config::<OneCap>("test_prune_two", &db_ctx),
            )
            .await
            .unwrap();

            let k = key(0);
            // Always assigned before the loop breaks.
            let mut expected;

            // Keep growing until the settle guard allows 2+ pruned chunks.
            // The absorber for chunk pair [0,1] at gh=8 needs ~766 ops leaves.
            let mut round = 0u64;
            loop {
                expected = Some(val(60_000 + round));
                mmb_commit(&mut db, [(k, expected)]).await;
                round += 1;
                db.prune(db.sync_boundary()).await.unwrap();
                if db.pruned_bits() >= 512 {
                    break;
                }
                assert!(
                    round < 500,
                    "failed to reach 2 pruned chunks after {round} commits"
                );
            }
            db.sync().await.unwrap();

            let target_root = db.root();
            drop(db);

            let reopen_ctx = context.child("db_reopen");
            let reopened: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                reopen_ctx.child("db"),
                variable_config::<OneCap>("test_prune_two", &reopen_ctx),
            )
            .await
            .unwrap();

            assert_eq!(reopened.root(), target_root);
            assert_eq!(reopened.get(&k).await.unwrap(), expected);
            reopened.destroy().await.unwrap();
        });
    }

    /// Three rounds of grow + prune + reopen. Verifies repeated prune cycles don't diverge.
    #[test_traced]
    fn test_current_mmb_repeated_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db_ctx = context.child("db_init");
            let mut db: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                db_ctx.child("db"),
                variable_config::<OneCap>("test_repeated_prune", &db_ctx),
            )
            .await
            .unwrap();

            for round in 0..3u64 {
                let k = key(round * 1000);
                let mut expected = None;
                for i in 0..90 {
                    expected = Some(val(round * 1000 + i));
                    mmb_commit(&mut db, [(k, expected)]).await;
                }

                db.prune(db.sync_boundary()).await.unwrap();
                db.sync().await.unwrap();

                let root_before = db.root();
                db_ctx = context.child("db").with_attribute("round", round);

                let prev_db = db;
                db = UnorderedVariableMmbDb::init(
                    db_ctx.child("db"),
                    variable_config::<OneCap>("test_repeated_prune", &db_ctx),
                )
                .await
                .unwrap();

                assert_eq!(db.root(), root_before);
                assert_eq!(db.get(&k).await.unwrap(), expected);
                drop(prev_db);
            }

            db.destroy().await.unwrap();
        });
    }

    /// Step-by-step growth after prune, comparing roots against an unpruned reference.
    #[test_traced]
    fn test_current_mmb_stepwise_growth_matches_unpruned_reference() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_ctx = context.child("db_stepwise");
            let mut db: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                db_ctx.child("db"),
                variable_config::<OneCap>("test_stepwise", &db_ctx),
            )
            .await
            .unwrap();

            let ref_ctx = context.child("ref_stepwise");
            let mut ref_db: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                ref_ctx.child("db"),
                variable_config::<OneCap>("test_stepwise_ref", &ref_ctx),
            )
            .await
            .unwrap();

            let k = key(0);
            let mut commit_idx = 0u64;

            // Grow until the inactivity floor reaches 4 chunks.
            while *db.inactivity_floor_loc() < 1024 {
                let value = Some(val(80_000 + commit_idx));
                mmb_commit(&mut db, [(k, value)]).await;
                mmb_commit(&mut ref_db, [(k, value)]).await;
                commit_idx += 1;
            }

            db.prune(db.sync_boundary()).await.unwrap();
            db.sync().await.unwrap();
            assert_eq!(
                db.root(),
                ref_db.root(),
                "root mismatch immediately after prune"
            );

            // Step-by-step growth through the delayed-merge window.
            loop {
                let db_leaves =
                    *Location::<mmb::Family>::try_from(db.any.log.merkle.size()).unwrap();
                if db_leaves >= 1560 {
                    break;
                }

                let value = Some(val(80_000 + commit_idx));
                mmb_commit(&mut db, [(k, value)]).await;
                mmb_commit(&mut ref_db, [(k, value)]).await;
                commit_idx += 1;

                let db_leaves =
                    *Location::<mmb::Family>::try_from(db.any.log.merkle.size()).unwrap();
                assert_eq!(
                    db.root(),
                    ref_db.root(),
                    "stepwise root mismatch: leaves={db_leaves}, commit_idx={commit_idx}"
                );
            }

            db.destroy().await.unwrap();
            ref_db.destroy().await.unwrap();
        });
    }

    /// Multi-round prune + reopen + proof against an unpruned reference.
    #[test_traced]
    fn test_current_mmb_large_repeated_prune_matches_unpruned_reference() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const ROUNDS: u64 = 8;
            const COMMITS_PER_ROUND: u64 = 120;

            let mut db_ctx = context.child("db_init");
            let mut db: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                db_ctx.child("db"),
                variable_config::<OneCap>("test_large_prune", &db_ctx),
            )
            .await
            .unwrap();

            let ref_ctx = context.child("ref");
            let mut ref_db: UnorderedVariableMmbDb = UnorderedVariableMmbDb::init(
                ref_ctx.child("db"),
                variable_config::<OneCap>("test_large_prune_ref", &ref_ctx),
            )
            .await
            .unwrap();

            let k = key(0);
            let mut expected = None;

            for round in 0..ROUNDS {
                for i in 0..COMMITS_PER_ROUND {
                    let value = Some(val(round * 10_000 + i));
                    expected = value;
                    mmb_commit(&mut db, [(k, value)]).await;
                    mmb_commit(&mut ref_db, [(k, value)]).await;
                }

                assert_eq!(
                    db.root(),
                    ref_db.root(),
                    "root mismatch before prune at round {round}"
                );

                db.prune(db.sync_boundary()).await.unwrap();
                db.sync().await.unwrap();

                assert_eq!(
                    db.root(),
                    ref_db.root(),
                    "root mismatch after prune at round {round}"
                );

                let hasher = crate::qmdb::hasher::<Sha256>();
                let proof = db.key_value_proof(&hasher, k).await.unwrap();
                assert!(
                    UnorderedVariableMmbDb::verify_key_value_proof(
                        &hasher,
                        k,
                        expected.expect("value should exist"),
                        &proof,
                        &db.root()
                    ),
                    "proof verification failed at round {round}"
                );

                db_ctx = context.child("db_reopen").with_attribute("round", round);
                let prev_db = db;
                db = UnorderedVariableMmbDb::init(
                    db_ctx.child("db"),
                    variable_config::<OneCap>("test_large_prune", &db_ctx),
                )
                .await
                .unwrap();

                assert_eq!(
                    db.root(),
                    ref_db.root(),
                    "root mismatch after reopen at round {round}"
                );
                assert_eq!(
                    db.get(&k).await.unwrap(),
                    expected,
                    "value mismatch after reopen at round {round}"
                );

                let hasher = crate::qmdb::hasher::<Sha256>();
                let proof = db.key_value_proof(&hasher, k).await.unwrap();
                assert!(
                    UnorderedVariableMmbDb::verify_key_value_proof(
                        &hasher,
                        k,
                        expected.expect("value should exist"),
                        &proof,
                        &db.root()
                    ),
                    "proof verification failed after reopen at round {round}"
                );

                drop(prev_db);
            }

            db.destroy().await.unwrap();
            ref_db.destroy().await.unwrap();
        });
    }

    /// Verify that prune beyond the sync boundary is rejected without mutating state.
    #[test_traced]
    fn test_current_prune_rejects_beyond_sync_boundary_without_mutation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const COMMITS: u64 = 160;

            let partition = "current-prune-beyond-boundary";
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>(partition, &ctx),
            )
            .await
            .unwrap();

            let key0 = key(0);
            for round in 0..COMMITS {
                commit_writes_with_metadata(&mut db, [(key0, Some(val(40_000 + round)))], None)
                    .await;
            }

            let expected_root = db.root();
            let expected_ops_root = db.ops_root();
            let expected_boundary = db.sync_boundary();
            let expected_pruned_bits = db.pruned_bits();
            let expected_value = db.get(&key0).await.unwrap();

            // 32 * 8 = 256 bits per chunk for N=32.
            let invalid_prune_loc = Location::new(*expected_boundary + 256);
            let result = db.prune(invalid_prune_loc).await;
            assert!(
                matches!(result, Err(Error::PruneBeyondMinRequired(loc, boundary))
                    if loc == invalid_prune_loc && boundary == expected_boundary),
                "expected prune rejection above sync boundary, got {result:?}"
            );

            assert_eq!(db.root(), expected_root);
            assert_eq!(db.ops_root(), expected_ops_root);
            assert_eq!(db.pruned_bits(), expected_pruned_bits);
            assert_eq!(db.get(&key0).await.unwrap(), expected_value);

            drop(db);

            let reopened: UnorderedVariableDb = UnorderedVariableDb::init(
                context.child("reopen"),
                variable_config::<OneCap>(partition, &context),
            )
            .await
            .unwrap();
            assert_eq!(reopened.root(), expected_root);
            assert_eq!(reopened.ops_root(), expected_ops_root);
            assert_eq!(reopened.pruned_bits(), expected_pruned_bits);
            assert_eq!(reopened.get(&key0).await.unwrap(), expected_value);

            reopened.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_current_rewind_small_delta_large_history() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const COMMITS: u64 = 200;

            let partition = "current-rewind-small-delta";
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>(partition, &ctx),
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
                context.child("reopen_small_delta"),
                variable_config::<OneCap>(partition, &context),
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
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb =
                UnorderedVariableDb::init(ctx.child("storage"), variable_config::<OneCap>(partition, &ctx))
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

            db.prune(db.sync_boundary()).await.unwrap();
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
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb =
                UnorderedVariableDb::init(ctx.child("storage"), variable_config::<OneCap>(partition, &ctx))
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
            let mut db: C = open_db_clone(context.child("init"), partition.clone()).await;
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

            let db: C = open_db(context.child("reopen"), partition).await;
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
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("mg", &ctx),
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
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("ch", &ctx),
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
            let ctx = context.child("db");
            let mut db: UnorderedFixedDb =
                UnorderedFixedDb::init(ctx.child("storage"), fixed_config::<OneCap>("ucr", &ctx))
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
            let ctx = context.child("db");
            let mut db: OrderedFixedDb =
                OrderedFixedDb::init(ctx.child("storage"), fixed_config::<OneCap>("ocr", &ctx))
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
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>(partition, &ctx),
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
                context.child("reopen"),
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
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("pipe", &ctx),
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
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("ff", &ctx),
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
            let ctx2 = context.child("db").with_attribute("index", 2);
            let mut db2: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx2.child("db"),
                variable_config::<OneCap>("ff2", &ctx2),
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
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("tb", &ctx),
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

    /// A live batch (built off the committed state) must remain readable and applicable after
    /// [`Db::prune`] advances the shared bitmap's pruning boundary. Pruning only discards
    /// chunks for inactive bits (below the inactivity floor); the batch's own chain and
    /// overlays operate at or above the floor, so no reads should land in the pruned region.
    #[test_traced("INFO")]
    fn test_current_live_batch_safe_across_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("prune-live", &ctx),
            )
            .await
            .unwrap();

            // Seed enough ops to span multiple bitmap chunks.
            let mut seed = db.new_batch();
            for i in 0u64..300 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let seed_m = seed.merkleize(&db, None).await.unwrap();
            db.apply_batch(seed_m).await.unwrap();
            db.commit().await.unwrap();

            // Overwrite keys 0..250 so the inactivity floor advances past chunk 0.
            let mut p = db.new_batch();
            for i in 0u64..250 {
                p = p.write(key(i), Some(val(i + 10_000)));
            }
            let p_m = p.merkleize(&db, None).await.unwrap();
            db.apply_batch(Arc::clone(&p_m)).await.unwrap();
            db.commit().await.unwrap();

            // Build c off p_m; c is live and shares the committed bitmap via its chain.
            let c = p_m
                .new_batch::<Sha256>()
                .write(key(250), Some(val(99_999)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Prune with c still alive. This advances pruned_chunks on the shared bitmap.
            db.prune(db.sync_boundary()).await.unwrap();

            // Sanity: c's pending write is still readable via the any-layer diff chain.
            assert_eq!(c.get(&key(250), &db).await.unwrap(), Some(val(99_999)));

            // The actual prune-interaction test: apply c after prune. apply_batch skips overlay
            // chunks below the current pruned boundary.
            db.apply_batch(c).await.unwrap();
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(10_000)));
            assert_eq!(db.get(&key(250)).await.unwrap(), Some(val(99_999)));

            db.destroy().await.unwrap();
        });
    }

    /// Regression: extending a batch after it has been applied (building a child off the
    /// just-applied parent) must produce correct data.
    ///
    /// With the shared-bitmap `RwLock` design, applying `A` mutates the committed bitmap in
    /// place; reads through `A`'s chain after apply fall through to the committed bitmap (which
    /// now reflects `A`'s state), and `A`'s own overlays applied on top are consistent with
    /// committed. So `A.new_batch()` followed by merkleize + apply is the right-by-construction
    /// case, and this test locks it in.
    #[test_traced("INFO")]
    fn test_current_extend_applied_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("xtend", &ctx),
            )
            .await
            .unwrap();

            // Apply A, retaining our Arc so we can extend it post-apply.
            let a = db
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(Arc::clone(&a)).await.unwrap();

            // Build B off A after A was applied. B's chain walks through A's layer and falls
            // through to the committed bitmap (now post-A). B's merkleize must read consistent
            // state from both sources.
            let b = a
                .new_batch::<Sha256>()
                .write(key(1), Some(val(1)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(b).await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));

            // Extend once more to lock in multi-generation behavior.
            let c = db
                .new_batch()
                .write(key(2), Some(val(2)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(c).await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));
            assert_eq!(db.get(&key(2)).await.unwrap(), Some(val(2)));

            db.destroy().await.unwrap();
        });
    }

    /// Build a child batch from a still-live parent whose apply was followed by a prune, then
    /// merkleize and apply the child. The parent's `BitmapBatch` chain terminates in the shared
    /// committed bitmap, and `prune` mutates that bitmap's pruning boundary in place. When the
    /// child is constructed via `parent.new_batch()`, the internal `trim_committed` call must
    /// observe the advanced boundary and produce a correct child chain; merkleize and apply must
    /// then produce correct state for keys at and beyond the advanced floor.
    #[test_traced("INFO")]
    fn test_current_live_batch_child_after_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("child-after-prune", &ctx),
            )
            .await
            .unwrap();

            // Seed enough ops to span multiple bitmap chunks.
            let mut seed = db.new_batch();
            for i in 0u64..300 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let seed_m = seed.merkleize(&db, None).await.unwrap();
            db.apply_batch(seed_m).await.unwrap();
            db.commit().await.unwrap();

            // Overwrite keys 0..250 so the inactivity floor advances past chunk 0.
            let mut a_batch = db.new_batch();
            for i in 0u64..250 {
                a_batch = a_batch.write(key(i), Some(val(i + 10_000)));
            }
            let a = a_batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(Arc::clone(&a)).await.unwrap();
            db.commit().await.unwrap();

            // Prune while `a` is still live. Mutates the shared bitmap's pruning boundary in place.
            db.prune(db.sync_boundary()).await.unwrap();

            // Extend `a` into `b` AFTER the prune. Building `b` off `a` triggers
            // `trim_committed` on `a`'s chain, which must correctly see the advanced pruning
            // boundary on the shared bitmap.
            let b = a
                .new_batch::<Sha256>()
                .write(key(300), Some(val(300)))
                .merkleize(&db, None)
                .await
                .unwrap();

            db.apply_batch(b).await.unwrap();
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(10_000)));
            assert_eq!(db.get(&key(249)).await.unwrap(), Some(val(10_249)));
            assert_eq!(db.get(&key(300)).await.unwrap(), Some(val(300)));

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
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("adrop", &ctx),
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
            let ctx1 = context.child("db").with_attribute("index", 1);
            let mut db1: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx1.child("db"),
                variable_config::<OneCap>("ord1", &ctx1),
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
            let ctx2 = context.child("db").with_attribute("index", 2);
            let mut db2: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx2.child("db"),
                variable_config::<OneCap>("ord2", &ctx2),
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

    /// Regression: C's diff entry has a stale `base_old_loc` (255) pointing into a chunk that
    /// was pruned after parent P was committed. `committed_locs` precedence in
    /// `any::Db::apply_batch` must override the stale value with P's rewrite location, so the
    /// `set_bit(false)` call targets P's (post-floor-raise) loc, not the pruned chunk.
    ///
    /// With N=32, CHUNK_SIZE_BITS=256. Seed places key(0) at loc 255 (end of chunk 0). P
    /// overwrites keys 1..254; P's floor-raise moves key(0) from 255 to a fresh loc above 255.
    /// C is built from P and writes key(0) again. After committing P and pruning chunk 0, C's
    /// pre-merkleize `base_old_loc=255` is no longer the right clear target — `committed_locs`
    /// substitutes P's rewrite loc instead. If that precedence path broke, apply would panic
    /// (`set_bit` on a pruned bit).
    #[test_traced("WARN")]
    fn test_current_stale_bitmap_clears_after_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("stale-clears", &ctx),
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

            db.prune(db.sync_boundary()).await.unwrap();
            db.apply_batch(c_m).await.unwrap();

            db.destroy().await.unwrap();
        });
    }

    /// Apply C (grandchild of A) after only A is committed. B's data (any-layer
    /// snapshot diff + current-layer bitmap) must still be applied.
    #[test_traced("INFO")]
    fn test_current_partial_ancestor_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("pac", &ctx),
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
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("bmo", &ctx),
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
            let ref_ctx = context.child("ref");
            let mut ref_db: UnorderedVariableDb = UnorderedVariableDb::init(
                ref_ctx.child("db"),
                variable_config::<OneCap>("bmo_ref", &ref_ctx),
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

    /// Regression: the bitmap chunks produced by the speculative `BitmapBatch` chain during
    /// merkleize must equal the bytes that `any::Db::apply_batch` writes via diff-driven
    /// updates. `current::Db::apply_batch` relies on this equivalence to install the precomputed
    /// `batch.grafted` against the now-current bitmap.
    ///
    /// The workload spans multiple bitmap chunks and exercises:
    /// - parent/child same-key overwrite (`committed_locs` precedence path),
    /// - parent-create then child-delete (uncommitted-ancestor precedence),
    /// - mixed deletes and overwrites in different chunks (clear-bit + set-bit paths).
    #[test_traced("INFO")]
    fn test_current_apply_chunks_match_speculative_chunks() {
        const N: usize = 32;
        const CHUNK_SIZE_BITS: u64 = commonware_utils::bitmap::Prunable::<N>::CHUNK_SIZE_BITS;
        // Seed enough keys to cross at least one chunk boundary. Each batch also produces a
        // CommitFloor op, so the bitmap grows past the user-visible key count.
        const SEED_KEYS: u64 = CHUNK_SIZE_BITS + 50;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let mut db: UnorderedVariableDb = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_config::<OneCap>("spec_eq", &ctx),
            )
            .await
            .unwrap();

            // Seed all keys in one committed batch.
            let seed = (0..SEED_KEYS).fold(db.new_batch(), |b, i| b.write(key(i), Some(val(i))));
            let seed = seed.merkleize(&db, None).await.unwrap();
            db.apply_batch(seed).await.unwrap();
            db.commit().await.unwrap();

            // Setup sanity: the committed bitmap spans at least two chunks.
            assert!(
                Readable::<N>::len(db.any.bitmap.as_ref()) > CHUNK_SIZE_BITS,
                "setup must cross a chunk boundary",
            );

            // Parent (uncommitted): overwrites + delete + creates spread across the bitmap.
            let parent = db
                .new_batch()
                .write(key(10), Some(val(110))) // overwrite (low chunk)
                .write(key(50), None) // delete (low chunk)
                .write(key(CHUNK_SIZE_BITS + 5), Some(val(120))) // overwrite (high chunk)
                .write(key(SEED_KEYS), Some(val(130))) // create new key
                .write(key(SEED_KEYS + 1), Some(val(131))) // create new key
                .merkleize(&db, None)
                .await
                .unwrap();

            // Child (uncommitted, descendant of parent):
            //   - same-key overwrite of parent's key(10)        -> committed_locs precedence
            //   - delete of parent's just-created key(SEED_KEYS) -> uncommitted-create-child-delete
            //   - additional delete + overwrite in mixed chunks -> set-bit + clear-bit coverage
            let child = parent
                .new_batch::<Sha256>()
                .write(key(10), Some(val(210)))
                .write(key(SEED_KEYS), None)
                .write(key(75), None)
                .write(key(CHUNK_SIZE_BITS + 30), Some(val(220)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Snapshot every chunk in the speculative `BitmapBatch` chain (read through child).
            let speculative_chunks: Vec<[u8; N]> = {
                let len = Readable::<N>::len(&child.bitmap);
                let chunk_count = len.div_ceil(CHUNK_SIZE_BITS) as usize;
                (0..chunk_count)
                    .map(|idx| Readable::<N>::get_chunk(&child.bitmap, idx))
                    .collect()
            };
            // Setup sanity: speculative state spans at least two chunks.
            assert!(speculative_chunks.len() >= 2);

            // Apply child (commits parent + child) and re-read every chunk from the committed
            // bitmap. The two views must be byte-identical; otherwise the precomputed
            // `batch.canonical_root` is no longer valid against the post-apply state.
            db.apply_batch(child).await.unwrap();
            let committed_chunks: Vec<[u8; N]> = {
                let len = Readable::<N>::len(db.any.bitmap.as_ref());
                let chunk_count = len.div_ceil(CHUNK_SIZE_BITS) as usize;
                (0..chunk_count)
                    .map(|idx| Readable::<N>::get_chunk(db.any.bitmap.as_ref(), idx))
                    .collect()
            };

            assert_eq!(
                speculative_chunks, committed_chunks,
                "speculative chunks must equal post-apply committed chunks across all chunks",
            );

            db.destroy().await.unwrap();
        });
    }

    /// Regression: `ops_historical_proof` must verify with QMDB's ops-tree hasher configuration.
    #[test_traced("INFO")]
    fn test_current_mmb_ops_historical_proof_verifies_with_backward_bagging() {
        use crate::{merkle::hasher::Standard, qmdb::verify_proof};
        use commonware_utils::NZU64;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let mut db: UnorderedFixedMmbDb = UnorderedFixedMmbDb::init(
                ctx.child("storage"),
                fixed_config::<OneCap>("mmb-ops-proof", &ctx),
            )
            .await
            .unwrap();

            // Apply a batch and commit so an ops historical proof exists.
            let writes: Vec<(Digest, Option<Digest>)> =
                (0u64..16).map(|i| (key(i), Some(val(i)))).collect();
            commit_writes(&mut db, writes).await.unwrap();

            let ops_root = db.ops_root();
            let historical_size = db.bounds().await.end;
            let (proof, ops) = db
                .ops_historical_proof(historical_size, Location::new(0), NZU64!(32))
                .await
                .unwrap();

            // Verifies under the QMDB ops-tree hasher configuration.
            let hasher = qmdb::hasher::<Sha256>();
            assert!(verify_proof(
                &hasher,
                &proof,
                Location::new(0),
                &ops,
                &ops_root
            ));

            // Sanity: a different Merkle hasher configuration must not accept this proof.
            let plain = Standard::<Sha256>::new(ForwardFold);
            assert!(!verify_proof(
                &plain,
                &proof,
                Location::new(0),
                &ops,
                &ops_root
            ));

            db.destroy().await.unwrap();
        });
    }
}
