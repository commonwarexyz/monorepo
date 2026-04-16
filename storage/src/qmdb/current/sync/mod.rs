//! Shared synchronization logic for [crate::qmdb::current] databases.
//!
//! Contains implementation of [crate::qmdb::sync::Database] for all [Db](crate::qmdb::current::db::Db)
//! variants (ordered/unordered, fixed/variable).
//!
//! The canonical root of a `current` database combines the ops root, grafted MMR root, and
//! optional partial chunk into a single hash (see the [Root structure](super) section in the
//! module documentation). The sync engine operates on the **ops root**, not the canonical root:
//! it downloads operations and verifies each batch against the ops root using standard MMR
//! range proofs (identical to `any` sync). Validating that the ops root is part of the
//! canonical root is the caller's responsibility; the sync engine does not perform this check.
//!
//! After all operations are synced, the bitmap and grafted MMR are reconstructed
//! deterministically from the operations. The canonical root is then computed from the
//! ops root, the reconstructed grafted MMR root, and any partial chunk.
//!
//! The [Database]`::`[root()](crate::qmdb::sync::Database::root)
//! implementation returns the **ops root** (not the canonical root) because that is what the
//! sync engine verifies against.
//!
//! For pruned databases (`range.start > 0`), grafted MMR pinned nodes for the pruned region
//! are read directly from the ops MMR after it is built. This works because of the zero-chunk
//! identity: for all-zero bitmap chunks (which all pruned chunks are), the grafted leaf equals
//! the ops subtree root, making the grafted MMR structurally identical to the ops MMR at and
//! above the grafting height.

use crate::{
    index::Factory as IndexFactory,
    journal::{
        authenticated,
        contiguous::{fixed, variable, Mutable},
    },
    merkle::{
        mmr::{self, Family, Location, StandardHasher},
        Family as _,
    },
    qmdb::{
        self,
        any::{
            db::Db as AnyDb,
            operation::{update::Update, Operation},
            ordered::{
                fixed::{Operation as OrderedFixedOp, Update as OrderedFixedUpdate},
                variable::{Operation as OrderedVariableOp, Update as OrderedVariableUpdate},
            },
            unordered::{
                fixed::{Operation as UnorderedFixedOp, Update as UnorderedFixedUpdate},
                variable::{Operation as UnorderedVariableOp, Update as UnorderedVariableUpdate},
            },
            FixedValue, VariableValue,
        },
        current::{
            db, grafting,
            ordered::{
                fixed::Db as CurrentOrderedFixedDb, variable::Db as CurrentOrderedVariableDb,
            },
            unordered::{
                fixed::Db as CurrentUnorderedFixedDb, variable::Db as CurrentUnorderedVariableDb,
            },
            FixedConfig, VariableConfig,
        },
        operation::{Committable, Key},
        sync::{Database, DatabaseConfig as Config},
    },
    translator::Translator,
    Context, Persistable,
};
use commonware_codec::{Codec, CodecShared, Read as CodecRead};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_utils::{bitmap::Prunable as BitMap, channel::oneshot, sync::AsyncMutex, Array};
use std::{ops::Range, sync::Arc};

#[cfg(test)]
pub(crate) mod tests;

impl<T: Translator, J: Clone> Config for super::Config<T, J> {
    type JournalConfig = J;

    fn journal_config(&self) -> Self::JournalConfig {
        self.journal_config.clone()
    }
}

/// Shared helper to build a `current::db::Db` from sync components.
///
/// This follows the same pattern as `any/sync/mod.rs::build_db` but additionally:
/// * Builds the activity bitmap by replaying the operations log.
/// * Extracts grafted pinned nodes from the ops MMR (zero-chunk identity).
/// * Builds the grafted MMR from the bitmap and ops MMR.
/// * Computes and caches the canonical root.
#[allow(clippy::too_many_arguments)]
async fn build_db<E, U, I, H, J, T, const N: usize>(
    context: E,
    mmr_config: mmr::journaled::Config,
    log: J,
    translator: T,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: Range<Location>,
    apply_batch_size: usize,
    metadata_partition: String,
    thread_pool: Option<commonware_parallel::ThreadPool>,
) -> Result<db::Db<Family, E, J, I, H, U, N>, qmdb::Error<Family>>
where
    E: Context,
    U: Update + Send + Sync + 'static,
    I: IndexFactory<T, Value = Location>,
    H: Hasher,
    T: Translator,
    J: Mutable<Item = Operation<Family, U>> + Persistable<Error = crate::journal::Error>,
    Operation<Family, U>: Codec + Committable + CodecShared,
{
    // Build authenticated log.
    let hasher = StandardHasher::<H>::new();
    let mmr = mmr::journaled::Mmr::init_sync(
        context.with_label("mmr"),
        mmr::journaled::SyncConfig {
            config: mmr_config,
            range: range.clone(),
            pinned_nodes,
        },
        &hasher,
    )
    .await?;
    let index = I::new(context.with_label("index"), translator);
    let log = authenticated::Journal::<Family, _, _, _>::from_components(
        mmr,
        log,
        hasher,
        apply_batch_size as u64,
    )
    .await?;

    // Initialize bitmap with pruned chunks.
    //
    // Floor division is intentional: chunks entirely below range.start are pruned.
    // If range.start is not chunk-aligned, the partial leading chunk is reconstructed by
    // init_from_log, which pads the gap between `pruned_chunks * CHUNK_SIZE_BITS` and the
    // journal's inactivity floor with inactive (false) bits.
    let pruned_chunks = (*range.start / BitMap::<N>::CHUNK_SIZE_BITS) as usize;
    let mut status = BitMap::<N>::new_with_pruned_chunks(pruned_chunks)
        .map_err(|_| qmdb::Error::<Family>::DataCorrupted("pruned chunks overflow"))?;

    // Build any::Db with bitmap callback.
    //
    // init_from_log replays the operations, building the snapshot (index) and invoking
    // our callback for each operation to populate the bitmap.
    let known_inactivity_floor = Location::new(status.len());
    let any: AnyDb<Family, E, J, I, H, U> = AnyDb::init_from_log(
        index,
        log,
        Some(known_inactivity_floor),
        |is_active: bool, old_loc: Option<Location>| {
            status.push(is_active);
            if let Some(loc) = old_loc {
                status.set_bit(*loc, false);
            }
        },
    )
    .await?;

    // Extract grafted pinned nodes from the ops MMR.
    //
    // With the zero-chunk identity, all-zero bitmap chunks (which all pruned chunks are)
    // produce grafted leaves equal to the corresponding ops subtree root. The grafted
    // MMR's pinned nodes for the pruned region are therefore the first
    // `popcount(pruned_chunks)` ops pinned nodes (in decreasing height order).
    //
    // `nodes_to_pin(range.start)` returns all ops peaks, but only the first
    // `popcount(pruned_chunks)` are at or above the grafting height. The remaining
    // smaller peaks cover the partial trailing chunk and are not grafted pinned nodes.
    let grafted_pinned_nodes = {
        let ops_pin_positions = mmr::Family::nodes_to_pin(range.start);
        let num_grafted_pins = (pruned_chunks as u64).count_ones() as usize;
        let mut pins = Vec::with_capacity(num_grafted_pins);
        for pos in ops_pin_positions.take(num_grafted_pins) {
            let digest = any.log.merkle.get_node(pos).await?.ok_or(
                qmdb::Error::<mmr::Family>::DataCorrupted("missing ops pinned node"),
            )?;
            pins.push(digest);
        }
        pins
    };

    // Build grafted MMR.
    let hasher = StandardHasher::<H>::new();
    let grafted_tree = db::build_grafted_tree::<Family, H, N>(
        &hasher,
        &status,
        &grafted_pinned_nodes,
        &any.log.merkle,
        thread_pool.as_ref(),
    )
    .await?;

    // Compute the canonical root. The grafted root is deterministic from the ops
    // (which are authenticated by the engine) and the bitmap (which is deterministic
    // from the ops).
    let storage = grafting::Storage::new(
        &grafted_tree,
        grafting::height::<N>(),
        &any.log.merkle,
        hasher.clone(),
    );
    let partial = db::partial_chunk(&status);
    let grafted_root = db::compute_grafted_root(&hasher, &status, &storage).await?;
    let ops_root = any.log.root();
    let partial_digest = partial.map(|(chunk, next_bit)| {
        let digest = hasher.digest(&chunk);
        (next_bit, digest)
    });
    let root = db::combine_roots(
        &hasher,
        &ops_root,
        &grafted_root,
        partial_digest.as_ref().map(|(nb, d)| (*nb, d)),
    );

    // Initialize metadata store and construct the Db.
    let (metadata, _, _) = db::init_metadata::<Family, E, DigestOf<H>>(
        context.with_label("metadata"),
        &metadata_partition,
    )
    .await?;

    let current_db = db::Db {
        any,
        status: crate::qmdb::current::batch::BitmapBatch::Base(Arc::new(status)),
        grafted_tree,
        metadata: AsyncMutex::new(metadata),
        thread_pool,
        root,
    };

    // Persist metadata so the db can be reopened with init_fixed/init_variable.
    current_db.sync_metadata().await?;

    Ok(current_db)
}

// --- Database trait implementations ---

macro_rules! impl_current_sync_database {
    ($db:ident, $op:ident, $update:ident,
     $journal:ty, $config:ty,
     $key_bound:path, $value_bound:ident
     $(; $($where_extra:tt)+)?) => {
        impl<E, K, V, H, T, const N: usize> Database for $db<Family, E, K, V, H, T, N>
        where
            E: Context,
            K: Array + $key_bound,
            V: $value_bound + 'static,
            H: Hasher,
            T: Translator,
            $($($where_extra)+)?
        {
            type Context = E;
            type Op = $op<Family, K, V>;
            type Journal = $journal;
            type Hasher = H;
            type Config = $config;
            type Digest = H::Digest;

            async fn from_sync_result(
                context: Self::Context,
                config: Self::Config,
                log: Self::Journal,
                pinned_nodes: Option<Vec<Self::Digest>>,
                range: Range<Location>,
                apply_batch_size: usize,
            ) -> Result<Self, qmdb::Error<Family>> {
                let mmr_config = config.merkle_config.clone();
                let metadata_partition = config.grafted_metadata_partition.clone();
                let thread_pool = config.merkle_config.thread_pool.clone();
                let translator = config.translator.clone();
                build_db::<_, $update<K, V>, _, H, _, T, N>(
                    context,
                    mmr_config,
                    log,
                    translator,
                    pinned_nodes,
                    range,
                    apply_batch_size,
                    metadata_partition,
                    thread_pool,
                )
                .await
            }

            fn has_local_target_state(
                context: Self::Context,
                config: &Self::Config,
                target: &qmdb::sync::Target<Self::Digest>,
            ) -> impl std::future::Future<Output = bool> + Send {
                let config = config.clone();
                let target = target.clone();

                async move {
                    let Ok(db) = Self::init(context, config).await else {
                        return false;
                    };
                    let bounds = db.bounds().await;
                    let lower_bound = db.inactivity_floor_loc();
                    lower_bound == target.range.start()
                        && bounds.end == target.range.end()
                        && <Self as qmdb::sync::Database>::root(&db) == target.root
                }
            }

            /// Returns the ops root (not the canonical root), since the sync engine verifies
            /// batches against the ops MMR.
            fn root(&self) -> Self::Digest {
                self.any.log.root()
            }
        }
    };
}

impl_current_sync_database!(
    CurrentUnorderedFixedDb, UnorderedFixedOp, UnorderedFixedUpdate,
    fixed::Journal<E, Self::Op>, FixedConfig<T>,
    Array, FixedValue
);

impl_current_sync_database!(
    CurrentUnorderedVariableDb, UnorderedVariableOp, UnorderedVariableUpdate,
    variable::Journal<E, Self::Op>,
    VariableConfig<T, <UnorderedVariableOp<Family, K, V> as CodecRead>::Cfg>,
    Key, VariableValue;
    UnorderedVariableOp<Family, K, V>: CodecShared
);

impl_current_sync_database!(
    CurrentOrderedFixedDb, OrderedFixedOp, OrderedFixedUpdate,
    fixed::Journal<E, Self::Op>, FixedConfig<T>,
    Array, FixedValue
);

impl_current_sync_database!(
    CurrentOrderedVariableDb, OrderedVariableOp, OrderedVariableUpdate,
    variable::Journal<E, Self::Op>,
    VariableConfig<T, <OrderedVariableOp<Family, K, V> as CodecRead>::Cfg>,
    Key, VariableValue;
    OrderedVariableOp<Family, K, V>: CodecShared
);

// --- Resolver implementations ---
//
// The resolver for `current` databases serves ops-level proofs (not grafted proofs) from
// the inner `any` db. The sync engine verifies each batch against the ops root.

macro_rules! impl_current_resolver {
    ($db:ident, $op:ident, $val_bound:ident, $key_bound:path $(; $($where_extra:tt)+)?) => {
        impl<E, K, V, H, T, const N: usize> crate::qmdb::sync::Resolver
            for std::sync::Arc<$db<Family, E, K, V, H, T, N>>
        where
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            $($($where_extra)+)?
        {
            type Digest = H::Digest;
            type Op = $op<Family, K, V>;
            type Error = qmdb::Error<Family>;

            async fn get_operations(
                &self,
                op_count: Location,
                start_loc: Location,
                max_ops: std::num::NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<crate::qmdb::sync::FetchResult<Self::Op, Self::Digest>, Self::Error> {
                let (proof, operations) = self.any
                    .historical_proof(op_count, start_loc, max_ops)
                    .await?;
                let pinned_nodes = if include_pinned_nodes {
                    Some(self.any.pinned_nodes_at(start_loc).await?)
                } else {
                    None
                };
                Ok(crate::qmdb::sync::FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                })
            }
        }

        impl<E, K, V, H, T, const N: usize> crate::qmdb::sync::Resolver
            for std::sync::Arc<
                commonware_utils::sync::AsyncRwLock<
                    $db<Family, E, K, V, H, T, N>,
                >,
            >
        where
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            $($($where_extra)+)?
        {
            type Digest = H::Digest;
            type Op = $op<Family, K, V>;
            type Error = qmdb::Error<Family>;

            async fn get_operations(
                &self,
                op_count: Location,
                start_loc: Location,
                max_ops: std::num::NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<crate::qmdb::sync::FetchResult<Self::Op, Self::Digest>, qmdb::Error<Family>> {
                let db = self.read().await;
                let (proof, operations) = db.any
                    .historical_proof(op_count, start_loc, max_ops)
                    .await?;
                let pinned_nodes = if include_pinned_nodes {
                    Some(db.any.pinned_nodes_at(start_loc).await?)
                } else {
                    None
                };
                Ok(crate::qmdb::sync::FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                })
            }
        }

        impl<E, K, V, H, T, const N: usize> crate::qmdb::sync::Resolver
            for std::sync::Arc<
                commonware_utils::sync::AsyncRwLock<
                    Option<$db<Family, E, K, V, H, T, N>>,
                >,
            >
        where
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            $($($where_extra)+)?
        {
            type Digest = H::Digest;
            type Op = $op<Family, K, V>;
            type Error = qmdb::Error<Family>;

            async fn get_operations(
                &self,
                op_count: Location,
                start_loc: Location,
                max_ops: std::num::NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<crate::qmdb::sync::FetchResult<Self::Op, Self::Digest>, qmdb::Error<Family>> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(qmdb::Error::<Family>::KeyNotFound)?;
                let (proof, operations) = db.any
                    .historical_proof(op_count, start_loc, max_ops)
                    .await?;
                let pinned_nodes = if include_pinned_nodes {
                    Some(db.any.pinned_nodes_at(start_loc).await?)
                } else {
                    None
                };
                Ok(crate::qmdb::sync::FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                })
            }
        }
    };
}

// Unordered Fixed
impl_current_resolver!(CurrentUnorderedFixedDb, UnorderedFixedOp, FixedValue, Array);

// Unordered Variable
impl_current_resolver!(
    CurrentUnorderedVariableDb, UnorderedVariableOp, VariableValue, Key;
    UnorderedVariableOp<Family, K, V>: CodecShared,
);

// Ordered Fixed
impl_current_resolver!(CurrentOrderedFixedDb, OrderedFixedOp, FixedValue, Array);

// Ordered Variable
impl_current_resolver!(
    CurrentOrderedVariableDb, OrderedVariableOp, VariableValue, Key;
    OrderedVariableOp<Family, K, V>: CodecShared,
);
