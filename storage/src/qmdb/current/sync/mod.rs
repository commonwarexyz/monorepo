//! Shared synchronization logic for [crate::qmdb::current] databases.
//!
//! Contains implementation of [crate::qmdb::sync::Database] for all [Db](crate::qmdb::current::db::Db)
//! variants (ordered/unordered, fixed/variable).
//!
//! The canonical root of a `current` database combines the ops root, grafted tree root, and
//! optional partial chunk into a single hash (see the [Root structure](super) section in the
//! module documentation). The sync engine operates on the **ops root**, not the canonical root:
//! it downloads operations and verifies each batch against the ops root using ops-tree range proofs
//! (identical to `any` sync). Callers that verify current ops proofs directly should
//! use `qmdb::hasher`. [crate::qmdb::current::proof::OpsRootWitness] can be
//! used by callers that need to authenticate the synced ops root against a trusted canonical root;
//! the sync engine does not perform this check itself.
//!
//! After all operations are synced, the bitmap and grafted tree are reconstructed
//! deterministically from the operations. The canonical root is then computed from the
//! ops root, the reconstructed grafted tree root, and any partial chunk.
//!
//! The [Database]`::`[root()](crate::qmdb::sync::Database::root)
//! implementation returns the **ops root** (not the canonical root) because that is what the
//! sync engine verifies against.
//!
//! For pruned databases (`range.start > 0`), grafted pinned nodes for the pruned region are
//! read directly from the ops tree after it is built. This works because of the zero-chunk
//! identity: for all-zero bitmap chunks (which all pruned chunks are), the grafted leaf equals
//! the ops subtree root, making the grafted tree structurally identical to the ops tree at
//! and above the grafting height.

use crate::{
    index::Factory as IndexFactory,
    journal::{
        authenticated,
        contiguous::{fixed, variable, Mutable, Reader as _},
    },
    merkle::{
        full::{self, Merkle},
        Graftable, Location,
    },
    qmdb::{
        self,
        any::{
            db::{Db as AnyDb, Metrics as AnyMetrics},
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
        bitmap::Shared,
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
        operation::{Committable, Key, Operation as _},
        sync::{Database, DatabaseConfig as Config},
    },
    translator::Translator,
    Context, Persistable,
};
use commonware_codec::{Codec, CodecShared, Read as CodecRead};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{
    bitmap::Prunable as BitMap, channel::oneshot, range::NonEmptyRange, sync::AsyncMutex, Array,
};
use std::sync::Arc;

#[cfg(test)]
pub(crate) mod tests;

impl<T: Translator, J: Clone, S: Strategy> Config for super::Config<T, J, S> {
    type JournalConfig = J;

    fn journal_config(&self) -> Self::JournalConfig {
        self.journal_config.clone()
    }
}

/// Shared helper to build a `current::db::Db` from sync components.
///
/// This follows the same pattern as `any/sync/mod.rs::build_db` but additionally:
/// * Builds the activity bitmap by replaying the operations log.
/// * Extracts grafted pinned nodes from the ops tree (zero-chunk identity).
/// * Builds the grafted tree from the bitmap and ops tree.
/// * Computes and caches the canonical root.
#[allow(clippy::too_many_arguments)]
async fn build_db<F, E, U, I, H, J, T, const N: usize, S>(
    context: E,
    merkle_config: full::Config<S>,
    log: J,
    translator: T,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: NonEmptyRange<Location<F>>,
    apply_batch_size: usize,
    metadata_partition: String,
    strategy: S,
) -> Result<db::Db<F, E, J, I, H, U, N, S>, qmdb::Error<F>>
where
    F: Graftable,
    E: Context,
    U: Update + Send + Sync + 'static,
    I: IndexFactory<T, Value = Location<F>>,
    H: Hasher,
    T: Translator,
    J: Mutable<Item = Operation<F, U>> + Persistable<Error = crate::journal::Error>,
    S: Strategy,
    Operation<F, U>: Codec + Committable + CodecShared,
{
    // Build authenticated log.
    let hasher = qmdb::hasher::<H>();
    let merkle = Merkle::<F, _, _, S>::init_sync(
        context.child("merkle"),
        full::SyncConfig {
            config: merkle_config,
            range: range.clone(),
            pinned_nodes,
        },
    )
    .await?;
    let index = I::new(context.child("index"), translator);
    let log = authenticated::Journal::<F, _, _, _, S>::from_components(
        merkle,
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
    let pruned_chunks = (*range.start() / BitMap::<N>::CHUNK_SIZE_BITS) as usize;
    let bitmap = BitMap::<N>::new_with_pruned_chunks(pruned_chunks)
        .map_err(|_| qmdb::Error::<F>::DataCorrupted("pruned chunks overflow"))?;
    let bitmap = Arc::new(Shared::<N>::new(bitmap));

    // Build any::Db, handing it the pre-allocated bitmap. `init_from_log` populates the bitmap
    // during replay.
    let any_metrics = AnyMetrics::new(context.child("any"));
    let any: AnyDb<F, E, J, I, H, U, N, S> =
        AnyDb::init_from_log(index, log, Some(bitmap), any_metrics).await?;

    // Fetch grafted pinned nodes from the ops tree. For each position the grafted family
    // needs at its pruning boundary, source the digest from the ops tree via the zero-chunk
    // identity: when the covered chunks are all zero (which pruned chunks always are), the
    // ops-family digest at the mapped position equals the grafted digest.
    //
    // Requires `range.start <=` target's [`Db::sync_boundary`](db::Db::sync_boundary): that
    // bound guarantees every required ops-tree node is born at `range.end`.
    let grafted_pinned_nodes = {
        let grafted_boundary = Location::<F>::new(pruned_chunks as u64);
        let grafting_height = grafting::height::<N>();
        let mut pins = Vec::new();
        for grafted_pos in F::nodes_to_pin(grafted_boundary) {
            let ops_pos = grafting::grafted_to_ops_pos::<F>(grafted_pos, grafting_height);
            let digest = any
                .log
                .merkle
                .get_node(ops_pos)
                .await?
                .ok_or(qmdb::Error::<F>::DataCorrupted("missing ops pinned node"))?;
            pins.push(digest);
        }
        pins
    };

    // Build grafted tree.
    let hasher = qmdb::hasher::<H>();
    let grafted_tree = db::build_grafted_tree::<F, H, S, N>(
        &hasher,
        any.bitmap.as_ref(),
        &grafted_pinned_nodes,
        &any.log.merkle,
        &strategy,
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
    let partial = db::partial_chunk(any.bitmap.as_ref());
    let grafted_root = db::compute_grafted_root(
        &hasher,
        any.bitmap.as_ref(),
        &storage,
        any.inactivity_floor_loc,
    )
    .await?;
    let ops_root = any.root();
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
    let (metadata, _, _) =
        db::init_metadata::<F, E, DigestOf<H>>(context.child("metadata"), &metadata_partition)
            .await?;

    let metrics = db::Metrics::new(context);
    let current_db = db::Db {
        any,
        grafted_tree,
        metadata: AsyncMutex::new(metadata),
        strategy,
        root,
        metrics,
    };
    current_db.update_metrics();

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
        impl<F, E, K, V, H, T, const N: usize, S> Database for $db<F, E, K, V, H, T, N, S>
        where
            F: Graftable,
            E: Context,
            K: $key_bound,
            V: $value_bound + 'static,
            H: Hasher,
            T: Translator,
            S: Strategy,
            $($($where_extra)+)?
        {
            type Family = F;
            type Context = E;
            type Op = $op<F, K, V>;
            type Journal = $journal;
            type Hasher = H;
            type Config = $config;
            type Digest = H::Digest;

            async fn from_sync_result(
                context: Self::Context,
                config: Self::Config,
                log: Self::Journal,
                pinned_nodes: Option<Vec<Self::Digest>>,
                range: NonEmptyRange<Location<F>>,
                apply_batch_size: usize,
            ) -> Result<Self, qmdb::Error<F>> {
                let merkle_config = config.merkle_config.clone();
                let metadata_partition = config.grafted_metadata_partition.clone();
                let strategy = config.merkle_config.strategy.clone();
                let translator = config.translator.clone();
                build_db::<F, _, $update<K, V>, _, H, _, T, N, _>(
                    context,
                    merkle_config,
                    log,
                    translator,
                    pinned_nodes,
                    range,
                    apply_batch_size,
                    metadata_partition,
                    strategy,
                )
                .await
            }

            async fn has_local_target_state(
                context: Self::Context,
                config: &Self::Config,
                target: &qmdb::sync::Target<Self::Family, Self::Digest>,
            ) -> bool {
                let Ok(journal) = <$journal>::init(
                    context.child("local_target_journal_probe"),
                    config.journal_config(),
                )
                .await
                else {
                    return false;
                };
                let reader = journal.reader().await;
                let bounds = reader.bounds();
                if Location::new(bounds.start) > target.range.start() {
                    return false;
                }
                let Ok(inactivity_floor) =
                    qmdb::find_inactivity_floor_at::<F, _>(&reader, target.range.end(), |op| {
                        op.has_floor()
                    })
                    .await
                else {
                    return false;
                };

                let inactive_peaks = F::inactive_peaks(
                    F::location_to_position(target.range.end()),
                    inactivity_floor,
                );
                if !qmdb::any::sync::has_local_target_state::<F, _, H, S>(
                    context.child("local_target_merkle_probe"),
                    config.merkle_config.clone(),
                    target,
                    inactive_peaks,
                )
                .await
                {
                    return false;
                }

                true
            }

            /// Returns the ops root (not the canonical root), since the sync engine verifies
            /// batches against the ops tree.
            fn root(&self) -> Self::Digest {
                self.any.root()
            }
        }
    };
}

impl_current_sync_database!(
    CurrentUnorderedFixedDb, UnorderedFixedOp, UnorderedFixedUpdate,
    fixed::Journal<E, Self::Op>, FixedConfig<T, S>,
    Array, FixedValue
);

impl_current_sync_database!(
    CurrentUnorderedVariableDb, UnorderedVariableOp, UnorderedVariableUpdate,
    variable::Journal<E, Self::Op>,
    VariableConfig<T, <UnorderedVariableOp<F, K, V> as CodecRead>::Cfg, S>,
    Key, VariableValue;
    UnorderedVariableOp<F, K, V>: CodecShared
);

impl_current_sync_database!(
    CurrentOrderedFixedDb, OrderedFixedOp, OrderedFixedUpdate,
    fixed::Journal<E, Self::Op>, FixedConfig<T, S>,
    Array, FixedValue
);

impl_current_sync_database!(
    CurrentOrderedVariableDb, OrderedVariableOp, OrderedVariableUpdate,
    variable::Journal<E, Self::Op>,
    VariableConfig<T, <OrderedVariableOp<F, K, V> as CodecRead>::Cfg, S>,
    Key, VariableValue;
    OrderedVariableOp<F, K, V>: CodecShared
);

// --- Resolver implementations ---
//
// The resolver for `current` databases serves ops-level proofs (not grafted proofs) from
// the inner `any` db. The sync engine verifies each batch against the ops root.

macro_rules! impl_current_resolver {
    ($db:ident, $op:ident, $val_bound:ident, $key_bound:path $(; $($where_extra:tt)+)?) => {
        impl<F, E, K, V, H, T, const N: usize> crate::qmdb::sync::Resolver
            for std::sync::Arc<$db<F, E, K, V, H, T, N>>
        where
            F: Graftable,
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            $($($where_extra)+)?
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<F>,
                start_loc: Location<F>,
                max_ops: std::num::NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<crate::qmdb::sync::FetchResult<F, Self::Op, Self::Digest>, Self::Error> {
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

        impl<F, E, K, V, H, T, const N: usize> crate::qmdb::sync::Resolver
            for std::sync::Arc<
                commonware_utils::sync::AsyncRwLock<
                    $db<F, E, K, V, H, T, N>,
                >,
            >
        where
            F: Graftable,
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            $($($where_extra)+)?
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<F>,
                start_loc: Location<F>,
                max_ops: std::num::NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<crate::qmdb::sync::FetchResult<F, Self::Op, Self::Digest>, qmdb::Error<F>> {
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

        impl<F, E, K, V, H, T, const N: usize> crate::qmdb::sync::Resolver
            for std::sync::Arc<
                commonware_utils::sync::AsyncRwLock<
                    Option<$db<F, E, K, V, H, T, N>>,
                >,
            >
        where
            F: Graftable,
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            $($($where_extra)+)?
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<F>,
                start_loc: Location<F>,
                max_ops: std::num::NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<crate::qmdb::sync::FetchResult<F, Self::Op, Self::Digest>, qmdb::Error<F>> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(qmdb::Error::<F>::KeyNotFound)?;
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
    UnorderedVariableOp<F, K, V>: CodecShared,
);

// Ordered Fixed
impl_current_resolver!(CurrentOrderedFixedDb, OrderedFixedOp, FixedValue, Array);

// Ordered Variable
impl_current_resolver!(
    CurrentOrderedVariableDb, OrderedVariableOp, VariableValue, Key;
    OrderedVariableOp<F, K, V>: CodecShared,
);
