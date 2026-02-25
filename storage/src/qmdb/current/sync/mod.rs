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
    index::{ordered, unordered},
    journal::{
        authenticated,
        contiguous::{fixed, variable, Mutable},
    },
    mmr::{
        self, hasher::Hasher as _, journaled::Config as MmrConfig, mem::Clean, Location, Position,
        StandardHasher,
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
            FixedConfig as AnyFixedConfig, FixedValue, ValueEncoding,
            VariableConfig as AnyVariableConfig, VariableValue,
        },
        current::{
            db::{self, Merkleized},
            grafting,
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
        Durable,
    },
    translator::Translator,
    Persistable,
};
use commonware_codec::{Codec, CodecShared, Read as CodecRead};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{bitmap::Prunable as BitMap, sync::AsyncMutex, Array};
use std::ops::Range;

#[cfg(test)]
pub(crate) mod tests;

impl<T: Translator> Config for FixedConfig<T> {
    type JournalConfig = fixed::Config;

    fn journal_config(&self) -> Self::JournalConfig {
        let any_config: AnyFixedConfig<T> = self.clone().into();
        <AnyFixedConfig<T> as Config>::journal_config(&any_config)
    }
}

impl<T: Translator, C: Clone> Config for VariableConfig<T, C> {
    type JournalConfig = variable::Config<C>;

    fn journal_config(&self) -> Self::JournalConfig {
        let any_config: AnyVariableConfig<T, C> = self.clone().into();
        <AnyVariableConfig<T, C> as Config>::journal_config(&any_config)
    }
}

/// Extract MMR config from [FixedConfig].
fn mmr_config_from_fixed<T: Translator>(config: &FixedConfig<T>) -> MmrConfig {
    MmrConfig {
        journal_partition: config.mmr_journal_partition.clone(),
        metadata_partition: config.mmr_metadata_partition.clone(),
        items_per_blob: config.mmr_items_per_blob,
        write_buffer: config.mmr_write_buffer,
        thread_pool: config.thread_pool.clone(),
        page_cache: config.page_cache.clone(),
    }
}

/// Extract MMR config from [VariableConfig].
fn mmr_config_from_variable<T: Translator, C>(config: &VariableConfig<T, C>) -> MmrConfig {
    MmrConfig {
        journal_partition: config.mmr_journal_partition.clone(),
        metadata_partition: config.mmr_metadata_partition.clone(),
        items_per_blob: config.mmr_items_per_blob,
        write_buffer: config.mmr_write_buffer,
        thread_pool: config.thread_pool.clone(),
        page_cache: config.page_cache.clone(),
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
async fn build_db<E, K, V, U, I, H, J, const N: usize>(
    context: E,
    mmr_config: MmrConfig,
    log: J,
    index: I,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: Range<Location>,
    apply_batch_size: usize,
    metadata_partition: String,
    thread_pool: Option<commonware_parallel::ThreadPool>,
) -> Result<db::Db<E, J, I, H, U, N, Merkleized<DigestOf<H>>, Durable>, qmdb::Error>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    U: Update<K, V> + Send + Sync + 'static,
    I: crate::index::Unordered<Value = Location>,
    H: Hasher,
    J: Mutable<Item = Operation<K, V, U>> + Persistable<Error = crate::journal::Error>,
    Operation<K, V, U>: Codec + Committable + CodecShared,
{
    // Build authenticated log.
    let mut hasher = StandardHasher::<H>::new();
    let mmr = mmr::journaled::Mmr::init_sync(
        context.with_label("mmr"),
        mmr::journaled::SyncConfig {
            config: mmr_config,
            range: Position::try_from(range.start)?..Position::try_from(range.end + 1)?,
            pinned_nodes,
        },
        &mut hasher,
    )
    .await?;
    let log = authenticated::Journal::<_, _, _, Clean<DigestOf<H>>>::from_components(
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
        .map_err(|_| qmdb::Error::DataCorrupted("pruned chunks overflow"))?;

    // Build any::Db with bitmap callback.
    //
    // init_from_log replays the operations, building the snapshot (index) and invoking
    // our callback for each operation to populate the bitmap.
    let known_inactivity_floor = Location::new_unchecked(status.len());
    let any: AnyDb<E, J, I, H, U, _, _> = AnyDb::init_from_log(
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
        let ops_pin_positions = mmr::iterator::nodes_to_pin(Position::try_from(range.start)?);
        let num_grafted_pins = (pruned_chunks as u64).count_ones() as usize;
        let mut pins = Vec::with_capacity(num_grafted_pins);
        for pos in ops_pin_positions.take(num_grafted_pins) {
            let digest = any
                .log
                .mmr
                .get_node(pos)
                .await?
                .ok_or(qmdb::Error::DataCorrupted("missing ops pinned node"))?;
            pins.push(digest);
        }
        pins
    };

    // Build grafted MMR.
    let mut hasher = StandardHasher::<H>::new();
    let grafted_mmr = db::build_grafted_mmr::<H, N>(
        &mut hasher,
        &status,
        &grafted_pinned_nodes,
        &any.log.mmr,
        thread_pool.as_ref(),
    )
    .await?;

    // Compute the canonical root. The grafted root is deterministic from the ops
    // (which are authenticated by the engine) and the bitmap (which is deterministic
    // from the ops).
    let storage = grafting::Storage::new(&grafted_mmr, grafting::height::<N>(), &any.log.mmr);
    let partial = db::partial_chunk(&status);
    let grafted_mmr_root = db::compute_grafted_mmr_root(&mut hasher, &storage).await?;
    let ops_root = any.log.root();
    let partial_digest = partial.map(|(chunk, next_bit)| {
        let digest = hasher.digest(chunk);
        (next_bit, digest)
    });
    let root = db::combine_roots(
        &mut hasher,
        &ops_root,
        &grafted_mmr_root,
        partial_digest.as_ref().map(|(nb, d)| (*nb, d)),
    );

    // Initialize metadata store and construct the Db.
    let (metadata, _, _) =
        db::init_metadata::<E, DigestOf<H>>(context.with_label("metadata"), &metadata_partition)
            .await?;

    let current_db = db::Db {
        any,
        status,
        grafted_mmr,
        metadata: AsyncMutex::new(metadata),
        thread_pool,
        state: Merkleized { root },
    };

    // Persist metadata so the db can be reopened with init_fixed/init_variable.
    current_db.sync_metadata().await?;

    Ok(current_db)
}

// --- Database trait implementations ---

impl<E, K, V, H, T, const N: usize> Database
    for CurrentUnorderedFixedDb<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher,
    T: Translator,
{
    type Context = E;
    type Op = UnorderedFixedOp<K, V>;
    type Journal = fixed::Journal<E, Self::Op>;
    type Hasher = H;
    type Config = FixedConfig<T>;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error> {
        let mmr_config = mmr_config_from_fixed(&config);
        let metadata_partition = config.grafted_mmr_metadata_partition.clone();
        let thread_pool = config.thread_pool.clone();
        let index = unordered::Index::new(context.with_label("index"), config.translator.clone());
        build_db::<_, K, _, UnorderedFixedUpdate<K, V>, _, H, _, N>(
            context,
            mmr_config,
            log,
            index,
            pinned_nodes,
            range,
            apply_batch_size,
            metadata_partition,
            thread_pool,
        )
        .await
    }

    /// Returns the ops root (not the canonical root), since the sync engine verifies
    /// batches against the ops MMR.
    fn root(&self) -> Self::Digest {
        self.any.log.root()
    }
}

impl<E, K, V, H, T, const N: usize> Database
    for CurrentUnorderedVariableDb<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher,
    T: Translator,
    UnorderedVariableOp<K, V>: CodecShared,
{
    type Context = E;
    type Op = UnorderedVariableOp<K, V>;
    type Journal = variable::Journal<E, Self::Op>;
    type Hasher = H;
    type Config = VariableConfig<T, <UnorderedVariableOp<K, V> as CodecRead>::Cfg>;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error> {
        let mmr_config = mmr_config_from_variable(&config);
        let metadata_partition = config.grafted_mmr_metadata_partition.clone();
        let thread_pool = config.thread_pool.clone();
        let index = unordered::Index::new(context.with_label("index"), config.translator.clone());
        build_db::<_, K, _, UnorderedVariableUpdate<K, V>, _, H, _, N>(
            context,
            mmr_config,
            log,
            index,
            pinned_nodes,
            range,
            apply_batch_size,
            metadata_partition,
            thread_pool,
        )
        .await
    }

    /// Returns the ops root (not the canonical root), since the sync engine verifies
    /// batches against the ops MMR.
    fn root(&self) -> Self::Digest {
        self.any.log.root()
    }
}

impl<E, K, V, H, T, const N: usize> Database
    for CurrentOrderedFixedDb<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher,
    T: Translator,
{
    type Context = E;
    type Op = OrderedFixedOp<K, V>;
    type Journal = fixed::Journal<E, Self::Op>;
    type Hasher = H;
    type Config = FixedConfig<T>;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error> {
        let mmr_config = mmr_config_from_fixed(&config);
        let metadata_partition = config.grafted_mmr_metadata_partition.clone();
        let thread_pool = config.thread_pool.clone();
        let index = ordered::Index::new(context.with_label("index"), config.translator.clone());
        build_db::<_, K, _, OrderedFixedUpdate<K, V>, _, H, _, N>(
            context,
            mmr_config,
            log,
            index,
            pinned_nodes,
            range,
            apply_batch_size,
            metadata_partition,
            thread_pool,
        )
        .await
    }

    /// Returns the ops root (not the canonical root), since the sync engine verifies
    /// batches against the ops MMR.
    fn root(&self) -> Self::Digest {
        self.any.log.root()
    }
}

impl<E, K, V, H, T, const N: usize> Database
    for CurrentOrderedVariableDb<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher,
    T: Translator,
    OrderedVariableOp<K, V>: CodecShared,
{
    type Context = E;
    type Op = OrderedVariableOp<K, V>;
    type Journal = variable::Journal<E, Self::Op>;
    type Hasher = H;
    type Config = VariableConfig<T, <OrderedVariableOp<K, V> as CodecRead>::Cfg>;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error> {
        let mmr_config = mmr_config_from_variable(&config);
        let metadata_partition = config.grafted_mmr_metadata_partition.clone();
        let thread_pool = config.thread_pool.clone();
        let index = ordered::Index::new(context.with_label("index"), config.translator.clone());
        build_db::<_, K, _, OrderedVariableUpdate<K, V>, _, H, _, N>(
            context,
            mmr_config,
            log,
            index,
            pinned_nodes,
            range,
            apply_batch_size,
            metadata_partition,
            thread_pool,
        )
        .await
    }

    /// Returns the ops root (not the canonical root), since the sync engine verifies
    /// batches against the ops MMR.
    fn root(&self) -> Self::Digest {
        self.any.log.root()
    }
}

// --- Resolver implementations ---
//
// The resolver for `current` databases serves ops-level proofs (not grafted proofs) from
// the inner `any` db. The sync engine verifies each batch against the ops root.

macro_rules! impl_current_resolver {
    ($db:ident, $op:ident, $val_bound:ident, $key_bound:path $(; $($where_extra:tt)+)?) => {
        impl<E, K, V, H, T, const N: usize> crate::qmdb::sync::Resolver
            for std::sync::Arc<$db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>>
        where
            E: Storage + Clock + Metrics,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            $($($where_extra)+)?
        {
            type Digest = H::Digest;
            type Op = $op<K, V>;
            type Error = qmdb::Error;

            async fn get_operations(
                &self,
                op_count: Location,
                start_loc: Location,
                max_ops: std::num::NonZeroU64,
            ) -> Result<crate::qmdb::sync::FetchResult<Self::Op, Self::Digest>, Self::Error> {
                self.any
                    .historical_proof(op_count, start_loc, max_ops)
                    .await
                    .map(|(proof, operations)| crate::qmdb::sync::FetchResult {
                        proof,
                        operations,
                        success_tx: commonware_utils::channel::oneshot::channel().0,
                    })
            }
        }

        impl<E, K, V, H, T, const N: usize> crate::qmdb::sync::Resolver
            for std::sync::Arc<
                commonware_utils::sync::AsyncRwLock<
                    $db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>,
                >,
            >
        where
            E: Storage + Clock + Metrics,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            $($($where_extra)+)?
        {
            type Digest = H::Digest;
            type Op = $op<K, V>;
            type Error = qmdb::Error;

            async fn get_operations(
                &self,
                op_count: Location,
                start_loc: Location,
                max_ops: std::num::NonZeroU64,
            ) -> Result<crate::qmdb::sync::FetchResult<Self::Op, Self::Digest>, qmdb::Error> {
                let db = self.read().await;
                db.any
                    .historical_proof(op_count, start_loc, max_ops)
                    .await
                    .map(|(proof, operations)| crate::qmdb::sync::FetchResult {
                        proof,
                        operations,
                        success_tx: commonware_utils::channel::oneshot::channel().0,
                    })
            }
        }

        impl<E, K, V, H, T, const N: usize> crate::qmdb::sync::Resolver
            for std::sync::Arc<
                commonware_utils::sync::AsyncRwLock<
                    Option<$db<E, K, V, H, T, N, Merkleized<DigestOf<H>>, Durable>>,
                >,
            >
        where
            E: Storage + Clock + Metrics,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            $($($where_extra)+)?
        {
            type Digest = H::Digest;
            type Op = $op<K, V>;
            type Error = qmdb::Error;

            async fn get_operations(
                &self,
                op_count: Location,
                start_loc: Location,
                max_ops: std::num::NonZeroU64,
            ) -> Result<crate::qmdb::sync::FetchResult<Self::Op, Self::Digest>, qmdb::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(qmdb::Error::KeyNotFound)?;
                db.any
                    .historical_proof(op_count, start_loc, max_ops)
                    .await
                    .map(|(proof, operations)| crate::qmdb::sync::FetchResult {
                        proof,
                        operations,
                        success_tx: commonware_utils::channel::oneshot::channel().0,
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
    UnorderedVariableOp<K, V>: CodecShared,
);

// Ordered Fixed
impl_current_resolver!(CurrentOrderedFixedDb, OrderedFixedOp, FixedValue, Array);

// Ordered Variable
impl_current_resolver!(
    CurrentOrderedVariableDb, OrderedVariableOp, VariableValue, Key;
    OrderedVariableOp<K, V>: CodecShared,
);
