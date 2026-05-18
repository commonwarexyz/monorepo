//! Synchronization logic for [crate::qmdb::current] databases.
//!
//! Contains implementation of the sync `Database` trait for all
//! [Db](crate::qmdb::current::db::Db) variants (ordered/unordered, fixed/variable), plus a
//! [sync()] wrapper for targets anchored by trusted database roots.
//!
//! The database root of a `current` database combines the ops root, grafted root, and optional
//! pending and partial chunk digests into a single hash (see the [Root structure](super) section in
//! the module documentation). The shared sync engine operates on the **ops root** internally,
//! downloading operations and verifying each batch against the ops root using ops-tree range proofs
//! (identical to `any` sync).
//!
//! Callers that only trust a database root (e.g., from consensus) should use [sync()] with a
//! [Target] that includes an [OpsRootWitness]. The wrapper verifies each target's witness before
//! forwarding its ops root to the shared sync engine, then checks the reconstructed database root
//! for the target the engine finishes on.
//!
//! After all operations are synced, the bitmap and grafted tree are reconstructed deterministically
//! from the operations. The database root is then computed from the ops root, the reconstructed
//! grafted root, and any pending or partial chunk digests.
//!
//! `Database::ops_root()` returns the ops root because that is what the sync engine verifies
//! against. `Database::root()` returns the full database root.
//!
//! For pruned databases (`range.start > 0`), grafted pinned nodes for the pruned region are read
//! directly from the ops tree after it is built. This works because of the zero-chunk identity: for
//! all-zero bitmap chunks (which all pruned chunks are), the grafted leaf equals the ops subtree
//! root, making the grafted tree structurally identical to the ops tree at and above the grafting
//! height.

use crate::{
    index::Factory as IndexFactory,
    journal::{
        authenticated,
        contiguous::{fixed, variable, Mutable, Reader as _},
    },
    merkle::{
        full::{self, Merkle},
        hasher::Standard as StandardHasher,
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
            proof::OpsRootWitness,
            unordered::{
                fixed::Db as CurrentUnorderedFixedDb, variable::Db as CurrentUnorderedVariableDb,
            },
            FixedConfig, VariableConfig,
        },
        operation::{Committable, Key, Operation as _},
        sync::{
            self as qmdb_sync, engine::Config as EngineConfig, Database, DatabaseConfig,
            DbResolver, EngineError,
        },
    },
    translator::Translator,
    Context, Persistable,
};
use commonware_codec::{Codec, CodecShared, Encode, Read as CodecRead, ReadExt as _};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{
    bitmap::Prunable as BitMap,
    channel::{mpsc, oneshot},
    range::NonEmptyRange,
    sync::AsyncMutex,
    Array,
};
use futures::future::{select, Either};
use std::{num::NonZeroU64, sync::Arc};

#[cfg(test)]
pub(crate) mod tests;

/// Sync target for `current` databases, anchored by a trusted database root.
///
/// The witness authenticates `ops_root` against `root`; the shared sync engine
/// uses the authenticated ops root as its target.
#[derive(Clone, Debug)]
pub struct Target<F: Graftable, D: Digest> {
    /// The trusted database root.
    pub root: D,
    /// The ops root provided by the sync source.
    pub ops_root: D,
    /// Witness proving the `root` commits to `ops_root`.
    pub witness: OpsRootWitness<F, D>,
    /// Range of operations to sync.
    pub range: NonEmptyRange<Location<F>>,
}

impl<F: Graftable, D: Digest> Target<F, D> {
    /// Verify the witness and return the ops-root target consumed by the shared sync engine.
    pub fn to_engine_target<H: commonware_cryptography::Hasher<Digest = D>>(
        &self,
        hasher: &StandardHasher<H>,
    ) -> Option<qmdb_sync::Target<F, D>> {
        if self.witness.verify(hasher, &self.ops_root, &self.root) {
            Some(qmdb_sync::Target::from_roots(
                self.root,
                self.ops_root,
                self.range.clone(),
            ))
        } else {
            None
        }
    }
}

impl<F: Graftable, D: Digest> commonware_codec::Write for Target<F, D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.root.write(buf);
        self.ops_root.write(buf);
        self.witness.write(buf);
        self.range.write(buf);
    }
}

impl<F: Graftable, D: Digest> commonware_codec::EncodeSize for Target<F, D> {
    fn encode_size(&self) -> usize {
        self.root.encode_size()
            + self.ops_root.encode_size()
            + self.witness.encode_size()
            + self.range.encode_size()
    }
}

impl<F: Graftable, D: Digest> commonware_codec::Read for Target<F, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        let root = D::read(buf)?;
        let ops_root = D::read(buf)?;
        let witness = OpsRootWitness::<F, D>::read(buf)?;
        let range = NonEmptyRange::<Location<F>>::read(buf)?;
        if !range.start().is_valid() || !range.end().is_valid() {
            return Err(commonware_codec::Error::Invalid(
                "storage::qmdb::current::sync::Target",
                "range bounds out of valid range",
            ));
        }
        Ok(Self {
            root,
            ops_root,
            witness,
            range,
        })
    }
}

/// Configuration for syncing a `current` database from trusted database-root targets.
pub struct Config<DB: Database, R: DbResolver<DB>>
where
    DB::Family: Graftable,
    DB::Op: Encode,
{
    /// Runtime context.
    pub context: DB::Context,
    /// Resolver for fetching operations and proofs.
    pub resolver: R,
    /// Sync target with trusted database root and witness.
    pub target: Target<DB::Family, DB::Digest>,
    /// Maximum parallel outstanding requests.
    pub max_outstanding_requests: usize,
    /// Maximum operations per fetch batch.
    pub fetch_batch_size: NonZeroU64,
    /// Operations to apply per internal batch.
    pub apply_batch_size: usize,
    /// Database-specific configuration.
    pub db_config: DB::Config,
    /// Channel for receiving target updates during sync.
    ///
    /// Each update must include a witness authenticating its ops root against its trusted root.
    pub update_rx: Option<mpsc::Receiver<Target<DB::Family, DB::Digest>>>,
    /// Channel that requests sync completion once the current target is reached.
    pub finish_rx: Option<mpsc::Receiver<()>>,
    /// Channel to notify an observer when the current target is reached.
    pub reached_target_tx: Option<mpsc::Sender<qmdb_sync::Target<DB::Family, DB::Digest>>>,
    /// Historical roots to retain for in-flight request verification.
    pub max_retained_roots: usize,
}

/// Sync a `current` database from a trusted database root.
///
/// Verifies the initial target and any target update witnesses before forwarding ops-root targets
/// to the shared sync engine, then checks the reconstructed database root for the target the
/// engine finishes on.
pub async fn sync<DB, R>(
    config: Config<DB, R>,
) -> Result<DB, qmdb_sync::Error<DB::Family, R::Error, DB::Digest>>
where
    DB: Database,
    DB::Family: Graftable,
    DB::Op: Encode,
    R: DbResolver<DB>,
{
    let hasher = qmdb::hasher::<DB::Hasher>();

    let engine_target = config
        .target
        .to_engine_target(&hasher)
        .ok_or(qmdb_sync::Error::Engine(EngineError::OpsRootWitnessInvalid))?;
    let mut roots = vec![(engine_target.clone(), config.target.root)];

    // The caller controls the public update channel capacity. Once updates reach this wrapper,
    // keep the internal queue shallow so verified current targets cannot get far ahead of the
    // target the shared sync engine has consumed.
    let (engine_update_tx, engine_update_rx) = if config.update_rx.is_some() {
        let (tx, rx) = mpsc::channel(1);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let engine_config = EngineConfig::<DB, R> {
        context: config.context,
        resolver: config.resolver,
        target: engine_target,
        max_outstanding_requests: config.max_outstanding_requests,
        fetch_batch_size: config.fetch_batch_size,
        apply_batch_size: config.apply_batch_size,
        db_config: config.db_config,
        update_rx: engine_update_rx,
        finish_rx: config.finish_rx,
        reached_target_tx: config.reached_target_tx,
        max_retained_roots: config.max_retained_roots,
    };

    let engine = qmdb_sync::Engine::new(engine_config).await?;
    let engine_fut = Box::pin(engine.sync_with_target());

    let (database, final_target) = if let Some(mut update_rx) = config.update_rx {
        let update_tx = engine_update_tx.expect("engine update sender must exist");
        let forward_fut = Box::pin(async {
            let update_tx = update_tx;
            while let Some(current_target) = update_rx.recv().await {
                let Some(engine_target) = current_target.to_engine_target(&hasher) else {
                    tracing::warn!("target update witness verification failed");
                    return Err(qmdb_sync::Error::Engine(EngineError::OpsRootWitnessInvalid));
                };
                if update_tx.send(engine_target.clone()).await.is_err() {
                    break;
                }
                roots.push((engine_target, current_target.root));
            }
            Ok(())
        });
        let result = match select(engine_fut, forward_fut).await {
            Either::Left((result, _)) => result?,
            Either::Right((forward_result, engine_fut)) => {
                forward_result?;
                engine_fut.await?
            }
        };
        result
    } else {
        engine_fut.await?
    };

    let expected = roots
        .iter()
        .rev()
        .find(|(target, _)| target == &final_target)
        .expect("final current sync target was verified")
        .1;
    let actual = database.root();
    if actual != expected {
        return Err(qmdb_sync::Error::Engine(EngineError::RootMismatch {
            expected,
            actual,
        }));
    }

    Ok(database)
}

impl<T: Translator, J: Clone, S: Strategy> DatabaseConfig for super::Config<T, J, S> {
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
/// * Computes and caches the database root.
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
    let ops_size = any.log.merkle.size();
    let ops_leaves = Location::<F>::try_from(ops_size)?;
    let grafted_tree = db::build_grafted_tree::<F, H, S, N>(
        &hasher,
        any.bitmap.as_ref(),
        &grafted_pinned_nodes,
        &any.log.merkle,
        ops_leaves,
        &strategy,
    )
    .await?;

    // Compute the database root. The grafted root is deterministic from the ops
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
        ops_leaves,
        any.inactivity_floor_loc,
    )
    .await?;
    let ops_root = any.root();
    let partial_digest = partial.map(|(chunk, next_bit)| {
        let digest = hasher.digest(&chunk);
        (next_bit, digest)
    });
    let pending_digest =
        db::pending_chunk::<F, _, N>(any.bitmap.as_ref(), ops_leaves, grafting::height::<N>())?
            .map(|chunk| hasher.digest(&chunk));
    let root = db::combine_roots(
        &hasher,
        &ops_root,
        &grafted_root,
        pending_digest.as_ref(),
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

            fn ops_root(&self) -> Self::Digest {
                self.any.root()
            }

            fn root(&self) -> Self::Digest {
                self.root
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
        impl<F, E, K, V, H, T, const N: usize, S> crate::qmdb::sync::Resolver
            for std::sync::Arc<$db<F, E, K, V, H, T, N, S>>
        where
            F: Graftable,
            E: Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
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

        impl<F, E, K, V, H, T, const N: usize, S> crate::qmdb::sync::Resolver
            for std::sync::Arc<
                commonware_utils::sync::AsyncRwLock<
                    $db<F, E, K, V, H, T, N, S>,
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
            S: Strategy,
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

        impl<F, E, K, V, H, T, const N: usize, S> crate::qmdb::sync::Resolver
            for std::sync::Arc<
                commonware_utils::sync::AsyncRwLock<
                    Option<$db<F, E, K, V, H, T, N, S>>,
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
            S: Strategy,
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
