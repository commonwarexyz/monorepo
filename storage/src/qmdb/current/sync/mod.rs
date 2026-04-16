//! Shared synchronization logic for [crate::qmdb::current] databases.
//!
//! Contains implementation of [crate::qmdb::sync::Database] for all
//! [Db](crate::qmdb::current::db::Db) variants (ordered/unordered, fixed/variable).
//!
//! # Trust model
//!
//! The canonical root of a `current` database combines the ops root, grafted tree root, and
//! optional partial chunk into a single hash (see the [Root structure](super) section in the
//! module documentation). The sync engine operates on the **ops root**, not the canonical root:
//! it downloads operations and verifies each batch against the ops root using standard Merkle
//! range proofs (identical to `any` sync). Validating that the ops root is part of the
//! canonical root is the caller's responsibility; the sync engine does not perform this check.
//!
//! The [Database](crate::qmdb::sync::Database)`::`[root()](crate::qmdb::sync::Database::root)
//! implementation returns the **ops root** (not the canonical root) because that is what the
//! sync engine verifies against.
//!
//! # Grafted pruning state and overlay state
//!
//! For pruned databases (`range.start > 0`), the receiver needs the grafted tree's pinned
//! nodes at the sender's pruning boundary in order to reconstruct the canonical root.
//! Deriving those pins from the synced ops tree alone (e.g., taking the first
//! `popcount(pruned_chunks)` entries of `F::nodes_to_pin(range.start)`) relies on the
//! zero-chunk identity (pruned chunks are all-zero so each grafted leaf equals its ops
//! subtree root) **and** on the ops pin ordering coinciding with the grafted pin ordering.
//!
//! That coincidence holds for MMR. It does **not** hold in general for MMB: delayed merges
//! can put ops pins at heights below the grafting height, and for some sender states the
//! receiver's derivation produces a different `pruned_chunks` value than the sender's actual
//! overlay pruning. When that happens the reconstructed grafted tree diverges from the
//! sender's, and the canonical root drifts.
//!
//! To avoid that divergence, the sender ships its overlay state explicitly via
//! [`CurrentOverlayState`] on the first (boundary) batch of the sync, carried on
//! [`FetchResult`](crate::qmdb::sync::FetchResult). The receiver seeds the grafted tree from
//! those pins rather than re-deriving them from `range.start`, and authenticates the payload
//! indirectly by comparing the rebuilt database's canonical root against
//! [`Target::canonical_root`](crate::qmdb::sync::Target::canonical_root) (when the caller
//! supplied one). A lying sender therefore cannot coerce the receiver into persisting a
//! diverged overlay: the canonical-root check fails before anything is written to disk.

use crate::{
    index::Factory as IndexFactory,
    journal::{
        authenticated,
        contiguous::{fixed, variable, Mutable},
    },
    merkle::{self, hasher::Standard as StandardHasher, journaled, Location},
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
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_utils::{
    bitmap::{Prunable as BitMap, Readable as BitmapReadable},
    channel::oneshot,
    sync::AsyncMutex,
    Array,
};
use std::{ops::Range, sync::Arc};

#[cfg(test)]
pub(crate) mod tests;

/// Sender-supplied overlay state for [crate::qmdb::current] sync.
///
/// The sync engine authenticates operations and ops-MMR pinned nodes against the **ops root**.
/// That does not authenticate the grafted tree's pruning state. For `current` sync to reproduce
/// the sender's actual overlay (bitmap pruning + grafted pinned digests) — not a reconstruction
/// inferred from the synced ops range — the sender must ship its overlay state explicitly, and
/// the receiver must validate it indirectly by checking that the rebuilt database's **canonical
/// root** matches the canonical root supplied in the sync target.
///
/// See the [module-level trust model](self) for the full authentication story.
///
/// # Invariants (enforced at the sync boundary, not by this struct)
///
/// - `grafted_pinned_nodes.len() == F::nodes_to_pin(Location::new(pruned_chunks)).count()`
/// - `pruned_chunks * CHUNK_SIZE_BITS <= range.start` (sender hasn't pruned past the synced
///   ops-range floor)
/// - `pruned_chunks * CHUNK_SIZE_BITS <= range.end` (sender hasn't pruned past the top of the
///   synced ops range)
/// - If `pruned_chunks == 0`, `grafted_pinned_nodes` is empty
///
/// These invariants are intentionally validated at `build_db` time rather than in a constructor
/// here, because the check needs access to the merkle family `F` and the sync range; this struct
/// is a pure data carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentOverlayState<D: Digest> {
    /// Number of fully-pruned bitmap chunks at the sender.
    ///
    /// Note that under the MMB settlement guard this may lag
    /// `inactivity_floor_loc / CHUNK_SIZE_BITS` — the receiver must trust this field rather
    /// than re-deriving it from `range.start`.
    pub pruned_chunks: u64,

    /// Grafted tree's pinned node digests at the `pruned_chunks` boundary, in the order
    /// returned by `F::nodes_to_pin(Location::new(pruned_chunks))`.
    ///
    /// Length equals `F::nodes_to_pin(Location::new(pruned_chunks)).count()` (the popcount
    /// of `pruned_chunks` under the default `nodes_to_pin` behavior).
    pub grafted_pinned_nodes: Vec<D>,
}

impl<T: Translator, J: Clone> Config for super::Config<T, J> {
    type JournalConfig = J;

    fn journal_config(&self) -> Self::JournalConfig {
        self.journal_config.clone()
    }
}

/// Shared helper to build a `current::db::Db` from sync components.
///
/// Runs one of two reconstruction paths depending on whether the sender supplied overlay
/// state:
///
/// * **Sender-supplied overlay (normal sync).** `overlay_state` carries the sender's
///   `pruned_chunks` and the corresponding grafted pinned nodes. The receiver validates the
///   payload's invariants, uses those pins to seed the grafted tree, and replays the synced
///   operations to populate the bitmap tail. The grafted pruning boundary intentionally does
///   **not** derive from `range.start`: under the MMB settlement guard the sender's
///   `pruned_chunks` lags its inactivity floor, and deriving from the ops range would
///   produce a divergent grafted tree.
///
/// * **No overlay, existing on-disk state (exact-match reopen).** `overlay_state` is `None`
///   only when the engine completed without canonical-root authentication (e.g. `any`,
///   `immutable`, `keyless` databases, or `current` without a trusted canonical root). When
///   `canonical_root` is set, the engine defers completion until the normal boundary-request
///   pipeline has delivered fresh overlay state (see `Engine::needs_fresh_boundary_state`),
///   so `overlay_state` is always `Some` for authenticated `current` sync. The fallback to
///   persisted metadata therefore only applies to the unauthenticated path, which trusts the
///   overlay persisted by a prior run. If no persisted overlay exists, we treat the database
///   as unpruned (`pruned_chunks = 0`), matching the normal init path.
///
/// If `canonical_root` is `Some`, the rebuilt database's canonical root is compared against
/// it after construction; a mismatch returns [`qmdb::Error::DataCorrupted`] without
/// persisting any metadata. This is the authentication anchor for the overlay payload: the
/// sync engine verifies operations against the ops root but has no way to verify overlay
/// state on its own, so the caller must supply a trusted canonical root to detect a lying
/// sender.
#[allow(clippy::too_many_arguments)]
async fn build_db<F, E, U, I, H, J, T, const N: usize>(
    context: E,
    merkle_config: journaled::Config,
    log: J,
    translator: T,
    pinned_nodes: Option<Vec<H::Digest>>,
    overlay_state: Option<CurrentOverlayState<H::Digest>>,
    canonical_root: Option<H::Digest>,
    range: Range<Location<F>>,
    apply_batch_size: usize,
    metadata_partition: String,
    thread_pool: Option<commonware_parallel::ThreadPool>,
) -> Result<db::Db<F, E, J, I, H, U, N>, qmdb::Error<F>>
where
    F: merkle::Graftable,
    E: Context,
    U: Update + Send + Sync + 'static,
    I: IndexFactory<T, Value = Location<F>>,
    H: Hasher,
    T: Translator,
    J: Mutable<Item = Operation<F, U>> + Persistable<Error = crate::journal::Error>,
    Operation<F, U>: Codec + Committable + CodecShared,
{
    // Load persisted metadata up front. On a fresh partition this returns
    // `(metadata, 0, vec![])`; on a reopen of an already-synced partition it returns the
    // previously-persisted `pruned_chunks` and grafted pins, which we use as the fallback
    // when the sync engine did not obtain overlay state from the sender.
    let (metadata, persisted_pruned_chunks, persisted_pins) =
        db::init_metadata::<F, E, DigestOf<H>>(context.with_label("metadata"), &metadata_partition)
            .await?;

    // Resolve the effective overlay state. `overlay_state` from the sender takes precedence.
    // When absent, fall back to persisted metadata — but only for the unauthenticated path
    // (canonical_root is None). For authenticated pruned sync the engine guarantees a fresh
    // boundary fetch, so overlay_state should always be Some.
    let (pruned_chunks, grafted_pinned_nodes) = match overlay_state {
        Some(state) => {
            // Validate sender-supplied overlay-state invariants before touching any tree
            // state. Digest validity is already enforced by codec.
            let CurrentOverlayState {
                pruned_chunks,
                grafted_pinned_nodes,
            } = state;
            let pruned_chunks = usize::try_from(pruned_chunks).map_err(|_| {
                qmdb::Error::<F>::DataCorrupted("overlay pruned_chunks overflows usize")
            })?;
            // `F::nodes_to_pin` panics on invalid `prune_loc` (exceeds `F::MAX_LEAVES`),
            // so validate the location before invoking it. A malicious sender could otherwise
            // supply an oversized `pruned_chunks` and convert a protocol-level failure into a
            // panic in the receiver.
            let pruned_loc = Location::<F>::new(pruned_chunks as u64);
            if !pruned_loc.is_valid() {
                return Err(qmdb::Error::<F>::DataCorrupted(
                    "overlay pruned_chunks exceeds F::MAX_LEAVES",
                ));
            }
            let expected_pins = F::nodes_to_pin(pruned_loc).count();
            if grafted_pinned_nodes.len() != expected_pins {
                return Err(qmdb::Error::<F>::DataCorrupted(
                    "overlay grafted_pinned_nodes length does not match F::nodes_to_pin(pruned_chunks)",
                ));
            }
            if pruned_chunks == 0 && !grafted_pinned_nodes.is_empty() {
                return Err(qmdb::Error::<F>::DataCorrupted(
                    "overlay grafted_pinned_nodes must be empty when pruned_chunks == 0",
                ));
            }
            // The sender cannot have pruned past the synced ops range; otherwise the receiver
            // would claim chunks pruned that it lacks the ops to reconstruct.
            let pruned_bits = (pruned_chunks as u64)
                .checked_mul(BitMap::<N>::CHUNK_SIZE_BITS)
                .ok_or(qmdb::Error::<F>::DataCorrupted(
                    "overlay pruned_chunks * chunk bits overflows u64",
                ))?;
            if pruned_bits > *range.start {
                return Err(qmdb::Error::<F>::DataCorrupted(
                    "overlay pruned_chunks extends past sync range.start",
                ));
            }
            if pruned_bits > *range.end {
                return Err(qmdb::Error::<F>::DataCorrupted(
                    "overlay pruned_chunks extends past sync range.end",
                ));
            }
            (pruned_chunks, grafted_pinned_nodes)
        }
        None => {
            // Authenticated pruned sync requires fresh overlay state — the engine
            // guarantees a boundary fetch when canonical_root is set, so reaching here
            // with canonical_root + pruned persisted state means something went wrong
            // (e.g. stale metadata from a prior failed sync).
            if canonical_root.is_some() && persisted_pruned_chunks > 0 {
                return Err(qmdb::Error::<F>::DataCorrupted(
                    "overlay state required for authenticated pruned sync but not provided",
                ));
            }
            (persisted_pruned_chunks, persisted_pins)
        }
    };

    // Build authenticated log.
    let hasher = StandardHasher::<H>::new();
    let merkle = journaled::Journaled::<F, _, _>::init_sync(
        context.with_label("merkle"),
        journaled::SyncConfig {
            config: merkle_config,
            range: range.clone(),
            pinned_nodes,
        },
        &hasher,
    )
    .await?;
    let index = I::new(context.with_label("index"), translator);
    let log = authenticated::Journal::<F, _, _, _>::from_components(
        merkle,
        log,
        hasher,
        apply_batch_size as u64,
    )
    .await?;

    // Initialize bitmap with the sender's overlay pruning boundary. If `pruned_bits` is less
    // than the ops log's inactivity floor (e.g. MMB settlement guard defers bitmap pruning),
    // init_from_log below replays ops from `pruned_bits` up to the floor and populates those
    // bits as inactive (they correspond to ops that have been superseded or committed).
    let mut status = BitMap::<N>::new_with_pruned_chunks(pruned_chunks)
        .map_err(|_| qmdb::Error::<F>::DataCorrupted("pruned chunks overflow"))?;

    // Build any::Db with bitmap callback.
    //
    // init_from_log replays the operations, building the snapshot (index) and invoking
    // our callback for each operation to populate the bitmap.
    let known_inactivity_floor = Location::new(status.len());
    let any: AnyDb<F, E, J, I, H, U> = AnyDb::init_from_log(
        index,
        log,
        Some(known_inactivity_floor),
        |is_active: bool, old_loc: Option<Location<F>>| {
            status.push(is_active);
            if let Some(loc) = old_loc {
                status.set_bit(*loc, false);
            }
        },
    )
    .await?;

    // Build grafted tree.
    let hasher = StandardHasher::<H>::new();
    let grafted_tree = db::build_grafted_tree::<F, H, N>(
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

    // The metadata store was loaded earlier (to resolve overlay-state fallback). Construct
    // the Db and persist the final overlay state below.
    let current_db = db::Db {
        any,
        status: crate::qmdb::current::batch::BitmapBatch::Base(Arc::new(status)),
        grafted_tree,
        metadata: AsyncMutex::new(metadata),
        thread_pool,
        root,
    };

    // Authenticate the overlay payload indirectly: the sync engine only verifies operations
    // against the ops root, so a lying sender could have shipped overlay state that produces
    // a different canonical root than the one the caller trusts. Check the rebuilt canonical
    // root against the caller-supplied anchor before persisting any metadata.
    if let Some(expected) = canonical_root {
        if current_db.root != expected {
            return Err(qmdb::Error::<F>::DataCorrupted(
                "rebuilt canonical root does not match target canonical_root",
            ));
        }
    }

    // Persist metadata so the db can be reopened with init_fixed/init_variable.
    current_db.sync_metadata().await?;

    Ok(current_db)
}

/// Extract the sender's overlay state from a live `current::db::Db`.
///
/// Called by the current-sync resolver on boundary batches (when `include_pinned_nodes`
/// is set) to ship the exact grafted-tree pruning state to the receiver. This reads the
/// live in-memory `grafted_tree` directly rather than going through persisted metadata,
/// which can lag the in-memory state between commits.
fn extract_overlay_state<F, E, C, I, H, U, const N: usize>(
    db: &db::Db<F, E, C, I, H, U, N>,
) -> Result<CurrentOverlayState<H::Digest>, qmdb::Error<F>>
where
    F: merkle::Graftable,
    E: Context,
    C: crate::journal::contiguous::Contiguous<Item: CodecShared>,
    I: crate::index::Unordered<Value = Location<F>>,
    H: Hasher,
    U: Send + Sync,
{
    let pruned_chunks = db.status.pruned_chunks() as u64;
    let mut grafted_pinned_nodes = Vec::new();
    if pruned_chunks > 0 {
        let grafted_boundary = Location::<F>::new(pruned_chunks);
        for pos in F::nodes_to_pin(grafted_boundary) {
            let digest = db
                .grafted_tree
                .get_node(pos)
                .ok_or(qmdb::Error::<F>::DataCorrupted(
                    "grafted tree missing pinned node for pruned boundary",
                ))?;
            grafted_pinned_nodes.push(digest);
        }
    }
    Ok(CurrentOverlayState {
        pruned_chunks,
        grafted_pinned_nodes,
    })
}

// --- Database trait implementations ---

macro_rules! impl_current_sync_database {
    ($db:ident, $op:ident, $update:ident,
     $journal:ty, $config:ty,
     $key_bound:path, $value_bound:ident
     $(; $($where_extra:tt)+)?) => {
        impl<F, E, K, V, H, T, const N: usize> Database for $db<F, E, K, V, H, T, N>
        where
            F: merkle::Graftable,
            E: Context,
            K: $key_bound,
            V: $value_bound + 'static,
            H: Hasher,
            T: Translator,
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
                overlay_state: Option<CurrentOverlayState<Self::Digest>>,
                canonical_root: Option<Self::Digest>,
                range: Range<Location<F>>,
                apply_batch_size: usize,
            ) -> Result<Self, qmdb::Error<F>> {
                let merkle_config = config.merkle_config.clone();
                let metadata_partition = config.grafted_metadata_partition.clone();
                let thread_pool = config.merkle_config.thread_pool.clone();
                let translator = config.translator.clone();
                build_db::<F, _, $update<K, V>, _, H, _, T, N>(
                    context,
                    merkle_config,
                    log,
                    translator,
                    pinned_nodes,
                    overlay_state,
                    canonical_root,
                    range,
                    apply_batch_size,
                    metadata_partition,
                    thread_pool,
                )
                .await
            }

            /// Returns the ops root (not the canonical root), since the sync engine verifies
            /// batches against the ops tree.
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
    VariableConfig<T, <UnorderedVariableOp<F, K, V> as CodecRead>::Cfg>,
    Key, VariableValue;
    UnorderedVariableOp<F, K, V>: CodecShared
);

impl_current_sync_database!(
    CurrentOrderedFixedDb, OrderedFixedOp, OrderedFixedUpdate,
    fixed::Journal<E, Self::Op>, FixedConfig<T>,
    Array, FixedValue
);

impl_current_sync_database!(
    CurrentOrderedVariableDb, OrderedVariableOp, OrderedVariableUpdate,
    variable::Journal<E, Self::Op>,
    VariableConfig<T, <OrderedVariableOp<F, K, V> as CodecRead>::Cfg>,
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
            F: merkle::Graftable,
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
            ) -> Result<
                crate::qmdb::sync::FetchResult<Self::Family, Self::Op, Self::Digest>,
                Self::Error,
            > {
                let (proof, operations) = self.any
                    .historical_proof(op_count, start_loc, max_ops)
                    .await?;
                let (pinned_nodes, overlay_state) = if include_pinned_nodes {
                    (
                        Some(self.any.pinned_nodes_at(start_loc).await?),
                        Some(extract_overlay_state(&**self)?),
                    )
                } else {
                    (None, None)
                };
                Ok(crate::qmdb::sync::FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                    overlay_state,
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
            F: merkle::Graftable,
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
            ) -> Result<
                crate::qmdb::sync::FetchResult<Self::Family, Self::Op, Self::Digest>,
                qmdb::Error<F>,
            > {
                let db = self.read().await;
                let (proof, operations) = db.any
                    .historical_proof(op_count, start_loc, max_ops)
                    .await?;
                let (pinned_nodes, overlay_state) = if include_pinned_nodes {
                    (
                        Some(db.any.pinned_nodes_at(start_loc).await?),
                        Some(extract_overlay_state(&*db)?),
                    )
                } else {
                    (None, None)
                };
                Ok(crate::qmdb::sync::FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                    overlay_state,
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
            F: merkle::Graftable,
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
            ) -> Result<
                crate::qmdb::sync::FetchResult<Self::Family, Self::Op, Self::Digest>,
                qmdb::Error<F>,
            > {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(qmdb::Error::<F>::KeyNotFound)?;
                let (proof, operations) = db.any
                    .historical_proof(op_count, start_loc, max_ops)
                    .await?;
                let (pinned_nodes, overlay_state) = if include_pinned_nodes {
                    (
                        Some(db.any.pinned_nodes_at(start_loc).await?),
                        Some(extract_overlay_state(db)?),
                    )
                } else {
                    (None, None)
                };
                Ok(crate::qmdb::sync::FetchResult {
                    proof,
                    operations,
                    success_tx: oneshot::channel().0,
                    pinned_nodes,
                    overlay_state,
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
