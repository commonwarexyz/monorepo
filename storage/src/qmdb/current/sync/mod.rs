//! Synchronization logic for [crate::qmdb::current] databases.
//!
//! Contains the sync `Database` and `Resolver` trait implementations for all
//! [Db](crate::qmdb::current::db::Db) variants (ordered/unordered, fixed/variable), plus a
//! [sync()] wrapper that drives the shared sync engine from a stream of trusted canonical
//! roots.
//!
//! # Why this wrapper exists
//!
//! A `current` database's canonical root commits to the ops root, the grafted root, and
//! optional pending/partial chunk digests (see the [Root structure](super) section in the
//! module documentation). The shared sync engine, however, verifies each operation batch
//! against the **ops root** alone — not the canonical root — because the ops-tree range
//! proof format is shared with `any` sync.
//!
//! That leaves a gap: a client that only trusts a canonical root from consensus cannot
//! drive the engine directly. It needs the ops root that the trusted canonical root
//! commits to, plus an [`OpsRootWitness`] proving the binding. Only a node holding the
//! live database state can produce that witness, and only for states it has committed.
//!
//! # API shape
//!
//! - [`CurrentResolver`] extends [`qmdb_sync::Resolver`] with `target_for_roots`: the
//!   client passes a set of trusted canonical roots and the server answers from a small
//!   per-commit cache populated at [`Db::cache_current_target`](crate::qmdb::current::db::Db).
//! - [`sync()`] takes a `trusted_root_rx: mpsc::Receiver<Digest>` (e.g., a stream of
//!   finalized roots from consensus) and a `CurrentResolver`. It buffers recent trusted
//!   roots and polls the resolver until a verified target is returned, then drives the
//!   shared engine and continues forwarding matching updates as the chain advances.
//! - Every returned target passes two gates before reaching the engine: **membership**
//!   (target root is in the trusted buffer) and **witness verification**
//!   (witness commits `ops_root` to `target.root`).
//!
//! # Liveness model
//!
//! Discovery and forward loops wake on either a new trusted root or a `target_poll_interval`
//! tick. Polling guarantees progress under a quiet trusted-root stream: if the resolver's
//! cache lags behind a buffered root, the wrapper retries on each tick. Closing the
//! trusted-root stream while the buffer is non-empty switches the wrapper to poll-only
//! mode; closing while the buffer is empty returns `TrustedStreamClosed`.
//!
//! # Engine completion
//!
//! After the engine downloads all operations, the bitmap and grafted tree are reconstructed
//! deterministically. The wrapper recomputes the canonical root and rejects with
//! `RootMismatch` if it differs from the latest accepted target's `root`.
//!
//! For pruned targets (`range.start > 0`), grafted pinned nodes for the pruned region are
//! read directly from the ops tree via the zero-chunk identity: all-zero bitmap chunks
//! produce a grafted leaf equal to the ops subtree root, making the grafted tree
//! structurally identical to the ops tree at and above the grafting height.

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
            EngineError,
        },
    },
    translator::Translator,
    Context, Persistable,
};
use commonware_codec::{Codec, CodecShared, Encode, Read as CodecRead, ReadExt as _};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Supervisor};
use commonware_utils::{
    bitmap::Prunable as BitMap,
    channel::{mpsc, oneshot},
    range::NonEmptyRange,
    sync::AsyncMutex,
    Array,
};
use futures::future::{select, Either};
use std::{
    collections::VecDeque,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

#[cfg(test)]
pub(crate) mod tests;

impl<F: Graftable, D: Digest> From<db::CachedTarget<F, D>> for Target<F, D> {
    fn from(t: db::CachedTarget<F, D>) -> Self {
        Self::new(t.root, t.ops_root, t.witness, t.range)
    }
}

/// Resolver extension for `current` databases: query the server for a sync target whose
/// canonical root appears in a set of trusted roots.
///
/// The server's witness cache holds up to `witness_cache_size` recent committed targets,
/// including the init-seeded entry when the database is non-empty (the seed counts
/// against capacity and may be evicted by later commits). The client passes its recent
/// trusted-root buffer (e.g., from consensus) and the server returns the first match, if
/// any. Callers must still verify each returned target's witness against the trusted
/// root before driving sync; the helper [`sync()`] in this module performs both checks.
pub trait CurrentResolver: qmdb_sync::Resolver
where
    Self::Family: Graftable,
{
    /// Return the first cached target whose canonical root appears in `trusted_roots`,
    /// or `None` if no entry matches. A cache miss is not an error.
    #[allow(clippy::type_complexity)]
    fn target_for_roots<'a>(
        &'a self,
        trusted_roots: &'a [Self::Digest],
    ) -> impl Future<Output = Result<Option<Target<Self::Family, Self::Digest>>, Self::Error>> + Send + 'a;
}

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

impl<F: Graftable, D: Digest> PartialEq for Target<F, D> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.ops_root == other.ops_root
            && self.witness.grafted_root == other.witness.grafted_root
            && self.witness.pending_chunk_digest == other.witness.pending_chunk_digest
            && self.witness.partial_chunk == other.witness.partial_chunk
            && self.range == other.range
    }
}

impl<F: Graftable, D: Digest> Eq for Target<F, D> {}

impl<F: Graftable, D: Digest> Target<F, D> {
    /// Create a target anchored by a trusted database root and an authenticated ops root.
    pub const fn new(
        root: D,
        ops_root: D,
        witness: OpsRootWitness<F, D>,
        range: NonEmptyRange<Location<F>>,
    ) -> Self {
        Self {
            root,
            ops_root,
            witness,
            range,
        }
    }

    /// Return true if the witness authenticates the ops root against the trusted root.
    pub fn verify<H: commonware_cryptography::Hasher<Digest = D>>(
        &self,
        hasher: &StandardHasher<H>,
    ) -> bool {
        self.witness.verify(hasher, &self.ops_root, &self.root)
    }
}

impl<F: Graftable, D: Digest> qmdb_sync::Target for Target<F, D> {
    type Family = F;
    type Digest = D;

    fn root(&self) -> Self::Digest {
        self.root
    }

    fn ops_root(&self) -> Self::Digest {
        self.ops_root
    }

    fn range(&self) -> &NonEmptyRange<Location<Self::Family>> {
        &self.range
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

/// Configuration for syncing a `current` database from trusted canonical roots.
///
/// The caller feeds a stream of canonical roots from consensus (or another trust source) via
/// [`Config::trusted_root_rx`]. The wrapper buffers the most recent
/// [`Config::trusted_root_buffer`] roots and queries `resolver` for a matching target on
/// every new trusted root **and** on every `target_poll_interval` tick. The first match
/// starts the engine; subsequent matches are forwarded as in-flight target updates.
///
/// Polling on a fixed interval guarantees progress even when the trusted-root stream goes
/// silent (e.g., consensus is finalized but no new roots arrive) — without it, a resolver
/// that lags behind the client's trusted set could stall sync indefinitely.
pub struct Config<
    DB: Database,
    R: CurrentResolver<Family = DB::Family, Op = DB::Op, Digest = DB::Digest>,
> where
    DB::Family: Graftable,
    DB::Op: Encode,
{
    /// Runtime context.
    pub context: DB::Context,
    /// Resolver for fetching operations, proofs, and sync targets.
    pub resolver: R,
    /// Stream of trusted canonical roots (e.g., from consensus finalization).
    pub trusted_root_rx: mpsc::Receiver<DB::Digest>,
    /// Number of recent trusted roots to retry against on each resolver query. Must be > 0.
    ///
    /// Network resolvers silently cap the per-request payload at the wire-format limit
    /// (typically 256). Setting this larger than the wire cap still works for local
    /// resolvers but only the most-recent wire-cap entries are sent over the network on
    /// each query.
    pub trusted_root_buffer: NonZeroUsize,
    /// Backoff between resolver queries when the trusted-root stream is idle. Queries are
    /// also triggered immediately on every new trusted root. Must be > 0 to avoid a
    /// busy-loop. Very small values may be quantized by the runtime scheduler.
    pub target_poll_interval: Duration,
    /// Maximum parallel outstanding requests.
    pub max_outstanding_requests: usize,
    /// Maximum operations per fetch batch.
    pub fetch_batch_size: NonZeroU64,
    /// Operations to apply per internal batch.
    pub apply_batch_size: usize,
    /// Database-specific configuration.
    pub db_config: DB::Config,
    /// Channel that requests sync completion once the current target is reached.
    pub finish_rx: Option<mpsc::Receiver<()>>,
    /// Channel to notify an observer when the current target is reached.
    pub reached_target_tx: Option<mpsc::Sender<Target<DB::Family, DB::Digest>>>,
    /// Historical roots to retain for in-flight request verification.
    pub max_retained_roots: usize,
}

/// Bounded FIFO of recent trusted canonical roots plus a `HashSet` for O(1) membership.
struct TrustedRootBuffer<D: Digest> {
    order: VecDeque<D>,
    set: std::collections::HashSet<D>,
    capacity: NonZeroUsize,
}

impl<D: Digest> TrustedRootBuffer<D> {
    fn new(capacity: NonZeroUsize) -> Self {
        Self {
            order: VecDeque::with_capacity(capacity.get()),
            set: std::collections::HashSet::with_capacity(capacity.get()),
            capacity,
        }
    }

    /// Insert `root`. Evicts the oldest entry when capacity is exceeded. No-op if already
    /// present.
    fn insert(&mut self, root: D) {
        if !self.set.insert(root) {
            return;
        }
        self.order.push_back(root);
        while self.order.len() > self.capacity.get() {
            if let Some(evicted) = self.order.pop_front() {
                self.set.remove(&evicted);
            }
        }
    }

    fn contains(&self, root: &D) -> bool {
        self.set.contains(root)
    }

    fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    fn as_slice_vec(&self) -> Vec<D> {
        // Most-recent first so resolvers honoring caller order check the freshest first.
        self.order.iter().rev().copied().collect()
    }
}

/// Ask `resolver` for a target whose root is in `trusted` and verify it.
///
/// Returns `Ok(Some(target))` only after passing two checks:
/// 1. **Membership**: `target.root` is in `trusted`. A malicious resolver may return a
///    self-consistent target for an untrusted root; the engine's end-of-sync `RootMismatch`
///    check does not catch this, so the wrapper must.
/// 2. **Witness**: `target.verify(&hasher)` succeeds (cryptographically binds `ops_root`).
///
/// A resolver `None` is `Ok(None)` (cache miss). A resolver error propagates.
/// A returned target failing either check returns `Err(OpsRootWitnessInvalid)`.
async fn next_verified_target<F, D, R, H>(
    resolver: &R,
    trusted: &TrustedRootBuffer<D>,
    hasher: &StandardHasher<H>,
) -> Result<Option<Target<F, D>>, qmdb_sync::Error<F, R::Error, D>>
where
    F: Graftable,
    D: Digest,
    H: commonware_cryptography::Hasher<Digest = D>,
    R: CurrentResolver<Family = F, Digest = D>,
{
    let roots = trusted.as_slice_vec();
    if roots.is_empty() {
        return Ok(None);
    }
    let target = match resolver
        .target_for_roots(&roots)
        .await
        .map_err(qmdb_sync::Error::Resolver)?
    {
        Some(t) => t,
        None => return Ok(None),
    };
    if !trusted.contains(&target.root) {
        tracing::warn!("resolver returned target for untrusted root");
        return Err(qmdb_sync::Error::Engine(EngineError::OpsRootWitnessInvalid));
    }
    if !target.verify(hasher) {
        tracing::warn!("resolver returned target with invalid witness");
        return Err(qmdb_sync::Error::Engine(EngineError::OpsRootWitnessInvalid));
    }
    Ok(Some(target))
}

/// Sync a `current` database from a stream of trusted canonical roots.
///
/// The wrapper buffers recent trusted roots and queries `resolver` for matches. The first
/// verified match (passing membership + witness checks) starts the engine; subsequent matches
/// that strictly advance the current target are forwarded as engine updates.
pub async fn sync<DB, R>(
    config: Config<DB, R>,
) -> Result<DB, qmdb_sync::Error<DB::Family, R::Error, DB::Digest>>
where
    DB: Database,
    DB::Family: Graftable,
    DB::Op: Encode,
    R: CurrentResolver<Family = DB::Family, Op = DB::Op, Digest = DB::Digest>,
{
    let hasher = qmdb::hasher::<DB::Hasher>();
    let mut trusted_root_rx = config.trusted_root_rx;
    let resolver = config.resolver;
    if config.target_poll_interval.is_zero() {
        return Err(qmdb_sync::Error::Engine(EngineError::InvalidConfig(
            "target_poll_interval must be > 0",
        )));
    }
    let poll_interval = config.target_poll_interval;

    // Take an owned clock handle BEFORE moving `config.context` into the engine. Both the
    // discovery loop (this function's body) and the forward task (spawned later via
    // `select` in the same task) need to call `sleep`, but the engine consumes the
    // primary context. `Supervisor::child` (via `Metrics: Supervisor`) returns a fresh
    // child handle from `&self`, so we get a clock without requiring `Context: Clone`.
    let poll_clock = config.context.child("current_sync_poll");

    // Discovery phase: pull trusted roots, queried on each new root or `poll_interval`
    // tick (whichever first), until the resolver returns a matching target.
    //
    // Channel-close handling: if the trusted-root stream closes while the buffer already
    // holds roots, switch to poll-only mode — the resolver may catch up later and produce
    // a match against the buffered roots. Only return `TrustedStreamClosed` when the
    // channel closes AND the buffer is empty (we have nothing to match against).
    let mut trusted = TrustedRootBuffer::<DB::Digest>::new(config.trusted_root_buffer);
    let mut stream_closed = false;
    let initial_target = loop {
        if stream_closed {
            // Buffer is non-empty (we checked at close); just poll.
            poll_clock.sleep(poll_interval).await;
        } else {
            let recv_fut = trusted_root_rx.recv();
            let sleep_fut = poll_clock.sleep(poll_interval);
            futures::pin_mut!(recv_fut);
            futures::pin_mut!(sleep_fut);
            match select(recv_fut, sleep_fut).await {
                Either::Left((Some(root), _)) => trusted.insert(root),
                Either::Left((None, _)) => {
                    if trusted.is_empty() {
                        return Err(qmdb_sync::Error::Engine(EngineError::TrustedStreamClosed));
                    }
                    stream_closed = true;
                }
                Either::Right(_) => {} // poll tick: re-query the resolver with the current buffer
            }
        }
        if let Some(t) =
            next_verified_target::<_, _, _, DB::Hasher>(&resolver, &trusted, &hasher).await?
        {
            break t;
        }
    };

    // Build the engine, with an internal update channel of capacity 1: the wrapper-side
    // discovery loop will push at most one in-flight target ahead of the engine at any time.
    let (engine_update_tx, engine_update_rx) = mpsc::channel::<Target<DB::Family, DB::Digest>>(1);
    let engine_config: EngineConfig<DB, R, Target<DB::Family, DB::Digest>> = EngineConfig {
        context: config.context,
        resolver: resolver.clone(),
        target: initial_target.clone(),
        max_outstanding_requests: config.max_outstanding_requests,
        fetch_batch_size: config.fetch_batch_size,
        apply_batch_size: config.apply_batch_size,
        db_config: config.db_config,
        update_rx: Some(engine_update_rx),
        finish_rx: config.finish_rx,
        reached_target_tx: config.reached_target_tx,
        max_retained_roots: config.max_retained_roots,
    };

    let engine = qmdb_sync::Engine::new(engine_config).await?;
    let engine_fut = Box::pin(engine.sync_with_target());

    // Continue feeding trusted roots and forwarding strictly-forward matches as engine
    // updates while the engine runs.
    //
    // Channel-close handling mirrors the discovery loop: if the stream closes while the
    // buffer holds roots, keep polling — a buffered trusted root may still match a future
    // resolver state and produce a forward update. The forward task exits naturally when
    // (a) the engine completes and the wrapping `select` drops this future, or (b) the
    // engine update channel is closed (`engine_update_tx.send` returns Err).
    let mut last_accepted = initial_target;
    let forward_fut = Box::pin(async move {
        type ForwardResult<DB, R> = Result<
            (),
            qmdb_sync::Error<
                <DB as Database>::Family,
                <R as qmdb_sync::Resolver>::Error,
                <DB as Database>::Digest,
            >,
        >;
        let result: ForwardResult<DB, R> = loop {
            if stream_closed {
                poll_clock.sleep(poll_interval).await;
            } else {
                let recv_fut = trusted_root_rx.recv();
                let sleep_fut = poll_clock.sleep(poll_interval);
                futures::pin_mut!(recv_fut);
                futures::pin_mut!(sleep_fut);
                match select(recv_fut, sleep_fut).await {
                    Either::Left((Some(root), _)) => trusted.insert(root),
                    Either::Left((None, _)) => {
                        if trusted.is_empty() {
                            break Ok(()); // nothing more to forward
                        }
                        stream_closed = true;
                    }
                    Either::Right(_) => {} // poll tick: re-query and continue
                }
            }
            let candidate =
                match next_verified_target::<_, _, _, DB::Hasher>(&resolver, &trusted, &hasher)
                    .await
                {
                    Ok(Some(t)) => t,
                    Ok(None) => continue,
                    Err(e) => break Err(e),
                };
            // Wrapper-level non-forward filter: mirror `qmdb_sync::target::validate_update`
            // and drop anything that would fail it, so the engine never sees a hard error
            // from a stale-but-valid target. The conditions match validate_update exactly:
            //   - start moves backward
            //   - end fails to strictly advance
            //   - ops_root is unchanged
            if candidate.range.start() < last_accepted.range.start()
                || candidate.range.end() <= last_accepted.range.end()
                || candidate.ops_root == last_accepted.ops_root
            {
                continue;
            }
            if engine_update_tx.send(candidate.clone()).await.is_err() {
                // Engine dropped its receiver: it has finished. Stop forwarding.
                break Ok(());
            }
            last_accepted = candidate;
        };
        result
    });

    let (database, final_target) = match select(engine_fut, forward_fut).await {
        Either::Left((result, _)) => result?,
        Either::Right((forward_result, engine_fut)) => {
            forward_result?;
            engine_fut.await?
        }
    };

    let expected = final_target.root;
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
    witness_cache_size: usize,
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

    // Compute the database root and the witness binding the ops root to it. The grafted root
    // is deterministic from the ops (authenticated by the engine) and the bitmap (deterministic
    // from the ops).
    let storage = grafting::Storage::new(
        &grafted_tree,
        grafting::height::<N>(),
        &any.log.merkle,
        hasher.clone(),
    );
    let partial = db::partial_chunk(any.bitmap.as_ref());
    let ops_root = any.root();
    let db::ComputedRoot { root, witness } = db::compute_db_root::<F, H, _, _, N>(
        &hasher,
        any.bitmap.as_ref(),
        &storage,
        ops_leaves,
        partial,
        any.inactivity_floor_loc,
        &ops_root,
    )
    .await?;

    // Initialize metadata store and construct the Db.
    let (metadata, _, _) =
        db::init_metadata::<F, E, DigestOf<H>>(context.child("metadata"), &metadata_partition)
            .await?;

    let metrics = db::Metrics::new(context);
    let witness_cache = db::WitnessCache::new(witness_cache_size);
    let mut current_db = db::Db {
        any,
        grafted_tree,
        metadata: AsyncMutex::new(metadata),
        strategy,
        root,
        witness_cache,
        metrics,
    };
    current_db.cache_current_target(ops_root, witness).await;
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
                let witness_cache_size = config.witness_cache_size;
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
                    witness_cache_size,
                )
                .await
            }

            async fn has_local_target_state<Target>(
                context: Self::Context,
                config: &Self::Config,
                target: &Target,
            ) -> bool
            where
                Target: qmdb_sync::Target<Family = Self::Family, Digest = Self::Digest>,
            {
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
                if Location::new(bounds.start) > target.range().start() {
                    return false;
                }
                let Ok(inactivity_floor) =
                    qmdb::find_inactivity_floor_at::<F, _>(&reader, target.range().end(), |op| {
                        op.has_floor()
                    })
                    .await
                else {
                    return false;
                };

                let inactive_peaks = F::inactive_peaks(
                    F::location_to_position(target.range().end()),
                    inactivity_floor,
                );
                if !qmdb::any::sync::has_local_target_state::<F, _, H, S, _>(
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

        impl<F, E, K, V, H, T, const N: usize, S> CurrentResolver
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
            fn target_for_roots<'a>(
                &'a self,
                trusted_roots: &'a [H::Digest],
            ) -> impl std::future::Future<
                    Output = Result<Option<Target<F, H::Digest>>, qmdb::Error<F>>,
                > + Send
                  + 'a {
                async move {
                    Ok(self.cached_target(trusted_roots).map(Into::into))
                }
            }
        }

        impl<F, E, K, V, H, T, const N: usize, S> CurrentResolver
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
            fn target_for_roots<'a>(
                &'a self,
                trusted_roots: &'a [H::Digest],
            ) -> impl std::future::Future<
                    Output = Result<Option<Target<F, H::Digest>>, qmdb::Error<F>>,
                > + Send
                  + 'a {
                async move {
                    let db = self.read().await;
                    Ok(db.cached_target(trusted_roots).map(Into::into))
                }
            }
        }

        impl<F, E, K, V, H, T, const N: usize, S> CurrentResolver
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
            fn target_for_roots<'a>(
                &'a self,
                trusted_roots: &'a [H::Digest],
            ) -> impl std::future::Future<
                    Output = Result<Option<Target<F, H::Digest>>, qmdb::Error<F>>,
                > + Send
                  + 'a {
                async move {
                    let guard = self.read().await;
                    let db = guard.as_ref().ok_or(qmdb::Error::<F>::KeyNotFound)?;
                    Ok(db.cached_target(trusted_roots).map(Into::into))
                }
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

#[cfg(feature = "arbitrary")]
impl<F: Graftable, D: Digest> arbitrary::Arbitrary<'_> for Target<F, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    F::PendingChunk<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let root = u.arbitrary()?;
        let ops_root = u.arbitrary()?;
        let witness = u.arbitrary()?;
        let max_loc = F::MAX_LEAVES;
        let lower = u.int_in_range(0..=*max_loc - 1)?;
        let upper = u.int_in_range(lower + 1..=*max_loc)?;
        Ok(Self {
            root,
            ops_root,
            witness,
            range: commonware_utils::non_empty_range!(Location::new(lower), Location::new(upper)),
        })
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use crate::merkle::{mmb, mmr};
    use commonware_codec::conformance::CodecConformance;
    use commonware_cryptography::sha256::Digest as Sha256Digest;

    commonware_conformance::conformance_tests! {
        CodecConformance<Target<mmr::Family, Sha256Digest>>,
        CodecConformance<Target<mmb::Family, Sha256Digest>>,
    }
}
