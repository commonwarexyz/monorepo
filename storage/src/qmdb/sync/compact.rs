//! Compact sync for compact-storage qmdbs.
//!
//! Compact sync does not transfer or reconstruct the full historical operation log. Instead, the
//! source serves the minimum authenticated state needed to recreate the latest committed compact db
//! state:
//!
//! - the total committed leaf count,
//! - the compact frontier's pinned nodes for that leaf count,
//! - the final commit operation, and
//! - a proof authenticating that final commit against the requested root.
//!
//! # What compact dbs store
//!
//! A compact db's only persistent state is its witness journal (`qmdb::compact::witness`), whose
//! entries each snapshot one committed state (commit operation, proof, and frontier pins).
//! The in-memory compact Merkle ([`crate::merkle::compact`]) is rebuilt from the journal tip on
//! reopen. Frontier pins reconstruct the root and allow further appends; serving compact sync also
//! requires the retained final commit operation and its proof.
//!
//! # When compact state changes
//!
//! Ordinary mutations become servable only on durable persistence:
//!
//! - [`sync`] verifies the final commit proof and compact frontier before database construction.
//! - [`Database::from_validated_state`] reconstructs the already-validated state without
//!   persisting it. That imported tip is immediately servable from memory, but is not restart
//!   stable until [`Database::persist_compact_state`] succeeds; older on-disk witnesses are not
//!   exposed while replacement is pending.
//! - Compact db persistence appends one witness entry during `commit` or `sync`.
//! - `rewind` restores the frontier and the witness from the target journal entry.
//!
//! Outside that validated-import exception, unsynced in-memory mutations are intentionally not
//! servable: `target()` and compact-state responses lag behind `apply_batch()` until the db's next
//! sync. A target identifies the currently servable witness; it is not itself a durability signal.
//!
//! # Safety and invariants
//!
//! The compact path relies on these invariants:
//!
//! - the served commit proof must authenticate the final commit at `leaf_count - 1`,
//! - reopen and rewind must re-verify the persisted witness against the root recomputed from the
//!   frontier rebuilt from the same journal entry, and
//! - reconstructed state must not be persisted until the db recomputes the requested root locally.
//!
//! If those invariants are violated by missing or corrupted persisted data, compact db reopen fails
//! with `DataCorrupted` rather than silently serving or restoring mismatched state.

use crate::{
    merkle::{Family, Location, Proof, hasher::Hasher as MerkleHasher},
    qmdb::{
        self,
        any::{FixedValue, VariableValue, value::ValueEncoding},
        immutable::{
            CompactDb as ImmutableCompactDb, Operation as ImmutableOp,
            fixed::{Db as ImmutableFixedDb, Operation as ImmutableFixedOp},
            variable::{Db as ImmutableVariableDb, Operation as ImmutableVariableOp},
        },
        keyless::{
            CompactDb as KeylessCompactDb, Operation as KeylessOp,
            fixed::{Db as KeylessFixedDb, Operation as KeylessFixedOp},
            variable::{Db as KeylessVariableDb, Operation as KeylessVariableOp},
        },
        operation::Key,
        sync::{EngineError, Error},
        verify_proof,
    },
    translator::Translator,
};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_macros::{boxed, select};
use commonware_parallel::Strategy;
use commonware_runtime::{Buf, BufMut, Clock, Metrics, Storage, Supervisor, reschedule};
use commonware_utils::{
    Array,
    channel::{mpsc, oneshot},
    sync::{AsyncRwLock, TracedAsyncRwLock},
};
use futures::future::{Either, pending};
use std::{future::Future, num::NonZeroU64, ops::Range, sync::Arc};

/// Compact-sync target for a compact-storage database.
///
/// Compact sync authenticates only the final committed root and total leaf count. Unlike replay
/// sync, there is no lower replay bound here because compact sync does not transfer or reconstruct
/// historical operations.
#[derive(Debug)]
pub struct Target<F: Family, D: Digest> {
    /// Authenticated root of the committed compact state.
    pub root: D,
    /// Total committed operations/leaves in that state.
    pub leaf_count: Location<F>,
}

impl<F: Family, D: Digest> Target<F, D> {
    const INVALID_LEAF_COUNT: &'static str = "leaf_count must be in 1..=MAX_LEAVES";

    /// Create a compact-sync target.
    pub const fn new(root: D, leaf_count: Location<F>) -> Self {
        Self { root, leaf_count }
    }

    /// Validate a compact target that may have been constructed programmatically.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.leaf_count.is_valid() || self.leaf_count == 0 {
            return Err(Self::INVALID_LEAF_COUNT);
        }
        Ok(())
    }
}

impl<F: Family, D: Digest> Clone for Target<F, D> {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            leaf_count: self.leaf_count,
        }
    }
}

impl<F: Family, D: Digest> PartialEq for Target<F, D> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.leaf_count == other.leaf_count
    }
}

impl<F: Family, D: Digest> Eq for Target<F, D> {}

impl<F: Family, D: Digest> Write for Target<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.leaf_count.write(buf);
    }
}

impl<F: Family, D: Digest> EncodeSize for Target<F, D> {
    fn encode_size(&self) -> usize {
        self.root.encode_size() + self.leaf_count.encode_size()
    }
}

impl<F: Family, D: Digest> Read for Target<F, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let root = D::read(buf)?;
        let leaf_count = Location::<F>::read(buf)?;
        let target = Self { root, leaf_count };
        target.validate().map_err(|reason| {
            CodecError::Invalid("storage::qmdb::sync::compact::Target", reason)
        })?;
        Ok(target)
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest> arbitrary::Arbitrary<'_> for Target<F, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let root = u.arbitrary()?;
        let leaf_count = Location::new(u.int_in_range(1..=*F::MAX_LEAVES)?);
        Ok(Self { root, leaf_count })
    }
}

/// Authenticated state for initializing a compact-storage database at a target root.
#[derive(Clone, Debug)]
pub struct State<F: Family, Op, D: Digest> {
    /// Total number of operations/leaves in the target database.
    pub leaf_count: Location<F>,
    /// Pinned Merkle nodes for the current frontier.
    pub pinned_nodes: Vec<D>,
    /// The final commit operation at `leaf_count - 1`.
    pub last_commit_op: Op,
    /// Proof authenticating `last_commit_op` against the target root.
    pub last_commit_proof: Proof<F, D>,
}

/// Compact state that has been validated against a target root.
#[derive(Clone, Debug)]
pub struct ValidatedState<F: Family, Op, D: Digest> {
    /// The compact state fetched from a peer after validation.
    pub state: State<F, Op, D>,
    /// The target root that `state` was validated against.
    pub root: D,
}

impl<F: Family, Op, D: Digest> Write for State<F, Op, D>
where
    Op: Write,
{
    fn write(&self, buf: &mut impl BufMut) {
        self.leaf_count.write(buf);
        self.pinned_nodes.write(buf);
        self.last_commit_op.write(buf);
        self.last_commit_proof.write(buf);
    }
}

/// Result from a compact-state fetch.
pub struct FetchResult<F: Family, Op, D: Digest> {
    /// The fetched compact state.
    pub state: State<F, Op, D>,
    /// Callback used to report whether downstream validated the state.
    pub callback: Option<oneshot::Sender<bool>>,
}

impl<F: Family, Op: std::fmt::Debug, D: Digest> std::fmt::Debug for FetchResult<F, Op, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchResult")
            .field("state", &self.state)
            .field("callback", &self.callback.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

impl<F: Family, Op, D: Digest> From<State<F, Op, D>> for FetchResult<F, Op, D> {
    fn from(state: State<F, Op, D>) -> Self {
        Self {
            state,
            callback: None,
        }
    }
}

impl<F: Family, Op, D: Digest> EncodeSize for State<F, Op, D>
where
    Op: EncodeSize,
{
    fn encode_size(&self) -> usize {
        self.leaf_count.encode_size()
            + self.pinned_nodes.encode_size()
            + self.last_commit_op.encode_size()
            + self.last_commit_proof.encode_size()
    }
}

impl<F: Family, Op, D: Digest> Read for State<F, Op, D>
where
    Op: Read,
{
    type Cfg = (RangeCfg<usize>, Op::Cfg, usize);

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let (pinned_nodes_cfg, op_cfg, max_proof_digests) = cfg;
        Ok(Self {
            leaf_count: Location::<F>::read(buf)?,
            pinned_nodes: Vec::<D>::read_cfg(buf, &(*pinned_nodes_cfg, ()))?,
            last_commit_op: Op::read_cfg(buf, op_cfg)?,
            last_commit_proof: Proof::<F, D>::read_cfg(buf, max_proof_digests)?,
        })
    }
}

/// Resolver-side errors for compact state serving.
#[derive(Debug, thiserror::Error)]
pub enum ServeError<F: Family, D: Digest> {
    /// The source database returned an error while building compact state.
    #[error("compact source database error: {0}")]
    Database(#[from] qmdb::Error<F>),
    /// The caller requested a target that compact sync cannot serve.
    #[error("invalid compact target: {0}")]
    InvalidTarget(&'static str),
    /// The resolver wrapper did not currently hold a database.
    #[error("compact source missing")]
    MissingSource,
    /// The source cannot see the requested leaf count: it is past the source's tip, or fell
    /// outside the window the source still retains.
    #[error("stale compact target - requested {requested:?}, current {current:?}")]
    StaleTarget {
        requested: Target<F, D>,
        current: Target<F, D>,
    },
    /// The source reaches the requested leaf count but cannot authenticate the requested
    /// committed root, because the boundary is not a commit or belongs to another history.
    #[error("divergent compact target - requested {requested:?}, current {current:?}")]
    DivergentTarget {
        requested: Target<F, D>,
        current: Target<F, D>,
    },
}

/// Trait for compact sync fetches from a source database.
#[allow(clippy::type_complexity)]
pub trait Resolver: Send + Sync + Clone + 'static {
    /// The merkle family backing the resolver's proofs.
    type Family: Family;

    /// The digest type used in proofs returned by the resolver.
    type Digest: Digest;

    /// The type of operations returned by the resolver.
    type Op;

    /// The error type returned by the resolver.
    type Error: std::error::Error + Send + 'static;

    /// Fetch the authenticated state for `target`.
    fn get_compact_state<'a>(
        &'a self,
        target: Target<Self::Family, Self::Digest>,
    ) -> impl Future<Output = Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error>>
    + Send
    + 'a;
}

/// Marker trait for resolvers whose associated types match a specific compact-sync database.
///
/// This is a trait-alias pattern used to avoid repeating
/// `Resolver<Family = DB::Family, Op = DB::Op, Digest = DB::Digest>`.
/// Blanket-implemented for any matching [`Resolver`], so callers never implement this directly.
pub trait CompactDbResolver<DB: Database>:
    Resolver<Family = DB::Family, Op = DB::Op, Digest = DB::Digest>
{
}

impl<DB, R> CompactDbResolver<DB> for R
where
    DB: Database,
    R: Resolver<Family = DB::Family, Op = DB::Op, Digest = DB::Digest>,
{
}

/// Database types that can be initialized directly from compact state.
pub trait Database: Sized + Send {
    type Family: Family;
    type Op: Encode + Send;
    type Config: Clone;
    type Digest: Digest;
    type Context: Storage + Clock + Metrics;
    type Hasher: Hasher<Digest = Self::Digest>;

    /// Build a database from authenticated state in memory.
    ///
    /// The caller has already validated `last_commit_proof` and the compact frontier against the
    /// requested target root and passes the derived validation artifacts with the state. This
    /// constructor must not durably persist anything; persistence happens only after the caller
    /// re-checks that `Self::root()` matches the target root.
    fn from_validated_state(
        context: Self::Context,
        config: Self::Config,
        state: ValidatedState<Self::Family, Self::Op, Self::Digest>,
    ) -> impl Future<Output = Result<Self, qmdb::Error<Self::Family>>> + Send;

    /// Return the inactivity floor if the operation is a commit.
    fn inactivity_floor(op: &Self::Op) -> Option<Location<Self::Family>>;

    /// Get the root digest for final verification.
    fn root(&self) -> Self::Digest;

    /// Persist the compact-initialized state once the caller has verified its root.
    fn persist_compact_state(
        self,
    ) -> impl Future<Output = Result<Self, qmdb::Error<Self::Family>>> + Send;
}

/// Configuration for compact synchronization into a compact-storage database.
pub struct Config<DB, R>
where
    DB: Database,
    R: CompactDbResolver<DB>,
{
    /// Runtime context for creating database components.
    pub context: DB::Context,
    /// Source resolver for fetching compact authenticated state.
    pub resolver: R,
    /// Sync target (root digest and total leaf count).
    pub target: Target<DB::Family, DB::Digest>,
    /// Database-specific configuration.
    pub db_config: DB::Config,
    /// Channel for receiving sync target updates. Updates must strictly advance the leaf count and
    /// change the root. They cancel an in-flight fetch, but never local persistence that has
    /// already started.
    pub update_rx: Option<mpsc::Receiver<Target<DB::Family, DB::Digest>>>,
    /// Channel that requests sync completion once the current target is reached.
    ///
    /// When `None`, sync completes as soon as the target is reached. Closing a configured channel
    /// before sending the finish signal returns [`EngineError::FinishChannelClosed`].
    pub finish_rx: Option<mpsc::Receiver<()>>,
    /// Channel used to notify an observer once the current target is reached.
    /// If the receiver is dropped, sync completes with the current database.
    pub reached_target_tx: Option<mpsc::Sender<Target<DB::Family, DB::Digest>>>,
}

/// Maximum queued target updates drained per scheduling tick.
const MAX_UPDATE_DRAIN_PER_TICK: usize = 32;

/// Drain and validate the target updates queued at entry without blocking, returning the newest.
async fn drain_latest_target<T, E>(
    update_rx: &mut mpsc::Receiver<T>,
    current: &T,
    mut validate: impl FnMut(&T, &T) -> Result<(), E>,
) -> Result<Option<T>, E> {
    let mut latest = None;
    for drained in 1..=update_rx.len() {
        match update_rx.try_recv() {
            Ok(update) => {
                validate(latest.as_ref().unwrap_or(current), &update)?;
                latest = Some(update);
                if drained.is_multiple_of(MAX_UPDATE_DRAIN_PER_TICK) {
                    reschedule().await;
                }
            }
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        }
    }
    Ok(latest)
}

/// Create/open a compact-storage database and initialize it from compact authenticated state.
///
/// Unlike streaming sync, compact sync jumps directly to `target.leaf_count`. This path
/// authenticates the final commit and frontier state for the target root rather than replaying a
/// retained operation range.
///
/// Targets received on `update_rx` supersede the current target. When `finish_rx` is `Some(...)`,
/// reaching a target parks sync until a finish signal or another target update arrives. Each
/// reached target is reported on `reached_target_tx`.
#[boxed]
pub async fn sync<DB, R>(
    config: Config<DB, R>,
) -> Result<DB, Error<DB::Family, R::Error, DB::Digest>>
where
    DB: Database,
    R: CompactDbResolver<DB>,
{
    let Config {
        context,
        resolver,
        mut target,
        db_config,
        mut update_rx,
        mut finish_rx,
        reached_target_tx,
    } = config;
    let metrics = super::Metrics::new(&context);
    target
        .validate()
        .map_err(|reason| Error::Engine(EngineError::InvalidCompactTarget(reason)))?;

    let mut attempt = 0u64;
    loop {
        // Prefer the newest queued target before starting an attempt.
        if let Some(update_rx) = update_rx.as_mut()
            && let Some(update) =
                drain_latest_target(update_rx, &target, validate_compact_target_update)
                    .await
                    .map_err(Error::Engine)?
        {
            target = update;
        }

        metrics.record_target(*target.leaf_count);

        attempt += 1;
        let update_future = update_rx.as_mut().map_or_else(
            || Either::Right(pending()),
            |update_rx| Either::Left(update_rx.recv()),
        );
        let finish_future = finish_rx.as_mut().map_or_else(
            || Either::Right(pending()),
            |finish_rx| Either::Left(finish_rx.recv()),
        );
        let validated_state = select! {
            finish = finish_future => match finish {
                Some(()) => {
                    finish_rx = None;
                    continue;
                }
                None => return Err(Error::Engine(EngineError::FinishChannelClosed)),
            },
            update = update_future => {
                let Some(update) = update else {
                    update_rx = None;
                    continue;
                };
                validate_compact_target_update(&target, &update).map_err(Error::Engine)?;
                target = update;
                continue;
            },
            validated = fetch_validated_state::<DB, R>(&resolver, &target) => validated?,
        };

        // Construction can replace an existing compact witness journal. Once it starts, let it
        // finish before observing another target update so cancellation cannot leave the journal
        // between its clear and persist steps.
        let db = persist_validated_state::<DB, R>(
            &context,
            attempt,
            &db_config,
            &target,
            validated_state,
        )
        .await?;
        metrics.record_synced(*target.leaf_count);

        // A target queued while the attempt ran supersedes the result.
        if let Some(update_rx) = update_rx.as_mut()
            && let Some(update) =
                drain_latest_target(update_rx, &target, validate_compact_target_update)
                    .await
                    .map_err(Error::Engine)?
        {
            target = update;
            continue;
        }

        if let Some(reached_target_tx) = reached_target_tx.as_ref()
            && reached_target_tx.send(target.clone()).await.is_err()
        {
            return Ok(db);
        }

        let Some(finish_rx) = finish_rx.as_mut() else {
            return Ok(db);
        };
        loop {
            let update_future = update_rx.as_mut().map_or_else(
                || Either::Right(pending()),
                |update_rx| Either::Left(update_rx.recv()),
            );
            select! {
                finish = finish_rx.recv() => match finish {
                    Some(()) => return Ok(db),
                    None => return Err(Error::Engine(EngineError::FinishChannelClosed)),
                },
                update = update_future => match update {
                    Some(update) => {
                        validate_compact_target_update(&target, &update)
                            .map_err(Error::Engine)?;
                        target = update;
                        break;
                    }
                    None => update_rx = None,
                },
            }
        }
    }
}

/// Validate compact state fetched for `target` without writing local storage.
async fn fetch_validated_state<DB, R>(
    resolver: &R,
    target: &Target<DB::Family, DB::Digest>,
) -> Result<CompactValidatedState<DB>, Error<DB::Family, R::Error, DB::Digest>>
where
    DB: Database,
    R: CompactDbResolver<DB>,
{
    // Compact sync has no request scheduler, so this loop is its retry boundary for bad peer
    // responses. Resolver errors remain terminal.
    loop {
        let FetchResult { state, callback } = resolver
            .get_compact_state(target.clone())
            .await
            .map_err(Error::Resolver)?;

        match validate_compact_state::<DB>(target, state) {
            Ok(state) => {
                if let Some(callback) = callback {
                    let _ = callback.send(true);
                }
                return Ok(state);
            }
            Err(err) => {
                if let Some(callback) = callback {
                    let _ = callback.send(false);
                }
                tracing::debug!(error = ?err, "compact state failed validation, will retry");
                reschedule().await;
            }
        }
    }
}

/// Construct and persist compact state already validated against `target`.
///
/// This phase must run to completion once started because persistence may replace an existing
/// compact witness journal in place.
async fn persist_validated_state<DB, R>(
    context: &DB::Context,
    attempt: u64,
    db_config: &DB::Config,
    target: &Target<DB::Family, DB::Digest>,
    validated_state: CompactValidatedState<DB>,
) -> Result<DB, Error<DB::Family, R::Error, DB::Digest>>
where
    DB: Database,
    R: CompactDbResolver<DB>,
{
    let db = DB::from_validated_state(
        context.child("compact").with_attribute("attempt", attempt),
        db_config.clone(),
        validated_state,
    )
    .await
    .map_err(Error::Database)?;
    let actual = db.root();
    if actual != target.root {
        return Err(Error::Engine(EngineError::RootMismatch {
            expected: target.root,
            actual,
        }));
    }
    db.persist_compact_state().await.map_err(Error::Database)
}

fn validate_compact_target_update<F: Family, D: Digest>(
    current: &Target<F, D>,
    update: &Target<F, D>,
) -> Result<(), EngineError<F, D>> {
    update
        .validate()
        .map_err(EngineError::InvalidCompactTarget)?;
    if update.leaf_count <= current.leaf_count {
        return Err(EngineError::InvalidCompactTarget(
            "target update must strictly advance leaf_count",
        ));
    }
    if update.root == current.root {
        return Err(EngineError::SyncTargetRootUnchanged);
    }
    Ok(())
}

/// Validate the peer-provided compact state before constructing local database storage.
fn validate_compact_state<DB>(
    target: &Target<DB::Family, DB::Digest>,
    state: State<DB::Family, DB::Op, DB::Digest>,
) -> CompactFrontierValidation<DB>
where
    DB: Database,
{
    if state.leaf_count != target.leaf_count {
        return Err(EngineError::UnexpectedLeafCount {
            expected: target.leaf_count,
            actual: state.leaf_count,
        });
    }

    let last_commit_loc = Location::new(*state.leaf_count - 1);
    if !verify_proof::<DB::Hasher, _, _>(
        &state.last_commit_proof,
        last_commit_loc,
        std::slice::from_ref(&state.last_commit_op),
        &target.root,
    ) {
        return Err(EngineError::InvalidProof);
    }

    validate_compact_frontier::<DB>(target, state)
}

/// Peer-provided compact state validated against a target.
type CompactValidatedState<DB> =
    ValidatedState<<DB as Database>::Family, <DB as Database>::Op, <DB as Database>::Digest>;

/// Result of validating a peer-provided compact frontier.
type CompactFrontierValidation<DB> = Result<
    CompactValidatedState<DB>,
    EngineError<<DB as Database>::Family, <DB as Database>::Digest>,
>;

/// Validate that a peer-provided compact frontier authenticates the requested target root.
fn validate_compact_frontier<DB>(
    target: &Target<DB::Family, DB::Digest>,
    state: State<DB::Family, DB::Op, DB::Digest>,
) -> CompactFrontierValidation<DB>
where
    DB: Database,
{
    // The final commit is the only operation carried in compact state. Its floor determines which
    // peaks are inactive when authenticating the compact frontier root.
    let last_commit_loc = Location::new(*state.leaf_count - 1);
    let Some(inactivity_floor_loc) = DB::inactivity_floor(&state.last_commit_op) else {
        return Err(EngineError::InvalidProof);
    };
    if inactivity_floor_loc > last_commit_loc {
        return Err(EngineError::InvalidProof);
    }

    // Rebuild a disposable Merkle view from the pinned frontier before opening any database
    // storage. Invalid pin counts or inactive peak layouts are treated as bad peer proofs.
    let mem = crate::merkle::mem::Mem::<DB::Family, DB::Digest>::init(crate::merkle::mem::Config {
        nodes: Vec::new(),
        pruning_boundary: state.leaf_count,
        pinned_nodes: state.pinned_nodes.clone(),
    })
    .map_err(|_| EngineError::InvalidProof)?;
    let hasher = qmdb::hasher::<DB::Hasher>();
    let inactive_peaks = DB::Family::inactive_peaks(
        DB::Family::location_to_position(state.leaf_count),
        inactivity_floor_loc,
    );
    let actual = mem
        .root(&hasher, inactive_peaks)
        .map_err(|_| EngineError::InvalidProof)?;
    if actual != target.root {
        return Err(EngineError::RootMismatch {
            expected: target.root,
            actual,
        });
    }

    Ok(ValidatedState {
        state,
        root: target.root,
    })
}

async fn fetch_state_from_full_source<F, Op, D, MH, Source, Hist, HistFut, Pins, PinsFut>(
    target: Target<F, D>,
    hasher: MH,
    source: Source,
    historical_proof: Hist,
    pinned_nodes_at: Pins,
) -> Result<State<F, Op, D>, ServeError<F, D>>
where
    F: Family,
    D: Digest,
    Op: Encode,
    MH: MerkleHasher<F, Digest = D>,
    Source: FnOnce() -> (D, Range<Location<F>>),
    Hist: FnOnce(Location<F>, Location<F>) -> HistFut,
    HistFut: Future<Output = Result<(Proof<F, D>, Vec<Op>), qmdb::Error<F>>>,
    Pins: FnOnce(Location<F>) -> PinsFut,
    PinsFut: Future<Output = Result<Vec<D>, qmdb::Error<F>>>,
{
    // Full sources do not cache a compact witness. Instead, derive the compact payload on demand
    // from the historical commit proof plus the frontier pins at the requested tree size.
    target.validate().map_err(ServeError::InvalidTarget)?;

    let (root, provable) = source();
    let current = Target::new(root, provable.end);
    let leaf_count = target.leaf_count;
    let last_commit_loc = Location::new(*leaf_count - 1);

    // A retained commit is servable only while its final leaf remains within the provable window.
    // Targets ahead of the tip or below that window are stale.
    if leaf_count > current.leaf_count || last_commit_loc < provable.start {
        return Err(ServeError::StaleTarget {
            requested: target,
            current,
        });
    }

    // The window check rules out pruning, so `HistoricalFloorPruned` here means `leaf_count` is
    // not a commit boundary.
    let (last_commit_proof, mut operations) =
        match historical_proof(leaf_count, last_commit_loc).await {
            Ok(state) => state,
            Err(qmdb::Error::HistoricalFloorPruned(_)) => {
                return Err(ServeError::DivergentTarget {
                    requested: target,
                    current,
                });
            }
            Err(err) => return Err(ServeError::Database(err)),
        };

    // Compact sync always authenticates exactly the final commit leaf.
    let last_commit_op =
        operations
            .pop()
            .ok_or(ServeError::Database(qmdb::Error::DataCorrupted(
                "missing last commit operation",
            )))?;

    // Answer only what the source can prove satisfies the request. The commit it just proved
    // authenticates exactly one root at `leaf_count`, so a target naming a different one
    // describes a history this source does not have. Checking before reading the pins keeps
    // the decline off the frontier read.
    if !last_commit_proof.verify_range_inclusion(
        &hasher,
        &[last_commit_op.encode()],
        last_commit_loc,
        &target.root,
    ) {
        return Err(ServeError::DivergentTarget {
            requested: target,
            current,
        });
    }

    let pinned_nodes = pinned_nodes_at(leaf_count)
        .await
        .map_err(ServeError::Database)?;
    Ok(State {
        leaf_count,
        pinned_nodes,
        last_commit_op,
        last_commit_proof,
    })
}

// Resolver impls for full keyless databases. These synthesize compact state by querying the
// historical tip proof and current frontier pins from the full source.
macro_rules! impl_compact_resolver_keyless {
    ($db:ident, $op:ident, $val_bound:ident) => {
        impl<F, E, V, H, S> Resolver for Arc<$db<F, E, V, H, S>>
        where
            F: Family,
            E: crate::Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                fetch_state_from_full_source(
                    target,
                    qmdb::hasher::<H>(),
                    || (self.root(), self.provable_bounds()),
                    |leaf_count, last_commit_loc| {
                        self.historical_proof(
                            leaf_count,
                            last_commit_loc,
                            NonZeroU64::new(1).unwrap(),
                        )
                    },
                    |leaf_count| self.pinned_nodes_at(leaf_count),
                )
                .await
                .map(Into::into)
            }
        }
        impl_compact_resolver_keyless!(@locked $db, $op, $val_bound, AsyncRwLock);
        impl_compact_resolver_keyless!(@locked $db, $op, $val_bound, TracedAsyncRwLock);
    };
    (@locked $db:ident, $op:ident, $val_bound:ident, $lock:ident) => {

        impl<F, E, V, H, S> Resolver for Arc<$lock<$db<F, E, V, H, S>>>
        where
            F: Family,
            E: crate::Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                fetch_state_from_full_source(
                    target,
                    qmdb::hasher::<H>(),
                    || (db.root(), db.provable_bounds()),
                    |leaf_count, last_commit_loc| {
                        db.historical_proof(
                            leaf_count,
                            last_commit_loc,
                            NonZeroU64::new(1).unwrap(),
                        )
                    },
                    |leaf_count| db.pinned_nodes_at(leaf_count),
                )
                .await
                .map(Into::into)
            }
        }

        impl<F, E, V, H, S> Resolver for Arc<$lock<Option<$db<F, E, V, H, S>>>>
        where
            F: Family,
            E: crate::Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(ServeError::MissingSource)?;
                fetch_state_from_full_source(
                    target,
                    qmdb::hasher::<H>(),
                    || (db.root(), db.provable_bounds()),
                    |leaf_count, last_commit_loc| {
                        db.historical_proof(
                            leaf_count,
                            last_commit_loc,
                            NonZeroU64::new(1).unwrap(),
                        )
                    },
                    |leaf_count| db.pinned_nodes_at(leaf_count),
                )
                .await
                .map(Into::into)
            }
        }
    };
}

// Resolver impls for full immutable databases. Same pattern as keyless, but with the extra key and
// translator parameters carried by immutable variants.
macro_rules! impl_compact_resolver_immutable {
    ($db:ident, $op:ident, $val_bound:ident, $key_bound:path) => {
        impl<F, E, K, V, H, T, S> Resolver for Arc<$db<F, E, K, V, H, T, S>>
        where
            F: Family,
            E: crate::Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                fetch_state_from_full_source(
                    target,
                    qmdb::hasher::<H>(),
                    || (self.root(), self.provable_bounds()),
                    |leaf_count, last_commit_loc| {
                        self.historical_proof(
                            leaf_count,
                            last_commit_loc,
                            NonZeroU64::new(1).unwrap(),
                        )
                    },
                    |leaf_count| self.pinned_nodes_at(leaf_count),
                )
                .await
                .map(Into::into)
            }
        }
        impl_compact_resolver_immutable!(@locked $db, $op, $val_bound, $key_bound, AsyncRwLock);
        impl_compact_resolver_immutable!(@locked $db, $op, $val_bound, $key_bound, TracedAsyncRwLock);
    };
    (@locked $db:ident, $op:ident, $val_bound:ident, $key_bound:path, $lock:ident) => {

        impl<F, E, K, V, H, T, S> Resolver for Arc<$lock<$db<F, E, K, V, H, T, S>>>
        where
            F: Family,
            E: crate::Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                fetch_state_from_full_source(
                    target,
                    qmdb::hasher::<H>(),
                    || (db.root(), db.provable_bounds()),
                    |leaf_count, last_commit_loc| {
                        db.historical_proof(
                            leaf_count,
                            last_commit_loc,
                            NonZeroU64::new(1).unwrap(),
                        )
                    },
                    |leaf_count| db.pinned_nodes_at(leaf_count),
                )
                .await
                .map(Into::into)
            }
        }

        impl<F, E, K, V, H, T, S> Resolver for Arc<$lock<Option<$db<F, E, K, V, H, T, S>>>>
        where
            F: Family,
            E: crate::Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(ServeError::MissingSource)?;
                fetch_state_from_full_source(
                    target,
                    qmdb::hasher::<H>(),
                    || (db.root(), db.provable_bounds()),
                    |leaf_count, last_commit_loc| {
                        db.historical_proof(
                            leaf_count,
                            last_commit_loc,
                            NonZeroU64::new(1).unwrap(),
                        )
                    },
                    |leaf_count| db.pinned_nodes_at(leaf_count),
                )
                .await
                .map(Into::into)
            }
        }
    };
}

// Resolver impls for compact keyless databases. These persist a witness journal, so serving
// reads a retained witness entry rather than reconstructing anything from history.
macro_rules! impl_compact_resolver_compact_keyless {
    ($db:ident, $op:ident) => {
        impl<F, E, V, H, C, S> Resolver for Arc<$db<F, E, V, H, C, S>>
        where
            F: Family,
            E: crate::Context,
            V: ValueEncoding + Send + Sync + 'static,
            H: Hasher,
            $op<F, V>: Encode + Read<Cfg = C>,
            C: Clone + Send + Sync + 'static,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                self.compact_state(target).await.map(Into::into)
            }
        }
        impl_compact_resolver_compact_keyless!(@locked $db, $op, AsyncRwLock);
        impl_compact_resolver_compact_keyless!(@locked $db, $op, TracedAsyncRwLock);
    };
    (@locked $db:ident, $op:ident, $lock:ident) => {

        impl<F, E, V, H, C, S> Resolver for Arc<$lock<$db<F, E, V, H, C, S>>>
        where
            F: Family,
            E: crate::Context,
            V: ValueEncoding + Send + Sync + 'static,
            H: Hasher,
            $op<F, V>: Encode + Read<Cfg = C>,
            C: Clone + Send + Sync + 'static,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                db.compact_state(target).await.map(Into::into)
            }
        }

        impl<F, E, V, H, C, S> Resolver for Arc<$lock<Option<$db<F, E, V, H, C, S>>>>
        where
            F: Family,
            E: crate::Context,
            V: ValueEncoding + Send + Sync + 'static,
            H: Hasher,
            $op<F, V>: Encode + Read<Cfg = C>,
            C: Clone + Send + Sync + 'static,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(ServeError::MissingSource)?;
                db.compact_state(target).await.map(Into::into)
            }
        }
    };
}

// Resolver impls for compact immutable databases. Like the keyless compact path, these read the
// persisted witness directly instead of rebuilding it from a full operation log.
macro_rules! impl_compact_resolver_compact_immutable {
    ($db:ident, $op:ident) => {
        impl<F, E, K, V, H, C, S> Resolver for Arc<$db<F, E, K, V, H, C, S>>
        where
            F: Family,
            E: crate::Context,
            K: Key,
            V: ValueEncoding + Send + Sync + 'static,
            H: Hasher,
            $op<F, K, V>: Encode + Read<Cfg = C>,
            C: Clone + Send + Sync + 'static,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                self.compact_state(target).await.map(Into::into)
            }
        }
        impl_compact_resolver_compact_immutable!(@locked $db, $op, AsyncRwLock);
        impl_compact_resolver_compact_immutable!(@locked $db, $op, TracedAsyncRwLock);
    };
    (@locked $db:ident, $op:ident, $lock:ident) => {

        impl<F, E, K, V, H, C, S> Resolver for Arc<$lock<$db<F, E, K, V, H, C, S>>>
        where
            F: Family,
            E: crate::Context,
            K: Key,
            V: ValueEncoding + Send + Sync + 'static,
            H: Hasher,
            $op<F, K, V>: Encode + Read<Cfg = C>,
            C: Clone + Send + Sync + 'static,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                db.compact_state(target).await.map(Into::into)
            }
        }

        impl<F, E, K, V, H, C, S> Resolver for Arc<$lock<Option<$db<F, E, K, V, H, C, S>>>>
        where
            F: Family,
            E: crate::Context,
            K: Key,
            V: ValueEncoding + Send + Sync + 'static,
            H: Hasher,
            $op<F, K, V>: Encode + Read<Cfg = C>,
            C: Clone + Send + Sync + 'static,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(ServeError::MissingSource)?;
                db.compact_state(target).await.map(Into::into)
            }
        }
    };
}

impl_compact_resolver_compact_keyless!(KeylessCompactDb, KeylessOp);
impl_compact_resolver_compact_immutable!(ImmutableCompactDb, ImmutableOp);

impl_compact_resolver_keyless!(KeylessFixedDb, KeylessFixedOp, FixedValue);
impl_compact_resolver_keyless!(KeylessVariableDb, KeylessVariableOp, VariableValue);
impl_compact_resolver_immutable!(ImmutableFixedDb, ImmutableFixedOp, FixedValue, Array);
impl_compact_resolver_immutable!(ImmutableVariableDb, ImmutableVariableOp, VariableValue, Key);

#[cfg(test)]
mod tests {
    use super::{
        Config, Database, FetchResult, Resolver, State, Target, drain_latest_target,
        validate_compact_target_update,
    };
    use crate::{
        merkle::{Location, mmr},
        qmdb,
    };
    use commonware_codec::{DecodeExt as _, Encode as _, RangeCfg};
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
    use commonware_parallel::Rayon;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{channel::mpsc, sync::AsyncRwLock};
    use std::{
        collections::VecDeque,
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    macro_rules! assert_resolver_variants {
        ($db:ty) => {
            assert_resolver::<Arc<$db>>();
            assert_resolver::<Arc<AsyncRwLock<$db>>>();
            assert_resolver::<Arc<AsyncRwLock<Option<$db>>>>();
        };
    }

    fn assert_resolver<R: super::Resolver>() {}

    struct TestDb {
        root: Digest,
        persists: Arc<AtomicUsize>,
        persistence_allowed: Arc<AtomicBool>,
    }

    #[derive(Clone)]
    struct TestDbConfig {
        constructions: Arc<AtomicUsize>,
        persists: Arc<AtomicUsize>,
        construction_allowed: Arc<AtomicBool>,
        persistence_allowed: Arc<AtomicBool>,
        root_override: Option<Digest>,
    }

    impl Database for TestDb {
        type Family = mmr::Family;
        type Op = u8;
        type Config = TestDbConfig;
        type Digest = Digest;
        type Context = deterministic::Context;
        type Hasher = Sha256;

        async fn from_validated_state(
            _context: Self::Context,
            config: Self::Config,
            state: super::ValidatedState<Self::Family, Self::Op, Self::Digest>,
        ) -> Result<Self, qmdb::Error<Self::Family>> {
            while !config.construction_allowed.load(Ordering::SeqCst) {
                commonware_runtime::reschedule().await;
            }
            config.constructions.fetch_add(1, Ordering::SeqCst);
            Ok(Self {
                root: config.root_override.unwrap_or(state.root),
                persists: config.persists,
                persistence_allowed: config.persistence_allowed,
            })
        }

        fn inactivity_floor(_op: &Self::Op) -> Option<Location<Self::Family>> {
            Some(Location::new(0))
        }

        fn root(&self) -> Self::Digest {
            self.root
        }

        async fn persist_compact_state(self) -> Result<Self, qmdb::Error<Self::Family>> {
            while !self.persistence_allowed.load(Ordering::SeqCst) {
                commonware_runtime::reschedule().await;
            }
            self.persists.fetch_add(1, Ordering::SeqCst);
            Ok(self)
        }
    }

    #[derive(Clone)]
    struct SequenceResolver {
        states: Arc<commonware_utils::sync::Mutex<VecDeque<FetchResult<mmr::Family, u8, Digest>>>>,
        fetches: Arc<AtomicUsize>,
    }

    impl Resolver for SequenceResolver {
        type Family = mmr::Family;
        type Digest = Digest;
        type Op = u8;
        type Error = Infallible;

        async fn get_compact_state(
            &self,
            _target: Target<Self::Family, Self::Digest>,
        ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .states
                .lock()
                .pop_front()
                .expect("missing compact fetch result"))
        }
    }

    #[derive(Clone)]
    struct PendingResolver;

    impl Resolver for PendingResolver {
        type Family = mmr::Family;
        type Digest = Digest;
        type Op = u8;
        type Error = Infallible;

        async fn get_compact_state(
            &self,
            _target: Target<Self::Family, Self::Digest>,
        ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
            std::future::pending().await
        }
    }

    fn valid_state_and_target_for(
        ops: &[u8],
    ) -> (State<mmr::Family, u8, Digest>, Target<mmr::Family, Digest>) {
        assert!(!ops.is_empty());
        let hasher = qmdb::hasher::<Sha256>();
        let mut merkle = crate::merkle::mem::Mem::<mmr::Family, Digest>::new();
        let batch = ops.iter().fold(merkle.new_batch(), |batch, op| {
            batch.add(&hasher, &op.encode())
        });
        let batch = batch.merkleize(&merkle, &hasher);
        merkle.apply_batch(&batch).unwrap();
        let root = merkle.root(&hasher, 0).unwrap();
        let leaf_count = Location::new(ops.len() as u64);
        let pinned_nodes = merkle
            .nodes_to_pin(leaf_count)
            .into_values()
            .collect::<Vec<_>>();
        let last_commit_loc = Location::new(*leaf_count - 1);
        let proof = merkle.proof(&hasher, last_commit_loc, 0).unwrap();
        (
            State {
                leaf_count,
                pinned_nodes,
                last_commit_op: *ops.last().unwrap(),
                last_commit_proof: proof,
            },
            Target::<mmr::Family, Digest> { root, leaf_count },
        )
    }

    fn valid_state_and_target() -> (State<mmr::Family, u8, Digest>, Target<mmr::Family, Digest>) {
        valid_state_and_target_for(&[1, 0])
    }

    fn test_db_config(constructions: Arc<AtomicUsize>, persists: Arc<AtomicUsize>) -> TestDbConfig {
        TestDbConfig {
            constructions,
            persists,
            construction_allowed: Arc::new(AtomicBool::new(true)),
            persistence_allowed: Arc::new(AtomicBool::new(true)),
            root_override: None,
        }
    }

    #[test]
    fn test_all_compact_qmdb_variants_implement_strategy_resolvers() {
        type KeylessFixedCompactDb = crate::qmdb::keyless::fixed::CompactDb<
            mmr::Family,
            deterministic::Context,
            Digest,
            commonware_cryptography::Sha256,
            Rayon,
        >;
        type KeylessVariableCompactDb = crate::qmdb::keyless::variable::CompactDb<
            mmr::Family,
            deterministic::Context,
            Vec<u8>,
            commonware_cryptography::Sha256,
            (RangeCfg<usize>, ()),
            Rayon,
        >;
        type ImmutableFixedCompactDb = crate::qmdb::immutable::fixed::CompactDb<
            mmr::Family,
            deterministic::Context,
            Digest,
            Digest,
            commonware_cryptography::Sha256,
            Rayon,
        >;
        type ImmutableVariableCompactDb = crate::qmdb::immutable::variable::CompactDb<
            mmr::Family,
            deterministic::Context,
            Digest,
            Vec<u8>,
            commonware_cryptography::Sha256,
            ((), (RangeCfg<usize>, ())),
            Rayon,
        >;

        assert_resolver_variants!(KeylessFixedCompactDb);
        assert_resolver_variants!(KeylessVariableCompactDb);
        assert_resolver_variants!(ImmutableFixedCompactDb);
        assert_resolver_variants!(ImmutableVariableCompactDb);
    }

    #[test]
    fn test_target_decode_rejects_zero_leaf_count() {
        let unused_root = commonware_cryptography::Sha256::hash(&[b"unused"]);
        let encoded = Target::<mmr::Family, Digest> {
            root: unused_root,
            leaf_count: crate::merkle::Location::new(0),
        }
        .encode();

        assert!(Target::<mmr::Family, Digest>::decode(encoded).is_err());
    }

    #[test]
    fn test_target_update_must_advance() {
        let (_, current) = valid_state_and_target_for(&[1, 0]);
        let (_, newer) = valid_state_and_target_for(&[1, 0, 2, 0]);
        assert!(validate_compact_target_update(&current, &newer).is_ok());

        let same_size = Target::new(newer.root, current.leaf_count);
        assert!(matches!(
            validate_compact_target_update(&current, &same_size),
            Err(super::EngineError::InvalidCompactTarget(_))
        ));

        let unchanged_root = Target::new(current.root, newer.leaf_count);
        assert!(matches!(
            validate_compact_target_update(&current, &unchanged_root),
            Err(super::EngineError::SyncTargetRootUnchanged)
        ));
    }

    #[test]
    fn test_target_drain_is_bounded_and_validates_each_update() {
        deterministic::Runner::default().start(|_| async move {
            struct RefillOnDrop {
                value: u8,
                refill: Option<commonware_utils::channel::mpsc::Sender<Self>>,
            }

            impl Drop for RefillOnDrop {
                fn drop(&mut self) {
                    let Some(sender) = self.refill.take() else {
                        return;
                    };
                    assert!(
                        sender
                            .try_send(Self {
                                value: 3,
                                refill: None,
                            })
                            .is_ok()
                    );
                }
            }

            let (sender, mut receiver) = commonware_utils::channel::mpsc::channel(2);
            sender
                .try_send(RefillOnDrop {
                    value: 1,
                    refill: Some(sender.clone()),
                })
                .unwrap_or_else(|_| panic!("first update should fit"));
            sender
                .try_send(RefillOnDrop {
                    value: 2,
                    refill: None,
                })
                .unwrap_or_else(|_| panic!("second update should fit"));

            let current = RefillOnDrop {
                value: 0,
                refill: None,
            };
            let latest =
                drain_latest_target(&mut receiver, &current, |_, _| Ok::<(), Infallible>(()))
                    .await
                    .unwrap()
                    .expect("snapshot should not be empty");
            assert_eq!(latest.value, 2);
            assert_eq!(
                receiver
                    .try_recv()
                    .expect("refill should remain queued")
                    .value,
                3
            );

            let (_, current) = valid_state_and_target_for(&[1, 0]);
            let (_, newest) = valid_state_and_target_for(&[1, 0, 2, 0, 3, 0]);
            let (_, rollback) = valid_state_and_target_for(&[1, 0, 2, 0]);
            let (sender, mut receiver) = mpsc::channel(2);
            sender.try_send(newest).unwrap();
            sender.try_send(rollback).unwrap();
            assert!(matches!(
                drain_latest_target(&mut receiver, &current, validate_compact_target_update,).await,
                Err(super::EngineError::InvalidCompactTarget(_))
            ));
        });
    }

    #[test]
    fn test_compact_sync_retries_divergent_frontier_without_feedback() {
        deterministic::Runner::default().start(|context| async move {
            let (good_state, target) = valid_state_and_target();
            let mut bad_state = good_state.clone();
            let divergent_pin = Sha256::hash(&[b"divergent pin"]);
            assert_ne!(bad_state.pinned_nodes[0], divergent_pin);
            bad_state.pinned_nodes[0] = divergent_pin;
            assert!(matches!(
                super::validate_compact_state::<TestDb>(&target, bad_state.clone()),
                Err(super::EngineError::RootMismatch { expected, actual })
                    if expected == target.root && actual != expected
            ));
            let (good_tx, good_rx) = commonware_utils::channel::oneshot::channel();
            let constructions = Arc::new(AtomicUsize::new(0));
            let persists = Arc::new(AtomicUsize::new(0));
            let fetches = Arc::new(AtomicUsize::new(0));

            let db = super::sync::<TestDb, _>(Config {
                context,
                resolver: SequenceResolver {
                    states: Arc::new(commonware_utils::sync::Mutex::new(VecDeque::from([
                        FetchResult {
                            state: bad_state,
                            callback: None,
                        },
                        FetchResult {
                            state: good_state,
                            callback: Some(good_tx),
                        },
                    ]))),
                    fetches: fetches.clone(),
                },
                target: target.clone(),
                db_config: test_db_config(constructions.clone(), persists.clone()),
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
            })
            .await
            .unwrap();

            assert!(good_rx.await.expect("valid feedback should arrive"));
            assert_eq!(fetches.load(Ordering::SeqCst), 2);
            assert_eq!(constructions.load(Ordering::SeqCst), 1);
            assert_eq!(persists.load(Ordering::SeqCst), 1);
            assert_eq!(db.root(), target.root);
        });
    }

    #[test]
    fn test_target_update_waits_for_in_progress_persist() {
        deterministic::Runner::default().start(|context| async move {
            let (first_state, first_target) = valid_state_and_target_for(&[1, 0]);
            let (second_state, second_target) = valid_state_and_target_for(&[1, 0, 2, 0]);
            let constructions = Arc::new(AtomicUsize::new(0));
            let persists = Arc::new(AtomicUsize::new(0));
            let (update_tx, update_rx) = mpsc::channel(1);
            let (first_feedback_tx, first_feedback_rx) =
                commonware_utils::channel::oneshot::channel();
            let db_config = test_db_config(constructions.clone(), persists.clone());
            db_config
                .construction_allowed
                .store(false, Ordering::SeqCst);
            db_config.persistence_allowed.store(false, Ordering::SeqCst);
            let construction_allowed = db_config.construction_allowed.clone();
            let persistence_allowed = db_config.persistence_allowed.clone();

            let sync = super::sync::<TestDb, _>(Config {
                context,
                resolver: SequenceResolver {
                    states: Arc::new(commonware_utils::sync::Mutex::new(VecDeque::from([
                        FetchResult {
                            state: first_state,
                            callback: Some(first_feedback_tx),
                        },
                        second_state.into(),
                    ]))),
                    fetches: Arc::new(AtomicUsize::new(0)),
                },
                target: first_target,
                db_config,
                update_rx: Some(update_rx),
                finish_rx: None,
                reached_target_tx: None,
            });
            let update = async {
                assert!(
                    first_feedback_rx
                        .await
                        .expect("validation feedback should arrive")
                );
                assert_eq!(
                    constructions.load(Ordering::SeqCst),
                    0,
                    "peer feedback must not wait for local construction"
                );
                construction_allowed.store(true, Ordering::SeqCst);
                while constructions.load(Ordering::SeqCst) == 0 {
                    commonware_runtime::reschedule().await;
                }
                update_tx
                    .send(second_target.clone())
                    .await
                    .expect("target update should be observed");
                for _ in 0..4 {
                    commonware_runtime::reschedule().await;
                }
                assert_eq!(
                    constructions.load(Ordering::SeqCst),
                    1,
                    "a target update must not replace construction during persistence",
                );
                assert_eq!(
                    persists.load(Ordering::SeqCst),
                    0,
                    "the first persistence operation should still be in progress",
                );
                persistence_allowed.store(true, Ordering::SeqCst);
            };

            let (result, ()) = futures::join!(sync, update);
            let db = result.unwrap();
            assert_eq!(db.root(), second_target.root);
            assert_eq!(constructions.load(Ordering::SeqCst), 2);
            assert_eq!(persists.load(Ordering::SeqCst), 2);
        });
    }

    #[test]
    fn test_reconstructed_root_mismatch_is_an_error() {
        deterministic::Runner::default().start(|context| async move {
            let (state, target) = valid_state_and_target();
            let actual = Digest::from([0xff; 32]);
            assert_ne!(actual, target.root);
            let persists = Arc::new(AtomicUsize::new(0));
            let mut db_config = test_db_config(Arc::new(AtomicUsize::new(0)), persists.clone());
            db_config.root_override = Some(actual);

            let result = super::sync::<TestDb, _>(Config {
                context,
                resolver: SequenceResolver {
                    states: Arc::new(commonware_utils::sync::Mutex::new(VecDeque::from([
                        state.into()
                    ]))),
                    fetches: Arc::new(AtomicUsize::new(0)),
                },
                target: target.clone(),
                db_config,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
            })
            .await;

            assert!(matches!(
                result,
                Err(qmdb::sync::Error::Engine(
                    qmdb::sync::EngineError::RootMismatch { expected, actual: got }
                )) if expected == target.root && got == actual
            ));
            assert_eq!(persists.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn test_invalid_ready_response_yields_to_target_update() {
        deterministic::Runner::default().start(|context| async move {
            let (mut invalid_state, first_target) = valid_state_and_target_for(&[1, 0]);
            invalid_state
                .pinned_nodes
                .push(Sha256::hash(&[b"extra pin"]));
            let (second_state, second_target) = valid_state_and_target_for(&[1, 0, 2, 0]);
            let fetches = Arc::new(AtomicUsize::new(0));
            let constructions = Arc::new(AtomicUsize::new(0));
            let (update_tx, update_rx) = mpsc::channel(1);

            let sync = super::sync::<TestDb, _>(Config {
                context,
                resolver: SequenceResolver {
                    states: Arc::new(commonware_utils::sync::Mutex::new(VecDeque::from([
                        invalid_state.into(),
                        second_state.into(),
                    ]))),
                    fetches: fetches.clone(),
                },
                target: first_target,
                db_config: test_db_config(constructions.clone(), Arc::new(AtomicUsize::new(0))),
                update_rx: Some(update_rx),
                finish_rx: None,
                reached_target_tx: None,
            });
            let update = async {
                while fetches.load(Ordering::SeqCst) == 0 {
                    commonware_runtime::reschedule().await;
                }
                update_tx
                    .send(second_target.clone())
                    .await
                    .expect("target update should be observed");
            };

            let (result, ()) = futures::join!(sync, update);
            assert_eq!(result.unwrap().root(), second_target.root);
            assert_eq!(constructions.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn test_finish_signal_is_required_after_update_channel_closes() {
        deterministic::Runner::default().start(|context| async move {
            let (state, target) = valid_state_and_target();
            let constructions = Arc::new(AtomicUsize::new(0));
            let persists = Arc::new(AtomicUsize::new(0));
            let (update_tx, update_rx) = mpsc::channel(1);
            let (finish_tx, finish_rx) = mpsc::channel(1);
            let (reached_tx, mut reached_rx) = mpsc::channel(1);

            let sync = super::sync::<TestDb, _>(Config {
                context,
                resolver: SequenceResolver {
                    states: Arc::new(commonware_utils::sync::Mutex::new(VecDeque::from([
                        state.into()
                    ]))),
                    fetches: Arc::new(AtomicUsize::new(0)),
                },
                target: target.clone(),
                db_config: test_db_config(constructions, persists),
                update_rx: Some(update_rx),
                finish_rx: Some(finish_rx),
                reached_target_tx: Some(reached_tx),
            });
            let finish = async {
                assert_eq!(reached_rx.recv().await, Some(target.clone()));
                drop(update_tx);
                commonware_runtime::reschedule().await;
                finish_tx
                    .send(())
                    .await
                    .expect("sync must keep waiting for the explicit finish signal");
            };

            let (result, ()) = futures::join!(sync, finish);
            assert_eq!(result.unwrap().root(), target.root);
        });
    }

    #[test]
    fn test_closed_finish_channel_is_an_error() {
        deterministic::Runner::default().start(|context| async move {
            let (_, target) = valid_state_and_target();
            let (finish_tx, finish_rx) = mpsc::channel(1);
            drop(finish_tx);

            let result = super::sync::<TestDb, _>(Config {
                context,
                resolver: PendingResolver,
                target,
                db_config: test_db_config(
                    Arc::new(AtomicUsize::new(0)),
                    Arc::new(AtomicUsize::new(0)),
                ),
                update_rx: None,
                finish_rx: Some(finish_rx),
                reached_target_tx: None,
            })
            .await;

            assert!(matches!(
                result,
                Err(qmdb::sync::Error::Engine(
                    qmdb::sync::EngineError::FinishChannelClosed
                ))
            ));
        });
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
