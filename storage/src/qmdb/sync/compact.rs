//! Compact sync for compact-storage qmdbs.
//!
//! Compact sync does not transfer or reconstruct the full historical operation log. Instead, the
//! source serves the minimum authenticated state needed to recreate the latest committed compact db
//! state:
//!
//! - the total committed leaf count,
//! - the frontier pins at that leaf count,
//! - the final commit operation, and
//! - a proof authenticating that final commit against the requested root.
//!
//! # What compact dbs store
//!
//! A compact db's only persistent state is its witness journal (`qmdb::compact::witness`), whose
//! entries each snapshot one committed state (commit operation, proof, and frontier pins).
//! The in-memory compact Merkle ([`crate::merkle::compact`]) is rebuilt from the journal tip on
//! reopen. Without the witness, a compact db could recover its root and continue appending, but
//! it could not serve compact sync to another node.
//!
//! # When compact state changes
//!
//! The servable compact state advances only on durable persistence:
//!
//! - [`sync`] verifies the final commit proof and compact frontier before database construction.
//! - [`Database::from_validated_state`] reconstructs the already-validated state without
//!   persisting it.
//! - Compact db-local commits append one witness entry during `sync`.
//! - `rewind` restores the frontier and the witness from the target journal entry.
//!
//! Unsynced in-memory mutations are therefore intentionally not servable: `target()` and
//! compact-state responses lag behind `apply_batch()` until the db's next sync.
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
    merkle::{Family, Location, Proof},
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
        sync::{
            EngineError, Error, ServeError,
            source::{Request, Response, Source, Validity},
        },
        verify_proof,
    },
    translator::Translator,
};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_macros::{boxed, select};
use commonware_parallel::Strategy;
use commonware_runtime::{Buf, BufMut, Clock, Metrics, Storage, Supervisor, reschedule};
use commonware_utils::{Array, NZU64, channel::mpsc};
use futures::future::{Either, pending};
use std::future::Future;

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

impl<F: Family, D: Digest> PartialOrd for Target<F, D> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: Family, D: Digest> Ord for Target<F, D> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.root
            .cmp(&other.root)
            .then_with(|| self.leaf_count.cmp(&other.leaf_count))
    }
}

impl<F: Family, D: Digest> std::hash::Hash for Target<F, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.root.hash(state);
        self.leaf_count.hash(state);
    }
}

impl<F: Family, D: Digest> std::fmt::Display for Target<F, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Target(root={}, leaf_count={})",
            self.root, self.leaf_count
        )
    }
}

impl<F: Family, D: Digest> commonware_utils::Span for Target<F, D> {}

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

/// Compact state that has been validated against a target root.
///
/// Only successful validation produces one: the frontier pins and the final commit have both
/// been authenticated against `root`, so construction can treat them as trusted.
#[derive(Clone, Debug)]
pub struct ValidatedState<F: Family, Op, D: Digest> {
    /// Total committed operations, taken from the proof rather than sent alongside it.
    pub(crate) leaf_count: Location<F>,
    /// Pinned Merkle nodes for the committed frontier.
    pub(crate) pinned_nodes: Vec<D>,
    /// The final commit operation at `leaf_count - 1`.
    pub(crate) last_commit_op: Op,
    /// Proof authenticating `last_commit_op` against `root`.
    pub(crate) last_commit_proof: Proof<F, D>,
    /// The target root this state was validated against.
    pub(crate) root: D,
}

impl<F: Family, Op, D: Digest> ValidatedState<F, Op, D> {
    /// Total committed operations.
    pub const fn leaf_count(&self) -> Location<F> {
        self.leaf_count
    }

    /// Pinned Merkle nodes for the committed frontier.
    pub fn pinned_nodes(&self) -> &[D] {
        &self.pinned_nodes
    }

    /// The final commit operation at `leaf_count - 1`.
    pub const fn last_commit_op(&self) -> &Op {
        &self.last_commit_op
    }

    /// Proof authenticating the final commit against `root`.
    pub const fn last_commit_proof(&self) -> &Proof<F, D> {
        &self.last_commit_proof
    }

    /// The target root this state was validated against.
    pub const fn root(&self) -> D {
        self.root
    }
}

/// A [`Source`] of compact state whose associated types match a specific [`Database`].
///
/// Blanket-impled for any matching `Source`, so callers never implement this directly. No
/// `'static`, unlike [`crate::qmdb::sync::SourceFor`]: compact sync reads one response through
/// a borrow.
pub trait SourceFor<DB: Database>:
    Source<Target<DB::Family, DB::Digest>, Family = DB::Family, Op = DB::Op, Digest = DB::Digest>
{
}

impl<DB, S> SourceFor<DB> for S
where
    DB: Database,
    S: Source<
            Target<DB::Family, DB::Digest>,
            Family = DB::Family,
            Op = DB::Op,
            Digest = DB::Digest,
        >,
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
pub struct Config<DB, S>
where
    DB: Database,
    S: SourceFor<DB>,
{
    /// Runtime context for creating database components.
    pub context: DB::Context,
    /// Serves compact authenticated state.
    pub source: S,
    /// Sync target (root digest and total leaf count).
    pub target: Target<DB::Family, DB::Digest>,
    /// Database-specific configuration.
    pub db_config: DB::Config,
    /// Channel for receiving sync target updates. Each update supersedes the
    /// current target, cancelling any in-flight attempt against it.
    pub update_rx: Option<mpsc::Receiver<Target<DB::Family, DB::Digest>>>,
    /// Channel that requests sync completion once the current target is reached.
    ///
    /// When `None`, sync completes as soon as the target is reached.
    pub finish_rx: Option<mpsc::Receiver<()>>,
    /// Channel used to notify an observer once the current target is reached.
    /// If the receiver is dropped, sync completes with the current database.
    pub reached_target_tx: Option<mpsc::Sender<Target<DB::Family, DB::Digest>>>,
}

/// Maximum queued target updates drained per scheduling tick.
const MAX_UPDATE_DRAIN_PER_TICK: usize = 32;

/// Drain all queued target updates without blocking, returning the newest.
async fn drain_latest_target<T>(update_rx: &mut mpsc::Receiver<T>) -> Option<T> {
    let mut latest = None;
    let mut drained = 0usize;
    loop {
        match update_rx.try_recv() {
            Ok(update) => {
                latest = Some(update);
                drained += 1;
                if drained.is_multiple_of(MAX_UPDATE_DRAIN_PER_TICK) {
                    reschedule().await;
                }
            }
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                return latest;
            }
        }
    }
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
pub async fn sync<DB, S>(
    config: Config<DB, S>,
) -> Result<DB, Error<DB::Family, S::Error, DB::Digest>>
where
    DB: Database,
    S: SourceFor<DB>,
{
    let Config {
        context,
        source,
        mut target,
        db_config,
        mut update_rx,
        mut finish_rx,
        reached_target_tx,
    } = config;
    let metrics = super::Metrics::new(&context);
    let mut attempt = 0u64;
    loop {
        // Prefer the newest queued target before starting an attempt.
        if let Some(update_rx) = update_rx.as_mut()
            && let Some(update) = drain_latest_target(update_rx).await
        {
            target = update;
        }
        target
            .validate()
            .map_err(|reason| Error::Engine(EngineError::InvalidCompactTarget(reason)))?;
        metrics.record_target(*target.leaf_count);

        attempt += 1;
        let update_future = update_rx.as_mut().map_or_else(
            || Either::Right(pending()),
            |update_rx| Either::Left(update_rx.recv()),
        );
        let db = select! {
            update = update_future => {
                let Some(update) = update else {
                    update_rx = None;
                    continue;
                };
                target = update;
                continue;
            },
            db = attempt_sync(&context, attempt, &source, &db_config, &target) => db?,
        };
        metrics.record_synced(*target.leaf_count);

        // A target queued while the attempt ran supersedes the result.
        if let Some(update_rx) = update_rx.as_mut()
            && let Some(update) = drain_latest_target(update_rx).await
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
        let Some(update_rx) = update_rx.as_mut() else {
            return Ok(db);
        };
        select! {
            _ = finish_rx.recv() => return Ok(db),
            update = update_rx.recv() => {
                let Some(update) = update else {
                    return Ok(db);
                };
                target = update;
            },
        }
    }
}

/// Run one compact sync attempt against `target`.
///
/// Verification order:
/// 1. Fetch the proposed compact state for `target`.
/// 2. Verify the final commit proof against `target.root`.
/// 3. Rebuild the compact frontier in memory and compare its root against `target.root`.
/// 4. Build the compact db from that already-validated state.
/// 5. Assert the db root still matches and persist the state.
///
/// A failure before the final persist leaves on-disk state untouched.
async fn attempt_sync<DB, S>(
    context: &DB::Context,
    attempt: u64,
    source: &S,
    db_config: &DB::Config,
    target: &Target<DB::Family, DB::Digest>,
) -> Result<DB, Error<DB::Family, S::Error, DB::Digest>>
where
    DB: Database,
    S: SourceFor<DB>,
{
    // Compact sync has no request scheduler, so this loop is its retry boundary for bad peer
    // responses. Source errors and local construction failures remain terminal.
    loop {
        let (response, validity_tx) = source
            .serve(target.clone())
            .await
            .map_err(Error::Source)?;

        // Validation failures describe a bad compact response. Reject it if the source supplied
        // feedback, then fetch another candidate.
        let validated_state = match validate_compact_state::<DB>(target, response) {
            Ok(state) => state,
            Err(err) => {
                if let Some(validity_tx) = validity_tx {
                    let _ = validity_tx.send(false);
                }
                tracing::debug!(error = ?err, "compact state failed validation, will retry");
                continue;
            }
        };

        // The peer response has already authenticated the final commit and frontier. From here,
        // construction should only fail for local database/storage reasons; a root mismatch is a
        // local defect, terminal and never persisted, and no fault of the peer.
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

        if let Some(validity_tx) = validity_tx {
            let _ = validity_tx.send(true);
        }
        let db = db.persist_compact_state().await?;
        return Ok(db);
    }
}

/// Validate the peer-provided compact state before constructing local database storage.
/// Whether a response has the shape and commit proof of compact state for `target`.
///
/// The cheap prefix of full validation: exactly one operation, the pins at the tip, a proof
/// sized to the target, and the commit proof verifying against the target root. It does not
/// verify the frontier pins, which requires rebuilding the tip; only [`ValidatedState`]
/// certifies those. Use it to reject malformed responses before fanning them out.
pub fn admissible<H, F, Op>(
    target: &Target<F, H::Digest>,
    response: &Response<F, Op, H::Digest>,
) -> bool
where
    H: Hasher,
    F: Family,
    Op: Encode,
{
    let Some(last_commit_loc) = (*target.leaf_count).checked_sub(1) else {
        return false;
    };
    let [last_commit_op] = &response.operations[..] else {
        return false;
    };
    let Some(pinned_nodes) = &response.pinned_nodes else {
        return false;
    };
    if response.proof.leaves != target.leaf_count
        || pinned_nodes.len() != F::nodes_to_pin(target.leaf_count).count()
    {
        return false;
    }
    verify_proof::<H, _, _>(
        &response.proof,
        Location::new(last_commit_loc),
        std::slice::from_ref(last_commit_op),
        &target.root,
    )
}

pub(crate) fn validate_compact_state<DB>(
    target: &Target<DB::Family, DB::Digest>,
    response: Response<DB::Family, DB::Op, DB::Digest>,
) -> CompactFrontierValidation<DB>
where
    DB: Database,
{
    if !admissible::<DB::Hasher, _, _>(target, &response) {
        return Err(EngineError::InvalidProof);
    }
    let Response {
        proof: last_commit_proof,
        mut operations,
        pinned_nodes,
    } = response;
    let last_commit_op = operations.pop().expect("admissible checked length");
    let pinned_nodes = pinned_nodes.expect("admissible checked pins");
    validate_compact_frontier::<DB>(target, pinned_nodes, last_commit_op, last_commit_proof)
}

/// Result of validating a peer-provided compact frontier.
type CompactFrontierValidation<DB> = Result<
    ValidatedState<<DB as Database>::Family, <DB as Database>::Op, <DB as Database>::Digest>,
    EngineError<<DB as Database>::Family, <DB as Database>::Digest>,
>;

/// Validate that a peer-provided compact frontier authenticates the requested target root.
fn validate_compact_frontier<DB>(
    target: &Target<DB::Family, DB::Digest>,
    pinned_nodes: Vec<DB::Digest>,
    last_commit_op: DB::Op,
    last_commit_proof: Proof<DB::Family, DB::Digest>,
) -> CompactFrontierValidation<DB>
where
    DB: Database,
{
    let leaf_count = target.leaf_count;
    // The final commit is the only operation carried in compact state. Its floor determines which
    // peaks are inactive when authenticating the compact frontier root.
    let last_commit_loc = Location::new(*leaf_count - 1);
    let Some(inactivity_floor_loc) = DB::inactivity_floor(&last_commit_op) else {
        return Err(EngineError::InvalidProof);
    };
    if inactivity_floor_loc > last_commit_loc {
        return Err(EngineError::InvalidProof);
    }

    // Rebuild a disposable Merkle view from the pinned frontier before opening any database
    // storage. Invalid pin counts or inactive peak layouts are treated as bad peer proofs.
    let mem = crate::merkle::mem::Mem::<DB::Family, DB::Digest>::init(crate::merkle::mem::Config {
        nodes: Vec::new(),
        pruning_boundary: leaf_count,
        pinned_nodes: pinned_nodes.clone(),
    })
    .map_err(|_| EngineError::InvalidProof)?;
    let hasher = qmdb::hasher::<DB::Hasher>();
    let inactive_peaks = DB::Family::inactive_peaks(
        DB::Family::location_to_position(leaf_count),
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
        leaf_count,
        pinned_nodes,
        last_commit_op,
        last_commit_proof,
        root: target.root,
    })
}

/// Derive compact state from a source that still holds its operation log.
///
/// A full database has no persisted witness, so its compact state is synthesized on demand.
/// This is the same request the operation-log path makes, at the degenerate range: prove the
/// final commit, and pin at the tip, because a compact client retains no operations at all.
async fn compact_state_from_log<S, F, D>(
    source: &S,
    current: Target<F, D>,
    target: Target<F, D>,
) -> Result<Response<F, S::Op, D>, ServeError<F, D>>
where
    F: Family,
    D: Digest,
    S: crate::qmdb::sync::Source<Request<F>, Family = F, Digest = D, Error = qmdb::Error<F>>,
{
    target.validate().map_err(ServeError::InvalidTarget)?;
    if target.root != current.root || target.leaf_count != current.leaf_count {
        return Err(ServeError::StaleTarget {
            requested: target,
            current,
        });
    }

    let leaf_count = target.leaf_count;
    let last_commit_loc = Location::new(*leaf_count - 1);
    let request = Request::new(leaf_count, last_commit_loc, NZU64!(1))
        .retaining_from(leaf_count);
    let (response, _validity_tx) = source.serve(request).await?;

    Ok(response)
}

/// Implement [`Source<Target>`] for a database.
///
/// A `full` database has no persisted witness, so its state is synthesized on demand from
/// the current tip commit plus the frontier pins at the requested tree size; a `compact`
/// database reads its witness directly. The `keyless` arms exist because those databases
/// have no key or translator parameter.
macro_rules! impl_compact_source {
    (full $db:ident, $op:ident, $val_bound:ident, $key_bound:path) => {
        impl<F, E, K, V, H, T, S> Source<Target<F, H::Digest>> for $db<F, E, K, V, H, T, S>
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

            async fn serve(
                &self,
                target: Target<F, H::Digest>,
            ) -> Result<(Response<F, Self::Op, H::Digest>, Validity), Self::Error> {
                let current = Target::new(self.root(), self.bounds().end);
                Ok((compact_state_from_log(self, current, target).await?, None))
            }
        }
    };
    (full keyless $db:ident, $op:ident, $val_bound:ident) => {
        impl<F, E, V, H, S> Source<Target<F, H::Digest>> for $db<F, E, V, H, S>
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

            async fn serve(
                &self,
                target: Target<F, H::Digest>,
            ) -> Result<(Response<F, Self::Op, H::Digest>, Validity), Self::Error> {
                let current = Target::new(self.root(), self.bounds().end);
                Ok((compact_state_from_log(self, current, target).await?, None))
            }
        }
    };
    (compact $db:ident, $op:ident) => {
        impl<F, E, K, V, H, C, S> Source<Target<F, H::Digest>> for $db<F, E, K, V, H, C, S>
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

            async fn serve(
                &self,
                target: Target<F, H::Digest>,
            ) -> Result<(Response<F, Self::Op, H::Digest>, Validity), Self::Error> {
                Ok((self.compact_state(target)?, None))
            }
        }
    };
    (compact keyless $db:ident, $op:ident) => {
        impl<F, E, V, H, C, S> Source<Target<F, H::Digest>> for $db<F, E, V, H, C, S>
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

            async fn serve(
                &self,
                target: Target<F, H::Digest>,
            ) -> Result<(Response<F, Self::Op, H::Digest>, Validity), Self::Error> {
                Ok((self.compact_state(target)?, None))
            }
        }
    };
}

impl_compact_source!(compact keyless KeylessCompactDb, KeylessOp);
impl_compact_source!(compact ImmutableCompactDb, ImmutableOp);
impl_compact_source!(full keyless KeylessFixedDb, KeylessFixedOp, FixedValue);
impl_compact_source!(full keyless KeylessVariableDb, KeylessVariableOp, VariableValue);
impl_compact_source!(full ImmutableFixedDb, ImmutableFixedOp, FixedValue, Array);
impl_compact_source!(full ImmutableVariableDb, ImmutableVariableOp, VariableValue, Key);

#[cfg(test)]
mod tests {
    use super::{Config, Database, Response, Source, Target, Validity};
    use crate::{
        merkle::{Location, mmr},
        qmdb,
    };
    use commonware_codec::{DecodeExt as _, Encode as _, RangeCfg};
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
    use commonware_parallel::Rayon;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::sync::{AsyncRwLock, TracedAsyncRwLock};
    use std::{
        collections::VecDeque,
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    macro_rules! assert_source_variants {
        ($db:ty) => {
            assert_serves::<Arc<$db>>();
            assert_serves::<Arc<AsyncRwLock<$db>>>();
            assert_serves::<Arc<AsyncRwLock<Option<$db>>>>();
            assert_serves::<Arc<TracedAsyncRwLock<$db>>>();
            assert_serves::<Arc<TracedAsyncRwLock<Option<$db>>>>();
        };
    }

    fn assert_serves<S: Source<Target<mmr::Family, Digest>>>() {}

    struct TestDb {
        root: Digest,
    }

    impl Database for TestDb {
        type Family = mmr::Family;
        type Op = u8;
        type Config = (Digest, Arc<AtomicUsize>);
        type Digest = Digest;
        type Context = deterministic::Context;
        type Hasher = Sha256;

        async fn from_validated_state(
            _context: Self::Context,
            (root, constructions): Self::Config,
            _state: super::ValidatedState<Self::Family, Self::Op, Self::Digest>,
        ) -> Result<Self, qmdb::Error<Self::Family>> {
            constructions.fetch_add(1, Ordering::SeqCst);
            Ok(Self { root })
        }

        fn inactivity_floor(_op: &Self::Op) -> Option<Location<Self::Family>> {
            Some(Location::new(0))
        }

        fn root(&self) -> Self::Digest {
            self.root
        }

        async fn persist_compact_state(self) -> Result<Self, qmdb::Error<Self::Family>> {
            Ok(self)
        }
    }

    type CompactResponse = (Response<mmr::Family, u8, Digest>, Validity);

    /// Serves a canned sequence of responses, one per call, so tests can drive the retry loop.
    struct SequenceSource {
        responses: Arc<commonware_utils::sync::Mutex<VecDeque<CompactResponse>>>,
    }

    impl Source<Target<mmr::Family, Digest>> for SequenceSource {
        type Family = mmr::Family;
        type Digest = Digest;
        type Op = u8;
        type Error = Infallible;

        async fn serve(
            &self,
            _target: Target<Self::Family, Self::Digest>,
        ) -> Result<CompactResponse, Self::Error> {
            Ok(self
                .responses
                .lock()
                .pop_front()
                .expect("missing compact response"))
        }
    }

    fn valid_state_and_target() -> (
        Response<mmr::Family, u8, Digest>,
        Target<mmr::Family, Digest>,
    ) {
        let hasher = qmdb::hasher::<Sha256>();
        let mut merkle = crate::merkle::mem::Mem::<mmr::Family, Digest>::new();
        let op = 0u8;
        let first_op = 1u8;
        let batch = merkle
            .new_batch()
            .add(&hasher, &first_op.encode())
            .add(&hasher, &op.encode());
        let batch = batch.merkleize(&merkle, &hasher);
        merkle.apply_batch(&batch).unwrap();
        let root = merkle.root(&hasher, 0).unwrap();
        let leaf_count = Location::new(2);
        let pinned_nodes = merkle
            .nodes_to_pin(leaf_count)
            .into_values()
            .collect::<Vec<_>>();
        let proof = merkle.proof(&hasher, Location::new(1), 0).unwrap();
        (
            Response::new(proof, vec![op], Some(pinned_nodes)),
            Target::<mmr::Family, Digest> { root, leaf_count },
        )
    }

    #[test]
    fn test_all_compact_qmdb_variants_implement_source() {
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

        assert_source_variants!(KeylessFixedCompactDb);
        assert_source_variants!(KeylessVariableCompactDb);
        assert_source_variants!(ImmutableFixedCompactDb);
        assert_source_variants!(ImmutableVariableCompactDb);
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
    fn test_compact_sync_retries_invalid_state_without_feedback() {
        deterministic::Runner::default().start(|context| async move {
            let (good_state, target) = valid_state_and_target();
            let mut bad_state = good_state.clone();
            bad_state
                .pinned_nodes
                .as_mut()
                .expect("valid state carries pins")
                .push(Sha256::hash(&[b"extra pin"]));
            let (good_tx, good_rx) = commonware_utils::channel::oneshot::channel();
            let constructions = Arc::new(AtomicUsize::new(0));

            let db = super::sync::<TestDb, _>(Config {
                context,
                source: SequenceSource {
                    responses: Arc::new(commonware_utils::sync::Mutex::new(VecDeque::from([
                        (bad_state, None),
                        (good_state, Some(good_tx)),
                    ]))),
                },
                target: target.clone(),
                db_config: (target.root, constructions.clone()),
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
            })
            .await
            .unwrap();

            assert!(good_rx.await.expect("valid feedback should arrive"));
            assert_eq!(constructions.load(Ordering::SeqCst), 1);
            assert_eq!(db.root(), target.root);
        });
    }

    #[test]
    fn test_compact_sync_reconstruction_mismatch_is_terminal() {
        deterministic::Runner::default().start(|context| async move {
            let (state, target) = valid_state_and_target();
            let (validity_tx, validity_rx) = commonware_utils::channel::oneshot::channel();
            let constructions = Arc::new(AtomicUsize::new(0));
            let wrong_root = Sha256::hash(&[b"wrong root"]);

            // The database reconstructs to a root other than the validated target: a local
            // defect, so sync must fail without retrying or judging the peer.
            let result = super::sync::<TestDb, _>(Config {
                context,
                resolver: SequenceSource {
                    responses: Arc::new(commonware_utils::sync::Mutex::new(VecDeque::from([(
                        state,
                        Some(validity_tx),
                    )]))),
                },
                target: target.clone(),
                db_config: (wrong_root, constructions.clone()),
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
            })
            .await;

            match result {
                Err(super::Error::Engine(super::EngineError::RootMismatch {
                    expected,
                    actual,
                })) => {
                    assert_eq!(expected, target.root);
                    assert_eq!(actual, wrong_root);
                }
                Err(other) => panic!("expected RootMismatch, got {other:?}"),
                Ok(_) => panic!("expected RootMismatch, sync succeeded"),
            }
            assert_eq!(constructions.load(Ordering::SeqCst), 1);
            assert!(validity_rx.await.is_err(), "peer must not be judged");
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
