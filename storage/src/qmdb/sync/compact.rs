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
//! A compact db persists two pieces of state that must always describe the same committed tip:
//!
//! 1. the compact Merkle frontier (persisted by [`crate::merkle::compact`]), and
//! 2. a db-level witness for the last commit (persisted by `qmdb::compact_witness`).
//!
//! The witness exists because only the db layer knows how to encode and decode the typed commit
//! operation. Without it, a compact db could recover its root and continue appending, but it could
//! not serve compact sync to another node.
//!
//! # When compact state changes
//!
//! The servable compact state advances only on durable persistence:
//!
//! - [`Database::from_compact_state`] reconstructs candidate state in memory only.
//! - [`sync`] verifies the final commit proof first, then asks the db to rebuild its own root from
//!   the supplied frontier, and only then persists the result.
//! - Compact db-local commits persist the frontier and witness together during `sync`/`commit`.
//! - `rewind` restores both the frontier and the witness from the previous slot together.
//!
//! Unsynced in-memory mutations are therefore intentionally not servable: `current_target()` and
//! compact-state responses lag behind `apply_batch()` until the next durable sync.
//!
//! # Safety and invariants
//!
//! The compact path relies on these invariants:
//!
//! - the served commit proof must authenticate the final commit at `leaf_count - 1`,
//! - the frontier pins and witness must move together in the same ping-pong slot,
//! - reopen and rewind must re-verify the persisted witness against the root restored from that
//!   slot, and
//! - reconstructed state must not be persisted until the db recomputes the requested root locally.
//!
//! If those invariants are violated by missing or corrupted persisted data, compact db reopen fails
//! with `DataCorrupted` rather than silently serving or restoring mismatched state.

use crate::{
    merkle::{hasher::Standard as StandardHasher, Family, Location, Proof},
    qmdb::{
        self,
        any::{value::ValueEncoding, FixedValue, VariableValue},
        immutable::{
            fixed::{Db as ImmutableFixedDb, Operation as ImmutableFixedOp},
            variable::{Db as ImmutableVariableDb, Operation as ImmutableVariableOp},
            CompactDb as ImmutableCompactDb, Operation as ImmutableOp,
        },
        keyless::{
            fixed::{Db as KeylessFixedDb, Operation as KeylessFixedOp},
            variable::{Db as KeylessVariableDb, Operation as KeylessVariableOp},
            CompactDb as KeylessCompactDb, Operation as KeylessOp,
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
use commonware_runtime::{Buf, BufMut, Clock, Metrics, Storage};
use commonware_utils::{sync::AsyncRwLock, Array};
use std::{future::Future, num::NonZeroU64, sync::Arc};

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
    /// The caller requested a target different from the source's current servable state.
    #[error("stale compact target - requested {requested:?}, current {current:?}")]
    StaleTarget {
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
    ) -> impl Future<Output = Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error>> + Send + 'a;
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
    /// The caller has already verified `last_commit_proof` against the requested target root, but
    /// the database has not yet authenticated `pinned_nodes` by recomputing its own root. This
    /// constructor must not durably persist anything; persistence happens only after the caller
    /// verifies that `Self::root()` matches the target root.
    fn from_compact_state(
        context: Self::Context,
        config: Self::Config,
        state: State<Self::Family, Self::Op, Self::Digest>,
    ) -> impl Future<Output = Result<Self, qmdb::Error<Self::Family>>> + Send;

    /// Get the root digest for final verification.
    fn root(&self) -> Self::Digest;

    /// Persist the compact-initialized state once the caller has verified its root.
    fn persist_compact_state(
        &self,
    ) -> impl Future<Output = Result<(), qmdb::Error<Self::Family>>> + Send;
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
}

/// Create/open a compact-storage database and initialize it from compact authenticated state.
///
/// Unlike streaming sync, compact sync jumps directly to `target.leaf_count`. This path
/// authenticates the final commit and frontier state for the target root rather than replaying a
/// retained operation range.
///
/// Verification order:
/// 1. Fetch the proposed compact state for `target`.
/// 2. Verify the final commit proof against `target.root`.
/// 3. Rebuild the compact db in memory from the proposed frontier.
/// 4. Compare the rebuilt db root against `target.root`.
/// 5. Persist the state only after both checks succeed.
///
/// Any failure leaves the local compact db unopened or unchanged on disk.
pub async fn sync<DB, R>(
    config: Config<DB, R>,
) -> Result<DB, Error<DB::Family, R::Error, DB::Digest>>
where
    DB: Database,
    R: CompactDbResolver<DB>,
{
    let target = config.target;
    target
        .validate()
        .map_err(|reason| Error::Engine(EngineError::InvalidCompactTarget(reason)))?;
    let state = config
        .resolver
        .get_compact_state(target.clone())
        .await
        .map_err(Error::Resolver)?;

    if state.leaf_count != target.leaf_count {
        return Err(Error::Engine(EngineError::UnexpectedLeafCount {
            expected: target.leaf_count,
            actual: state.leaf_count,
        }));
    }

    let hasher = StandardHasher::<DB::Hasher>::new();
    let last_commit_loc = Location::new(*state.leaf_count - 1);
    if !verify_proof(
        &hasher,
        &state.last_commit_proof,
        last_commit_loc,
        std::slice::from_ref(&state.last_commit_op),
        &target.root,
    ) {
        return Err(Error::Engine(EngineError::InvalidProof));
    }

    let db = DB::from_compact_state(config.context, config.db_config, state).await?;
    let actual = db.root();
    if actual != target.root {
        return Err(Error::Engine(EngineError::RootMismatch {
            expected: target.root,
            actual,
        }));
    }
    db.persist_compact_state().await?;
    Ok(db)
}

async fn fetch_state_from_full_source<F, Op, D, Current, CurrentFut, Hist, HistFut, Pins, PinsFut>(
    target: Target<F, D>,
    current_target: Current,
    historical_proof: Hist,
    pinned_nodes_at: Pins,
) -> Result<State<F, Op, D>, ServeError<F, D>>
where
    F: Family,
    D: Digest,
    Current: FnOnce() -> CurrentFut,
    CurrentFut: Future<Output = Target<F, D>>,
    Hist: FnOnce(Location<F>, Location<F>) -> HistFut,
    HistFut: Future<Output = Result<(Proof<F, D>, Vec<Op>), qmdb::Error<F>>>,
    Pins: FnOnce(Location<F>) -> PinsFut,
    PinsFut: Future<Output = Result<Vec<D>, qmdb::Error<F>>>,
{
    // Full sources do not cache a compact witness. Instead, derive the compact payload on demand
    // from the current tip commit plus the frontier pins at the requested tree size.
    target.validate().map_err(ServeError::InvalidTarget)?;
    let current = current_target().await;
    if target.root != current.root || target.leaf_count != current.leaf_count {
        return Err(ServeError::StaleTarget {
            requested: target,
            current,
        });
    }
    let leaf_count = target.leaf_count;
    let last_commit_loc = Location::new(*leaf_count - 1);
    let (last_commit_proof, mut operations) = historical_proof(leaf_count, last_commit_loc)
        .await
        .map_err(ServeError::Database)?;
    // Compact sync always authenticates exactly the final commit leaf.
    let last_commit_op =
        operations
            .pop()
            .ok_or(ServeError::Database(qmdb::Error::DataCorrupted(
                "missing last commit operation",
            )))?;
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
        impl<F, E, V, H> Resolver for Arc<$db<F, E, V, H>>
        where
            F: Family,
            E: crate::Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                fetch_state_from_full_source(
                    target,
                    || async {
                        Target {
                            root: self.root(),
                            leaf_count: self.bounds().await.end,
                        }
                    },
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
            }
        }

        impl<F, E, V, H> Resolver for Arc<AsyncRwLock<$db<F, E, V, H>>>
        where
            F: Family,
            E: crate::Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                fetch_state_from_full_source(
                    target,
                    || async {
                        Target {
                            root: db.root(),
                            leaf_count: db.bounds().await.end,
                        }
                    },
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
            }
        }

        impl<F, E, V, H> Resolver for Arc<AsyncRwLock<Option<$db<F, E, V, H>>>>
        where
            F: Family,
            E: crate::Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(ServeError::MissingSource)?;
                fetch_state_from_full_source(
                    target,
                    || async {
                        Target {
                            root: db.root(),
                            leaf_count: db.bounds().await.end,
                        }
                    },
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
            }
        }
    };
}

// Resolver impls for full immutable databases. Same pattern as keyless, but with the extra key and
// translator parameters carried by immutable variants.
macro_rules! impl_compact_resolver_immutable {
    ($db:ident, $op:ident, $val_bound:ident, $key_bound:path) => {
        impl<F, E, K, V, H, T> Resolver for Arc<$db<F, E, K, V, H, T>>
        where
            F: Family,
            E: crate::Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                fetch_state_from_full_source(
                    target,
                    || async {
                        Target {
                            root: self.root(),
                            leaf_count: self.bounds().await.end,
                        }
                    },
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
            }
        }

        impl<F, E, K, V, H, T> Resolver for Arc<AsyncRwLock<$db<F, E, K, V, H, T>>>
        where
            F: Family,
            E: crate::Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                fetch_state_from_full_source(
                    target,
                    || async {
                        Target {
                            root: db.root(),
                            leaf_count: db.bounds().await.end,
                        }
                    },
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
            }
        }

        impl<F, E, K, V, H, T> Resolver for Arc<AsyncRwLock<Option<$db<F, E, K, V, H, T>>>>
        where
            F: Family,
            E: crate::Context,
            K: $key_bound,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(ServeError::MissingSource)?;
                fetch_state_from_full_source(
                    target,
                    || async {
                        Target {
                            root: db.root(),
                            leaf_count: db.bounds().await.end,
                        }
                    },
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
            }
        }
    };
}

// Resolver impls for compact keyless databases. These already persist a compact witness, so serving
// is just a validated `compact_state()` read rather than reconstructing anything from history.
macro_rules! impl_compact_resolver_compact_keyless {
    ($db:ident, $op:ident) => {
        impl<F, E, V, H, C> Resolver for Arc<$db<F, E, V, H, C>>
        where
            F: Family,
            E: crate::Context,
            V: ValueEncoding + Send + Sync + 'static,
            H: Hasher,
            $op<F, V>: Encode + Read<Cfg = C>,
            C: Clone + Send + Sync + 'static,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                self.compact_state(target)
            }
        }

        impl<F, E, V, H, C> Resolver for Arc<AsyncRwLock<$db<F, E, V, H, C>>>
        where
            F: Family,
            E: crate::Context,
            V: ValueEncoding + Send + Sync + 'static,
            H: Hasher,
            $op<F, V>: Encode + Read<Cfg = C>,
            C: Clone + Send + Sync + 'static,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                self.read().await.compact_state(target)
            }
        }

        impl<F, E, V, H, C> Resolver for Arc<AsyncRwLock<Option<$db<F, E, V, H, C>>>>
        where
            F: Family,
            E: crate::Context,
            V: ValueEncoding + Send + Sync + 'static,
            H: Hasher,
            $op<F, V>: Encode + Read<Cfg = C>,
            C: Clone + Send + Sync + 'static,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(ServeError::MissingSource)?;
                db.compact_state(target)
            }
        }
    };
}

// Resolver impls for compact immutable databases. Like the keyless compact path, these read the
// persisted witness/cache directly instead of rebuilding it from a full operation log.
macro_rules! impl_compact_resolver_compact_immutable {
    ($db:ident, $op:ident) => {
        impl<F, E, K, V, H, C> Resolver for Arc<$db<F, E, K, V, H, C>>
        where
            F: Family,
            E: crate::Context,
            K: Key,
            V: ValueEncoding + Send + Sync + 'static,
            H: Hasher,
            $op<F, K, V>: Encode + Read<Cfg = C>,
            C: Clone + Send + Sync + 'static,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                self.compact_state(target)
            }
        }

        impl<F, E, K, V, H, C> Resolver for Arc<AsyncRwLock<$db<F, E, K, V, H, C>>>
        where
            F: Family,
            E: crate::Context,
            K: Key,
            V: ValueEncoding + Send + Sync + 'static,
            H: Hasher,
            $op<F, K, V>: Encode + Read<Cfg = C>,
            C: Clone + Send + Sync + 'static,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                self.read().await.compact_state(target)
            }
        }

        impl<F, E, K, V, H, C> Resolver for Arc<AsyncRwLock<Option<$db<F, E, K, V, H, C>>>>
        where
            F: Family,
            E: crate::Context,
            K: Key,
            V: ValueEncoding + Send + Sync + 'static,
            H: Hasher,
            $op<F, K, V>: Encode + Read<Cfg = C>,
            C: Clone + Send + Sync + 'static,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = ServeError<F, H::Digest>;

            async fn get_compact_state(
                &self,
                target: Target<Self::Family, Self::Digest>,
            ) -> Result<State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(ServeError::MissingSource)?;
                db.compact_state(target)
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
    use super::Target;
    use crate::merkle::mmr;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{sha256::Digest, Hasher as _};

    #[test]
    fn test_target_decode_rejects_zero_leaf_count() {
        let unused_root = commonware_cryptography::Sha256::hash(b"unused");
        let encoded = Target::<mmr::Family, Digest> {
            root: unused_root,
            leaf_count: crate::merkle::Location::new(0),
        }
        .encode();

        assert!(Target::<mmr::Family, Digest>::decode(encoded).is_err());
    }
}
