use crate::{
    journal::{authenticated, contiguous::Reader as ContiguousReader},
    merkle::{Family, Location, Proof},
    qmdb::{
        self,
        any::{
            db::Db as AnyDb,
            ordered::{
                fixed::{Db as OrderedFixedDb, Operation as OrderedFixedOperation},
                variable::{Db as OrderedVariableDb, Operation as OrderedVariableOperation},
            },
            unordered::{
                fixed::{Db as FixedDb, Operation as FixedOperation},
                variable::{Db as VariableDb, Operation as VariableOperation},
            },
            FixedValue, VariableValue,
        },
        immutable::{
            fixed::{Db as ImmutableFixedDb, Operation as ImmutableFixedOp},
            variable::{Db as ImmutableVariableDb, Operation as ImmutableVariableOp},
            Immutable,
        },
        keyless::{
            fixed::{Db as KeylessFixedDb, Operation as KeylessFixedOp},
            variable::{Db as KeylessVariableDb, Operation as KeylessVariableOp},
            Keyless,
        },
        operation::{Key, Operation as QmdbOperation},
    },
    translator::Translator,
    Context,
};
use commonware_codec::{CodecShared, EncodeShared};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{
    channel::oneshot,
    sync::{AsyncRwLock, TracedAsyncRwLock},
    Array,
};
use std::{future::Future, num::NonZeroU64, sync::Arc};

/// Result from a fetch operation.
pub struct FetchResult<F: Family, Op, D: Digest> {
    /// The proof for the operations
    pub proof: Proof<F, D>,
    /// The operations that were fetched
    pub operations: Vec<Op>,
    /// Pinned merkle nodes at the start location, if requested
    pub pinned_nodes: Option<Vec<D>>,
    /// Optional callback for resolvers that observe downstream validation feedback.
    pub callback: Option<oneshot::Sender<bool>>,
}

impl<F: Family, Op, D: Digest> FetchResult<F, Op, D> {
    /// Creates a fetch result that does not observe the validation acknowledgement.
    pub const fn new(
        proof: Proof<F, D>,
        operations: Vec<Op>,
        pinned_nodes: Option<Vec<D>>,
    ) -> Self {
        Self {
            proof,
            operations,
            pinned_nodes,
            callback: None,
        }
    }

    /// Creates a fetch result using an externally managed validation callback.
    pub const fn with_callback(
        proof: Proof<F, D>,
        operations: Vec<Op>,
        pinned_nodes: Option<Vec<D>>,
        callback: oneshot::Sender<bool>,
    ) -> Self {
        Self {
            proof,
            operations,
            pinned_nodes,
            callback: Some(callback),
        }
    }
}

/// Operations fetched from a resolver before packaging as a [`FetchResult`].
pub struct FetchedOperations<F: Family, Op, D: Digest> {
    /// The proof for the operations
    pub proof: Proof<F, D>,
    /// The operations that were fetched
    pub operations: Vec<Op>,
    /// Pinned merkle nodes at the start location, if requested
    pub pinned_nodes: Option<Vec<D>>,
}

impl<F: Family, Op, D: Digest> FetchedOperations<F, Op, D> {
    /// Creates fetched operations with optional pinned nodes.
    pub const fn new(
        proof: Proof<F, D>,
        operations: Vec<Op>,
        pinned_nodes: Option<Vec<D>>,
    ) -> Self {
        Self {
            proof,
            operations,
            pinned_nodes,
        }
    }
}

/// A resolver backed by a live authenticated-log reader.
pub struct LogResolver<F, E, C, H>
where
    F: Family,
    E: Context,
    C: authenticated::Inner<E>,
    C::Item: EncodeShared,
    H: Hasher,
{
    log: authenticated::Reader<F, E, C, H>,
}

impl<F, E, C, H> Clone for LogResolver<F, E, C, H>
where
    F: Family,
    E: Context,
    C: authenticated::Inner<E>,
    C::Item: EncodeShared,
    H: Hasher,
{
    fn clone(&self) -> Self {
        Self {
            log: self.log.clone(),
        }
    }
}

impl<F, E, C, H> LogResolver<F, E, C, H>
where
    F: Family,
    E: Context,
    C: authenticated::Inner<E>,
    C::Item: EncodeShared,
    H: Hasher,
{
    /// Create a resolver from an authenticated-log reader.
    pub const fn new(log: authenticated::Reader<F, E, C, H>) -> Self {
        Self { log }
    }
}

/// A database that can expose a lock-free resolver reader.
pub trait Provider: Send + Sync + 'static {
    /// The merkle family backing the resolver's proofs.
    type Family: Family;

    /// The digest type used in proofs returned by the resolver.
    type Digest: Digest;

    /// The type of operations returned by the resolver.
    type Op;

    /// The resolver handle produced by this database.
    type Resolver: Resolver<Family = Self::Family, Digest = Self::Digest, Op = Self::Op>;

    /// Return a resolver backed by this database's published read state.
    fn resolver(&self) -> Self::Resolver;
}

impl<F: Family, Op: std::fmt::Debug, D: Digest> std::fmt::Debug for FetchResult<F, Op, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchResult")
            .field("proof", &self.proof)
            .field("operations", &self.operations)
            .field("pinned_nodes", &self.pinned_nodes)
            .field("callback", &self.callback.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

/// Fetch an operation range with a caller-provided callback and package it as a
/// [`FetchResult`].
///
/// Use this when the source returns the proof, operations, and optional pinned nodes together,
/// such as a network `get_operations` request.
pub async fn fetch_operation_range<F, Op, D, Error, Fetch, FetchFuture>(
    op_count: Location<F>,
    start_loc: Location<F>,
    max_ops: NonZeroU64,
    include_pinned_nodes: bool,
    fetch: Fetch,
) -> Result<FetchResult<F, Op, D>, Error>
where
    F: Family,
    D: Digest,
    Fetch: FnOnce(Location<F>, Location<F>, NonZeroU64, bool) -> FetchFuture,
    FetchFuture: Future<Output = Result<FetchedOperations<F, Op, D>, Error>>,
{
    let FetchedOperations {
        proof,
        operations,
        pinned_nodes,
    } = fetch(op_count, start_loc, max_ops, include_pinned_nodes).await?;
    Ok(FetchResult::new(proof, operations, pinned_nodes))
}

/// Fetch an operation range from separate local-store callbacks and package it as a
/// [`FetchResult`].
///
/// Use this for database APIs that expose `historical_proof` separately from
/// `pinned_nodes_at`; pinned nodes are fetched only when `include_pinned_nodes` is true.
pub async fn fetch_operations<
    F,
    Op,
    D,
    Error,
    HistoricalProof,
    HistoricalFuture,
    Pins,
    PinsFuture,
>(
    op_count: Location<F>,
    start_loc: Location<F>,
    max_ops: NonZeroU64,
    include_pinned_nodes: bool,
    historical_proof: HistoricalProof,
    pinned_nodes_at: Pins,
) -> Result<FetchResult<F, Op, D>, Error>
where
    F: Family,
    D: Digest,
    HistoricalProof: FnOnce(Location<F>, Location<F>, NonZeroU64) -> HistoricalFuture,
    HistoricalFuture: Future<Output = Result<(Proof<F, D>, Vec<Op>), Error>>,
    Pins: FnOnce(Location<F>) -> PinsFuture,
    PinsFuture: Future<Output = Result<Vec<D>, Error>>,
{
    fetch_operation_range(
        op_count,
        start_loc,
        max_ops,
        include_pinned_nodes,
        |op_count, start_loc, max_ops, include_pinned_nodes| async move {
            let (proof, operations) = historical_proof(op_count, start_loc, max_ops).await?;
            let pinned_nodes = if include_pinned_nodes {
                Some(pinned_nodes_at(start_loc).await?)
            } else {
                None
            };
            Ok(FetchedOperations::new(proof, operations, pinned_nodes))
        },
    )
    .await
}

/// Trait for network communication with the sync server.
pub trait Resolver: Send + Sync + Clone + 'static {
    /// The merkle family backing the resolver's proofs
    type Family: Family;

    /// The digest type used in proofs returned by the resolver
    type Digest: Digest;

    /// The type of operations returned by the resolver
    type Op;

    /// The error type returned by the resolver
    type Error: std::error::Error + Send + 'static;

    /// Get the operations starting at `start_loc` in the database, up to `max_ops` operations.
    /// Returns the operations and a proof that they were present in the database when it had
    /// `op_count` operations. If `include_pinned_nodes` is true, the result will include the
    /// pinned merkle nodes at `start_loc`.
    ///
    /// The corresponding `cancel_tx` is dropped when the engine no longer needs this
    /// request (e.g. due to a target update), causing `cancel_rx.await` to return
    /// `Err`. Implementations may `select!` on it to abort in-flight work early.
    #[allow(clippy::type_complexity)]
    fn get_operations<'a>(
        &'a self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
        cancel_rx: oneshot::Receiver<()>,
    ) -> impl Future<Output = Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error>>
           + Send
           + 'a;
}

impl<F, E, C, H> Resolver for LogResolver<F, E, C, H>
where
    F: Family,
    E: Context + 'static,
    C: authenticated::Inner<E> + 'static,
    C::Item: QmdbOperation<F> + EncodeShared + Send + Sync + 'static,
    C::Reader: 'static,
    H: Hasher + 'static,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = C::Item;
    type Error = qmdb::Error<F>;

    async fn get_operations(
        &self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
        _cancel_rx: oneshot::Receiver<()>,
    ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        let snapshot = self.log.snapshot();
        let historical = snapshot.clone();
        fetch_operations(
            op_count,
            start_loc,
            max_ops,
            include_pinned_nodes,
            |op_count, start_loc, max_ops| async move {
                let inactive_peaks =
                    qmdb::inactive_peaks_at::<F, _>(&historical, op_count, |op| op.has_floor())
                        .await?;
                historical
                    .historical_proof(op_count, start_loc, max_ops, inactive_peaks)
                    .await
                    .map_err(Into::into)
            },
            |start_loc| async move {
                snapshot
                    .pinned_nodes_at(start_loc)
                    .await
                    .map_err(Into::into)
            },
        )
        .await
    }
}

impl<F, E, C, H> super::compact::Resolver for LogResolver<F, E, C, H>
where
    F: Family,
    E: Context + 'static,
    C: authenticated::Inner<E> + 'static,
    C::Item: QmdbOperation<F> + EncodeShared + Send + Sync + 'static,
    C::Reader: 'static,
    H: Hasher + 'static,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = C::Item;
    type Error = super::compact::ServeError<F, H::Digest>;

    async fn get_compact_state(
        &self,
        target: super::compact::Target<Self::Family, Self::Digest>,
    ) -> Result<super::compact::FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error>
    {
        target
            .validate()
            .map_err(super::compact::ServeError::InvalidTarget)?;

        let snapshot = self.log.snapshot();
        let leaf_count = Location::new(snapshot.bounds().end);
        let inactive_peaks =
            qmdb::inactive_peaks_at::<F, _>(&snapshot, leaf_count, |op| op.has_floor())
                .await
                .map_err(super::compact::ServeError::Database)?;
        let current = super::compact::Target::new(
            snapshot
                .root(inactive_peaks)
                .map_err(qmdb::Error::from)
                .map_err(super::compact::ServeError::Database)?,
            leaf_count,
        );
        if target.root != current.root || target.leaf_count != current.leaf_count {
            return Err(super::compact::ServeError::StaleTarget {
                requested: target,
                current,
            });
        }

        let last_commit_loc = Location::new(*leaf_count - 1);
        let (last_commit_proof, mut operations) = snapshot
            .historical_proof(
                leaf_count,
                last_commit_loc,
                NonZeroU64::new(1).unwrap(),
                inactive_peaks,
            )
            .await
            .map_err(qmdb::Error::from)
            .map_err(super::compact::ServeError::Database)?;
        let last_commit_op = operations
            .pop()
            .ok_or(super::compact::ServeError::Database(
                qmdb::Error::DataCorrupted("missing last commit operation"),
            ))?;
        let pinned_nodes = snapshot
            .pinned_nodes_at(leaf_count)
            .await
            .map_err(qmdb::Error::from)
            .map_err(super::compact::ServeError::Database)?;

        Ok(super::compact::State {
            leaf_count,
            pinned_nodes,
            last_commit_op,
            last_commit_proof,
        }
        .into())
    }
}

impl<F, E, C, I, H, U, const N: usize, S> Provider for AnyDb<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context + 'static,
    C: authenticated::Inner<E> + 'static,
    C::Item: QmdbOperation<F> + CodecShared + Send + Sync + 'static,
    C::Reader: 'static,
    I: crate::index::Unordered<Value = Location<F>> + 'static,
    H: Hasher + 'static,
    U: Send + Sync + 'static,
    S: Strategy + 'static,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = C::Item;
    type Resolver = LogResolver<F, E, C, H>;

    fn resolver(&self) -> Self::Resolver {
        LogResolver::new(self.log.read_handle())
    }
}

impl<F, E, V, C, H, S> Provider for Keyless<F, E, V, C, H, S>
where
    F: Family,
    E: Context + 'static,
    V: qmdb::any::value::ValueEncoding + Send + Sync + 'static,
    C: authenticated::Inner<E, Item = qmdb::keyless::Operation<F, V>> + 'static,
    C::Reader: 'static,
    H: Hasher + 'static,
    S: Strategy + 'static,
    qmdb::keyless::Operation<F, V>: EncodeShared + QmdbOperation<F> + Send + Sync + 'static,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = qmdb::keyless::Operation<F, V>;
    type Resolver = LogResolver<F, E, C, H>;

    fn resolver(&self) -> Self::Resolver {
        LogResolver::new(self.journal.read_handle())
    }
}

impl<F, E, K, V, C, H, T, S> Provider for Immutable<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context + 'static,
    K: Key + Send + Sync + 'static,
    V: qmdb::any::value::ValueEncoding + Send + Sync + 'static,
    C: authenticated::Inner<E, Item = qmdb::immutable::Operation<F, K, V>> + 'static,
    C::Reader: 'static,
    H: Hasher + 'static,
    T: Translator + Send + Sync + 'static,
    T::Key: Send + Sync,
    S: Strategy + 'static,
    qmdb::immutable::Operation<F, K, V>: EncodeShared + QmdbOperation<F> + Send + Sync + 'static,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = qmdb::immutable::Operation<F, K, V>;
    type Resolver = LogResolver<F, E, C, H>;

    fn resolver(&self) -> Self::Resolver {
        LogResolver::new(self.journal.read_handle())
    }
}

macro_rules! impl_resolver {
    ($db:ident, $op:ident, $val_bound:ident) => {
        impl<F, E, K, V, H, T, S> Resolver for Arc<$db<F, E, K, V, H, T, S>>
        where
            F: Family,
            E: Context,
            K: Array,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                fetch_operations(
                    op_count,
                    start_loc,
                    max_ops,
                    include_pinned_nodes,
                    |op_count, start_loc, max_ops| {
                        self.historical_proof(op_count, start_loc, max_ops)
                    },
                    |start_loc| self.pinned_nodes_at(start_loc),
                )
                .await
            }
        }
        impl_resolver!(@locked $db, $op, $val_bound, AsyncRwLock);
        impl_resolver!(@locked $db, $op, $val_bound, TracedAsyncRwLock);
    };
    (@locked $db:ident, $op:ident, $val_bound:ident, $lock:ident) => {

        impl<F, E, K, V, H, T, S> Resolver for Arc<$lock<$db<F, E, K, V, H, T, S>>>
        where
            F: Family,
            E: Context,
            K: Array,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                fetch_operations(
                    op_count,
                    start_loc,
                    max_ops,
                    include_pinned_nodes,
                    |op_count, start_loc, max_ops| {
                        db.historical_proof(op_count, start_loc, max_ops)
                    },
                    |start_loc| db.pinned_nodes_at(start_loc),
                )
                .await
            }
        }

        impl<F, E, K, V, H, T, S> Resolver for Arc<$lock<Option<$db<F, E, K, V, H, T, S>>>>
        where
            F: Family,
            E: Context,
            K: Array,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            T: Translator + Send + Sync + 'static,
            T::Key: Send + Sync,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, K, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(qmdb::Error::KeyNotFound)?;
                fetch_operations(
                    op_count,
                    start_loc,
                    max_ops,
                    include_pinned_nodes,
                    |op_count, start_loc, max_ops| {
                        db.historical_proof(op_count, start_loc, max_ops)
                    },
                    |start_loc| db.pinned_nodes_at(start_loc),
                )
                .await
            }
        }
    };
}

// Unordered Fixed
impl_resolver!(FixedDb, FixedOperation, FixedValue);

// Unordered Variable
impl_resolver!(VariableDb, VariableOperation, VariableValue);

// Ordered Fixed
impl_resolver!(OrderedFixedDb, OrderedFixedOperation, FixedValue);

// Ordered Variable
impl_resolver!(OrderedVariableDb, OrderedVariableOperation, VariableValue);

// Immutable types need a separate macro because the key bound varies
// (Array for fixed, Key for variable) unlike the other DB types which
// always use Array.
macro_rules! impl_resolver_immutable {
    ($db:ident, $op:ident, $val_bound:ident, $key_bound:path) => {
        impl<F, E, K, V, H, T, S> Resolver for Arc<$db<F, E, K, V, H, T, S>>
        where
            F: Family,
            E: Context,
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
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                fetch_operations(
                    op_count,
                    start_loc,
                    max_ops,
                    include_pinned_nodes,
                    |op_count, start_loc, max_ops| {
                        self.historical_proof(op_count, start_loc, max_ops)
                    },
                    |start_loc| self.pinned_nodes_at(start_loc),
                )
                .await
            }
        }
        impl_resolver_immutable!(@locked $db, $op, $val_bound, $key_bound, AsyncRwLock);
        impl_resolver_immutable!(@locked $db, $op, $val_bound, $key_bound, TracedAsyncRwLock);
    };
    (@locked $db:ident, $op:ident, $val_bound:ident, $key_bound:path, $lock:ident) => {

        impl<F, E, K, V, H, T, S> Resolver for Arc<$lock<$db<F, E, K, V, H, T, S>>>
        where
            F: Family,
            E: Context,
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
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                fetch_operations(
                    op_count,
                    start_loc,
                    max_ops,
                    include_pinned_nodes,
                    |op_count, start_loc, max_ops| {
                        db.historical_proof(op_count, start_loc, max_ops)
                    },
                    |start_loc| db.pinned_nodes_at(start_loc),
                )
                .await
            }
        }

        impl<F, E, K, V, H, T, S> Resolver for Arc<$lock<Option<$db<F, E, K, V, H, T, S>>>>
        where
            F: Family,
            E: Context,
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
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(qmdb::Error::KeyNotFound)?;
                fetch_operations(
                    op_count,
                    start_loc,
                    max_ops,
                    include_pinned_nodes,
                    |op_count, start_loc, max_ops| {
                        db.historical_proof(op_count, start_loc, max_ops)
                    },
                    |start_loc| db.pinned_nodes_at(start_loc),
                )
                .await
            }
        }
    };
}

// Immutable Fixed
impl_resolver_immutable!(ImmutableFixedDb, ImmutableFixedOp, FixedValue, Array);

// Immutable Variable
impl_resolver_immutable!(ImmutableVariableDb, ImmutableVariableOp, VariableValue, Key);

// Keyless types have no key or translator, so they need their own macro.
macro_rules! impl_resolver_keyless {
    ($db:ident, $op:ident, $val_bound:ident) => {
        impl<F, E, V, H, S> Resolver for Arc<$db<F, E, V, H, S>>
        where
            F: Family,
            E: Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                fetch_operations(
                    op_count,
                    start_loc,
                    max_ops,
                    include_pinned_nodes,
                    |op_count, start_loc, max_ops| {
                        self.historical_proof(op_count, start_loc, max_ops)
                    },
                    |start_loc| self.pinned_nodes_at(start_loc),
                )
                .await
            }
        }
        impl_resolver_keyless!(@locked $db, $op, $val_bound, AsyncRwLock);
        impl_resolver_keyless!(@locked $db, $op, $val_bound, TracedAsyncRwLock);
    };
    (@locked $db:ident, $op:ident, $val_bound:ident, $lock:ident) => {

        impl<F, E, V, H, S> Resolver for Arc<$lock<$db<F, E, V, H, S>>>
        where
            F: Family,
            E: Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                fetch_operations(
                    op_count,
                    start_loc,
                    max_ops,
                    include_pinned_nodes,
                    |op_count, start_loc, max_ops| {
                        db.historical_proof(op_count, start_loc, max_ops)
                    },
                    |start_loc| db.pinned_nodes_at(start_loc),
                )
                .await
            }
        }

        impl<F, E, V, H, S> Resolver for Arc<$lock<Option<$db<F, E, V, H, S>>>>
        where
            F: Family,
            E: Context,
            V: $val_bound + Send + Sync + 'static,
            H: Hasher,
            S: Strategy,
        {
            type Family = F;
            type Digest = H::Digest;
            type Op = $op<F, V>;
            type Error = qmdb::Error<F>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
                _cancel_rx: oneshot::Receiver<()>,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(qmdb::Error::KeyNotFound)?;
                fetch_operations(
                    op_count,
                    start_loc,
                    max_ops,
                    include_pinned_nodes,
                    |op_count, start_loc, max_ops| {
                        db.historical_proof(op_count, start_loc, max_ops)
                    },
                    |start_loc| db.pinned_nodes_at(start_loc),
                )
                .await
            }
        }
    };
}

// Keyless Fixed
impl_resolver_keyless!(KeylessFixedDb, KeylessFixedOp, FixedValue);

// Keyless Variable
impl_resolver_keyless!(KeylessVariableDb, KeylessVariableOp, VariableValue);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        merkle::mmr,
        translator::{OneCap, TwoCap},
    };
    use commonware_cryptography::{sha256::Digest as ShaDigest, Sha256};
    use commonware_parallel::Rayon;
    use commonware_runtime::deterministic;
    use commonware_utils::sync::AsyncRwLock;
    use std::{marker::PhantomData, sync::Arc};

    macro_rules! assert_resolver_variants {
        ($db:ty) => {
            assert_resolver::<Arc<$db>>();
            assert_resolver::<Arc<AsyncRwLock<$db>>>();
            assert_resolver::<Arc<AsyncRwLock<Option<$db>>>>();
        };
    }

    fn assert_resolver<R: Resolver>() {}

    fn empty_proof() -> Proof<mmr::Family, ShaDigest> {
        Proof {
            leaves: Location::new(0),
            inactive_peaks: 0,
            digests: vec![],
        }
    }

    #[test]
    fn test_fetch_result_new_has_no_success_acknowledgement() {
        let result = FetchResult::<mmr::Family, (), ShaDigest>::new(empty_proof(), vec![], None);
        assert!(result.callback.is_none());
    }

    #[test]
    fn test_fetch_result_with_callback_reports_to_external_receiver() {
        let (success_tx, mut success_rx) = oneshot::channel();
        let result = FetchResult::<mmr::Family, (), ShaDigest>::with_callback(
            empty_proof(),
            vec![],
            None,
            success_tx,
        );
        assert!(result.callback.expect("success sender").send(true).is_ok());
        assert_eq!(success_rx.try_recv(), Ok(true));
    }

    /// A resolver that always fails.
    #[derive(Clone)]
    pub struct FailResolver<F: Family, Op, D> {
        _phantom: PhantomData<(F, Op, D)>,
    }

    impl<F, Op, D> Resolver for FailResolver<F, Op, D>
    where
        F: Family,
        D: Digest,
        Op: Send + Sync + Clone + 'static,
    {
        type Family = F;
        type Digest = D;
        type Op = Op;
        type Error = qmdb::Error<F>;

        async fn get_operations(
            &self,
            _op_count: Location<F>,
            _start_loc: Location<F>,
            _max_ops: NonZeroU64,
            _include_pinned_nodes: bool,
            _cancel: oneshot::Receiver<()>,
        ) -> Result<FetchResult<F, Op, D>, qmdb::Error<F>> {
            Err(qmdb::Error::KeyNotFound) // Arbitrary dummy error
        }
    }

    impl<F: Family, Op, D> FailResolver<F, Op, D> {
        pub fn new() -> Self {
            Self {
                _phantom: PhantomData,
            }
        }
    }

    #[test]
    fn test_all_qmdb_variants_implement_strategy_resolvers() {
        type AnyOrderedFixed = crate::qmdb::any::ordered::fixed::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            ShaDigest,
            Sha256,
            OneCap,
            Rayon,
        >;
        type AnyOrderedVariable = crate::qmdb::any::ordered::variable::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Vec<u8>,
            Sha256,
            OneCap,
            Rayon,
        >;
        type AnyUnorderedFixed = crate::qmdb::any::unordered::fixed::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            ShaDigest,
            Sha256,
            TwoCap,
            Rayon,
        >;
        type AnyUnorderedVariable = crate::qmdb::any::unordered::variable::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Vec<u8>,
            Sha256,
            TwoCap,
            Rayon,
        >;
        type CurrentOrderedFixed = crate::qmdb::current::ordered::fixed::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            ShaDigest,
            Sha256,
            OneCap,
            32,
            Rayon,
        >;
        type CurrentOrderedVariable = crate::qmdb::current::ordered::variable::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Vec<u8>,
            Sha256,
            OneCap,
            32,
            Rayon,
        >;
        type CurrentUnorderedFixed = crate::qmdb::current::unordered::fixed::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            ShaDigest,
            Sha256,
            TwoCap,
            32,
            Rayon,
        >;
        type CurrentUnorderedVariable = crate::qmdb::current::unordered::variable::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Vec<u8>,
            Sha256,
            TwoCap,
            32,
            Rayon,
        >;
        type ImmutableFixed = crate::qmdb::immutable::fixed::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            ShaDigest,
            Sha256,
            TwoCap,
            Rayon,
        >;
        type ImmutableVariable = crate::qmdb::immutable::variable::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Vec<u8>,
            Sha256,
            TwoCap,
            Rayon,
        >;
        type KeylessFixed = crate::qmdb::keyless::fixed::Db<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Sha256,
            Rayon,
        >;
        type KeylessVariable = crate::qmdb::keyless::variable::Db<
            mmr::Family,
            deterministic::Context,
            Vec<u8>,
            Sha256,
            Rayon,
        >;

        assert_resolver_variants!(AnyOrderedFixed);
        assert_resolver_variants!(AnyOrderedVariable);
        assert_resolver_variants!(AnyUnorderedFixed);
        assert_resolver_variants!(AnyUnorderedVariable);
        assert_resolver_variants!(CurrentOrderedFixed);
        assert_resolver_variants!(CurrentOrderedVariable);
        assert_resolver_variants!(CurrentUnorderedFixed);
        assert_resolver_variants!(CurrentUnorderedVariable);
        assert_resolver_variants!(ImmutableFixed);
        assert_resolver_variants!(ImmutableVariable);
        assert_resolver_variants!(KeylessFixed);
        assert_resolver_variants!(KeylessVariable);
    }
}
