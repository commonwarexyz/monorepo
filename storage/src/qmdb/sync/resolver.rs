use crate::{
    Context,
    merkle::{Family, Location, Proof},
    qmdb::{
        self,
        any::{
            FixedValue, VariableValue,
            ordered::{
                fixed::{Db as OrderedFixedDb, Operation as OrderedFixedOperation},
                variable::{Db as OrderedVariableDb, Operation as OrderedVariableOperation},
            },
            unordered::{
                fixed::{Db as FixedDb, Operation as FixedOperation},
                variable::{Db as VariableDb, Operation as VariableOperation},
            },
        },
        immutable::{
            fixed::{Db as ImmutableFixedDb, Operation as ImmutableFixedOp},
            variable::{Db as ImmutableVariableDb, Operation as ImmutableVariableOp},
        },
        keyless::{
            fixed::{Db as KeylessFixedDb, Operation as KeylessFixedOp},
            variable::{Db as KeylessVariableDb, Operation as KeylessVariableOp},
        },
        operation::Key,
        sync::compact::ServeError,
    },
    translator::Translator,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{
    Array,
    channel::oneshot,
    sync::{AsyncRwLock, TracedAsyncRwLock},
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
    #[allow(clippy::type_complexity)]
    fn get_operations<'a>(
        &'a self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
    ) -> impl Future<Output = Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error>>
    + Send
    + 'a;
}

/// A source of QMDB operations that can prove them.
///
/// Sync serving reads through this trait, so a live database and an owned snapshot are
/// interchangeable to it. An implementor supplies the two primitive reads, and this module's
/// [`Resolver`] implementations then cover every shape a source is held in: directly, behind
/// a lock, or behind a lock that may be empty.
pub trait ProofSource: Send + Sync {
    /// The merkle family backing this source's proofs.
    type Family: Family;

    /// The digest type used in this source's proofs.
    type Digest: Digest;

    /// The type of operations this source yields. Served across threads, so it is [`Send`].
    type Op: Send;

    /// Prove the operations starting at `start_loc`, against the state this source held when
    /// it had `op_count` operations.
    #[allow(clippy::type_complexity)]
    fn historical_proof<'a>(
        &'a self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
    ) -> impl Future<
        Output = Result<
            (Proof<Self::Family, Self::Digest>, Vec<Self::Op>),
            qmdb::Error<Self::Family>,
        >,
    > + Send
    + 'a;

    /// Return the pinned Merkle nodes for a lower operation boundary of `loc`.
    fn pinned_nodes_at<'a>(
        &'a self,
        loc: Location<Self::Family>,
    ) -> impl Future<Output = Result<Vec<Self::Digest>, qmdb::Error<Self::Family>>> + Send + 'a;

    /// Prove the operations starting at `start_loc` and package them for a peer, including
    /// the pinned nodes at `start_loc` when `include_pinned_nodes` is set.
    #[allow(clippy::type_complexity)]
    fn fetch_operations<'a>(
        &'a self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
    ) -> impl Future<
        Output = Result<
            FetchResult<Self::Family, Self::Op, Self::Digest>,
            qmdb::Error<Self::Family>,
        >,
    > + Send
    + 'a {
        async move {
            let (proof, operations) = self.historical_proof(op_count, start_loc, max_ops).await?;
            let pinned_nodes = if include_pinned_nodes {
                Some(self.pinned_nodes_at(start_loc).await?)
            } else {
                None
            };
            Ok(FetchResult::new(proof, operations, pinned_nodes))
        }
    }
}

/// Serve from a source held directly.
impl<T> Resolver for Arc<T>
where
    T: ProofSource + 'static,
{
    type Family = T::Family;
    type Digest = T::Digest;
    type Op = T::Op;
    type Error = qmdb::Error<T::Family>;

    async fn get_operations(
        &self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
    ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        self.fetch_operations(op_count, start_loc, max_ops, include_pinned_nodes)
            .await
    }
}

/// Serve from a source behind a lock, and from one behind a lock that may be empty.
///
/// A single read guard spans the whole fetch, so the proof and its pinned nodes are read
/// from one state even while a writer waits. A macro rather than a further blanket
/// implementation because the two lock types share no trait to be generic over.
macro_rules! impl_locked_resolver {
    ($lock:ident) => {
        impl<T> Resolver for Arc<$lock<T>>
        where
            T: ProofSource + 'static,
        {
            type Family = T::Family;
            type Digest = T::Digest;
            type Op = T::Op;
            type Error = qmdb::Error<T::Family>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let db = self.read().await;
                db.fetch_operations(op_count, start_loc, max_ops, include_pinned_nodes)
                    .await
            }
        }

        impl<T> Resolver for Arc<$lock<Option<T>>>
        where
            T: ProofSource + 'static,
        {
            type Family = T::Family;
            type Digest = T::Digest;
            type Op = T::Op;
            type Error = ServeError<T::Family, T::Digest>;

            async fn get_operations(
                &self,
                op_count: Location<Self::Family>,
                start_loc: Location<Self::Family>,
                max_ops: NonZeroU64,
                include_pinned_nodes: bool,
            ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let db = guard.as_ref().ok_or(ServeError::MissingSource)?;
                Ok(db
                    .fetch_operations(op_count, start_loc, max_ops, include_pinned_nodes)
                    .await?)
            }
        }
    };
}

impl_locked_resolver!(AsyncRwLock);
impl_locked_resolver!(TracedAsyncRwLock);

/// Forward a database's inherent proof reads to [`ProofSource`].
///
/// The keyless arm exists because those databases have no key or translator parameter.
macro_rules! impl_proof_source {
    ($db:ident, $op:ident, $val_bound:ident, $key_bound:path) => {
        impl<F, E, K, V, H, T, S> ProofSource for $db<F, E, K, V, H, T, S>
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

            async fn historical_proof(
                &self,
                op_count: Location<F>,
                start_loc: Location<F>,
                max_ops: NonZeroU64,
            ) -> Result<(Proof<F, H::Digest>, Vec<Self::Op>), qmdb::Error<F>> {
                self.historical_proof(op_count, start_loc, max_ops).await
            }

            async fn pinned_nodes_at(
                &self,
                loc: Location<F>,
            ) -> Result<Vec<H::Digest>, qmdb::Error<F>> {
                self.pinned_nodes_at(loc).await
            }
        }
    };
    (keyless $db:ident, $op:ident, $val_bound:ident) => {
        impl<F, E, V, H, S> ProofSource for $db<F, E, V, H, S>
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

            async fn historical_proof(
                &self,
                op_count: Location<F>,
                start_loc: Location<F>,
                max_ops: NonZeroU64,
            ) -> Result<(Proof<F, H::Digest>, Vec<Self::Op>), qmdb::Error<F>> {
                self.historical_proof(op_count, start_loc, max_ops).await
            }

            async fn pinned_nodes_at(
                &self,
                loc: Location<F>,
            ) -> Result<Vec<H::Digest>, qmdb::Error<F>> {
                self.pinned_nodes_at(loc).await
            }
        }
    };
}

impl_proof_source!(FixedDb, FixedOperation, FixedValue, Array);
impl_proof_source!(VariableDb, VariableOperation, VariableValue, Array);
impl_proof_source!(OrderedFixedDb, OrderedFixedOperation, FixedValue, Array);
impl_proof_source!(
    OrderedVariableDb,
    OrderedVariableOperation,
    VariableValue,
    Array
);
impl_proof_source!(ImmutableFixedDb, ImmutableFixedOp, FixedValue, Array);
impl_proof_source!(ImmutableVariableDb, ImmutableVariableOp, VariableValue, Key);
impl_proof_source!(keyless KeylessFixedDb, KeylessFixedOp, FixedValue);
impl_proof_source!(keyless KeylessVariableDb, KeylessVariableOp, VariableValue);

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        merkle::mmr,
        translator::{OneCap, TwoCap},
    };
    use commonware_cryptography::{Sha256, sha256::Digest as ShaDigest};
    use commonware_parallel::Rayon;
    use commonware_runtime::deterministic;
    use commonware_utils::sync::{AsyncRwLock, TracedAsyncRwLock};
    use std::{marker::PhantomData, sync::Arc};

    macro_rules! assert_resolver_variants {
        ($db:ty) => {
            assert_resolver::<Arc<$db>>();
            assert_resolver::<Arc<AsyncRwLock<$db>>>();
            assert_resolver::<Arc<AsyncRwLock<Option<$db>>>>();
            assert_resolver::<Arc<TracedAsyncRwLock<$db>>>();
            assert_resolver::<Arc<TracedAsyncRwLock<Option<$db>>>>();
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
