use crate::{
    Context,
    merkle::{Family, Location, Proof},
    qmdb::{self, operation::Key, sync::compact::ServeError},
    translator::Translator,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{
    channel::oneshot,
    sync::{AsyncRwLock, TracedAsyncRwLock},
};
use std::{future::Future, num::NonZeroU64, sync::Arc};

/// A request for operations from a source's log.
pub struct Request<F: Family> {
    /// Prove against the root the tree had at this many operations.
    pub size: Location<F>,
    /// First operation to return.
    pub start: Location<F>,
    /// Maximum number of operations to return.
    pub max_ops: NonZeroU64,
    /// The lowest location the client will retain.
    ///
    /// When set, the response also carries the pins at that boundary. The proof in the same
    /// response authenticates them, so there is no way to request them on their own.
    pub retain_from: Option<Location<F>>,
}

impl<F: Family> Request<F> {
    /// Request operations at `start`, proven against the tree at `size`.
    pub const fn new(size: Location<F>, start: Location<F>, max_ops: NonZeroU64) -> Self {
        Self {
            size,
            start,
            max_ops,
            retain_from: None,
        }
    }

    /// Also return the pins at `boundary`, the lowest location the client will retain.
    pub const fn retaining_from(mut self, boundary: Location<F>) -> Self {
        self.retain_from = Some(boundary);
        self
    }
}

impl<F: Family> Clone for Request<F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: Family> Copy for Request<F> {}

impl<F: Family> std::fmt::Debug for Request<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("size", &self.size)
            .field("start", &self.start)
            .field("max_ops", &self.max_ops)
            .field("retain_from", &self.retain_from)
            .finish()
    }
}

/// One authenticated response.
///
/// The proof, the operations, and the pins are verified as a unit: the pins are only
/// believable because the proof folds them into digests it already commits to.
pub struct Response<F: Family, Op, D: Digest> {
    /// Proof authenticating `operations` against the root at the requested size.
    pub proof: Proof<F, D>,
    /// The operations that were fetched.
    pub operations: Vec<Op>,
    /// Pins at the requested boundary, if the request asked for them.
    pub pinned_nodes: Option<Vec<D>>,
}

impl<F: Family, Op, D: Digest> Response<F, Op, D> {
    /// Create a response.
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

impl<F: Family, Op: std::fmt::Debug, D: Digest> std::fmt::Debug for Response<F, Op, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("proof", &self.proof)
            .field("operations", &self.operations)
            .field("pinned_nodes", &self.pinned_nodes)
            .finish()
    }
}

/// Where to report whether a fetched response verified, so a remote peer can be scored.
///
/// `None` when the response came from local storage, where there is no peer to score.
pub type Validity = Option<oneshot::Sender<bool>>;

/// A handle a sync client fetches operations through. May be local or remote.
pub trait Resolver: Send + Sync + Clone + 'static {
    /// The merkle family backing the resolver's proofs
    type Family: Family;

    /// The digest type used in proofs returned by the resolver
    type Digest: Digest;

    /// The type of operations returned by the resolver
    type Op;

    /// The error type returned by the resolver
    type Error: std::error::Error + Send + 'static;

    /// Fetch the operations `request` asks for.
    ///
    /// Implementations may `select!` on it to abort in-flight work early.
    #[allow(clippy::type_complexity)]
    fn fetch<'a>(
        &'a self,
        request: Request<Self::Family>,
    ) -> impl Future<
        Output = Result<(Response<Self::Family, Self::Op, Self::Digest>, Validity), Self::Error>,
    > + Send
    + 'a;
}

/// A source of QMDB operations that can prove them.
///
/// A live database is a source; so is an owned snapshot; so is a lock around either, because
/// wrapping a source yields a source. That is what lets a single [`Resolver`] implementation
/// cover every shape a source is held in.
pub trait ProofSource: Send + Sync {
    /// The merkle family backing this source's proofs.
    type Family: Family;

    /// The digest type used in this source's proofs.
    type Digest: Digest;

    /// The type of operations this source yields. Served across threads, so it is [`Send`].
    type Op: Send;

    /// Why this source could not answer.
    type Error: std::error::Error + Send + 'static;

    /// Answer one request.
    ///
    /// When `request.retain_from` is set, the response also carries the pins at that
    /// boundary. They are authenticated by the proof in the same response, which is why
    /// there is no way to ask for them on their own.
    #[allow(clippy::type_complexity)]
    fn serve<'a>(
        &'a self,
        request: Request<Self::Family>,
    ) -> impl Future<
        Output = Result<Response<Self::Family, Self::Op, Self::Digest>, Self::Error>,
    > + Send
    + 'a;
}

/// A lock around a source is a source.
macro_rules! impl_locked_source {
    ($lock:ident) => {
        impl<T: ProofSource> ProofSource for $lock<T> {
            type Family = T::Family;
            type Digest = T::Digest;
            type Op = T::Op;
            type Error = T::Error;

            async fn serve(
                &self,
                request: Request<Self::Family>,
            ) -> Result<Response<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                self.read().await.serve(request).await
            }
        }

        impl<T: ProofSource> ProofSource for $lock<Option<T>>
        where
            ServeError<T::Family, T::Digest>: From<T::Error>,
        {
            type Family = T::Family;
            type Digest = T::Digest;
            type Op = T::Op;
            type Error = ServeError<T::Family, T::Digest>;

            async fn serve(
                &self,
                request: Request<Self::Family>,
            ) -> Result<Response<Self::Family, Self::Op, Self::Digest>, Self::Error> {
                let guard = self.read().await;
                let source = guard.as_ref().ok_or(ServeError::MissingSource)?;
                Ok(source.serve(request).await?)
            }
        }
    };
}

impl_locked_source!(AsyncRwLock);
impl_locked_source!(TracedAsyncRwLock);

/// Serve from any source, however it is held.
impl<T> Resolver for Arc<T>
where
    T: ProofSource + 'static,
{
    type Family = T::Family;
    type Digest = T::Digest;
    type Op = T::Op;
    type Error = T::Error;

    async fn fetch(
        &self,
        request: Request<Self::Family>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, Validity), Self::Error> {
        Ok((T::serve(self, request).await?, None))
    }
}

/// Answer a [`Request`] from a database's inherent proof reads.
///
/// Written once and expanded by each [`ProofSource`] implementation below. The two reads
/// belong to one answer: the pins are only meaningful because the proof in the same response
/// authenticates them.
macro_rules! serve_request {
    () => {
        async fn serve(
            &self,
            request: $crate::qmdb::sync::resolver::Request<F>,
        ) -> Result<
            $crate::qmdb::sync::resolver::Response<F, Self::Op, H::Digest>,
            $crate::qmdb::Error<F>,
        > {
            let source = self;
            let (proof, operations) = source
                .historical_proof(request.size, request.start, request.max_ops)
                .await?;
            let pinned_nodes = match request.retain_from {
                Some(boundary) => Some(source.pinned_nodes_at(boundary).await?),
                None => None,
            };
            Ok($crate::qmdb::sync::resolver::Response::new(
                proof,
                operations,
                pinned_nodes,
            ))
        }
    };
}

/// Every `any` database alias resolves to this one generic, so one implementation covers all
/// four of them.
impl<F, E, U, C, I, H, const N: usize, S> ProofSource
    for crate::qmdb::any::db::Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    U: crate::qmdb::any::operation::update::Update + Send + Sync + 'static,
    C: crate::journal::contiguous::Mutable<Item = crate::qmdb::any::operation::Operation<F, U>>
        + Send
        + Sync,
    I: crate::index::Unordered<Value = Location<F>> + Send + Sync,
    H: Hasher,
    S: Strategy,
    crate::qmdb::any::operation::Operation<F, U>: commonware_codec::Codec + Send,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = crate::qmdb::any::operation::Operation<F, U>;
    type Error = qmdb::Error<F>;

    serve_request!();
}
/// Both `immutable` aliases resolve to this one generic.
impl<F, E, K, V, C, H, T, S> ProofSource for crate::qmdb::immutable::Immutable<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: crate::qmdb::any::value::ValueEncoding,
    C: crate::journal::contiguous::Mutable<
            Item = crate::qmdb::immutable::Operation<F, K, V>,
        > + Send
        + Sync,
    C::Item: commonware_codec::EncodeShared + Send,
    H: Hasher,
    T: Translator + Send + Sync,
    T::Key: Send + Sync,
    S: Strategy,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = crate::qmdb::immutable::Operation<F, K, V>;
    type Error = qmdb::Error<F>;

    serve_request!();
}

/// Both `keyless` aliases resolve to this one generic.
impl<F, E, V, C, H, S> ProofSource for crate::qmdb::keyless::Keyless<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: crate::qmdb::any::value::ValueEncoding,
    C: crate::journal::contiguous::Mutable<Item = crate::qmdb::keyless::Operation<F, V>>
        + Send
        + Sync,
    H: Hasher,
    S: Strategy,
    crate::qmdb::keyless::Operation<F, V>: commonware_codec::EncodeShared + Send,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = crate::qmdb::keyless::Operation<F, V>;
    type Error = qmdb::Error<F>;

    serve_request!();
}

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

        async fn fetch(
            &self,
            _request: Request<F>,
        ) -> Result<(Response<F, Op, D>, Validity), qmdb::Error<F>> {
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
