use crate::{
    Context,
    merkle::{Family, Location, MAX_PINNED_NODES, MAX_PROOF_DIGESTS_PER_ELEMENT, Proof},
    qmdb::{self, operation::Key, sync::ServeError},
    translator::Translator,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadRangeExt as _, Write};
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

impl<F: Family, Op: Clone, D: Digest> Clone for Response<F, Op, D> {
    fn clone(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            operations: self.operations.clone(),
            pinned_nodes: self.pinned_nodes.clone(),
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

impl<F: Family, Op: Write, D: Digest> Write for Response<F, Op, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.operations.write(buf);
        self.pinned_nodes.write(buf);
    }
}

impl<F: Family, Op: EncodeSize, D: Digest> EncodeSize for Response<F, Op, D> {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.operations.encode_size() + self.pinned_nodes.encode_size()
    }
}

impl<F: Family, Op: Read, D: Digest> Read for Response<F, Op, D>
where
    Op::Cfg: Clone,
{
    /// The `max_ops` the request asked for, and the configuration for decoding one operation.
    type Cfg = (usize, Op::Cfg);

    fn read_cfg(buf: &mut impl Buf, (max_ops, op_cfg): &Self::Cfg) -> Result<Self, CodecError> {
        let max_proof_digests = max_ops.saturating_mul(MAX_PROOF_DIGESTS_PER_ELEMENT);
        let proof = Proof::<F, D>::read_cfg(buf, &max_proof_digests)?;
        let operations = Vec::<Op>::read_cfg(buf, &((..=*max_ops).into(), op_cfg.clone()))?;
        // Pins are the fold-prefix peaks at the requested boundary, independent of `max_ops`.
        let pinned_nodes = Option::<Vec<D>>::read_range(buf, ..=MAX_PINNED_NODES)?;
        Ok(Self {
            proof,
            operations,
            pinned_nodes,
        })
    }
}

/// Where to report whether a fetched response verified, so a remote peer can be scored.
///
/// `None` when the response came from local storage, where there is no peer to score.
pub type Validity = Option<oneshot::Sender<bool>>;

/// Anything that can answer request `Req`.
///
/// A database is a source; so is an owned snapshot; so is a lock around either, because
/// wrapping a source yields a source; so is a handle to a remote peer. One implementation of
/// this trait therefore covers both where the data lives and how it is reached.
pub trait Source<Req: Send + 'static>: Send + Sync {
    /// The merkle family backing this source's proofs.
    type Family: Family;

    /// The digest type used in this source's proofs.
    type Digest: Digest;

    /// The type of operations this source yields.
    type Op;

    /// Why this source could not answer.
    type Error: std::error::Error + Send + 'static;

    /// Answer one request.
    ///
    #[allow(clippy::type_complexity)]
    fn serve<'a>(
        &'a self,
        request: Req,
    ) -> impl Future<
        Output = Result<(Response<Self::Family, Self::Op, Self::Digest>, Validity), Self::Error>,
    > + Send
    + 'a;
}

/// An `Arc` around a source is a source.
impl<T, Req> Source<Req> for Arc<T>
where
    T: Source<Req> + ?Sized,
    Req: Send + 'static,
{
    type Family = T::Family;
    type Digest = T::Digest;
    type Op = T::Op;
    type Error = T::Error;

    fn serve<'a>(
        &'a self,
        request: Req,
    ) -> impl Future<
        Output = Result<(Response<Self::Family, Self::Op, Self::Digest>, Validity), Self::Error>,
    > + Send
    + 'a {
        T::serve(self, request)
    }
}

/// A source that may be absent is a source that may report [`ServeError::MissingSource`].
///
/// This is what makes `Arc<Lock<Option<Db>>>` work: the `Option` contributes the missing case,
/// the lock contributes the guard, and the `Arc` is transparent.
impl<T, Req> Source<Req> for Option<T>
where
    T: Source<Req>,
    Req: Send + 'static,
    ServeError<T::Family, T::Digest>: From<T::Error>,
{
    type Family = T::Family;
    type Digest = T::Digest;
    type Op = T::Op;
    type Error = ServeError<T::Family, T::Digest>;

    async fn serve(
        &self,
        request: Req,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, Validity), Self::Error> {
        let source = self.as_ref().ok_or(ServeError::MissingSource)?;
        Ok(source.serve(request).await?)
    }
}

/// A lock around a source is a source.
///
/// The guard is held across the whole call, so a writer cannot prune the pins out from under
/// the proof. A macro rather than one implementation generic over the lock because the two
/// lock types share no trait, and giving them one would make this overlap with the
/// implementation for [`Arc`].
macro_rules! impl_locked_source {
    ($lock:ident) => {
        impl<T, Req> Source<Req> for $lock<T>
        where
            T: Source<Req>,
            Req: Send + 'static,
        {
            type Family = T::Family;
            type Digest = T::Digest;
            type Op = T::Op;
            type Error = T::Error;

            async fn serve(
                &self,
                request: Req,
            ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, Validity), Self::Error> {
                self.read().await.serve(request).await
            }
        }
    };
}

impl_locked_source!(AsyncRwLock);
impl_locked_source!(TracedAsyncRwLock);

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
            (
                $crate::qmdb::sync::resolver::Response<F, Self::Op, H::Digest>,
                $crate::qmdb::sync::resolver::Validity,
            ),
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
            Ok((
                $crate::qmdb::sync::resolver::Response::new(proof, operations, pinned_nodes),
                None,
            ))
        }
    };
}

/// Every `any` database alias resolves to this one generic, so one implementation covers all
/// four of them.
impl<F, E, U, C, I, H, const N: usize, S> Source<Request<F>>
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
impl<F, E, K, V, C, H, T, S> Source<Request<F>>
    for crate::qmdb::immutable::Immutable<F, E, K, V, C, H, T, S>
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
impl<F, E, V, C, H, S> Source<Request<F>> for crate::qmdb::keyless::Keyless<F, E, V, C, H, S>
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
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{
        NZU64,
        sync::{AsyncRwLock, TracedAsyncRwLock},
    };
    use std::{marker::PhantomData, sync::Arc};

    macro_rules! assert_resolver_variants {
        ($db:ty) => {
            assert_serves::<mmr::Family, Arc<$db>>();
            assert_serves::<mmr::Family, Arc<AsyncRwLock<$db>>>();
            assert_serves::<mmr::Family, Arc<AsyncRwLock<Option<$db>>>>();
            assert_serves::<mmr::Family, Arc<TracedAsyncRwLock<$db>>>();
            assert_serves::<mmr::Family, Arc<TracedAsyncRwLock<Option<$db>>>>();
        };
    }

    fn assert_serves<F: Family, R: Source<Request<F>>>() {}

    /// A resolver that always fails.
    pub struct FailResolver<F: Family, Op, D> {
        _phantom: PhantomData<(F, Op, D)>,
    }

    impl<F: Family, Op, D> Clone for FailResolver<F, Op, D> {
        fn clone(&self) -> Self {
            Self {
                _phantom: PhantomData,
            }
        }
    }

    impl<F, Op, D> Source<Request<F>> for FailResolver<F, Op, D>
    where
        F: Family,
        D: Digest,
        Op: Send + Sync + Clone + 'static,
    {
        type Family = F;
        type Digest = D;
        type Op = Op;
        type Error = qmdb::Error<F>;

        async fn serve(
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

    /// A source behind a lock reaches the source and reports its error.
    #[test]
    fn test_locked_source_reaches_source() {
        deterministic::Runner::default().start(|_context| async move {
            let lock = AsyncRwLock::new(FailResolver::<mmr::Family, u8, ShaDigest>::new());

            let request = Request::new(Location::new(1), Location::new(0), NZU64!(1));
            let result = lock.serve(request).await;
            assert!(matches!(result, Err(crate::qmdb::Error::KeyNotFound)));
        });
    }
}
