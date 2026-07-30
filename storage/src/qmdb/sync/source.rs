use crate::{
    Context,
    journal::{authenticated, contiguous::Contiguous},
    merkle::{Family, Location, Proof},
    qmdb::{
        self,
        operation::{Floored, Key},
        sync::ServeError,
    },
    translator::Translator,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{
    channel::oneshot,
    sync::{AsyncRwLock, TracedAsyncRwLock},
};
use std::{future::Future, num::NonZeroU64, sync::Arc};

/// A request for operations from a source's log.
pub enum Request<F: Family> {
    /// Fetch the operations in `[start, start + max_ops)`.
    Operations {
        /// Prove against the root the merkle structure had at this many operations.
        size: Location<F>,
        /// First operation to return.
        start: Location<F>,
        /// Maximum number of operations to return.
        max_ops: NonZeroU64,
    },
    /// Fetch the single operation at `start` plus the pins at that boundary, the lowest
    /// location the client will retain. The proof in the response authenticates the pins,
    /// so there is no way to request them on their own.
    Boundary {
        /// Prove against the root the merkle structure had at this many operations.
        size: Location<F>,
        /// The operation to return, which is also the pin boundary.
        start: Location<F>,
    },
}

impl<F: Family> Request<F> {
    /// The size whose root the response's proof must verify against.
    pub const fn size(&self) -> Location<F> {
        match self {
            Self::Operations { size, .. } | Self::Boundary { size, .. } => *size,
        }
    }

    /// First operation to return.
    pub const fn start(&self) -> Location<F> {
        match self {
            Self::Operations { start, .. } | Self::Boundary { start, .. } => *start,
        }
    }

    /// Maximum number of operations to return.
    pub const fn max_ops(&self) -> NonZeroU64 {
        match self {
            Self::Operations { max_ops, .. } => *max_ops,
            Self::Boundary { .. } => NonZeroU64::MIN,
        }
    }

    /// The boundary whose pins the response must carry, if any.
    pub const fn retain_from(&self) -> Option<Location<F>> {
        match self {
            Self::Operations { .. } => None,
            Self::Boundary { start, .. } => Some(*start),
        }
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
        match self {
            Self::Operations {
                size,
                start,
                max_ops,
            } => f
                .debug_struct("Operations")
                .field("size", size)
                .field("start", start)
                .field("max_ops", max_ops)
                .finish(),
            Self::Boundary { size, start } => f
                .debug_struct("Boundary")
                .field("size", size)
                .field("start", start)
                .finish(),
        }
    }
}

/// One authenticated response, shaped like the [`Request`] it answers.
///
/// In a [`Response::Boundary`], the proof, the operation, and the pins are verified as a
/// unit: the pins are only believable because the proof folds them into digests it already
/// commits to.
pub enum Response<F: Family, Op, D: Digest> {
    /// Answer to a [`Request::Operations`].
    Operations {
        /// Proof authenticating `operations` against the root at the requested size.
        proof: Proof<F, D>,
        /// The operations that were fetched.
        operations: Vec<Op>,
    },
    /// Answer to a [`Request::Boundary`].
    Boundary {
        /// Proof authenticating `op` against the root at the requested size.
        proof: Proof<F, D>,
        /// The operation at the requested boundary.
        op: Op,
        /// Pins at the requested boundary.
        pins: Vec<D>,
    },
}

impl<F: Family, Op, D: Digest> Response<F, Op, D> {
    /// The proof authenticating this response.
    pub const fn proof(&self) -> &Proof<F, D> {
        match self {
            Self::Operations { proof, .. } | Self::Boundary { proof, .. } => proof,
        }
    }
}

impl<F: Family, Op: Clone, D: Digest> Clone for Response<F, Op, D> {
    fn clone(&self) -> Self {
        match self {
            Self::Operations { proof, operations } => Self::Operations {
                proof: proof.clone(),
                operations: operations.clone(),
            },
            Self::Boundary { proof, op, pins } => Self::Boundary {
                proof: proof.clone(),
                op: op.clone(),
                pins: pins.clone(),
            },
        }
    }
}

impl<F: Family, Op: std::fmt::Debug, D: Digest> std::fmt::Debug for Response<F, Op, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operations { proof, operations } => f
                .debug_struct("Operations")
                .field("proof", proof)
                .field("operations", operations)
                .finish(),
            Self::Boundary { proof, op, pins } => f
                .debug_struct("Boundary")
                .field("proof", proof)
                .field("op", op)
                .field("pins", pins)
                .finish(),
        }
    }
}

/// Where to report whether a fetched response verified, so a remote peer can be given feedback.
/// `None` means the answer is final: an invalid response fails the sync instead of being
/// retried, because a source that accepts no feedback cannot serve a different answer.
pub type ValidityTx = Option<oneshot::Sender<bool>>;

/// A source for proofs and operations.
pub trait Source: Send + Sync {
    /// The merkle family backing this source's proofs.
    type Family: Family;

    /// The digest type used in this source's proofs.
    type Digest: Digest;

    /// The type of operations this source yields.
    type Op;

    /// Why this source could not answer.
    type Error: std::error::Error + Send + 'static;

    /// Answer one request.
    #[allow(clippy::type_complexity)]
    fn serve<'a>(
        &'a self,
        request: Request<Self::Family>,
    ) -> impl Future<
        Output = Result<(Response<Self::Family, Self::Op, Self::Digest>, ValidityTx), Self::Error>,
    > + Send
    + 'a;
}

impl<T> Source for Arc<T>
where
    T: Source + ?Sized,
{
    type Family = T::Family;
    type Digest = T::Digest;
    type Op = T::Op;
    type Error = T::Error;

    fn serve<'a>(
        &'a self,
        request: Request<Self::Family>,
    ) -> impl Future<
        Output = Result<(Response<Self::Family, Self::Op, Self::Digest>, ValidityTx), Self::Error>,
    > + Send
    + 'a {
        T::serve(self, request)
    }
}

impl<T> Source for Option<T>
where
    T: Source,
    ServeError<T::Family>: From<T::Error>,
{
    type Family = T::Family;
    type Digest = T::Digest;
    type Op = T::Op;
    type Error = ServeError<T::Family>;

    async fn serve(
        &self,
        request: Request<Self::Family>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, ValidityTx), Self::Error> {
        let source = self.as_ref().ok_or(ServeError::MissingSource)?;
        Ok(source.serve(request).await?)
    }
}

macro_rules! impl_locked_source {
    ($lock:ident) => {
        impl<T> Source for $lock<T>
        where
            T: Source,
        {
            type Family = T::Family;
            type Digest = T::Digest;
            type Op = T::Op;
            type Error = T::Error;

            async fn serve(
                &self,
                request: Request<Self::Family>,
            ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, ValidityTx), Self::Error>
            {
                self.read().await.serve(request).await
            }
        }
    };
}

impl_locked_source!(AsyncRwLock);
impl_locked_source!(TracedAsyncRwLock);

impl<F, E, C, H, S> Source for authenticated::Journal<F, E, C, H, S>
where
    F: Family,
    E: Context,
    C: Contiguous<Item: EncodeShared + Floored<F>>,
    H: Hasher,
    S: Strategy,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = C::Item;
    type Error = qmdb::Error<F>;

    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.sync.serve",
        level = "info",
        skip_all,
        fields(
            size = *request.size(),
            start = *request.start(),
            max_ops = request.max_ops().get(),
        ),
    )]
    async fn serve(
        &self,
        request: Request<F>,
    ) -> Result<(Response<F, C::Item, H::Digest>, ValidityTx), qmdb::Error<F>> {
        // Reject before the floor lookup so the error carries the requested size and the
        // floor read never touches out-of-range locations.
        if request.size() > self.size() {
            return Err(crate::merkle::Error::RangeOutOfBounds(request.size()).into());
        }
        let inactive_peaks = qmdb::inactive_peaks_at::<F, _>(self, request.size()).await?;
        let response = match request {
            Request::Operations {
                size,
                start,
                max_ops,
            } => {
                let (proof, operations) = self
                    .historical_proof(size, start, max_ops, inactive_peaks)
                    .await?;
                Response::Operations { proof, operations }
            }
            Request::Boundary { size, start } => {
                let (proof, mut operations) = self
                    .historical_proof(size, start, NonZeroU64::MIN, inactive_peaks)
                    .await?;
                let op = operations
                    .pop()
                    .ok_or(crate::merkle::Error::RangeOutOfBounds(start))?;
                let pins = self.merkle.pinned_nodes_at(start).await?;
                Response::Boundary { proof, op, pins }
            }
        };
        Ok((response, None))
    }
}

impl<F, E, U, C, I, H, const N: usize, S> Source
    for crate::qmdb::any::db::Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    U: crate::qmdb::any::operation::update::Update,
    C: crate::journal::contiguous::Mutable<Item = crate::qmdb::any::operation::Operation<F, U>>,
    I: crate::index::Unordered<Value = Location<F>> + Send + Sync,
    H: Hasher,
    S: Strategy,
    crate::qmdb::any::operation::Operation<F, U>: commonware_codec::Codec,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = crate::qmdb::any::operation::Operation<F, U>;
    type Error = qmdb::Error<F>;

    async fn serve(
        &self,
        request: Request<F>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, ValidityTx), Self::Error> {
        self.log.serve(request).await
    }
}
impl<F, E, K, V, C, H, T, S> Source for crate::qmdb::immutable::Immutable<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: crate::qmdb::any::value::ValueEncoding,
    C: crate::journal::contiguous::Mutable<Item = crate::qmdb::immutable::Operation<F, K, V>>,
    C::Item: commonware_codec::EncodeShared,
    H: Hasher,
    T: Translator + Send + Sync,
    T::Key: Send + Sync,
    S: Strategy,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = crate::qmdb::immutable::Operation<F, K, V>;
    type Error = qmdb::Error<F>;

    async fn serve(
        &self,
        request: Request<F>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, ValidityTx), Self::Error> {
        self.journal.serve(request).await
    }
}

impl<F, E, V, C, H, S> Source for crate::qmdb::keyless::Keyless<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: crate::qmdb::any::value::ValueEncoding,
    C: crate::journal::contiguous::Mutable<Item = crate::qmdb::keyless::Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    crate::qmdb::keyless::Operation<F, V>: commonware_codec::EncodeShared,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = crate::qmdb::keyless::Operation<F, V>;
    type Error = qmdb::Error<F>;

    async fn serve(
        &self,
        request: Request<F>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, ValidityTx), Self::Error> {
        self.journal.serve(request).await
    }
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

    macro_rules! assert_source_variants {
        ($db:ty) => {
            assert_serves::<Arc<$db>>();
            assert_serves::<Arc<AsyncRwLock<$db>>>();
            assert_serves::<Arc<AsyncRwLock<Option<$db>>>>();
            assert_serves::<Arc<TracedAsyncRwLock<$db>>>();
            assert_serves::<Arc<TracedAsyncRwLock<Option<$db>>>>();
        };
    }

    fn assert_serves<S: Source>() {}

    /// A source that always fails. Not `Clone`, which the engine must not require.
    pub struct FailSource<F: Family, Op, D> {
        _phantom: PhantomData<(F, Op, D)>,
    }

    impl<F, Op, D> Source for FailSource<F, Op, D>
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
        ) -> Result<(Response<F, Op, D>, ValidityTx), qmdb::Error<F>> {
            Err(qmdb::Error::KeyNotFound) // Arbitrary dummy error
        }
    }

    impl<F: Family, Op, D> FailSource<F, Op, D> {
        pub fn new() -> Self {
            Self {
                _phantom: PhantomData,
            }
        }
    }

    #[test]
    fn test_all_qmdb_variants_implement_source() {
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

        assert_source_variants!(AnyOrderedFixed);
        assert_source_variants!(AnyOrderedVariable);
        assert_source_variants!(AnyUnorderedFixed);
        assert_source_variants!(AnyUnorderedVariable);
        assert_source_variants!(CurrentOrderedFixed);
        assert_source_variants!(CurrentOrderedVariable);
        assert_source_variants!(CurrentUnorderedFixed);
        assert_source_variants!(CurrentUnorderedVariable);
        assert_source_variants!(ImmutableFixed);
        assert_source_variants!(ImmutableVariable);
        assert_source_variants!(KeylessFixed);
        assert_source_variants!(KeylessVariable);

        type KeylessFixedCompactDb = crate::qmdb::keyless::fixed::CompactDb<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Sha256,
            Rayon,
        >;
        type KeylessVariableCompactDb = crate::qmdb::keyless::variable::CompactDb<
            mmr::Family,
            deterministic::Context,
            Vec<u8>,
            Sha256,
            (commonware_codec::RangeCfg<usize>, ()),
            Rayon,
        >;
        type ImmutableFixedCompactDb = crate::qmdb::immutable::fixed::CompactDb<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            ShaDigest,
            Sha256,
            Rayon,
        >;
        type ImmutableVariableCompactDb = crate::qmdb::immutable::variable::CompactDb<
            mmr::Family,
            deterministic::Context,
            ShaDigest,
            Vec<u8>,
            Sha256,
            ((), (commonware_codec::RangeCfg<usize>, ())),
            Rayon,
        >;

        assert_source_variants!(KeylessFixedCompactDb);
        assert_source_variants!(KeylessVariableCompactDb);
        assert_source_variants!(ImmutableFixedCompactDb);
        assert_source_variants!(ImmutableVariableCompactDb);
    }

    /// A source behind a lock reaches the source and reports its error.
    #[test]
    fn test_locked_source_reaches_source() {
        deterministic::Runner::default().start(|_context| async move {
            let lock = AsyncRwLock::new(FailSource::<mmr::Family, u8, ShaDigest>::new());

            let request = Request::Operations {
                size: Location::new(1),
                start: Location::new(0),
                max_ops: NZU64!(1),
            };
            let result = lock.serve(request).await;
            assert!(matches!(result, Err(crate::qmdb::Error::KeyNotFound)));
        });
    }
}
