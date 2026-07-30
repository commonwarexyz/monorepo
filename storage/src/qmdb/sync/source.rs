use crate::{
    Context,
    merkle::{Family, Location, MAX_PINNED_NODES, MAX_PROOF_DIGESTS_PER_ELEMENT, Proof},
    qmdb::{self, operation::Key, sync::ServeError},
    translator::Translator,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize, Error as CodecError, Read, ReadExt as _, ReadRangeExt as _, Write,
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
    const INVALID: &'static str = "start and retain_from must lie within a valid size";

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

    /// Check the field invariants the codec enforces at decode.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.size.is_valid()
            || self.start >= self.size
            || self
                .retain_from
                .is_some_and(|boundary| boundary > self.size)
        {
            return Err(Self::INVALID);
        }
        Ok(())
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

impl<F: Family> PartialEq for Request<F> {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size
            && self.start == other.start
            && self.max_ops == other.max_ops
            && self.retain_from == other.retain_from
    }
}

impl<F: Family> Eq for Request<F> {}

impl<F: Family> PartialOrd for Request<F> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: Family> Ord for Request<F> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.size
            .cmp(&other.size)
            .then_with(|| self.start.cmp(&other.start))
            .then_with(|| self.max_ops.cmp(&other.max_ops))
            .then_with(|| self.retain_from.cmp(&other.retain_from))
    }
}

impl<F: Family> std::hash::Hash for Request<F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.size.hash(state);
        self.start.hash(state);
        self.max_ops.hash(state);
        self.retain_from.hash(state);
    }
}

impl<F: Family> std::fmt::Display for Request<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Request(size={}, start={}, max_ops={}, retain_from=",
            self.size, self.start, self.max_ops,
        )?;
        match self.retain_from {
            Some(boundary) => write!(f, "{boundary})"),
            None => write!(f, "none)"),
        }
    }
}

impl<F: Family> Write for Request<F> {
    fn write(&self, buf: &mut impl BufMut) {
        self.size.write(buf);
        self.start.write(buf);
        self.max_ops.get().write(buf);
        self.retain_from.write(buf);
    }
}

impl<F: Family> EncodeSize for Request<F> {
    fn encode_size(&self) -> usize {
        self.size.encode_size()
            + self.start.encode_size()
            + self.max_ops.get().encode_size()
            + self.retain_from.encode_size()
    }
}

impl<F: Family> Read for Request<F> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let size = Location::<F>::read(buf)?;
        let start = Location::<F>::read(buf)?;
        let max_ops = NonZeroU64::new(u64::read(buf)?).ok_or(CodecError::Invalid(
            "storage::qmdb::sync::source::Request",
            "max_ops cannot be zero",
        ))?;
        let retain_from = Option::<Location<F>>::read(buf)?;
        let request = Self {
            size,
            start,
            max_ops,
            retain_from,
        };
        request.validate().map_err(|reason| {
            CodecError::Invalid("storage::qmdb::sync::source::Request", reason)
        })?;
        Ok(request)
    }
}

impl<F: Family> commonware_utils::Span for Request<F> {}

#[cfg(feature = "arbitrary")]
impl<F: Family> arbitrary::Arbitrary<'_> for Request<F> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let size = u.int_in_range(1..=*F::MAX_LEAVES)?;
        let start = Location::new(u.int_in_range(0..=size - 1)?);
        let max_ops = NonZeroU64::new(u.int_in_range(1..=u64::MAX)?).unwrap();
        let retain_from = u
            .arbitrary::<bool>()?
            .then(|| u.int_in_range(0..=size).map(Location::new))
            .transpose()?;
        Ok(Self {
            size: Location::new(size),
            start,
            max_ops,
            retain_from,
        })
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

/// Decode limits for a [`Response`], derived from the request it answers.
///
/// Named fields so an absolute digest cap cannot be mistaken for an operation count and then
/// multiplied into a much larger proof allowance.
#[derive(Clone, Debug)]
pub struct ResponseConfig<C> {
    /// Maximum operations the request asked for.
    pub max_ops: usize,
    /// Absolute cap on proof digests, independent of `max_ops`.
    pub max_proof_digests: usize,
    /// Configuration for decoding one operation.
    pub op: C,
}

impl<C> ResponseConfig<C> {
    /// Limits for a decoder that knows the request it is answering, where the per-request
    /// proof bound is the only cap.
    pub const fn request_bounded(max_ops: usize, op: C) -> Self {
        Self {
            max_ops,
            max_proof_digests: max_ops.saturating_mul(MAX_PROOF_DIGESTS_PER_ELEMENT),
            op,
        }
    }
}

impl<F: Family, Op: Read, D: Digest> Read for Response<F, Op, D>
where
    Op::Cfg: Clone,
{
    type Cfg = ResponseConfig<Op::Cfg>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let max_proof_digests = cfg
            .max_proof_digests
            .min(cfg.max_ops.saturating_mul(MAX_PROOF_DIGESTS_PER_ELEMENT));
        let (max_ops, op_cfg) = (&cfg.max_ops, &cfg.op);
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

#[cfg(feature = "arbitrary")]
impl<F: Family, Op, D: Digest> arbitrary::Arbitrary<'_> for Response<F, Op, D>
where
    Op: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            proof: u.arbitrary()?,
            operations: u.arbitrary()?,
            pinned_nodes: u.arbitrary()?,
        })
    }
}

/// Where to report whether a fetched response verified, so a remote peer can be scored.
///
/// `None` when there is no peer to score, e.g. the response came from local storage.
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
            ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, Validity), Self::Error>
            {
                self.read().await.serve(request).await
            }
        }
    };
}

impl_locked_source!(AsyncRwLock);
impl_locked_source!(TracedAsyncRwLock);

/// Answer a [`Request`] from a database's inherent proof reads.
///
/// Written once and expanded by each [`Source`] implementation below. The two reads
/// belong to one answer: the pins are only meaningful because the proof in the same response
/// authenticates them.
macro_rules! serve_request {
    () => {
        async fn serve(
            &self,
            request: $crate::qmdb::sync::source::Request<F>,
        ) -> Result<
            (
                $crate::qmdb::sync::source::Response<F, Self::Op, H::Digest>,
                $crate::qmdb::sync::source::Validity,
            ),
            $crate::qmdb::Error<F>,
        > {
            let (proof, operations) = self
                .historical_proof(request.size, request.start, request.max_ops)
                .await?;
            let pinned_nodes = match request.retain_from {
                Some(boundary) => Some(self.pinned_nodes_at(boundary).await?),
                None => None,
            };
            Ok((
                $crate::qmdb::sync::source::Response::new(proof, operations, pinned_nodes),
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
    C: crate::journal::contiguous::Mutable<Item = crate::qmdb::immutable::Operation<F, K, V>>
        + Send
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
    use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
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
            assert_serves::<mmr::Family, Arc<$db>>();
            assert_serves::<mmr::Family, Arc<AsyncRwLock<$db>>>();
            assert_serves::<mmr::Family, Arc<AsyncRwLock<Option<$db>>>>();
            assert_serves::<mmr::Family, Arc<TracedAsyncRwLock<$db>>>();
            assert_serves::<mmr::Family, Arc<TracedAsyncRwLock<Option<$db>>>>();
        };
    }

    fn assert_serves<F: Family, S: Source<Request<F>>>() {}

    /// A source that always fails. Not `Clone`, which the engine must not require.
    pub struct FailSource<F: Family, Op, D> {
        _phantom: PhantomData<(F, Op, D)>,
    }

    impl<F, Op, D> Source<Request<F>> for FailSource<F, Op, D>
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
    }

    /// The codec rejects requests whose fields contradict each other.
    #[test]
    fn test_request_decode_rejects_contradictions() {
        let valid = Request::<mmr::Family>::new(Location::new(128), Location::new(64), NZU64!(16));
        assert_eq!(Request::<mmr::Family>::decode(valid.encode()).unwrap(), valid);

        // start >= size
        let mut bad = valid;
        bad.start = Location::new(128);
        assert!(Request::<mmr::Family>::decode(bad.encode()).is_err());

        // retain_from > size
        let bad = valid.retaining_from(Location::new(129));
        assert!(Request::<mmr::Family>::decode(bad.encode()).is_err());

        // retain_from at the tip is allowed
        let tip = valid.retaining_from(Location::new(128));
        assert_eq!(Request::<mmr::Family>::decode(tip.encode()).unwrap(), tip);

        // max_ops = 0 is unrepresentable via the constructor, so reject it at the byte level
        let mut zero_max = Vec::new();
        valid.size.write(&mut zero_max);
        valid.start.write(&mut zero_max);
        0u64.write(&mut zero_max);
        valid.retain_from.write(&mut zero_max);
        assert!(Request::<mmr::Family>::decode(zero_max.as_slice()).is_err());
    }

    /// Pins ride outside the operation-count limit: a one-op response may carry many pins.
    #[test]
    fn test_response_decode_allows_pinned_nodes_above_max_ops() {
        let response = Response::<mmr::Family, u64, ShaDigest>::new(
            Proof {
                leaves: Location::new(10),
                inactive_peaks: 0,
                digests: vec![ShaDigest::from([7; 32])],
            },
            vec![1],
            Some(vec![ShaDigest::from([9; 32]); 3]),
        );
        let cfg = ResponseConfig {
            max_ops: 1,
            max_proof_digests: usize::MAX,
            op: (),
        };
        let decoded =
            Response::<mmr::Family, u64, ShaDigest>::decode_cfg(response.encode(), &cfg).unwrap();
        assert_eq!(decoded.operations, vec![1]);
        assert_eq!(decoded.pinned_nodes.unwrap().len(), 3);
    }

    #[test]
    fn test_response_decode_absolute_digest_cap_tightens() {
        let response = Response::<mmr::Family, u64, ShaDigest>::new(
            Proof {
                leaves: Location::new(10),
                inactive_peaks: 0,
                digests: vec![ShaDigest::from([7; 32]); 3],
            },
            vec![1],
            None,
        );
        let cfg = ResponseConfig {
            max_ops: 1,
            max_proof_digests: 2,
            op: (),
        };
        assert!(
            Response::<mmr::Family, u64, ShaDigest>::decode_cfg(response.encode(), &cfg).is_err()
        );
    }

    /// A response carrying exactly the per-request digest cap decodes.
    #[test]
    fn test_response_decode_allows_max_proof_digests() {
        let response = Response::<mmr::Family, u64, ShaDigest>::new(
            Proof {
                leaves: Location::new(10),
                inactive_peaks: 0,
                digests: vec![ShaDigest::from([7; 32]); MAX_PROOF_DIGESTS_PER_ELEMENT],
            },
            vec![1],
            None,
        );
        let cfg = ResponseConfig::request_bounded(1, ());
        let decoded =
            Response::<mmr::Family, u64, ShaDigest>::decode_cfg(response.encode(), &cfg).unwrap();
        assert_eq!(decoded.proof.digests.len(), MAX_PROOF_DIGESTS_PER_ELEMENT);
    }

    /// The pinned-nodes flag must be exactly 0 or 1 on the wire.
    #[test]
    fn test_response_decode_rejects_invalid_pins_flag() {
        let response = Response::<mmr::Family, u64, ShaDigest>::new(
            Proof {
                leaves: Location::new(10),
                inactive_peaks: 0,
                digests: vec![ShaDigest::from([7; 32])],
            },
            vec![1],
            None,
        );
        let mut bytes = response.encode().to_vec();
        *bytes.last_mut().unwrap() = 2;
        let cfg = ResponseConfig::request_bounded(1, ());
        assert!(
            Response::<mmr::Family, u64, ShaDigest>::decode_cfg(bytes.as_slice(), &cfg).is_err()
        );
    }

    /// A source behind a lock reaches the source and reports its error.
    #[test]
    fn test_locked_source_reaches_source() {
        deterministic::Runner::default().start(|_context| async move {
            let lock = AsyncRwLock::new(FailSource::<mmr::Family, u8, ShaDigest>::new());

            let request = Request::new(Location::new(1), Location::new(0), NZU64!(1));
            let result = lock.serve(request).await;
            assert!(matches!(result, Err(crate::qmdb::Error::KeyNotFound)));
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
        CodecConformance<Request<mmr::Family>>,
        CodecConformance<Request<mmb::Family>>,
        CodecConformance<Response<mmr::Family, u64, Sha256Digest>>,
        CodecConformance<Response<mmb::Family, u64, Sha256Digest>>,
    }
}
