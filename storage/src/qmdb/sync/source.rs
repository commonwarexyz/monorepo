use crate::{
    Context,
    journal::{authenticated, contiguous::Contiguous},
    merkle::{Family, Location, MAX_PINNED_NODES, MAX_PROOF_DIGESTS_PER_ELEMENT, Proof},
    qmdb::{self, operation::Floored, sync::ServeError},
};
use bytes::BufMut;
use commonware_codec::{
    Buf, EncodeShared, EncodeSize, Error as CodecError, Read, ReadExt as _, ReadRangeExt as _,
    Write,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{
    Span,
    channel::{mpsc, oneshot},
    sync::{AsyncRwLock, TracedAsyncRwLock},
};
use std::{cmp::Ordering, future::Future, num::NonZeroU64, sync::Arc};

/// A request for operations from a source's log.
pub enum Request<F: Family> {
    /// Fetch the operations in `[start, start + max_ops)`.
    Operations {
        /// Prove against the root the database had at this size.
        size: Location<F>,
        /// First operation to return.
        start: Location<F>,
        /// Maximum number of operations to return.
        max_ops: NonZeroU64,
    },
    /// Fetch the single operation at `start` plus the pinned nodes at `start`, the lowest
    /// location the client will retain. The proof in the response authenticates the pinned nodes,
    /// so there is no way to request them on their own.
    Boundary {
        /// Prove against the root the database had at this size.
        size: Location<F>,
        /// The operation to return, which is also the location of the returned pinned nodes.
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

    /// Total-order key for map lookups. The final component separates the variants.
    fn order_key(&self) -> (u64, u64, u64, bool) {
        (
            *self.size(),
            *self.start(),
            self.max_ops().get(),
            matches!(self, Self::Boundary { .. }),
        )
    }
}

impl<F: Family> Clone for Request<F> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: Family> Copy for Request<F> {}

impl<F: Family> PartialEq for Request<F> {
    fn eq(&self, other: &Self) -> bool {
        self.order_key() == other.order_key()
    }
}

impl<F: Family> Eq for Request<F> {}

impl<F: Family> PartialOrd for Request<F> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: Family> Ord for Request<F> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.order_key().cmp(&other.order_key())
    }
}

impl<F: Family> std::hash::Hash for Request<F> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.order_key().hash(state);
    }
}

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

impl<F: Family> std::fmt::Display for Request<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operations {
                size,
                start,
                max_ops,
            } => write!(f, "Operations(size={size}, start={start}, max={max_ops})"),
            Self::Boundary { size, start } => write!(f, "Boundary(size={size}, start={start})"),
        }
    }
}

impl<F: Family> Write for Request<F> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Operations {
                size,
                start,
                max_ops,
            } => {
                0u8.write(buf);
                size.write(buf);
                start.write(buf);
                max_ops.write(buf);
            }
            Self::Boundary { size, start } => {
                1u8.write(buf);
                size.write(buf);
                start.write(buf);
            }
        }
    }
}

impl<F: Family> EncodeSize for Request<F> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Operations {
                size,
                start,
                max_ops,
            } => size.encode_size() + start.encode_size() + max_ops.encode_size(),
            Self::Boundary { size, start } => size.encode_size() + start.encode_size(),
        }
    }
}

impl<F: Family> Read for Request<F> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> std::result::Result<Self, CodecError> {
        let request = match u8::read(buf)? {
            0 => Self::Operations {
                size: Location::<F>::read(buf)?,
                start: Location::<F>::read(buf)?,
                max_ops: NonZeroU64::read(buf)?,
            },
            1 => Self::Boundary {
                size: Location::<F>::read(buf)?,
                start: Location::<F>::read(buf)?,
            },
            d => return Err(CodecError::InvalidEnum(d)),
        };
        if request.start() >= request.size() {
            return Err(CodecError::Invalid("Request", "start >= size"));
        }
        Ok(request)
    }
}

impl<F: Family> Span for Request<F> {}

#[cfg(feature = "arbitrary")]
impl<F: Family> arbitrary::Arbitrary<'_> for Request<F> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let size = u.int_in_range(1..=*F::MAX_LEAVES)?;
        let start = u.int_in_range(0..=size - 1)?;
        let size = Location::new(size);
        let start = Location::new(start);
        Ok(if u.arbitrary()? {
            Self::Boundary { size, start }
        } else {
            Self::Operations {
                size,
                start,
                max_ops: u.arbitrary()?,
            }
        })
    }
}

/// One response, shaped like the [`Request`] it answers.
///
/// In a [`Response::Boundary`], the proof, the operation, and the pinned nodes are verified as a
/// unit. The pinned nodes are only believable because the proof folds them into digests it already
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
        /// Pinned nodes at the requested location.
        pinned_nodes: Vec<D>,
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
            Self::Boundary {
                proof,
                op,
                pinned_nodes,
            } => Self::Boundary {
                proof: proof.clone(),
                op: op.clone(),
                pinned_nodes: pinned_nodes.clone(),
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
            Self::Boundary {
                proof,
                op,
                pinned_nodes,
            } => f
                .debug_struct("Boundary")
                .field("proof", proof)
                .field("op", op)
                .field("pinned_nodes", pinned_nodes)
                .finish(),
        }
    }
}

impl<F: Family, Op: Write, D: Digest> Write for Response<F, Op, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Operations { proof, operations } => {
                0u8.write(buf);
                proof.write(buf);
                operations.write(buf);
            }
            Self::Boundary {
                proof,
                op,
                pinned_nodes,
            } => {
                1u8.write(buf);
                proof.write(buf);
                op.write(buf);
                pinned_nodes.write(buf);
            }
        }
    }
}

impl<F: Family, Op: EncodeSize, D: Digest> EncodeSize for Response<F, Op, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Operations { proof, operations } => {
                proof.encode_size() + operations.encode_size()
            }
            Self::Boundary {
                proof,
                op,
                pinned_nodes,
            } => proof.encode_size() + op.encode_size() + pinned_nodes.encode_size(),
        }
    }
}

impl<F: Family, Op: Read, D: Digest> Read for Response<F, Op, D> {
    /// The `max_ops` the request asked for, and the configuration for decoding one operation.
    type Cfg = (usize, Op::Cfg);

    fn read_cfg(
        buf: &mut impl Buf,
        (max_ops, op_cfg): &Self::Cfg,
    ) -> std::result::Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => {
                let max_proof_digests = max_ops.saturating_mul(MAX_PROOF_DIGESTS_PER_ELEMENT);
                let proof = Proof::<F, D>::read_cfg(buf, &max_proof_digests)?;
                let operations = Vec::<Op>::read_cfg(buf, &((..=*max_ops).into(), op_cfg.clone()))?;
                Ok(Self::Operations { proof, operations })
            }
            1 => {
                let proof = Proof::<F, D>::read_cfg(buf, &MAX_PROOF_DIGESTS_PER_ELEMENT)?;
                let op = Op::read_cfg(buf, op_cfg)?;
                let pinned_nodes = Vec::<D>::read_range(buf, ..=MAX_PINNED_NODES)?;
                Ok(Self::Boundary {
                    proof,
                    op,
                    pinned_nodes,
                })
            }
            d => Err(CodecError::InvalidEnum(d)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<F: Family, Op, D: Digest> arbitrary::Arbitrary<'_> for Response<F, Op, D>
where
    Op: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(if u.arbitrary()? {
            Self::Boundary {
                proof: u.arbitrary()?,
                op: u.arbitrary()?,
                pinned_nodes: u.arbitrary()?,
            }
        } else {
            Self::Operations {
                proof: u.arbitrary()?,
                operations: u.arbitrary()?,
            }
        })
    }
}

/// Reports whether a response's proof is valid and retains the request for another candidate.
///
/// Feedback does not report whether the response was applied or persisted. Dropping it leaves the
/// response unjudged and cancels the request.
pub struct Feedback<R> {
    sender: oneshot::Sender<bool>,
    receiver: mpsc::Receiver<(R, oneshot::Sender<bool>)>,
}

impl<R> Feedback<R> {
    /// Creates feedback for one response and its request's later candidates.
    pub const fn new(
        sender: oneshot::Sender<bool>,
        receiver: mpsc::Receiver<(R, oneshot::Sender<bool>)>,
    ) -> Self {
        Self { sender, receiver }
    }

    /// Reports that the response's proof is valid and closes the request.
    pub fn accept(self) {
        let _ = self.sender.send(true);
    }

    /// Reports that the response's proof is invalid and waits for the next candidate.
    pub async fn reject(self) -> Option<(R, Self)> {
        let Self {
            sender,
            mut receiver,
        } = self;
        sender.send(false).ok()?;
        let (response, sender) = receiver.recv().await?;
        Some((response, Self { sender, receiver }))
    }
}

/// The response type of a [`Source`].
pub type ResponseOf<S> = Response<<S as Source>::Family, <S as Source>::Op, <S as Source>::Digest>;

/// The result of [`Source::serve`].
pub type Result<S> =
    std::result::Result<(ResponseOf<S>, Option<Feedback<ResponseOf<S>>>), <S as Source>::Error>;

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

    /// Serves a response with optional [`Feedback`] for reporting its validity.
    ///
    /// Dropping the future or feedback cancels the request without judging the response.
    fn serve(&self, request: Request<Self::Family>) -> impl Future<Output = Result<Self>> + Send;
}

impl<T> Source for Arc<T>
where
    T: Source + ?Sized,
{
    type Family = T::Family;
    type Digest = T::Digest;
    type Op = T::Op;
    type Error = T::Error;

    fn serve(&self, request: Request<Self::Family>) -> impl Future<Output = Result<Self>> + Send {
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

    async fn serve(&self, request: Request<Self::Family>) -> Result<Self> {
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

            async fn serve(&self, request: Request<Self::Family>) -> Result<Self> {
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
    async fn serve(&self, request: Request<F>) -> Result<Self> {
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
                let pinned_nodes = self.merkle.pinned_nodes_at(start).await?;
                Response::Boundary {
                    proof,
                    op,
                    pinned_nodes,
                }
            }
        };
        Ok((response, None))
    }
}

impl<F, E, C, I, H, U, const N: usize, S> Source
    for crate::qmdb::any::db::Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    C: crate::journal::contiguous::Mutable<Item = crate::qmdb::any::operation::Operation<F, U>>,
    I: crate::index::Unordered<Value = Location<F>>,
    H: Hasher,
    U: crate::qmdb::any::operation::update::Update,
    S: Strategy,
    crate::qmdb::any::operation::Operation<F, U>: commonware_codec::Codec,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = crate::qmdb::any::operation::Operation<F, U>;
    type Error = qmdb::Error<F>;

    async fn serve(&self, request: Request<F>) -> Result<Self> {
        self.log.serve(request).await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        merkle::mmr,
        translator::{OneCap, TwoCap},
    };
    use commonware_codec::{Copying, Decode as _, DecodeExt as _, Encode as _};
    use commonware_cryptography::{Sha256, sha256::Digest as ShaDigest};
    use commonware_parallel::Rayon;
    use commonware_runtime::{Runner as _, Spawner as _, Supervisor as _, deterministic};
    use commonware_utils::{
        NZU64,
        sync::{AsyncRwLock, Mutex, TracedAsyncRwLock},
    };
    use std::{marker::PhantomData, mem, sync::Arc};

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

    /// A source that offers a fixed response sequence for one request.
    #[derive(Clone)]
    pub struct SequenceSource<F: Family, Op, D: Digest> {
        responses: Arc<Mutex<Vec<Response<F, Op, D>>>>,
        verdicts: Arc<Mutex<Vec<oneshot::Receiver<bool>>>>,
    }

    impl<F: Family, Op, D: Digest> SequenceSource<F, Op, D> {
        pub fn new(responses: Vec<Response<F, Op, D>>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses)),
                verdicts: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Collects the reported verdicts, omitting unjudged responses.
        pub async fn take_verdicts(&self) -> Vec<bool> {
            let receivers = mem::take(&mut *self.verdicts.lock());
            let mut verdicts = Vec::with_capacity(receivers.len());
            for receiver in receivers {
                if let Ok(verdict) = receiver.await {
                    verdicts.push(verdict);
                }
            }
            verdicts
        }
    }

    impl<F, Op, D> Source for SequenceSource<F, Op, D>
    where
        F: Family,
        D: Digest,
        Op: Send,
    {
        type Family = F;
        type Digest = D;
        type Op = Op;
        type Error = qmdb::Error<F>;

        async fn serve(&self, _request: Request<F>) -> Result<Self> {
            let mut responses = mem::take(&mut *self.responses.lock()).into_iter();
            let response = responses.next().ok_or(qmdb::Error::KeyNotFound)?;
            let (candidate_tx, candidate_rx) = mpsc::channel(responses.len().max(1));
            let (verdict_tx, verdict_rx) = oneshot::channel();
            let mut verdicts = self.verdicts.lock();
            verdicts.push(verdict_rx);
            for response in responses {
                let (verdict_tx, verdict_rx) = oneshot::channel();
                assert!(candidate_tx.try_send((response, verdict_tx)).is_ok());
                verdicts.push(verdict_rx);
            }
            Ok((response, Some(Feedback::new(verdict_tx, candidate_rx))))
        }
    }

    async fn next_candidate<R>(
        verdict_rx: oneshot::Receiver<bool>,
        candidate_tx: mpsc::Sender<(R, oneshot::Sender<bool>)>,
        response: R,
    ) -> Option<bool> {
        if verdict_rx.await.ok()? {
            return Some(true);
        }
        let (verdict_tx, next_verdict_rx) = oneshot::channel();
        candidate_tx.send((response, verdict_tx)).await.ok()?;
        next_verdict_rx.await.ok()
    }

    #[test]
    fn feedback_accepts_and_closes_request() {
        deterministic::Runner::default().start(|_context| async move {
            let (candidate_tx, candidate_rx) = mpsc::channel::<(u8, _)>(1);
            let (verdict_tx, verdict_rx) = oneshot::channel();

            Feedback::new(verdict_tx, candidate_rx).accept();

            assert!(verdict_rx.await.unwrap());
            let (next_verdict_tx, _) = oneshot::channel();
            assert!(candidate_tx.send((2, next_verdict_tx)).await.is_err());
        });
    }

    #[test]
    fn feedback_rejects_and_returns_next_candidate() {
        deterministic::Runner::default().start(|context| async move {
            let (candidate_tx, candidate_rx) = mpsc::channel(1);
            let (verdict_tx, verdict_rx) = oneshot::channel();
            let driver = context
                .child("driver")
                .spawn(move |_| async move { next_candidate(verdict_rx, candidate_tx, 2u8).await });

            let (response, feedback) = Feedback::new(verdict_tx, candidate_rx)
                .reject()
                .await
                .unwrap();
            assert_eq!(response, 2);
            feedback.accept();
            assert_eq!(driver.await.unwrap(), Some(true));
        });
    }

    #[test]
    fn dropping_feedback_cancels_request() {
        deterministic::Runner::default().start(|_context| async move {
            let (candidate_tx, candidate_rx) = mpsc::channel::<(u8, _)>(1);
            let (verdict_tx, verdict_rx) = oneshot::channel();

            drop(Feedback::new(verdict_tx, candidate_rx));

            assert!(verdict_rx.await.is_err());
            let (next_verdict_tx, _) = oneshot::channel();
            assert!(candidate_tx.send((2, next_verdict_tx)).await.is_err());
        });
    }

    #[test]
    fn dropping_rejection_wait_cancels_request() {
        deterministic::Runner::default().start(|_context| async move {
            let (candidate_tx, candidate_rx) = mpsc::channel::<(u8, _)>(1);
            let (verdict_tx, verdict_rx) = oneshot::channel();
            let mut reject = Box::pin(Feedback::new(verdict_tx, candidate_rx).reject());

            commonware_macros::select! {
                _ = reject.as_mut() => panic!("rejection completed without another candidate"),
                verdict = verdict_rx => assert_eq!(verdict.unwrap(), false),
            }
            drop(reject);

            let (next_verdict_tx, _) = oneshot::channel();
            assert!(candidate_tx.send((2, next_verdict_tx)).await.is_err());
        });
    }

    #[test]
    fn feedback_stops_when_verdict_receiver_is_gone() {
        deterministic::Runner::default().start(|_context| async move {
            let (_candidate_tx, candidate_rx) = mpsc::channel::<(u8, _)>(1);
            let (verdict_tx, verdict_rx) = oneshot::channel();
            drop(verdict_rx);

            assert!(
                Feedback::new(verdict_tx, candidate_rx)
                    .reject()
                    .await
                    .is_none()
            );
        });
    }

    #[test]
    fn feedback_stops_when_source_closes_candidate_stream() {
        deterministic::Runner::default().start(|_context| async move {
            let (candidate_tx, candidate_rx) = mpsc::channel::<(u8, _)>(1);
            let (verdict_tx, verdict_rx) = oneshot::channel();
            drop(candidate_tx);

            assert!(
                Feedback::new(verdict_tx, candidate_rx)
                    .reject()
                    .await
                    .is_none()
            );
            assert!(!verdict_rx.await.unwrap());
        });
    }

    /// Fetch `target`'s final commit operation and pinned nodes from `source`.
    pub async fn fetch_compact_state<R: Source>(
        source: &R,
        target: crate::qmdb::sync::CompactTarget<R::Family, R::Digest>,
    ) -> std::result::Result<Response<R::Family, R::Op, R::Digest>, R::Error>
    where
        R::Op: Send + 'static,
    {
        let (response, feedback) = source
            .serve(Request::Boundary {
                size: target.size,
                start: target.size - 1,
            })
            .await?;
        if let Some(feedback) = feedback {
            feedback.accept();
        }
        Ok(response)
    }

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

        async fn serve(&self, _request: Request<F>) -> Result<Self> {
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

    /// The request codec refuses frames whose start reaches their size, and unknown tags.
    #[test]
    fn test_request_decode_rejects_malformed() {
        let valid = Request::<mmr::Family>::Operations {
            size: Location::new(10),
            start: Location::new(3),
            max_ops: NZU64!(2),
        };
        let decoded = Request::<mmr::Family>::decode(valid.encode()).unwrap();
        assert_eq!(decoded, valid);

        let mut malformed = Vec::new();
        1u8.write(&mut malformed); // Boundary tag
        Location::<mmr::Family>::new(10).write(&mut malformed);
        Location::<mmr::Family>::new(10).write(&mut malformed); // start == size
        assert!(Request::<mmr::Family>::decode(malformed).is_err());

        let bad_tag = [7u8];
        assert!(Request::<mmr::Family>::decode(Copying(&bad_tag)).is_err());
    }

    /// Requests are map keys, so equality and ordering must separate every distinct request.
    /// A `Boundary` differs from a one-op `Operations` at the same coordinates only by variant.
    #[test]
    fn test_request_identity() {
        let operations = Request::<mmr::Family>::Operations {
            size: Location::new(10),
            start: Location::new(3),
            max_ops: NZU64!(1),
        };
        let boundary = Request::<mmr::Family>::Boundary {
            size: Location::new(10),
            start: Location::new(3),
        };
        assert_eq!(boundary.max_ops(), NZU64!(1));
        assert_ne!(operations, boundary);

        let mut set = std::collections::BTreeSet::new();
        assert!(set.insert(operations));
        assert!(set.insert(boundary));
        assert!(!set.insert(operations));
        assert_eq!(set.len(), 2);

        // Ordering is by size, then start, then max_ops.
        let smaller_size = Request::<mmr::Family>::Operations {
            size: Location::new(9),
            start: Location::new(8),
            max_ops: NZU64!(5),
        };
        let smaller_start = Request::<mmr::Family>::Operations {
            size: Location::new(10),
            start: Location::new(2),
            max_ops: NZU64!(5),
        };
        let fewer_ops = Request::<mmr::Family>::Operations {
            size: Location::new(10),
            start: Location::new(3),
            max_ops: NZU64!(2),
        };
        let larger_ops = Request::<mmr::Family>::Operations {
            size: Location::new(10),
            start: Location::new(3),
            max_ops: NZU64!(5),
        };
        assert!(smaller_size < smaller_start);
        assert!(smaller_start < fewer_ops);
        assert!(fewer_ops < larger_ops);
    }

    /// The response codec enforces the request-derived caps and rejects unknown tags.
    #[test]
    fn test_response_decode_rejects_malformed() {
        type R = Response<mmr::Family, u64, ShaDigest>;
        let digest = ShaDigest::from([7u8; 32]);
        let proof = Proof::<mmr::Family, ShaDigest> {
            leaves: Location::new(3),
            inactive_peaks: 0,
            digests: vec![digest],
        };

        // More operations than the request's max_ops.
        let response = R::Operations {
            proof: proof.clone(),
            operations: vec![1, 2, 3],
        };
        assert!(R::decode_cfg(response.encode(), &(3, ())).is_ok());
        assert!(R::decode_cfg(response.encode(), &(2, ())).is_err());

        // More proof digests than the request-derived budget.
        let oversized = Proof::<mmr::Family, ShaDigest> {
            leaves: Location::new(3),
            inactive_peaks: 0,
            digests: vec![digest; MAX_PROOF_DIGESTS_PER_ELEMENT + 1],
        };
        let response = R::Operations {
            proof: oversized,
            operations: vec![1],
        };
        assert!(R::decode_cfg(response.encode(), &(1, ())).is_err());

        // More pinned nodes than the codec allows.
        let response = R::Boundary {
            proof: proof.clone(),
            op: 1,
            pinned_nodes: vec![digest; MAX_PINNED_NODES + 1],
        };
        assert!(R::decode_cfg(response.encode(), &(1, ())).is_err());
        let response = R::Boundary {
            proof,
            op: 1,
            pinned_nodes: vec![digest; MAX_PINNED_NODES],
        };
        assert!(R::decode_cfg(response.encode(), &(1, ())).is_ok());

        // Unknown tag.
        assert!(R::decode_cfg(Copying(&[9u8]), &(1, ())).is_err());
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

    #[test]
    fn sequence_source_offers_candidates_until_accepted() {
        deterministic::Runner::default().start(|_context| async move {
            let response = |op| Response::Operations {
                proof: Proof {
                    leaves: Location::new(1),
                    inactive_peaks: 0,
                    digests: vec![],
                },
                operations: vec![op],
            };
            let source = SequenceSource::<mmr::Family, _, ShaDigest>::new(vec![
                response(1),
                response(2),
                response(3),
            ]);
            let request = Request::Operations {
                size: Location::new(1),
                start: Location::new(0),
                max_ops: NZU64!(1),
            };

            let locked = Arc::new(AsyncRwLock::new(Some(source.clone())));
            let (first, feedback) = locked.serve(request).await.unwrap();
            assert!(matches!(
                first,
                Response::Operations { operations, .. } if operations == [1]
            ));
            let (second, feedback) = feedback.unwrap().reject().await.unwrap();
            assert!(matches!(
                second,
                Response::Operations { operations, .. } if operations == [2]
            ));
            feedback.accept();
            assert_eq!(source.take_verdicts().await, vec![false, true]);
            assert!(matches!(
                source.serve(request).await,
                Err(qmdb::Error::KeyNotFound)
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
        CodecConformance<Request<mmr::Family>>,
        CodecConformance<Request<mmb::Family>>,
        CodecConformance<Response<mmr::Family, u64, Sha256Digest>>,
        CodecConformance<Response<mmb::Family, u64, Sha256Digest>>,
    }
}
