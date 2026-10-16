//! Marshal's public value types, L-QC verification, and value shapes shared by its actors.

use super::{
    actors::{backfill, catalog, delivery, promoter, synchronizer},
    bodies,
    storage::{Error as StorageError, commit::CustodyRef},
};
use crate::{
    Block,
    multimmit::{
        actors::util::Completion,
        types::{CertificateId, Lqc, TransactionBlock},
    },
};
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedSize, Read, ReadExt as _, Write};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::{acknowledgement::Exact, channel::oneshot};
use std::{error::Error as StdError, fmt, future::Future, sync::Arc};

/// The reply channel of a request that fails with `E`.
pub(super) type Reply<T, E> = oneshot::Sender<Result<T, E>>;

/// A retained L-QC, if any.
pub(super) type MaybeLqc<V, D> = Option<Arc<Lqc<V, D>>>;

/// A retained floor and the index of its last output, if any.
pub(super) type MaybeFloor<V, D> = Option<(OutputIndex, Floor<V, D>)>;

/// Durable custody for each requested block reference, `None` where no body is held.
pub(super) type CustodyValues<D> = Vec<Option<CustodyRef<D>>>;

/// The body of each requested block reference, `None` where it is not held.
pub(super) type BodyValues<H, B> = Vec<Option<Arc<TransactionBlock<H, B>>>>;

/// Cryptographic verification for peer-resolved L-QCs and externally supplied floors.
pub trait LqcVerifier<H: Hasher, V: Variant>: Send + 'static {
    /// Verification failure returned for an invalid proof or unavailable verifier.
    type Error: StdError + Send + Sync + 'static;

    /// Authenticates one externally resolved L-QC before marshal admits it.
    fn verify(
        &mut self,
        proof: &Lqc<V, H::Digest>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Index of a block in the marshal's finalized stream.
///
/// Marshal delivers finalized blocks in order, and each delivered block takes the next index.
/// Indices are canonical within a stream: every node assigns the same index to the same block,
/// whether it replayed the stream from genesis or started from a state-sync floor. Index zero is
/// the stream's genesis and is never delivered.
///
/// A block's height is its height in its own producer chain, so it differs from its index.
///
/// Indices encode as a fixed-width big-endian `u64` so they can key fixed-size records.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct OutputIndex(u64);

impl OutputIndex {
    /// Returns index zero, the stream's genesis.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Creates a new index from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying u64 value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns true if this is index zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns the next index.
    ///
    /// # Panics
    ///
    /// Panics if the index would overflow u64::MAX. A stream would have to deliver more than
    /// `u64::MAX` blocks for this to happen.
    pub const fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("output index overflow"))
    }

    /// Returns the previous index, or `None` if this is index zero.
    pub fn previous(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }
}

impl fmt::Display for OutputIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Write for OutputIndex {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl FixedSize for OutputIndex {
    const SIZE: usize = <u64 as FixedSize>::SIZE;
}

impl Read for OutputIndex {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self(u64::read(buf)?))
    }
}

/// One complete block in the finalized application stream, at the next output index.
#[derive(Clone, Debug)]
pub struct Update<B: Block> {
    /// Canonical index of the block in the finalized stream.
    pub index: OutputIndex,
    /// Complete block, including its protocol-defined header and opaque application body.
    pub block: Arc<B>,
    /// Acknowledged after the application has durably applied the block.
    pub acknowledgement: Exact,
}

/// One value for each finalized artifact family.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Families<T> {
    /// Leader quorum certificates.
    pub lqc: T,
    /// Tip-history openings.
    pub history: T,
    /// Producer blocks.
    pub blocks: T,
}

impl<T> Families<T> {
    /// Returns families that all hold `value`.
    pub const fn uniform(value: T) -> Self
    where
        T: Copy,
    {
        Self {
            lqc: value,
            history: value,
            blocks: value,
        }
    }

    /// Returns whether any family satisfies `f`.
    pub(super) fn any(&self, mut f: impl FnMut(&T) -> bool) -> bool {
        f(&self.lqc) || f(&self.history) || f(&self.blocks)
    }
}

impl Families<bool> {
    /// Marks every family that `later` marks.
    pub(super) const fn merge(&mut self, later: Self) {
        self.lqc |= later.lqc;
        self.history |= later.history;
        self.blocks |= later.blocks;
    }
}

/// A public marshal request failed.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    /// The marshal service has reached its configured ingress capacity.
    #[error("marshal service is busy")]
    Busy,
    /// The marshal service has reached its bound on callers waiting for block subscriptions.
    #[error("marshal block subscription capacity is exhausted")]
    SubscriptionCapacity,
    /// The marshal service is no longer accepting work.
    #[error("marshal service is closed")]
    Closed,
    /// A marshal component could not complete the request.
    #[error("marshal request failed: {0}")]
    Failed(#[from] Failure),
}

impl Error {
    /// Returns the failure of a marshal component.
    pub(super) fn failed(cause: impl Into<Cause>) -> Self {
        Self::Failed(Failure::from(cause.into()))
    }
}

/// A stopped catalog means a closed marshal.
impl From<catalog::Error> for Error {
    fn from(error: catalog::Error) -> Self {
        match error {
            catalog::Error::Closed => Self::Closed,
            error => Self::failed(error),
        }
    }
}

/// A stopped catalog or promoter means a closed marshal.
impl From<bodies::Error> for Error {
    fn from(error: bodies::Error) -> Self {
        match error {
            bodies::Error::Catalog(catalog::Error::Closed)
            | bodies::Error::Promoter(promoter::Error::Closed) => Self::Closed,
            error => Self::failed(error),
        }
    }
}

/// A stopped backfill means a closed marshal, and a full pending-fetch bound means busy.
impl From<backfill::Error> for Error {
    fn from(error: backfill::Error) -> Self {
        match error {
            backfill::Error::MailboxClosed => Self::Closed,
            backfill::Error::PendingFull => Self::Busy,
            error => Self::failed(error),
        }
    }
}

/// A stopped synchronizer means a closed marshal.
impl From<synchronizer::Error> for Error {
    fn from(error: synchronizer::Error) -> Self {
        match error {
            synchronizer::Error::Closed => Self::Closed,
            error => Self::failed(error),
        }
    }
}

/// The failure of a marshal component, with its typed cause as the error source.
#[derive(Clone, Debug, thiserror::Error)]
#[error(transparent)]
pub struct Failure(Arc<Cause>);

impl From<Cause> for Failure {
    fn from(cause: Cause) -> Self {
        Self(Arc::new(cause))
    }
}

/// A marshal component that runs as its own task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Component {
    Catalog,
    Promoter,
    Backfill,
    Serve,
    Synchronizer,
    Delivery,
    Router,
    Supervisor,
}

impl fmt::Display for Component {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Catalog => "catalog",
            Self::Promoter => "promoter",
            Self::Backfill => "backfill",
            Self::Serve => "serve",
            Self::Synchronizer => "synchronizer",
            Self::Delivery => "delivery",
            Self::Router => "router",
            Self::Supervisor => "supervisor",
        })
    }
}

/// Why a marshal component failed.
#[derive(Debug, thiserror::Error)]
pub(super) enum Cause {
    #[error("storage failed: {0}")]
    Storage(#[from] StorageError),
    #[error("catalog request failed: {0}")]
    Catalog(#[from] catalog::Error),
    #[error("catalog stopped: {0}")]
    CatalogStopped(#[from] catalog::Fatal),
    #[error("body lookup failed: {0}")]
    Bodies(#[from] bodies::Error),
    #[error("promoter failed: {0}")]
    Promoter(#[from] promoter::Error),
    #[error("backfill failed: {0}")]
    Backfill(#[from] backfill::Error),
    #[error("backfill serving failed: {0}")]
    Serve(#[from] backfill::serve::Error),
    #[error("synchronizer failed: {0}")]
    Synchronizer(#[from] synchronizer::Error),
    #[error("delivery failed: {0}")]
    Delivery(#[from] delivery::Error),
    #[error("router failed: {0}")]
    Router(#[from] Error),
    #[error("{component} task failed: {error}")]
    Task {
        component: Component,
        error: commonware_runtime::Error,
    },
}

/// Completion of one staged producer block's durable custody.
///
/// Staging makes the block available to marshal and allows its storage work to coalesce with
/// adjacent admissions. The block is crash-recoverable only after [`Custody::wait`] succeeds. A
/// marshal that stops first resolves it to [`Error::Closed`].
pub type Custody = Completion<Error>;

/// A state-sync floor from which marshal can resume ordering: delivery resumes at the index after
/// the floor's, and the application snapshot is assumed to contain exactly the blocks through the
/// opened tips. Marshal authenticates a floor when it is installed.
pub use crate::multimmit::types::Floor;

/// Marshal's compact durable progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarshalProgress<D: Digest> {
    /// Active state-sync generation.
    pub floor_generation: u64,
    /// Identifier of the retained floor L-QC, or of the genesis V-QC before any L-QC is
    /// finalized.
    pub floor: CertificateId<D>,
    /// Highest durably committed output, or the floor index if none is committed above it.
    pub committed: OutputIndex,
    /// Highest durably acknowledged output, or the floor index if none is acknowledged above it.
    pub acknowledged: OutputIndex,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode as _};

    #[test]
    fn output_index_constructors() {
        assert_eq!(OutputIndex::zero().get(), 0);
        assert_eq!(OutputIndex::new(42).get(), 42);
        assert_eq!(OutputIndex::default(), OutputIndex::zero());
        assert!(OutputIndex::zero().is_zero());
        assert!(!OutputIndex::new(1).is_zero());
    }

    #[test]
    fn output_index_next_and_previous() {
        assert_eq!(OutputIndex::zero().next(), OutputIndex::new(1));
        assert_eq!(OutputIndex::zero().previous(), None);
        assert_eq!(OutputIndex::new(5).previous(), Some(OutputIndex::new(4)));
    }

    #[test]
    #[should_panic(expected = "output index overflow")]
    fn output_index_next_overflow() {
        OutputIndex::new(u64::MAX).next();
    }

    #[test]
    fn output_index_encoding_is_fixed_width() {
        for value in [0, 1, u64::MAX] {
            let index = OutputIndex::new(value);
            let encoded = index.encode();
            assert_eq!(encoded.len(), OutputIndex::SIZE);
            assert_eq!(encoded.as_ref(), value.to_be_bytes());
            assert_eq!(OutputIndex::decode(encoded).unwrap(), index);
        }
    }

    #[test]
    fn stopped_children_are_closed_and_backfill_saturation_is_busy() {
        assert!(matches!(Error::from(catalog::Error::Closed), Error::Closed));
        assert!(matches!(
            Error::from(bodies::Error::Catalog(catalog::Error::Closed)),
            Error::Closed
        ));
        assert!(matches!(
            Error::from(bodies::Error::Promoter(promoter::Error::Closed)),
            Error::Closed
        ));
        assert!(matches!(
            Error::from(backfill::Error::MailboxClosed),
            Error::Closed
        ));
        assert!(matches!(
            Error::from(backfill::Error::PendingFull),
            Error::Busy
        ));
        assert!(matches!(
            Error::from(synchronizer::Error::Closed),
            Error::Closed
        ));
        assert!(matches!(
            Error::from(catalog::Error::Invalid("rejected")),
            Error::Failed(_)
        ));
        assert!(matches!(
            Error::from(backfill::Error::NetworkClosed),
            Error::Failed(_)
        ));
    }

    #[test]
    fn families_any_and_merge() {
        let mut touched = Families::<bool>::default();
        assert!(!touched.any(|family| *family));
        touched.merge(Families {
            lqc: false,
            history: true,
            blocks: false,
        });
        assert!(touched.any(|family| *family));
        assert_eq!(
            touched,
            Families {
                lqc: false,
                history: true,
                blocks: false,
            }
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::{
            multimmit::types::{BlockRef, HistoryRecord, arbitrary_codec_config},
            types::Height,
        };
        use commonware_codec::{
            Decode as _,
            conformance::{CodecConformance, generate_value},
        };
        use commonware_cryptography::{
            bls12381::primitives::variant::MinSig, sha256::Digest as Sha256Digest,
        };

        type TestFloor = Floor<MinSig, Sha256Digest>;

        #[test]
        fn floors_round_trip_and_reject_overflowing_openings() {
            let config = arbitrary_codec_config();
            for seed in 0..32 {
                let floor = generate_value::<TestFloor>(seed);
                let encoded = floor.encode();
                assert_eq!(
                    TestFloor::decode_cfg(encoded.clone(), &config).unwrap(),
                    floor
                );
                assert!(
                    TestFloor::decode_cfg(encoded.slice(..encoded.len() - 1), &config).is_err()
                );

                let overflowing = floor
                    .tips()
                    .iter()
                    .map(|tip| BlockRef::new(tip.chain(), Height::new(u64::MAX), tip.digest()))
                    .collect();
                let overflowing = Floor::new(
                    Arc::clone(&floor.lqc),
                    Arc::new(HistoryRecord::new(floor.opening().parent(), overflowing).unwrap()),
                );
                assert!(matches!(
                    TestFloor::decode_cfg(overflowing.encode(), &config),
                    Err(CodecError::Invalid(..))
                ));
            }
        }

        commonware_conformance::conformance_tests! {
            CodecConformance<OutputIndex> => 1024,
            CodecConformance<TestFloor> => 128,
        }
    }
}
