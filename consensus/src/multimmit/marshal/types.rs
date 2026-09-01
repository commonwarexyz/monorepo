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
        types::{BlockRef, CertificateId, Lqc, TipRecord, TransactionBlock},
    },
};
use bytes::BufMut;
use commonware_codec::{Buf, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::{acknowledgement::Exact, channel::oneshot};
use std::{error::Error as StdError, fmt, future::Future, sync::Arc};

/// The reply channel of a request that fails with `E`.
pub(super) type Reply<T, E> = oneshot::Sender<Result<T, E>>;

/// A retained L-QC, if any.
pub(super) type MaybeLqc<V, D> = Option<Arc<Lqc<V, D>>>;

/// Durable custody for each requested block reference, `None` where no body is held.
pub(super) type CustodyValues<D> = Vec<Option<CustodyRef<D>>>;

/// The body of each requested block reference, `None` where it is not held.
pub(super) type BodyValues<H, B> = Vec<Option<Arc<TransactionBlock<H, B>>>>;

/// Cryptographic verification for peer-resolved L-QCs and externally supplied floor anchors.
pub trait LqcVerifier<H: Hasher, V: Variant>: Send + 'static {
    /// Verification failure returned for an invalid proof or unavailable verifier.
    type Error: StdError + Send + Sync + 'static;

    /// Authenticates one externally resolved L-QC before marshal admits it.
    fn verify(
        &mut self,
        proof: &Lqc<V, H::Digest>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// A local coordinate in the dense application delivery stream.
///
/// The index is assigned after Multimmit's cross-chain ordering is reconstructed. It is not a
/// consensus view or a producer-chain height.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutputIndex(u64);

impl OutputIndex {
    /// The first output in a stream.
    pub const ZERO: Self = Self(0);

    /// Creates an output index.
    pub const fn new(index: u64) -> Self {
        Self(index)
    }

    /// Returns the underlying index.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next index, or `None` at the end of the coordinate space.
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(index) => Some(Self(index)),
            None => None,
        }
    }

    /// Returns the index after `cursor`, or [`Self::ZERO`] when there is no cursor.
    ///
    /// Returns `None` when `cursor` is the end of the coordinate space.
    pub const fn after(cursor: Option<Self>) -> Option<Self> {
        match cursor {
            Some(index) => index.next(),
            None => Some(Self::ZERO),
        }
    }

    /// Returns the number of outputs through `cursor`, saturating at `u64::MAX`.
    pub const fn count(cursor: Option<Self>) -> u64 {
        match cursor {
            Some(index) => index.0.saturating_add(1),
            None => 0,
        }
    }
}

impl fmt::Display for OutputIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Write for OutputIndex {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl FixedSize for OutputIndex {
    const SIZE: usize = u64::SIZE;
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
    /// Marshal-local dense coordinate.
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

/// A state-sync floor from which marshal can resume ordering.
///
/// The application snapshot is assumed to contain every block through `emitted`. Output indices
/// are absent because they are local and monotone across floor installations.
#[derive(Clone, Debug)]
pub struct Floor<V: Variant, D: Digest> {
    pub(super) anchor: Arc<Lqc<V, D>>,
    pub(super) history: Arc<TipRecord<D>>,
    pub(super) emitted: Vec<BlockRef<D>>,
}

impl<V: Variant, D: Digest> Floor<V, D> {
    /// Creates a floor from an anchoring L-QC, the tip-history opening its leader committed, and
    /// the highest block of the application snapshot on every chain, in chain order.
    pub const fn new(
        anchor: Arc<Lqc<V, D>>,
        history: Arc<TipRecord<D>>,
        emitted: Vec<BlockRef<D>>,
    ) -> Self {
        Self {
            anchor,
            history,
            emitted,
        }
    }

    /// Returns the L-QC anchoring the floor.
    pub fn anchor(&self) -> &Lqc<V, D> {
        &self.anchor
    }

    /// Returns the tip-history opening committed by the anchor's leader.
    pub fn history(&self) -> &TipRecord<D> {
        &self.history
    }

    /// Returns the application snapshot frontier in chain order.
    pub fn emitted(&self) -> &[BlockRef<D>] {
        &self.emitted
    }
}

/// A request to prune data made obsolete by an installed floor generation.
///
/// Naming the generation prevents a delayed request from pruning data selected by a newer floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prune {
    floor_generation: u64,
}

impl Prune {
    /// Creates a pruning request for an installed floor generation.
    pub const fn new(floor_generation: u64) -> Self {
        Self { floor_generation }
    }

    /// Returns the floor generation authorized by the request.
    pub const fn floor_generation(self) -> u64 {
        self.floor_generation
    }
}

/// Marshal's compact durable progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarshalProgress<D: Digest> {
    /// Active state-sync generation.
    pub floor_generation: u64,
    /// Retained L-QC floor anchor.
    pub floor: CertificateId<D>,
    /// Highest durably committed dense output.
    pub committed: Option<OutputIndex>,
    /// Highest durably acknowledged dense output.
    pub acknowledged: Option<OutputIndex>,
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for OutputIndex {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn output_index_round_trip_and_overflow() {
        let index = OutputIndex::new(41);
        assert_eq!(OutputIndex::decode(index.encode()).unwrap(), index);
        assert_eq!(index.next(), Some(OutputIndex::new(42)));
        assert_eq!(OutputIndex::new(u64::MAX).next(), None);
    }

    #[test]
    fn output_index_after_and_count_follow_an_optional_cursor() {
        assert_eq!(OutputIndex::after(None), Some(OutputIndex::ZERO));
        assert_eq!(
            OutputIndex::after(Some(OutputIndex::new(41))),
            Some(OutputIndex::new(42))
        );
        assert_eq!(OutputIndex::after(Some(OutputIndex::new(u64::MAX))), None);
        assert_eq!(OutputIndex::count(None), 0);
        assert_eq!(OutputIndex::count(Some(OutputIndex::ZERO)), 1);
        assert_eq!(OutputIndex::count(Some(OutputIndex::new(41))), 42);
        assert_eq!(
            OutputIndex::count(Some(OutputIndex::new(u64::MAX))),
            u64::MAX
        );
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
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<OutputIndex> => 1024,
        }
    }
}
