//! Marshal's public value types, L-QC verification, and value shapes shared by its actors.

use super::{
    actors::{backfill, catalog, delivery, promoter, synchronizer},
    bodies,
    storage::{Error as StorageError, catalog_state::frontier_index, commit::CustodyRef},
};
use crate::{
    Block, Epochable, Viewable,
    multimmit::{
        actors::util::Completion,
        types::{BlockRef, CertificateId, CodecConfig, Frontier, Lqc, TipRecord, TransactionBlock},
    },
    types::{Epoch, OutputIndex, View},
};
#[cfg(feature = "arbitrary")]
use crate::{multimmit::types::ChainId, types::Height};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, RangeCfg, Read, Write};
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

/// A state-sync floor from which marshal can resume ordering.
///
/// The application snapshot is assumed to contain every block through `emitted`. Producer chains
/// start at height zero and every output advances one chain by one height, so the floor's index
/// is the sum of `emitted`'s heights, and delivery resumes at the index after it.
///
/// Decoding checks only the floor's shape. Marshal authenticates a floor when it is installed.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// A floor's epoch is its anchor's, which the anchor's certificate signs.
impl<V: Variant, D: Digest> Epochable for Floor<V, D> {
    fn epoch(&self) -> Epoch {
        self.anchor.epoch()
    }
}

/// A floor's view is its anchor's, which the anchor's certificate signs.
impl<V: Variant, D: Digest> Viewable for Floor<V, D> {
    fn view(&self) -> View {
        self.anchor.view()
    }
}

impl<V: Variant, D: Digest> Write for Floor<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.anchor.write(writer);
        self.history.write(writer);
        self.emitted.write(writer);
    }
}

impl<V: Variant, D: Digest> EncodeSize for Floor<V, D> {
    fn encode_size(&self) -> usize {
        self.anchor.encode_size() + self.history.encode_size() + self.emitted.encode_size()
    }
}

impl<V: Variant, D: Digest> Read for Floor<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(reader: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let anchor = Lqc::<V, D>::read_cfg(reader, config)?;
        let history = TipRecord::<D>::read_cfg(reader, config)?;
        let emitted =
            Vec::<BlockRef<D>>::read_cfg(reader, &(RangeCfg::exact(config.chains()), ()))?;
        let emitted = Frontier::new(emitted)
            .map_err(|_| {
                CodecError::Invalid(
                    "consensus::multimmit::marshal::Floor",
                    "emitted frontier is not in chain order",
                )
            })?
            .into_references();
        if frontier_index(&emitted).is_none() {
            return Err(CodecError::Invalid(
                "consensus::multimmit::marshal::Floor",
                "emitted frontier overflows the output index",
            ));
        }
        Ok(Self::new(Arc::new(anchor), Arc::new(history), emitted))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, V> arbitrary::Arbitrary<'a> for Floor<V, commonware_cryptography::sha256::Digest>
where
    V: Variant,
    Lqc<V, commonware_cryptography::sha256::Digest>: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let emitted = (0..crate::multimmit::types::arbitrary_codec_config().chains())
            .map(|chain| {
                // Heights stay small enough that the floor's index fits the output index.
                Ok(BlockRef::new(
                    ChainId::new(chain as u32),
                    Height::new(u64::from(u.arbitrary::<u32>()?)),
                    u.arbitrary()?,
                ))
            })
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self::new(
            Arc::new(u.arbitrary()?),
            Arc::new(u.arbitrary()?),
            emitted,
        ))
    }
}

/// Marshal's compact durable progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarshalProgress<D: Digest> {
    /// Active state-sync generation.
    pub floor_generation: u64,
    /// Retained L-QC floor anchor.
    pub floor: CertificateId<D>,
    /// Highest durably committed output, or the floor index if none is committed above it.
    pub committed: OutputIndex,
    /// Highest durably acknowledged output, or the floor index if none is acknowledged above it.
    pub acknowledged: OutputIndex,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        use crate::multimmit::types::arbitrary_codec_config;
        use commonware_codec::{
            Decode as _, Encode as _,
            conformance::{CodecConformance, generate_value},
        };
        use commonware_cryptography::{
            bls12381::primitives::variant::MinSig, sha256::Digest as Sha256Digest,
        };

        type TestFloor = Floor<MinSig, Sha256Digest>;

        #[test]
        fn floors_round_trip_and_reject_invalid_frontiers() {
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

                let mut emitted = floor.emitted().to_vec();
                emitted.swap(0, 1);
                let shuffled = Floor::new(
                    Arc::clone(&floor.anchor),
                    Arc::clone(&floor.history),
                    emitted,
                );
                assert!(matches!(
                    TestFloor::decode_cfg(shuffled.encode(), &config),
                    Err(CodecError::Invalid(..))
                ));

                let overflowing = floor
                    .emitted()
                    .iter()
                    .map(|reference| {
                        BlockRef::new(reference.chain(), Height::new(u64::MAX), reference.digest())
                    })
                    .collect();
                let overflowing = Floor::new(
                    Arc::clone(&floor.anchor),
                    Arc::clone(&floor.history),
                    overflowing,
                );
                assert!(matches!(
                    TestFloor::decode_cfg(overflowing.encode(), &config),
                    Err(CodecError::Invalid(..))
                ));
            }
        }

        commonware_conformance::conformance_tests! {
            CodecConformance<TestFloor> => 128,
        }
    }
}
