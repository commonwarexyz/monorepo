//! Marshal's public value types.

use super::store::Error as StorageError;
use crate::{
    Block, Epochable, Viewable,
    multimmit::{
        actors::util::Completion,
        scheme::Scheme,
        types::{BlockRef, CertificateId, CodecConfig, Frontier, Lqc, TipRecord},
    },
    types::{Epoch, OutputIndex, View},
};
#[cfg(feature = "arbitrary")]
use crate::{multimmit::types::ChainId, types::Height};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, RangeCfg, Read, Write};
use commonware_cryptography::{Digest, Digested, Hasher};
use commonware_utils::acknowledgement::Exact;
use std::{error::Error as StdError, future::Future, sync::Arc};

/// Cryptographic verification for peer-resolved L-QCs and externally supplied floor anchors.
pub trait LqcVerifier<H: Hasher, S: Scheme>: Send + 'static {
    /// Verification failure returned for an invalid proof or unavailable verifier.
    type Error: StdError + Send + Sync + 'static;

    /// Authenticates one externally resolved L-QC before marshal admits it.
    fn verify(
        &mut self,
        proof: &Lqc<S, H::Digest>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// One item marshal reports to the application.
#[derive(Clone, Debug)]
pub enum Update<B: Block> {
    /// One complete block in the finalized application stream, at the next output index.
    Block {
        /// Canonical index of the block in the finalized stream.
        index: OutputIndex,
        /// Complete block, including its protocol-defined header and opaque application body.
        block: Digested<B>,
        /// Acknowledged after the application has durably applied the block.
        acknowledgement: Exact,
    },
    /// A complete final block that marshal has not yet delivered as [`Update::Block`].
    ///
    /// A block is final once a leader finality fact names a final tip at or above it on its
    /// producer chain, or once it is committed. Marshal reports it once the block is in local
    /// custody, oldest first on its chain, so the application can start work for it while
    /// earlier blocks are still being ordered or applied. The block is later delivered as
    /// [`Update::Block`] at an index not yet known, unless installing a floor resumes the stream
    /// past it.
    ///
    /// It carries no acknowledgement and does not change the finalized stream. While marshal
    /// runs, it reports each final block at most once and never after the block's
    /// [`Update::Block`]. After a restart, it may report again any final block it has not yet
    /// delivered in the new run, including outputs redelivered from the acknowledgement cursor
    /// that the application may already have applied.
    Final(Digested<B>),
}

/// A public marshal request failed.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    /// The marshal service has reached its configured ingress capacity.
    #[error("marshal service is busy")]
    Busy,
    /// The marshal service is no longer accepting work.
    #[error("marshal service is closed")]
    Closed,
    /// Marshal refused the request, leaving its state unchanged. Retrying the same request
    /// fails the same way.
    #[error("marshal rejected the request: {0}")]
    Rejected(&'static str),
    /// Marshal stopped on a failure.
    #[error("marshal failed: {0}")]
    Failed(#[from] Failure),
}

/// The failure that stopped marshal, with its typed cause as the error source.
#[derive(Clone, Debug, thiserror::Error)]
#[error(transparent)]
pub struct Failure(Arc<Cause>);

impl From<Cause> for Failure {
    fn from(cause: Cause) -> Self {
        Self(Arc::new(cause))
    }
}

/// Why marshal stopped.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Cause {
    /// A storage operation failed; the store is not used again.
    #[error("storage failed: {0}")]
    Storage(#[from] StorageError),
    /// The application dropped an acknowledgement without acknowledging it.
    #[error("the application dropped an acknowledgement")]
    Acknowledgement,
    /// The application stopped accepting updates.
    #[error("the application stopped accepting updates")]
    Application,
    /// Authenticated proofs contradict each other: more faults than the protocol tolerates.
    #[error("authenticated proofs contradict each other: {0}")]
    Safety(&'static str),
    /// History records consensus reported waited longer than their bound.
    #[error("the backlog of history records exceeded its bound")]
    Backlog,
    /// A marshal task failed.
    #[error("marshal task failed: {0}")]
    Task(commonware_runtime::Error),
}

/// Completion of one staged block's durable custody.
///
/// The block is crash-recoverable once [`Custody::wait`] succeeds. A marshal that stops first
/// resolves it to [`Error::Closed`].
pub type Custody = Completion<Error>;

/// A state-sync floor from which marshal can resume ordering.
///
/// The application snapshot is assumed to contain every block through `emitted`. Producer chains
/// start at height zero and every output advances one chain by one height, so the floor's index
/// is the sum of `emitted`'s heights, and delivery resumes at the index after it.
///
/// Decoding checks only the floor's shape. Marshal authenticates a floor when it is installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Floor<S: Scheme, D: Digest> {
    pub(super) anchor: Arc<Lqc<S, D>>,
    pub(super) history: Arc<TipRecord<D>>,
    pub(super) emitted: Vec<BlockRef<D>>,
}

impl<S: Scheme, D: Digest> Floor<S, D> {
    /// Creates a floor from an anchoring L-QC, the tip-history opening its leader committed, and
    /// the highest block of the application snapshot on every chain, in chain order.
    pub const fn new(
        anchor: Arc<Lqc<S, D>>,
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
    pub fn anchor(&self) -> &Lqc<S, D> {
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
impl<S: Scheme, D: Digest> Epochable for Floor<S, D> {
    fn epoch(&self) -> Epoch {
        self.anchor.epoch()
    }
}

/// A floor's view is its anchor's, which the anchor's certificate signs.
impl<S: Scheme, D: Digest> Viewable for Floor<S, D> {
    fn view(&self) -> View {
        self.anchor.view()
    }
}

impl<S: Scheme, D: Digest> Write for Floor<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.anchor.write(writer);
        self.history.write(writer);
        self.emitted.write(writer);
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Floor<S, D> {
    fn encode_size(&self) -> usize {
        self.anchor.encode_size() + self.history.encode_size() + self.emitted.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for Floor<S, D> {
    type Cfg = CodecConfig;

    fn read_cfg(reader: &mut impl Buf, config: &Self::Cfg) -> Result<Self, CodecError> {
        let anchor = Lqc::<S, D>::read_cfg(reader, config)?;
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
        if emitted
            .iter()
            .try_fold(0u64, |sum, block| sum.checked_add(block.height().get()))
            .is_none()
        {
            return Err(CodecError::Invalid(
                "consensus::multimmit::marshal::Floor",
                "emitted frontier overflows the output index",
            ));
        }
        Ok(Self::new(Arc::new(anchor), Arc::new(history), emitted))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, S> arbitrary::Arbitrary<'a> for Floor<S, commonware_cryptography::sha256::Digest>
where
    S: Scheme,
    Lqc<S, commonware_cryptography::sha256::Digest>: arbitrary::Arbitrary<'a>,
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

/// Marshal's progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarshalProgress<D: Digest> {
    /// The floor marshal last installed or pruned to, if any.
    pub floor: Option<CertificateId<D>>,
    /// The highest output index durable proofs authenticate.
    pub proven: OutputIndex,
    /// The highest output index delivered to the application.
    pub delivered: OutputIndex,
    /// The highest output index durably acknowledged.
    pub acknowledged: OutputIndex,
}

#[cfg(all(test, feature = "arbitrary"))]
mod tests {
    use super::*;

    mod conformance {
        use super::*;
        use crate::multimmit::mocks::Bls;
        use commonware_codec::{
            Decode as _, Encode as _,
            conformance::{CodecConformance, generate_value},
        };
        use commonware_cryptography::{
            bls12381::primitives::variant::MinSig, sha256::Digest as Sha256Digest,
        };

        type TestFloor = Floor<Bls<MinSig>, Sha256Digest>;

        #[test]
        fn floors_round_trip_and_reject_invalid_frontiers() {
            let config = crate::multimmit::types::arbitrary_codec_config();
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
