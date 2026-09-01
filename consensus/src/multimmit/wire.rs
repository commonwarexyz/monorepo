//! Versioned wire envelope and per-plane message unions for one Multimmit epoch.
//!
//! Every network plane carries [`Envelope`]-framed canonical payloads. The envelope binds the wire
//! version and epoch before any payload bytes are decoded, so traffic for another epoch is rejected
//! without allocating payload state. Payload unions reuse the canonical protocol codecs from
//! [`crate::multimmit::types`]; decoding rejects trailing bytes, non-canonical values, and any count
//! or byte bound above the epoch codec profile.

use crate::{
    multimmit::types::{
        Artifact, ChainId, CodecConfig, DaCertificate, DaVote, Lqc, NoVote, Nullification, Nullify,
        SignedLeaderBlock, SignedTransactionBlock, Vote, Vqc,
    },
    types::Epoch,
};
use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, Encode as _, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::telemetry::metrics::EncodeLabelValue;
#[cfg(any(test, feature = "mocks"))]
use std::iter::once;

/// The Multimmit wire-format version.
pub const WIRE_VERSION: u8 = 0;

const DATA_BLOCK: u8 = 0;
const DATA_DA_VOTE: u8 = 1;
const DATA_DA_CERTIFICATE: u8 = 2;

const CONSENSUS_PROPOSAL: u8 = 0;
const CONSENSUS_VOTE: u8 = 1;
const CONSENSUS_NOVOTE: u8 = 2;
const CONSENSUS_NULLIFY: u8 = 3;

const PARENT_OMITTED: u8 = 0;
const PARENT_ATTACHED: u8 = 1;

const CERTIFICATE_NULLIFICATION: u8 = 0;
const CERTIFICATE_VQC: u8 = 1;
const CERTIFICATE_LQC: u8 = 2;

/// A network plane: one registered channel with its own message union and frame bound.
///
/// Separate planes keep bulk data from delaying the messages a round waits on.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, EncodeLabelValue)]
pub enum Plane {
    /// Transaction-block headers, DA shares, and DA certificates.
    Data = 0,
    /// Leader proposals, votes, novotes, and nullify shares.
    Consensus = 1,
    /// Recovered nullifications, V-QCs, and L-QCs.
    Certificate = 2,
}

impl Plane {
    /// Every plane, in discriminant order.
    pub const ALL: [Self; 3] = [Self::Data, Self::Consensus, Self::Certificate];

    /// Returns the plane served after this one in fair rotation.
    pub const fn next(self) -> Self {
        match self {
            Self::Consensus => Self::Certificate,
            Self::Certificate => Self::Data,
            Self::Data => Self::Consensus,
        }
    }

    /// Returns every plane once in rotation order, starting with this one.
    pub const fn rotation(self) -> [Self; 3] {
        [self, self.next(), self.next().next()]
    }

    /// Returns the plane's lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Consensus => "consensus",
            Self::Certificate => "certificate",
        }
    }

    /// Returns whether the plane carries artifacts the round waits on.
    ///
    /// Every consensus and certificate plane artifact is
    /// [view-critical](Artifact::view_critical); no data plane artifact is.
    pub const fn view_critical(self) -> bool {
        !matches!(self, Self::Data)
    }
}

/// Decode configuration: frame size cap, expected epoch, and payload bounds.
#[derive(Clone, Debug)]
pub struct EnvelopeConfig<C> {
    /// Maximum encoded bytes accepted for the complete envelope.
    pub max_frame_bytes: usize,
    /// The engine's immutable epoch.
    pub epoch: Epoch,
    /// Bounded payload decode configuration.
    pub payload: C,
}

/// A version and epoch bound wire frame.
///
/// Decoding fails before payload bytes are touched unless the frame names the exact expected
/// epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Envelope<M> {
    epoch: Epoch,
    payload: M,
}

impl<M> Envelope<M> {
    /// Frames `payload` for one epoch.
    pub const fn new(epoch: Epoch, payload: M) -> Self {
        Self { epoch, payload }
    }

    /// Returns the framed payload.
    pub fn into_payload(self) -> M {
        self.payload
    }
}

impl<M: Write> Write for Envelope<M> {
    fn write(&self, buf: &mut impl BufMut) {
        WIRE_VERSION.write(buf);
        self.epoch.write(buf);
        self.payload.write(buf);
    }
}

impl<M: EncodeSize> EncodeSize for Envelope<M> {
    fn encode_size(&self) -> usize {
        WIRE_VERSION.encode_size() + self.epoch.encode_size() + self.payload.encode_size()
    }
}

impl<M: Read> Read for Envelope<M> {
    type Cfg = EnvelopeConfig<M::Cfg>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        if buf.remaining() > cfg.max_frame_bytes {
            return Err(CodecError::InvalidLength(buf.remaining()));
        }
        if u8::read(buf)? != WIRE_VERSION {
            return Err(CodecError::Invalid(
                "consensus::multimmit::wire::Envelope",
                "unsupported wire version",
            ));
        }
        let epoch = Epoch::read(buf)?;
        if epoch != cfg.epoch {
            return Err(CodecError::Invalid(
                "consensus::multimmit::wire::Envelope",
                "wrong epoch",
            ));
        }
        Ok(Self {
            epoch,
            payload: M::read_cfg(buf, &cfg.payload)?,
        })
    }
}

/// A data-plane message: producer chains and data availability.
///
/// Decoding rejects a message addressed to a producer chain outside the epoch codec profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataMessage<V: Variant, D: Digest> {
    /// See [`Artifact::TransactionBlock`].
    Block(SignedTransactionBlock<V, D>),
    /// See [`Artifact::DaVote`].
    DaVote(DaVote<V, D>),
    /// See [`Artifact::DaCertificate`].
    DaCertificate(DaCertificate<V, D>),
}

#[cfg(feature = "arbitrary")]
impl<'a, V: Variant, D: Digest> arbitrary::Arbitrary<'a> for DataMessage<V, D>
where
    SignedTransactionBlock<V, D>: arbitrary::Arbitrary<'a>,
    DaVote<V, D>: arbitrary::Arbitrary<'a>,
    DaCertificate<V, D>: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=2)? {
            0 => Ok(Self::Block(u.arbitrary()?)),
            1 => Ok(Self::DaVote(u.arbitrary()?)),
            2 => Ok(Self::DaCertificate(u.arbitrary()?)),
            _ => unreachable!("generated data-message tag is bounded"),
        }
    }
}

impl<V: Variant, D: Digest> DataMessage<V, D> {
    /// Returns the producer chain addressed by this message.
    pub const fn chain(&self) -> ChainId {
        match self {
            Self::Block(block) => block.header().chain(),
            Self::DaVote(vote) => vote.header().chain(),
            Self::DaCertificate(certificate) => certificate.header().chain(),
        }
    }

    /// Returns this message's untrusted artifact.
    pub fn into_artifact(self) -> Artifact<V, D> {
        match self {
            Self::Block(block) => Artifact::TransactionBlock(block),
            Self::DaVote(vote) => Artifact::DaVote(vote),
            Self::DaCertificate(certificate) => Artifact::DaCertificate(certificate),
        }
    }
}

impl<V: Variant, D: Digest> Write for DataMessage<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Block(block) => {
                DATA_BLOCK.write(buf);
                block.write(buf);
            }
            Self::DaVote(vote) => {
                DATA_DA_VOTE.write(buf);
                vote.write(buf);
            }
            Self::DaCertificate(certificate) => {
                DATA_DA_CERTIFICATE.write(buf);
                certificate.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for DataMessage<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Block(block) => block.encode_size(),
            Self::DaVote(vote) => vote.encode_size(),
            Self::DaCertificate(certificate) => certificate.encode_size(),
        }
    }
}

impl<V: Variant, D: Digest> Read for DataMessage<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, codec: &Self::Cfg) -> Result<Self, CodecError> {
        let message = match u8::read(buf)? {
            DATA_BLOCK => Self::Block(SignedTransactionBlock::read(buf)?),
            DATA_DA_VOTE => Self::DaVote(DaVote::read(buf)?),
            DATA_DA_CERTIFICATE => Self::DaCertificate(DaCertificate::read(buf)?),
            tag => return Err(CodecError::InvalidEnum(tag)),
        };
        if message.chain().get() as usize >= codec.chains() {
            return Err(CodecError::Invalid(
                "consensus::multimmit::wire::DataMessage",
                "chain outside the epoch",
            ));
        }
        Ok(message)
    }
}

/// A consensus-plane message: proposals, votes, abstentions, and nullify shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusMessage<V: Variant, D: Digest> {
    /// A signed leader proposal, optionally carrying the parent V-QC it references.
    Proposal {
        /// The parent certificate, unless it was already broadcast or is synthetic genesis.
        parent: Option<Box<Vqc<V, D>>>,
        /// See [`Artifact::LeaderBlock`].
        block: Box<SignedLeaderBlock<V, D>>,
    },
    /// See [`Artifact::Vote`].
    Vote(Vote<V, D>),
    /// See [`Artifact::NoVote`].
    NoVote(NoVote<V>),
    /// See [`Artifact::Nullify`].
    Nullify(Nullify<V>),
}

#[cfg(feature = "arbitrary")]
impl<'a, V: Variant, D: Digest> arbitrary::Arbitrary<'a> for ConsensusMessage<V, D>
where
    Vqc<V, D>: arbitrary::Arbitrary<'a>,
    SignedLeaderBlock<V, D>: arbitrary::Arbitrary<'a>,
    Vote<V, D>: arbitrary::Arbitrary<'a>,
    NoVote<V>: arbitrary::Arbitrary<'a>,
    Nullify<V>: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=4)? {
            0 => Ok(Self::Proposal {
                parent: None,
                block: Box::new(u.arbitrary()?),
            }),
            1 => Ok(Self::Proposal {
                parent: Some(Box::new(u.arbitrary()?)),
                block: Box::new(u.arbitrary()?),
            }),
            2 => Ok(Self::Vote(u.arbitrary()?)),
            3 => Ok(Self::NoVote(u.arbitrary()?)),
            4 => Ok(Self::Nullify(u.arbitrary()?)),
            _ => unreachable!("generated consensus-message tag is bounded"),
        }
    }
}

impl<V: Variant, D: Digest> ConsensusMessage<V, D> {
    /// Returns this message's untrusted artifacts in observation order.
    ///
    /// An attached proposal parent precedes its leader block so the dependency is observed first.
    #[cfg(any(test, feature = "mocks"))]
    pub fn into_artifacts(self) -> impl Iterator<Item = Artifact<V, D>> {
        let (parent, artifact) = match self {
            Self::Proposal { parent, block } => {
                let parent = parent.map(|parent| Artifact::Vqc(*parent));
                (parent, Artifact::LeaderBlock(*block))
            }
            Self::Vote(vote) => (None, Artifact::Vote(vote)),
            Self::NoVote(vote) => (None, Artifact::NoVote(vote)),
            Self::Nullify(nullify) => (None, Artifact::Nullify(nullify)),
        };
        parent.into_iter().chain(once(artifact))
    }
}

impl<V: Variant, D: Digest> Write for ConsensusMessage<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Proposal { parent, block } => {
                CONSENSUS_PROPOSAL.write(buf);
                match parent {
                    None => PARENT_OMITTED.write(buf),
                    Some(parent) => {
                        PARENT_ATTACHED.write(buf);
                        parent.write(buf);
                    }
                }
                block.write(buf);
            }
            Self::Vote(vote) => {
                CONSENSUS_VOTE.write(buf);
                vote.write(buf);
            }
            Self::NoVote(vote) => {
                CONSENSUS_NOVOTE.write(buf);
                vote.write(buf);
            }
            Self::Nullify(nullify) => {
                CONSENSUS_NULLIFY.write(buf);
                nullify.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for ConsensusMessage<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Proposal { parent, block } => {
                let parent_size = parent.as_ref().map_or(0, |parent| parent.encode_size());
                1 + parent_size + block.encode_size()
            }
            Self::Vote(vote) => vote.encode_size(),
            Self::NoVote(vote) => vote.encode_size(),
            Self::Nullify(nullify) => nullify.encode_size(),
        }
    }
}

impl<V: Variant, D: Digest> Read for ConsensusMessage<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, codec: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            CONSENSUS_PROPOSAL => {
                let parent = match u8::read(buf)? {
                    PARENT_OMITTED => None,
                    PARENT_ATTACHED => Some(Box::new(Vqc::read_cfg(buf, codec)?)),
                    tag => return Err(CodecError::InvalidEnum(tag)),
                };
                Ok(Self::Proposal {
                    parent,
                    block: Box::new(SignedLeaderBlock::read_cfg(buf, codec)?),
                })
            }
            CONSENSUS_VOTE => Ok(Self::Vote(Vote::read_cfg(buf, codec)?)),
            CONSENSUS_NOVOTE => Ok(Self::NoVote(NoVote::read(buf)?)),
            CONSENSUS_NULLIFY => Ok(Self::Nullify(Nullify::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// A certificate-plane message: recovered or aggregated exit and finality proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertificateMessage<V: Variant, D: Digest> {
    /// See [`Artifact::Nullification`].
    Nullification(Nullification<V>),
    /// See [`Artifact::Vqc`].
    Vqc(Vqc<V, D>),
    /// See [`Artifact::Lqc`].
    Lqc(Lqc<V, D>),
}

#[cfg(feature = "arbitrary")]
impl<'a, V: Variant, D: Digest> arbitrary::Arbitrary<'a> for CertificateMessage<V, D>
where
    Nullification<V>: arbitrary::Arbitrary<'a>,
    Vqc<V, D>: arbitrary::Arbitrary<'a>,
    Lqc<V, D>: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=2)? {
            0 => Ok(Self::Nullification(u.arbitrary()?)),
            1 => Ok(Self::Vqc(u.arbitrary()?)),
            2 => Ok(Self::Lqc(u.arbitrary()?)),
            _ => unreachable!("generated certificate-message tag is bounded"),
        }
    }
}

impl<V: Variant, D: Digest> CertificateMessage<V, D> {
    /// Returns this message's untrusted artifact.
    pub fn into_artifact(self) -> Artifact<V, D> {
        match self {
            Self::Nullification(nullification) => Artifact::Nullification(nullification),
            Self::Vqc(certificate) => Artifact::Vqc(certificate),
            Self::Lqc(certificate) => Artifact::Lqc(certificate),
        }
    }
}

impl<V: Variant, D: Digest> Write for CertificateMessage<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Nullification(nullification) => {
                CERTIFICATE_NULLIFICATION.write(buf);
                nullification.write(buf);
            }
            Self::Vqc(certificate) => {
                CERTIFICATE_VQC.write(buf);
                certificate.write(buf);
            }
            Self::Lqc(certificate) => {
                CERTIFICATE_LQC.write(buf);
                certificate.write(buf);
            }
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for CertificateMessage<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Nullification(nullification) => nullification.encode_size(),
            Self::Vqc(certificate) => certificate.encode_size(),
            Self::Lqc(certificate) => certificate.encode_size(),
        }
    }
}

impl<V: Variant, D: Digest> Read for CertificateMessage<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, codec: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            CERTIFICATE_NULLIFICATION => Ok(Self::Nullification(Nullification::read(buf)?)),
            CERTIFICATE_VQC => Ok(Self::Vqc(Vqc::read_cfg(buf, codec)?)),
            CERTIFICATE_LQC => Ok(Self::Lqc(Lqc::read_cfg(buf, codec)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One artifact encoded in its epoch envelope, with the plane that carries it.
pub(crate) struct Frame<D: Digest> {
    /// The plane that carries the message.
    pub(crate) plane: Plane,
    /// The encoded envelope.
    pub(crate) bytes: Bytes,
    /// The transaction-block header digest to relay before publishing the block.
    pub(crate) relay: Option<D>,
}

impl<D: Digest> Frame<D> {
    /// Frames one non-proposal artifact for its ordinary plane.
    ///
    /// Leader blocks return `None` because they travel only as a [`ConsensusMessage::Proposal`]
    /// with their parent.
    pub(crate) fn artifact<H: Hasher<Digest = D>, V: Variant>(
        epoch: Epoch,
        artifact: &Artifact<V, D>,
    ) -> Option<Self> {
        let (plane, bytes, relay) = match artifact {
            Artifact::TransactionBlock(block) => (
                Plane::Data,
                Envelope::new(epoch, DataMessage::Block(block.clone())).encode(),
                Some(block.header().digest::<H>()),
            ),
            Artifact::DaVote(vote) => (
                Plane::Data,
                Envelope::new(epoch, DataMessage::DaVote(vote.clone())).encode(),
                None,
            ),
            Artifact::DaCertificate(certificate) => (
                Plane::Data,
                Envelope::new(epoch, DataMessage::DaCertificate(certificate.clone())).encode(),
                None,
            ),
            Artifact::LeaderBlock(_) => return None,
            Artifact::Vote(vote) => (
                Plane::Consensus,
                Envelope::new(epoch, ConsensusMessage::Vote(vote.clone())).encode(),
                None,
            ),
            Artifact::NoVote(vote) => (
                Plane::Consensus,
                Envelope::new(epoch, ConsensusMessage::<V, D>::NoVote(vote.clone())).encode(),
                None,
            ),
            Artifact::Nullify(nullify) => (
                Plane::Consensus,
                Envelope::new(epoch, ConsensusMessage::<V, D>::Nullify(nullify.clone())).encode(),
                None,
            ),
            Artifact::Nullification(nullification) => (
                Plane::Certificate,
                Envelope::new(
                    epoch,
                    CertificateMessage::<V, D>::Nullification(nullification.clone()),
                )
                .encode(),
                None,
            ),
            Artifact::Vqc(certificate) => (
                Plane::Certificate,
                Envelope::new(epoch, CertificateMessage::Vqc(certificate.clone())).encode(),
                None,
            ),
            Artifact::Lqc(certificate) => (
                Plane::Certificate,
                Envelope::new(epoch, CertificateMessage::Lqc(certificate.clone())).encode(),
                None,
            ),
        };
        Some(Self {
            plane,
            bytes,
            relay,
        })
    }

    /// Frames one leader proposal, carrying `parent` ahead of the block when present.
    pub(crate) fn proposal<V: Variant>(
        epoch: Epoch,
        block: &SignedLeaderBlock<V, D>,
        parent: Option<&Vqc<V, D>>,
    ) -> Self {
        let message = ConsensusMessage::Proposal {
            block: Box::new(block.clone()),
            parent: parent.map(|parent| Box::new(parent.clone())),
        };
        Self {
            plane: Plane::Consensus,
            bytes: Envelope::new(epoch, message).encode(),
            relay: None,
        }
    }
}

/// Malformed-frame campaign over every network plane, the body of the `fuzz_wire` target.
#[cfg(any(test, feature = "mocks"))]
pub(crate) mod fuzz {
    use super::{CertificateMessage, ConsensusMessage, DataMessage, Envelope, EnvelopeConfig};
    use crate::{
        multimmit::types::{CodecConfig, PathLimits},
        types::Epoch,
    };
    use commonware_codec::{Codec, Copying, Decode as _, Encode as _};
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use core::fmt::Debug;

    const MAX_FRAME_BYTES: usize = 1024 * 1024;

    /// Decodes `input` as each plane's envelope and checks that accepted frames re-encode
    /// canonically.
    pub(crate) fn exercise(input: &[u8]) {
        let config = EnvelopeConfig {
            max_frame_bytes: MAX_FRAME_BYTES,
            epoch: Epoch::new(7),
            payload: CodecConfig::new(6, 2, PathLimits::new(2, 1).unwrap()).unwrap(),
        };
        roundtrip::<DataMessage<MinPk, Sha256Digest>>(input, &config);
        roundtrip::<ConsensusMessage<MinPk, Sha256Digest>>(input, &config);
        roundtrip::<CertificateMessage<MinPk, Sha256Digest>>(input, &config);
    }

    fn roundtrip<M>(input: &[u8], config: &EnvelopeConfig<CodecConfig>)
    where
        M: Codec<Cfg = CodecConfig> + PartialEq + Debug,
    {
        if let Ok(envelope) = Envelope::<M>::decode_cfg(Copying(input), config) {
            assert_eq!(envelope.encode().as_ref(), input);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::exercise;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]
            #[test]
            fn accepted_frames_reencode_canonically(input in proptest::collection::vec(any::<u8>(), 0..1024)) {
                exercise(&input);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Epochable as _,
        multimmit::{
            mocks::Committee,
            types::{
                Anchor, CertificateId, ChainId, ChainProposal, LeaderBlock, PathLimits,
                TransactionBlockHeader, ViewMessage,
            },
        },
        types::{Height, Participant, Round, View},
    };
    use bytes::{BufMut, BytesMut};
    use commonware_codec::Decode as _;
    use commonware_cryptography::{
        Sha256,
        bls12381::primitives::variant::{MinPk, MinSig},
        sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use core::fmt::Debug;

    fn committee() -> Committee<MinPk> {
        Committee::builder(11, 6).build()
    }

    fn maximal_committee<V: Variant>() -> Committee<V> {
        Committee::builder(u64::MAX, 1)
            .limits(PathLimits::new(1, 0).unwrap())
            .build()
    }

    fn transaction_header<V: Variant>(
        committee: &Committee<V>,
        height: u64,
    ) -> TransactionBlockHeader<Sha256Digest> {
        TransactionBlockHeader::new(
            committee.config.epoch(),
            ChainId::new(0),
            Height::new(height),
            Sha256::hash(&[b"parent"]),
            Sha256::hash(&[b"commitment"]),
        )
        .unwrap()
    }

    fn da_certificate<V: Variant>(
        committee: &Committee<V>,
        header: TransactionBlockHeader<Sha256Digest>,
    ) -> DaCertificate<V, Sha256Digest> {
        let votes = (0..committee.codec().da_quorum())
            .map(|signer| committee.da_vote(Participant::from_usize(signer), header.clone()))
            .collect::<Vec<_>>();
        committee
            .verifier
            .assemble_da_certificate(&votes, &Sequential)
            .unwrap()
    }

    fn maximal_leader_block<V: Variant>(
        committee: &Committee<V>,
    ) -> SignedLeaderBlock<V, Sha256Digest> {
        maximal_leader_block_with_history(committee, Sha256::hash(&[b"history"]))
    }

    fn maximal_leader_block_with_history<V: Variant>(
        committee: &Committee<V>,
        history: Sha256Digest,
    ) -> SignedLeaderBlock<V, Sha256Digest> {
        let anchor = Anchor::Certificate(da_certificate(
            committee,
            transaction_header(committee, u64::MAX - 1),
        ));
        let proposal = ChainProposal::new(
            ChainId::new(0),
            anchor,
            vec![Sha256::hash(&[b"payload"])],
            committee.codec().pipeline_depth(),
        )
        .unwrap();
        let block = LeaderBlock::new(
            Round::new(committee.config.epoch(), View::new(u64::MAX)),
            CertificateId::new(Sha256::hash(&[b"parent vqc"])),
            history,
            vec![proposal],
            committee.codec(),
        )
        .unwrap();
        committee.signers[0].sign_leader_block(block).unwrap()
    }

    fn maximal_vqc<V: Variant>(committee: &Committee<V>) -> Vqc<V, Sha256Digest> {
        let leader = maximal_leader_block(committee);
        let vote = committee.vote(Participant::new(0), &leader);
        committee
            .verifier
            .assemble_vqc::<Sha256, _>(
                leader.block().clone(),
                &[ViewMessage::Vote(vote)],
                &Sequential,
            )
            .unwrap()
    }

    fn config<V: Variant, C>(committee: &Committee<V>, payload: C) -> EnvelopeConfig<C> {
        EnvelopeConfig {
            max_frame_bytes: usize::MAX,
            epoch: committee.config.epoch(),
            payload,
        }
    }

    fn envelope<V: Variant, M>(committee: &Committee<V>, payload: M) -> Envelope<M> {
        Envelope::new(committee.config.epoch(), payload)
    }

    fn envelope_prefix<V: Variant>(committee: &Committee<V>) -> BytesMut {
        let mut encoded = BytesMut::new();
        WIRE_VERSION.write(&mut encoded);
        committee.config.epoch().write(&mut encoded);
        encoded
    }

    #[test]
    fn round_trips_every_plane_message() {
        let committee = committee();
        let commitment = Sha256::hash(&[b"transaction commitment"]);
        let block = committee.signed_block(ChainId::new(0), commitment);
        let header = block.header().clone();

        let data = [
            DataMessage::Block(block),
            DataMessage::DaVote(committee.da_vote(Participant::new(1), header)),
        ];
        for message in data {
            let encoded = envelope(&committee, message.clone()).encode();
            let decoded = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                encoded,
                &config(&committee, committee.codec()),
            )
            .unwrap();
            assert_eq!(decoded.into_payload(), message);
        }

        let consensus = [
            ConsensusMessage::NoVote(committee.novote(Participant::new(2), View::new(1))),
            ConsensusMessage::Nullify(committee.nullify(Participant::new(3), View::new(1))),
        ];
        for message in consensus {
            let encoded = envelope(&committee, message.clone()).encode();
            let decoded = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                encoded,
                &config(&committee, committee.codec()),
            )
            .unwrap();
            assert_eq!(decoded.into_payload(), message);
        }

        let message = CertificateMessage::Nullification(committee.nullification(View::new(1)));
        let encoded = envelope(&committee, message.clone()).encode();
        let decoded = Envelope::<CertificateMessage<MinPk, Sha256Digest>>::decode_cfg(
            encoded,
            &config(&committee, committee.codec()),
        )
        .unwrap();
        assert_eq!(decoded.into_payload(), message);
    }

    fn assert_accepted_under_bound<V: Variant, M>(
        committee: &Committee<V>,
        message: M,
        payload: M::Cfg,
        max_frame_bytes: usize,
    ) where
        M: Clone + Debug + PartialEq + EncodeSize + Read + Write,
    {
        let encoded = envelope(committee, message.clone()).encode();
        assert!(
            encoded.len() <= max_frame_bytes,
            "{}-byte frame exceeds derived {max_frame_bytes}-byte bound",
            encoded.len(),
        );
        let config = EnvelopeConfig {
            max_frame_bytes,
            epoch: committee.config.epoch(),
            payload,
        };
        let decoded = Envelope::<M>::decode_cfg(encoded, &config).unwrap();
        assert_eq!(decoded.into_payload(), message);
    }

    fn assert_derived_plane_bounds_accept_every_message_variant<V: Variant>() {
        let committee = Committee::<V>::builder(11, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_WIRE_BOUNDS_TEST")
            .producers(vec![Participant::new(4), Participant::new(1)])
            .build();
        let codec = committee.codec();
        let bounds = codec.encoded_bounds::<V, Sha256Digest>().unwrap();

        let block =
            committee.signed_block(ChainId::new(0), Sha256::hash(&[b"transaction commitment"]));
        let header = block.header().clone();
        let data = [
            DataMessage::Block(block),
            DataMessage::DaVote(committee.da_vote(Participant::new(1), header.clone())),
            DataMessage::DaCertificate(da_certificate(&committee, header)),
        ];
        for message in data {
            assert_accepted_under_bound(&committee, message, codec, bounds.max_data_frame_bytes());
        }

        let genesis_block = committee.leader_block(View::new(1));
        let parent = committee.vqc(View::new(2));
        let exact_block = committee.leader_block_with_parent(View::new(3), &parent);
        let consensus = [
            ConsensusMessage::Proposal {
                parent: None,
                block: Box::new(genesis_block.clone()),
            },
            ConsensusMessage::Proposal {
                parent: Some(Box::new(parent.clone())),
                block: Box::new(exact_block),
            },
            ConsensusMessage::Vote(committee.vote(Participant::new(0), &genesis_block)),
            ConsensusMessage::NoVote(committee.novote(Participant::new(1), View::new(1))),
            ConsensusMessage::Nullify(committee.nullify(Participant::new(2), View::new(1))),
        ];
        for message in consensus {
            assert_accepted_under_bound(
                &committee,
                message,
                codec,
                bounds.max_consensus_frame_bytes(),
            );
        }

        let certificates = [
            CertificateMessage::Nullification(committee.nullification(View::new(1))),
            CertificateMessage::Vqc(parent),
            CertificateMessage::Lqc(committee.lqc(View::new(1))),
        ];
        for message in certificates {
            assert_accepted_under_bound(
                &committee,
                message,
                codec,
                bounds.max_certificate_frame_bytes(),
            );
        }
    }

    #[test]
    fn derived_plane_bounds_accept_every_message_variant() {
        assert_derived_plane_bounds_accept_every_message_variant::<MinPk>();
        assert_derived_plane_bounds_accept_every_message_variant::<MinSig>();
    }

    #[test]
    fn wire_version_is_zero_and_rejects_one() {
        let committee = committee();
        let message = ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
            committee.novote(Participant::new(1), View::new(1)),
        );
        let mut v1 = BytesMut::from(envelope(&committee, message).encode().as_ref());
        v1[0] = 1;

        assert_eq!(WIRE_VERSION, 0);
        assert!(
            Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                v1.freeze(),
                &config(&committee, committee.codec()),
            )
            .is_err(),
            "wire version zero must reject a version one envelope",
        );
    }

    #[test]
    fn round_trips_genesis_proposal() {
        let committee = committee();
        let block = committee.leader_block(View::new(1));
        let message = ConsensusMessage::Proposal {
            parent: None,
            block: Box::new(block.clone()),
        };

        let encoded = envelope(&committee, message.clone()).encode();
        let mut expected = envelope_prefix(&committee);
        0u8.write(&mut expected);
        0u8.write(&mut expected);
        block.write(&mut expected);
        assert_eq!(encoded, expected.freeze());

        let decoded = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
            encoded,
            &config(&committee, committee.codec()),
        )
        .unwrap();
        assert_eq!(decoded.clone().into_payload(), message);

        let artifacts: Vec<_> = decoded.into_payload().into_artifacts().collect();
        assert_eq!(artifacts.len(), 1);
        assert!(matches!(&artifacts[0], Artifact::LeaderBlock(decoded) if decoded == &block));
    }

    #[test]
    fn round_trips_exact_proposal_with_its_parent_first() {
        let committee = committee();
        let block = committee.leader_block(View::new(2));
        let parent = committee.vqc(View::new(1));
        let message = ConsensusMessage::Proposal {
            parent: Some(Box::new(parent.clone())),
            block: Box::new(block.clone()),
        };

        let encoded = envelope(&committee, message.clone()).encode();
        let mut expected = envelope_prefix(&committee);
        0u8.write(&mut expected);
        1u8.write(&mut expected);
        parent.write(&mut expected);
        block.write(&mut expected);
        assert_eq!(encoded, expected.freeze());

        let decoded = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
            encoded,
            &config(&committee, committee.codec()),
        )
        .unwrap();
        assert_eq!(decoded.clone().into_payload(), message);

        let artifacts: Vec<_> = decoded.into_payload().into_artifacts().collect();
        assert_eq!(artifacts.len(), 2);
        assert!(matches!(&artifacts[0], Artifact::Vqc(vqc) if vqc == &parent));
        assert!(matches!(&artifacts[1], Artifact::LeaderBlock(b) if b == &block));

        let certificate = CertificateMessage::Vqc(parent);
        let encoded = envelope(&committee, certificate.clone()).encode();
        let decoded = Envelope::<CertificateMessage<MinPk, Sha256Digest>>::decode_cfg(
            encoded,
            &config(&committee, committee.codec()),
        )
        .unwrap();
        assert_eq!(decoded.into_payload(), certificate);
    }

    fn assert_exact_frame_cap<V: Variant, M>(
        committee: &Committee<V>,
        message: M,
        payload: M::Cfg,
        max_frame_bytes: usize,
    ) where
        M: Debug + EncodeSize + Read + Write,
    {
        let encoded = envelope(committee, message).encode();
        assert_eq!(encoded.len(), max_frame_bytes);
        let config = EnvelopeConfig {
            max_frame_bytes,
            epoch: committee.config.epoch(),
            payload,
        };

        Envelope::<M>::decode_cfg(encoded.clone(), &config).unwrap();

        let mut oversized = BytesMut::from(encoded.as_ref());
        oversized[0] ^= 1;
        oversized[envelope_prefix(committee).len()] = u8::MAX;
        oversized.put_u8(0);
        let oversized_len = oversized.len();
        let error = Envelope::<M>::decode_cfg(oversized.freeze(), &config).unwrap_err();
        assert!(matches!(error, CodecError::InvalidLength(len) if len == oversized_len));
    }

    fn assert_exact_derived_frame_caps_reject_before_parsing<V: Variant>() {
        let committee = maximal_committee::<V>();
        let codec = committee.codec();
        let bounds = codec.encoded_bounds::<V, Sha256Digest>().unwrap();

        let header = transaction_header(&committee, u64::MAX);
        let block = committee.signers[0].sign_transaction_block(header).unwrap();
        assert_exact_frame_cap(
            &committee,
            DataMessage::Block(block),
            codec,
            bounds.max_data_frame_bytes(),
        );

        let parent = maximal_vqc(&committee);
        let leader = maximal_leader_block(&committee);
        let proposal = ConsensusMessage::Proposal {
            parent: Some(Box::new(parent)),
            block: Box::new(leader),
        };
        assert_exact_frame_cap(
            &committee,
            proposal,
            codec,
            bounds.max_consensus_frame_bytes(),
        );

        assert_exact_frame_cap(
            &committee,
            CertificateMessage::Vqc(maximal_vqc(&committee)),
            codec,
            bounds.max_certificate_frame_bytes(),
        );
    }

    #[test]
    fn exact_derived_frame_caps_reject_before_parsing() {
        assert_exact_derived_frame_caps_reject_before_parsing::<MinPk>();
        assert_exact_derived_frame_caps_reject_before_parsing::<MinSig>();
    }

    #[test]
    fn rejects_unknown_proposal_parent_tags() {
        let committee = committee();
        let mut encoded = envelope_prefix(&committee);
        0u8.write(&mut encoded);
        9u8.write(&mut encoded);
        committee.leader_block(View::new(1)).write(&mut encoded);

        let error = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
            encoded.freeze(),
            &config(&committee, committee.codec()),
        )
        .unwrap_err();
        assert!(matches!(error, CodecError::InvalidEnum(9)));
    }

    #[test]
    fn rejects_wrong_version_epoch_and_trailing_bytes() {
        let committee = committee();
        let message = ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
            committee.novote(Participant::new(1), View::new(1)),
        );
        let cfg = config(&committee, committee.codec());

        let valid = envelope(&committee, message).encode();
        assert!(
            Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(valid.clone(), &cfg,)
                .is_ok()
        );

        let mut wrong_version = BytesMut::from(valid.as_ref());
        wrong_version[0] ^= 1;
        assert!(
            Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                wrong_version.freeze(),
                &cfg,
            )
            .is_err()
        );

        let other = Committee::<MinPk>::builder(12, 6).build();
        assert!(
            Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                valid.clone(),
                &config(&other, other.codec()),
            )
            .is_err()
        );

        let mut trailing = BytesMut::from(valid.as_ref());
        trailing.put_u8(0);
        assert!(
            Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(trailing.freeze(), &cfg,)
                .is_err()
        );
    }

    #[test]
    fn rejects_data_messages_for_chains_outside_the_epoch() {
        let committee = committee();
        let codec = committee.codec();
        let header = TransactionBlockHeader::new(
            committee.config.epoch(),
            ChainId::new(codec.chains() as u32),
            Height::new(1),
            Sha256::hash(&[b"parent"]),
            Sha256::hash(&[b"commitment"]),
        )
        .unwrap();
        // Decoding never checks the share, so a valid share over another header suffices.
        let share = committee
            .da_vote(
                Participant::new(1),
                committee.transaction_header(ChainId::new(0), Sha256::hash(&[b"commitment"])),
            )
            .share()
            .clone();
        let message = DataMessage::DaVote(DaVote::new(header, share));
        let encoded = envelope(&committee, message).encode();
        let error = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
            encoded,
            &config(&committee, codec),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CodecError::Invalid("consensus::multimmit::wire::DataMessage", _)
        ));
    }

    #[test]
    fn planes_rotate_through_every_plane() {
        for plane in Plane::ALL {
            let rotation = plane.rotation();
            assert_eq!(rotation[0], plane);
            let mut sorted = rotation;
            sorted.sort();
            assert_eq!(sorted, Plane::ALL, "a rotation visits every plane once");
        }
        assert_eq!(Plane::Consensus.next(), Plane::Certificate);
        assert_eq!(Plane::Certificate.next(), Plane::Data);
        assert_eq!(Plane::Data.next(), Plane::Consensus);
        assert_eq!(
            Plane::ALL.map(Plane::as_str),
            ["data", "consensus", "certificate"]
        );
    }

    #[test]
    fn plane_criticality_matches_every_carried_artifact() {
        let committee = committee();
        let epoch = committee.config.epoch();
        let block =
            committee.signed_block(ChainId::new(0), Sha256::hash(&[b"transaction commitment"]));
        let header = block.header().clone();
        let leader = committee.leader_block(View::new(1));
        let artifacts = [
            Artifact::TransactionBlock(block),
            Artifact::DaVote(committee.da_vote(Participant::new(1), header.clone())),
            Artifact::DaCertificate(da_certificate(&committee, header)),
            Artifact::Vote(committee.vote(Participant::new(0), &leader)),
            Artifact::NoVote(committee.novote(Participant::new(1), View::new(1))),
            Artifact::Nullify(committee.nullify(Participant::new(2), View::new(1))),
            Artifact::Nullification(committee.nullification(View::new(1))),
            Artifact::Vqc(committee.vqc(View::new(1))),
            Artifact::Lqc(committee.lqc(View::new(1))),
        ];
        for artifact in artifacts {
            let frame = Frame::artifact::<Sha256, _>(epoch, &artifact).expect("ordinary artifact");
            assert_eq!(
                frame.plane.view_critical(),
                artifact.view_critical(),
                "{:?} on the {} plane",
                artifact.kind(),
                frame.plane.as_str(),
            );
        }
        let proposal = Frame::proposal(epoch, &leader, None);
        assert!(proposal.plane.view_critical());
        assert!(Artifact::LeaderBlock(leader).view_critical());
    }

    #[test]
    fn rejects_unknown_message_kinds() {
        let committee = committee();
        let mut encoded = envelope_prefix(&committee);
        9u8.write(&mut encoded);
        assert!(
            Envelope::<CertificateMessage<MinPk, Sha256Digest>>::decode_cfg(
                encoded.freeze(),
                &config(&committee, committee.codec()),
            )
            .is_err()
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::{CodecConformance, generate_value};

        #[test]
        fn generated_envelopes_cover_every_wire_arm() {
            let mut data = 0u8;
            let mut consensus = 0u8;
            let mut certificates = 0u8;
            for seed in 0..128 {
                match generate_value::<Envelope<DataMessage<MinPk, Sha256Digest>>>(seed)
                    .into_payload()
                {
                    DataMessage::Block(_) => data |= 1 << 0,
                    DataMessage::DaVote(_) => data |= 1 << 1,
                    DataMessage::DaCertificate(_) => data |= 1 << 2,
                }
                match generate_value::<Envelope<ConsensusMessage<MinPk, Sha256Digest>>>(seed)
                    .into_payload()
                {
                    ConsensusMessage::Proposal { parent: None, .. } => consensus |= 1 << 0,
                    ConsensusMessage::Proposal {
                        parent: Some(_), ..
                    } => consensus |= 1 << 1,
                    ConsensusMessage::Vote(_) => consensus |= 1 << 2,
                    ConsensusMessage::NoVote(_) => consensus |= 1 << 3,
                    ConsensusMessage::Nullify(_) => consensus |= 1 << 4,
                }
                match generate_value::<Envelope<CertificateMessage<MinPk, Sha256Digest>>>(seed)
                    .into_payload()
                {
                    CertificateMessage::Nullification(_) => certificates |= 1 << 0,
                    CertificateMessage::Vqc(_) => certificates |= 1 << 1,
                    CertificateMessage::Lqc(_) => certificates |= 1 << 2,
                }
            }
            assert_eq!(data, 0b111);
            assert_eq!(consensus, 0b1_1111);
            assert_eq!(certificates, 0b111);
        }

        commonware_conformance::conformance_tests! {
            CodecConformance<Envelope<DataMessage<MinPk, Sha256Digest>>> => 128,
            CodecConformance<Envelope<DataMessage<MinSig, Sha256Digest>>> => 128,
            CodecConformance<Envelope<ConsensusMessage<MinPk, Sha256Digest>>> => 128,
            CodecConformance<Envelope<ConsensusMessage<MinSig, Sha256Digest>>> => 128,
            CodecConformance<Envelope<CertificateMessage<MinPk, Sha256Digest>>> => 128,
            CodecConformance<Envelope<CertificateMessage<MinSig, Sha256Digest>>> => 128,
        }
    }
}
