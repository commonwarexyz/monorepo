//! Frozen wire envelope and per-plane message unions for one Multimmit epoch.
//!
//! Every network plane carries [`Envelope`]-framed canonical payloads. The envelope binds the wire
//! version and epoch before any payload bytes are decoded, so traffic for another epoch is rejected
//! without allocating payload state. Payload unions reuse the canonical protocol codecs from
//! [`crate::multimmit::types`]; decoding rejects trailing bytes, non-canonical values, and any count
//! or byte bound above the epoch codec profile.

use crate::{
    multimmit::{
        config::CodecConfig,
        machine::Artifact,
        types::{
            ChainId, DaCertificate, DaVote, Lqc, NoVote, Nullification, Nullify, SignedLeaderBlock,
            SignedTransactionBlock, Vote, Vqc,
        },
    },
    types::Epoch,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::iter::once;

/// The frozen Multimmit wire-format version.
pub const WIRE_VERSION: u8 = 0;

/// The outbound protocol plane selected for one voter transmission.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Plane {
    /// Transaction-block headers, DA shares, and DA certificates.
    Data = 0,
    /// Leader proposals, votes, novotes, and nullify shares.
    Consensus = 1,
    /// Recovered nullifications, V-QCs, and L-QCs.
    Certificate = 2,
}

/// Expected envelope facts plus the payload decode bounds for one plane.
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

#[cfg(feature = "arbitrary")]
impl<'a, M> arbitrary::Arbitrary<'a> for Envelope<M>
where
    M: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?))
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
                "consensus::multimmit::actors::Envelope",
                "unsupported wire version",
            ));
        }
        let epoch = Epoch::read(buf)?;
        if epoch != cfg.epoch {
            return Err(CodecError::Invalid(
                "consensus::multimmit::actors::Envelope",
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataMessage<V: Variant, D: Digest> {
    /// A producer-authenticated transaction-block header.
    Block(SignedTransactionBlock<V, D>),
    /// One attributed data-availability share.
    DaVote(DaVote<V, D>),
    /// A recovered data-availability certificate.
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
                0u8.write(buf);
                block.write(buf);
            }
            Self::DaVote(vote) => {
                1u8.write(buf);
                vote.write(buf);
            }
            Self::DaCertificate(certificate) => {
                2u8.write(buf);
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
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Block(SignedTransactionBlock::read(buf)?)),
            1 => Ok(Self::DaVote(DaVote::read(buf)?)),
            2 => Ok(Self::DaCertificate(DaCertificate::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// A consensus-plane message: proposals, votes, abstentions, and nullify shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusMessage<V: Variant, D: Digest> {
    /// A signed leader proposal, optionally carrying the exact parent V-QC it references.
    Proposal {
        /// The exact parent certificate, unless it was already broadcast or is synthetic genesis.
        parent: Option<Box<Vqc<V, D>>>,
        /// The leader-authenticated proposal.
        block: Box<SignedLeaderBlock<V, D>>,
    },
    /// A complete consensus vote.
    Vote(Vote<V, D>),
    /// An attributed abstention.
    NoVote(NoVote<V>),
    /// An attributed nullification share.
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
                0u8.write(buf);
                match parent {
                    None => 0u8.write(buf),
                    Some(parent) => {
                        1u8.write(buf);
                        parent.write(buf);
                    }
                }
                block.write(buf);
            }
            Self::Vote(vote) => {
                1u8.write(buf);
                vote.write(buf);
            }
            Self::NoVote(vote) => {
                2u8.write(buf);
                vote.write(buf);
            }
            Self::Nullify(nullify) => {
                3u8.write(buf);
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
            0 => {
                let parent = match u8::read(buf)? {
                    0 => None,
                    1 => Some(Box::new(Vqc::read_cfg(buf, codec)?)),
                    tag => return Err(CodecError::InvalidEnum(tag)),
                };
                Ok(Self::Proposal {
                    parent,
                    block: Box::new(SignedLeaderBlock::read_cfg(buf, codec)?),
                })
            }
            1 => Ok(Self::Vote(Vote::read_cfg(buf, codec)?)),
            2 => Ok(Self::NoVote(NoVote::read(buf)?)),
            3 => Ok(Self::Nullify(Nullify::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// A certificate-plane message: recovered or aggregated exit and finality proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertificateMessage<V: Variant, D: Digest> {
    /// A recovered threshold nullification.
    Nullification(Nullification<V>),
    /// A view quorum certificate.
    Vqc(Vqc<V, D>),
    /// A leader finalization quorum certificate.
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
                0u8.write(buf);
                nullification.write(buf);
            }
            Self::Vqc(certificate) => {
                1u8.write(buf);
                certificate.write(buf);
            }
            Self::Lqc(certificate) => {
                2u8.write(buf);
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
            0 => Ok(Self::Nullification(Nullification::read(buf)?)),
            1 => Ok(Self::Vqc(Vqc::read_cfg(buf, codec)?)),
            2 => Ok(Self::Lqc(Lqc::read_cfg(buf, codec)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::Limits,
            mocks::Committee,
            types::{
                Anchor, CertificateId, ChainId, ChainProposal, Height, LeaderBlock,
                TransactionBlockHeader, ViewMessage,
            },
        },
        types::{Participant, Round, View},
    };
    use bytes::{BufMut, BytesMut};
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_cryptography::{
        Hasher as _, Sha256,
        bls12381::primitives::variant::{MinPk, MinSig},
        sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use core::fmt::Debug;

    fn committee() -> Committee<MinPk> {
        Committee::new(11, 6, Limits::new(2, 1).unwrap())
    }

    fn maximal_committee<V: Variant>() -> Committee<V> {
        Committee::new(u64::MAX, 1, Limits::new(1, 0).unwrap())
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
            .map(|signer| committee.da_vote(signer, header.clone()))
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
        let vote = committee.vote(0, &leader);
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
        let block = committee.signed_block(0, commitment);
        let header = block.header().clone();

        let data = [
            DataMessage::Block(block),
            DataMessage::DaVote(committee.da_vote(1, header)),
        ];
        for message in data {
            let encoded = envelope(&committee, message.clone()).encode();
            let decoded = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                encoded,
                &config(&committee, ()),
            )
            .unwrap();
            assert_eq!(decoded.into_payload(), message);
        }

        let consensus = [
            ConsensusMessage::NoVote(committee.novote(2, 1)),
            ConsensusMessage::Nullify(committee.nullify(3, 1)),
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

        let message = CertificateMessage::Nullification(committee.nullification(1));
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
        let committee = Committee::<V>::new_with_namespace_and_producers(
            11,
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_WIRE_BOUNDS_TEST",
            6,
            vec![Participant::new(4), Participant::new(1)],
            Limits::new(2, 1).unwrap(),
        );
        let codec = committee.codec();
        let bounds = codec.encoded_bounds::<V, Sha256Digest>().unwrap();

        let block = committee.signed_block(0, Sha256::hash(&[b"transaction commitment"]));
        let header = block.header().clone();
        let data = [
            DataMessage::Block(block),
            DataMessage::DaVote(committee.da_vote(1, header.clone())),
            DataMessage::DaCertificate(da_certificate(&committee, header)),
        ];
        for message in data {
            assert_accepted_under_bound(&committee, message, (), bounds.max_data_frame_bytes());
        }

        let genesis_block = committee.leader_block(1);
        let parent = committee.vqc(2);
        let exact_block = committee.leader_block_with_parent(3, &parent);
        let consensus = [
            ConsensusMessage::Proposal {
                parent: None,
                block: Box::new(genesis_block.clone()),
            },
            ConsensusMessage::Proposal {
                parent: Some(Box::new(parent.clone())),
                block: Box::new(exact_block),
            },
            ConsensusMessage::Vote(committee.vote(0, &genesis_block)),
            ConsensusMessage::NoVote(committee.novote(1, 1)),
            ConsensusMessage::Nullify(committee.nullify(2, 1)),
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
            CertificateMessage::Nullification(committee.nullification(1)),
            CertificateMessage::Vqc(parent),
            CertificateMessage::Lqc(committee.lqc(1)),
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
        let message = ConsensusMessage::<MinPk, Sha256Digest>::NoVote(committee.novote(1, 1));
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
        let block = committee.leader_block(1);
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
        let block = committee.leader_block(2);
        let parent = committee.vqc(1);
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
            (),
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
        committee.leader_block(1).write(&mut encoded);

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
        let message = ConsensusMessage::<MinPk, Sha256Digest>::NoVote(committee.novote(1, 1));
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

        let other = Committee::<MinPk>::new(12, 6, Limits::new(2, 1).unwrap());
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
