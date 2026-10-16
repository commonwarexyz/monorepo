//! Versioned wire envelope and per-plane message unions for one Multimmit epoch.
//!
//! Every network plane carries [`Envelope`]-framed canonical payloads. The envelope binds the wire
//! version and epoch before any payload bytes are decoded, so traffic for another epoch is rejected
//! without allocating payload state. Payload unions reuse the canonical protocol codecs from
//! [`crate::multimmit::types`]; decoding rejects trailing bytes, non-canonical values, and any
//! count or byte bound above the epoch codec profile.

use crate::{
    multimmit::types::{
        Artifact, ChainId, CodecConfig, Lqc, SignedLeaderBlock, SignedTransactionBlock, VoteUpdate,
        Vqc,
    },
    types::Epoch,
};
use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, Encode as _, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::telemetry::metrics::EncodeLabelValue;

/// The Multimmit wire-format version.
pub const WIRE_VERSION: u8 = 0;

const DATA_BLOCK: u8 = 0;

const CONSENSUS_PROPOSAL: u8 = 0;
const CONSENSUS_UPDATE: u8 = 1;

const PARENT_OMITTED: u8 = 0;
const PARENT_ATTACHED: u8 = 1;

const CERTIFICATE_VQC: u8 = 0;
const CERTIFICATE_LQC: u8 = 1;

/// A network plane: one registered channel with its own message union and frame bound.
///
/// Separate planes keep bulk data from delaying the messages a round waits on.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, EncodeLabelValue)]
pub enum Plane {
    /// Producer-signed transaction-block headers.
    Data = 0,
    /// Leader proposals and vote updates.
    Consensus = 1,
    /// V-QCs and L-QCs.
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
    /// Every consensus plane artifact and every certificate plane V-QC is
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

/// A data-plane message: producer-chain headers.
///
/// Decoding rejects a message addressed to a producer chain outside the epoch codec profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataMessage<V: Variant, D: Digest> {
    /// See [`Artifact::TransactionBlock`].
    Block(SignedTransactionBlock<V, D>),
}

#[cfg(feature = "arbitrary")]
impl<'a, V: Variant, D: Digest> arbitrary::Arbitrary<'a> for DataMessage<V, D>
where
    SignedTransactionBlock<V, D>: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::Block(u.arbitrary()?))
    }
}

impl<V: Variant, D: Digest> DataMessage<V, D> {
    /// Returns the producer chain addressed by this message.
    pub const fn chain(&self) -> ChainId {
        match self {
            Self::Block(block) => block.header().chain(),
        }
    }

    /// Returns this message's untrusted artifact.
    pub fn into_artifact(self) -> Artifact<V, D> {
        match self {
            Self::Block(block) => Artifact::TransactionBlock(block),
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
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for DataMessage<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Block(block) => block.encode_size(),
        }
    }
}

impl<V: Variant, D: Digest> Read for DataMessage<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, codec: &Self::Cfg) -> Result<Self, CodecError> {
        let message = match u8::read(buf)? {
            DATA_BLOCK => Self::Block(SignedTransactionBlock::read(buf)?),
            tag => return Err(CodecError::InvalidEnum(tag)),
        };
        if message.chain().index() >= codec.chains() {
            return Err(CodecError::Invalid(
                "consensus::multimmit::wire::DataMessage",
                "chain outside the epoch",
            ));
        }
        Ok(message)
    }
}

/// A consensus-plane message: leader proposals and vote updates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusMessage<V: Variant, D: Digest> {
    /// A signed leader proposal, optionally carrying the parent V-QC it references.
    Proposal {
        /// The parent certificate, unless it was already broadcast or is synthetic genesis.
        parent: Option<Box<Vqc<V, D>>>,
        /// See [`Artifact::LeaderBlock`].
        block: Box<SignedLeaderBlock<V, D>>,
    },
    /// See [`Artifact::Update`].
    Update(VoteUpdate<V, D>),
}

#[cfg(feature = "arbitrary")]
impl<'a, V: Variant, D: Digest> arbitrary::Arbitrary<'a> for ConsensusMessage<V, D>
where
    Vqc<V, D>: arbitrary::Arbitrary<'a>,
    SignedLeaderBlock<V, D>: arbitrary::Arbitrary<'a>,
    VoteUpdate<V, D>: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=2)? {
            0 => Ok(Self::Proposal {
                parent: None,
                block: Box::new(u.arbitrary()?),
            }),
            1 => Ok(Self::Proposal {
                parent: Some(Box::new(u.arbitrary()?)),
                block: Box::new(u.arbitrary()?),
            }),
            2 => Ok(Self::Update(u.arbitrary()?)),
            _ => unreachable!("generated consensus-message tag is bounded"),
        }
    }
}

impl<V: Variant, D: Digest> ConsensusMessage<V, D> {
    /// Returns this message's untrusted artifacts in observation order.
    ///
    /// An attached proposal parent precedes its leader block so the dependency is observed first.
    #[cfg(test)]
    pub fn into_artifacts(self) -> impl Iterator<Item = Artifact<V, D>> {
        let (parent, artifact) = match self {
            Self::Proposal { parent, block } => {
                let parent = parent.map(|parent| Artifact::Vqc(*parent));
                (parent, Artifact::LeaderBlock(*block))
            }
            Self::Update(update) => (None, Artifact::Update(update)),
        };
        parent.into_iter().chain(std::iter::once(artifact))
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
            Self::Update(update) => {
                CONSENSUS_UPDATE.write(buf);
                update.write(buf);
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
            Self::Update(update) => update.encode_size(),
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
                    block: Box::new(SignedLeaderBlock::read(buf)?),
                })
            }
            CONSENSUS_UPDATE => Ok(Self::Update(VoteUpdate::read_cfg(buf, codec)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// A certificate-plane message: view and finality certificates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertificateMessage<V: Variant, D: Digest> {
    /// See [`Artifact::Vqc`].
    Vqc(Vqc<V, D>),
    /// See [`Artifact::Lqc`].
    Lqc(Lqc<V, D>),
}

#[cfg(feature = "arbitrary")]
impl<'a, V: Variant, D: Digest> arbitrary::Arbitrary<'a> for CertificateMessage<V, D>
where
    Vqc<V, D>: arbitrary::Arbitrary<'a>,
    Lqc<V, D>: arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=1)? {
            0 => Ok(Self::Vqc(u.arbitrary()?)),
            1 => Ok(Self::Lqc(u.arbitrary()?)),
            _ => unreachable!("generated certificate-message tag is bounded"),
        }
    }
}

impl<V: Variant, D: Digest> CertificateMessage<V, D> {
    /// Returns this message's untrusted artifact.
    pub fn into_artifact(self) -> Artifact<V, D> {
        match self {
            Self::Vqc(certificate) => Artifact::Vqc(certificate),
            Self::Lqc(certificate) => Artifact::Lqc(certificate),
        }
    }
}

impl<V: Variant, D: Digest> Write for CertificateMessage<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
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
            Self::Vqc(certificate) => certificate.encode_size(),
            Self::Lqc(certificate) => certificate.encode_size(),
        }
    }
}

impl<V: Variant, D: Digest> Read for CertificateMessage<V, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, codec: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
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
            Artifact::LeaderBlock(_) | Artifact::Floor(_) => return None,
            Artifact::Update(update) => (
                Plane::Consensus,
                Envelope::new(epoch, ConsensusMessage::Update(update.clone())).encode(),
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
        multimmit::types::{CodecConfig, Window},
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
            payload: CodecConfig::new(6, 2, Window::new(2).unwrap()).unwrap(),
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
            types::{ChainChange, ChainSet, TransactionBlockHeader, Window},
        },
        types::{Height, Participant, View},
    };
    use bytes::BytesMut;
    use commonware_codec::Decode as _;
    use commonware_cryptography::{
        Sha256,
        bls12381::primitives::variant::{MinPk, MinSig},
        sha256::Digest as Sha256Digest,
    };
    use core::fmt::Debug;

    fn committee<V: Variant>() -> Committee<V> {
        Committee::builder(11, 6).build()
    }

    fn config<V: Variant>(committee: &Committee<V>) -> EnvelopeConfig<CodecConfig> {
        EnvelopeConfig {
            max_frame_bytes: usize::MAX,
            epoch: committee.config.epoch(),
            payload: committee.codec(),
        }
    }

    fn envelope_prefix<V: Variant>(committee: &Committee<V>) -> BytesMut {
        let mut encoded = BytesMut::new();
        WIRE_VERSION.write(&mut encoded);
        committee.config.epoch().write(&mut encoded);
        encoded
    }

    fn block<V: Variant>(committee: &Committee<V>) -> SignedTransactionBlock<V, Sha256Digest> {
        let genesis = committee.genesis().tips()[0];
        committee.sign_header(committee.header(&genesis, Sha256::hash(&[b"body"])))
    }

    fn update<V: Variant>(committee: &Committee<V>) -> VoteUpdate<V, Sha256Digest> {
        let genesis = committee.genesis().tips().to_vec();
        let mut tips = genesis.clone();
        tips[0] = block(committee).header().block_ref::<Sha256>();
        let endorsement = committee.endorsement(ChainSet::empty(committee.codec().chains()), tips);
        let content = committee.content(View::new(1), None, false, endorsement);
        committee.update(Participant::new(2), &content, &genesis, 1)
    }

    /// Encodes `message` in its envelope and checks it decodes to itself within `max_frame_bytes`.
    fn assert_round_trip<V: Variant, M>(
        committee: &Committee<V>,
        message: M,
        max_frame_bytes: usize,
    ) where
        M: Clone + Debug + PartialEq + EncodeSize + Read<Cfg = CodecConfig> + Write,
    {
        let encoded = Envelope::new(committee.config.epoch(), message.clone()).encode();
        assert!(
            encoded.len() <= max_frame_bytes,
            "{}-byte frame exceeds the derived {max_frame_bytes}-byte bound",
            encoded.len()
        );
        let config = EnvelopeConfig {
            max_frame_bytes,
            ..config(committee)
        };
        let decoded = Envelope::<M>::decode_cfg(encoded, &config).unwrap();
        assert_eq!(decoded.into_payload(), message);
    }

    fn assert_every_message_fits_its_plane<V: Variant>() {
        let committee = committee::<V>();
        let bounds = committee
            .codec()
            .encoded_bounds::<V, Sha256Digest>()
            .unwrap();

        assert_round_trip(
            &committee,
            DataMessage::Block(block(&committee)),
            bounds.max_data_frame_bytes(),
        );

        let parent = committee.vqc(View::new(1));
        let consensus = [
            ConsensusMessage::Proposal {
                parent: None,
                block: Box::new(committee.leader_block(View::new(1))),
            },
            ConsensusMessage::Proposal {
                parent: Some(Box::new(parent.clone())),
                block: Box::new(committee.leader_block_with(
                    View::new(2),
                    parent.id::<Sha256>(),
                    Sha256::hash(&[b"history"]),
                )),
            },
            ConsensusMessage::Update(update(&committee)),
        ];
        for message in consensus {
            assert_round_trip(&committee, message, bounds.max_consensus_frame_bytes());
        }

        for message in [
            CertificateMessage::Vqc(parent),
            CertificateMessage::Lqc(committee.lqc(View::new(1))),
        ] {
            assert_round_trip(&committee, message, bounds.max_certificate_frame_bytes());
        }
    }

    #[test]
    fn every_message_fits_its_plane() {
        assert_every_message_fits_its_plane::<MinPk>();
        assert_every_message_fits_its_plane::<MinSig>();
    }

    #[test]
    fn proposals_carry_their_parent_first() {
        let committee = committee::<MinPk>();
        let parent = committee.vqc(View::new(1));
        let leader = committee.leader_block(View::new(2));
        let message = ConsensusMessage::Proposal {
            parent: Some(Box::new(parent.clone())),
            block: Box::new(leader.clone()),
        };
        let encoded = Envelope::new(committee.config.epoch(), message.clone()).encode();
        let mut expected = envelope_prefix(&committee);
        CONSENSUS_PROPOSAL.write(&mut expected);
        PARENT_ATTACHED.write(&mut expected);
        parent.write(&mut expected);
        leader.write(&mut expected);
        assert_eq!(encoded, expected.freeze());

        let artifacts: Vec<_> = message.into_artifacts().collect();
        assert!(matches!(&artifacts[0], Artifact::Vqc(vqc) if vqc == &parent));
        assert!(matches!(&artifacts[1], Artifact::LeaderBlock(block) if block == &leader));
    }

    #[test]
    fn rejects_unknown_tags_wrong_version_epoch_and_trailing_bytes() {
        let committee = committee::<MinPk>();
        let cfg = config(&committee);
        let valid = Envelope::new(
            committee.config.epoch(),
            ConsensusMessage::Update(update(&committee)),
        )
        .encode();
        assert!(
            Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(valid.clone(), &cfg)
                .is_ok()
        );

        let mut wrong_version = BytesMut::from(valid.as_ref());
        wrong_version[0] = 1;
        assert!(
            Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                wrong_version.freeze(),
                &cfg
            )
            .is_err()
        );

        let other = Committee::<MinPk>::builder(12, 6).build();
        assert!(
            Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                valid.clone(),
                &config(&other)
            )
            .is_err()
        );

        let mut trailing = BytesMut::from(valid.as_ref());
        trailing.put_u8(0);
        assert!(
            Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(trailing.freeze(), &cfg)
                .is_err()
        );

        for tag in [2u8, 9] {
            let mut unknown = envelope_prefix(&committee);
            tag.write(&mut unknown);
            assert!(
                Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                    unknown.freeze(),
                    &cfg
                )
                .is_err()
            );
        }
        let mut parent_tag = envelope_prefix(&committee);
        CONSENSUS_PROPOSAL.write(&mut parent_tag);
        9u8.write(&mut parent_tag);
        committee.leader_block(View::new(1)).write(&mut parent_tag);
        assert!(matches!(
            Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                parent_tag.freeze(),
                &cfg
            ),
            Err(CodecError::InvalidEnum(9))
        ));
    }

    #[test]
    fn frame_bound_rejects_before_parsing() {
        let committee = committee::<MinPk>();
        let encoded = Envelope::new(
            committee.config.epoch(),
            DataMessage::Block(block(&committee)),
        )
        .encode();
        let cfg = EnvelopeConfig {
            max_frame_bytes: encoded.len() - 1,
            ..config(&committee)
        };
        assert!(matches!(
            Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(encoded.clone(), &cfg),
            Err(CodecError::InvalidLength(len)) if len == encoded.len()
        ));
    }

    #[test]
    fn rejects_data_messages_for_chains_outside_the_epoch() {
        let committee = committee::<MinPk>();
        let codec = committee.codec();
        let signed = block(&committee);
        let header = TransactionBlockHeader::new(
            committee.config.epoch(),
            ChainId::new(codec.chains() as u32),
            Height::new(1),
            Sha256::hash(&[b"parent"]),
            Sha256::hash(&[b"body"]),
        )
        .unwrap();
        // Decoding never checks the signature, so any attestation suffices.
        let message = DataMessage::Block(SignedTransactionBlock::new(
            header,
            signed.attestation().clone(),
        ));
        let encoded = Envelope::new(committee.config.epoch(), message).encode();
        assert!(matches!(
            Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(encoded, &config(&committee)),
            Err(CodecError::Invalid(
                "consensus::multimmit::wire::DataMessage",
                _
            ))
        ));
    }

    #[test]
    fn update_change_counts_are_bounded_by_the_chain_count() {
        let committee = committee::<MinPk>();
        let codec = CodecConfig::new(11, 6, Window::new(2).unwrap()).unwrap();
        let change = ChainChange::new(committee.genesis().tips()[0], Vec::new(), codec).unwrap();
        assert_eq!(change.chain(), ChainId::new(0));
        let mut encoded = envelope_prefix(&committee);
        CONSENSUS_UPDATE.write(&mut encoded);
        committee.round(View::new(1)).write(&mut encoded);
        Option::<Sha256Digest>::None.write(&mut encoded);
        false.write(&mut encoded);
        ChainSet::empty(6).write(&mut encoded);
        commonware_codec::varint::UInt(1u32).write(&mut encoded);
        commonware_codec::varint::UInt(7u32).write(&mut encoded);
        assert!(
            Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                encoded.freeze(),
                &config(&committee)
            )
            .is_err()
        );
    }

    #[test]
    fn plane_criticality_matches_every_carried_artifact() {
        let committee = committee::<MinPk>();
        let epoch = committee.config.epoch();
        let artifacts = [
            Artifact::TransactionBlock(block(&committee)),
            Artifact::Update(update(&committee)),
            Artifact::Vqc(committee.vqc(View::new(1))),
        ];
        for artifact in artifacts {
            let frame = Frame::artifact::<Sha256, _>(epoch, &artifact).expect("ordinary artifact");
            assert_eq!(frame.plane.view_critical(), artifact.view_critical());
        }
        // An L-QC shares the certificate plane with V-QCs but gates no view.
        let lqc = Artifact::Lqc(committee.lqc(View::new(1)));
        let frame = Frame::artifact::<Sha256, _>(epoch, &lqc).expect("ordinary artifact");
        assert!(frame.plane.view_critical() && !lqc.view_critical());
        let leader = committee.leader_block(View::new(1));
        assert!(Frame::proposal(epoch, &leader, None).plane.view_critical());
        assert!(Artifact::LeaderBlock(leader).view_critical());
    }

    #[test]
    fn planes_rotate_through_every_plane() {
        for plane in Plane::ALL {
            let mut rotation = plane.rotation();
            assert_eq!(rotation[0], plane);
            rotation.sort();
            assert_eq!(rotation, Plane::ALL);
        }
        assert_eq!(
            Plane::ALL.map(Plane::as_str),
            ["data", "consensus", "certificate"]
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

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
