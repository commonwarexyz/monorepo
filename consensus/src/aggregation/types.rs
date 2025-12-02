//! Types used in [aggregation](super).

use crate::{
    aggregation::signing_scheme::AggregationScheme,
    signing_scheme::{Context, Scheme, Vote},
    types::Epoch,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write,
};
use commonware_cryptography::Digest;
use commonware_utils::union;
use futures::channel::oneshot;
use rand::{CryptoRng, Rng};
use std::hash::Hash;

/// Error that may be encountered when interacting with `aggregation`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // Proposal Errors
    /// The proposal was canceled by the application
    #[error("Application verify error: {0}")]
    AppProposeCanceled(oneshot::Canceled),

    // P2P Errors
    /// Unable to send a message over the P2P network
    #[error("Unable to send message")]
    UnableToSendMessage,

    // Epoch Errors
    /// The specified validator is not a participant in the epoch
    #[error("Epoch {0} has no validator {1}")]
    UnknownValidator(Epoch, String),
    /// The local node is not a signer in the scheme for the specified epoch.
    #[error("Not a signer at epoch {0}")]
    NotASigner(Epoch),

    // Peer Errors
    /// The sender's public key doesn't match the expected key
    #[error("Peer mismatch")]
    PeerMismatch,

    // Signature Errors
    /// The acknowledgment signature is invalid
    #[error("Invalid ack signature")]
    InvalidAckSignature,

    // Ignorable Message Errors
    /// The acknowledgment's epoch is outside the accepted bounds
    #[error("Invalid ack epoch {0} outside bounds {1} - {2}")]
    AckEpochOutsideBounds(Epoch, Epoch, Epoch),
    /// The acknowledgment's height is outside the accepted bounds
    #[error("Non-useful ack index {0}")]
    AckIndex(Index),
    /// The acknowledgment's digest is incorrect
    #[error("Invalid ack digest {0}")]
    AckDigest(Index),
    /// Duplicate acknowledgment for the same index
    #[error("Duplicate ack from sender {0} for index {1}")]
    AckDuplicate(String, Index),
    /// The acknowledgement is for an index that already has a certificate
    #[error("Ack for index {0} already has been certified")]
    AckCertified(Index),
    /// The epoch is unknown
    #[error("Unknown epoch {0}")]
    UnknownEpoch(Epoch),
}

impl Error {
    /// Returns true if the error represents a blockable offense by a peer.
    pub fn blockable(&self) -> bool {
        matches!(self, Error::PeerMismatch | Error::InvalidAckSignature)
    }
}

/// Index represents the sequential position of items being aggregated.
/// Indices are monotonically increasing within each epoch.
pub type Index = u64;

/// Suffix used to identify an acknowledgment (ack) namespace for domain separation.
/// Used when signing and verifying acks to prevent signature reuse across different message types.
const ACK_SUFFIX: &[u8] = b"_AGG_ACK";

/// Returns a suffixed namespace for signing an ack.
///
/// This provides domain separation for signatures, preventing cross-protocol attacks
/// by ensuring signatures for acks cannot be reused for other message types.
#[inline]
fn ack_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ACK_SUFFIX)
}

/// Item represents a single element being aggregated in the protocol.
/// Each item has a unique index and contains a digest that validators sign.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Item<D: Digest> {
    /// Sequential position of this item within the current epoch
    pub index: Index,
    /// Cryptographic digest of the data being aggregated
    pub digest: D,
}

impl<D: Digest> Write for Item<D> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.index).write(writer);
        self.digest.write(writer);
    }
}

impl<D: Digest> Read for Item<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let index = UInt::read(reader)?.into();
        let digest = D::read(reader)?;
        Ok(Self { index, digest })
    }
}

impl<D: Digest> EncodeSize for Item<D> {
    fn encode_size(&self) -> usize {
        UInt(self.index).encode_size() + self.digest.encode_size()
    }
}

impl<D: Digest> Context for &Item<D> {
    fn namespace_and_message(&self, namespace: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (ack_namespace(namespace), self.encode().to_vec())
    }
}

/// Acknowledgment (ack) represents a validator's vote on an item.
/// Multiple acks can be recovered into a certificate for consensus.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ack<S: Scheme, D: Digest> {
    /// The item being acknowledged
    pub item: Item<D>,
    /// The epoch in which this acknowledgment was created
    pub epoch: Epoch,
    /// Scheme-specific vote material
    pub vote: Vote<S>,
}

impl<S: Scheme, D: Digest> Ack<S, D> {
    /// Verifies the signature on this acknowledgment.
    ///
    /// Returns `true` if the signature is valid for the given namespace and public key.
    /// Domain separation is automatically applied to prevent signature reuse.
    pub fn verify(&self, scheme: &S, namespace: &[u8]) -> bool
    where
        S: AggregationScheme<D>,
    {
        scheme.verify_vote::<D>(namespace, &self.item, &self.vote)
    }

    /// Creates a new acknowledgment by signing an item with a validator's key.
    ///
    /// The signature uses domain separation to prevent cross-protocol attacks.
    ///
    /// # Determinism
    ///
    /// Signatures produced by this function are deterministic and safe for consensus.
    pub fn sign(scheme: &S, namespace: &[u8], epoch: Epoch, item: Item<D>) -> Option<Self>
    where
        S: AggregationScheme<D>,
    {
        let vote = scheme.sign_vote::<D>(namespace, &item)?;
        Some(Self { item, epoch, vote })
    }
}

impl<S: Scheme, D: Digest> Write for Ack<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.item.write(writer);
        self.epoch.write(writer);
        self.vote.write(writer);
    }
}

impl<S: Scheme, D: Digest> Read for Ack<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let item = Item::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let vote = Vote::read(reader)?;
        Ok(Self { item, epoch, vote })
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Ack<S, D> {
    fn encode_size(&self) -> usize {
        self.item.encode_size() + self.epoch.encode_size() + self.vote.encode_size()
    }
}

/// Message exchanged between peers containing an acknowledgment and tip information.
/// This combines a validator's vote with their view of consensus progress.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TipAck<S: Scheme, D: Digest> {
    /// The peer's local view of the tip (the lowest index that is not yet confirmed).
    pub tip: Index,

    /// The peer's acknowledgement (vote) for an item.
    pub ack: Ack<S, D>,
}

impl<S: Scheme, D: Digest> Write for TipAck<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.tip).write(writer);
        self.ack.write(writer);
    }
}

impl<S: Scheme, D: Digest> Read for TipAck<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tip = UInt::read(reader)?.into();
        let ack = Ack::read(reader)?;
        Ok(Self { tip, ack })
    }
}

impl<S: Scheme, D: Digest> EncodeSize for TipAck<S, D> {
    fn encode_size(&self) -> usize {
        UInt(self.tip).encode_size() + self.ack.encode_size()
    }
}

/// A recovered certificate for some [Item].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<S: Scheme, D: Digest> {
    /// The item that was recovered.
    pub item: Item<D>,
    /// The recovered certificate.
    pub certificate: S::Certificate,
}

impl<S: Scheme, D: Digest> Certificate<S, D> {
    pub fn from_acks<'a>(scheme: &S, acks: impl IntoIterator<Item = &'a Ack<S, D>>) -> Option<Self>
    where
        S: AggregationScheme<D>,
    {
        let mut iter = acks.into_iter().peekable();
        let item = iter.peek()?.item.clone();
        let votes = iter
            .filter(|ack| ack.item == item)
            .map(|ack| ack.vote.clone());
        let certificate = scheme.assemble_certificate(votes)?;

        Some(Self { item, certificate })
    }

    /// Verifies the recovered certificate for the item.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, namespace: &[u8]) -> bool
    where
        R: Rng + CryptoRng,
        S: AggregationScheme<D>,
    {
        scheme.verify_certificate::<_, D>(rng, namespace, &self.item, &self.certificate)
    }
}

impl<S: Scheme, D: Digest> Write for Certificate<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.item.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: Scheme, D: Digest> Read for Certificate<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let item = Item::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;
        Ok(Self { item, certificate })
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Certificate<S, D> {
    fn encode_size(&self) -> usize {
        self.item.encode_size() + self.certificate.encode_size()
    }
}

/// Used as [Reporter::Activity](crate::Reporter::Activity) to report activities that occur during
/// aggregation. Also used to journal events that are needed to initialize the aggregation engine
/// when the node restarts.
#[derive(Clone, Debug, PartialEq)]
pub enum Activity<S: Scheme, D: Digest> {
    /// Received an ack from a participant.
    Ack(Ack<S, D>),

    /// Certified an [Item].
    Certified(Certificate<S, D>),

    /// Moved the tip to a new index.
    Tip(Index),
}

impl<S: Scheme, D: Digest> Write for Activity<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Activity::Ack(ack) => {
                0u8.write(writer);
                ack.write(writer);
            }
            Activity::Certified(certificate) => {
                1u8.write(writer);
                certificate.write(writer);
            }
            Activity::Tip(index) => {
                2u8.write(writer);
                UInt(*index).write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> Read for Activity<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Activity::Ack(Ack::read(reader)?)),
            1 => Ok(Activity::Certified(Certificate::read_cfg(reader, cfg)?)),
            2 => Ok(Activity::Tip(UInt::read(reader)?.into())),
            _ => Err(CodecError::Invalid(
                "consensus::aggregation::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Activity<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Activity::Ack(ack) => ack.encode_size(),
            Activity::Certified(certificate) => certificate.encode_size(),
            Activity::Tip(index) => UInt(*index).encode_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregation::signing_scheme::{bls12381_multisig, bls12381_threshold, ed25519};
    use bytes::BytesMut;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::{
            dkg::ops,
            primitives::{
                group::Private as BlsPrivate,
                variant::{MinPk, MinSig, Variant},
            },
        },
        ed25519::{PrivateKey as EdPrivateKey, PublicKey as EdPublicKey},
        Hasher, PrivateKeyExt, Sha256, Signer,
    };
    use commonware_utils::{
        quorum,
        set::{Ordered, OrderedQuorum},
    };
    use rand::{rngs::StdRng, SeedableRng};

    const NAMESPACE: &[u8] = b"test";

    type Sha256Digest = <Sha256 as Hasher>::Digest;

    fn generate_ed25519_schemes(n: usize, seed: u64) -> Vec<ed25519::Scheme> {
        let mut rng = StdRng::seed_from_u64(seed);
        let private_keys: Vec<_> = (0..n).map(|_| EdPrivateKey::from_rng(&mut rng)).collect();

        let participants: Ordered<_> = private_keys.iter().map(|p| p.public_key()).collect();

        private_keys
            .into_iter()
            .map(|sk| ed25519::Scheme::new(participants.clone(), sk))
            .collect()
    }

    fn generate_bls12381_multisig_schemes<V: Variant>(
        n: u32,
        seed: u64,
    ) -> Vec<bls12381_multisig::Scheme<EdPublicKey, V>> {
        let mut rng = StdRng::seed_from_u64(seed);

        // Generate ed25519 keys for participant identities
        let identity_keys: Vec<_> = (0..n).map(|_| EdPrivateKey::from_rng(&mut rng)).collect();
        let participants: Vec<_> = identity_keys.iter().map(|p| p.public_key()).collect();

        // Generate BLS keys for signing
        let bls_keys: Vec<_> = (0..n).map(|_| BlsPrivate::from_rand(&mut rng)).collect();
        let bls_publics: Vec<_> = bls_keys
            .iter()
            .map(|sk| commonware_cryptography::bls12381::primitives::ops::compute_public::<V>(sk))
            .collect();

        let participants_with_bls = participants
            .into_iter()
            .zip(bls_publics)
            .collect::<commonware_utils::set::OrderedAssociated<_, _>>();

        bls_keys
            .into_iter()
            .map(|bls_sk| bls12381_multisig::Scheme::new(participants_with_bls.clone(), bls_sk))
            .collect()
    }

    fn generate_bls12381_threshold_schemes<V: Variant>(
        n: u32,
        seed: u64,
    ) -> Vec<bls12381_threshold::Scheme<EdPublicKey, V>> {
        let mut rng = StdRng::seed_from_u64(seed);
        let t = quorum(n);

        // Generate ed25519 keys for participant identities
        let participants: Vec<_> = (0..n)
            .map(|_| EdPrivateKey::from_rng(&mut rng).public_key())
            .collect();

        let (polynomial, shares) = ops::generate_shares::<_, V>(&mut rng, None, n, t);

        shares
            .into_iter()
            .map(|share| {
                bls12381_threshold::Scheme::new(participants.clone().into(), &polynomial, share)
            })
            .collect()
    }

    #[test]
    fn test_ack_namespace() {
        let namespace = b"test_namespace";
        let expected = [namespace, ACK_SUFFIX].concat();
        assert_eq!(ack_namespace(namespace), expected);
    }

    fn codec<S: AggregationScheme<Sha256Digest>>(schemes: &[S]) {
        let item = Item {
            index: 100,
            digest: Sha256::hash(b"test_item"),
        };

        // Test Item codec
        let restored_item = Item::decode(item.encode()).unwrap();
        assert_eq!(item, restored_item);

        // Test Ack creation and codec
        let ack = Ack::sign(&schemes[0], NAMESPACE, Epoch::new(1), item.clone()).unwrap();
        let cfg = schemes[0].certificate_codec_config();
        let encoded_ack = ack.encode();
        let restored_ack: Ack<S, Sha256Digest> = Ack::decode(encoded_ack).unwrap();

        // Verify the restored ack
        assert_eq!(restored_ack.item, item);
        assert_eq!(restored_ack.epoch, Epoch::new(1));
        assert!(restored_ack.verify(&schemes[0], NAMESPACE));

        // Test TipAck codec
        let tip_ack = TipAck {
            ack: ack.clone(),
            tip: 42,
        };
        let encoded_tip_ack = tip_ack.encode();
        let restored_tip_ack: TipAck<S, Sha256Digest> = TipAck::decode(encoded_tip_ack).unwrap();
        assert_eq!(restored_tip_ack.tip, 42);
        assert_eq!(restored_tip_ack.ack.item, item);
        assert_eq!(restored_tip_ack.ack.epoch, Epoch::new(1));

        // Test Activity codec - Ack variant
        let activity_ack = Activity::Ack(ack.clone());
        let encoded_activity = activity_ack.encode();
        let restored_activity_ack: Activity<S, Sha256Digest> =
            Activity::decode_cfg(encoded_activity, &cfg).unwrap();
        if let Activity::Ack(restored) = restored_activity_ack {
            assert_eq!(restored.item, item);
            assert_eq!(restored.epoch, Epoch::new(1));
        } else {
            panic!("Expected Activity::Ack");
        }

        // Test Activity codec - Certified variant
        // Collect enough acks for a certificate
        let acks: Vec<_> = schemes
            .iter()
            .take(schemes[0].participants().quorum() as usize)
            .filter_map(|scheme| Ack::sign(scheme, NAMESPACE, Epoch::new(1), item.clone()))
            .collect();

        let certificate = Certificate::from_acks(&schemes[0], &acks).unwrap();
        let mut rng = StdRng::seed_from_u64(0);
        assert!(certificate.verify(&mut rng, &schemes[0], NAMESPACE));

        let activity_certified = Activity::Certified(certificate.clone());
        let encoded_certified = activity_certified.encode();
        let restored_activity_certified: Activity<S, Sha256Digest> =
            Activity::decode_cfg(encoded_certified, &cfg).unwrap();
        if let Activity::Certified(restored) = restored_activity_certified {
            assert_eq!(restored.item, item);
            assert!(restored.verify(&mut rng, &schemes[0], NAMESPACE));
        } else {
            panic!("Expected Activity::Certified");
        }

        // Test Activity codec - Tip variant
        let activity_tip: Activity<S, Sha256Digest> = Activity::Tip(123);
        let encoded_tip = activity_tip.encode();
        let restored_activity_tip: Activity<S, Sha256Digest> =
            Activity::decode_cfg(encoded_tip, &cfg).unwrap();
        if let Activity::Tip(index) = restored_activity_tip {
            assert_eq!(index, 123);
        } else {
            panic!("Expected Activity::Tip");
        }
    }

    #[test]
    fn test_codec() {
        let ed_schemes = generate_ed25519_schemes(4, 0);
        codec(&ed_schemes);

        let multisig_schemes = generate_bls12381_multisig_schemes::<MinPk>(4, 0);
        codec(&multisig_schemes);

        let threshold_schemes = generate_bls12381_threshold_schemes::<MinSig>(4, 0);
        codec(&threshold_schemes);
    }

    fn activity_invalid_enum<S: AggregationScheme<Sha256Digest>>(schemes: &[S]) {
        let mut buf = BytesMut::new();
        3u8.write(&mut buf); // Invalid discriminant

        let cfg = schemes[0].certificate_codec_config();
        let result = Activity::<S, Sha256Digest>::read_cfg(&mut &buf[..], &cfg);
        assert!(matches!(
            result,
            Err(CodecError::Invalid(
                "consensus::aggregation::Activity",
                "Invalid type"
            ))
        ));
    }

    #[test]
    fn test_activity_invalid_enum() {
        let ed_schemes = generate_ed25519_schemes(4, 1);
        activity_invalid_enum(&ed_schemes);

        let multisig_schemes = generate_bls12381_multisig_schemes::<MinPk>(4, 1);
        activity_invalid_enum(&multisig_schemes);

        let threshold_schemes = generate_bls12381_threshold_schemes::<MinSig>(4, 1);
        activity_invalid_enum(&threshold_schemes);
    }
}
