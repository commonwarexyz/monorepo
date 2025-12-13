//! Types used in [aggregation](super).

use crate::types::Epoch;
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write,
};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Share,
        ops,
        sharing::Sharing,
        variant::{PartialSignature, Variant},
    },
    Digest,
};
use commonware_utils::union;
use futures::channel::oneshot;
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
    /// No cryptographic share is known for the specified epoch
    #[error("Unknown share at epoch {0}")]
    UnknownShare(Epoch),

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
    /// The acknowledgement is for an index that already has a threshold
    #[error("Ack for index {0} already has a threshold")]
    AckThresholded(Index),
    /// The epoch is unknown
    #[error("Unknown epoch {0}")]
    UnknownEpoch(Epoch),
}

impl Error {
    /// Returns true if the error represents a blockable offense by a peer.
    pub const fn blockable(&self) -> bool {
        matches!(self, Self::PeerMismatch | Self::InvalidAckSignature)
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

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Item<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let index = u.arbitrary::<u64>()?;
        let digest = u.arbitrary::<D>()?;
        Ok(Self { index, digest })
    }
}

/// Acknowledgment (ack) represents a validator's partial signature on an item.
/// Multiple acks can be recovered into a threshold signature for consensus.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ack<V: Variant, D: Digest> {
    /// The item being acknowledged
    pub item: Item<D>,
    /// The epoch in which this acknowledgment was created
    pub epoch: Epoch,
    /// Partial signature on the item using the validator's threshold share
    pub signature: PartialSignature<V>,
}

impl<V: Variant, D: Digest> Ack<V, D> {
    /// Verifies the partial signature on this acknowledgment.
    ///
    /// Returns `true` if the signature is valid for the given namespace and public key.
    /// Domain separation is automatically applied to prevent signature reuse.
    pub fn verify(&self, namespace: &[u8], polynomial: &Sharing<V>) -> bool {
        let Ok(public) = polynomial.partial_public(self.signature.index) else {
            return false;
        };
        ops::verify_message::<V>(
            &public,
            Some(ack_namespace(namespace).as_ref()),
            self.item.encode().as_ref(),
            &self.signature.value,
        )
        .is_ok()
    }

    /// Creates a new acknowledgment by signing an item with a validator's threshold share.
    ///
    /// The signature uses domain separation to prevent cross-protocol attacks.
    ///
    /// # Determinism
    ///
    /// Signatures produced by this function are deterministic and safe for consensus.
    pub fn sign(namespace: &[u8], epoch: Epoch, share: &Share, item: Item<D>) -> Self {
        let ack_namespace = ack_namespace(namespace);
        let signature = ops::partial_sign_message::<V>(
            share,
            Some(ack_namespace.as_ref()),
            item.encode().as_ref(),
        );
        Self {
            item,
            epoch,
            signature,
        }
    }
}

impl<V: Variant, D: Digest> Write for Ack<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.item.write(writer);
        self.epoch.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Variant, D: Digest> Read for Ack<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let item = Item::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let signature = PartialSignature::<V>::read(reader)?;
        Ok(Self {
            item,
            epoch,
            signature,
        })
    }
}

impl<V: Variant, D: Digest> EncodeSize for Ack<V, D> {
    fn encode_size(&self) -> usize {
        self.item.encode_size() + self.epoch.encode_size() + self.signature.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant, D: Digest> arbitrary::Arbitrary<'_> for Ack<V, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    PartialSignature<V>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let item = u.arbitrary::<Item<D>>()?;
        let epoch = u.arbitrary::<Epoch>()?;
        let signature = u.arbitrary::<PartialSignature<V>>()?;
        Ok(Self {
            item,
            epoch,
            signature,
        })
    }
}

/// Message exchanged between peers containing an acknowledgment and tip information.
/// This combines a validator's partial signature with their view of consensus progress.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TipAck<V: Variant, D: Digest> {
    /// The peer's local view of the tip (the lowest index that is not yet confirmed).
    pub tip: Index,

    /// The peer's acknowledgement (partial signature) for an item.
    pub ack: Ack<V, D>,
}

impl<V: Variant, D: Digest> Write for TipAck<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.tip).write(writer);
        self.ack.write(writer);
    }
}

impl<V: Variant, D: Digest> Read for TipAck<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tip = UInt::read(reader)?.into();
        let ack = Ack::<V, D>::read(reader)?;
        Ok(Self { tip, ack })
    }
}

impl<V: Variant, D: Digest> EncodeSize for TipAck<V, D> {
    fn encode_size(&self) -> usize {
        UInt(self.tip).encode_size() + self.ack.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant, D: Digest> arbitrary::Arbitrary<'_> for TipAck<V, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    Ack<V, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let tip = u.arbitrary::<u64>()?;
        let ack = u.arbitrary::<Ack<V, D>>()?;
        Ok(Self { tip, ack })
    }
}

/// A recovered signature for some [Item].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<V: Variant, D: Digest> {
    /// The item that was recovered.
    pub item: Item<D>,
    /// The recovered signature.
    pub signature: V::Signature,
}

impl<V: Variant, D: Digest> Write for Certificate<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.item.write(writer);
        self.signature.write(writer);
    }
}

impl<V: Variant, D: Digest> Read for Certificate<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let item = Item::read(reader)?;
        let signature = V::Signature::read(reader)?;
        Ok(Self { item, signature })
    }
}

impl<V: Variant, D: Digest> EncodeSize for Certificate<V, D> {
    fn encode_size(&self) -> usize {
        self.item.encode_size() + self.signature.encode_size()
    }
}

impl<V: Variant, D: Digest> Certificate<V, D> {
    /// Verifies the signature on this certificate.
    ///
    /// Returns `true` if the signature is valid for the given namespace and public key.
    /// Domain separation is automatically applied to prevent signature reuse.
    pub fn verify(&self, namespace: &[u8], identity: &V::Public) -> bool {
        ops::verify_message::<V>(
            identity,
            Some(ack_namespace(namespace).as_ref()),
            self.item.encode().as_ref(),
            &self.signature,
        )
        .is_ok()
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant, D: Digest> arbitrary::Arbitrary<'_> for Certificate<V, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    V::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let item = u.arbitrary::<Item<D>>()?;
        let signature = u.arbitrary::<V::Signature>()?;
        Ok(Self { item, signature })
    }
}

/// Used as [Reporter::Activity](crate::Reporter::Activity) to report activities that occur during
/// aggregation. Also used to journal events that are needed to initialize the aggregation engine
/// when the node restarts.
#[derive(Clone, Debug, PartialEq)]
pub enum Activity<V: Variant, D: Digest> {
    /// Received an ack from a participant.
    Ack(Ack<V, D>),

    /// Certified an [Item].
    Certified(Certificate<V, D>),

    /// Moved the tip to a new index.
    Tip(Index),
}

impl<V: Variant, D: Digest> Write for Activity<V, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Ack(ack) => {
                0u8.write(writer);
                ack.write(writer);
            }
            Self::Certified(certificate) => {
                1u8.write(writer);
                certificate.write(writer);
            }
            Self::Tip(index) => {
                2u8.write(writer);
                UInt(*index).write(writer);
            }
        }
    }
}

impl<V: Variant, D: Digest> Read for Activity<V, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Self::Ack(Ack::read(reader)?)),
            1 => Ok(Self::Certified(Certificate::read(reader)?)),
            2 => Ok(Self::Tip(UInt::read(reader)?.into())),
            _ => Err(CodecError::Invalid(
                "consensus::aggregation::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for Activity<V, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Ack(ack) => ack.encode_size(),
            Self::Certified(certificate) => certificate.encode_size(),
            Self::Tip(index) => UInt(*index).encode_size(),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant, D: Digest> arbitrary::Arbitrary<'_> for Activity<V, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    Ack<V, D>: for<'a> arbitrary::Arbitrary<'a>,
    Certificate<V, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => Ok(Self::Ack(u.arbitrary::<Ack<V, D>>()?)),
            1 => Ok(Self::Certified(u.arbitrary::<Certificate<V, D>>()?)),
            2 => Ok(Self::Tip(u.arbitrary::<u64>()?)),
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::{
            dkg,
            primitives::{ops::sign_message, variant::MinSig},
        },
        Hasher, Sha256,
    };
    use commonware_utils::NZU32;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn test_ack_namespace() {
        let namespace = b"test_namespace";
        let expected = [namespace, ACK_SUFFIX].concat();
        assert_eq!(ack_namespace(namespace), expected);
    }

    #[test]
    fn test_codec() {
        let namespace = b"test";
        let mut rng = StdRng::seed_from_u64(0);
        let (public, shares) =
            dkg::deal_anonymous::<MinSig>(&mut rng, Default::default(), NZU32!(4));
        let item = Item {
            index: 100,
            digest: Sha256::hash(b"test_item"),
        };

        // Test Item codec
        let restored_item = Item::decode(item.encode()).unwrap();
        assert_eq!(item, restored_item);

        // Test Ack creation, signing, verification, and codec
        let ack: Ack<MinSig, _> = Ack::sign(namespace, Epoch::new(1), &shares[0], item.clone());
        assert!(ack.verify(namespace, &public));
        assert!(!ack.verify(b"wrong", &public));

        let restored_ack: Ack<MinSig, <Sha256 as Hasher>::Digest> =
            Ack::decode(ack.encode()).unwrap();
        assert_eq!(ack, restored_ack);

        // Test TipAck codec
        let tip_ack = TipAck { ack, tip: 42 };
        let restored: TipAck<MinSig, <Sha256 as Hasher>::Digest> =
            TipAck::decode(tip_ack.encode()).unwrap();
        assert_eq!(tip_ack, restored);

        // Test Activity codec - Ack variant
        let activity_ack = Activity::Ack(Ack::sign(
            namespace,
            Epoch::new(1),
            &shares[0],
            item.clone(),
        ));
        let restored_activity_ack: Activity<MinSig, <Sha256 as Hasher>::Digest> =
            Activity::decode(activity_ack.encode()).unwrap();
        assert_eq!(activity_ack, restored_activity_ack);

        // Test Activity codec - Certified variant
        let signature = sign_message::<MinSig>(shares[0].as_ref(), Some(b"test"), b"message");
        let activity_certified = Activity::Certified(Certificate { item, signature });
        let restored_activity_certified: Activity<MinSig, <Sha256 as Hasher>::Digest> =
            Activity::decode(activity_certified.encode()).unwrap();
        assert_eq!(activity_certified, restored_activity_certified);

        // Test Activity codec - Tip variant
        let activity_tip = Activity::Tip(123);
        let restored_activity_tip: Activity<MinSig, <Sha256 as Hasher>::Digest> =
            Activity::decode(activity_tip.encode()).unwrap();
        assert_eq!(activity_tip, restored_activity_tip);
    }

    #[test]
    fn test_activity_invalid_enum() {
        let mut buf = BytesMut::new();
        3u8.write(&mut buf); // Invalid discriminant

        let result = Activity::<MinSig, <Sha256 as Hasher>::Digest>::decode(&buf[..]);
        assert!(matches!(
            result,
            Err(CodecError::Invalid(
                "consensus::aggregation::Activity",
                "Invalid type"
            ))
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<Item<Sha256Digest>>,
            CodecConformance<Ack<MinSig, Sha256Digest>>,
            CodecConformance<TipAck<MinSig, Sha256Digest>>,
            CodecConformance<Certificate<MinSig, Sha256Digest>>,
            CodecConformance<Activity<MinSig, Sha256Digest>>,
        }
    }
}
