//! Standard types sent over the wire for [Dealer] shares and [Player] acknowledgements.
//!
//! [Dealer]: crate::bls12381::dkg::Dealer
//! [Player]: crate::bls12381::dkg::Player

use crate::{
    bls12381::primitives::{group::Share, poly::Public, variant::Variant},
    PublicKey, Signature,
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_utils::quorum;

const SHARE_VARIANT_TAG: u8 = 0;
const ACK_VARIANT_TAG: u8 = 1;

/// The signature namespace for DKG share acknowledgements.
pub const DKG_ACK_NAMESPACE: &[u8] = b"DKG_ACK";

/// Represents a top-level message for the Distributed Key Generation (DKG) protocol,
/// typically sent over a dedicated DKG communication channel.
///
/// It encapsulates a specific round number and a payload containing the actual
/// DKG protocol message content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<V: Variant, S: Signature> {
    /// The round of the DKG protocol this message pertains to.
    round: u64,
    /// The message [Payload].
    payload: Payload<V, S>,
}

impl<V: Variant, S: Signature> Write for Message<V, S> {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.round).write(buf);
        self.payload.write(buf);
    }
}

impl<V: Variant, S: Signature> Read for Message<V, S> {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, num_players: &usize) -> Result<Self, commonware_codec::Error> {
        let round = UInt::read(buf)?.into();
        let payload = Payload::read_cfg(buf, num_players)?;
        Ok(Self { round, payload })
    }
}

impl<V: Variant, S: Signature> EncodeSize for Message<V, S> {
    fn encode_size(&self) -> usize {
        UInt(self.round).encode_size() + self.payload.encode_size()
    }
}

/// Defines the different types of messages exchanged during the DKG protocol.
///
/// This enum is used as the `payload` field within the [Message] struct.
/// The generic parameter `S` represents the type used for signatures in acknowledgments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload<V: Variant, S: Signature> {
    /// Message sent by a [Dealer] node to a [Player] node.
    ///
    /// Contains the [Dealer]'s public commitment to their polynomial and the specific
    /// share calculated for the receiving [Player].
    ///
    /// [Dealer]: crate::bls12381::dkg::Dealer
    /// [Player]: crate::bls12381::dkg::Player
    Share {
        /// The [Dealer]'s public commitment (coefficients of the polynomial).
        ///
        /// [Dealer]: crate::bls12381::dkg::Dealer
        commitment: Public<V>,
        /// The secret share evaluated for the recipient [Player].
        ///
        /// [Player]: crate::bls12381::dkg::Player
        share: Share,
    },

    /// Message sent by a [Player] node back to the [Dealer] node.
    ///
    /// Acknowledges the receipt and verification of a [Payload::Share] message.
    /// Includes a signature to authenticate the acknowledgment.
    ///
    /// [Dealer]: crate::bls12381::dkg::Dealer
    /// [Player]: crate::bls12381::dkg::Player
    Ack {
        /// The public key identifier of the [Player] sending the acknowledgment.
        ///
        /// [Player]: crate::bls12381::dkg::Player
        public_key: u32,
        /// A signature covering the DKG round, dealer ID, and the [Dealer]'s commitment.
        /// This confirms the player received and validated the correct share.
        ///
        /// [Dealer]: crate::bls12381::dkg::Dealer
        signature: S,
    },
}

impl<V: Variant, S: Signature> Payload<V, S> {
    /// Wraps the [Payload] in a [Message] for the specified DKG round.
    pub fn as_message(self, round: u64) -> Message<V, S> {
        Message {
            round,
            payload: self,
        }
    }
}

impl<V: Variant, S: Signature> Write for Payload<V, S> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Payload::Share { commitment, share } => {
                buf.put_u8(SHARE_VARIANT_TAG);
                commitment.write(buf);
                share.write(buf);
            }
            Payload::Ack {
                public_key,
                signature,
            } => {
                buf.put_u8(ACK_VARIANT_TAG);
                UInt(*public_key).write(buf);
                signature.write(buf);
            }
        }
    }
}

impl<V: Variant, S: Signature> Read for Payload<V, S> {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, p: &usize) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        let t = quorum(u32::try_from(*p).unwrap()) as usize;
        let result = match tag {
            SHARE_VARIANT_TAG => Payload::Share {
                commitment: Public::<V>::read_cfg(buf, &t)?,
                share: Share::read(buf)?,
            },
            ACK_VARIANT_TAG => Payload::Ack {
                public_key: UInt::read(buf)?.into(),
                signature: S::read(buf)?,
            },
            _ => return Err(commonware_codec::Error::InvalidEnum(tag)),
        };
        Ok(result)
    }
}

impl<V: Variant, S: Signature> EncodeSize for Payload<V, S> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Payload::Share { commitment, share } => {
                    commitment.encode_size() + share.encode_size()
                }
                Payload::Ack {
                    public_key,
                    signature,
                } => UInt(*public_key).encode_size() + signature.encode_size(),
            }
    }
}

/// Create a signature payload for acking a secret.
///
/// This payload consists of the round number, [Dealer]'s public key, and the [Dealer]'s commitment,
/// and the signature over this payload is included in the [Payload::Ack] message.
///
/// [Dealer]: crate::bls12381::dkg::Dealer
pub fn ack_signature_payload<V: Variant, P: PublicKey>(
    round: u64,
    dealer: &P,
    commitment: &Public<V>,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(u64::SIZE + P::SIZE + commitment.encode_size());
    round.write(&mut payload);
    dealer.write(&mut payload);
    commitment.write(&mut payload);
    payload
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        bls12381::{
            dkg::ops,
            primitives::{group::Share, poly::Public, variant::MinSig},
        },
        ed25519::PrivateKey,
        PrivateKeyExt, Signer,
    };
    use commonware_utils::quorum;
    use rand_core::OsRng;

    type P = Payload<MinSig, <PrivateKey as Signer>::Signature>;
    type M = Message<MinSig, <PrivateKey as Signer>::Signature>;

    fn generate_identities(num_peers: u32) -> (Public<MinSig>, Vec<(PrivateKey, Share)>) {
        // Generate consensus key
        let threshold = quorum(num_peers);
        let (polynomial, shares) =
            ops::generate_shares::<_, MinSig>(&mut OsRng, None, num_peers, threshold);

        // Generate p2p private keys
        let mut peer_signers = (0..num_peers)
            .map(|_| PrivateKey::from_rng(&mut OsRng))
            .collect::<Vec<_>>();
        peer_signers.sort_by_key(|signer| signer.public_key());

        let identities = peer_signers.into_iter().zip(shares).collect::<Vec<_>>();

        (polynomial, identities)
    }

    #[test]
    fn test_payload_share_roundtrip() {
        const NUM_PARTICIPANTS: usize = 1;

        let (group_poly, identities) = generate_identities(NUM_PARTICIPANTS as u32);
        let (_, share) = &identities[0];

        let payload = P::Share {
            commitment: group_poly,
            share: share.clone(),
        };

        let mut buf = Vec::with_capacity(payload.encode_size());
        payload.write(&mut buf);

        let decoded = P::read_cfg(&mut buf.as_slice(), &NUM_PARTICIPANTS).unwrap();

        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_payload_ack_roundtrip() {
        const NUM_PARTICIPANTS: usize = 1;

        let (group_poly, identities) = generate_identities(NUM_PARTICIPANTS as u32);
        let (signer, _) = &identities[0];

        let payload_bytes = ack_signature_payload::<MinSig, <PrivateKey as Signer>::PublicKey>(
            42,
            &signer.public_key(),
            &group_poly,
        );
        let signature = signer.sign(Some(DKG_ACK_NAMESPACE), &payload_bytes);

        let payload = P::Ack {
            public_key: 1337,
            signature,
        };

        let mut buf = Vec::with_capacity(payload.encode_size());
        payload.write(&mut buf);

        let decoded = P::read_cfg(&mut buf.as_slice(), &NUM_PARTICIPANTS).unwrap();

        assert_eq!(payload, decoded);
    }

    #[test]
    fn test_payload_bad_tag() {
        const NUM_PARTICIPANTS: usize = 1;

        let (group_poly, identities) = generate_identities(NUM_PARTICIPANTS as u32);
        let (_, share) = &identities[0];

        let payload = P::Share {
            commitment: group_poly,
            share: share.clone(),
        };

        let mut buf = Vec::with_capacity(payload.encode_size());
        payload.write(&mut buf);

        // Mutate the tag
        buf[0] = 0xFF;

        let decoded = P::read_cfg(&mut buf.as_slice(), &NUM_PARTICIPANTS).unwrap_err();

        assert!(matches!(
            decoded,
            commonware_codec::Error::InvalidEnum(0xFF)
        ));
    }

    #[test]
    fn test_message_share_roundtrip() {
        const NUM_PARTICIPANTS: usize = 1;

        let (group_poly, identities) = generate_identities(NUM_PARTICIPANTS as u32);
        let (_, share) = &identities[0];

        let message = P::Share {
            commitment: group_poly,
            share: share.clone(),
        }
        .as_message(42);

        let mut buf = Vec::with_capacity(message.encode_size());
        message.write(&mut buf);

        let decoded = M::read_cfg(&mut buf.as_slice(), &NUM_PARTICIPANTS).unwrap();

        assert_eq!(message, decoded);
    }

    #[test]
    fn test_message_ack_roundtrip() {
        const NUM_PARTICIPANTS: usize = 1;

        let (group_poly, identities) = generate_identities(NUM_PARTICIPANTS as u32);
        let (signer, _) = &identities[0];

        let payload_bytes = ack_signature_payload::<MinSig, <PrivateKey as Signer>::PublicKey>(
            42,
            &signer.public_key(),
            &group_poly,
        );
        let signature = signer.sign(Some(DKG_ACK_NAMESPACE), &payload_bytes);

        let message = P::Ack {
            public_key: 1337,
            signature,
        }
        .as_message(42);

        let mut buf = Vec::with_capacity(message.encode_size());
        message.write(&mut buf);

        let decoded = M::read_cfg(&mut buf.as_slice(), &NUM_PARTICIPANTS).unwrap();

        assert_eq!(message, decoded);
    }
}
