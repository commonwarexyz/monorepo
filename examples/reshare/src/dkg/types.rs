//! Types for the DKG/reshare protocol.

use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::primitives::{group::Share, poly::Public, variant::Variant},
    PrivateKey, Signature,
};
use commonware_utils::quorum;

/// The namespace used when signing [DealOutcome]s.
pub const OUTCOME_NAMESPACE: &[u8] = b"RESHARE_OUTCOME";

/// The result of a resharing operation from the local [Dealer].
///
/// [Dealer]: commonware_cryptography::bls12381::dkg::Dealer
#[derive(Clone)]
pub struct DealOutcome<P: PrivateKey, V: Variant> {
    /// The public key of the dealer.
    pub dealer: P::PublicKey,

    /// The dealer's signature over the resharing round, commitment, acks, and reveals.
    pub dealer_signature: P::Signature,

    /// The round of the resharing operation.
    pub round: u64,

    /// The new group public key polynomial.
    pub commitment: Public<V>,

    /// All signed acknowledgements from participants.
    pub acks: Vec<(u32, P::Signature)>,

    /// Any revealed secret shares.
    pub reveals: Vec<Share>,
}

impl<P: PrivateKey, V: Variant> DealOutcome<P, V> {
    /// Creates a new [DealOutcome], signing its inner payload with the [Dealer]'s [PrivateKey].
    ///
    /// [Dealer]: commonware_cryptography::bls12381::dkg::Dealer
    pub fn new(
        dealer_signer: &P,
        round: u64,
        commitment: Public<V>,
        acks: Vec<(u32, P::Signature)>,
        reveals: Vec<Share>,
    ) -> Self {
        // Sign the resharing outcome
        let payload = Self::signature_payload_from_parts(round, &commitment, &acks, &reveals);
        let dealer_signature = dealer_signer.sign(Some(OUTCOME_NAMESPACE), payload.as_ref());

        Self {
            dealer: dealer_signer.public_key(),
            dealer_signature,
            round,
            commitment,
            acks,
            reveals,
        }
    }

    /// Returns the payload that was signed by the dealer.
    pub fn signature_payload(&self) -> Vec<u8> {
        Self::signature_payload_from_parts(self.round, &self.commitment, &self.acks, &self.reveals)
    }

    /// Returns the payload that was signed by the dealer, formed from raw parts.
    fn signature_payload_from_parts(
        round: u64,
        commitment: &Public<V>,
        acks: &[(u32, P::Signature)],
        reveals: &Vec<Share>,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            UInt(round).encode_size()
                + commitment.encode_size()
                + acks.encode_size()
                + reveals.encode_size(),
        );
        UInt(round).write(&mut buf);
        commitment.write(&mut buf);
        acks.write(&mut buf);
        reveals.write(&mut buf);
        buf
    }
}

impl<P: PrivateKey, V: Variant> Write for DealOutcome<P, V> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dealer.write(buf);
        self.dealer_signature.write(buf);
        UInt(self.round).write(buf);
        self.commitment.write(buf);
        self.acks.write(buf);
        self.reveals.write(buf);
    }
}

impl<P: PrivateKey, V: Variant> EncodeSize for DealOutcome<P, V> {
    fn encode_size(&self) -> usize {
        self.dealer.encode_size()
            + self.dealer_signature.encode_size()
            + UInt(self.round).encode_size()
            + self.commitment.encode_size()
            + self.acks.encode_size()
            + self.reveals.encode_size()
    }
}

impl<P: PrivateKey, V: Variant> Read for DealOutcome<P, V> {
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            dealer: P::PublicKey::read(buf)?,
            dealer_signature: P::Signature::read(buf)?,
            round: UInt::read(buf)?.into(),
            commitment: Public::<V>::read_cfg(buf, cfg)?,
            acks: Vec::<(u32, P::Signature)>::read_cfg(
                buf,
                &(RangeCfg::from(0..=usize::MAX), ((), ())),
            )?,
            reveals: Vec::<Share>::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?,
        })
    }
}

/// Represents a top-level message for the Distributed Key Generation (DKG) protocol,
/// typically sent over a dedicated DKG communication channel.
///
/// It encapsulates a specific round number and a payload containing the actual
/// DKG protocol message content.
#[derive(Clone, Debug, PartialEq)]
pub struct Dkg<V: Variant, S: Signature> {
    pub round: u64,
    pub payload: Payload<V, S>,
}

impl<V: Variant, S: Signature> Write for Dkg<V, S> {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.round).write(buf);
        self.payload.write(buf);
    }
}

impl<V: Variant, S: Signature> Read for Dkg<V, S> {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, num_players: &usize) -> Result<Self, commonware_codec::Error> {
        let round = UInt::read(buf)?.into();
        let payload = Payload::read_cfg(buf, num_players)?;
        Ok(Self { round, payload })
    }
}

impl<V: Variant, S: Signature> EncodeSize for Dkg<V, S> {
    fn encode_size(&self) -> usize {
        UInt(self.round).encode_size() + self.payload.encode_size()
    }
}

/// Defines the different types of messages exchanged during the DKG protocol.
///
/// This enum is used as the `payload` field within the [Dkg] message struct.
/// The generic parameter `Sig` represents the type used for signatures in acknowledgments.
#[derive(Clone, Debug, PartialEq)]
pub enum Payload<V: Variant, S: Signature> {
    /// Message sent by a dealer node to a player node.
    ///
    /// Contains the dealer's public commitment to their polynomial and the specific
    /// share calculated for the receiving player.
    Share {
        /// The dealer's public commitment (coefficients of the polynomial).
        commitment: Public<V>,
        /// The secret share evaluated for the recipient player.
        share: Share,
    },

    /// Message sent by a player node back to the dealer node.
    ///
    /// Acknowledges the receipt and verification of a [Payload::Share] message.
    /// Includes a signature to authenticate the acknowledgment.
    Ack {
        /// The public key identifier of the player sending the acknowledgment.
        public_key: u32,
        /// A signature covering the DKG round, dealer ID, and the dealer's commitment.
        /// This confirms the player received and validated the correct share.
        signature: S,
    },
}

impl<V: Variant, S: Signature> Write for Payload<V, S> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Payload::Share { commitment, share } => {
                buf.put_u8(0);
                commitment.write(buf);
                share.write(buf);
            }
            Payload::Ack {
                public_key,
                signature,
            } => {
                buf.put_u8(1);
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
            0 => Payload::Share {
                commitment: Public::<V>::read_cfg(buf, &t)?,
                share: Share::read(buf)?,
            },
            1 => Payload::Ack {
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
        1 + match self {
            Payload::Share { commitment, share } => commitment.encode_size() + share.encode_size(),
            Payload::Ack {
                public_key,
                signature,
            } => UInt(*public_key).encode_size() + signature.encode_size(),
        }
    }
}
