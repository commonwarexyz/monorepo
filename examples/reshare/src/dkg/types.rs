//! Types for the DKG/reshare protocol.

use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::{
        dkg::types::{Ack, Share},
        primitives::{group, poly::Public, variant::Variant},
    },
    Signature, Signer, Verifier,
};

/// The result of a resharing operation from the local [Dealer].
///
/// [Dealer]: commonware_cryptography::bls12381::dkg::Dealer
#[derive(Clone)]
pub struct DealOutcome<C: Signer, V: Variant> {
    /// The public key of the dealer.
    pub dealer: C::PublicKey,

    /// The dealer's signature over the resharing round, commitment, acks, and reveals.
    pub dealer_signature: C::Signature,

    /// The round of the resharing operation.
    pub round: u64,

    /// The new group public key polynomial.
    pub commitment: Public<V>,

    /// All signed acknowledgements from participants.
    pub acks: Vec<Ack<C::Signature>>,

    /// Any revealed secret shares.
    pub reveals: Vec<group::Share>,
}

impl<C: Signer, V: Variant> DealOutcome<C, V> {
    /// Creates a new [DealOutcome], signing its inner payload with the [commonware_cryptography::bls12381::dkg::Dealer]'s [Signer].
    pub fn new(
        dealer_signer: &C,
        namespace: &[u8],
        round: u64,
        commitment: Public<V>,
        acks: Vec<Ack<C::Signature>>,
        reveals: Vec<group::Share>,
    ) -> Self {
        // Sign the resharing outcome
        let payload = Self::signature_payload_from_parts(round, &commitment, &acks, &reveals);
        let dealer_signature = dealer_signer.sign(Some(namespace), payload.as_ref());

        Self {
            dealer: dealer_signer.public_key(),
            dealer_signature,
            round,
            commitment,
            acks,
            reveals,
        }
    }

    /// Verifies the [DealOutcome]'s signature.
    pub fn verify(&self, namespace: &[u8]) -> bool {
        let payload = Self::signature_payload_from_parts(
            self.round,
            &self.commitment,
            &self.acks,
            &self.reveals,
        );
        self.dealer
            .verify(Some(namespace), &payload, &self.dealer_signature)
    }

    /// Returns the payload that was signed by the dealer, formed from raw parts.
    fn signature_payload_from_parts(
        round: u64,
        commitment: &Public<V>,
        acks: &[Ack<C::Signature>],
        reveals: &Vec<group::Share>,
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

impl<C: Signer, V: Variant> Write for DealOutcome<C, V> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dealer.write(buf);
        self.dealer_signature.write(buf);
        UInt(self.round).write(buf);
        self.commitment.write(buf);
        self.acks.write(buf);
        self.reveals.write(buf);
    }
}

impl<C: Signer, V: Variant> EncodeSize for DealOutcome<C, V> {
    fn encode_size(&self) -> usize {
        self.dealer.encode_size()
            + self.dealer_signature.encode_size()
            + UInt(self.round).encode_size()
            + self.commitment.encode_size()
            + self.acks.encode_size()
            + self.reveals.encode_size()
    }
}

impl<C: Signer, V: Variant> Read for DealOutcome<C, V> {
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            dealer: C::PublicKey::read(buf)?,
            dealer_signature: C::Signature::read(buf)?,
            round: UInt::read(buf)?.into(),
            commitment: Public::<V>::read_cfg(buf, cfg)?,
            acks: Vec::<Ack<C::Signature>>::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?,
            reveals: Vec::<group::Share>::read_cfg(buf, &(RangeCfg::from(0..=usize::MAX), ()))?,
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
    type Cfg = u32;

    fn read_cfg(buf: &mut impl Buf, num_players: &u32) -> Result<Self, commonware_codec::Error> {
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

const SHARE_TAG: u8 = 0;
const ACK_TAG: u8 = 1;

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
    Share(Share<V>),

    /// Message sent by a player node back to the dealer node.
    ///
    /// Acknowledges the receipt and verification of a [Payload::Share] message.
    /// Includes a signature to authenticate the acknowledgment.
    Ack(Ack<S>),
}

impl<V: Variant, S: Signature> Payload<V, S> {
    /// Lifts the [Payload] into a [Dkg] message for a specific round.
    pub fn into_message(self, round: u64) -> Dkg<V, S> {
        Dkg {
            round,
            payload: self,
        }
    }
}

impl<V: Variant, S: Signature> Write for Payload<V, S> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Payload::Share(inner) => {
                buf.put_u8(SHARE_TAG);
                inner.write(buf);
            }
            Payload::Ack(inner) => {
                buf.put_u8(ACK_TAG);
                inner.write(buf);
            }
        }
    }
}

impl<V: Variant, S: Signature> Read for Payload<V, S> {
    type Cfg = u32;

    fn read_cfg(buf: &mut impl Buf, p: &u32) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        let result = match tag {
            SHARE_TAG => Payload::Share(Share::read_cfg(buf, p)?),
            ACK_TAG => Payload::Ack(Ack::read(buf)?),
            _ => return Err(commonware_codec::Error::InvalidEnum(tag)),
        };
        Ok(result)
    }
}

impl<V: Variant, S: Signature> EncodeSize for Payload<V, S> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Payload::Share(inner) => inner.encode_size(),
                Payload::Ack(inner) => inner.encode_size(),
            }
    }
}
