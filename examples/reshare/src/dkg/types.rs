//! Types for the DKG/reshare protocol.

use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, Encode, EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{
    bls12381::{
        dkg::types::{Ack, Share},
        dkg2::DealerLog,
        primitives::variant::Variant,
    },
    transcript::Transcript,
    Signature, Signer, Verifier,
};

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
