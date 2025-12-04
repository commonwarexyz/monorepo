use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, EncodeSize, Error, RangeCfg, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_cryptography::{
    bls12381::{
        dkg::types::{Ack, Share},
        primitives::{
            group,
            poly::{self, Eval},
            variant::{MinSig, Variant},
        },
    },
    Signature,
};
use commonware_utils::{quorum, NZU32};
use std::collections::BTreeMap;

/// Represents a top-level message for the Distributed Key Generation (DKG) protocol,
/// typically sent over a dedicated DKG communication channel.
///
/// It encapsulates a specific round number and a payload containing the actual
/// DKG protocol message content.
#[derive(Clone, Debug, PartialEq)]
pub struct Dkg<S: Signature> {
    pub round: u64,
    pub payload: Payload<S>,
}

impl<S: Signature> Write for Dkg<S> {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.round).write(buf);
        self.payload.write(buf);
    }
}

impl<S: Signature> Read for Dkg<S> {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, num_players: &usize) -> Result<Self, Error> {
        let round = UInt::read(buf)?.into();
        let payload = Payload::<S>::read_cfg(buf, num_players)?;
        Ok(Self { round, payload })
    }
}

impl<S: Signature> EncodeSize for Dkg<S> {
    fn encode_size(&self) -> usize {
        UInt(self.round).encode_size() + self.payload.encode_size()
    }
}

/// Defines the different types of messages exchanged during the DKG protocol.
///
/// This enum is used as the `payload` field within the [Dkg] message struct.
/// The generic parameter `Sig` represents the type used for signatures in acknowledgments.
#[derive(Clone, Debug, PartialEq)]
pub enum Payload<S: Signature> {
    /// Message sent by the arbiter to initiate a DKG round.
    ///
    /// Optionally includes a pre-existing group public key if reforming a group.
    Start {
        /// Optional existing group public polynomial commitment.
        group: Option<poly::Public<MinSig>>,
    },

    /// Message sent by a dealer node to a player node.
    ///
    /// Contains the dealer's public commitment to their polynomial and the specific
    /// share calculated for the receiving player.
    Share(Share<MinSig>),

    /// Message sent by a player node back to the dealer node.
    ///
    /// Acknowledges the receipt and verification of a [Payload::Share] message.
    /// Includes a signature to authenticate the acknowledgment.
    Ack(Ack<S>),

    /// Message sent by a dealer node to the arbiter.
    ///
    /// Sent after the dealer has collected a sufficient number of [Payload::Ack] messages
    /// from players. Contains the dealer's commitment, the collected acknowledgments,
    /// and potentially revealed shares (e.g., for handling unresponsive players).
    Commitment {
        /// The dealer's public commitment.
        commitment: poly::Public<MinSig>,
        /// A list of received [Ack]s.
        acks: Vec<Ack<S>>,
        /// A vector of shares revealed by the dealer, potentially for players who did not acknowledge.
        reveals: Vec<group::Share>,
    },

    /// Message sent by the arbiter to player nodes upon successful completion of a DKG round.
    ///
    /// Contains the final aggregated commitments and revealed shares from all participating dealers.
    Success {
        /// A map of dealer public key identifiers to their final public commitments.
        commitments: BTreeMap<u32, poly::Public<MinSig>>,
        /// A map of player public key identifiers to their corresponding revealed shares,
        /// aggregated from all dealers' [Payload::Commitment] messages.
        reveals: BTreeMap<u32, group::Share>,
    },

    /// Message broadcast by the arbiter to all player nodes if the DKG round fails or is aborted.
    Abort,
}

impl<S: Signature> Write for Payload<S> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Start { group } => {
                buf.put_u8(0);
                group.write(buf);
            }
            Self::Share(share) => {
                buf.put_u8(1);
                share.write(buf);
            }
            Self::Ack(ack) => {
                buf.put_u8(2);
                ack.write(buf);
            }
            Self::Commitment {
                commitment,
                acks,
                reveals,
            } => {
                buf.put_u8(3);
                commitment.write(buf);
                acks.write(buf);
                reveals.write(buf);
            }
            Self::Success {
                commitments,
                reveals,
            } => {
                buf.put_u8(4);
                commitments.write(buf);
                reveals.write(buf);
            }
            Self::Abort => {
                buf.put_u8(5);
            }
        }
    }
}

impl<S: Signature> Read for Payload<S> {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, p: &usize) -> Result<Self, Error> {
        let tag = u8::read(buf)?;
        let t = quorum(u32::try_from(*p).expect("participant count exceeds u32")); // threshold
        let result = match tag {
            0 => Self::Start {
                group: Option::<poly::Public<MinSig>>::read_cfg(buf, &RangeCfg::exact(NZU32!(t)))?,
            },
            1 => Self::Share(Share::read_cfg(buf, &(*p as u32))?),
            2 => Self::Ack(Ack::read(buf)?),
            3 => {
                let commitment =
                    poly::Public::<MinSig>::read_cfg(buf, &RangeCfg::exact(NZU32!(t)))?;
                let acks = Vec::<Ack<S>>::read_range(buf, ..=*p)?;
                let r = p.checked_sub(acks.len()).unwrap(); // The lengths of the two sets must sum to exactly p.
                let reveals = Vec::<group::Share>::read_range(buf, r..=r)?;
                Self::Commitment {
                    commitment,
                    acks,
                    reveals,
                }
            }
            4 => {
                let commitments = BTreeMap::<u32, poly::Public<MinSig>>::read_cfg(
                    buf,
                    &((..=*p).into(), ((), RangeCfg::exact(NZU32!(t)))),
                )?;
                let reveals = BTreeMap::<u32, group::Share>::read_range(buf, ..=*p)?;
                Self::Success {
                    commitments,
                    reveals,
                }
            }
            5 => Self::Abort,
            _ => return Err(Error::InvalidEnum(tag)),
        };
        Ok(result)
    }
}
impl<S: Signature> EncodeSize for Payload<S> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Start { group } => group.encode_size(),
            Self::Share(share) => share.encode_size(),
            Self::Ack(ack) => ack.encode_size(),
            Self::Commitment {
                commitment,
                acks,
                reveals,
            } => commitment.encode_size() + acks.encode_size() + reveals.encode_size(),
            Self::Success {
                commitments,
                reveals,
            } => commitments.encode_size() + reveals.encode_size(),
            Self::Abort => 0,
        }
    }
}

/// Represents a message containing a Verifiable Random Function (VRF) output,
/// typically sent over a dedicated VRF communication channel.
///
/// It includes the round number for which the VRF was computed and the resulting
/// evaluated signature (VRF proof).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vrf {
    /// The round number associated with this VRF output.
    pub round: u64,
    /// The VRF signature/proof, represented as an evaluation of a threshold signature.
    pub signature: Eval<<MinSig as Variant>::Signature>,
}

impl Write for Vrf {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.round).write(buf);
        self.signature.write(buf);
    }
}

impl Read for Vrf {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = UInt::read(buf)?.into();
        let signature = Eval::<<MinSig as Variant>::Signature>::read(buf)?;
        Ok(Self { round, signature })
    }
}

impl EncodeSize for Vrf {
    fn encode_size(&self) -> usize {
        UInt(self.round).encode_size() + self.signature.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::ACK_NAMESPACE;
    use commonware_codec::{Decode, DecodeExt, Encode, FixedSize};
    use commonware_cryptography::{
        bls12381::primitives::{
            group::{self, Element},
            poly,
            variant::Variant,
        },
        ed25519::{PrivateKey, Signature},
        PrivateKeyExt, Signer,
    };
    use rand::{thread_rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    const N: usize = 11;
    const T: usize = 8;

    fn new_signature(b: u8) -> Signature {
        Signature::decode([b; Signature::SIZE].as_ref()).unwrap()
    }

    fn new_share(v: u32) -> group::Share {
        group::Share {
            index: v,
            private: group::Private::from_rand(&mut thread_rng()),
        }
    }

    fn new_eval(v: u32) -> Eval<<MinSig as Variant>::Signature> {
        let mut signature = <MinSig as Variant>::Signature::one();
        let scalar = group::Scalar::from_rand(&mut thread_rng());
        signature.mul(&scalar);
        Eval {
            index: v,
            value: signature,
        }
    }

    fn new_poly() -> poly::Public<MinSig> {
        let mut public = <MinSig as Variant>::Public::one();
        let scalar = group::Scalar::from_rand(&mut thread_rng());
        public.mul(&scalar);
        poly::Public::<MinSig>::from(vec![public; T])
    }

    #[test]
    fn test_dkg_start_codec() {
        let original: Dkg<Signature> = Dkg {
            round: 1,
            payload: Payload::Start {
                group: Some(new_poly()),
            },
        };
        let encoded = original.encode();
        let decoded = Dkg::<Signature>::decode_cfg(encoded, &N).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_dkg_share_codec() {
        let original: Dkg<Signature> = Dkg {
            round: 1,
            payload: Payload::Share(Share::new(new_poly(), new_share(42))),
        };
        let encoded = original.encode();
        let decoded = Dkg::<Signature>::decode_cfg(encoded, &N).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_dkg_ack_codec() {
        let mut rng = ChaCha8Rng::seed_from_u64(0xdead);
        let poly = new_poly();
        let signer = PrivateKey::from_rng(&mut rng);

        let original: Dkg<Signature> = Dkg {
            round: 1,
            payload: Payload::Ack(Ack::new::<_, MinSig>(
                ACK_NAMESPACE,
                &signer,
                1337,
                42,
                &signer.public_key(),
                &poly,
            )),
        };
        let encoded = original.encode();
        let decoded = Dkg::<Signature>::decode_cfg(encoded, &N).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_dkg_commitment_codec() {
        let commitment = new_poly();
        let acks = vec![Ack {
            player: 1,
            signature: new_signature(1),
        }];
        let num_reveals = N - acks.len();
        let reveals_vec = vec![new_share(4321); num_reveals];

        let original: Dkg<Signature> = Dkg {
            round: 1,
            payload: Payload::Commitment {
                commitment,
                acks,
                reveals: reveals_vec,
            },
        };
        let encoded = original.encode();
        let decoded = Dkg::<Signature>::decode_cfg(encoded, &N).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_dkg_success_codec() {
        let mut commitments = BTreeMap::<u32, poly::Public<MinSig>>::new();
        commitments.insert(1, new_poly());
        let mut reveals = BTreeMap::<u32, group::Share>::new();
        reveals.insert(1, new_share(123));

        let original: Dkg<Signature> = Dkg {
            round: 1,
            payload: Payload::Success {
                commitments,
                reveals,
            },
        };
        let encoded = original.encode();
        let decoded = Dkg::<Signature>::decode_cfg(encoded, &N).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_dkg_abort_codec() {
        let original: Dkg<Signature> = Dkg {
            round: 1,
            payload: Payload::Abort,
        };
        let encoded = original.encode();
        let decoded = Dkg::<Signature>::decode_cfg(encoded, &N).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_vrf_codec() {
        let original = Vrf {
            round: 1,
            signature: new_eval(123),
        };
        let encoded = original.encode();
        let decoded = Vrf::decode_cfg(encoded, &()).unwrap();
        assert_eq!(original, decoded);
    }
}
