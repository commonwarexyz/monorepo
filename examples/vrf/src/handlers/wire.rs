use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::bls12381::primitives::{
    group,
    poly::{self, Eval},
};
use commonware_utils::{quorum, Array};
use std::collections::HashMap;

/// Represents a top-level message for the Distributed Key Generation (DKG) protocol,
/// typically sent over a dedicated DKG communication channel.
///
/// It encapsulates a specific round number and a payload containing the actual
/// DKG protocol message content.
#[derive(Clone, Debug, PartialEq)]
pub struct Dkg<Sig: Array> {
    pub round: u64,
    pub payload: Payload<Sig>,
}

impl<Sig: Array> Write for Dkg<Sig> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.payload.write(buf);
    }
}

impl<Sig: Array> Read<usize> for Dkg<Sig> {
    fn read_cfg(buf: &mut impl Buf, num_players: &usize) -> Result<Self, Error> {
        let round = u64::read(buf)?;
        let payload = Payload::<Sig>::read_cfg(buf, num_players)?;
        Ok(Self { round, payload })
    }
}

impl<Sig: Array> EncodeSize for Dkg<Sig> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.payload.encode_size()
    }
}

/// Defines the different types of messages exchanged during the DKG protocol.
///
/// This enum is used as the `payload` field within the [`Dkg`] message struct.
/// The generic parameter `Sig` represents the type used for signatures in acknowledgments.
#[derive(Clone, Debug, PartialEq)]
pub enum Payload<Sig: Array> {
    /// Message sent by the arbiter to initiate a DKG round.
    ///
    /// Optionally includes a pre-existing group public key if reforming a group.
    Start {
        /// Optional existing group public polynomial commitment.
        group: Option<poly::Public>,
    },

    /// Message sent by a dealer node to a player node.
    ///
    /// Contains the dealer's public commitment to their polynomial and the specific
    /// share calculated for the receiving player.
    Share {
        /// The dealer's public commitment (coefficients of the polynomial).
        commitment: poly::Public,
        /// The secret share evaluated for the recipient player.
        share: group::Share,
    },

    /// Message sent by a player node back to the dealer node.
    ///
    /// Acknowledges the receipt and verification of a [`Payload::Share`] message.
    /// Includes a signature to authenticate the acknowledgment.
    Ack {
        /// The public key identifier of the player sending the acknowledgment.
        public_key: u32,
        /// A signature covering the DKG round, dealer ID, and the dealer's commitment.
        /// This confirms the player received and validated the correct share.
        signature: Sig,
    },

    /// Message sent by a dealer node to the arbiter.
    ///
    /// Sent after the dealer has collected a sufficient number of [`Payload::Ack`] messages
    /// from players. Contains the dealer's commitment, the collected acknowledgments,
    /// and potentially revealed shares (e.g., for handling unresponsive players).
    Commitment {
        /// The dealer's public commitment.
        commitment: poly::Public,
        /// A map of player public key identifiers to their corresponding acknowledgment signatures.
        acks: HashMap<u32, Sig>,
        /// A vector of shares revealed by the dealer, potentially for players who did not acknowledge.
        reveals: Vec<group::Share>,
    },

    /// Message sent by the arbiter to player nodes upon successful completion of a DKG round.
    ///
    /// Contains the final aggregated commitments and revealed shares from all participating dealers.
    Success {
        /// A map of dealer public key identifiers to their final public commitments.
        commitments: HashMap<u32, poly::Public>,
        /// A map of player public key identifiers to their corresponding revealed shares,
        /// aggregated from all dealers' [`Payload::Commitment`] messages.
        reveals: HashMap<u32, group::Share>,
    },

    /// Message broadcast by the arbiter to all player nodes if the DKG round fails or is aborted.
    Abort,
}

impl<Sig: Array> Write for Payload<Sig> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Payload::Start { group } => {
                buf.put_u8(0);
                group.write(buf);
            }
            Payload::Share { commitment, share } => {
                buf.put_u8(1);
                commitment.write(buf);
                share.write(buf);
            }
            Payload::Ack {
                public_key,
                signature,
            } => {
                buf.put_u8(2);
                public_key.write(buf);
                signature.write(buf);
            }
            Payload::Commitment {
                commitment,
                acks,
                reveals,
            } => {
                buf.put_u8(3);
                commitment.write(buf);
                acks.write(buf);
                reveals.write(buf);
            }
            Payload::Success {
                commitments,
                reveals,
            } => {
                buf.put_u8(4);
                commitments.write(buf);
                reveals.write(buf);
            }
            Payload::Abort => {
                buf.put_u8(5);
            }
        }
    }
}

impl<Sig: Array> Read<usize> for Payload<Sig> {
    fn read_cfg(buf: &mut impl Buf, p: &usize) -> Result<Self, Error> {
        let tag = u8::read(buf)?;
        let t = quorum(u32::try_from(*p).unwrap()) as usize; // threshold
        let result = match tag {
            0 => Payload::Start {
                group: Option::<poly::Public>::read_cfg(buf, &t)?,
            },
            1 => Payload::Share {
                commitment: poly::Public::read_cfg(buf, &t)?,
                share: group::Share::read(buf)?,
            },
            2 => Payload::Ack {
                public_key: u32::read(buf)?,
                signature: Sig::read(buf)?,
            },
            3 => {
                let commitment = poly::Public::read_cfg(buf, &t)?;
                let acks = HashMap::<u32, Sig>::read_range(buf, ..=*p)?;
                let r = p.checked_sub(acks.len()).unwrap(); // The lengths of the two sets must sum to exactly p.
                let reveals = Vec::<group::Share>::read_range(buf, r..=r)?;
                Payload::Commitment {
                    commitment,
                    acks,
                    reveals,
                }
            }
            4 => {
                let commitments = HashMap::<u32, poly::Public>::read_cfg(buf, &(..=*p, ((), t)))?;
                let reveals = HashMap::<u32, group::Share>::read_range(buf, ..=*p)?;
                Payload::Success {
                    commitments,
                    reveals,
                }
            }
            5 => Payload::Abort,
            _ => return Err(Error::InvalidEnum(tag)),
        };
        Ok(result)
    }
}
impl<Sig: Array> EncodeSize for Payload<Sig> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Payload::Start { group } => group.encode_size(),
            Payload::Share { commitment, .. } => commitment.encode_size() + group::Share::SIZE,
            Payload::Ack { .. } => u32::SIZE + Sig::SIZE,
            Payload::Commitment {
                commitment,
                acks,
                reveals,
            } => commitment.encode_size() + acks.encode_size() + reveals.encode_size(),
            Payload::Success {
                commitments,
                reveals,
            } => commitments.encode_size() + reveals.encode_size(),
            Payload::Abort => 0,
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
    pub signature: Eval<group::Signature>,
}

impl Write for Vrf {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.signature.write(buf);
    }
}

impl Read for Vrf {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = u64::read(buf)?;
        let signature = Eval::<group::Signature>::read(buf)?;
        Ok(Self { round, signature })
    }
}

impl FixedSize for Vrf {
    const SIZE: usize = u64::SIZE + Eval::<group::Signature>::SIZE;
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::primitives::{
            group::{self, Element},
            poly,
        },
        ed25519::Signature,
    };
    use rand::thread_rng;
    use std::collections::HashMap;

    const N: usize = 11;
    const T: usize = 8;

    fn new_signature(b: u8) -> Signature {
        Signature::decode([b; Signature::SIZE].as_ref()).unwrap()
    }

    fn new_share(v: u32) -> group::Share {
        group::Share {
            index: v,
            private: group::Private::rand(&mut thread_rng()),
        }
    }

    fn new_eval(v: u32) -> Eval<group::Signature> {
        let mut signature = group::Signature::one();
        let scalar = group::Scalar::rand(&mut thread_rng());
        signature.mul(&scalar);
        Eval {
            index: v,
            value: signature,
        }
    }

    fn new_poly() -> poly::Public {
        let mut public = group::Public::one();
        let scalar = group::Scalar::rand(&mut thread_rng());
        public.mul(&scalar);
        poly::Public::from(vec![public; T])
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
            payload: Payload::Share {
                commitment: new_poly(),
                share: new_share(42),
            },
        };
        let encoded = original.encode();
        let decoded = Dkg::<Signature>::decode_cfg(encoded, &N).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_dkg_ack_codec() {
        let original: Dkg<Signature> = Dkg {
            round: 1,
            payload: Payload::Ack {
                public_key: 1,
                signature: new_signature(123),
            },
        };
        let encoded = original.encode();
        let decoded = Dkg::<Signature>::decode_cfg(encoded, &N).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_dkg_commitment_codec() {
        let commitment = new_poly();
        let mut acks = HashMap::<u32, Signature>::new();
        acks.insert(1, new_signature(123));
        let num_reveals = N - acks.len();
        let reveals_vec = vec![new_share(4321); num_reveals];

        let original: Dkg<Signature> = Dkg {
            round: 1,
            payload: Payload::Commitment {
                commitment: commitment.clone(),
                acks: acks.clone(),
                reveals: reveals_vec.clone(),
            },
        };
        let encoded = original.encode();
        let decoded = Dkg::<Signature>::decode_cfg(encoded, &N).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_dkg_success_codec() {
        let mut commitments = HashMap::<u32, poly::Public>::new();
        commitments.insert(1, new_poly());
        let mut reveals = HashMap::<u32, group::Share>::new();
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
