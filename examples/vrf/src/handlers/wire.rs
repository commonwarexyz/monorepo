use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::bls12381::primitives::{
    group,
    poly::{self, Eval},
};
use commonware_utils::Array;
use std::collections::HashMap;

// All messages that can be sent over DKG_CHANNEL.
pub struct DKG<Sig: Array> {
    pub round: u64,
    pub payload: Payload<Sig>,
}

impl<Sig: Array> Write for DKG<Sig> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.payload.write(buf);
    }
}

impl<Sig: Array> Read<usize> for DKG<Sig> {
    fn read_cfg(buf: &mut impl Buf, poly_size: &usize) -> Result<Self, Error> {
        let round = u64::read(buf)?;
        let payload = Payload::<Sig>::read_cfg(buf, poly_size)?;
        Ok(Self { round, payload })
    }
}

impl<Sig: Array> EncodeSize for DKG<Sig> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.payload.encode_size()
    }
}

pub enum Payload<Sig: Array> {
    // Sent by arbiter to start DKG
    Start {
        group: Option<poly::Public>,
    },

    // Sent by dealer to player
    Share {
        commitment: poly::Public,
        share: group::Share,
    },

    // Sent by player to dealer
    Ack(Ack<Sig>),

    // Sent by dealer to arbiter after collecting acks from players
    Commitment {
        commitment: poly::Public,
        acks: Vec<Ack<Sig>>,
        reveals: Vec<group::Share>,
    },

    // Sent by arbiter to a player if round is successful
    Success {
        commitments: HashMap<u32, poly::Public>,
        reveals: HashMap<u32, group::Share>,
    },

    // Sent by arbiter to all players if round is unsuccessful
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
            Payload::Ack(ack) => {
                buf.put_u8(2);
                ack.public_key.write(buf);
                ack.signature.write(buf);
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
    fn read_cfg(buf: &mut impl Buf, poly_size: &usize) -> Result<Self, Error> {
        let tag = u8::read(buf)?;
        let result = match tag {
            0 => Payload::Start {
                group: Option::<poly::Public>::read_cfg(buf, poly_size)?,
            },
            1 => Payload::Share {
                commitment: poly::Public::read_cfg(buf, poly_size)?,
                share: group::Share::read(buf)?,
            },
            2 => Payload::Ack(Ack::<Sig>::read(buf)?),
            3 => Payload::Commitment {
                commitment: poly::Public::read_cfg(buf, poly_size)?,
                acks: Vec::<Ack<Sig>>::read_range(buf, ..)?, // TODO: is this expected to be at-most or exactly poly_size?
                reveals: Vec::<group::Share>::read_range(buf, ..)?, // TODO: is this expected to be at-most or exactly poly_size?
            },
            4 => Payload::Success {
                commitments: HashMap::<u32, poly::Public>::read_cfg(buf, &(.., ((), *poly_size)))?, // TODO: is this expected to be at-most or exactly poly_size?
                reveals: HashMap::<u32, group::Share>::read_range(buf, ..)?, // TODO: is this expected to be at-most or exactly poly_size?
            },
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

pub struct Ack<S: Array> {
    pub public_key: u32,
    // Signature over round + dealer + commitment
    pub signature: S,
}

impl<S: Array> Write for Ack<S> {
    fn write(&self, buf: &mut impl BufMut) {
        self.public_key.write(buf);
        self.signature.write(buf);
    }
}

impl<S: Array> Read for Ack<S> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let public_key = u32::read(buf)?;
        let signature = S::read(buf)?;
        Ok(Self {
            public_key,
            signature,
        })
    }
}

impl<S: Array> FixedSize for Ack<S> {
    const SIZE: usize = u32::SIZE + S::SIZE;
}

// All messages that can be sent over VRF_CHANNEL.
pub struct VRF {
    pub round: u64,
    pub signature: Eval<group::Signature>,
}

impl Write for VRF {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.signature.write(buf);
    }
}

impl Read for VRF {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = u64::read(buf)?;
        let signature = Eval::<group::Signature>::read(buf)?;
        Ok(Self { round, signature })
    }
}

impl FixedSize for VRF {
    const SIZE: usize = u64::SIZE + Eval::<group::Signature>::SIZE;
}
