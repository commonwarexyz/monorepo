use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::bls12381::primitives::{
    group,
    poly::{self, Eval},
};
use commonware_utils::{quorum, Array};
use std::collections::HashMap;

// All messages that can be sent over DKG_CHANNEL.
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

pub enum Payload<Sig: Array> {
    /// Sent by arbiter to start DKG
    Start { group: Option<poly::Public> },

    /// Sent by dealer to player
    Share {
        commitment: poly::Public,
        share: group::Share,
    },

    /// Sent by player to dealer
    Ack {
        public_key: u32,

        /// Signature over round + dealer + commitment
        signature: Sig,
    },

    /// Sent by dealer to arbiter after collecting acks from players
    Commitment {
        commitment: poly::Public,
        acks: HashMap<u32, Sig>,
        reveals: Vec<group::Share>,
    },

    /// Sent by arbiter to a player if round is successful
    Success {
        commitments: HashMap<u32, poly::Public>,
        reveals: HashMap<u32, group::Share>,
    },

    /// Sent by arbiter to all players if round is unsuccessful
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
        let t = quorum(u32::try_from(*p).unwrap()).unwrap() as usize; // threshold
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
            3 => Payload::Commitment {
                commitment: poly::Public::read_cfg(buf, &t)?,
                acks: HashMap::<u32, Sig>::read_range(buf, ..=*p)?, // TODO: is this expected to be at-most or exactly t?
                reveals: Vec::<group::Share>::read_range(buf, ..=*p)?, // TODO: is this expected to be at-most or exactly t?
            },
            4 => Payload::Success {
                commitments: HashMap::<u32, poly::Public>::read_cfg(buf, &(..=*p, ((), t)))?, // TODO: is this expected to be at-most or exactly t?
                reveals: HashMap::<u32, group::Share>::read_range(buf, ..=*p)?, // TODO: is this expected to be at-most or exactly t?
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

// All messages that can be sent over VRF_CHANNEL.
pub struct Vrf {
    pub round: u64,
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
