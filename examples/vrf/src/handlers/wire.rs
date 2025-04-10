use bytes::{BufMut, Buf};
use commonware_codec::{Config, EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::bls12381::primitives::{
    group,
    poly::{self, Eval, PartialSignature},
};
use commonware_utils::Array;
use std::collections::HashMap;

// All messages that can be sent over DKG_CHANNEL.
pub struct DKG<Sig: Array> {
    pub round: u64,
    pub payload: Payload<Sig>,
}

impl<Sig: Array> Write for DKG<Sig> {
    fn write(&self, buf: &mut impl Buf) {
        self.round.write(buf);
        self.payload.write(buf);
    }
}

impl<Sig: Array> Read for DKG<Sig> {
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let round = u64::read(buf)?;
        let payload = Payload::<Sig>::read(buf);
        Ok(Self { round, payload })
    }
}

impl<Sig: Array> EncodeSize for DKG<Sig> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.payload.encode_size()
    }
}

pub enum Payload<Sig: Array> {
    Start(Start),
    Share(Share),
    Ack(Ack<Sig>),
    Commitment(Commitment<Sig>),
    Success(Success),

    // Sent by arbiter to all players if round is unsuccessful
    Abort,
}

impl<Sig: Array> Write for Payload<Sig> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Payload::Start(start) => {
                buf.put_u8(0);
                start.write(buf);
            }
            Payload::Share(share) => {
                buf.put_u8(1);
                share.write(buf);
            }
            Payload::Ack(ack) => {
                buf.put_u8(2);
                ack.write(buf);
            }
            Payload::Commitment(commitment) => {
                buf.put_u8(3);
                commitment.write(buf);
            }
            Payload::Success(success) => {
                buf.put_u8(4);
                success.write(buf);
            }
            Payload::Abort => {
                buf.put_u8(5);
            }
        }
    }
}

impl<Sig: Array> Read for Payload<Sig> {
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let tag = buf.get_u8();
        match tag {
            0 => Ok(Payload::Start(Start::read(buf)?)),
            1 => Ok(Payload::Share(Share::read(buf)?)),
            2 => Ok(Payload::Ack(Ack::<Sig>::read(buf)?)),
            3 => Ok(Payload::Commitment(Commitment::<Sig>::read(buf)?)),
            4 => Ok(Payload::Success(Success::read(buf)?)),
            5 => Ok(Payload::Abort),
            _ => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<Sig: Array> EncodeSize for Payload<Sig> {
    fn encode_size(&self) -> usize {
       1+ match self {
            Payload::Start(start) => start.encode_size(),
            Payload::Share(share) => share.encode_size(),
            Payload::Ack(ack) => ack.encode_size(),
            Payload::Commitment(commitment) => commitment.encode_size(),
            Payload::Success(success) => success.encode_size(),
            Payload::Abort => 0,
        }
    }
}

// Send by arbiter to start DKG
pub struct Start {
    pub group: Option<poly::Public>,
}

impl Write for Start {
    fn write(&self, buf: &mut impl BufMut) {
        self.group.write(buf);
    }
}

impl Read for Start {
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let group = poly::Public::read(buf)?;
        Ok(Self { group })
    }
}

impl FixedSize for Start {
    const SIZE: usize = poly::Public::SIZE;
}

// Sent by dealer to player
pub struct Share {
    pub commitment: poly::Public,
    pub share: group::Share,
}

impl Write for Share {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitment.write(buf);
        self.share.write(buf);
    }
}

impl Read for Share {
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let commitment = poly::Public::read(buf)?;
        let share = group::Share::read(buf)?;
        Ok(Self { commitment, share })
    }
}

impl FixedSize for Share {
    const SIZE: usize = poly::Public::SIZE + group::Share::SIZE;
}

// Sent by player to dealer
pub struct Ack<Sig: Array> {
    pub public_key: u32,

    // Signature over round + dealer + commitment
    pub signature: Sig,
}

impl<Sig: Array> Write for Ack<Sig> {
    fn write(&self, buf: &mut impl BufMut) {
        self.public_key.write(buf);
        self.signature.write(buf);
    }
}

impl<Sig: Array> Read for Ack<Sig> {
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let public_key = u32::read(buf)?;
        let signature = Sig::read(buf)?;
        Ok(Self { public_key, signature })
    }
}

impl<Sig: Array> FixedSize for Ack<Sig> {
    const SIZE: usize = u32::SIZE + Sig::SIZE;
}

// Sent by dealer to arbiter after collecting acks from players
pub struct Commitment<Sig: Array> {
    pub commitment: poly::Public,
    pub acks: Vec<Ack<Sig>>,
    pub reveals: Vec<group::Share>,
}

impl<Sig: Array> Write for Commitment<Sig> {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitment.write(buf);
        self.acks.write(buf);
        self.reveals.write(buf);
    }
}

impl<Sig: Array> Read for Commitment<Sig> {
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let commitment = poly::Public::read(buf)?;
        let acks = Vec::<Ack<Sig>>::read(buf)?;
        let reveals = Vec::<group::Share>::read(buf)?;
        Ok(Self {
            commitment,
            acks,
            reveals,
        })
    }
}

impl<Sig: Array> FixedSize for Commitment<Sig> {
    const SIZE: usize = poly::Public::SIZE + Vec::<Ack<Sig>>::SIZE + Vec::<group::Share>::SIZE;
}

// Sent by arbiter to a player if round is successful
pub struct Success {
    pub commitments: HashMap<u32, poly::Public>,
    pub reveals: HashMap<u32, group::Share>,
}

impl Write for Success {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitments.write(buf);
        self.reveals.write(buf);
    }
}

impl Read for Success {
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let commitments = HashMap::<u32, poly::Public>::read(buf)?;
        let reveals = HashMap::<u32, group::Share>::read(buf)?;
        Ok(Self {
            commitments,
            reveals,
        })
    }
}

impl FixedSize for Success {
    const SIZE: usize = HashMap::<u32, poly::Public>::SIZE + HashMap::<u32, group::Share>::SIZE;
}

// All messages that can be sent over VRF_CHANNEL.
pub struct VRF {
    round: u64,
    signature: Eval<group::Signature>,
}

impl Write for VRF {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.signature.write(buf);
    }
}

impl Read for VRF {
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        let round = u64::read(buf)?;
        let signature = Eval::<group::Signature>::read(buf)?;
        Ok(Self { round, signature })
    }
}

impl FixedSize for VRF {
    const SIZE: usize = u64::SIZE + Eval::<group::Signature>::SIZE;
}
