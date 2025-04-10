use bytes::Buf;
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

impl<Sig: Array, Cfg: Config> Read<Cfg> for DKG<Sig> {}

pub enum Payload<Sig: Array> {
    Start(Start),
    Share(Share),
    Ack(Ack<Sig>),
    Commitment(Commitment<Sig>),
    Success(Success),

    // Sent by arbiter to all players if round is unsuccessful
    Abort,
}

// Send by arbiter to start DKG
pub struct Start {
    pub group: Option<poly::Public>,
}

// Sent by dealer to player
pub struct Share {
    pub commitment: poly::Public,
    pub share: group::Share,
}

// Sent by player to dealer
pub struct Ack<Sig: Array> {
    pub public_key: u32,

    // Signature over round + dealer + commitment
    pub signature: Sig,
}

// Sent by dealer to arbiter after collecting acks from players
pub struct Commitment<Sig: Array> {
    pub commitment: poly::Public,
    pub acks: Vec<Ack<Sig>>,
    pub reveals: Vec<group::Share>,
}

// Sent by arbiter to a player if round is successful
pub struct Success {
    pub commitments: HashMap<u32, poly::Public>,
    pub reveals: HashMap<u32, group::Share>,
}

// All messages that can be sent over VRF_CHANNEL.
pub struct VRF {
    round: u64,
    signature: Eval<group::Signature>,
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
