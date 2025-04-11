use commonware_cryptography::bls12381::primitives::{
    group,
    poly::{self, PartialSignature},
};
use commonware_utils::Array;

pub enum Inbound {
    PutBlock(PutBlock),
    GetBlock(GetBlock),
    PutFinalization(PutFinalization),
    GetFinalization(GetFinalization),
}

pub struct PutBlock {
    pub network: group::Public,
    pub data: Bytes,
}

pub struct GetBlock<D: Array> {
    pub network: group::Public,
    pub digest: D,
}

pub struct PutFinalization {
    pub network: group::Public,
    pub data: Bytes,
}

pub struct GetFinalization {
    pub network: group::Public,
}

pub enum Outbound {
    Success(bool), // if PUT (success), if GET (success is false if not found)
    Block(Bytes),
    Finalization(Bytes),
}
