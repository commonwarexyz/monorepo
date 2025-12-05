use arbitrary::Arbitrary;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use std::collections::HashMap;

#[derive(Debug, Clone, Arbitrary)]
pub enum Message {
    Notarize,
    Nullify,
    Finalize,
    Random,
}

pub struct Notarization {
    pub payload: Sha256Digest,
    pub signature_count: Option<usize>,
}

pub struct Nullification {
    pub signature_count: Option<usize>,
}

pub struct Finalization {
    pub payload: Sha256Digest,
    pub signature_count: Option<usize>,
}

pub type ReplicaState = (
    HashMap<u64, Notarization>,
    HashMap<u64, Nullification>,
    HashMap<u64, Finalization>,
);
