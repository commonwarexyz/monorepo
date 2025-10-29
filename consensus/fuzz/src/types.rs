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

// Generic data structures for invariant checking
pub struct Notarization {
    pub payload: Sha256Digest,
    pub signature_count: Option<usize>, // Some for Simplex, None for Threshold Simplex
}

pub struct Nullification {
    pub signature_count: Option<usize>, // Some for simplex, None for Threshold Simplex
}

pub struct Finalization {
    pub payload: Sha256Digest,
    pub signature_count: Option<usize>, // Some for simplex, None for Threshold Simplex
}

type View = u64;

pub type ReplicaState = (
    HashMap<View, Notarization>,
    HashMap<View, Nullification>,
    HashMap<View, Finalization>,
);
