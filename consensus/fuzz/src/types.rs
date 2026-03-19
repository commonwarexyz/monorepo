use arbitrary::Arbitrary;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use std::collections::{HashMap, HashSet};

/// Message types the disrupter can send.
#[derive(Debug, Clone, Arbitrary)]
pub enum Message {
    Notarize,
    Nullify,
    Finalize,
    /// Random bytes (malformed message).
    Random,
}

pub struct Notarization {
    pub payload: Sha256Digest,
    /// None for threshold schemes where count is not exposed.
    pub signature_count: Option<usize>,
}

pub struct Nullification {
    /// None for threshold schemes where count is not exposed.
    pub signature_count: Option<usize>,
}

pub struct Finalization {
    pub payload: Sha256Digest,
    /// None for threshold schemes where count is not exposed.
    pub signature_count: Option<usize>,
}

/// Per-replica observable state used by the fuzzer (certificates only).
pub type ReplicaState = (
    HashMap<u64, Notarization>,
    HashMap<u64, Nullification>,
    HashMap<u64, Finalization>,
);

/// Per-replica observable state used by the replayer (certificates + votes).
pub struct ReplayedReplicaState {
    pub notarizations: HashMap<u64, Notarization>,
    pub nullifications: HashMap<u64, Nullification>,
    pub finalizations: HashMap<u64, Finalization>,
    /// Notarize votes per view -> set of signer IDs (e.g. "n0", "n1").
    pub notarize_votes: HashMap<u64, HashSet<String>>,
    /// Nullify votes per view -> set of signer IDs.
    pub nullify_votes: HashMap<u64, HashSet<String>>,
    /// Finalize votes per view -> set of signer IDs.
    pub finalize_votes: HashMap<u64, HashSet<String>>,
}
