use arbitrary::Arbitrary;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use std::collections::{BTreeSet, HashMap, HashSet};

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

/// Per-replica observable state used by the replayer.
pub struct ReplayedReplicaState {
    pub notarizations: HashMap<u64, Notarization>,
    pub nullifications: HashMap<u64, Nullification>,
    pub finalizations: HashMap<u64, Finalization>,
    /// Views that have any certificate (notarization, nullification, or finalization).
    pub certified: HashSet<u64>,
    /// Per-view set of node IDs ("n0", "n1", ...) that sent notarize votes.
    pub notarize_signers: HashMap<u64, BTreeSet<String>>,
    /// Per-view set of node IDs that sent nullify votes.
    pub nullify_signers: HashMap<u64, BTreeSet<String>>,
    /// Per-view set of node IDs that sent finalize votes.
    pub finalize_signers: HashMap<u64, BTreeSet<String>>,
}
