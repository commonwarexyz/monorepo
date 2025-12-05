use arbitrary::Arbitrary;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use std::collections::HashMap;

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

/// Per-replica state: (notarizations, nullifications, finalizations) keyed by view.
pub type ReplicaState = (
    HashMap<u64, Notarization>,
    HashMap<u64, Nullification>,
    HashMap<u64, Finalization>,
);
