use arbitrary::Arbitrary;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use std::collections::{BTreeMap, BTreeSet, HashMap};

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

/// Proposal recorded for a certified view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProposalData {
    pub parent: u64,
    pub payload: String,
}

/// Deep per-replica state extracted from a reporter for state-coverage feedback.
///
/// View-keyed certificate sets, per-view signature counts, and the replica's
/// finalized frontier. This is the input to the state-coverage abstraction
/// (`state_cov::alpha`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReporterReplicaStateData {
    pub notarizations: BTreeMap<u64, ProposalData>,
    pub notarization_signature_counts: BTreeMap<u64, Option<usize>>,
    pub nullifications: BTreeSet<u64>,
    pub nullification_signature_counts: BTreeMap<u64, Option<usize>>,
    pub finalizations: BTreeMap<u64, ProposalData>,
    pub finalization_signature_counts: BTreeMap<u64, Option<usize>>,
    pub notarize_vote_counts: BTreeMap<u64, usize>,
    pub nullify_vote_counts: BTreeMap<u64, usize>,
    pub finalize_vote_counts: BTreeMap<u64, usize>,
    /// Views that have any certificate (notarization, nullification, or finalization).
    pub certified: BTreeSet<u64>,
    /// Views with a proposal certificate usable for parent selection.
    pub successful_certifications: BTreeSet<u64>,
    /// Views where the known leader sent a nullify vote.
    pub leader_nullify_views: BTreeSet<u64>,
    /// Max view with a finalization certificate.
    pub last_finalized: u64,
    /// Max view this replica has notarized (notarize vote or notarization certificate).
    pub last_notarized: u64,
    /// Max view this replica has nullified (nullify vote or nullification certificate).
    pub last_nullified: u64,
}
