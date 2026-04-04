use super::sniffer::TraceEntry;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceProposalData {
    pub view: u64,
    pub parent: u64,
    pub payload: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReporterReplicaStateData {
    pub notarizations: BTreeMap<u64, TraceProposalData>,
    pub notarization_signature_counts: BTreeMap<u64, Option<usize>>,
    pub nullifications: BTreeSet<u64>,
    pub nullification_signature_counts: BTreeMap<u64, Option<usize>>,
    pub finalizations: BTreeMap<u64, TraceProposalData>,
    pub finalization_signature_counts: BTreeMap<u64, Option<usize>>,
    /// Views that have any certificate (notarization, nullification, or finalization).
    #[serde(default)]
    pub certified: BTreeSet<u64>,
    pub notarize_signers: BTreeMap<u64, BTreeSet<String>>,
    pub nullify_signers: BTreeMap<u64, BTreeSet<String>>,
    pub finalize_signers: BTreeMap<u64, BTreeSet<String>>,
    pub max_finalized_view: u64,
}

/// Serializable trace document for quint test generation.
#[derive(Serialize, Deserialize)]
pub struct TraceData {
    pub n: usize,
    pub faults: usize,
    pub epoch: u64,
    pub max_view: u64,
    pub entries: Vec<TraceEntry>,
    pub required_containers: u64,
    #[serde(default)]
    pub reporter_states: BTreeMap<String, ReporterReplicaStateData>,
}
