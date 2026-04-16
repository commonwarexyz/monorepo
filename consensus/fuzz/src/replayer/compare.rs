use crate::{
    tracing::data::ReporterReplicaStateData,
    types::ReplayedReplicaState,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Observable state from the Quint model for a single correct node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedNodeState {
    /// Views that have been notarized, mapped to block hex digest.
    pub notarizations: BTreeMap<u64, String>,
    /// Views that have been nullified.
    pub nullifications: BTreeSet<u64>,
    /// Views that have been finalized, mapped to block hex digest.
    pub finalizations: BTreeMap<u64, String>,
    /// Expected visible certificate signer counts per view.
    #[serde(default)]
    pub notarization_signature_counts: BTreeMap<u64, Option<usize>>,
    #[serde(default)]
    pub nullification_signature_counts: BTreeMap<u64, Option<usize>>,
    #[serde(default)]
    pub finalization_signature_counts: BTreeMap<u64, Option<usize>>,
    /// The last finalized view.
    pub last_finalized: u64,
    /// Committed block sequence (views in finalization order).
    pub committed_sequence: Vec<u64>,
    /// Views for which the replica observed any certificate.
    #[serde(default)]
    pub certified: BTreeSet<u64>,
    /// Views that the replica marked as successfully certified.
    #[serde(default)]
    pub successful_certifications: BTreeSet<u64>,
    /// Per-view set of node IDs that sent notarize votes to this node.
    #[serde(default)]
    pub notarize_signers: BTreeMap<u64, BTreeSet<String>>,
    /// Per-view set of node IDs that sent nullify votes to this node.
    #[serde(default)]
    pub nullify_signers: BTreeMap<u64, BTreeSet<String>>,
    /// Per-view set of node IDs that sent finalize votes to this node.
    #[serde(default)]
    pub finalize_signers: BTreeMap<u64, BTreeSet<String>>,
}

/// Expected observable state from the Quint model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedState {
    /// Per correct node expected state, keyed by node ID (e.g. "n1", "n2").
    pub nodes: BTreeMap<String, ExpectedNodeState>,
}

/// Builds an expected state from embedded reporter-like trace state.
pub fn expected_from_reporter_states(
    reporter_states: &BTreeMap<String, ReporterReplicaStateData>,
) -> ExpectedState {
    let nodes = reporter_states
        .iter()
        .map(|(node, state)| {
            (
                node.clone(),
                ExpectedNodeState {
                    notarizations: state
                        .notarizations
                        .iter()
                        .map(|(view, proposal)| (*view, proposal.payload.clone()))
                        .collect(),
                    nullifications: state.nullifications.clone(),
                    finalizations: state
                        .finalizations
                        .iter()
                        .map(|(view, proposal)| (*view, proposal.payload.clone()))
                        .collect(),
                    notarization_signature_counts: state.notarization_signature_counts.clone(),
                    nullification_signature_counts: state.nullification_signature_counts.clone(),
                    finalization_signature_counts: state.finalization_signature_counts.clone(),
                    last_finalized: state.max_finalized_view,
                    committed_sequence: Vec::new(),
                    certified: state.certified.clone(),
                    successful_certifications: state.successful_certifications.clone(),
                    notarize_signers: state.notarize_signers.clone(),
                    nullify_signers: state.nullify_signers.clone(),
                    finalize_signers: state.finalize_signers.clone(),
                },
            )
        })
        .collect();

    ExpectedState { nodes }
}

/// A single mismatch between expected and actual state.
#[derive(Debug)]
pub enum Mismatch {
    MissingNotarization {
        node: String,
        view: u64,
    },
    ExtraNotarization {
        node: String,
        view: u64,
    },
    NotarizationPayloadMismatch {
        node: String,
        view: u64,
        expected: String,
        actual: String,
    },
    NotarizationSignatureCountMismatch {
        node: String,
        view: u64,
        expected: Option<usize>,
        actual: Option<usize>,
    },
    MissingNullification {
        node: String,
        view: u64,
    },
    ExtraNullification {
        node: String,
        view: u64,
    },
    NullificationSignatureCountMismatch {
        node: String,
        view: u64,
        expected: Option<usize>,
        actual: Option<usize>,
    },
    MissingFinalization {
        node: String,
        view: u64,
    },
    ExtraFinalization {
        node: String,
        view: u64,
    },
    FinalizationPayloadMismatch {
        node: String,
        view: u64,
        expected: String,
        actual: String,
    },
    FinalizationSignatureCountMismatch {
        node: String,
        view: u64,
        expected: Option<usize>,
        actual: Option<usize>,
    },
    LastFinalizedMismatch {
        node: String,
        expected: u64,
        actual: u64,
    },
    CertifiedViewsMismatch {
        node: String,
        expected: BTreeSet<u64>,
        actual: BTreeSet<u64>,
    },
    VoteSignerMismatch {
        node: String,
        view: u64,
        vote_type: &'static str,
        expected: BTreeSet<String>,
        actual: BTreeSet<String>,
    },
}

/// Compares expected Quint state with actual Rust reporter state.
///
/// `faults` is the number of Byzantine nodes (correct nodes start at index `faults`).
/// `states` are the extracted ReplicaStates, one per correct node (in order).
pub fn compare(
    expected: &ExpectedState,
    states: &[ReplayedReplicaState],
    faults: usize,
) -> Vec<Mismatch> {
    let mut mismatches = Vec::new();

    for (correct_idx, state) in states.iter().enumerate() {
        let node_idx = correct_idx + faults;
        let node_id = format!("n{node_idx}");

        let Some(expected_node) = expected.nodes.get(&node_id) else {
            continue;
        };

        // Compare notarizations
        let actual_views: BTreeSet<u64> = state.notarizations.keys().copied().collect();
        let expected_views: BTreeSet<u64> = expected_node.notarizations.keys().copied().collect();

        for &view in expected_views.difference(&actual_views) {
            mismatches.push(Mismatch::MissingNotarization {
                node: node_id.clone(),
                view,
            });
        }
        for &view in actual_views.difference(&expected_views) {
            mismatches.push(Mismatch::ExtraNotarization {
                node: node_id.clone(),
                view,
            });
        }
        for view in expected_views.intersection(&actual_views) {
            let expected_data = &expected_node.notarizations[view];
            let actual_data = state
                .notarizations
                .get(view)
                .expect("view present in both maps");
            if expected_data != &actual_data.payload.to_string() {
                mismatches.push(Mismatch::NotarizationPayloadMismatch {
                    node: node_id.clone(),
                    view: *view,
                    expected: expected_data.clone(),
                    actual: actual_data.payload.to_string(),
                });
            }
            let expected_count = expected_node
                .notarization_signature_counts
                .get(view)
                .copied()
                .unwrap_or(None);
            if expected_count != actual_data.signature_count {
                mismatches.push(Mismatch::NotarizationSignatureCountMismatch {
                    node: node_id.clone(),
                    view: *view,
                    expected: expected_count,
                    actual: actual_data.signature_count,
                });
            }
        }

        // Compare nullifications
        let actual_null_views: BTreeSet<u64> = state.nullifications.keys().copied().collect();
        let expected_null_views: BTreeSet<u64> =
            expected_node.nullifications.iter().copied().collect();

        for &view in expected_null_views.difference(&actual_null_views) {
            mismatches.push(Mismatch::MissingNullification {
                node: node_id.clone(),
                view,
            });
        }
        for &view in actual_null_views.difference(&expected_null_views) {
            mismatches.push(Mismatch::ExtraNullification {
                node: node_id.clone(),
                view,
            });
        }
        for view in expected_null_views.intersection(&actual_null_views) {
            let expected_count = expected_node
                .nullification_signature_counts
                .get(view)
                .copied()
                .unwrap_or(None);
            let actual_count = state
                .nullifications
                .get(view)
                .expect("view present in both maps")
                .signature_count;
            if expected_count != actual_count {
                mismatches.push(Mismatch::NullificationSignatureCountMismatch {
                    node: node_id.clone(),
                    view: *view,
                    expected: expected_count,
                    actual: actual_count,
                });
            }
        }

        // Compare finalizations
        let actual_final_views: BTreeSet<u64> = state.finalizations.keys().copied().collect();
        let expected_final_views: BTreeSet<u64> =
            expected_node.finalizations.keys().copied().collect();

        for &view in expected_final_views.difference(&actual_final_views) {
            mismatches.push(Mismatch::MissingFinalization {
                node: node_id.clone(),
                view,
            });
        }
        for &view in actual_final_views.difference(&expected_final_views) {
            mismatches.push(Mismatch::ExtraFinalization {
                node: node_id.clone(),
                view,
            });
        }
        for view in expected_final_views.intersection(&actual_final_views) {
            let expected_data = &expected_node.finalizations[view];
            let actual_data = state
                .finalizations
                .get(view)
                .expect("view present in both maps");
            if expected_data != &actual_data.payload.to_string() {
                mismatches.push(Mismatch::FinalizationPayloadMismatch {
                    node: node_id.clone(),
                    view: *view,
                    expected: expected_data.clone(),
                    actual: actual_data.payload.to_string(),
                });
            }
            let expected_count = expected_node
                .finalization_signature_counts
                .get(view)
                .copied()
                .unwrap_or(None);
            if expected_count != actual_data.signature_count {
                mismatches.push(Mismatch::FinalizationSignatureCountMismatch {
                    node: node_id.clone(),
                    view: *view,
                    expected: expected_count,
                    actual: actual_data.signature_count,
                });
            }
        }

        // Compare last finalized
        let actual_last = state.finalizations.keys().max().copied().unwrap_or(0);
        if expected_node.last_finalized != actual_last {
            mismatches.push(Mismatch::LastFinalizedMismatch {
                node: node_id.clone(),
                expected: expected_node.last_finalized,
                actual: actual_last,
            });
        }

        // Compare certified views
        let actual_certified: BTreeSet<u64> = state.certified.iter().copied().collect();
        if expected_node.certified != actual_certified {
            mismatches.push(Mismatch::CertifiedViewsMismatch {
                node: node_id.clone(),
                expected: expected_node.certified.clone(),
                actual: actual_certified,
            });
        }

        // Compare vote signers
        compare_signers(
            &mut mismatches,
            &node_id,
            "notarize",
            &expected_node.notarize_signers,
            &state.notarize_signers,
        );
        compare_signers(
            &mut mismatches,
            &node_id,
            "nullify",
            &expected_node.nullify_signers,
            &state.nullify_signers,
        );
        compare_signers(
            &mut mismatches,
            &node_id,
            "finalize",
            &expected_node.finalize_signers,
            &state.finalize_signers,
        );
    }

    mismatches
}

fn compare_signers(
    mismatches: &mut Vec<Mismatch>,
    node: &str,
    vote_type: &'static str,
    expected: &BTreeMap<u64, BTreeSet<String>>,
    actual: &HashMap<u64, BTreeSet<String>>,
) {
    let all_views: BTreeSet<u64> = expected.keys().chain(actual.keys()).copied().collect();

    for view in all_views {
        // Skip GENESIS_VIEW: no consensus votes at view 0.
        if view == 0 {
            continue;
        }
        let empty = BTreeSet::new();
        let exp_set = expected.get(&view).unwrap_or(&empty);
        let act_set = actual.get(&view).unwrap_or(&empty);
        // The node's own vote may or may not be present on either side due
        // to timing (spec may not have sent it, impl may have received the
        // certificate first). Union both sides with {node} to ignore this.
        let node_str = node.to_string();
        let mut exp_with_self = exp_set.clone();
        exp_with_self.insert(node_str.clone());
        let mut act_with_self = act_set.clone();
        act_with_self.insert(node_str);
        if exp_with_self != act_with_self {
            mismatches.push(Mismatch::VoteSignerMismatch {
                node: node.to_string(),
                view,
                vote_type,
                expected: exp_set.clone(),
                actual: act_set.clone(),
            });
        }
    }
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mismatch::MissingNotarization { node, view } => {
                write!(f, "{node}: missing notarization for view {view}")
            }
            Mismatch::ExtraNotarization { node, view } => {
                write!(f, "{node}: extra notarization for view {view}")
            }
            Mismatch::NotarizationPayloadMismatch {
                node,
                view,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{node}: notarization payload mismatch at view {view}: spec={expected}, impl={actual}"
                )
            }
            Mismatch::NotarizationSignatureCountMismatch {
                node,
                view,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{node}: notarization signature count mismatch at view {view}: spec={expected:?}, impl={actual:?}"
                )
            }
            Mismatch::MissingNullification { node, view } => {
                write!(f, "{node}: missing nullification for view {view}")
            }
            Mismatch::ExtraNullification { node, view } => {
                write!(f, "{node}: extra nullification for view {view}")
            }
            Mismatch::NullificationSignatureCountMismatch {
                node,
                view,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{node}: nullification signature count mismatch at view {view}: spec={expected:?}, impl={actual:?}"
                )
            }
            Mismatch::MissingFinalization { node, view } => {
                write!(f, "{node}: missing finalization for view {view}")
            }
            Mismatch::ExtraFinalization { node, view } => {
                write!(f, "{node}: extra finalization for view {view}")
            }
            Mismatch::FinalizationPayloadMismatch {
                node,
                view,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{node}: finalization payload mismatch at view {view}: spec={expected}, impl={actual}"
                )
            }
            Mismatch::FinalizationSignatureCountMismatch {
                node,
                view,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{node}: finalization signature count mismatch at view {view}: spec={expected:?}, impl={actual:?}"
                )
            }
            Mismatch::LastFinalizedMismatch {
                node,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{node}: last_finalized mismatch: expected {expected}, got {actual}"
                )
            }
            Mismatch::CertifiedViewsMismatch {
                node,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{node}: certified views mismatch: spec={expected:?}, impl={actual:?}"
                )
            }
            Mismatch::VoteSignerMismatch {
                node,
                view,
                vote_type,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "{node}: {vote_type} signers mismatch at view {view}: spec={expected:?}, impl={actual:?}"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tracing::data::{ReporterReplicaStateData, TraceProposalData},
        types::{Finalization, Notarization, ReplayedReplicaState},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use std::collections::{HashMap, HashSet};

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest([byte; 32])
    }

    #[test]
    fn compare_reports_payload_count_and_certified_mismatches() {
        let expected = ExpectedState {
            nodes: BTreeMap::from([(
                "n1".to_string(),
                ExpectedNodeState {
                    notarizations: BTreeMap::from([(3, "aa".repeat(32))]),
                    nullifications: BTreeSet::new(),
                    finalizations: BTreeMap::from([(4, "bb".repeat(32))]),
                    notarization_signature_counts: BTreeMap::from([(3, Some(3))]),
                    nullification_signature_counts: BTreeMap::new(),
                    finalization_signature_counts: BTreeMap::from([(4, Some(3))]),
                    last_finalized: 4,
                    committed_sequence: vec![4],
                    certified: BTreeSet::from([3, 4]),
                    successful_certifications: BTreeSet::from([4]),
                    notarize_signers: BTreeMap::new(),
                    nullify_signers: BTreeMap::new(),
                    finalize_signers: BTreeMap::new(),
                },
            )]),
        };

        let actual = vec![ReplayedReplicaState {
            notarizations: HashMap::from([(
                3,
                Notarization {
                    payload: digest(0xcc),
                    signature_count: Some(4),
                },
            )]),
            nullifications: HashMap::new(),
            finalizations: HashMap::from([(
                4,
                Finalization {
                    payload: digest(0xdd),
                    signature_count: Some(4),
                },
            )]),
            certified: HashSet::from([4]),
            notarize_signers: HashMap::new(),
            nullify_signers: HashMap::new(),
            finalize_signers: HashMap::new(),
        }];

        let mismatches = compare(&expected, &actual, 1);

        assert!(mismatches
            .iter()
            .any(|m| matches!(m, Mismatch::NotarizationPayloadMismatch { .. })));
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, Mismatch::NotarizationSignatureCountMismatch { .. })));
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, Mismatch::FinalizationPayloadMismatch { .. })));
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, Mismatch::FinalizationSignatureCountMismatch { .. })));
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, Mismatch::CertifiedViewsMismatch { .. })));
    }

    #[test]
    fn expected_from_reporter_states_converts_embedded_trace_state() {
        let reporter_states = BTreeMap::from([(
            "n1".to_string(),
            ReporterReplicaStateData {
                notarizations: BTreeMap::from([(
                    3,
                    TraceProposalData {
                        view: 3,
                        parent: 2,
                        payload: "aa".repeat(32),
                    },
                )]),
                notarization_signature_counts: BTreeMap::from([(3, Some(3))]),
                nullifications: BTreeSet::from([4]),
                nullification_signature_counts: BTreeMap::from([(4, Some(3))]),
                finalizations: BTreeMap::from([(
                    5,
                    TraceProposalData {
                        view: 5,
                        parent: 4,
                        payload: "bb".repeat(32),
                    },
                )]),
                finalization_signature_counts: BTreeMap::from([(5, Some(3))]),
                certified: BTreeSet::from([3, 4, 5]),
                successful_certifications: BTreeSet::from([3, 5]),
                notarize_signers: BTreeMap::from([(3, BTreeSet::from(["n1".to_string()]))]),
                nullify_signers: BTreeMap::from([(4, BTreeSet::from(["n1".to_string()]))]),
                finalize_signers: BTreeMap::from([(5, BTreeSet::from(["n1".to_string()]))]),
                max_finalized_view: 5,
            },
        )]);

        let expected = expected_from_reporter_states(&reporter_states);
        let node = expected.nodes.get("n1").expect("missing node");
        assert_eq!(node.notarizations.get(&3), Some(&"aa".repeat(32)));
        assert!(node.nullifications.contains(&4));
        assert_eq!(node.finalizations.get(&5), Some(&"bb".repeat(32)));
        assert_eq!(node.last_finalized, 5);
        assert_eq!(node.certified, BTreeSet::from([3, 4, 5]));
        assert_eq!(node.successful_certifications, BTreeSet::from([3, 5]));
    }
}
