use crate::types::ReplayedReplicaState;
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
    /// The last finalized view.
    pub last_finalized: u64,
    /// Committed block sequence (views in finalization order).
    pub committed_sequence: Vec<u64>,
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
    MissingNullification {
        node: String,
        view: u64,
    },
    ExtraNullification {
        node: String,
        view: u64,
    },
    MissingFinalization {
        node: String,
        view: u64,
    },
    ExtraFinalization {
        node: String,
        view: u64,
    },
    LastFinalizedMismatch {
        node: String,
        expected: u64,
        actual: u64,
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

        // Compare last finalized
        let actual_last = state.finalizations.keys().max().copied().unwrap_or(0);
        if expected_node.last_finalized != actual_last {
            mismatches.push(Mismatch::LastFinalizedMismatch {
                node: node_id.clone(),
                expected: expected_node.last_finalized,
                actual: actual_last,
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
            Mismatch::MissingNullification { node, view } => {
                write!(f, "{node}: missing nullification for view {view}")
            }
            Mismatch::ExtraNullification { node, view } => {
                write!(f, "{node}: extra nullification for view {view}")
            }
            Mismatch::MissingFinalization { node, view } => {
                write!(f, "{node}: missing finalization for view {view}")
            }
            Mismatch::ExtraFinalization { node, view } => {
                write!(f, "{node}: extra finalization for view {view}")
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
