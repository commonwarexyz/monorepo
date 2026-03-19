use crate::types::ReplayedReplicaState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Observable state from the Quint model for a single correct node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedNodeState {
    /// Views that have been notarized, mapped to block hex digest.
    pub notarizations: BTreeMap<u64, String>,
    /// Views that have been nullified.
    pub nullifications: BTreeSet<u64>,
    /// Views that have been finalized, mapped to block hex digest.
    pub finalizations: BTreeMap<u64, String>,
    /// Notarize votes per view -> set of signer IDs.
    pub notarize_votes: BTreeMap<u64, BTreeSet<String>>,
    /// Nullify votes per view -> set of signer IDs.
    pub nullify_votes: BTreeMap<u64, BTreeSet<String>>,
    /// Finalize votes per view -> set of signer IDs.
    pub finalize_votes: BTreeMap<u64, BTreeSet<String>>,
    /// The last finalized view.
    pub last_finalized: u64,
    /// Committed block sequence (views in finalization order).
    pub committed_sequence: Vec<u64>,
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
    MissingNotarizeVote {
        node: String,
        view: u64,
        signer: String,
    },
    ExtraNotarizeVote {
        node: String,
        view: u64,
        signer: String,
    },
    MissingNullifyVote {
        node: String,
        view: u64,
        signer: String,
    },
    ExtraNullifyVote {
        node: String,
        view: u64,
        signer: String,
    },
    MissingFinalizeVote {
        node: String,
        view: u64,
        signer: String,
    },
    ExtraFinalizeVote {
        node: String,
        view: u64,
        signer: String,
    },
    LastFinalizedMismatch {
        node: String,
        expected: u64,
        actual: u64,
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

        // Compare notarize votes
        compare_votes(
            &node_id,
            &expected_node.notarize_votes,
            &state.notarize_votes,
            |node, view, signer| Mismatch::MissingNotarizeVote { node, view, signer },
            |node, view, signer| Mismatch::ExtraNotarizeVote { node, view, signer },
            &mut mismatches,
        );

        // Compare nullify votes
        compare_votes(
            &node_id,
            &expected_node.nullify_votes,
            &state.nullify_votes,
            |node, view, signer| Mismatch::MissingNullifyVote { node, view, signer },
            |node, view, signer| Mismatch::ExtraNullifyVote { node, view, signer },
            &mut mismatches,
        );

        // Compare finalize votes
        compare_votes(
            &node_id,
            &expected_node.finalize_votes,
            &state.finalize_votes,
            |node, view, signer| Mismatch::MissingFinalizeVote { node, view, signer },
            |node, view, signer| Mismatch::ExtraFinalizeVote { node, view, signer },
            &mut mismatches,
        );

        // Compare last finalized
        let actual_last = state.finalizations.keys().max().copied().unwrap_or(0);
        if expected_node.last_finalized != actual_last {
            mismatches.push(Mismatch::LastFinalizedMismatch {
                node: node_id.clone(),
                expected: expected_node.last_finalized,
                actual: actual_last,
            });
        }
    }

    mismatches
}

fn compare_votes(
    node_id: &str,
    expected: &BTreeMap<u64, BTreeSet<String>>,
    actual: &std::collections::HashMap<u64, HashSet<String>>,
    missing_ctor: impl Fn(String, u64, String) -> Mismatch,
    extra_ctor: impl Fn(String, u64, String) -> Mismatch,
    mismatches: &mut Vec<Mismatch>,
) {
    let all_views: BTreeSet<u64> = expected
        .keys()
        .chain(actual.keys())
        .copied()
        .collect();

    for view in all_views {
        let expected_signers: BTreeSet<&String> = expected
            .get(&view)
            .map(|s| s.iter().collect())
            .unwrap_or_default();
        let actual_signers: BTreeSet<&String> = actual
            .get(&view)
            .map(|s| s.iter().collect())
            .unwrap_or_default();

        for signer in expected_signers.difference(&actual_signers) {
            mismatches.push(missing_ctor(
                node_id.to_string(),
                view,
                (*signer).clone(),
            ));
        }
        for signer in actual_signers.difference(&expected_signers) {
            mismatches.push(extra_ctor(
                node_id.to_string(),
                view,
                (*signer).clone(),
            ));
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
            Mismatch::MissingNotarizeVote {
                node,
                view,
                signer,
            } => {
                write!(f, "{node}: missing notarize vote from {signer} for view {view}")
            }
            Mismatch::ExtraNotarizeVote {
                node,
                view,
                signer,
            } => {
                write!(f, "{node}: extra notarize vote from {signer} for view {view}")
            }
            Mismatch::MissingNullifyVote {
                node,
                view,
                signer,
            } => {
                write!(f, "{node}: missing nullify vote from {signer} for view {view}")
            }
            Mismatch::ExtraNullifyVote {
                node,
                view,
                signer,
            } => {
                write!(f, "{node}: extra nullify vote from {signer} for view {view}")
            }
            Mismatch::MissingFinalizeVote {
                node,
                view,
                signer,
            } => {
                write!(f, "{node}: missing finalize vote from {signer} for view {view}")
            }
            Mismatch::ExtraFinalizeVote {
                node,
                view,
                signer,
            } => {
                write!(f, "{node}: extra finalize vote from {signer} for view {view}")
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
        }
    }
}
