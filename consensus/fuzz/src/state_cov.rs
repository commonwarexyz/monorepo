//! State-coverage feedback for the Simplex harness.
//!
//! This module adds a second, protocol-aware signal: it projects the end-of-run per-replica
//! state to a set of canonical *state tokens* (`alpha`) and lights, for each
//! token, one counter in a large custom SanitizerCoverage table indexed by a
//! stable hash of the token.
//!
//! The token set is the novelty signal. libFuzzer turns each non-zero counter
//! into a feature independently (with `-use_counters=1`, bucketed by magnitude),
//! so a single fixed feature vector would only ever express per-dimension
//! progress: distinct abstract states that share every counter's bucket collapse.
//! Hashing each token to its own counter instead means a state token never
//! reached before in the campaign lights a previously-zero counter, so the input
//! is retained for protocol-state novelty even when it lights no new code edge.
//!
//! Tokens are structural and `(view, payload)`-aware: payloads are interned to
//! dense class ids so *relationships* between proposals (agreement and
//! equivocation across replicas) are captured, while the random digest bytes
//! that would prevent saturation are abstracted away.
//!
//! `alpha` is a pure function of the run's own state. The deterministic runtime
//! makes that state a deterministic function of the fuzz input, which is what
//! libFuzzer requires of a coverage signal.
use crate::{
    invariants::get_signature_count,
    types::{ProposalData, ReporterReplicaStateData},
    utils::fnv1a_hash,
};
use commonware_consensus::simplex::{
    elector::Config as Elector, mocks::reporter::Reporter, scheme::Scheme,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use rand_core::CryptoRngCore;
use sancov::Counters;
use std::collections::{BTreeMap, BTreeSet};

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Projects each replica reporter data into a [`ReporterReplicaStateData`], keyed by
/// replica index. Retains per-view certificate facts, signature counts, and the
/// finalized frontier for the state-coverage abstraction below.
pub fn encode_reporter_states<E, S, L>(
    reporters: &[Reporter<E, S, L, Sha256Digest>],
    max_participants: usize,
) -> BTreeMap<String, ReporterReplicaStateData>
where
    E: CryptoRngCore,
    S: Scheme<Sha256Digest>,
    L: Elector<S>,
{
    reporters
        .iter()
        .enumerate()
        .map(|(idx, reporter)| {
            let mut data = ReporterReplicaStateData::default();

            let notarizations = reporter.notarizations.lock();
            for (view, cert) in notarizations.iter() {
                let v = view.get();
                data.notarizations.insert(
                    v,
                    ProposalData {
                        parent: cert.proposal.parent.get(),
                        payload: lower_hex(cert.proposal.payload.as_ref()),
                    },
                );
                data.notarization_signature_counts.insert(
                    v,
                    get_signature_count::<S>(&cert.certificate, max_participants),
                );
                data.last_notarized = data.last_notarized.max(v);
            }
            drop(notarizations);

            let nullifications = reporter.nullifications.lock();
            for (view, cert) in nullifications.iter() {
                let v = view.get();
                data.nullifications.insert(v);
                data.nullification_signature_counts.insert(
                    v,
                    get_signature_count::<S>(&cert.certificate, max_participants),
                );
                data.last_nullified = data.last_nullified.max(v);
            }
            drop(nullifications);

            let finalizations = reporter.finalizations.lock();
            for (view, cert) in finalizations.iter() {
                let v = view.get();
                data.finalizations.insert(
                    v,
                    ProposalData {
                        parent: cert.proposal.parent.get(),
                        payload: lower_hex(cert.proposal.payload.as_ref()),
                    },
                );
                data.finalization_signature_counts.insert(
                    v,
                    get_signature_count::<S>(&cert.certificate, max_participants),
                );
                data.last_finalized = data.last_finalized.max(v);
            }
            drop(finalizations);

            let certified = reporter.certified.lock();
            data.certified = certified.iter().map(|v| v.get()).collect();
            drop(certified);

            data.successful_certifications = data
                .notarizations
                .keys()
                .chain(data.finalizations.keys())
                .copied()
                .collect();

            // Vote maps advance the frontier past the recovered certificates: a
            // replica may have voted in a view that never formed a certificate.
            let notarizes = reporter.notarizes.lock();
            for view in notarizes.keys() {
                data.last_notarized = data.last_notarized.max(view.get());
            }
            drop(notarizes);

            let nullifies = reporter.nullifies.lock();
            for view in nullifies.keys() {
                data.last_nullified = data.last_nullified.max(view.get());
            }
            drop(nullifies);

            (idx.to_string(), data)
        })
        .collect()
}

/// Number of counters in the custom SanitizerCoverage table. Each distinct state
/// token maps (by stable hash) to one counter, so a token never reached before in
/// the campaign lights a previously-zero counter and the input is retained. Sized
/// well above the number of structurally-distinct tokens a small Simplex run
/// produces, to keep hash collisions (two states sharing a counter) rare.
const STATE_COUNTERS: usize = 1 << 16;

static COUNTERS: Counters<STATE_COUNTERS> = Counters::new();

/// Raw pointer to the counter bytes.
///
/// SAFETY: `Counters<N>` is `#[repr(transparent)]` over `UnsafeCell<[u8; N]>`
/// (documented and relied upon by the crate itself), so a shared reference
/// aliases a `[u8; N]` with interior mutability. `reset` and `observe` run
/// single-threaded at a run boundary; nothing else touches the table.
fn table() -> *mut u8 {
    &COUNTERS as *const Counters<STATE_COUNTERS> as *mut u8
}

/// Registers the table with the SanitizerCoverage consumer (once) and zeroes it.
///
/// Called at the start of every run so the counters reflect that run alone.
/// Registration touches a sanitizer symbol that only exists under
/// `-fsanitize=fuzzer`, so it is gated to fuzzing builds; the zeroing is a
/// harmless no-op elsewhere.
pub fn reset() {
    #[cfg(fuzzing)]
    {
        use std::sync::Once;
        static REGISTERED: Once = Once::new();
        REGISTERED.call_once(|| COUNTERS.register());
    }
    // SAFETY: see `table`.
    unsafe { core::ptr::write_bytes(table(), 0, STATE_COUNTERS) };
}

/// Lights one counter per state token from [`alpha`], so a token not reached
/// before in the campaign registers as new coverage and the input is retained.
/// The *set* of abstract-state tokens is the novelty signal, not a per-dimension
/// progress magnitude.
pub fn observe(states: &BTreeMap<String, ReporterReplicaStateData>) {
    for token in alpha(states) {
        let idx = (fnv1a_hash(token.as_bytes()) % STATE_COUNTERS as u64) as usize;
        // SAFETY: see `table`; `idx < STATE_COUNTERS` by construction.
        unsafe {
            let cell = table().add(idx);
            cell.write(cell.read().saturating_add(1));
        }
    }
}

/// Abstraction function: projects the per-replica state to the canonical set of
/// state tokens that defines its abstract state. Two runs with the same token set
/// are the same abstract state; a run that produces a token not seen before is a
/// new abstract state.
///
/// Payloads are interned to dense class ids by first occurrence in a canonical
/// structural traversal (not by payload value), so agreement and equivocation are
/// captured by `(view, class)` without the random digest bytes preventing
/// saturation.
pub fn alpha(states: &BTreeMap<String, ReporterReplicaStateData>) -> Vec<String> {
    // Assign payload class ids by first occurrence in a canonical structural
    // traversal (replica key order, then view order, notarizations before
    // finalizations). Sorting by payload hex instead would let the random digest
    // bytes pick the labels, so structurally-identical states whose payloads sort
    // differently would get different tokens and fake novelty.
    let mut class: BTreeMap<&str, usize> = BTreeMap::new();
    for replica in states.values() {
        for proposal in replica
            .notarizations
            .values()
            .chain(replica.finalizations.values())
        {
            let next = class.len();
            class.entry(proposal.payload.as_str()).or_insert(next);
        }
    }

    let mut tokens: BTreeSet<String> = BTreeSet::new();

    // Per-replica facts as independent tokens (identity-independent: a fact
    // reached by any replica is the same token). One token per fact, rather than a
    // concatenated per-replica string, keeps the token space a sum of per-fact
    // cardinalities instead of their product.
    for replica in states.values() {
        local_tokens(replica, &class, &mut tokens);
    }

    // Cross-replica certificate facts, keyed by (view, payload-class).
    let mut notarized: BTreeMap<u64, BTreeSet<usize>> = BTreeMap::new();
    let mut finalized: BTreeMap<u64, BTreeSet<usize>> = BTreeMap::new();
    let mut nullified: BTreeSet<u64> = BTreeSet::new();
    for replica in states.values() {
        for (view, proposal) in &replica.notarizations {
            notarized
                .entry(*view)
                .or_default()
                .insert(class[proposal.payload.as_str()]);
        }
        for (view, proposal) in &replica.finalizations {
            finalized
                .entry(*view)
                .or_default()
                .insert(class[proposal.payload.as_str()]);
        }
        nullified.extend(replica.nullifications.iter().copied());
    }
    for (view, classes) in &notarized {
        tokens.insert(format!("not:{view}:{classes:?}"));
    }
    for (view, classes) in &finalized {
        tokens.insert(format!("fin:{view}:{classes:?}"));
    }
    for view in &nullified {
        tokens.insert(format!("nul:{view}"));
    }

    // System-wide frontiers: the max over replicas of each per-replica frontier.
    // These expose "the network has reached view X" as coverage, which the
    // per-replica `rfront:` tokens do not.
    if let Some(view) = states.values().map(|r| r.last_finalized).max() {
        tokens.insert(format!("max_finalized:{view}"));
    }
    if let Some(view) = states.values().map(|r| r.last_notarized).max() {
        tokens.insert(format!("max_notarized:{view}"));
    }
    if let Some(view) = states.values().map(|r| r.last_nullified).max() {
        tokens.insert(format!("max_nullified:{view}"));
    }

    tokens.into_iter().collect()
}

/// Emits a replica's local state as independent, bounded tokens (one per fact),
/// identity-independent so a fact reached by any replica is the same token.
fn local_tokens(
    replica: &ReporterReplicaStateData,
    class: &BTreeMap<&str, usize>,
    tokens: &mut BTreeSet<String>,
) {
    tokens.insert(format!(
        "rfront:{}:{}:{}",
        replica.last_finalized, replica.last_notarized, replica.last_nullified,
    ));
    for (view, proposal) in &replica.notarizations {
        tokens.insert(format!(
            "rnot:{view}:{}:p{}:{:?}",
            class[proposal.payload.as_str()],
            proposal.parent,
            replica
                .notarization_signature_counts
                .get(view)
                .copied()
                .flatten(),
        ));
    }
    for (view, proposal) in &replica.finalizations {
        tokens.insert(format!(
            "rfin:{view}:{}:p{}:{:?}",
            class[proposal.payload.as_str()],
            proposal.parent,
            replica
                .finalization_signature_counts
                .get(view)
                .copied()
                .flatten(),
        ));
    }
    for view in &replica.nullifications {
        tokens.insert(format!(
            "rnul:{view}:{:?}",
            replica
                .nullification_signature_counts
                .get(view)
                .copied()
                .flatten(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replica(
        notarized: &[(u64, &str)],
        finalized: &[(u64, &str)],
        nullified: &[u64],
        last_finalized: u64,
    ) -> ReporterReplicaStateData {
        let mut data = ReporterReplicaStateData {
            last_finalized,
            nullifications: nullified.iter().copied().collect(),
            ..Default::default()
        };
        for &(view, payload) in notarized {
            data.notarizations.insert(
                view,
                ProposalData {
                    parent: 0,
                    payload: payload.to_string(),
                },
            );
        }
        for &(view, payload) in finalized {
            data.finalizations.insert(
                view,
                ProposalData {
                    parent: 0,
                    payload: payload.to_string(),
                },
            );
        }
        data
    }

    #[test]
    fn alpha_is_deterministic() {
        let mut states = BTreeMap::new();
        states.insert(
            "0".into(),
            replica(&[(1, "aa"), (2, "bb")], &[(1, "aa")], &[3], 1),
        );
        assert_eq!(alpha(&states), alpha(&states));
    }

    #[test]
    fn alpha_golden_single_replica() {
        let mut states = BTreeMap::new();
        states.insert("0".into(), replica(&[(1, "aa")], &[(1, "aa")], &[], 1));
        let tokens = alpha(&states);
        // One payload class ("aa" -> 0), parent 0, no signature counts.
        assert!(tokens.contains(&"not:1:{0}".to_string()));
        assert!(tokens.contains(&"fin:1:{0}".to_string()));
        assert!(tokens.contains(&"rfront:1:0:0".to_string()));
        assert!(tokens.contains(&"rnot:1:0:p0:None".to_string()));
        assert!(tokens.contains(&"rfin:1:0:p0:None".to_string()));
        assert!(tokens.contains(&"max_finalized:1".to_string()));
    }

    #[test]
    fn global_frontiers_are_part_of_state() {
        let mut states = BTreeMap::new();
        states.insert(
            "0".into(),
            ReporterReplicaStateData {
                last_finalized: 5,
                last_notarized: 7,
                last_nullified: 3,
                ..Default::default()
            },
        );
        states.insert(
            "1".into(),
            ReporterReplicaStateData {
                last_finalized: 4,
                last_notarized: 9,
                last_nullified: 6,
                ..Default::default()
            },
        );
        let tokens = alpha(&states);
        // Global frontiers are the max over replicas of each per-replica frontier.
        assert!(tokens.contains(&"max_finalized:5".to_string()));
        assert!(tokens.contains(&"max_notarized:9".to_string()));
        assert!(tokens.contains(&"max_nullified:6".to_string()));
    }

    #[test]
    fn parent_is_part_of_state() {
        // Same view and payload class, different parent: distinct ancestry must
        // not collapse to the same abstract state.
        let with_parent = |parent| {
            let mut data = ReporterReplicaStateData::default();
            data.notarizations.insert(
                1,
                ProposalData {
                    parent,
                    payload: "aa".into(),
                },
            );
            BTreeMap::from([("0".to_string(), data)])
        };
        assert_ne!(alpha(&with_parent(0)), alpha(&with_parent(9)));
    }

    #[test]
    fn class_ids_are_structural_not_payload_value() {
        // Same structure (one replica, two views, two distinct payloads, no
        // agreement), only the payload bytes are swapped between views. Class
        // labels must follow the traversal (view 1 -> 0, view 2 -> 1) in both,
        // so the abstract state is identical.
        let mut a = BTreeMap::new();
        a.insert("0".into(), replica(&[(1, "zz"), (2, "aa")], &[], &[], 0));
        let mut b = BTreeMap::new();
        b.insert("0".into(), replica(&[(1, "aa"), (2, "zz")], &[], &[], 0));
        assert_eq!(alpha(&a), alpha(&b));
    }

    #[test]
    fn alpha_emits_cross_replica_facts() {
        let mut states = BTreeMap::new();
        states.insert("0".into(), replica(&[(1, "aa")], &[(1, "aa")], &[2], 1));
        states.insert("1".into(), replica(&[(1, "aa")], &[(1, "aa")], &[2, 3], 1));
        let tokens = alpha(&states);
        assert!(tokens.contains(&"not:1:{0}".to_string()));
        assert!(tokens.contains(&"fin:1:{0}".to_string()));
        assert!(tokens.contains(&"nul:2".to_string()));
        assert!(tokens.contains(&"nul:3".to_string()));
    }

    #[test]
    fn alpha_empty_has_no_tokens() {
        let states = BTreeMap::new();
        assert!(alpha(&states).is_empty());
    }
}
