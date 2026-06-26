//! State-coverage feedback for the Simplex honest harness.
//!
//! Code coverage of the honest actors is saturated, so it no longer
//! discriminates between shallow and deep protocol behaviors. This module adds a
//! second, protocol-aware signal: it projects the end-of-run per-replica reporter
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
//! dense class ids so *relationships* between proposals (agreement, equivocation,
//! finalization without a matching notarization) are captured, while the random
//! digest bytes that would prevent saturation are abstracted away.
//!
//! `alpha` is a pure function of the run's own state. The deterministic runtime
//! makes that state a deterministic function of the fuzz input, which is what
//! libFuzzer requires of a coverage signal.
use crate::{
    invariants::get_signature_count,
    types::{ProposalData, ReporterReplicaStateData},
};
use commonware_consensus::simplex::{
    elector::Config as Elector, mocks::reporter::Reporter, scheme::Scheme,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_utils::ordered::Quorum;
use rand_core::CryptoRngCore;
use sancov::Counters;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Projects each honest reporter into a [`ReporterReplicaStateData`], keyed by
/// replica index. Retains per-view signer sets and the finalized frontier so the
/// abstraction below can read deeper structure than the safety oracle needs.
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
            // Payload of each recovered certificate, used to attribute signers to
            // the certified payload instead of unioning across the conflicting
            // votes the reporter observed.
            let mut recovered_not: BTreeMap<u64, Sha256Digest> = BTreeMap::new();
            let mut recovered_fin: BTreeMap<u64, Sha256Digest> = BTreeMap::new();

            let notarizations = reporter.notarizations.lock();
            for (view, cert) in notarizations.iter() {
                let v = view.get();
                recovered_not.insert(v, cert.proposal.payload);
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
            }
            drop(nullifications);

            let finalizations = reporter.finalizations.lock();
            for (view, cert) in finalizations.iter() {
                let v = view.get();
                recovered_fin.insert(v, cert.proposal.payload);
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
                data.max_finalized_view = data.max_finalized_view.max(v);
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

            // Signers are recorded as participant indices, not public-key hex.
            // The mock schemes regenerate keys from the fuzz RNG, so the same
            // signer set would otherwise produce a different token per input and
            // fake state novelty. Notarize/finalize signers are scoped to the
            // certified payload to keep the attribution payload-correct.
            let notarizes = reporter.notarizes.lock();
            for (view, by_digest) in notarizes.iter() {
                let v = view.get();
                let entry = data.notarize_signers.entry(v).or_default();
                if let Some(signers) = recovered_not.get(&v).and_then(|d| by_digest.get(d)) {
                    for pk in signers {
                        if let Some(index) = reporter.participants.index(pk) {
                            entry.insert(usize::from(index).to_string());
                        }
                    }
                }
            }
            drop(notarizes);

            let nullifies = reporter.nullifies.lock();
            for (view, signers) in nullifies.iter() {
                let entry = data.nullify_signers.entry(view.get()).or_default();
                for pk in signers {
                    if let Some(index) = reporter.participants.index(pk) {
                        entry.insert(usize::from(index).to_string());
                    }
                }
            }
            drop(nullifies);

            let finalizes = reporter.finalizes.lock();
            for (view, by_digest) in finalizes.iter() {
                let v = view.get();
                let entry = data.finalize_signers.entry(v).or_default();
                if let Some(signers) = recovered_fin.get(&v).and_then(|d| by_digest.get(d)) {
                    for pk in signers {
                        if let Some(index) = reporter.participants.index(pk) {
                            entry.insert(usize::from(index).to_string());
                        }
                    }
                }
            }
            drop(finalizes);

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

/// FNV-1a hash, mapping a state token onto a counter index. Stable and
/// dependency-free so the mapping is identical across every run in a campaign.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
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
        let idx = (fnv1a(token.as_bytes()) % STATE_COUNTERS as u64) as usize;
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

    // Per-replica local state shape (identity-independent: a shape reached by any
    // replica is the same token). Carries payload class, signers, and signature
    // counts, so replica-local distributions are not collapsed.
    for replica in states.values() {
        tokens.insert(local_token(replica, &class));
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

    // Anomalies, (view, payload)-aware where the certificate carries a payload: a
    // finalization for (view, class) with no notarization for that same class is
    // the interesting mismatch, even if some other class was notarized in the
    // view. (Nullifications carry no payload, so `cert_and_nul` is view-level.)
    for (view, fin_classes) in &finalized {
        let not_classes = notarized.get(view);
        for class in fin_classes {
            if not_classes.is_none_or(|n| !n.contains(class)) {
                tokens.insert(format!("fin_wo_not:{view}:{class}"));
            }
        }
    }
    for view in &nullified {
        if notarized.contains_key(view) || finalized.contains_key(view) {
            tokens.insert(format!("cert_and_nul:{view}"));
        }
    }

    // Whole-state token: one token derived from the full sorted token set, so a
    // new *combination* of already-seen tokens is itself new coverage. Without
    // it, libFuzzer rewards new individual tokens but not a novel token-set
    // state built from tokens it has each seen before.
    let mut result: Vec<String> = tokens.into_iter().collect();
    let digest = fnv1a(result.join("\n").as_bytes());
    result.push(format!("state:{digest:016x}"));
    result
}

/// Canonical token for a single replica's local state. Identity-independent so a
/// shape reached by any replica is the same token.
fn local_token(replica: &ReporterReplicaStateData, class: &BTreeMap<&str, usize>) -> String {
    let mut token = format!("local:f={}", replica.max_finalized_view);
    for (view, proposal) in &replica.notarizations {
        let _ = write!(
            token,
            "|N{view}:{}:p{}:{:?}:{:?}",
            class[proposal.payload.as_str()],
            proposal.parent,
            replica
                .notarization_signature_counts
                .get(view)
                .copied()
                .flatten(),
            replica.notarize_signers.get(view),
        );
    }
    for (view, proposal) in &replica.finalizations {
        let _ = write!(
            token,
            "|F{view}:{}:p{}:{:?}:{:?}",
            class[proposal.payload.as_str()],
            proposal.parent,
            replica
                .finalization_signature_counts
                .get(view)
                .copied()
                .flatten(),
            replica.finalize_signers.get(view),
        );
    }
    for view in &replica.nullifications {
        let _ = write!(
            token,
            "|U{view}:{:?}:{:?}",
            replica
                .nullification_signature_counts
                .get(view)
                .copied()
                .flatten(),
            replica.nullify_signers.get(view),
        );
    }
    token
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replica(
        notarized: &[(u64, &str)],
        finalized: &[(u64, &str)],
        nullified: &[u64],
        max_finalized_view: u64,
    ) -> ReporterReplicaStateData {
        let mut data = ReporterReplicaStateData {
            max_finalized_view,
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
        // One payload class ("aa" -> 0), parent 0, no signers / signature counts.
        assert!(tokens.contains(&"not:1:{0}".to_string()));
        assert!(tokens.contains(&"fin:1:{0}".to_string()));
        assert!(tokens.contains(&"local:f=1|N1:0:p0:None:None|F1:0:p0:None:None".to_string()));
        assert_eq!(tokens.iter().filter(|t| t.starts_with("state:")).count(), 1);
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
    fn whole_state_token_distinguishes_token_sets() {
        let state_token = |s: &BTreeMap<String, ReporterReplicaStateData>| {
            alpha(s)
                .into_iter()
                .find(|t| t.starts_with("state:"))
                .unwrap()
        };
        let mut a = BTreeMap::new();
        a.insert("0".into(), replica(&[(1, "aa")], &[(1, "aa")], &[], 1));
        let mut b = BTreeMap::new();
        b.insert("0".into(), replica(&[(1, "aa")], &[], &[2], 0));
        assert_ne!(state_token(&a), state_token(&b));
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
        // Honest agreement: finalized class matches a notarized class, no anomaly.
        assert!(!tokens.iter().any(|t| t.starts_with("fin_wo_not")));
    }

    #[test]
    fn fin_without_notarization_is_payload_aware() {
        // View 1 is finalized with payload "bb" but only "aa" is notarized there.
        // View-level differencing (old behavior) sees finalized{1} \ notarized{1}
        // = {} and reports nothing; the (view, payload) token catches the
        // mismatch on the unbacked class.
        let mut states = BTreeMap::new();
        states.insert("0".into(), replica(&[(1, "aa")], &[(1, "bb")], &[], 1));
        let tokens = alpha(&states);
        // Classes: "aa" -> 0, "bb" -> 1.
        assert!(tokens.contains(&"fin_wo_not:1:1".to_string()));
    }

    #[test]
    fn cert_and_nullified_view() {
        // A view that is both finalized (by one replica) and nullified (by
        // another) is an anomaly token.
        let mut states = BTreeMap::new();
        states.insert("0".into(), replica(&[(1, "aa")], &[(1, "aa")], &[], 1));
        states.insert("1".into(), replica(&[], &[], &[1], 0));
        let tokens = alpha(&states);
        assert!(tokens.contains(&"cert_and_nul:1".to_string()));
    }

    #[test]
    fn alpha_empty_has_only_whole_state_token() {
        let states = BTreeMap::new();
        let tokens = alpha(&states);
        assert_eq!(tokens.len(), 1);
        assert!(tokens[0].starts_with("state:"));
    }
}
