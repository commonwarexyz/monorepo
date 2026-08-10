use crate::{
    Configuration, bounds,
    simplex::Simplex,
    types::{Finalization, Notarization, Nullification, ReplicaState},
};
use commonware_codec::{Encode, Read};
use commonware_consensus::{
    simplex::{elector, mocks::reporter::Reporter, scheme, scheme::Scheme},
    types::TermLength,
};
use commonware_cryptography::{
    certificate::{self, Signers},
    sha256::Digest as Sha256Digest,
};
use rand_core::CryptoRng;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

// Intentionally restates View::covers with independent integer arithmetic:
// the fuzz oracle must not delegate to the production term predicates
// (same_term, term_start) or a bug in them could hide from the fuzzer.
// View 0 (genesis) is its own term; for views >= 1, term boundaries are
// [1, term_length], [term_length + 1, 2 * term_length], ...
fn nullification_conflicts(
    nullified_view: u64,
    finalized_view: u64,
    term_length: TermLength,
) -> bool {
    if nullified_view > finalized_view {
        return false;
    }
    if nullified_view == 0 {
        return finalized_view == 0;
    }
    let term_length = term_length.get();
    (nullified_view - 1) / term_length == (finalized_view - 1) / term_length
}

// Keep the fuzz oracle independent of the production term predicates. Genesis
// is term 0; view 1 begins term 1.
fn term_of(view: u64, term_length: TermLength) -> u64 {
    match view {
        0 => 0,
        view => 1 + (view - 1) / term_length.get(),
    }
}

// A term starts at genesis or immediately after a complete term.
fn is_term_start(view: u64, term_length: TermLength) -> bool {
    view == 0 || (view - 1).is_multiple_of(term_length.get())
}

/// Checks safety invariants across observations collected from every replica.
pub fn check<P: Simplex>(
    configuration: Configuration,
    term_length: TermLength,
    replicas: Vec<ReplicaState>,
) {
    let threshold = bounds::quorum(configuration.n) as usize;

    // Invariant: agreement
    // All replicas that finalized a given view must have the same digest for
    // that view. The parent is only compared when an honest quorum exists
    // (can_finalize): a Byzantine quorum can jointly mint a certificate with
    // a mutated parent view alongside the honest one, which would trip the
    // parent comparison without a real safety violation.
    let all_views: HashSet<u64> = replicas
        .iter()
        .flat_map(|(_, _, finalizations)| finalizations.keys().cloned())
        .collect();
    for view in all_views {
        let finalizations_for_view: Vec<(usize, (Sha256Digest, u64))> = replicas
            .iter()
            .enumerate()
            .filter_map(|(idx, (_, _, finalizations))| {
                finalizations
                    .get(&view)
                    .map(|d| (idx, (d.payload, d.parent)))
            })
            .collect();

        if let Some((first_idx, (first_payload, first_parent))) = finalizations_for_view.first() {
            for (idx, (payload, parent)) in &finalizations_for_view[1..] {
                assert_eq!(
                    payload, first_payload,
                    "Invariant violation: finalized digest mismatch in view {view}: replica {idx} has ({payload:?}, {parent}) but replica {first_idx} has ({first_payload:?}, {first_parent})",
                );
                if configuration.can_finalize() {
                    assert_eq!(
                        parent, first_parent,
                        "Invariant violation: finalized parent mismatch in view {view}: replica {idx} has ({payload:?}, {parent}) but replica {first_idx} has ({first_payload:?}, {first_parent})",
                    );
                }
            }
        }
    }

    // Invariant: finalization_ancestry
    // A finalized view's parent must be an earlier view, and no view may
    // finalize strictly between a parent and its child (such a block would be
    // forked around). A parent may also only skip views the protocol allows to
    // be skipped. Gated on `can_finalize` for the reason given above.
    if configuration.can_finalize() {
        let finalized_parents: BTreeMap<u64, u64> = replicas
            .iter()
            .flat_map(|(_, _, finalizations)| {
                finalizations.iter().map(|(&view, d)| (view, d.parent))
            })
            .collect();
        // Views any replica nullified. Taking the union across replicas is
        // deliberately permissive: a skip is accepted when the nullification
        // that justifies it was observed anywhere, not necessarily by the
        // replica that finalized. That can only weaken the check below.
        let nullified_views: BTreeSet<u64> = replicas
            .iter()
            .flat_map(|(_, nullifications, _)| nullifications.keys().copied())
            .collect();

        // In ascending view order, each parent must be strictly below its
        // child and at or above the previous finalized view (otherwise that
        // predecessor was forked around).
        let mut previous: Option<u64> = None;
        for (&view, &parent) in &finalized_parents {
            assert!(
                parent < view,
                "Invariant violation: view {view} finalized with parent {parent} not strictly below it",
            );
            if let Some(previous) = previous {
                assert!(
                    parent >= previous,
                    "Invariant violation: view {previous} finalized strictly between parent {parent} and finalized child {view}",
                );
            }
            previous = Some(view);

            // Only a term start may skip views, and then only over terms the
            // network agreed to abandon.
            if !is_term_start(view, term_length) {
                assert_eq!(
                    parent + 1,
                    view,
                    "Invariant violation: intra-term view {view} finalized with non-immediate parent {parent}",
                );
                continue;
            }
            // A nullification abandons its own view and the rest of that
            // view's term, so each term touched by the gap needs a
            // nullification at or below its first skipped view.
            let mut cursor = parent + 1;
            while cursor < view {
                let term = term_of(cursor, term_length);
                let covered = nullified_views
                    .range(..=cursor)
                    .next_back()
                    .is_some_and(|&nullified| term_of(nullified, term_length) == term);
                assert!(
                    covered,
                    "Invariant violation: view {view} finalized over view {cursor} (parent {parent}) with no nullification",
                );
                cursor = term * term_length.get() + 1;
            }
        }
    }

    // The remaining certificate-derived invariants are likewise gated on
    // `can_finalize`: each one encodes a safety argument that requires an
    // honest participant in the quorum intersection.
    if configuration.can_finalize() {
        // Invariant: no_nullification_in_finalized_view
        // If any replica finalized view v, no replica may have a nullification
        // that covers v (a nullification covers the rest of its term).
        let finalized_views: HashMap<u64, Sha256Digest> = replicas
            .iter()
            .flat_map(|(_, _, finalizations)| {
                finalizations.iter().map(|(&view, d)| (view, d.payload))
            })
            .collect();
        let nullified: HashSet<u64> = replicas
            .iter()
            .flat_map(|(_, nulls, _)| nulls.keys().cloned())
            .collect();
        for finalized_view in finalized_views.keys() {
            for nullified_view in &nullified {
                assert!(
                    !nullification_conflicts(*nullified_view, *finalized_view, term_length),
                    "Invariant violation: view {nullified_view} is nullified but view {finalized_view} is finalized in the same term",
                );
            }
        }

        // Invariant: no_conflicting_notarization_in_finalized_view
        // If any replica finalized view v for a digest, no replica may have a notarization for a different digest.
        for (idx, (notarizations, _, _)) in replicas.iter().enumerate() {
            for (&view, data) in notarizations.iter() {
                if let Some(&finalized_digest) = finalized_views.get(&view) {
                    assert_eq!(
                        finalized_digest, data.payload,
                        "Invariant violation: replica {idx} notarized view {view} with {:?} but finalized with {finalized_digest:?}",
                        data.payload
                    );
                }
            }
        }

        // Invariant: no_conflicting_quorum_notarizations
        // In any view, there cannot be quorum notarizations for multiple digests.
        let mut per_view: HashMap<u64, HashSet<Sha256Digest>> = HashMap::new();
        for (notarizations, _, _) in replicas.iter() {
            for (v, d) in notarizations {
                let is_quorum = d.signature_count.is_none_or(|c| c >= threshold);
                if is_quorum {
                    per_view.entry(*v).or_default().insert(d.payload);
                }
            }
        }
        for (v, payloads) in per_view {
            assert!(
                payloads.len() <= 1,
                "Invariant violation: conflicting quorum notarizations in view {v}: {payloads:?}"
            );
        }

        // Invariant: finalization_requires_notarization
        // Any finalization must be backed by some notarization for the same (view, payload).
        let notarized: HashSet<(u64, Sha256Digest)> = replicas
            .iter()
            .flat_map(|(notarizations, _, _)| notarizations.iter().map(|(&v, d)| (v, d.payload)))
            .collect();
        for (_, _, finalizations) in replicas.iter() {
            for (&v, d) in finalizations.iter() {
                assert!(
                    notarized.contains(&(v, d.payload)),
                    "Invariant violation: finalization without notarization: view {v}, payload={:?}",
                    d.payload
                );
            }
        }

        // Invariant: no_nullification_and_finalization_in_the_same_view
        for (_, nullifications, finalizations) in replicas.iter() {
            for view in nullifications.keys() {
                assert!(
                    !finalizations.contains_key(view),
                    "Invariant violation: view {view} has both nullification and finalization",
                );
            }
        }
    }

    // Invariant: certificates_are_valid
    // Certificates have the correct number of signatures. Signature validity
    // does not depend on the fault count, so this is never gated.
    for (notarizations, nullifications, finalizations) in replicas.iter() {
        for (view, data) in nullifications.iter() {
            if <P::Scheme as certificate::Scheme>::is_attributable() {
                let count = data
                    .signature_count
                    .expect("Attributable scheme must have signature count");
                assert!(
                    count >= threshold,
                    "Invariant violation: nullification in view {view} has {count} < {threshold} signatures"
                );
            } else {
                assert!(
                    data.signature_count.is_none(),
                    "Invariant violation: non-attributable scheme should not expose signature count"
                );
            }
        }

        for (view, data) in notarizations.iter() {
            if <P::Scheme as certificate::Scheme>::is_attributable() {
                let count = data
                    .signature_count
                    .expect("Attributable scheme must have signature count");
                assert!(
                    count >= threshold,
                    "Invariant violation: notarization in view {view} has {count} < {threshold} signatures"
                );
            } else {
                assert!(
                    data.signature_count.is_none(),
                    "Invariant violation: non-attributable scheme should not expose signature count"
                );
            }
        }

        for (view, data) in finalizations.iter() {
            if <P::Scheme as certificate::Scheme>::is_attributable() {
                let count = data
                    .signature_count
                    .expect("Attributable scheme must have signature count");
                assert!(
                    count >= threshold,
                    "Invariant violation: finalization in view {view} has {count} < {threshold} signatures"
                );
            } else {
                assert!(
                    data.signature_count.is_none(),
                    "Invariant violation: non-attributable scheme should not expose signature count"
                );
            }
        }
    }
}

fn get_signature_count<S: scheme::Scheme<Sha256Digest>>(
    certificate: &S::Certificate,
    max_participants: usize,
) -> Option<usize> {
    if !S::is_attributable() {
        return None;
    }

    let encoded = certificate.encode();
    let mut cursor = encoded.as_ref();
    let signers =
        Signers::read_cfg(&mut cursor, &max_participants).expect("certificate signers must decode");
    Some(signers.count())
}

pub fn extract<E, S, L>(
    reporters: Vec<Reporter<E, S, L, Sha256Digest>>,
    max_participants: usize,
) -> Vec<ReplicaState>
where
    E: CryptoRng,
    S: Scheme<Sha256Digest>,
    L: elector::Config<S>,
{
    reporters
        .iter()
        .map(|reporter| {
            let notarizations = reporter.notarizations.lock();
            let notarization_data = notarizations
                .iter()
                .map(|(view, cert)| {
                    (
                        view.get(),
                        Notarization {
                            payload: cert.proposal.payload,
                            signature_count: get_signature_count::<S>(
                                &cert.certificate,
                                max_participants,
                            ),
                        },
                    )
                })
                .collect();

            let nullifications = reporter.nullifications.lock();
            let nullification_data = nullifications
                .iter()
                .map(|(view, cert)| {
                    (
                        view.get(),
                        Nullification {
                            signature_count: get_signature_count::<S>(
                                &cert.certificate,
                                max_participants,
                            ),
                        },
                    )
                })
                .collect();

            let finalizations = reporter.finalizations.lock();
            let finalization_data = finalizations
                .iter()
                .map(|(view, cert)| {
                    (
                        view.get(),
                        Finalization {
                            payload: cert.proposal.payload,
                            parent: cert.proposal.parent.get(),
                            signature_count: get_signature_count::<S>(
                                &cert.certificate,
                                max_participants,
                            ),
                        },
                    )
                })
                .collect();

            (notarization_data, nullification_data, finalization_data)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{N4F1C3, N4F3C1, simplex::SimplexEd25519};
    use commonware_utils::NZU32;
    use std::{collections::HashMap, panic};

    /// Runs `check` and returns the panic message, so each test can assert
    /// its named invariant fired (fixtures can violate more than one rule).
    fn check_panics(
        configuration: Configuration,
        term_length: TermLength,
        replicas: Vec<ReplicaState>,
    ) -> String {
        let result = panic::catch_unwind(|| {
            check::<SimplexEd25519>(configuration, term_length, replicas);
        });
        let err = result.expect_err("check must panic");
        err.downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .expect("panic payload must be a string")
    }

    #[test]
    fn same_term_nullification_blocks_later_finalization() {
        let payload = Sha256Digest::from([7u8; 32]);
        let mut notarizations = HashMap::new();
        notarizations.insert(
            3,
            Notarization {
                payload,
                signature_count: Some(3),
            },
        );
        let mut nullifications = HashMap::new();
        nullifications.insert(
            1,
            Nullification {
                signature_count: Some(3),
            },
        );
        let mut finalizations = HashMap::new();
        // Parent 2 keeps the ancestry rules satisfied so only the same-term
        // nullification invariant can fire.
        finalizations.insert(
            3,
            Finalization {
                payload,
                parent: 2,
                signature_count: Some(3),
            },
        );

        let message = check_panics(
            N4F1C3,
            TermLength::new(NZU32!(5)),
            vec![(notarizations, nullifications, finalizations)],
        );
        assert!(
            message.contains("finalized in the same term"),
            "wrong invariant fired: {message}"
        );
    }

    #[test]
    fn parent_mismatch_requires_honest_quorum() {
        let payload = Sha256Digest::from([9u8; 32]);
        let replica = |parent| {
            let mut notarizations = HashMap::new();
            notarizations.insert(
                3,
                Notarization {
                    payload,
                    signature_count: Some(3),
                },
            );
            let mut finalizations = HashMap::new();
            finalizations.insert(
                3,
                Finalization {
                    payload,
                    parent,
                    signature_count: Some(3),
                },
            );
            (notarizations, HashMap::new(), finalizations)
        };

        // A Byzantine quorum can mint a certificate with a mutated parent
        // alongside the honest one, so a parent mismatch must not fire
        // without an honest quorum.
        check::<SimplexEd25519>(
            N4F3C1,
            TermLength::new(NZU32!(5)),
            vec![replica(1), replica(2)],
        );

        // With an honest quorum, a parent mismatch is a real violation. Pin
        // the message: whether the fixture's other violation (parent 1 skips
        // view 2) can also fire depends on how the checker flattens replicas.
        let message = check_panics(
            N4F1C3,
            TermLength::new(NZU32!(5)),
            vec![replica(1), replica(2)],
        );
        assert!(
            message.contains("finalized parent mismatch"),
            "wrong invariant fired: {message}"
        );
    }

    #[test]
    fn same_term_nullification_requires_honest_quorum() {
        let payload = Sha256Digest::from([8u8; 32]);
        let mut nullifications = HashMap::new();
        nullifications.insert(
            1,
            Nullification {
                signature_count: Some(3),
            },
        );
        let mut finalizations = HashMap::new();
        finalizations.insert(
            3,
            Finalization {
                payload,
                parent: 2,
                signature_count: Some(3),
            },
        );

        // A Byzantine quorum can mint both certificates on its own (and a
        // finalization without any notarization), so neither the same-term
        // exclusion nor the notarization-backing check may fire without an
        // honest quorum.
        check::<SimplexEd25519>(
            N4F3C1,
            TermLength::new(NZU32!(5)),
            vec![(HashMap::new(), nullifications, finalizations)],
        );
    }

    #[test]
    fn finalization_between_parent_and_child_fires() {
        let mut notarizations = HashMap::new();
        let mut finalizations = HashMap::new();
        for (view, byte, parent) in [(2u64, 2u8, 1u64), (5, 5, 1)] {
            let payload = Sha256Digest::from([byte; 32]);
            notarizations.insert(
                view,
                Notarization {
                    payload,
                    signature_count: Some(3),
                },
            );
            finalizations.insert(
                view,
                Finalization {
                    payload,
                    parent,
                    signature_count: Some(3),
                },
            );
        }

        // View 5 finalized with parent 1, but view 2 is also finalized: view 2
        // is forked around, so the ancestry invariant must fire. The fixture
        // also skips unnullified terms, so pin the message to the
        // forked-around invariant.
        let message = check_panics(
            N4F1C3,
            TermLength::ONE,
            vec![(notarizations, HashMap::new(), finalizations)],
        );
        assert!(
            message.contains("finalized strictly between parent"),
            "wrong invariant fired: {message}"
        );
    }

    #[test]
    fn intra_term_parent_skip_fires() {
        let payload = Sha256Digest::from([4u8; 32]);
        let state = || {
            let mut notarizations = HashMap::new();
            notarizations.insert(
                4,
                Notarization {
                    payload,
                    signature_count: Some(3),
                },
            );
            let mut finalizations = HashMap::new();
            finalizations.insert(
                4,
                Finalization {
                    payload,
                    parent: 2,
                    signature_count: Some(3),
                },
            );
            vec![(notarizations, HashMap::new(), finalizations)]
        };

        // View 4 is not a term start, so it must build on view 3.
        let message = check_panics(N4F1C3, TermLength::new(NZU32!(5)), state());
        assert!(
            message.contains("finalized with non-immediate parent"),
            "wrong invariant fired: {message}"
        );

        // Without an honest quorum the parent is not trustworthy, so the rule
        // must not fire (see `parent_mismatch_requires_honest_quorum`).
        check::<SimplexEd25519>(N4F3C1, TermLength::new(NZU32!(5)), state());
    }

    #[test]
    fn term_start_skip_requires_nullification() {
        let payload = Sha256Digest::from([6u8; 32]);
        // View 11 starts a term under term_length 5, so it may skip back to
        // view 3 only if the terms it skips (containing views 4 and 6) were
        // nullified.
        let state = |nullified: &[u64]| {
            let mut notarizations = HashMap::new();
            notarizations.insert(
                11,
                Notarization {
                    payload,
                    signature_count: Some(3),
                },
            );
            let mut nullifications = HashMap::new();
            for &view in nullified {
                nullifications.insert(
                    view,
                    Nullification {
                        signature_count: Some(3),
                    },
                );
            }
            let mut finalizations = HashMap::new();
            finalizations.insert(
                11,
                Finalization {
                    payload,
                    parent: 3,
                    signature_count: Some(3),
                },
            );
            vec![(notarizations, nullifications, finalizations)]
        };

        let message = check_panics(N4F1C3, TermLength::new(NZU32!(5)), state(&[]));
        assert!(
            message.contains("with no nullification"),
            "skip over an unnullified term must fire: {message}"
        );

        // Nullifying only the first skipped term leaves the second uncovered.
        let message = check_panics(N4F1C3, TermLength::new(NZU32!(5)), state(&[4]));
        assert!(
            message.contains("with no nullification"),
            "partial coverage must fire: {message}"
        );

        // A nullification covers only its own view and the rest of its term:
        // late nullifications (views 5 and 10) leave views 4 and 6 uncovered.
        // Pin the first uncovered view so coverage of view 4 cannot regress
        // while the assert still fires at view 6.
        let message = check_panics(N4F1C3, TermLength::new(NZU32!(5)), state(&[5, 10]));
        assert!(
            message.contains("over view 4"),
            "late nullifications must not cover earlier views: {message}"
        );

        // Both skipped terms nullified: the skip is legal.
        check::<SimplexEd25519>(N4F1C3, TermLength::new(NZU32!(5)), state(&[4, 6]));
    }

    #[test]
    fn parent_at_or_above_child_fires() {
        let payload = Sha256Digest::from([3u8; 32]);
        let mut finalizations = HashMap::new();
        finalizations.insert(
            3,
            Finalization {
                payload,
                parent: 3,
                signature_count: Some(3),
            },
        );

        let message = check_panics(
            N4F1C3,
            TermLength::new(NZU32!(5)),
            vec![(HashMap::new(), HashMap::new(), finalizations)],
        );
        assert!(
            message.contains("not strictly below it"),
            "wrong invariant fired: {message}"
        );
    }

    #[test]
    fn finalization_without_notarization_fires() {
        // Complements `same_term_nullification_requires_honest_quorum`, which
        // proves this check is suppressed without an honest quorum.
        let payload = Sha256Digest::from([10u8; 32]);
        let mut finalizations = HashMap::new();
        finalizations.insert(
            3,
            Finalization {
                payload,
                parent: 2,
                signature_count: Some(3),
            },
        );

        let message = check_panics(
            N4F1C3,
            TermLength::new(NZU32!(5)),
            vec![(HashMap::new(), HashMap::new(), finalizations)],
        );
        assert!(
            message.contains("finalization without notarization"),
            "wrong invariant fired: {message}"
        );
    }
}
