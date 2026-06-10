use crate::{
    bounds,
    simplex::Simplex,
    types::{Finalization, Notarization, Nullification, ReplicaState},
};
use commonware_codec::{Encode, Read};
use commonware_consensus::{
    simplex::{elector::Config as Elector, mocks::reporter::Reporter, scheme, scheme::Scheme},
    types::{TermLength, View},
};
use commonware_cryptography::{
    certificate::{self, Signers},
    sha256::Digest as Sha256Digest,
};
use rand_core::CryptoRngCore;
use std::collections::{HashMap, HashSet};

fn nullification_conflicts(
    nullified_view: u64,
    finalized_view: u64,
    term_length: TermLength,
) -> bool {
    let nullified_view = View::new(nullified_view);
    let finalized_view = View::new(finalized_view);
    nullified_view <= finalized_view && nullified_view.same_term(finalized_view, term_length)
}

pub fn check<P: Simplex>(n: u32, term_length: TermLength, replicas: Vec<ReplicaState>) {
    let threshold = bounds::quorum(n) as usize;

    // Invariant: agreement
    // All replicas that finalized a given view must have the same digest for that view.
    let all_views: HashSet<u64> = replicas
        .iter()
        .flat_map(|(_, _, finalizations)| finalizations.keys().cloned())
        .collect();
    for view in all_views {
        let finalizations_for_view: Vec<(usize, Sha256Digest)> = replicas
            .iter()
            .enumerate()
            .filter_map(|(idx, (_, _, finalizations))| {
                finalizations.get(&view).map(|d| (idx, d.payload))
            })
            .collect();

        if let Some((first_idx, first_digest)) = finalizations_for_view.first() {
            for (idx, digest) in &finalizations_for_view[1..] {
                assert_eq!(
                    digest, first_digest,
                    "Invariant violation: finalized digest mismatch in view {view}: replica {idx} has {digest:?} but replica {first_idx} has {first_digest:?}",
                );
            }
        }
    }

    // Invariant: no_nullification_in_finalized_view
    // If any replica finalized view v, no replica may have a nullification that covers v.
    let finalized_views: HashMap<u64, Sha256Digest> = replicas
        .iter()
        .flat_map(|(_, _, finalizations)| finalizations.iter().map(|(&view, d)| (view, d.payload)))
        .collect();
    for finalized_view in finalized_views.keys() {
        for (idx, (_, nullifications, _)) in replicas.iter().enumerate() {
            for nullified_view in nullifications.keys() {
                assert!(
                    !nullification_conflicts(*nullified_view, *finalized_view, term_length),
                    "Invariant violation: replica {idx} nullified view {nullified_view} but view {finalized_view} is finalized in the same term",
                );
            }
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

    // Invariant: no_finalization_for_nullified_view
    // If any replica nullified view v, no replica may finalize v or a later view in that term.
    let nullified: HashSet<u64> = replicas
        .iter()
        .flat_map(|(_, nulls, _)| nulls.keys().cloned())
        .collect();
    for (idx, (_, _, finals)) in replicas.iter().enumerate() {
        for v in finals.keys() {
            for nullified_view in &nullified {
                assert!(
                    !nullification_conflicts(*nullified_view, *v, term_length),
                    "Invariant violation: replica {idx} finalized view {v} which is nullified by view {nullified_view}"
                );
            }
        }
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

    // Enforce per-replica invariants
    for (notarizations, nullifications, finalizations) in replicas.iter() {
        // Invariant: certificates_are_valid
        // Certificates have the correct number of signatures.
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

        // Invariant: no_nullification_and_finalization_in_the_same_view
        for view in nullifications.keys() {
            assert!(
                !finalizations.contains_key(view),
                "Invariant violation: view {view} has both nullification and finalization",
            );
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
    E: CryptoRngCore,
    S: Scheme<Sha256Digest>,
    L: Elector<S>,
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
    use crate::simplex::SimplexEd25519;
    use commonware_utils::NZU64;
    use std::{collections::HashMap, panic};

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
        finalizations.insert(
            3,
            Finalization {
                payload,
                signature_count: Some(3),
            },
        );

        let result = panic::catch_unwind(|| {
            check::<SimplexEd25519>(
                4,
                TermLength::new(NZU64!(5)),
                vec![(notarizations, nullifications, finalizations)],
            );
        });
        assert!(result.is_err());
    }
}
