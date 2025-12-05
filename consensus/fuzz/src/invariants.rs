use crate::types::{Finalization, Notarization, Nullification, ReplicaState};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_utils::quorum;
use rand::{CryptoRng, Rng};
use std::collections::{HashMap, HashSet};

pub fn check(n: u32, replicas: Vec<ReplicaState>) {
    let threshold = quorum(n) as usize;

    // Agreement: all replicas finalize the same digest for each view
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
                    "finalized digest mismatch in view {view}: replica {idx} has {digest:?} but replica {first_idx} has {first_digest:?}",
                );
            }
        }
    }

    // Safe finalization: no nullification or conflicting notarization for finalized views
    let finalized_views: HashMap<u64, Sha256Digest> = replicas
        .iter()
        .flat_map(|(_, _, finalizations)| finalizations.iter().map(|(&view, d)| (view, d.payload)))
        .collect();

    for finalized_view in finalized_views.keys() {
        for (idx, (_, nullifications, _)) in replicas.iter().enumerate() {
            assert!(
                !nullifications.contains_key(finalized_view),
                "replica {idx} nullified view {finalized_view} but it is finalized",
            );
        }
    }

    for (idx, (notarizations, _, _)) in replicas.iter().enumerate() {
        for (&view, data) in notarizations.iter() {
            if let Some(&finalized_digest) = finalized_views.get(&view) {
                assert_eq!(
                    finalized_digest, data.payload,
                    "replica {idx} notarized view {view} with {:?} but finalized with {finalized_digest:?}",
                    data.payload
                );
            }
        }
    }

    // No conflicting quorum notarizations
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
            "conflicting quorum notarizations in view {v}: {payloads:?}"
        );
    }

    // No finalization for nullified views
    let nullified: HashSet<u64> = replicas
        .iter()
        .flat_map(|(_, nulls, _)| nulls.keys().cloned())
        .collect();

    for (idx, (_, _, finals)) in replicas.iter().enumerate() {
        for v in finals.keys() {
            assert!(
                !nullified.contains(v),
                "replica {idx} finalized view {v} which is nullified"
            );
        }
    }

    // Finalization requires matching notarization
    let notarized: HashSet<(u64, Sha256Digest)> = replicas
        .iter()
        .flat_map(|(notarizations, _, _)| notarizations.iter().map(|(&v, d)| (v, d.payload)))
        .collect();

    for (_, _, finalizations) in replicas.iter() {
        for (&v, d) in finalizations.iter() {
            assert!(
                notarized.contains(&(v, d.payload)),
                "finalization without notarization: view {v}, payload={:?}",
                d.payload
            );
        }
    }

    // Per-replica invariants
    for (notarizations, nullifications, finalizations) in replicas.iter() {
        // Certificate signature counts
        for (view, data) in nullifications.iter() {
            if let Some(count) = data.signature_count {
                assert!(
                    count >= threshold,
                    "nullification in view {view} has {count} < {threshold} signatures"
                );
            }
        }

        for (view, data) in notarizations.iter() {
            if let Some(count) = data.signature_count {
                assert!(
                    count >= threshold,
                    "notarization in view {view} has {count} < {threshold} signatures"
                );
            }
        }

        for (view, data) in finalizations.iter() {
            if let Some(count) = data.signature_count {
                assert!(
                    count >= threshold,
                    "finalization in view {view} has {count} < {threshold} signatures"
                );
            }
        }

        // Finalization matches local notarization
        for (&v, fin) in finalizations.iter() {
            match notarizations.get(&v) {
                Some(notar) => assert_eq!(
                    notar.payload, fin.payload,
                    "finalized view {v} with {:?} but notarized {:?}",
                    fin.payload, notar.payload
                ),
                None => panic!("finalized view {v} without local notarization"),
            }
        }

        // No nullification and finalization for same view
        for view in nullifications.keys() {
            assert!(
                !finalizations.contains_key(view),
                "view {view} has both nullification and finalization",
            );
        }
    }
}

pub fn extract<E, P, S>(
    reporters: Vec<commonware_consensus::simplex::mocks::reporter::Reporter<E, P, S, Sha256Digest>>,
) -> Vec<ReplicaState>
where
    E: Rng + CryptoRng,
    P: commonware_cryptography::PublicKey,
    S: commonware_consensus::simplex::signing_scheme::Scheme,
{
    reporters
        .iter()
        .map(|reporter| {
            let notarizations = reporter.notarizations.lock().unwrap();
            let notarization_data = notarizations
                .iter()
                .map(|(view, cert)| {
                    (
                        view.get(),
                        Notarization {
                            payload: cert.proposal.payload,
                            signature_count: None,
                        },
                    )
                })
                .collect();

            let nullifications = reporter.nullifications.lock().unwrap();
            let nullification_data = nullifications
                .keys()
                .map(|view| {
                    (
                        view.get(),
                        Nullification {
                            signature_count: None,
                        },
                    )
                })
                .collect();

            let finalizations = reporter.finalizations.lock().unwrap();
            let finalization_data = finalizations
                .iter()
                .map(|(view, cert)| {
                    (
                        view.get(),
                        Finalization {
                            payload: cert.proposal.payload,
                            signature_count: None,
                        },
                    )
                })
                .collect();

            (notarization_data, nullification_data, finalization_data)
        })
        .collect()
}
