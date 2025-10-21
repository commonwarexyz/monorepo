use arbitrary::Arbitrary;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_p2p::simulated::helpers::PartitionStrategy;
use commonware_utils::{quorum, NZUsize};
use rand::{CryptoRng, Rng};
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    time::Duration,
};

pub mod simplex_fuzzer;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);
pub const PAGE_SIZE: NonZeroUsize = NZUsize!(1024);
pub const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

#[derive(Debug, Clone, Arbitrary)]
pub enum Mutation {
    Payload,
    View,
    Parent,
    All,
}

#[derive(Debug, Clone, Arbitrary)]
pub enum Message {
    Notarize,
    Nullify,
    Finalize,
    Random,
}

#[derive(Debug, Arbitrary, Clone)]
pub struct FuzzInput {
    pub seed: u64, // Seed for rng
    pub partition: PartitionStrategy,
}

// Generic data structures for invariant checking
pub struct Notarization {
    pub payload: Sha256Digest,
    pub signature_count: Option<usize>, // Some for Simplex, None for Threshold Simplex
}

pub struct Nullification {
    pub signature_count: Option<usize>, // Some for simplex, None for Threshold Simplex
}

pub struct Finalization {
    pub payload: Sha256Digest,
    pub signature_count: Option<usize>, // Some for simplex, None for Threshold Simplex
}

type View = u64;

pub type ReplicaState = (
    HashMap<View, Notarization>,
    HashMap<View, Nullification>,
    HashMap<View, Finalization>,
);

// Single unified function for checking invariants
#[allow(dead_code)]
pub fn check_invariants(n: u32, replicas: Vec<ReplicaState>) {
    let threshold = quorum(n) as usize;

    // Invariant: agreement (global)
    // All replicas that finalized a given view must have the same digest (payload) for that view.
    {
        let all_views: HashSet<u64> = replicas
            .iter()
            .flat_map(|(_, _, finalizations)| finalizations.keys().cloned())
            .collect();

        // For each view, check that all existing finalizations are the same
        for view in all_views {
            let finalizations_for_view: Vec<(usize, Sha256Digest)> = replicas
                .iter()
                .enumerate()
                .filter_map(|(replica_idx, (_, _, finalizations))| {
                    finalizations
                        .get(&view)
                        .map(|data| (replica_idx, data.payload))
                })
                .collect();

            // If there are any finalizations for this view, they must all be the same
            if let Some((first_replica_idx, first_digest)) = finalizations_for_view.first() {
                for (replica_idx, digest) in &finalizations_for_view[1..] {
                    assert_eq!(
                        digest, first_digest,
                        "finalized digest mismatch in view {view}: replica {replica_idx} has {digest:?} but replica {first_replica_idx} has {first_digest:?}",
                    );
                }
            }
        }
    }

    // Invariant: Safe finalization (global)
    // If any replica finalized view v, no replica may have nullification for view v.
    {
        let finalized_views: HashMap<View, Sha256Digest> = replicas
            .iter()
            .flat_map(|(_, _, finalizations)| {
                finalizations
                    .iter()
                    .map(|(&view, data)| (view, data.payload))
            })
            .collect();

        // Invariant: no_nullification_in_finalized_view
        // If any replica finalized view v, no replica may have a nullification for view v.

        for finalized_view in finalized_views.keys() {
            for (replica_idx, (_, nullifications, _)) in replicas.iter().enumerate() {
                assert!(
                    !nullifications.contains_key(finalized_view),
                    "Replica {replica_idx} has nullified view {finalized_view} but this view is finalized by some replica",
                );
            }
        }

        // Invariant: no_notarization_in_finalized_view
        // If any replica finalized view v for a digest, no replica may have a notarization for another digest for this view v.

        for (replica_idx, (notarizations, _, _)) in replicas.iter().enumerate() {
            for (&notarized_view, notarized_data) in notarizations.iter() {
                if let Some(&finalized_digest) = finalized_views.get(&notarized_view) {
                    let notarized_digest = notarized_data.payload;

                    assert_eq!(
                        finalized_digest, notarized_digest,
                        "Invariant violation: Replica {replica_idx} notarized view {notarized_view} with digest {notarized_digest:?} but this view is finalized with digest {finalized_digest:?}",
                    );
                }
            }
        }
    }

    // Invariant: no two quorum notarizations for different payloads in the same view
    // In any view, there cannot be quorum notarizations for multiple digests (payloads).
    {
        let mut per_view: HashMap<View, HashSet<Sha256Digest>> = HashMap::new();
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
                "Conflicting quorum notarizations in view {v}: payloads={payloads:?}"
            );
        }
    }

    // Invariant: If any replica nullified view v, no replica may finalize v.
    {
        let nullified: HashSet<View> = replicas
            .iter()
            .flat_map(|(_, nulls, _)| nulls.keys().cloned())
            .collect();

        for (replica_idx, (_, _, finals)) in replicas.iter().enumerate() {
            for v in finals.keys() {
                assert!(
                    !nullified.contains(v),
                    "Replica {replica_idx} finalized view {v} which is nullified elsewhere"
                );
            }
        }
    }

    // Invariant: finalization requires a notarization for the same (view, payload)
    // Any finalization seen anywhere must be backed by some notarization for the same (view, payload) by any replica.
    {
        let notarized: HashSet<(View, Sha256Digest)> = replicas
            .iter()
            .flat_map(|(notarizations, _, _)| notarizations.iter().map(|(&v, d)| (v, d.payload)))
            .collect();

        for (_, _, finalizations) in replicas.iter() {
            for (&v, d) in finalizations.iter() {
                assert!(
                    notarized.contains(&(v, d.payload)),
                    "Finalization without matching notarization: view {v}, payload={:?}",
                    d.payload
                );
            }
        }
    }

    for (notarizations, nullifications, finalizations) in replicas.iter() {
        // Invariant: certificates_are_valid_inv
        // certificates have correct number of signatures (only for simplex, not threshold)
        {
            for (view, data) in nullifications.iter() {
                if let Some(sig_count) = data.signature_count {
                    assert!(
                        sig_count >= threshold,
                        "Nullification certificate in view {view} has {sig_count} signatures but needs >= {threshold}",
                    );
                }
            }

            for (view, data) in notarizations.iter() {
                if let Some(sig_count) = data.signature_count {
                    assert!(
                        sig_count >= threshold,
                        "Notarization certificate in view {view} has {sig_count} signatures but needs >= {threshold}",
                    );
                }
            }

            for (view, data) in finalizations.iter() {
                if let Some(sig_count) = data.signature_count {
                    assert!(
                        sig_count >= threshold,
                        "Finalization certificate in view {view} has {sig_count} signatures but needs >= {threshold}",
                    );
                }
            }
        }

        // Invariant: valid_last_finalized
        for (&v, fin) in finalizations.iter() {
            match notarizations.get(&v) {
                Some(notar) => assert_eq!(
                    notar.payload, fin.payload,
                    "Replica finalized view {v} with payload {:?} but its local notarization has {:?}",
                    fin.payload, notar.payload
                ),
                None => panic!(
                    "Replica finalized view {v} but has no local notarization for that view"
                ),
            }
        }

        // Invariant: no_nullification_and_finalization_in_the_same_view
        {
            for view in nullifications.keys() {
                assert!(
                    !finalizations.contains_key(view),
                    "View {view} has both nullification and finalization",
                );
            }
        }
    }
}

// Removed extract_threshold_simplex_state as we're ignoring threshold_simplex

#[allow(dead_code)]
pub fn extract_simplex_state<E, P, S>(
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
                .map(|(&view, cert)| {
                    (
                        view,
                        Notarization {
                            payload: cert.proposal.payload,
                            signature_count: None, // Ed25519 doesn't expose signature count directly
                        },
                    )
                })
                .collect();

            let nullifications = reporter.nullifications.lock().unwrap();
            let nullification_data = nullifications
                .iter()
                .map(|(&view, _cert)| {
                    (
                        view,
                        Nullification {
                            signature_count: None, // Ed25519 doesn't expose signature count directly
                        },
                    )
                })
                .collect();

            let finalizations = reporter.finalizations.lock().unwrap();
            let finalization_data = finalizations
                .iter()
                .map(|(&view, cert)| {
                    (
                        view,
                        Finalization {
                            payload: cert.proposal.payload,
                            signature_count: None, // Ed25519 doesn't expose signature count directly
                        },
                    )
                })
                .collect();

            (notarization_data, nullification_data, finalization_data)
        })
        .collect()
}
