use arbitrary::Arbitrary;
use commonware_consensus::simplex::mocks::supervisor::Supervisor;
use commonware_cryptography::{ed25519::PublicKey, sha256::Digest as Sha256Digest};
use commonware_p2p::simulated::helpers::PartitionStrategy;
use commonware_utils::{quorum, NZUsize};
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    time::Duration,
};

pub mod simplex_fuzzer;
pub mod threshold_simplex_fuzzer;

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

#[derive(Debug, Arbitrary)]
pub struct FuzzInput {
    pub seed: u64, // Seed for rng
    pub partition: PartitionStrategy,
}

#[allow(dead_code)]
pub fn check_invariants(n: u32, correct_replicas: Vec<Supervisor<PublicKey, Sha256Digest>>) {
    let threshold = quorum(n) as usize;

    // Invariant: agreement
    // Finalized digests must be the same
    {
        let all_views: HashSet<u64> = correct_replicas
            .iter()
            .flat_map(|replica| {
                let finalizations = replica.finalizations.lock().unwrap();
                finalizations.keys().cloned().collect::<Vec<_>>()
            })
            .collect();

        // For each view, check that all existing finalizations are the same
        for view in all_views {
            let finalizations_for_view: Vec<(usize, Sha256Digest)> = correct_replicas
                .iter()
                .enumerate()
                .filter_map(|(replica_idx, replica)| {
                    let finalizations = replica.finalizations.lock().unwrap();
                    finalizations
                        .get(&view)
                        .map(|cert| (replica_idx, cert.proposal.payload))
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

    // Invariant: safe_finalization = no_nullification_in_finalized_view and no_notarization_in_finalized_view
    {
        let finalized_views: HashMap<u64, Sha256Digest> = correct_replicas
            .iter()
            .flat_map(|replica| {
                let finalizations = replica.finalizations.lock().unwrap();
                finalizations
                    .iter()
                    .map(|(&view, cert)| (view, cert.proposal.payload))
                    .collect::<Vec<_>>()
            })
            .collect();

        // Invariant: no_nullification_in_finalized_view
        // If there is a finalized block in a view v, there is no nullification in the same view.

        for finalized_view in finalized_views.keys() {
            for (replica_idx, replica) in correct_replicas.iter().enumerate() {
                let nullifications = replica.nullifications.lock().unwrap();

                assert!(
                    !nullifications.contains_key(finalized_view),
                    "Replica {replica_idx} has nullified view {finalized_view} but this view is finalized by some replica",
                );
            }
        }

        // Invariant: no_notarization_in_finalized_view
        // If there is a finalized block in a view v, there is no notarization for another block in the same view.

        for (replica_idx, replica) in correct_replicas.iter().enumerate() {
            let notarizations = replica.notarizations.lock().unwrap();

            for (&notarized_view, notarized_cert) in notarizations.iter() {
                if let Some(&finalized_digest) = finalized_views.get(&notarized_view) {
                    let notarized_digest = notarized_cert.proposal.payload;

                    assert_eq!(
                        finalized_digest, notarized_digest,
                        "Invariant violation: Replica {replica_idx} notarized view {notarized_view} with digest {notarized_digest:?} but this view is finalized with digest {finalized_digest:?}",
                    );
                }
            }
        }
    }

    for replica in correct_replicas.iter() {
        let notarizations = replica.notarizations.lock().unwrap();
        let nullifications = replica.nullifications.lock().unwrap();
        let finalizations = replica.finalizations.lock().unwrap();

        // Invariant: certificates_are_valid_inv
        // certificates have correct number of signatures
        {
            for (view, cert) in nullifications.iter() {
                assert!(
                    cert.signatures.len() >= threshold,
                    "Nullification certificate in view {view} has {} signatures but needs >= {threshold}: {cert:?}",
                    cert.signatures.len()
                );
            }

            for (view, cert) in notarizations.iter() {
                assert!(
                    cert.signatures.len() >= threshold,
                    "Notarization certificate in view {view} has {} signatures but needs >= {threshold}: {cert:?}",
                    cert.signatures.len()
                );
            }

            for (view, cert) in finalizations.iter() {
                assert!(
                    cert.signatures.len() >= threshold,
                    "Finalization certificate in view {view} has {} signatures but needs >= {threshold}: {cert:?}",
                    cert.signatures.len()
                );
            }
        }

        // Invariant: valid_last_finalized
        // notarization.view >= finalization.view
        {
            let last_notarized_view = notarizations.keys().max();
            let last_finalizied_view = finalizations.keys().max();

            if let Some(last_finalizied_view) = last_finalizied_view {
                if let Some(last_notarized_view) = last_notarized_view {
                    assert!(
                        last_notarized_view >= last_finalizied_view,
                        "notarization view {last_notarized_view} >= finalization view {last_finalizied_view}"
                    );
                }
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
