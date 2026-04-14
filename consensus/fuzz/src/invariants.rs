use crate::{
    bounds,
    simplex::Simplex,
    types::{Finalization, Notarization, Nullification, ReplayedReplicaState, ReplicaState},
};
use commonware_codec::{Encode, Read};
use commonware_consensus::simplex::{
    elector::Config as Elector, mocks::reporter::Reporter, scheme, scheme::Scheme,
};
use commonware_cryptography::{
    certificate::{Scheme as CertificateScheme, Signers},
    sha256::Digest as Sha256Digest,
};
use rand_core::CryptoRngCore;
use std::collections::{BTreeSet, HashMap, HashSet};

pub fn check<P: Simplex>(n: u32, replicas: &[ReplicaState]) {
    let threshold = bounds::quorum(n) as usize;

    // Invariant: agreement
    // All replicas that finalized a given view must have the same digest for that view.
    let all_views: HashSet<u64> = replicas.iter().flat_map(|r| r.2.keys().cloned()).collect();
    for view in all_views {
        let finalizations_for_view: Vec<(usize, Sha256Digest)> = replicas
            .iter()
            .enumerate()
            .filter_map(|(idx, r)| r.2.get(&view).map(|d| (idx, d.payload)))
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
    // If any replica finalized view v, no replica may have a nullification for view v.
    let finalized_views: HashMap<u64, Sha256Digest> = replicas
        .iter()
        .flat_map(|r| r.2.iter().map(|(&view, d)| (view, d.payload)))
        .collect();
    for finalized_view in finalized_views.keys() {
        for (idx, r) in replicas.iter().enumerate() {
            assert!(
                !r.1.contains_key(finalized_view),
                "Invariant violation: replica {idx} nullified view {finalized_view} but it is finalized",
            );
        }
    }

    // Invariant: no_conflicting_notarization_in_finalized_view
    // If any replica finalized view v for a digest, no replica may have a notarization for a different digest.
    for (idx, r) in replicas.iter().enumerate() {
        for (&view, data) in r.0.iter() {
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
    for r in replicas.iter() {
        for (v, d) in &r.0 {
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
    // If any replica nullified view v, no replica may finalize v.
    let nullified: HashSet<u64> = replicas.iter().flat_map(|r| r.1.keys().cloned()).collect();
    for (idx, r) in replicas.iter().enumerate() {
        for v in r.2.keys() {
            assert!(
                !nullified.contains(v),
                "Invariant violation: replica {idx} finalized view {v} which is nullified"
            );
        }
    }

    // Invariant: finalization_requires_notarization
    // Any finalization must be backed by some notarization for the same (view, payload).
    let notarized: HashSet<(u64, Sha256Digest)> = replicas
        .iter()
        .flat_map(|r| r.0.iter().map(|(&v, d)| (v, d.payload)))
        .collect();
    for r in replicas.iter() {
        for (&v, d) in r.2.iter() {
            assert!(
                notarized.contains(&(v, d.payload)),
                "Invariant violation: finalization without notarization: view {v}, payload={:?}",
                d.payload
            );
        }
    }

    // Enforce per-replica invariants
    for r in replicas.iter() {
        // Invariant: certificates_are_valid
        // Certificates have the correct number of signatures.
        for (view, data) in r.1.iter() {
            if <P::Scheme as CertificateScheme>::is_attributable() {
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

        for (view, data) in r.0.iter() {
            if <P::Scheme as CertificateScheme>::is_attributable() {
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

        for (view, data) in r.2.iter() {
            if <P::Scheme as CertificateScheme>::is_attributable() {
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
        for view in r.1.keys() {
            assert!(
                !r.2.contains_key(view),
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
    reporters: &[Reporter<E, S, L, Sha256Digest>],
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
            let notarization_data = extract_notarizations::<S>(reporter, max_participants);
            let nullification_data = extract_nullifications::<S>(reporter, max_participants);
            let finalization_data = extract_finalizations::<S>(reporter, max_participants);
            (notarization_data, nullification_data, finalization_data)
        })
        .collect()
}

/// Extract replayed state including individual votes (for replayer comparison).
pub fn extract_replayed<E, S, L>(
    reporters: &[Reporter<E, S, L, Sha256Digest>],
    max_participants: usize,
) -> Vec<ReplayedReplicaState>
where
    E: CryptoRngCore,
    S: Scheme<Sha256Digest>,
    L: Elector<S>,
{
    reporters
        .iter()
        .map(|reporter| ReplayedReplicaState {
            notarizations: extract_notarizations::<S>(reporter, max_participants),
            nullifications: extract_nullifications::<S>(reporter, max_participants),
            finalizations: extract_finalizations::<S>(reporter, max_participants),
            certified: reporter.certified.lock().iter().map(|v| v.get()).collect(),
            notarize_signers: extract_notarize_signers(reporter),
            nullify_signers: extract_nullify_signers(reporter),
            finalize_signers: extract_finalize_signers(reporter),
        })
        .collect()
}

fn extract_notarizations<S: Scheme<Sha256Digest>>(
    reporter: &Reporter<impl CryptoRngCore, S, impl Elector<S>, Sha256Digest>,
    max_participants: usize,
) -> HashMap<u64, Notarization> {
    let notarizations = reporter.notarizations.lock();
    notarizations
        .iter()
        .map(|(view, cert)| {
            (
                view.get(),
                Notarization {
                    payload: cert.proposal.payload,
                    signature_count: get_signature_count::<S>(&cert.certificate, max_participants),
                },
            )
        })
        .collect()
}

fn extract_nullifications<S: Scheme<Sha256Digest>>(
    reporter: &Reporter<impl CryptoRngCore, S, impl Elector<S>, Sha256Digest>,
    max_participants: usize,
) -> HashMap<u64, Nullification> {
    let nullifications = reporter.nullifications.lock();
    nullifications
        .iter()
        .map(|(view, cert)| {
            (
                view.get(),
                Nullification {
                    signature_count: get_signature_count::<S>(&cert.certificate, max_participants),
                },
            )
        })
        .collect()
}

fn extract_finalizations<S: Scheme<Sha256Digest>>(
    reporter: &Reporter<impl CryptoRngCore, S, impl Elector<S>, Sha256Digest>,
    max_participants: usize,
) -> HashMap<u64, Finalization> {
    let finalizations = reporter.finalizations.lock();
    finalizations
        .iter()
        .map(|(view, cert)| {
            (
                view.get(),
                Finalization {
                    payload: cert.proposal.payload,
                    signature_count: get_signature_count::<S>(&cert.certificate, max_participants),
                },
            )
        })
        .collect()
}

fn pk_to_node_id<S: Scheme<Sha256Digest>>(
    participants: &commonware_utils::ordered::Set<S::PublicKey>,
    pk: &S::PublicKey,
) -> String {
    let idx = participants
        .iter()
        .position(|p| p == pk)
        .expect("public key not in participants");
    format!("n{idx}")
}

fn extract_notarize_signers<S: Scheme<Sha256Digest>>(
    reporter: &Reporter<impl CryptoRngCore, S, impl Elector<S>, Sha256Digest>,
) -> HashMap<u64, BTreeSet<String>> {
    let notarizes = reporter.notarizes.lock();
    let mut result = HashMap::new();
    for (view, payload_map) in notarizes.iter() {
        let mut signers = BTreeSet::new();
        for pks in payload_map.values() {
            for pk in pks {
                signers.insert(pk_to_node_id::<S>(&reporter.participants, pk));
            }
        }
        result.insert(view.get(), signers);
    }
    result
}

fn extract_nullify_signers<S: Scheme<Sha256Digest>>(
    reporter: &Reporter<impl CryptoRngCore, S, impl Elector<S>, Sha256Digest>,
) -> HashMap<u64, BTreeSet<String>> {
    let nullifies = reporter.nullifies.lock();
    let mut result = HashMap::new();
    for (view, pks) in nullifies.iter() {
        let signers = pks
            .iter()
            .map(|pk| pk_to_node_id::<S>(&reporter.participants, pk))
            .collect();
        result.insert(view.get(), signers);
    }
    result
}

fn extract_finalize_signers<S: Scheme<Sha256Digest>>(
    reporter: &Reporter<impl CryptoRngCore, S, impl Elector<S>, Sha256Digest>,
) -> HashMap<u64, BTreeSet<String>> {
    let finalizes = reporter.finalizes.lock();
    let mut result = HashMap::new();
    for (view, payload_map) in finalizes.iter() {
        let mut signers = BTreeSet::new();
        for pks in payload_map.values() {
            for pk in pks {
                signers.insert(pk_to_node_id::<S>(&reporter.participants, pk));
            }
        }
        result.insert(view.get(), signers);
    }
    result
}
