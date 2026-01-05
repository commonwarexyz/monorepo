use crate::{
    simplex::{
        Simplex, SimplexBls12381MultisigMinPk, SimplexBls12381MultisigMinSig, SimplexEd25519,
    },
    types::{Finalization, Notarization, Nullification, ReplicaState},
};
use commonware_consensus::simplex::{
    elector::Config as Elector, mocks::reporter::Reporter, scheme, scheme::Scheme,
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    sha256::Digest as Sha256Digest,
};
use commonware_utils::quorum;
use rand_core::CryptoRngCore;
use std::{
    any::TypeId,
    collections::{HashMap, HashSet},
};

pub fn check<P: Simplex>(n: u32, replicas: Vec<ReplicaState>) {
    let threshold = quorum(n) as usize;

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
    // If any replica finalized view v, no replica may have nullification for view v.
    let finalized_views: HashMap<u64, Sha256Digest> = replicas
        .iter()
        .flat_map(|(_, _, finalizations)| finalizations.iter().map(|(&view, d)| (view, d.payload)))
        .collect();

    for finalized_view in finalized_views.keys() {
        for (idx, (_, nullifications, _)) in replicas.iter().enumerate() {
            assert!(
                !nullifications.contains_key(finalized_view),
                "Invariant violation: replica {idx} nullified view {finalized_view} but it is finalized",
            );
        }
    }

    // Invariant: no_conflicting_notarization_in_finalized_view
    // If any replica finalized view v for a digest, no replica may have notarization for a different digest.
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
    // If any replica nullified view v, no replica may finalize v.
    let nullified: HashSet<u64> = replicas
        .iter()
        .flat_map(|(_, nulls, _)| nulls.keys().cloned())
        .collect();
    for (idx, (_, _, finals)) in replicas.iter().enumerate() {
        for v in finals.keys() {
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
            if is_attributable_scheme::<P>() {
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
            if is_attributable_scheme::<P>() {
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
            if is_attributable_scheme::<P>() {
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

fn is_attributable_scheme<P: Simplex>() -> bool {
    let type_id = TypeId::of::<P>();
    type_id == TypeId::of::<SimplexEd25519>()
        || type_id == TypeId::of::<SimplexBls12381MultisigMinPk>()
        || type_id == TypeId::of::<SimplexBls12381MultisigMinSig>()
}

fn get_signature_count<S: scheme::Scheme<Sha256Digest>>(
    certificate: &S::Certificate,
) -> Option<usize> {
    use commonware_cryptography::{bls12381::certificate, ed25519};

    let type_id = TypeId::of::<S::Certificate>();

    match type_id {
        t if t == TypeId::of::<ed25519::certificate::Certificate>() => {
            let cert = unsafe {
                &*(certificate as *const S::Certificate as *const ed25519::certificate::Certificate)
            };
            Some(cert.signatures.len())
        }
        t if t == TypeId::of::<certificate::multisig::Certificate<MinPk>>() => {
            let cert = unsafe {
                &*(certificate as *const S::Certificate
                    as *const certificate::multisig::Certificate<MinPk>)
            };
            Some(cert.signers.count())
        }
        t if t == TypeId::of::<certificate::multisig::Certificate<MinSig>>() => {
            let cert = unsafe {
                &*(certificate as *const S::Certificate
                    as *const certificate::multisig::Certificate<MinSig>)
            };
            Some(cert.signers.count())
        }
        _ => None,
    }
}

pub fn extract<E, S, L>(reporters: Vec<Reporter<E, S, L, Sha256Digest>>) -> Vec<ReplicaState>
where
    E: CryptoRngCore,
    S: Scheme<Sha256Digest>,
    L: Elector<S>,
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
                            signature_count: get_signature_count::<S>(&cert.certificate),
                        },
                    )
                })
                .collect();

            let nullifications = reporter.nullifications.lock().unwrap();
            let nullification_data = nullifications
                .iter()
                .map(|(view, cert)| {
                    (
                        view.get(),
                        Nullification {
                            signature_count: get_signature_count::<S>(&cert.certificate),
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
                            signature_count: get_signature_count::<S>(&cert.certificate),
                        },
                    )
                })
                .collect();

            (notarization_data, nullification_data, finalization_data)
        })
        .collect()
}
