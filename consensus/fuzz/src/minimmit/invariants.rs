use super::Minimmit;
use commonware_codec::{Encode, Read};
use commonware_consensus::{
    elector::Config as Elector,
    minimmit::{mocks::reporter::Reporter, scheme, scheme::Scheme},
};
use commonware_cryptography::{
    certificate::{Scheme as CertificateScheme, Signers},
    sha256::Digest as Sha256Digest,
};
use commonware_utils::{Faults, M5f1, N5f1};
use rand_core::CryptoRngCore;
use std::collections::{HashMap, HashSet};

pub struct MNotarizationData {
    pub payload: Sha256Digest,
    pub signature_count: Option<usize>,
}

pub struct NullificationData {
    pub signature_count: Option<usize>,
}

pub struct FinalizationData {
    pub payload: Sha256Digest,
    pub signature_count: Option<usize>,
}

/// Per-replica state: (m_notarizations, nullifications, finalizations) keyed by view.
pub type MinimmitReplicaState = (
    HashMap<u64, MNotarizationData>,
    HashMap<u64, NullificationData>,
    HashMap<u64, FinalizationData>,
);

pub fn check<P: Minimmit>(n: u32, replicas: Vec<MinimmitReplicaState>) {
    let m_quorum = M5f1::quorum(n) as usize;
    let l_quorum = N5f1::quorum(n) as usize;

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
    // If any replica finalized view v, no replica may have a nullification for view v.
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

    // Invariant: no_conflicting_m_notarization_in_finalized_view
    // If any replica finalized view v for a digest, no replica may have an M-notarization for a different digest.
    for (idx, (m_notarizations, _, _)) in replicas.iter().enumerate() {
        for (&view, data) in m_notarizations.iter() {
            if let Some(&finalized_digest) = finalized_views.get(&view) {
                assert_eq!(
                    finalized_digest, data.payload,
                    "Invariant violation: replica {idx} M-notarized view {view} with {:?} but finalized with {finalized_digest:?}",
                    data.payload
                );
            }
        }
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

    // Invariant: finalization_requires_m_notarization
    // Any finalization must be backed by some M-notarization for the same (view, payload).
    let m_notarized: HashSet<(u64, Sha256Digest)> = replicas
        .iter()
        .flat_map(|(m_notarizations, _, _)| m_notarizations.iter().map(|(&v, d)| (v, d.payload)))
        .collect();
    for (_, _, finalizations) in replicas.iter() {
        for (&v, d) in finalizations.iter() {
            assert!(
                m_notarized.contains(&(v, d.payload)),
                "Invariant violation: finalization without M-notarization: view {v}, payload={:?}",
                d.payload
            );
        }
    }

    // Enforce per-replica invariants
    for (m_notarizations, nullifications, finalizations) in replicas.iter() {
        // Invariant: certificates_are_valid
        // M-notarization certificates have >= M-quorum (2f+1) signatures.
        for (view, data) in m_notarizations.iter() {
            if <P::Scheme as CertificateScheme>::is_attributable() {
                let count = data
                    .signature_count
                    .expect("Attributable scheme must have signature count");
                assert!(
                    count >= m_quorum,
                    "Invariant violation: M-notarization in view {view} has {count} < {m_quorum} signatures"
                );
            } else {
                assert!(
                    data.signature_count.is_none(),
                    "Invariant violation: non-attributable scheme should not expose signature count"
                );
            }
        }

        // Nullification certificates have >= M-quorum (2f+1) signatures.
        for (view, data) in nullifications.iter() {
            if <P::Scheme as CertificateScheme>::is_attributable() {
                let count = data
                    .signature_count
                    .expect("Attributable scheme must have signature count");
                assert!(
                    count >= m_quorum,
                    "Invariant violation: nullification in view {view} has {count} < {m_quorum} signatures"
                );
            } else {
                assert!(
                    data.signature_count.is_none(),
                    "Invariant violation: non-attributable scheme should not expose signature count"
                );
            }
        }

        // Finalization certificates have >= L-quorum (n-f) signatures.
        for (view, data) in finalizations.iter() {
            if <P::Scheme as CertificateScheme>::is_attributable() {
                let count = data
                    .signature_count
                    .expect("Attributable scheme must have signature count");
                assert!(
                    count >= l_quorum,
                    "Invariant violation: finalization in view {view} has {count} < {l_quorum} signatures"
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
) -> Vec<MinimmitReplicaState>
where
    E: CryptoRngCore,
    S: Scheme<Sha256Digest>,
    L: Elector<S>,
{
    reporters
        .iter()
        .map(|reporter| {
            let m_notarizations = reporter.m_notarizations.lock();
            let m_notarization_data = m_notarizations
                .iter()
                .map(|(view, cert)| {
                    (
                        view.get(),
                        MNotarizationData {
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
                        NullificationData {
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
                        FinalizationData {
                            payload: cert.proposal.payload,
                            signature_count: get_signature_count::<S>(
                                &cert.certificate,
                                max_participants,
                            ),
                        },
                    )
                })
                .collect();

            (m_notarization_data, nullification_data, finalization_data)
        })
        .collect()
}
