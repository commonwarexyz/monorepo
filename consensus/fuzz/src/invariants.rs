use crate::{
    bounds,
    simplex::Simplex,
    types::{Finalization, Notarization, Nullification, ReplicaState},
};
use commonware_codec::{Encode, Read};
use commonware_consensus::simplex::{
    elector::Config as Elector, mocks::reporter::Reporter, scheme, scheme::Scheme, types::Activity,
};
use commonware_cryptography::{
    certificate::{self, Signers},
    sha256::Digest as Sha256Digest,
};
use commonware_utils::ordered::Quorum;
use rand_core::CryptoRng;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    hash::Hash,
};

pub fn check<P: Simplex>(n: u32, replicas: Vec<ReplicaState>) {
    let threshold = bounds::quorum(n) as usize;

    // Invariant: agreement
    // All replicas that finalized a given view must have the same proposal
    // (parent, payload) for that view.
    let all_views: HashSet<u64> = replicas
        .iter()
        .flat_map(|(_, _, finalizations)| finalizations.keys().cloned())
        .collect();
    for view in all_views {
        let finalizations_for_view: Vec<(usize, (u64, Sha256Digest))> = replicas
            .iter()
            .enumerate()
            .filter_map(|(idx, (_, _, finalizations))| {
                finalizations
                    .get(&view)
                    .map(|d| (idx, (d.parent, d.payload)))
            })
            .collect();

        if let Some((first_idx, first_proposal)) = finalizations_for_view.first() {
            for (idx, proposal) in &finalizations_for_view[1..] {
                assert_eq!(
                    proposal, first_proposal,
                    "Invariant violation: finalized proposal mismatch in view {view}: replica {idx} has {proposal:?} but replica {first_idx} has {first_proposal:?}",
                );
            }
        }
    }

    // Invariant: no_nullification_in_finalized_view
    // If any replica finalized view v, no replica may have a nullification for view v.
    let finalized_views: HashMap<u64, (u64, Sha256Digest)> = replicas
        .iter()
        .flat_map(|(_, _, finalizations)| {
            finalizations
                .iter()
                .map(|(&view, d)| (view, (d.parent, d.payload)))
        })
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
    // If any replica finalized view v for a proposal, no replica may have a
    // notarization for a different proposal (parent, payload).
    for (idx, (notarizations, _, _)) in replicas.iter().enumerate() {
        for (&view, data) in notarizations.iter() {
            if let Some(&finalized_proposal) = finalized_views.get(&view) {
                assert_eq!(
                    finalized_proposal,
                    (data.parent, data.payload),
                    "Invariant violation: replica {idx} notarized view {view} with {:?} but finalized with {finalized_proposal:?}",
                    (data.parent, data.payload)
                );
            }
        }
    }

    // Invariant: no_conflicting_quorum_notarizations
    // In any view, there cannot be quorum notarizations for multiple proposals.
    // Proposal identity is (parent, payload); duplicate certificates for the
    // same (view, parent, payload) are intentionally equivalent here.
    // Reporter extraction retains one certificate per reporter/view, so
    // same-reporter conflicts overwritten before extraction remain invisible.
    let mut per_view: HashMap<u64, HashSet<(u64, Sha256Digest)>> = HashMap::new();
    for (notarizations, _, _) in replicas.iter() {
        for (v, d) in notarizations {
            let is_quorum = d.signature_count.is_none_or(|c| c >= threshold);
            if is_quorum {
                per_view
                    .entry(*v)
                    .or_default()
                    .insert((d.parent, d.payload));
            }
        }
    }
    for (v, proposals) in per_view {
        assert!(
            proposals.len() <= 1,
            "Invariant violation: conflicting quorum notarizations in view {v}: {proposals:?}"
        );
    }

    // Invariant: no_conflicting_quorum_finalizations
    // In any view, there cannot be quorum finalizations for multiple proposals.
    // Proposal identity is (parent, payload); duplicate certificates for the
    // same (view, parent, payload) are intentionally equivalent here.
    // Reporter extraction retains one certificate per reporter/view, so
    // same-reporter conflicts overwritten before extraction remain invisible.
    let mut per_view: HashMap<u64, HashSet<(u64, Sha256Digest)>> = HashMap::new();
    for (_, _, finalizations) in replicas.iter() {
        for (v, d) in finalizations {
            let is_quorum = d.signature_count.is_none_or(|c| c >= threshold);
            if is_quorum {
                per_view
                    .entry(*v)
                    .or_default()
                    .insert((d.parent, d.payload));
            }
        }
    }
    for (v, proposals) in per_view {
        assert!(
            proposals.len() <= 1,
            "Invariant violation: conflicting quorum finalizations in view {v}: {proposals:?}"
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
    // Any finalization must be backed by some notarization for the same
    // (view, parent, payload).
    let notarized: HashSet<(u64, u64, Sha256Digest)> = replicas
        .iter()
        .flat_map(|(notarizations, _, _)| {
            notarizations.iter().map(|(&v, d)| (v, d.parent, d.payload))
        })
        .collect();
    for (_, _, finalizations) in replicas.iter() {
        for (&v, d) in finalizations.iter() {
            assert!(
                notarized.contains(&(v, d.parent, d.payload)),
                "Invariant violation: finalization without notarization: view {v}, parent={}, payload={:?}",
                d.parent,
                d.payload
            );
        }
    }

    // Invariant: chain_consistency
    // A certificate at view v with parent p implies every view in (p, v) was
    // nullified, so none of them may be finalized. This validates recorded
    // parent links only (consistency of the extracted certificate graph);
    // ancestry whose intermediate certificates were never reported is not
    // reconstructed.
    let finalized_ordered: BTreeSet<u64> = finalized_views.keys().copied().collect();
    for (idx, (notarizations, _, finalizations)) in replicas.iter().enumerate() {
        let links = notarizations
            .iter()
            .map(|(&v, d)| (v, d.parent, "notarization"))
            .chain(
                finalizations
                    .iter()
                    .map(|(&v, d)| (v, d.parent, "finalization")),
            );
        for (view, parent, kind) in links {
            assert!(
                parent < view,
                "Invariant violation: replica {idx} has {kind} in view {view} with parent {parent}"
            );
            if let Some(skipped) = finalized_ordered.range(parent + 1..view).next() {
                panic!(
                    "Invariant violation: replica {idx} has {kind} in view {view} with parent {parent} skipping finalized view {skipped}"
                );
            }
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

/// Checks invariants that require per-signer information (votes and fault
/// evidence). `faults` is the number of Byzantine nodes by participant index
/// (`0..faults`); only correct nodes (`faults..n`) are checked for equivocation.
pub fn check_vote_invariants<E, S, L>(faults: usize, reporters: &[Reporter<E, S, L, Sha256Digest>])
where
    E: CryptoRng,
    S: Scheme<Sha256Digest>,
    S::PublicKey: Eq + Hash + Clone,
    L: Elector<S>,
{
    let byzantine: HashSet<usize> = (0..faults).collect();
    check_vote_invariants_with_byzantine(&byzantine, reporters);
}

pub fn check_no_invalid_reports<E, S, L>(reporters: &[Reporter<E, S, L, Sha256Digest>])
where
    E: CryptoRng,
    S: Scheme<Sha256Digest>,
    L: Elector<S>,
{
    for reporter in reporters {
        reporter.assert_no_invalid();
    }
}

pub fn check_no_invalid_reports_if_no_faults<E, S, L>(
    faults: u32,
    reporters: &[Reporter<E, S, L, Sha256Digest>],
) where
    E: CryptoRng,
    S: Scheme<Sha256Digest>,
    L: Elector<S>,
{
    if faults == 0 {
        check_no_invalid_reports(reporters);
    }
}

/// Like [`check_vote_invariants`], but accepts an explicit set of Byzantine
/// participant indices instead of assuming a positional `0..faults` prefix.
///
/// Used by twins-style harnesses where the compromised set is sampled by the
/// scenario generator and may occupy arbitrary indices.
pub fn check_vote_invariants_with_byzantine<E, S, L>(
    byzantine: &HashSet<usize>,
    reporters: &[Reporter<E, S, L, Sha256Digest>],
) where
    E: CryptoRng,
    S: Scheme<Sha256Digest>,
    S::PublicKey: Eq + Hash + Clone,
    L: Elector<S>,
{
    // Invariant: no_fault_evidence_against_correct_signers
    // Fault proofs (ConflictingNotarize, ConflictingFinalize, NullifyFinalize)
    // are signature-verified by the reporter before being recorded, so evidence
    // against a correct signer proves that key signed conflicting messages: an
    // engine bug (e.g. mishandled WAL state on restart), not adversarial noise.
    // Byzantine signers are expected to equivocate and are excluded. Evidence
    // against a key outside the participant set is flagged rather than skipped.
    //
    // This complements no_vote_equivocation below: fault proofs catch conflicts
    // even when one side never reached quorum verification (and thus never
    // entered the vote maps), while vote aggregation catches conflicts no
    // single batcher observed.
    for reporter in reporters {
        let faults = reporter.faults.lock();
        let mut offenders: Vec<_> = faults
            .iter()
            .filter(|&(pk, _)| {
                reporter
                    .participants
                    .index(pk)
                    .is_none_or(|idx| !byzantine.contains(&usize::from(idx)))
            })
            .map(|(pk, by_view)| {
                let mut views: Vec<u64> = by_view.keys().map(|view| view.get()).collect();
                views.sort_unstable();
                let kinds: BTreeSet<&'static str> = by_view
                    .values()
                    .flatten()
                    .map(|activity| match activity {
                        Activity::ConflictingNotarize(_) => "conflicting_notarize",
                        Activity::ConflictingFinalize(_) => "conflicting_finalize",
                        Activity::NullifyFinalize(_) => "nullify_finalize",
                        _ => "unexpected",
                    })
                    .collect();
                (pk.as_ref().to_vec(), views, kinds)
            })
            .collect();
        offenders.sort_unstable();
        assert!(
            offenders.is_empty(),
            "Invariant violation: fault evidence against correct signers: {offenders:?}",
        );
    }

    // Invariant: no_vote_equivocation
    // A correct node cannot sign multiple payloads of the same vote kind in a
    // view, or both nullify and finalize in the same view.
    // Aggregate across all reporters to get a global view of who sent what.
    let mut seen_nullify: HashMap<u64, HashSet<S::PublicKey>> = HashMap::new();
    let mut seen_finalize: HashMap<u64, HashSet<S::PublicKey>> = HashMap::new();
    let mut seen_notarize_payload: HashMap<(u64, S::PublicKey), Sha256Digest> = HashMap::new();
    let mut seen_finalize_payload: HashMap<(u64, S::PublicKey), Sha256Digest> = HashMap::new();
    for reporter in reporters {
        let notarizes = reporter.notarizes.lock();
        for (view, by_digest) in notarizes.iter() {
            for (digest, signers) in by_digest {
                for pk in signers {
                    if reporter
                        .participants
                        .index(pk)
                        .is_some_and(|idx| !byzantine.contains(&usize::from(idx)))
                    {
                        let previous =
                            seen_notarize_payload.insert((view.get(), pk.clone()), *digest);
                        assert!(
                            previous.is_none_or(|payload| payload == *digest),
                            "Invariant violation: correct signer notarized multiple payloads in view {}",
                            view.get()
                        );
                    }
                }
            }
        }
        drop(notarizes);

        let nullifies = reporter.nullifies.lock();
        for (view, signers) in nullifies.iter() {
            let entry = seen_nullify.entry(view.get()).or_default();
            for pk in signers {
                if reporter
                    .participants
                    .index(pk)
                    .is_some_and(|idx| !byzantine.contains(&usize::from(idx)))
                {
                    entry.insert(pk.clone());
                }
            }
        }
        drop(nullifies);

        // Also collapse across digests to track whether this signer finalized
        // anything in this view.
        let finalizes = reporter.finalizes.lock();
        for (view, by_digest) in finalizes.iter() {
            let entry = seen_finalize.entry(view.get()).or_default();
            for (digest, signers) in by_digest {
                for pk in signers {
                    if reporter
                        .participants
                        .index(pk)
                        .is_some_and(|idx| !byzantine.contains(&usize::from(idx)))
                    {
                        entry.insert(pk.clone());
                        let previous =
                            seen_finalize_payload.insert((view.get(), pk.clone()), *digest);
                        assert!(
                            previous.is_none_or(|payload| payload == *digest),
                            "Invariant violation: correct signer finalized multiple payloads in view {}",
                            view.get()
                        );
                    }
                }
            }
        }
        drop(finalizes);
    }
    for (v, nullifiers) in &seen_nullify {
        if let Some(finalizers) = seen_finalize.get(v) {
            let equivocators: Vec<_> = nullifiers
                .intersection(finalizers)
                .map(|pk| pk.as_ref().to_vec())
                .collect();
            assert!(
                equivocators.is_empty(),
                "Invariant violation: vote equivocation in view {v}: {equivocators:?} both nullified and finalized",
            );
        }
    }
}

pub(crate) fn get_signature_count<S: scheme::Scheme<Sha256Digest>>(
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
                            parent: cert.proposal.parent.get(),
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
