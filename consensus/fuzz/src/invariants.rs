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
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, btree_map::Entry},
    hash::Hash,
};

pub fn check<P: Simplex>(n: u32, replicas: Vec<ReplicaState>) {
    let threshold = bounds::quorum(n) as usize;
    let attributable = <P::Scheme as certificate::Scheme>::is_attributable();

    // Invariant: certificates_are_valid
    // Attributable certificates carry between quorum and n signatures;
    // non-attributable schemes expose no count (a valid threshold certificate
    // implies quorum).
    let participants = n as usize;
    let check_count = |kind: &str, view: u64, signature_count: Option<usize>| {
        if attributable {
            let count = signature_count.expect("Attributable scheme must have signature count");
            assert!(
                count >= threshold,
                "Invariant violation: {kind} in view {view} has {count} < {threshold} signatures"
            );
            assert!(
                count <= participants,
                "Invariant violation: {kind} in view {view} has {count} signatures for {participants} participants"
            );
        } else {
            assert!(
                signature_count.is_none(),
                "Invariant violation: non-attributable scheme should not expose signature count"
            );
        }
    };

    // Normalization pass: fold every replica's certificates into global
    // view-indexed maps, checking certificate validity and per-view proposal
    // uniqueness at insert time. Validity runs first, so every recorded
    // certificate is quorum-backed and uniqueness needs no quorum filter.
    // Values retain the first recording replica for diagnostics; proposal
    // identity is (parent, payload). Duplicate certificates for the same
    // (view, parent, payload) are intentionally equivalent; the reporter
    // retains one certificate per view, so same-reporter conflicts
    // overwritten before extraction remain invisible.
    //
    // Invariant: agreement / no_conflicting_quorum_notarizations /
    // no_conflicting_quorum_finalizations
    // All replicas must agree on one proposal per notarized or finalized view.
    type Identity = (u64, Sha256Digest);
    let mut notarized: BTreeMap<u64, (usize, Identity)> = BTreeMap::new();
    let mut nullified: BTreeMap<u64, usize> = BTreeMap::new();
    let mut finalized: BTreeMap<u64, (usize, Identity)> = BTreeMap::new();
    for (idx, (notarizations, nullifications, finalizations)) in replicas.iter().enumerate() {
        for (&view, d) in notarizations.iter() {
            check_count("notarization", view, d.signature_count);
            let proposal = (d.parent, d.payload);
            match notarized.entry(view) {
                Entry::Vacant(entry) => {
                    entry.insert((idx, proposal));
                }
                Entry::Occupied(entry) => {
                    let &(first_idx, first_proposal) = entry.get();
                    assert_eq!(
                        proposal, first_proposal,
                        "Invariant violation: conflicting quorum notarizations in view {view}: replica {idx} has {proposal:?} but replica {first_idx} has {first_proposal:?}",
                    );
                }
            }
        }
        for (&view, d) in nullifications.iter() {
            check_count("nullification", view, d.signature_count);
            nullified.entry(view).or_insert(idx);
        }
        for (&view, d) in finalizations.iter() {
            check_count("finalization", view, d.signature_count);
            let proposal = (d.parent, d.payload);
            match finalized.entry(view) {
                Entry::Vacant(entry) => {
                    entry.insert((idx, proposal));
                }
                Entry::Occupied(entry) => {
                    let &(first_idx, first_proposal) = entry.get();
                    assert_eq!(
                        proposal, first_proposal,
                        "Invariant violation: finalized proposal mismatch in view {view}: replica {idx} has {proposal:?} but replica {first_idx} has {first_proposal:?}",
                    );
                }
            }
        }
    }

    // Invariant: no_finalized_view_nullified
    // A view cannot carry both a finalization and a nullification certificate,
    // regardless of which replicas recorded them.
    for (&view, &(fin_idx, _)) in finalized.iter() {
        if let Some(&null_idx) = nullified.get(&view) {
            panic!(
                "Invariant violation: view {view} finalized by replica {fin_idx} and nullified by replica {null_idx}"
            );
        }
    }

    // Invariant: finalization_requires_notarization
    // Any finalization must be backed by a notarization with the same
    // (parent, payload); combined with per-view uniqueness above this also
    // forbids any notarization conflicting with a finalized proposal.
    for (&view, &(idx, proposal)) in finalized.iter() {
        let notarized_proposal = notarized.get(&view).map(|&(_, p)| p);
        assert!(
            notarized_proposal == Some(proposal),
            "Invariant violation: finalization without matching notarization in view {view}: replica {idx} finalized {proposal:?} but notarized is {notarized_proposal:?}"
        );
    }

    // Invariant: chain_consistency
    // A certificate at view v with parent p requires a certified parent (a
    // notarization or finalization at p; genesis needs no certificate) and a
    // nullification for every view in (p, v), so none of them may be
    // finalized (the skipped-finalization scan is implied by the previous two
    // checks but retained for its sharper diagnostic). Any quorum contains at
    // least one honest voter whose reporter is in the checked set and that
    // recorded and reported exactly these certificates before voting, so the
    // union must contain them. This validates recorded parent links only
    // (consistency of the extracted certificate graph); ancestry whose
    // intermediate certificates were never reported is not reconstructed.
    // Comparing unevenly-progressed replicas (e.g. a frozen crash-stopped
    // reporter against live ones) is sound: skipped intervals are permanently
    // nullified by construction, so a finalization observed later by another
    // replica can only reveal a real violation, never create a spurious one.
    // Only notarized links are walked: finalization_requires_notarization has
    // already forced every finalized view onto an identical notarized link.
    for (&view, &(idx, (parent, _))) in notarized.iter() {
        assert!(
            parent < view,
            "Invariant violation: replica {idx} has notarization in view {view} with parent {parent}"
        );
        if let Some((skipped, _)) = finalized.range(parent + 1..view).next() {
            panic!(
                "Invariant violation: replica {idx} has notarization in view {view} with parent {parent} skipping finalized view {skipped}"
            );
        }
        assert!(
            parent == 0 || notarized.contains_key(&parent) || finalized.contains_key(&parent),
            "Invariant violation: replica {idx} has notarization in view {view} with uncertified parent {parent}"
        );
        // Walk the recorded nullifications in (parent, view) expecting
        // consecutive keys; the first gap is the missing view.
        let mut expected = parent + 1;
        for (&w, _) in nullified.range(parent + 1..view) {
            if w != expected {
                break;
            }
            expected += 1;
        }
        assert!(
            expected == view,
            "Invariant violation: replica {idx} has notarization in view {view} with parent {parent} but view {expected} has no nullification"
        );
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
    // Reporter maps are hash-based, so conflicts are accumulated in raw
    // iteration order (recording every conflicting payload against a
    // first-seen pivot, which makes the union order-independent) and reported
    // from ordered collections after the sweep: diagnostics stay deterministic
    // without allocating or sorting under the locks.
    let mut seen_nullify: BTreeMap<u64, HashSet<S::PublicKey>> = BTreeMap::new();
    let mut seen_finalize: BTreeMap<u64, HashSet<S::PublicKey>> = BTreeMap::new();
    let mut seen_notarize_payload: HashMap<(u64, S::PublicKey), Sha256Digest> = HashMap::new();
    let mut seen_finalize_payload: HashMap<(u64, S::PublicKey), Sha256Digest> = HashMap::new();
    let mut notarize_conflicts: BTreeMap<(u64, Vec<u8>), BTreeSet<Sha256Digest>> = BTreeMap::new();
    let mut finalize_conflicts: BTreeMap<(u64, Vec<u8>), BTreeSet<Sha256Digest>> = BTreeMap::new();
    for reporter in reporters {
        let correct = |pk: &S::PublicKey| {
            reporter
                .participants
                .index(pk)
                .is_some_and(|idx| !byzantine.contains(&usize::from(idx)))
        };

        let notarizes = reporter.notarizes.lock();
        for (view, by_digest) in notarizes.iter() {
            for (digest, signers) in by_digest {
                for pk in signers {
                    if !correct(pk) {
                        continue;
                    }
                    let pivot = *seen_notarize_payload
                        .entry((view.get(), pk.clone()))
                        .or_insert(*digest);
                    if pivot != *digest {
                        notarize_conflicts
                            .entry((view.get(), pk.as_ref().to_vec()))
                            .or_default()
                            .extend([pivot, *digest]);
                    }
                }
            }
        }
        drop(notarizes);

        let nullifies = reporter.nullifies.lock();
        for (view, signers) in nullifies.iter() {
            for pk in signers {
                if correct(pk) {
                    seen_nullify
                        .entry(view.get())
                        .or_default()
                        .insert(pk.clone());
                }
            }
        }
        drop(nullifies);

        // Also collapse across digests to track whether this signer finalized
        // anything in this view.
        let finalizes = reporter.finalizes.lock();
        for (view, by_digest) in finalizes.iter() {
            for (digest, signers) in by_digest {
                for pk in signers {
                    if !correct(pk) {
                        continue;
                    }
                    seen_finalize
                        .entry(view.get())
                        .or_default()
                        .insert(pk.clone());
                    let pivot = *seen_finalize_payload
                        .entry((view.get(), pk.clone()))
                        .or_insert(*digest);
                    if pivot != *digest {
                        finalize_conflicts
                            .entry((view.get(), pk.as_ref().to_vec()))
                            .or_default()
                            .extend([pivot, *digest]);
                    }
                }
            }
        }
        drop(finalizes);
    }
    if let Some(((view, signer), payloads)) = notarize_conflicts.first_key_value() {
        panic!(
            "Invariant violation: correct signer notarized multiple payloads in view {view}: signer {signer:?} signed {payloads:?}; all conflicts: {notarize_conflicts:?}"
        );
    }
    if let Some(((view, signer), payloads)) = finalize_conflicts.first_key_value() {
        panic!(
            "Invariant violation: correct signer finalized multiple payloads in view {view}: signer {signer:?} signed {payloads:?}; all conflicts: {finalize_conflicts:?}"
        );
    }
    for (v, nullifiers) in &seen_nullify {
        if let Some(finalizers) = seen_finalize.get(v) {
            let mut equivocators: Vec<_> = nullifiers
                .intersection(finalizers)
                .map(|pk| pk.as_ref().to_vec())
                .collect();
            equivocators.sort_unstable();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        id_mock,
        simplex::{SimplexBls12381MinPk, SimplexId},
    };
    use commonware_consensus::{
        Reporter as _,
        simplex::{
            elector::RoundRobin,
            mocks::reporter::Config as ReporterConfig,
            types::{ConflictingNotarize, Finalize, Notarize, Nullify, Proposal},
        },
        types::{Epoch, Round, View},
    };
    use commonware_utils::{TestRng, ordered::Set, test_rng};
    use std::panic;

    const N: u32 = 4;
    const Q: usize = 3;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest([byte; 32])
    }

    fn notarization(parent: u64, payload: u8) -> Notarization {
        notarization_with(parent, payload, Some(Q))
    }

    fn notarization_with(parent: u64, payload: u8, signature_count: Option<usize>) -> Notarization {
        Notarization {
            payload: digest(payload),
            parent,
            signature_count,
        }
    }

    fn nullification() -> Nullification {
        nullification_with(Some(Q))
    }

    fn nullification_with(signature_count: Option<usize>) -> Nullification {
        Nullification { signature_count }
    }

    fn finalization(parent: u64, payload: u8) -> Finalization {
        finalization_with(parent, payload, Some(Q))
    }

    fn finalization_with(parent: u64, payload: u8, signature_count: Option<usize>) -> Finalization {
        Finalization {
            payload: digest(payload),
            parent,
            signature_count,
        }
    }

    fn replica(
        notarizations: BTreeMap<u64, Notarization>,
        nullifications: BTreeMap<u64, Nullification>,
        finalizations: BTreeMap<u64, Finalization>,
    ) -> ReplicaState {
        (notarizations, nullifications, finalizations)
    }

    fn views<T>(entries: Vec<(u64, T)>) -> BTreeMap<u64, T> {
        entries.into_iter().collect()
    }

    /// N1(parent=0, A), F1(parent=0, A), Null2, N3(parent=1, B).
    fn chain_replica() -> ReplicaState {
        replica(
            views(vec![(1, notarization(0, 0xA)), (3, notarization(1, 0xB))]),
            views(vec![(2, nullification())]),
            views(vec![(1, finalization(0, 0xA))]),
        )
    }

    #[test]
    fn valid_consolidated_chain_passes() {
        check::<SimplexId>(N, vec![chain_replica(), chain_replica()]);
    }

    #[test]
    fn identical_certificates_from_multiple_replicas_pass() {
        check::<SimplexId>(N, vec![chain_replica(), chain_replica(), chain_replica()]);
    }

    #[test]
    fn notarization_and_nullification_same_view_is_allowed() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA))]),
            views(vec![(1, nullification())]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "conflicting quorum notarizations in view 1")]
    fn conflicting_notarizations_are_rejected() {
        let r0 = replica(
            views(vec![(1, notarization(0, 0xA))]),
            views(vec![]),
            views(vec![]),
        );
        let r1 = replica(
            views(vec![(1, notarization(0, 0xB))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r0, r1]);
    }

    #[test]
    #[should_panic(expected = "finalized proposal mismatch in view 1")]
    fn conflicting_finalizations_are_rejected() {
        let r0 = replica(
            views(vec![]),
            views(vec![]),
            views(vec![(1, finalization(0, 0xA))]),
        );
        let r1 = replica(
            views(vec![]),
            views(vec![]),
            views(vec![(1, finalization(0, 0xB))]),
        );
        check::<SimplexId>(N, vec![r0, r1]);
    }

    #[test]
    #[should_panic(expected = "view 1 finalized by replica 0 and nullified by replica 1")]
    fn finalization_and_nullification_across_replicas_are_rejected() {
        let r0 = replica(
            views(vec![(1, notarization(0, 0xA))]),
            views(vec![]),
            views(vec![(1, finalization(0, 0xA))]),
        );
        let r1 = replica(
            views(vec![]),
            views(vec![(1, nullification())]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r0, r1]);
    }

    #[test]
    #[should_panic(expected = "finalization without matching notarization")]
    fn finalization_without_notarization_is_rejected() {
        let r = replica(
            views(vec![]),
            views(vec![]),
            views(vec![(1, finalization(0, 0xA))]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "finalization without matching notarization")]
    fn finalization_with_different_notarized_payload_is_rejected() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA))]),
            views(vec![]),
            views(vec![(1, finalization(0, 0xB))]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "finalization without matching notarization")]
    fn finalization_with_different_notarized_parent_is_rejected() {
        let r = replica(
            views(vec![(2, notarization(1, 0xA))]),
            views(vec![]),
            views(vec![(2, finalization(0, 0xA))]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "notarization in view 1 has 2 < 3 signatures")]
    fn duplicate_subquorum_certificate_is_not_hidden_by_deduplication() {
        let r0 = replica(
            views(vec![(1, notarization(0, 0xA))]),
            views(vec![]),
            views(vec![]),
        );
        let r1 = replica(
            views(vec![(1, notarization_with(0, 0xA, Some(2)))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r0, r1]);
    }

    #[test]
    #[should_panic(expected = "notarization in view 1 has 2 < 3 signatures")]
    fn subquorum_notarization_is_rejected() {
        let r = replica(
            views(vec![(1, notarization_with(0, 0xA, Some(2)))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "nullification in view 1 has 2 < 3 signatures")]
    fn subquorum_nullification_is_rejected() {
        let r = replica(
            views(vec![]),
            views(vec![(1, nullification_with(Some(2)))]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "finalization in view 1 has 2 < 3 signatures")]
    fn subquorum_finalization_is_rejected() {
        let r = replica(
            views(vec![]),
            views(vec![]),
            views(vec![(1, finalization_with(0, 0xA, Some(2)))]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "notarization in view 1 has 5 signatures for 4 participants")]
    fn overcounted_certificate_is_rejected() {
        let r = replica(
            views(vec![(1, notarization_with(0, 0xA, Some(5)))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "Attributable scheme must have signature count")]
    fn attributable_certificate_requires_signature_count() {
        let r = replica(
            views(vec![(1, notarization_with(0, 0xA, None))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    fn non_attributable_certificate_with_none_count_passes() {
        let r = replica(
            views(vec![(1, notarization_with(0, 0xA, None))]),
            views(vec![(2, nullification_with(None))]),
            views(vec![(1, finalization_with(0, 0xA, None))]),
        );
        check::<SimplexBls12381MinPk>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "non-attributable scheme should not expose signature count")]
    fn non_attributable_certificate_with_count_is_rejected() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexBls12381MinPk>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "in view 2 with parent 2")]
    fn parent_must_precede_child() {
        let r = replica(
            views(vec![(2, notarization(2, 0xA))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "in view 2 with parent 3")]
    fn parent_after_child_is_rejected() {
        let r = replica(
            views(vec![(2, notarization(3, 0xA))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "uncertified parent 1")]
    fn parent_must_be_certified() {
        let r = replica(
            views(vec![(2, notarization(1, 0xA))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "view 2 has no nullification")]
    fn every_skipped_view_must_be_nullified() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA)), (3, notarization(1, 0xB))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    fn complete_skipped_nullification_range_passes() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA)), (4, notarization(1, 0xB))]),
            views(vec![(2, nullification()), (3, nullification())]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "skipping finalized view 1")]
    fn skipped_finalization_uses_sharp_diagnostic() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA)), (3, notarization(0, 0xB))]),
            views(vec![]),
            views(vec![(1, finalization(0, 0xA))]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "notarization in view 2 with uncertified parent 1")]
    fn matching_finalization_does_not_change_ancestry_result() {
        let r = replica(
            views(vec![(2, notarization(1, 0xA))]),
            views(vec![]),
            views(vec![(2, finalization(1, 0xA))]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "notarization in view 1 has 2 < 3 signatures")]
    fn certificate_failures_are_ordered_by_view() {
        let mut notarizations = BTreeMap::new();
        notarizations.insert(3, notarization_with(0, 0xB, Some(2)));
        notarizations.insert(1, notarization_with(0, 0xA, Some(2)));
        let r = replica(notarizations, views(vec![]), views(vec![]));
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    fn conflict_diagnostic_names_first_and_conflicting_replicas() {
        let r0 = replica(
            views(vec![(1, notarization(0, 0xA))]),
            views(vec![]),
            views(vec![]),
        );
        let r1 = replica(views(vec![]), views(vec![]), views(vec![]));
        let r2 = replica(
            views(vec![(1, notarization(0, 0xB))]),
            views(vec![]),
            views(vec![]),
        );
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check::<SimplexId>(N, vec![r0, r1, r2]);
        }));
        let payload = result.expect_err("conflicting notarizations must panic");
        let message = payload
            .downcast_ref::<String>()
            .expect("panic payload must be a string");
        assert!(
            message.contains("replica 2 has"),
            "missing conflicting replica: {message}"
        );
        assert!(
            message.contains("replica 0 has"),
            "missing first replica: {message}"
        );
    }

    // Vote-invariant fixtures: id_mock schemes share one signing record, so any
    // scheme instance verifies any participant's votes.
    fn vote_fixture() -> (Vec<id_mock::PublicKey>, Vec<id_mock::Scheme>) {
        id_mock::fixture(&mut test_rng(), b"invariants-tests", N)
    }

    fn vote_reporter(
        participants: &[id_mock::PublicKey],
        schemes: &[id_mock::Scheme],
    ) -> Reporter<TestRng, id_mock::Scheme, RoundRobin, Sha256Digest> {
        Reporter::new(
            test_rng(),
            ReporterConfig {
                participants: Set::try_from(participants.to_vec()).expect("unique keys"),
                scheme: schemes[0].clone(),
                elector: RoundRobin::default(),
            },
        )
    }

    fn proposal(view: u64, parent: u64, payload: u8) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(Epoch::new(0), View::new(view)),
            View::new(parent),
            digest(payload),
        )
    }

    fn round(view: u64) -> Round {
        Round::new(Epoch::new(0), View::new(view))
    }

    #[test]
    #[should_panic(expected = "correct signer notarized multiple payloads in view 5")]
    fn correct_signer_notarizing_two_payloads_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
        ));
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal(5, 4, 0xB)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    #[should_panic(expected = "correct signer finalized multiple payloads in view 5")]
    fn correct_signer_finalizing_two_payloads_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
        ));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[1], proposal(5, 4, 0xB)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    #[should_panic(expected = "vote equivocation in view 5")]
    fn correct_signer_nullifying_and_finalizing_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[1], round(5)).unwrap(),
        ));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    fn byzantine_signer_equivocation_is_allowed() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[0], proposal(5, 4, 0xA)).unwrap(),
        ));
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[0], proposal(5, 4, 0xB)).unwrap(),
        ));
        rep.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(5)).unwrap(),
        ));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal(5, 4, 0xA)).unwrap(),
        ));
        let byzantine: HashSet<usize> = [0].into_iter().collect();
        check_vote_invariants_with_byzantine(&byzantine, &[rep]);
    }

    #[test]
    #[should_panic(expected = "correct signer notarized multiple payloads in view 5")]
    fn conflicting_votes_across_reporters_are_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep_a = vote_reporter(&participants, &schemes);
        let mut rep_b = vote_reporter(&participants, &schemes);
        rep_a.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
        ));
        rep_b.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal(5, 4, 0xB)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep_a, rep_b]);
    }

    #[test]
    fn multiple_equivocators_produce_sorted_diagnostics() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        for signer in [2, 1] {
            rep.report(Activity::Nullify(
                Nullify::sign::<Sha256Digest>(&schemes[signer], round(5)).unwrap(),
            ));
            rep.report(Activity::Finalize(
                Finalize::sign(&schemes[signer], proposal(5, 4, 0xA)).unwrap(),
            ));
        }
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
        }));
        let payload = result.expect_err("equivocation must panic");
        let message = payload
            .downcast_ref::<String>()
            .expect("panic payload must be a string");
        assert!(
            message.contains("[[0, 0, 0, 1], [0, 0, 0, 2]]"),
            "equivocators must be sorted: {message}"
        );
    }

    #[test]
    #[should_panic(expected = "fault evidence against correct signers")]
    fn fault_evidence_against_correct_signer_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        let evidence = ConflictingNotarize::new(
            Notarize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
            Notarize::sign(&schemes[1], proposal(5, 4, 0xB)).unwrap(),
        );
        rep.report(Activity::ConflictingNotarize(evidence));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    fn fault_evidence_against_byzantine_signer_is_allowed() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        let evidence = ConflictingNotarize::new(
            Notarize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
            Notarize::sign(&schemes[1], proposal(5, 4, 0xB)).unwrap(),
        );
        rep.report(Activity::ConflictingNotarize(evidence));
        let byzantine: HashSet<usize> = [1].into_iter().collect();
        check_vote_invariants_with_byzantine(&byzantine, &[rep]);
    }
}
