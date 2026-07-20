use crate::{
    bounds,
    simplex::Simplex,
    simplex_audit::{AutomatonEvent, Completion, Event, RecordingReporter, summaries},
    types::{Finalization, Notarization, Nullification, ReplicaState},
};
use commonware_codec::{Encode, Read};
use commonware_consensus::{
    simplex::{
        elector::Config as Elector,
        mocks::reporter::Reporter,
        scheme,
        scheme::Scheme,
        types::{Activity, Attributable, Proposal},
    },
    types::{Round, View},
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

/// Safety-observation forms accepted by [`check`].
///
/// Extracted replica states and consensus mock Reporter slices run the basic
/// certificate-state invariants. RecordingReporter slices, supplied by the
/// dedicated audit targets, additionally run invariants requiring append-only
/// activity and automaton history.
pub trait SafetyObservations<P: Simplex> {
    fn check_safety(self, n: u32);
}

/// Checks Simplex safety using the provided observations.
///
/// This remains the single entrypoint: the concrete observation type determines
/// whether only the basic invariants or also the audit-history
/// invariants are observable.
pub fn check<P: Simplex>(n: u32, observations: impl SafetyObservations<P>) {
    observations.check_safety(n);
}

impl<P: Simplex> SafetyObservations<P> for Vec<ReplicaState> {
    fn check_safety(self, n: u32) {
        check_basic_invariants::<P>(n, self);
    }
}

impl<P, E, L> SafetyObservations<P> for &[Reporter<E, P::Scheme, L, Sha256Digest>]
where
    P: Simplex,
    E: CryptoRng,
    P::Scheme: Scheme<Sha256Digest>,
    L: Elector<P::Scheme>,
{
    fn check_safety(self, n: u32) {
        check_basic_invariants::<P>(n, extract(self, n as usize));
    }
}

impl<P, E, L> SafetyObservations<P> for &[RecordingReporter<E, P::Scheme, L, Sha256Digest>]
where
    P: Simplex,
    E: CryptoRng,
    P::Scheme: Scheme<Sha256Digest>,
    <P::Scheme as certificate::Verifier>::PublicKey: Eq + Hash + Clone,
    L: Elector<P::Scheme>,
    L::Elector: Clone,
{
    fn check_safety(self, n: u32) {
        check_fuzz_invariants(self);
        check_basic_invariants::<P>(n, extract(summaries(self), n as usize));
    }
}

fn check_basic_invariants<P: Simplex>(n: u32, replicas: Vec<ReplicaState>) {
    let threshold = bounds::quorum(n) as usize;
    let attributable = <P::Scheme as certificate::Scheme>::is_attributable();

    // Invariant: certificate_signature_counts_are_valid
    // Every observed certificate exposes the appropriate signer-count metadata:
    // - attributable certificates expose a count in [quorum, n];
    // - non-attributable certificates expose no signer count.
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

    // Invariants:
    // - no_conflicting_quorum_notarizations
    // - no_conflicting_quorum_finalizations
    //
    // Across all reported certificates, at most one (parent, payload) may be
    // notarized in a view, and at most one (parent, payload) may be finalized in
    // a view. Replicas without a certificate observation for that view impose no
    // requirement.
    //
    // The independently defined signature-count check runs before each observation
    // is merged, so an invalid duplicate cannot be hidden by an earlier valid one.
    type Identity = (u64, Sha256Digest);
    let mut notarized_by_view: BTreeMap<u64, (usize, Identity)> = BTreeMap::new();
    let mut nullified_by_view: BTreeMap<u64, usize> = BTreeMap::new();
    let mut finalized_by_view: BTreeMap<u64, (usize, Identity)> = BTreeMap::new();
    for (idx, (notarizations, nullifications, finalizations)) in replicas.iter().enumerate() {
        for (&view, d) in notarizations.iter() {
            check_count("notarization", view, d.signature_count);
            let proposal = (d.parent, d.payload);
            match notarized_by_view.entry(view) {
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
            nullified_by_view.entry(view).or_insert(idx);
        }
        for (&view, d) in finalizations.iter() {
            check_count("finalization", view, d.signature_count);
            let proposal = (d.parent, d.payload);
            match finalized_by_view.entry(view) {
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

    // Invariant: no_nullification_at_genesis
    // Genesis (view 0) is implicitly finalized and voting begins at view 1, so
    // no nullification certificate can exist for it (a quorum would require
    // correct signers to have voted nullify(0)). Notarizations and
    // finalizations at view 0 are already rejected by the parent < view and
    // finalization-requires-notarization checks.
    if let Some(&idx) = nullified_by_view.get(&0) {
        panic!(
            "Invariant violation: replica {idx} has nullification certificate at genesis view 0"
        );
    }

    // Invariant: no_finalized_view_nullified
    // A view cannot carry both a finalization and a nullification certificate,
    // regardless of which replicas recorded them.
    for (&view, &(fin_idx, _)) in finalized_by_view.iter() {
        if let Some(&null_idx) = nullified_by_view.get(&view) {
            panic!(
                "Invariant violation: view {view} finalized by replica {fin_idx} and nullified by replica {null_idx}"
            );
        }
    }

    // Invariant: finalization_requires_notarization
    // Any finalization must be backed by a notarization with the same
    // (parent, payload); combined with per-view uniqueness above this also
    // forbids any notarization conflicting with a finalized proposal.
    for (&view, &(idx, proposal)) in finalized_by_view.iter() {
        let notarized_proposal = notarized_by_view.get(&view).map(|&(_, p)| p);
        assert!(
            notarized_proposal == Some(proposal),
            "Invariant violation: finalization without matching notarization in view {view}: replica {idx} finalized {proposal:?} but notarized is {notarized_proposal:?}"
        );
    }

    // Invariant: chain_consistency
    // A notarization at view v with parent p must reference genesis or a view with a recorded
    // notarization/finalization certificate, and must have a
    // nullification for every view in (p, v). The explicit finalized-view scan
    // is redundant with nullification coverage and finalized/nullified
    // disjointness, but is retained for its sharper diagnostic.
    // This checks only the global extracted certificate graph; it does not
    // reconstruct unreported history or prove local possession or event ordering.
    // Only notarized links are walked: finalization_requires_notarization has
    // already forced every finalized view onto an identical notarized link.
    for (&view, &(idx, (parent, _))) in notarized_by_view.iter() {
        assert!(
            parent < view,
            "Invariant violation: replica {idx} has notarization in view {view} with parent {parent}"
        );
        if let Some((skipped, _)) = finalized_by_view.range(parent + 1..view).next() {
            panic!(
                "Invariant violation: replica {idx} has notarization in view {view} with parent {parent} skipping finalized view {skipped}"
            );
        }
        assert!(
            parent == 0
                || notarized_by_view.contains_key(&parent)
                || finalized_by_view.contains_key(&parent),
            "Invariant violation: replica {idx} has notarization in view {view} with uncertified parent {parent}"
        );
        // Walk the recorded nullifications in (parent, view) expecting
        // consecutive keys; the first gap is the missing view.
        let mut expected = parent + 1;
        for (&w, _) in nullified_by_view.range(parent + 1..view) {
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
    // Invariant: certificate_derived_leader_agreement
    // Every reporter that derives a leader for the same view must derive the
    // same participant. Missing entries are deliberately ignored: Reporter
    // records a leader only after observing a certificate for the preceding
    // view, so incomplete observation can suppress this check but cannot make
    // two present observations disagree.
    //
    // Source: the `simplex::elector` configuration contract requires all
    // honest participants to agree on each round's leader. The instantiated
    // protocol's "Embedded VRF" documentation additionally requires every
    // certificate type for a view to yield the same seed, which selects the
    // following view's leader.
    let mut leaders: HashMap<u64, S::PublicKey> = HashMap::new();
    let mut leader_conflicts: BTreeMap<u64, BTreeSet<Vec<u8>>> = BTreeMap::new();
    for reporter in reporters {
        let observed = reporter.leaders.lock();
        for (view, leader) in observed.iter() {
            let view = view.get();
            match leaders.entry(view) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(leader.clone());
                }
                std::collections::hash_map::Entry::Occupied(entry) if entry.get() != leader => {
                    leader_conflicts
                        .entry(view)
                        .or_default()
                        .extend([entry.get().as_ref().to_vec(), leader.as_ref().to_vec()]);
                }
                std::collections::hash_map::Entry::Occupied(_) => {}
            }
        }
    }
    if let Some((view, conflicting)) = leader_conflicts.first_key_value() {
        panic!(
            "Invariant violation: reporters derived conflicting leaders in view {view}: {conflicting:?}; all conflicts: {leader_conflicts:?}"
        );
    }

    // Invariant: contiguous_certificate_progression
    // With a genesis floor, observing a certificate at view v > 1 implies
    // that some certificate exists at v-1: a quorum at v contains correct
    // participants, and correct participants can enter v only from a
    // certificate at v-1. Check the union rather than individual reporters so
    // that partial observations cause false negatives, never false positives.
    //
    // Source: the Simplex paper's protocol and safety proof advance a process
    // from a view only with a block or dummy-block certificate. The
    // instantiated protocol documents the same rule in "Genesis",
    // "Specification for View v", and "Joining Consensus", with notarization,
    // nullification, and finalization certificates as its progress proofs.
    let mut certified_views = BTreeSet::new();
    for reporter in reporters {
        certified_views.extend(reporter.certified.lock().iter().map(|view| view.get()));
    }
    for &view in &certified_views {
        if view > 1 {
            assert!(
                certified_views.contains(&(view - 1)),
                "Invariant violation: certificate progression skips predecessor view {} before certified view {view}",
                view - 1
            );
        }
    }

    // Invariant: no_fault_evidence_against_correct_signers
    // Fault proofs (ConflictingNotarize, ConflictingFinalize, NullifyFinalize)
    // are signature-verified by the reporter before being recorded. For
    // attributable schemes, verified fault evidence identifies the signer.
    // Non-attributable schemes do not provide safe per-signer attribution.
    // Byzantine signers are expected to equivocate and are excluded. Evidence
    // against a key outside the participant set is flagged rather than skipped.
    //
    // This complements no_vote_equivocation below: fault proofs preserve a
    // conflicting vote rejected from the ordinary vote map, while global vote
    // aggregation detects conflicts observed by different reporters.
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
    // Hash iteration may change which represented violation is reported first,
    // but detection of conflicts retained by Reporter is order-independent.
    //
    // Certificates are carriers of votes: for attributable schemes the signer
    // set embedded in a verified certificate is unforgeable proof that each
    // listed signer cast that vote, so those implicit votes join the same
    // sweep. This catches a double-sign whose second signature exists only
    // inside an aggregated certificate. Notarize+nullify by one signer in one
    // view is legal (timeout after notarizing) and is never flagged.
    //
    // Invariant: genesis_is_vote_free
    // Genesis (view 0) is implicitly finalized and voting begins at view 1,
    // so a correct signer can never produce a vote for view 0 and no quorum
    // certificate of any kind can exist there. Byzantine signers can sign
    // anything, so their view-0 votes are ignored. Checked inline below.
    let mut seen_nullify: HashMap<u64, HashSet<S::PublicKey>> = HashMap::new();
    let mut seen_finalize: HashMap<u64, HashSet<S::PublicKey>> = HashMap::new();
    let mut seen_notarize_payload: HashMap<(u64, S::PublicKey), Sha256Digest> = HashMap::new();
    let mut seen_finalize_payload: HashMap<(u64, S::PublicKey), Sha256Digest> = HashMap::new();
    let mut notarize_conflicts: BTreeMap<(u64, Vec<u8>), BTreeSet<Sha256Digest>> = BTreeMap::new();
    let mut finalize_conflicts: BTreeMap<(u64, Vec<u8>), BTreeSet<Sha256Digest>> = BTreeMap::new();
    let mut correct_vote_views: BTreeSet<(u64, Vec<u8>)> = BTreeSet::new();
    let mut correct_raw_notarize_payloads: BTreeMap<u64, BTreeSet<Sha256Digest>> = BTreeMap::new();
    let mut notarization_cert_payloads: BTreeMap<u64, BTreeSet<Sha256Digest>> = BTreeMap::new();
    let mut nullification_cert_views: BTreeSet<u64> = BTreeSet::new();
    let mut finalization_cert_payloads: BTreeMap<u64, BTreeSet<Sha256Digest>> = BTreeMap::new();
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
                    assert!(
                        view.get() != 0,
                        "Invariant violation: correct signer {:?} has notarize vote at genesis view 0",
                        pk.as_ref()
                    );
                    correct_vote_views.insert((view.get(), pk.as_ref().to_vec()));
                    correct_raw_notarize_payloads
                        .entry(view.get())
                        .or_default()
                        .insert(*digest);
                    record_payload_conflict(
                        &mut seen_notarize_payload,
                        &mut notarize_conflicts,
                        view.get(),
                        pk,
                        *digest,
                    );
                }
            }
        }
        drop(notarizes);

        let nullifies = reporter.nullifies.lock();
        for (view, signers) in nullifies.iter() {
            for pk in signers {
                if correct(pk) {
                    assert!(
                        view.get() != 0,
                        "Invariant violation: correct signer {:?} has nullify vote at genesis view 0",
                        pk.as_ref()
                    );
                    correct_vote_views.insert((view.get(), pk.as_ref().to_vec()));
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
                    assert!(
                        view.get() != 0,
                        "Invariant violation: correct signer {:?} has finalize vote at genesis view 0",
                        pk.as_ref()
                    );
                    correct_vote_views.insert((view.get(), pk.as_ref().to_vec()));
                    seen_finalize
                        .entry(view.get())
                        .or_default()
                        .insert(pk.clone());
                    record_payload_conflict(
                        &mut seen_finalize_payload,
                        &mut finalize_conflicts,
                        view.get(),
                        pk,
                        *digest,
                    );
                }
            }
        }
        drop(finalizes);

        // Invariant: certificate_signers_vote_consistency
        // Fold each certificate's embedded signer set (attributable schemes
        // only) into the vote maps as implicit votes by the listed correct
        // signers, and reject any certificate recorded at genesis view 0.
        let max_participants = reporter.participants.len();
        let notarizations = reporter.notarizations.lock();
        for (view, notarization) in notarizations.iter() {
            let view = view.get();
            assert!(
                view != 0,
                "Invariant violation: notarization certificate at genesis view 0"
            );
            let payload = notarization.proposal.payload;
            notarization_cert_payloads
                .entry(view)
                .or_default()
                .insert(payload);
            let Some(signers) = get_signers::<S>(&notarization.certificate, max_participants)
            else {
                continue;
            };
            for signer in signers.iter() {
                let pk = reporter
                    .participants
                    .key(signer)
                    .expect("certificate signer must be a participant");
                if !correct(pk) {
                    continue;
                }
                correct_vote_views.insert((view, pk.as_ref().to_vec()));
                record_payload_conflict(
                    &mut seen_notarize_payload,
                    &mut notarize_conflicts,
                    view,
                    pk,
                    payload,
                );
            }
        }
        drop(notarizations);

        let nullifications = reporter.nullifications.lock();
        for (view, nullification) in nullifications.iter() {
            let view = view.get();
            assert!(
                view != 0,
                "Invariant violation: nullification certificate at genesis view 0"
            );
            nullification_cert_views.insert(view);
            let Some(signers) = get_signers::<S>(&nullification.certificate, max_participants)
            else {
                continue;
            };
            for signer in signers.iter() {
                let pk = reporter
                    .participants
                    .key(signer)
                    .expect("certificate signer must be a participant");
                if !correct(pk) {
                    continue;
                }
                correct_vote_views.insert((view, pk.as_ref().to_vec()));
                seen_nullify.entry(view).or_default().insert(pk.clone());
            }
        }
        drop(nullifications);

        let finalizations = reporter.finalizations.lock();
        for (view, finalization) in finalizations.iter() {
            let view = view.get();
            assert!(
                view != 0,
                "Invariant violation: finalization certificate at genesis view 0"
            );
            let payload = finalization.proposal.payload;
            finalization_cert_payloads
                .entry(view)
                .or_default()
                .insert(payload);
            let Some(signers) = get_signers::<S>(&finalization.certificate, max_participants)
            else {
                continue;
            };
            for signer in signers.iter() {
                let pk = reporter
                    .participants
                    .key(signer)
                    .expect("certificate signer must be a participant");
                if !correct(pk) {
                    continue;
                }
                correct_vote_views.insert((view, pk.as_ref().to_vec()));
                seen_finalize.entry(view).or_default().insert(pk.clone());
                record_payload_conflict(
                    &mut seen_finalize_payload,
                    &mut finalize_conflicts,
                    view,
                    pk,
                    payload,
                );
            }
        }
        drop(finalizations);
    }

    // Invariant: certificate_vote_quorum_intersection
    // A verified certificate proves >= quorum distinct signers cast its vote,
    // and a correct node never casts the opposing vote in the same view
    // (finalize vs nullify; a second notarize/finalize payload). At most
    // max_faults correct signers can therefore legally oppose any recorded
    // certificate. Exceeding that bound proves a correct node double-signed,
    // even for non-attributable schemes, without relying on certificate signer
    // identities.
    if let Some(first) = reporters.first() {
        let max_faults = bounds::max_faults(first.participants.len() as u32) as usize;
        for &view in finalization_cert_payloads.keys() {
            let opposing = seen_nullify.get(&view).map_or(0, |signers| signers.len());
            assert!(
                opposing <= max_faults,
                "Invariant violation: finalization certificate at view {view} coexists with {opposing} correct nullify signers (max {max_faults})"
            );
        }
        for &view in nullification_cert_views.iter() {
            let opposing = seen_finalize.get(&view).map_or(0, |signers| signers.len());
            assert!(
                opposing <= max_faults,
                "Invariant violation: nullification certificate at view {view} coexists with {opposing} correct finalize signers (max {max_faults})"
            );
        }
        let mut notarize_votes: HashMap<u64, HashMap<Sha256Digest, usize>> = HashMap::new();
        for ((view, _), payload) in seen_notarize_payload.iter() {
            *notarize_votes
                .entry(*view)
                .or_default()
                .entry(*payload)
                .or_default() += 1;
        }
        let mut finalize_votes: HashMap<u64, HashMap<Sha256Digest, usize>> = HashMap::new();
        for ((view, _), payload) in seen_finalize_payload.iter() {
            *finalize_votes
                .entry(*view)
                .or_default()
                .entry(*payload)
                .or_default() += 1;
        }
        let opposing_count = |votes: &HashMap<u64, HashMap<Sha256Digest, usize>>,
                              view: u64,
                              payload: &Sha256Digest| {
            votes.get(&view).map_or(0, |by_payload| {
                by_payload
                    .iter()
                    .filter(|(p, _)| *p != payload)
                    .map(|(_, count)| *count)
                    .sum::<usize>()
            })
        };
        for (&view, payloads) in notarization_cert_payloads.iter() {
            for payload in payloads {
                let opposing = opposing_count(&notarize_votes, view, payload);
                assert!(
                    opposing <= max_faults,
                    "Invariant violation: notarization certificate at view {view} coexists with {opposing} correct conflicting notarize signers (max {max_faults})"
                );
            }
        }
        for (&view, payloads) in finalization_cert_payloads.iter() {
            for payload in payloads {
                let opposing = opposing_count(&finalize_votes, view, payload);
                assert!(
                    opposing <= max_faults,
                    "Invariant violation: finalization certificate at view {view} coexists with {opposing} correct conflicting finalize signers (max {max_faults})"
                );
            }
        }
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

    // Invariant: correct_view_entry_requires_predecessor_certificate
    // Every vote attributed to a correct signer above view 1 proves that the
    // signer entered that view, which requires a certificate at the preceding
    // view. Direct votes and signers exposed by attributable certificates are
    // both evidence of participation. The predecessor is required only in the
    // aggregate certified-view union: this does not infer local possession,
    // observation order, or signers for non-attributable certificates.
    //
    // Source: the Simplex paper's view-transition protocol permits voting in a
    // new view only after leaving the prior view with a value or skip
    // certificate. The instantiated protocol preserves this rule in
    // "Specification for View v" and "Joining Consensus", while extending the
    // progress certificates to its certification and finalization behavior.
    let mut premature_votes = BTreeSet::new();
    for (view, signer) in &correct_vote_views {
        if *view > 1 && !certified_views.contains(&(view - 1)) {
            premature_votes.insert((*view, signer.clone()));
        }
    }
    if let Some((view, signer)) = premature_votes.first() {
        panic!(
            "Invariant violation: correct signer {signer:?} voted in view {view} without a certificate at predecessor view {}; all violations: {premature_votes:?}",
            view - 1
        );
    }

    // Invariant: honest_leader_payload_coherence
    // When the uniquely derived leader is correct, all raw notarize votes from
    // correct participants and every observed notarization/certification
    // certificate in that view must concern one payload. A Byzantine, missing,
    // or conflicting leader is outside this predicate; conflicting leaders
    // have already been rejected by certificate_derived_leader_agreement.
    //
    // Source: the Simplex paper's proposal rule accepts a value from the
    // designated leader and its quorum-intersection safety proof excludes two
    // notarized non-dummy values. The instantiated voter round strengthens the
    // observable premise: its proposal is the leader's first notarize vote,
    // and its equivocation handling prevents a correct leader from supplying
    // multiple proposal payloads.
    let leader_is_correct = |leader: &S::PublicKey| {
        reporters.first().is_some_and(|reporter| {
            reporter
                .participants
                .index(leader)
                .is_some_and(|idx| !byzantine.contains(&usize::from(idx)))
        })
    };
    let mut honest_leader_conflicts: BTreeMap<u64, BTreeSet<Sha256Digest>> = BTreeMap::new();
    for (&view, leader) in &leaders {
        if !leader_is_correct(leader) {
            continue;
        }
        let mut payloads = correct_raw_notarize_payloads
            .get(&view)
            .cloned()
            .unwrap_or_default();
        if let Some(certified) = notarization_cert_payloads.get(&view) {
            payloads.extend(certified);
        }
        if payloads.len() > 1 {
            honest_leader_conflicts.insert(view, payloads);
        }
    }
    if let Some((view, payloads)) = honest_leader_conflicts.first_key_value() {
        panic!(
            "Invariant violation: correct leader has conflicting proposal payloads in view {view}: {payloads:?}; all conflicts: {honest_leader_conflicts:?}"
        );
    }

    // Invariant: finalize_vote_requires_notarization
    // Every recorded finalize vote attributed to a correct signer must have a
    // matching (view, payload) notarization in the union of checked reporter
    // snapshots. For attributable schemes, finalization-certificate signers
    // are included as implicit votes, so their certificates are checked here
    // as well.
    // This checks global recorded evidence, not signer-local possession
    // or event ordering. Reporter merges Notarization and Certification, drops the
    // finalize parent, and retains only one notarization per view; therefore this
    // cannot check successful certification, exact proposal identity, or
    // overwritten history. Exact proposal agreement is checked if a finalization
    // certificate forms.
    let mut notarized: HashSet<(u64, Sha256Digest)> = HashSet::new();
    for reporter in reporters {
        let notarizations = reporter.notarizations.lock();
        for (view, notarization) in notarizations.iter() {
            notarized.insert((view.get(), notarization.proposal.payload));
        }
    }
    let mut unbacked: BTreeMap<(u64, Vec<u8>), Sha256Digest> = BTreeMap::new();
    for (key, payload) in &seen_finalize_payload {
        let (view, pk) = key;
        if !notarized.contains(&(*view, *payload)) {
            unbacked.insert((*view, pk.as_ref().to_vec()), *payload);
        }
    }
    if let Some(((view, signer), payload)) = unbacked.first_key_value() {
        panic!(
            "Invariant violation: finalize vote without notarization in view {view}: signer {signer:?} finalized {payload:?}; all violations: {unbacked:?}"
        );
    }
}

/// Checks invariants that require the append-only activity and automaton history
/// collected by the dedicated audit targets. Every reporter in this slice must
/// belong to a correct engine; adversarial observers remain available to the
/// separate vote/fault checker, but must not be passed to [`check`] as safety
/// observations.
fn check_fuzz_invariants<E, S, L>(reporters: &[RecordingReporter<E, S, L, Sha256Digest>])
where
    E: CryptoRng,
    S: Scheme<Sha256Digest>,
    S::PublicKey: Eq + Hash + Clone,
    L: Elector<S>,
    L::Elector: Clone,
{
    type ExactVotes = BTreeMap<(Round, Vec<u8>), BTreeSet<Proposal<Sha256Digest>>>;
    type ApplicationProposal = (Round, (View, Sha256Digest), Sha256Digest);

    let correct_observers: HashSet<Vec<u8>> = reporters
        .iter()
        .map(|reporter| reporter.audit().observer().as_ref().to_vec())
        .collect();
    let mut exact_notarizes: ExactVotes = BTreeMap::new();
    let mut exact_finalizes: ExactVotes = BTreeMap::new();
    let mut notarization_history: BTreeMap<Round, BTreeSet<Proposal<Sha256Digest>>> =
        BTreeMap::new();
    let mut finalization_history: BTreeMap<Round, BTreeSet<Proposal<Sha256Digest>>> =
        BTreeMap::new();
    let mut context_leaders: BTreeMap<Round, BTreeSet<Vec<u8>>> = BTreeMap::new();

    for reporter in reporters {
        let audit = reporter.audit();
        let observer = audit.observer();
        let participants = &reporter.inner().participants;
        let observer_idx = participants
            .index(observer)
            .expect("fuzz reporter observer must be a participant");
        let observer_bytes = observer.as_ref().to_vec();
        let events = audit.events();

        let mut accepted_proposals: BTreeSet<ApplicationProposal> = BTreeSet::new();
        let mut rejected_proposals: BTreeSet<ApplicationProposal> = BTreeSet::new();
        let mut successful_certifications: BTreeSet<(Round, Sha256Digest)> = BTreeSet::new();
        let mut failed_certifications: BTreeSet<(Round, Sha256Digest)> = BTreeSet::new();
        let mut reported_certifications: BTreeMap<Round, BTreeSet<Proposal<Sha256Digest>>> =
            BTreeMap::new();
        let mut local_finalizes: BTreeMap<Round, BTreeSet<Proposal<Sha256Digest>>> =
            BTreeMap::new();

        for recorded in &events {
            match &recorded.event {
                Event::Activity { valid: false, .. } => {}
                Event::Activity {
                    valid: true,
                    activity,
                } => {
                    // Invariant: exact_proposal_non_equivocation
                    // A correct signer cannot notarize two different full proposals
                    // in one round, cannot finalize two different full proposals in
                    // one round, and cannot disagree with an exact proposal carried
                    // by an attributable certificate. The full identity is
                    // (round, parent, payload), so equal payloads with different
                    // parents still conflict.
                    //
                    // Source: the Simplex paper's quorum-intersection safety proof
                    // relies on correct replicas not equivocating. The instantiated
                    // protocol's proposal, certification, and fault-evidence types
                    // sign the parent together with the payload. RecordingReporter
                    // extends the summary model by retaining that signed parent.
                    match activity {
                        Activity::Notarize(vote) => {
                            let public_key = participants
                                .key(vote.signer())
                                .expect("valid vote signer must be a participant");
                            if correct_observers.contains(public_key.as_ref()) {
                                record_exact_proposal(
                                    &mut exact_notarizes,
                                    vote.proposal.round,
                                    public_key,
                                    &vote.proposal,
                                );
                            }
                        }
                        Activity::Notarization(certificate)
                        | Activity::Certification(certificate) => {
                            notarization_history
                                .entry(certificate.proposal.round)
                                .or_default()
                                .insert(certificate.proposal.clone());
                            if let Some(signers) =
                                get_signers::<S>(&certificate.certificate, participants.len())
                            {
                                for signer in signers.iter() {
                                    let public_key = participants
                                        .key(signer)
                                        .expect("certificate signer must be a participant");
                                    if correct_observers.contains(public_key.as_ref()) {
                                        record_exact_proposal(
                                            &mut exact_notarizes,
                                            certificate.proposal.round,
                                            public_key,
                                            &certificate.proposal,
                                        );
                                    }
                                }
                            }
                        }
                        Activity::Finalize(vote) => {
                            let public_key = participants
                                .key(vote.signer())
                                .expect("valid vote signer must be a participant");
                            if correct_observers.contains(public_key.as_ref()) {
                                record_exact_proposal(
                                    &mut exact_finalizes,
                                    vote.proposal.round,
                                    public_key,
                                    &vote.proposal,
                                );
                            }
                        }
                        Activity::Finalization(certificate) => {
                            finalization_history
                                .entry(certificate.proposal.round)
                                .or_default()
                                .insert(certificate.proposal.clone());
                            if let Some(signers) =
                                get_signers::<S>(&certificate.certificate, participants.len())
                            {
                                for signer in signers.iter() {
                                    let public_key = participants
                                        .key(signer)
                                        .expect("certificate signer must be a participant");
                                    if correct_observers.contains(public_key.as_ref()) {
                                        record_exact_proposal(
                                            &mut exact_finalizes,
                                            certificate.proposal.round,
                                            public_key,
                                            &certificate.proposal,
                                        );
                                    }
                                }
                            }
                        }
                        _ => {}
                    }

                    match activity {
                        Activity::Notarize(vote) if vote.signer() == observer_idx => {
                            let matches_vote =
                                |(round, (parent_view, _), payload): &ApplicationProposal| {
                                    *round == vote.proposal.round
                                        && *parent_view == vote.proposal.parent
                                        && *payload == vote.proposal.payload
                                };

                            // Invariant: local_notarize_requires_application_acceptance
                            // Every notarize vote produced by a correct local engine
                            // must follow a successful proposal construction or a
                            // successful verification for the same round, parent view,
                            // and payload under at least one full parent context.
                            // Application outcomes retain both the parent view and
                            // digest. The signed Proposal exposes only the parent view,
                            // so a rejection under one parent digest cannot invalidate
                            // an acceptance under another digest with the same view.
                            //
                            // Source: the Automaton contract says returning a proposal
                            // commits the proposer to accepting it, while the
                            // instantiated voter's proposal lifecycle and round code
                            // require a Verified proposal before constructing a
                            // notarize vote.
                            if !accepted_proposals.iter().any(matches_vote) {
                                let rejected_contexts: BTreeSet<_> = rejected_proposals
                                    .iter()
                                    .filter(|proposal| matches_vote(proposal))
                                    .map(|(_, parent, _)| *parent)
                                    .collect();
                                panic!(
                                    "Invariant violation: local notarize without successful propose/verify: observer {observer_bytes:?}, proposal {:?}, rejected parent contexts {rejected_contexts:?}",
                                    vote.proposal
                                );
                            }
                        }
                        Activity::Certification(certificate) => {
                            let key = (certificate.proposal.round, certificate.proposal.payload);

                            // Invariant: certification_activity_requires_successful_result
                            // A Certification activity denotes this node's successful
                            // local decision, so it must be backed by a true automaton
                            // result for the same (round, payload).
                            //
                            // Source: Activity::Certification is documented as a
                            // locally certified notarization, and the instantiated
                            // protocol's "Certification" section reports it only
                            // after CertifiableAutomaton::certify returns true.
                            assert!(
                                successful_certifications.contains(&key),
                                "Invariant violation: successful certification activity without a true automaton result: observer {observer_bytes:?}, proposal {:?}",
                                certificate.proposal
                            );
                            reported_certifications
                                .entry(certificate.proposal.round)
                                .or_default()
                                .insert(certificate.proposal.clone());
                        }
                        Activity::Finalize(vote) if vote.signer() == observer_idx => {
                            let key = (vote.proposal.round, vote.proposal.payload);

                            // Invariant: local_finalize_requires_successful_certification
                            // A correct local engine may finalize a proposal only after
                            // its own automaton returned true for exactly that
                            // (round, payload). Closed, canceled, pending, and false
                            // certification do not authorize a finalize vote.
                            //
                            // Source: the instantiated protocol's "Certification"
                            // section and voter round construction require successful
                            // certification after notarization before finalizing,
                            // including for the node's own proposal.
                            assert!(
                                successful_certifications.contains(&key),
                                "Invariant violation: local finalize without successful certification: observer {observer_bytes:?}, proposal {:?}",
                                vote.proposal
                            );
                            local_finalizes
                                .entry(vote.proposal.round)
                                .or_default()
                                .insert(vote.proposal.clone());
                        }
                        _ => {}
                    }
                }
                Event::Automaton(event) => {
                    match event {
                        AutomatonEvent::ProposeRequested { context }
                        | AutomatonEvent::VerifyRequested { context, .. } => {
                            context_leaders
                                .entry(context.round)
                                .or_default()
                                .insert(context.leader.as_ref().to_vec());
                            // The recorded parent omits its epoch; the audited fuzz
                            // targets are single-epoch, so it matches the child epoch.
                            let parent = (
                                Round::new(context.round.epoch(), context.parent.0),
                                context.parent.1,
                            );

                            // Invariant: failed_certification_is_never_used
                            // Once a correct application rejects certification of
                            // (round, payload), that node must not finalize it or later
                            // ask the application to build or verify a proposal using
                            // it as parent. Closed or canceled certification is not a
                            // rejection and imposes no requirement.
                            //
                            // Source: the instantiated protocol's "Certification"
                            // section states that a false result causes nullification
                            // and that the participant refuses to build on the rejected
                            // proposal.
                            assert!(
                                !failed_certifications.contains(&parent),
                                "Invariant violation: failed certification used as parent: observer {observer_bytes:?}, parent {parent:?}, child round {:?}",
                                context.round
                            );
                        }
                        _ => {}
                    }

                    match event {
                        AutomatonEvent::ProposeRequested { context } => {
                            // Invariant: only_the_elected_leader_requests_a_proposal
                            // A correct node asks its application to construct a
                            // proposal only when that node is the leader named in the
                            // consensus context.
                            //
                            // Source: the Simplex paper permits only the designated
                            // leader to propose in a view. The instantiated voter
                            // exposes that decision through Context::leader before
                            // calling Automaton::propose.
                            assert_eq!(
                                &context.leader,
                                observer,
                                "Invariant violation: non-leader requested proposal in round {:?}: observer {observer_bytes:?}, leader {:?}",
                                context.round,
                                context.leader.as_ref()
                            );
                        }
                        AutomatonEvent::ProposeCompleted {
                            context,
                            outcome: Completion::Returned(payload),
                        } => {
                            accepted_proposals.insert((context.round, context.parent, *payload));
                        }
                        AutomatonEvent::VerifyCompleted {
                            context,
                            payload,
                            outcome: Completion::Returned(result),
                        } => {
                            let key = (context.round, context.parent, *payload);
                            if *result {
                                accepted_proposals.insert(key);
                            } else {
                                rejected_proposals.insert(key);
                            }
                        }
                        AutomatonEvent::CertifyCompleted {
                            round,
                            payload,
                            outcome: Completion::Returned(result),
                        } => {
                            let key = (*round, *payload);
                            if *result {
                                successful_certifications.insert(key);
                            } else {
                                failed_certifications.insert(key);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // Invariant: certification_finalize_exact_proposal_coherence
        // When a correct reporter retains both its successful Certification
        // activity and its own finalize vote for a round, the full proposals
        // must match, including the parent. Observation order is deliberately
        // irrelevant because the batcher and voter share the Reporter.
        //
        // Source: the instantiated protocol's "Certification" section permits a
        // finalize vote only for the notarized proposal accepted by the
        // certification decision; Proposal signatures commit to the parent.
        for (round, finalizes) in &local_finalizes {
            let Some(certifications) = reported_certifications.get(round) else {
                continue;
            };
            for proposal in finalizes {
                assert!(
                    certifications.contains(proposal),
                    "Invariant violation: certification/finalize proposal mismatch in round {round:?}: observer {observer_bytes:?}, certifications {certifications:?}, finalize {proposal:?}"
                );
            }
        }
    }

    if let Some(((round, signer), proposals)) = exact_notarizes
        .iter()
        .find(|(_, proposals)| proposals.len() > 1)
    {
        panic!(
            "Invariant violation: correct signer notarized multiple exact proposals in round {round:?}: signer {signer:?}, proposals {proposals:?}"
        );
    }
    if let Some(((round, signer), proposals)) = exact_finalizes
        .iter()
        .find(|(_, proposals)| proposals.len() > 1)
    {
        panic!(
            "Invariant violation: correct signer finalized multiple exact proposals in round {round:?}: signer {signer:?}, proposals {proposals:?}"
        );
    }

    // Extended invariant observation:
    // - no_conflicting_quorum_notarizations
    // - no_conflicting_quorum_finalizations
    //
    // The append-only history closes the summary Reporter's overwrite gap:
    // every valid certificate retained at a round participates, rather than
    // only the last certificate stored in each per-view map.
    //
    // Source: the Simplex paper's quorum-intersection lemmas exclude two
    // conflicting value certificates in one view. The instantiated
    // protocol's notarization and finalization certificates commit to the full
    // proposal, including its parent.
    if let Some((round, proposals)) = notarization_history
        .iter()
        .find(|(_, proposals)| proposals.len() > 1)
    {
        panic!(
            "Invariant violation: conflicting notarization history in round {round:?}: {proposals:?}"
        );
    }
    if let Some((round, proposals)) = finalization_history
        .iter()
        .find(|(_, proposals)| proposals.len() > 1)
    {
        panic!(
            "Invariant violation: conflicting finalization history in round {round:?}: {proposals:?}"
        );
    }

    // Invariant: automaton_context_leaders_agree
    // Every correct engine that requests application work for the same round
    // must name the same elected leader. Missing contexts are ignored.
    //
    // Source: the Simplex paper assumes one designated leader per view, and the
    // instantiated elector contract requires all honest participants to agree
    // on the elected participant.
    if let Some((round, leaders)) = context_leaders
        .iter()
        .find(|(_, leaders)| leaders.len() > 1)
    {
        panic!(
            "Invariant violation: correct automaton contexts disagree on leader in round {round:?}: {leaders:?}"
        );
    }
}

fn record_exact_proposal<P: AsRef<[u8]>>(
    votes: &mut BTreeMap<(Round, Vec<u8>), BTreeSet<Proposal<Sha256Digest>>>,
    round: Round,
    signer: &P,
    proposal: &Proposal<Sha256Digest>,
) {
    votes
        .entry((round, signer.as_ref().to_vec()))
        .or_default()
        .insert(proposal.clone());
}

/// Records a per-signer payload vote for equivocation detection: every payload
/// conflicting with the signer's first-seen pivot is accumulated so the union
/// is order-independent.
fn record_payload_conflict<P: Clone + Eq + Hash + AsRef<[u8]>>(
    pivots: &mut HashMap<(u64, P), Sha256Digest>,
    conflicts: &mut BTreeMap<(u64, Vec<u8>), BTreeSet<Sha256Digest>>,
    view: u64,
    pk: &P,
    payload: Sha256Digest,
) {
    let pivot = *pivots.entry((view, pk.clone())).or_insert(payload);
    if pivot != payload {
        conflicts
            .entry((view, pk.as_ref().to_vec()))
            .or_default()
            .extend([pivot, payload]);
    }
}

/// Decodes the signer bitmap used by the currently supported attributable
/// certificate encodings; returns `None` for non-attributable schemes.
pub(crate) fn get_signers<S: scheme::Scheme<Sha256Digest>>(
    certificate: &S::Certificate,
    max_participants: usize,
) -> Option<Signers> {
    if !S::is_attributable() {
        return None;
    }

    let encoded = certificate.encode();
    let mut cursor = encoded.as_ref();
    Some(
        Signers::read_cfg(&mut cursor, &max_participants).expect("certificate signers must decode"),
    )
}

pub(crate) fn get_signature_count<S: scheme::Scheme<Sha256Digest>>(
    certificate: &S::Certificate,
    max_participants: usize,
) -> Option<usize> {
    get_signers::<S>(certificate, max_participants).map(|signers| signers.count())
}

pub fn extract<E, S, L>(
    reporters: impl AsRef<[Reporter<E, S, L, Sha256Digest>]>,
    max_participants: usize,
) -> Vec<ReplicaState>
where
    E: CryptoRng,
    S: Scheme<Sha256Digest>,
    L: Elector<S>,
{
    let reporters = reporters.as_ref();
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
            scheme::bls12381_threshold::vrf as bls12381_threshold_vrf,
            types::{
                ConflictingNotarize, Context, Finalization as SimplexFinalization, Finalize,
                Notarization as SimplexNotarization, Notarize,
                Nullification as SimplexNullification, Nullify, Proposal,
            },
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, ed25519::PublicKey as Ed25519PublicKey,
    };
    use commonware_parallel::Sequential;
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
        notarizations: HashMap<u64, Notarization>,
        nullifications: HashMap<u64, Nullification>,
        finalizations: HashMap<u64, Finalization>,
    ) -> ReplicaState {
        (notarizations, nullifications, finalizations)
    }

    fn views<T>(entries: Vec<(u64, T)>) -> HashMap<u64, T> {
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
        let reporter = Reporter::new(
            test_rng(),
            ReporterConfig {
                participants: Set::try_from(participants.to_vec()).expect("unique keys"),
                scheme: schemes[0].clone(),
                elector: RoundRobin::default(),
            },
        );
        // Most vote fixtures exercise isolated view-5 behavior. Model the
        // genesis-started harness history that enabled entry into that view.
        reporter.certified.lock().extend((1..=4).map(View::new));
        reporter
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
    fn matching_and_missing_leader_observations_pass() {
        let (participants, schemes) = vote_fixture();
        let rep_a = vote_reporter(&participants, &schemes);
        let rep_b = vote_reporter(&participants, &schemes);
        rep_a
            .leaders
            .lock()
            .insert(View::new(5), participants[0].clone());
        // rep_b intentionally lacks view 5: incomplete observation must not
        // create a false positive.
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep_a, rep_b]);
    }

    #[test]
    #[should_panic(expected = "reporters derived conflicting leaders in view 5")]
    fn conflicting_certificate_derived_leaders_are_rejected() {
        let (participants, schemes) = vote_fixture();
        let rep_a = vote_reporter(&participants, &schemes);
        let rep_b = vote_reporter(&participants, &schemes);
        rep_a
            .leaders
            .lock()
            .insert(View::new(5), participants[0].clone());
        rep_b
            .leaders
            .lock()
            .insert(View::new(5), participants[1].clone());
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep_a, rep_b]);
    }

    #[test]
    fn certificate_progression_accepts_aggregate_predecessor_history() {
        let (participants, schemes) = vote_fixture();
        let rep_a = vote_reporter(&participants, &schemes);
        let rep_b = vote_reporter(&participants, &schemes);
        rep_a.certified.lock().clear();
        rep_b.certified.lock().clear();
        rep_a.certified.lock().insert(View::new(1));
        rep_b.certified.lock().insert(View::new(2));
        // Neither reporter has complete history, but the applicable aggregate
        // does. View 1 is the valid genesis boundary.
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep_a, rep_b]);
    }

    #[test]
    #[should_panic(expected = "certificate progression skips predecessor view 2")]
    fn certificate_progression_gap_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let rep = vote_reporter(&participants, &schemes);
        rep.certified.lock().clear();
        rep.certified.lock().extend([View::new(1), View::new(3)]);
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    fn correct_view_entry_accepts_predecessor_from_another_reporter() {
        let (participants, schemes) = vote_fixture();
        let mut rep_a = vote_reporter(&participants, &schemes);
        let rep_b = vote_reporter(&participants, &schemes);
        rep_a.certified.lock().clear();
        rep_b.certified.lock().clear();
        rep_b.certified.lock().insert(View::new(1));
        rep_a.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal(2, 1, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep_a, rep_b]);
    }

    #[test]
    #[should_panic(expected = "voted in view 2 without a certificate at predecessor view 1")]
    fn correct_vote_without_predecessor_certificate_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.certified.lock().clear();
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal(2, 1, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
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

    /// Assembles a quorum-backed notarization certificate over `proposal(view, parent, payload)`.
    fn notarization_activity(
        schemes: &[id_mock::Scheme],
        view: u64,
        parent: u64,
        payload: u8,
    ) -> SimplexNotarization<id_mock::Scheme, Sha256Digest> {
        notarization_activity_from(schemes, &[0, 1, 2], view, parent, payload)
    }

    fn notarization_activity_from(
        schemes: &[id_mock::Scheme],
        signers: &[usize],
        view: u64,
        parent: u64,
        payload: u8,
    ) -> SimplexNotarization<id_mock::Scheme, Sha256Digest> {
        assert_eq!(signers.len(), Q);
        let votes: Vec<_> = signers
            .iter()
            .map(|&signer| {
                Notarize::sign(&schemes[signer], proposal(view, parent, payload)).unwrap()
            })
            .collect();
        SimplexNotarization::from_notarizes(&schemes[0], &votes, &Sequential).unwrap()
    }

    /// Assembles a quorum-backed nullification certificate for `view`.
    fn nullification_activity(
        schemes: &[id_mock::Scheme],
        view: u64,
    ) -> SimplexNullification<id_mock::Scheme> {
        let votes: Vec<_> = schemes[..Q]
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round(view)).unwrap())
            .collect();
        SimplexNullification::from_nullifies(&schemes[0], &votes, &Sequential).unwrap()
    }

    /// Assembles a quorum-backed finalization certificate over `proposal(view, parent, payload)`.
    fn finalization_activity(
        schemes: &[id_mock::Scheme],
        view: u64,
        parent: u64,
        payload: u8,
    ) -> SimplexFinalization<id_mock::Scheme, Sha256Digest> {
        let votes: Vec<_> = schemes[..Q]
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal(view, parent, payload)).unwrap())
            .collect();
        SimplexFinalization::from_finalizes(&schemes[0], &votes, &Sequential).unwrap()
    }

    type AuditReporter = RecordingReporter<TestRng, id_mock::Scheme, RoundRobin, Sha256Digest>;

    fn audit_reporter(
        observer: usize,
        participants: &[id_mock::PublicKey],
        schemes: &[id_mock::Scheme],
    ) -> AuditReporter {
        RecordingReporter::new(
            test_rng(),
            participants[observer].clone(),
            0,
            ReporterConfig {
                participants: Set::try_from(participants.to_vec()).expect("unique keys"),
                scheme: schemes[observer].clone(),
                elector: RoundRobin::default(),
            },
        )
    }

    fn automaton_context(
        leader: id_mock::PublicKey,
        proposal: &Proposal<Sha256Digest>,
    ) -> Context<Sha256Digest, id_mock::PublicKey> {
        automaton_context_with_parent_digest(leader, proposal, digest(0xF))
    }

    fn automaton_context_with_parent_digest(
        leader: id_mock::PublicKey,
        proposal: &Proposal<Sha256Digest>,
        parent_digest: Sha256Digest,
    ) -> Context<Sha256Digest, id_mock::PublicKey> {
        Context {
            round: proposal.round,
            leader,
            parent: (proposal.parent, parent_digest),
        }
    }

    fn record_automaton(
        reporter: &AuditReporter,
        event: AutomatonEvent<Sha256Digest, id_mock::PublicKey>,
    ) {
        reporter.audit().record(Event::Automaton(event));
    }

    fn record_propose_success(reporter: &AuditReporter, proposal: &Proposal<Sha256Digest>) {
        let context = automaton_context(reporter.audit().observer().clone(), proposal);
        record_automaton(
            reporter,
            AutomatonEvent::ProposeCompleted {
                context,
                outcome: Completion::Returned(proposal.payload),
            },
        );
    }

    fn record_verify_result(
        reporter: &AuditReporter,
        leader: id_mock::PublicKey,
        proposal: &Proposal<Sha256Digest>,
        result: bool,
    ) {
        record_verify_result_with_parent_digest(reporter, leader, proposal, digest(0xF), result);
    }

    fn record_verify_result_with_parent_digest(
        reporter: &AuditReporter,
        leader: id_mock::PublicKey,
        proposal: &Proposal<Sha256Digest>,
        parent_digest: Sha256Digest,
        result: bool,
    ) {
        record_automaton(
            reporter,
            AutomatonEvent::VerifyCompleted {
                context: automaton_context_with_parent_digest(leader, proposal, parent_digest),
                payload: proposal.payload,
                outcome: Completion::Returned(result),
            },
        );
    }

    fn record_certify_result(
        reporter: &AuditReporter,
        proposal: &Proposal<Sha256Digest>,
        result: bool,
    ) {
        record_automaton(
            reporter,
            AutomatonEvent::CertifyCompleted {
                round: proposal.round,
                payload: proposal.payload,
                outcome: Completion::Returned(result),
            },
        );
    }

    #[test]
    fn check_selects_invariants_from_the_reporter_type() {
        let (participants, schemes) = vote_fixture();
        let mock = vote_reporter(&participants, &schemes);
        check::<SimplexId>(N, std::slice::from_ref(&mock));

        let fuzz = audit_reporter(0, &participants, &schemes);
        check::<SimplexId>(N, std::slice::from_ref(&fuzz));
    }

    #[test]
    fn exact_proposal_non_equivocation_accepts_one_complete_observation() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let proposal = proposal(5, 1, 0xA);
        record_propose_success(&reporter, &proposal);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], proposal).unwrap(),
        ));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "notarized multiple exact proposals")]
    fn exact_proposal_non_equivocation_rejects_same_payload_with_different_parents() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        for parent in [1, 2] {
            let proposal = proposal(5, parent, 0xA);
            record_propose_success(&reporter, &proposal);
            reporter.report(Activity::Notarize(
                Notarize::sign(&schemes[0], proposal).unwrap(),
            ));
        }
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    fn complete_certificate_history_accepts_repeated_identical_certificates() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(3, &participants, &schemes);
        let notarization = notarization_activity(&schemes, 5, 4, 0xA);
        let finalization = finalization_activity(&schemes, 5, 4, 0xA);
        reporter.report(Activity::Notarization(notarization.clone()));
        reporter.report(Activity::Notarization(notarization));
        reporter.report(Activity::Finalization(finalization.clone()));
        reporter.report(Activity::Finalization(finalization));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "conflicting notarization history")]
    fn complete_history_rejects_overwritten_conflicting_notarizations() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(3, &participants, &schemes);
        reporter.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 3, 0xA,
        )));
        reporter.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "conflicting finalization history")]
    fn complete_history_rejects_overwritten_conflicting_finalizations() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(3, &participants, &schemes);
        reporter.report(Activity::Finalization(finalization_activity(
            &schemes, 5, 3, 0xA,
        )));
        reporter.report(Activity::Finalization(finalization_activity(
            &schemes, 5, 4, 0xA,
        )));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    fn local_notarize_accepts_successful_verification() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(1, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        record_verify_result(&reporter, participants[0].clone(), &proposal, true);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal).unwrap(),
        ));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local notarize without successful propose/verify")]
    fn local_notarize_without_application_acceptance_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    fn canceled_application_request_without_a_vote_is_an_allowed_prefix() {
        let (participants, schemes) = vote_fixture();
        let reporter = audit_reporter(0, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeCompleted {
                context: automaton_context(participants[0].clone(), &proposal),
                outcome: Completion::Canceled,
            },
        );
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    fn rejection_under_another_parent_digest_does_not_override_acceptance() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(1, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        record_verify_result_with_parent_digest(
            &reporter,
            participants[0].clone(),
            &proposal,
            digest(0xE),
            false,
        );
        record_verify_result_with_parent_digest(
            &reporter,
            participants[0].clone(),
            &proposal,
            digest(0xF),
            true,
        );
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal).unwrap(),
        ));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local notarize without successful propose/verify")]
    fn local_notarize_after_only_rejection_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(1, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        record_verify_result(&reporter, participants[0].clone(), &proposal, false);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal).unwrap(),
        ));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    fn local_finalize_accepts_matching_successful_certification() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        record_certify_result(&reporter, &proposal, true);
        reporter.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal).unwrap(),
        ));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local finalize without successful certification")]
    fn local_finalize_without_successful_certification_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "certification activity without a true automaton result")]
    fn certification_activity_without_successful_result_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Certification(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    fn failed_certification_at_the_end_of_a_prefix_is_allowed() {
        let (participants, schemes) = vote_fixture();
        let reporter = audit_reporter(0, &participants, &schemes);
        record_certify_result(&reporter, &proposal(5, 4, 0xA), false);
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "failed certification used as parent")]
    fn failed_certification_cannot_be_used_as_a_parent() {
        let (participants, schemes) = vote_fixture();
        let reporter = audit_reporter(0, &participants, &schemes);
        let failed = proposal(5, 4, 0xA);
        record_certify_result(&reporter, &failed, false);
        let child = proposal(7, 5, 0xB);
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeRequested {
                context: Context {
                    round: child.round,
                    leader: participants[0].clone(),
                    parent: (failed.round.view(), failed.payload),
                },
            },
        );
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    fn elected_leader_and_follower_contexts_agree() {
        let (participants, schemes) = vote_fixture();
        let leader = audit_reporter(0, &participants, &schemes);
        let follower = audit_reporter(1, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        let context = automaton_context(participants[0].clone(), &proposal);
        record_automaton(
            &leader,
            AutomatonEvent::ProposeRequested {
                context: context.clone(),
            },
        );
        record_automaton(
            &follower,
            AutomatonEvent::VerifyRequested {
                context,
                payload: proposal.payload,
            },
        );
        check_fuzz_invariants(&[leader, follower]);
    }

    #[test]
    #[should_panic(expected = "non-leader requested proposal")]
    fn non_leader_proposal_request_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let reporter = audit_reporter(1, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeRequested {
                context: automaton_context(participants[0].clone(), &proposal),
            },
        );
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "automaton contexts disagree on leader")]
    fn correct_automaton_contexts_with_different_leaders_are_rejected() {
        let (participants, schemes) = vote_fixture();
        let reporter_a = audit_reporter(0, &participants, &schemes);
        let reporter_b = audit_reporter(1, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        record_automaton(
            &reporter_a,
            AutomatonEvent::ProposeRequested {
                context: automaton_context(participants[0].clone(), &proposal),
            },
        );
        record_automaton(
            &reporter_b,
            AutomatonEvent::ProposeRequested {
                context: automaton_context(participants[1].clone(), &proposal),
            },
        );
        check_fuzz_invariants(&[reporter_a, reporter_b]);
    }

    #[test]
    fn certification_and_finalize_accept_the_same_exact_proposal() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        record_certify_result(&reporter, &proposal, true);
        reporter.report(Activity::Certification(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        reporter.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal).unwrap(),
        ));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "certification/finalize proposal mismatch")]
    fn certification_and_finalize_with_different_parents_are_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let certified = proposal(5, 3, 0xA);
        let finalized = proposal(5, 4, 0xA);
        record_certify_result(&reporter, &certified, true);
        reporter.report(Activity::Certification(notarization_activity(
            &schemes, 5, 3, 0xA,
        )));
        reporter.report(Activity::Finalize(
            Finalize::sign(&schemes[0], finalized).unwrap(),
        ));
        check_fuzz_invariants(std::slice::from_ref(&reporter));
    }

    #[test]
    fn leader_based_invariants_skip_missing_leader_observation() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
        ));
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[2], proposal(5, 4, 0xB)).unwrap(),
        ));
        // Without a retained leader, honest-leader coherence may not draw a
        // conclusion from the divergent raw observations.
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    fn correct_leader_single_payload_passes() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.leaders
            .lock()
            .insert(View::new(5), participants[0].clone());
        for signer in [0, 1, 2] {
            rep.report(Activity::Notarize(
                Notarize::sign(&schemes[signer], proposal(5, 4, 0xA)).unwrap(),
            ));
        }
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    #[should_panic(expected = "correct leader has conflicting proposal payloads in view 5")]
    fn divergent_payloads_under_correct_leader_are_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.leaders
            .lock()
            .insert(View::new(5), participants[0].clone());
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[0], proposal(5, 4, 0xA)).unwrap(),
        ));
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal(5, 4, 0xB)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    fn payload_coherence_excludes_byzantine_leaders() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.leaders
            .lock()
            .insert(View::new(5), participants[0].clone());
        for (signer, payload) in [(0, 0xA), (0, 0xB), (1, 0xA), (2, 0xB)] {
            rep.report(Activity::Notarize(
                Notarize::sign(&schemes[signer], proposal(5, 4, payload)).unwrap(),
            ));
        }
        let byzantine = HashSet::from([0]);
        check_vote_invariants_with_byzantine(&byzantine, &[rep]);
    }

    #[test]
    fn finalize_vote_with_notarization_passes() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    fn finalize_vote_via_certification_activity_passes() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Certification(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    fn finalize_vote_backed_by_another_reporter_passes() {
        let (participants, schemes) = vote_fixture();
        let mut rep_a = vote_reporter(&participants, &schemes);
        let mut rep_b = vote_reporter(&participants, &schemes);
        rep_a.report(Activity::Finalize(
            Finalize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
        ));
        rep_b.report(Activity::Certification(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep_a, rep_b]);
    }

    #[test]
    #[should_panic(expected = "finalize vote without notarization in view 5")]
    fn finalize_vote_without_notarization_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    #[should_panic(expected = "finalize vote without notarization in view 5")]
    fn finalize_vote_with_mismatched_notarized_payload_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xB,
        )));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    fn byzantine_finalize_vote_without_notarization_is_allowed() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal(5, 4, 0xA)).unwrap(),
        ));
        let byzantine: HashSet<usize> = [0].into_iter().collect();
        check_vote_invariants_with_byzantine(&byzantine, &[rep]);
    }

    #[test]
    #[should_panic(expected = "nullification certificate at genesis view 0")]
    fn nullified_genesis_view_is_rejected() {
        let r = replica(
            views(vec![]),
            views(vec![(0, nullification())]),
            views(vec![]),
        );
        check::<SimplexId>(N, vec![r]);
    }

    #[test]
    #[should_panic(expected = "nullify vote at genesis view 0")]
    fn correct_signer_genesis_vote_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[1], round(0)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    fn byzantine_genesis_vote_is_allowed() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(0)).unwrap(),
        ));
        let byzantine: HashSet<usize> = [0].into_iter().collect();
        check_vote_invariants_with_byzantine(&byzantine, &[rep]);
    }

    #[test]
    #[should_panic(expected = "nullification certificate at genesis view 0")]
    fn nullification_certificate_at_genesis_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Nullification(nullification_activity(&schemes, 0)));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    #[should_panic(expected = "correct signer notarized multiple payloads in view 5")]
    fn certificate_signer_with_conflicting_notarize_vote_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal(5, 4, 0xB)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    #[should_panic(expected = "vote equivocation in view 5")]
    fn nullification_certificate_signer_with_finalize_vote_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Nullification(nullification_activity(&schemes, 5)));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    #[should_panic(expected = "vote equivocation in view 5")]
    fn finalization_certificate_signer_with_nullify_vote_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Finalization(finalization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[1], round(5)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    #[should_panic(expected = "correct signer finalized multiple payloads in view 5")]
    fn finalization_certificate_signer_with_conflicting_finalize_vote_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Finalization(finalization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[1], proposal(5, 4, 0xB)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    fn byzantine_certificate_signer_conflict_is_allowed() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal(5, 4, 0xB)).unwrap(),
        ));
        let byzantine: HashSet<usize> = [1].into_iter().collect();
        check_vote_invariants_with_byzantine(&byzantine, &[rep]);
    }

    #[test]
    #[should_panic(expected = "finalize vote without notarization in view 5")]
    fn finalization_certificate_without_notarization_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Finalization(finalization_activity(
            &schemes, 5, 4, 0xA,
        )));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    fn certificates_with_legal_timeout_overlap_pass() {
        // A notarization and a nullification certificate in one view plus a
        // minority finalize vote is a legal Simplex outcome (notarize, then
        // time out) and must not be flagged.
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Nullification(nullification_activity(&schemes, 5)));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[3], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    #[should_panic(
        expected = "finalization certificate at view 5 coexists with 2 correct nullify signers"
    )]
    fn finalization_with_excess_nullify_signers_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Finalization(finalization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[2], round(5)).unwrap(),
        ));
        rep.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[3], round(5)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    #[should_panic(
        expected = "nullification certificate at view 5 coexists with 2 correct finalize signers"
    )]
    fn nullification_with_excess_finalize_signers_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Nullification(nullification_activity(&schemes, 5)));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[2], proposal(5, 4, 0xA)).unwrap(),
        ));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[3], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    #[should_panic(
        expected = "notarization certificate at view 5 coexists with 2 correct conflicting notarize signers"
    )]
    fn notarization_with_excess_conflicting_notarize_signers_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[2], proposal(5, 4, 0xB)).unwrap(),
        ));
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[3], proposal(5, 4, 0xB)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    #[test]
    #[should_panic(
        expected = "finalization certificate at view 5 coexists with 2 correct conflicting finalize signers"
    )]
    fn finalization_with_excess_conflicting_finalize_signers_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Finalization(finalization_activity(
            &schemes, 5, 4, 0xA,
        )));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[2], proposal(5, 4, 0xB)).unwrap(),
        ));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[3], proposal(5, 4, 0xB)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(&HashSet::new(), &[rep]);
    }

    type ThresholdScheme = bls12381_threshold_vrf::Scheme<Ed25519PublicKey, MinPk>;

    fn threshold_vote_fixture() -> (Vec<Ed25519PublicKey>, Vec<ThresholdScheme>) {
        let fixture = bls12381_threshold_vrf::fixture::<MinPk, _>(
            &mut test_rng(),
            b"invariants-threshold-tests",
            N,
        );
        (fixture.participants, fixture.schemes)
    }

    fn threshold_vote_reporter(
        participants: &[Ed25519PublicKey],
        schemes: &[ThresholdScheme],
    ) -> Reporter<TestRng, ThresholdScheme, RoundRobin, Sha256Digest> {
        let reporter = Reporter::new(
            test_rng(),
            ReporterConfig {
                participants: Set::try_from(participants.to_vec()).expect("unique keys"),
                scheme: schemes[0].clone(),
                elector: RoundRobin::default(),
            },
        );
        reporter.certified.lock().extend((1..=4).map(View::new));
        reporter
    }

    fn threshold_notarization(
        schemes: &[ThresholdScheme],
        payload: u8,
    ) -> SimplexNotarization<ThresholdScheme, Sha256Digest> {
        let votes: Vec<_> = schemes[..Q]
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal(5, 4, payload)).unwrap())
            .collect();

        SimplexNotarization::from_notarizes(&schemes[0], &votes, &Sequential).unwrap()
    }

    #[test]
    #[should_panic(
        expected = "notarization certificate at view 5 coexists with 2 correct conflicting notarize signers"
    )]
    fn non_attributable_certificate_with_f_plus_one_opposing_votes_is_rejected() {
        assert!(
            !<ThresholdScheme as commonware_cryptography::certificate::Scheme>::is_attributable()
        );

        let (participants, schemes) = threshold_vote_fixture();
        let mut reporter = threshold_vote_reporter(&participants, &schemes);

        let certificate = threshold_notarization(&schemes, 0xA);
        assert!(get_signers::<ThresholdScheme>(&certificate.certificate, N as usize,).is_none());

        reporter.report(Activity::Notarization(certificate));

        // N=4, f=1: two opposing correct voters exceed f.
        for signer in [2, 3] {
            reporter.report(Activity::Notarize(
                Notarize::sign(&schemes[signer], proposal(5, 4, 0xB)).unwrap(),
            ));
        }

        check_vote_invariants_with_byzantine(&HashSet::new(), &[reporter]);
    }

    #[test]
    fn non_attributable_certificate_with_exactly_f_opposing_votes_passes() {
        let (participants, schemes) = threshold_vote_fixture();
        let mut reporter = threshold_vote_reporter(&participants, &schemes);

        reporter.report(Activity::Notarization(threshold_notarization(
            &schemes, 0xA,
        )));

        // Exactly f=1 opposing correct voter can be outside the certificate.
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[3], proposal(5, 4, 0xB)).unwrap(),
        ));

        check_vote_invariants_with_byzantine(&HashSet::new(), &[reporter]);
    }
}
