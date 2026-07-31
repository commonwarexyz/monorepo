use crate::{
    bounds,
    simplex::Simplex,
    simplex_audit::{AutomatonEvent, Completion, Event, RecordingReporter, summaries},
    types::{Finalization, Notarization, Nullification, ReplicaState},
};
use commonware_codec::{Encode, Read};
use commonware_consensus::{
    simplex::{
        elector::{Config as Elector, Elector as ElectorInstance},
        mocks::reporter::Reporter,
        scheme,
        scheme::Scheme,
        types::{Activity, Attributable, Proposal},
    },
    types::{Epoch, Round, TermLength, View},
};
use commonware_cryptography::{
    certificate::{self, Signers},
    sha256::Digest as Sha256Digest,
};
use commonware_utils::{Participant, ordered::Quorum};
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
    fn check_safety(self, term_length: TermLength);
}

/// Checks Simplex safety using the provided observations.
///
/// This remains the single entrypoint: the concrete observation type determines
/// whether only the basic invariants or also the audit-history
/// invariants are observable.
pub fn check<P: Simplex>(term_length: TermLength, observations: impl SafetyObservations<P>) {
    observations.check_safety(term_length);
}

impl<P: Simplex> SafetyObservations<P> for Vec<ReplicaState> {
    fn check_safety(self, term_length: TermLength) {
        check_basic_invariants(term_length, self);
    }
}

impl<P, E, L> SafetyObservations<P> for &[Reporter<E, P::Scheme, L, Sha256Digest>]
where
    P: Simplex,
    E: CryptoRng,
    P::Scheme: Scheme<Sha256Digest>,
    L: Elector<P::Scheme>,
{
    fn check_safety(self, term_length: TermLength) {
        check_basic_invariants(term_length, extract(self));
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
    fn check_safety(self, term_length: TermLength) {
        check_fuzz_invariants(term_length, self);
        check_basic_invariants(term_length, extract(summaries(self)));
    }
}

// Intentionally restates View::covers with independent integer arithmetic:
// the fuzz oracle must not delegate to the production term predicates
// (same_term, term_start) or a bug in them could hide from the fuzzer.
// View 0 (genesis) is its own term; for views >= 1, term boundaries are
// [1, term_length], [term_length + 1, 2 * term_length], ...
fn nullification_conflicts(
    nullified_view: u64,
    finalized_view: u64,
    term_length: TermLength,
) -> bool {
    if nullified_view > finalized_view {
        return false;
    }
    if nullified_view == 0 {
        return finalized_view == 0;
    }
    let term_length = term_length.get();
    (nullified_view - 1) / term_length == (finalized_view - 1) / term_length
}

// First view of the term containing `view`, with the same independent
// integer arithmetic as `nullification_conflicts`. Genesis (view 0) is its
// own term.
fn term_start(view: u64, term_length: TermLength) -> u64 {
    if view == 0 {
        return 0;
    }
    let term_length = term_length.get();
    ((view - 1) / term_length) * term_length + 1
}

// First view of the term after the one containing `view`: the view a
// nullification of `view` advances entry to. The term after genesis starts
// at view 1.
fn next_term_start(view: u64, term_length: TermLength) -> u64 {
    if view == 0 {
        return 1;
    }
    let term_length = term_length.get();
    ((view - 1) / term_length + 1) * term_length + 1
}

// Whether a nullification at `nullified` covers `view`: one nullification
// covers its own view through the end of its term, so a single certificate
// legalizes skipping the whole term tail.
fn nullification_covers(nullified: u64, view: u64, term_length: TermLength) -> bool {
    nullified != 0 && nullified <= view && {
        let term_length = term_length.get();
        (nullified - 1) / term_length == (view - 1) / term_length
    }
}

// Whether some nullification in `nullified` advances entry directly to
// `view`: a nullification of `u` advances to `next_term_start(u)`, so the
// candidates lie in the immediately preceding term.
fn entered_via_nullification(
    view: u64,
    nullified: &BTreeSet<u64>,
    term_length: TermLength,
) -> bool {
    nullified
        .range(view.saturating_sub(term_length.get())..view)
        .any(|&nullified| next_term_start(nullified, term_length) == view)
}

// Round-keyed variant of `entered_via_nullification` for the append-only
// audit history (single-epoch: candidates share the entry view's epoch).
fn entered_round_via_nullification(
    view: u64,
    epoch: Epoch,
    observed: &BTreeSet<Round>,
    term_length: TermLength,
) -> bool {
    observed
        .range(
            Round::new(epoch, View::new(view.saturating_sub(term_length.get())))
                ..Round::new(epoch, View::new(view)),
        )
        .any(|nullified| next_term_start(nullified.view().get(), term_length) == view)
}

fn check_basic_invariants(term_length: TermLength, replicas: Vec<ReplicaState>) {
    // Invariants:
    // - no_conflicting_quorum_notarizations
    // - no_conflicting_quorum_finalizations
    //
    // Across all reported certificates, at most one (parent, payload) may be
    // notarized in a view, and at most one (parent, payload) may be finalized in
    // a view. Replicas without a certificate observation for that view impose no
    // requirement.
    type Identity = (u64, Sha256Digest);
    let mut notarized_by_view: BTreeMap<u64, (usize, Identity)> = BTreeMap::new();
    let mut nullified_by_view: BTreeMap<u64, usize> = BTreeMap::new();
    let mut finalized_by_view: BTreeMap<u64, (usize, Identity)> = BTreeMap::new();
    for (idx, (notarizations, nullifications, finalizations)) in replicas.iter().enumerate() {
        for (&view, d) in notarizations.iter() {
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
        for &view in nullifications.keys() {
            nullified_by_view.entry(view).or_insert(idx);
        }
        for (&view, d) in finalizations.iter() {
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
    for finalized_view in finalized_by_view.keys() {
        for nullified_view in nullified_by_view.keys() {
            assert!(
                !nullification_conflicts(*nullified_view, *finalized_view, term_length),
                "Invariant violation: view {nullified_view} is nullified but view {finalized_view} is finalized in the same term",
            )
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
    // A notarization at view v with parent p must reference genesis or a view
    // with a recorded notarization/finalization certificate, and every view in
    // (p, v) must be covered by a recorded nullification: one nullification
    // covers its own view through the end of its term, so the covering
    // certificate for a skipped view may sit at any earlier view of the same
    // term, including at the notarized parent itself. Skipping a finalized
    // view is caught without a dedicated scan: the skipped view needs a
    // covering nullification, which finalized/nullified disjointness forbids.
    // This checks only the global extracted certificate graph; it does not
    // reconstruct unreported history or prove local possession or event ordering.
    // Only notarized links are walked: finalization_requires_notarization has
    // already forced every finalized view onto an identical notarized link.
    //
    // Invariant: intra_term_proposals_never_skip
    // Entry into a mid-term view is only sequential (a nullification advances
    // directly to the next term start), so a proposal at a view other than its
    // term start must extend exactly the preceding view, regardless of
    // nullification coverage.
    for (&view, &(idx, (parent, _))) in notarized_by_view.iter() {
        assert!(
            parent < view,
            "Invariant violation: replica {idx} has notarization in view {view} with parent {parent}"
        );
        assert!(
            parent == 0
                || notarized_by_view.contains_key(&parent)
                || finalized_by_view.contains_key(&parent),
            "Invariant violation: replica {idx} has notarization in view {view} with uncertified parent {parent}"
        );
        assert!(
            term_start(view, term_length) == view || parent + 1 == view,
            "Invariant violation: replica {idx} has mid-term notarization in view {view} with parent {parent} (term start {})",
            term_start(view, term_length)
        );
        for skipped in parent + 1..view {
            assert!(
                nullified_by_view
                    .keys()
                    .any(|&nullified| nullification_covers(nullified, skipped, term_length)),
                "Invariant violation: replica {idx} has notarization in view {view} with parent {parent} but view {skipped} has no covering nullification"
            );
        }
    }
}

/// Checks invariants that require per-signer information (votes and fault
/// evidence). `faults` is the number of Byzantine nodes by participant index
/// (`0..faults`); only correct nodes (`faults..n`) are checked for equivocation.
pub fn check_vote_invariants<E, S, L>(
    faults: usize,
    elector: L,
    epoch: Epoch,
    term_length: TermLength,
    reporters: &[Reporter<E, S, L, Sha256Digest>],
) where
    E: CryptoRng,
    S: Scheme<Sha256Digest>,
    S::PublicKey: Eq + Hash + Clone,
    L: Elector<S> + Clone,
{
    let byzantine: HashSet<usize> = (0..faults).collect();
    check_vote_invariants_with_byzantine(&byzantine, elector, epoch, term_length, reporters);
}

/// Invariant: per_certificate_leader_derivation_coherence
/// Re-derives leader election from every retained certificate, not only the
/// first certificate each reporter observed (which is all `leaders` records).
/// Every certificate retained for a view must elect one participant for the
/// view it advances entry to, and that participant must equal the recorded
/// leader schedule wherever any reporter retained an entry. Notarizations and
/// finalizations advance to the following view; a nullification advances
/// directly to the next term start.
///
/// `elector` must be the same configured instance the harness hands to both
/// engines and reporters for the checked target (`P::elector(term_length)`).
/// Elector configs are contractually deterministic, and for seed-carrying
/// schemes any valid certificate for a view embeds the unique threshold seed,
/// so the choice of certificate cannot legally change the elected leader.
///
/// Source: the `simplex::elector` configuration contract requires all honest
/// participants to agree on each round's leader, and the instantiated
/// protocol's "Embedded VRF" documentation guarantees one seed per view
/// regardless of certificate type.
///
/// Every retained certificate additionally requires that the SAME reporter
/// recorded a leader at the derived target view, and that it matches: the
/// mock records an election for every certificate it retains, so a missing
/// target key means the recording used the wrong view (e.g. the rotation
/// target instead of the term anchor) and must not pass silently just
/// because the derived and recorded key sets are disjoint.
///
/// Derivations are keyed by `View`, matching the summary Reporter's per-view
/// maps. This collapses epochs, so the check is sound only for the current
/// single-epoch harnesses; a multi-epoch backend needs `Round`-keyed summaries
/// first. The summary maps also retain only the latest certificate of each kind
/// per view, so overwrites can hide a conflict but cannot create one.
pub fn check_certificate_leader_derivation<E, S, L>(
    elector: L,
    term_length: TermLength,
    reporters: &[Reporter<E, S, L, Sha256Digest>],
) where
    E: CryptoRng,
    S: Scheme<Sha256Digest>,
    S::PublicKey: Eq + Hash + Clone,
    L: Elector<S>,
{
    let Some(first) = reporters.first() else {
        return;
    };
    let elector = elector.build(&first.participants);
    let mut derived: BTreeMap<u64, (S::PublicKey, &'static str)> = BTreeMap::new();
    for reporter in reporters {
        let mut derive = |round: Round, certificate: &_, kind: &'static str, target: u64| {
            let next = Round::new(round.epoch(), View::new(target));
            let leader = elector.elect(next, Some(certificate));
            let leader = first
                .participants
                .key(leader)
                .expect("elected leader must be a participant")
                .clone();
            match derived.entry(next.view().get()) {
                Entry::Vacant(entry) => {
                    entry.insert((leader.clone(), kind));
                }
                Entry::Occupied(entry) => {
                    let (existing, existing_kind) = entry.get();
                    assert!(
                        existing == &leader,
                        "Invariant violation: retained certificates derive conflicting leaders for view {}: {existing_kind} derives {:?} but {kind} derives {:?}",
                        next.view().get(),
                        existing.as_ref(),
                        leader.as_ref()
                    );
                }
            }
            let recorded = reporter.leaders.lock();
            match recorded.get(&next.view()) {
                None => panic!(
                    "Invariant violation: {kind} for view {} lacks a recorded leader at its target view {}: every retained certificate must record its election at the derived target",
                    round.view().get(),
                    next.view().get()
                ),
                Some(recorded_leader) => assert!(
                    recorded_leader == &leader,
                    "Invariant violation: certificate-derived leader disagrees with recorded leader for view {}: {kind} derives {:?} but recorded is {:?}",
                    next.view().get(),
                    leader.as_ref(),
                    recorded_leader.as_ref()
                ),
            }
        };
        for certificate in reporter.notarizations.lock().values() {
            derive(
                certificate.round(),
                &certificate.certificate,
                "notarization",
                certificate.round().view().get() + 1,
            );
        }
        for certificate in reporter.nullifications.lock().values() {
            derive(
                certificate.round,
                &certificate.certificate,
                "nullification",
                next_term_start(certificate.round.view().get(), term_length),
            );
        }
        for certificate in reporter.finalizations.lock().values() {
            derive(
                certificate.round(),
                &certificate.certificate,
                "finalization",
                certificate.round().view().get() + 1,
            );
        }
    }
    for reporter in reporters {
        let recorded = reporter.leaders.lock();
        for (view, leader) in recorded.iter() {
            if let Some((derived_leader, kind)) = derived.get(&view.get()) {
                assert!(
                    derived_leader == leader,
                    "Invariant violation: certificate-derived leader disagrees with recorded leader for view {}: {kind} derives {:?} but recorded is {:?}",
                    view.get(),
                    derived_leader.as_ref(),
                    leader.as_ref()
                );
            }
        }
    }
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
/// scenario generator and may occupy arbitrary indices. `elector` must be the
/// same configured instance the harness hands to engines and reporters (the
/// twins wrapper for Twins runs), so per-certificate leader derivation runs
/// on adversarial paths too.
pub fn check_vote_invariants_with_byzantine<E, S, L>(
    byzantine: &HashSet<usize>,
    elector: L,
    epoch: Epoch,
    term_length: TermLength,
    reporters: &[Reporter<E, S, L, Sha256Digest>],
) where
    E: CryptoRng,
    S: Scheme<Sha256Digest>,
    S::PublicKey: Eq + Hash + Clone,
    L: Elector<S> + Clone,
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

    // View 1 is entered from the genesis floor without a certificate, so no
    // reporter ever records a leader for it; derive it directly from the
    // configured elector at the harness epoch so the view-1 leader always
    // participates in the constancy and payload-coherence checks below, even
    // when only raw votes and no certificates were retained.
    if let Some(first) = reporters.first() {
        let elected = elector
            .clone()
            .build(&first.participants)
            .elect(Round::new(epoch, View::new(1)), None);
        leaders.insert(
            1,
            first
                .participants
                .key(elected)
                .expect("elected leader must be a participant")
                .clone(),
        );
    }

    // Invariant: stable_term_leader_constancy
    // All certificate-derived leaders recorded inside one leader term must
    // name the same participant: a term has exactly one leader, and only a
    // term boundary may rotate it. Views are grouped with the same
    // independent term arithmetic as the coverage checks. Leader records are
    // keyed by `View`, so this is sound only for the single-epoch harnesses.
    let mut term_leaders: BTreeMap<u64, (u64, S::PublicKey)> = BTreeMap::new();
    for (&view, leader) in &leaders {
        if view == 0 {
            continue;
        }
        match term_leaders.entry((view - 1) / term_length.get()) {
            Entry::Vacant(entry) => {
                entry.insert((view, leader.clone()));
            }
            Entry::Occupied(entry) => {
                let (first_view, first_leader) = entry.get();
                assert!(
                    first_leader == leader,
                    "Invariant violation: leader changes inside a stable term: view {first_view} has {:?} but view {view} has {:?}",
                    first_leader.as_ref(),
                    leader.as_ref()
                );
            }
        }
    }

    // Invariant: contiguous_certificate_progression
    // With a genesis floor, observing a certificate at view v > 1 implies
    // that entry into v was possible: either a value certificate
    // (notarization or finalization) exists at v-1, or some nullification
    // advances directly to v. A nullification of u covers the rest of u's
    // term and advances entry to the next term start, never to an
    // intermediate view; under one-view terms this reduces to the classic
    // any-certificate-at-v-1 rule. This says nothing about block ancestry,
    // which legally skips covered views and is checked by chain_consistency.
    //
    // Source: the Simplex paper's protocol and safety proof advance a process
    // from a view only with a block or dummy-block certificate; the
    // stable-leader extension advances a nullified view directly to the next
    // term ("Specification for View v", "Joining Consensus").
    let mut certified_views = BTreeSet::new();
    let mut value_progress_views = BTreeSet::new();
    let mut nullified_views: BTreeSet<u64> = BTreeSet::new();
    for reporter in reporters {
        certified_views.extend(reporter.certified.lock().iter().map(|view| view.get()));
        value_progress_views.extend(reporter.notarizations.lock().keys().map(|view| view.get()));
        value_progress_views.extend(reporter.finalizations.lock().keys().map(|view| view.get()));
        nullified_views.extend(reporter.nullifications.lock().keys().map(|view| view.get()));
    }
    // A certified view with no recorded nullification can only carry a value
    // certificate: the mock pairs every `certified` insert with a map insert,
    // so the fallback fires only for value-certified views (and for fixtures
    // that model prior history through `certified` alone).
    for &view in &certified_views {
        if !nullified_views.contains(&view) {
            value_progress_views.insert(view);
        }
    }
    for &view in &certified_views {
        if view > 1 {
            assert!(
                value_progress_views.contains(&(view - 1))
                    || entered_via_nullification(view, &nullified_views, term_length),
                "Invariant violation: certificate progression reaches view {view} without a value certificate at view {} or a nullification advancing to it",
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

    // Invariant: no_finalized_view_nullified (all-observer certificate form)
    // The basic-invariant checker enforces this over extracted honest states,
    // but adversarial harnesses (Twins, ByzzFuzz, Mallory) extract only
    // correct observers there. Verified certificates retained by ANY observer
    // are unforgeable, so a nullification and a later-or-equal finalization
    // in the same term conflict regardless of which observer retained them.
    for &nullified in &nullification_cert_views {
        for &finalized in finalization_cert_payloads.keys() {
            assert!(
                !nullification_conflicts(nullified, finalized, term_length),
                "Invariant violation: view {nullified} is nullified but view {finalized} is finalized in the same term",
            );
        }
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

    // Invariant: same_term_finalize_after_nullify_requires_healing
    // (summary form of own_nullify_gates_same_term_finalize) A correct signer
    // that nullified view u may cast a finalize vote at a later view v of the
    // same term only if a healing finalization certificate is retained in
    // [u, v). A correct node's current view never decreases, so u < v implies
    // the nullify came first even without the append-only log. Unlike the
    // audit form this cannot see observation order, so any retained healing
    // evidence excuses the pair; same-view pairs stay with the unconditional
    // equivocation check above, and cross-term pairs need no healing.
    let mut unhealed: BTreeMap<(u64, u64), Vec<Vec<u8>>> = BTreeMap::new();
    for (&nullified_view, nullifiers) in seen_nullify.iter() {
        for (&finalized_view, finalizers) in seen_finalize.iter() {
            if nullified_view >= finalized_view
                || !nullification_conflicts(nullified_view, finalized_view, term_length)
            {
                continue;
            }
            if finalization_cert_payloads
                .range(nullified_view..finalized_view)
                .next()
                .is_some()
            {
                continue;
            }
            let mut offenders: Vec<_> = nullifiers
                .intersection(finalizers)
                .map(|pk| pk.as_ref().to_vec())
                .collect();
            if offenders.is_empty() {
                continue;
            }
            offenders.sort_unstable();
            unhealed.insert((nullified_view, finalized_view), offenders);
        }
    }
    if let Some(((nullified_view, finalized_view), offenders)) = unhealed.first_key_value() {
        panic!(
            "Invariant violation: correct signer finalized view {finalized_view} after nullifying view {nullified_view} in the same term without healing finalization: {offenders:?}; all violations: {unhealed:?}"
        );
    }

    // Invariant: correct_view_entry_requires_predecessor_certificate
    // Every vote attributed to a correct signer above view 1 proves that the
    // signer entered that view, which requires a value certificate at the
    // preceding view or a nullification advancing entry directly to it (the
    // next term start). Direct votes and signers exposed by attributable
    // certificates are both evidence of participation. The evidence is
    // required only in the aggregate certificate union: this does not infer
    // local possession, observation order, or signers for non-attributable
    // certificates.
    //
    // Source: the Simplex paper's view-transition protocol permits voting in a
    // new view only after leaving the prior view with a value or skip
    // certificate; the stable-leader extension advances a nullified view
    // directly to the next term ("Specification for View v", "Joining
    // Consensus").
    let mut premature_votes = BTreeSet::new();
    for (view, signer) in &correct_vote_views {
        if *view > 1
            && !value_progress_views.contains(&(view - 1))
            && !entered_via_nullification(*view, &nullified_views, term_length)
        {
            premature_votes.insert((*view, signer.clone()));
        }
    }
    if let Some((view, signer)) = premature_votes.first() {
        panic!(
            "Invariant violation: correct signer {signer:?} voted in view {view} without entry evidence at predecessor view {}; all violations: {premature_votes:?}",
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

    check_certificate_leader_derivation(elector, term_length, reporters);
}

/// Checks invariants that require the append-only activity and automaton history
/// collected by the dedicated audit targets. Every reporter in this slice must
/// belong to a correct engine; adversarial observers remain available to the
/// separate vote/fault checker, but must not be passed to [`check`] as safety
/// observations.
fn check_fuzz_invariants<E, S, L>(
    term_length: TermLength,
    reporters: &[RecordingReporter<E, S, L, Sha256Digest>],
) where
    E: CryptoRng,
    S: Scheme<Sha256Digest>,
    S::PublicKey: Eq + Hash + Clone,
    L: Elector<S>,
    L::Elector: Clone,
{
    type ExactVotes = BTreeMap<(Round, Vec<u8>), BTreeSet<Proposal<Sha256Digest>>>;
    type ApplicationProposal = (Round, (View, Sha256Digest), Sha256Digest);
    type CertificateBacking = BTreeSet<(Proposal<Sha256Digest>, Option<Vec<Vec<u8>>>)>;
    type CertifyEvidence = BTreeMap<Vec<u8>, BTreeSet<(Round, Sha256Digest)>>;
    type AcceptanceEvidence = BTreeMap<Vec<u8>, BTreeSet<(Round, View, Sha256Digest)>>;

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
    let mut genesis_parent_digests: BTreeMap<Sha256Digest, Vec<u8>> = BTreeMap::new();
    let mut notarization_backing: CertificateBacking = BTreeSet::new();
    let mut finalization_backing: CertificateBacking = BTreeSet::new();
    let mut certify_evidence: CertifyEvidence = BTreeMap::new();
    let mut acceptance_evidence: AcceptanceEvidence = BTreeMap::new();

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
        let mut observed_notarizations: BTreeSet<Proposal<Sha256Digest>> = BTreeSet::new();
        let mut observed_nullifications: BTreeSet<Round> = BTreeSet::new();
        let mut successful_certifications: BTreeSet<(Round, Sha256Digest)> = BTreeSet::new();
        let mut failed_certifications: BTreeSet<(Round, Sha256Digest)> = BTreeSet::new();
        let mut reported_certifications: BTreeMap<Round, BTreeSet<Proposal<Sha256Digest>>> =
            BTreeMap::new();
        let mut local_finalizes: BTreeMap<Round, BTreeSet<Proposal<Sha256Digest>>> =
            BTreeMap::new();
        let mut certified_parents: BTreeSet<(Round, Sha256Digest)> = BTreeSet::new();
        let mut certified_activity_views: BTreeSet<u64> = BTreeSet::new();
        let mut predecessor_evidence: BTreeSet<u64> = BTreeSet::new();
        let mut own_nullified: BTreeSet<Round> = BTreeSet::new();
        let mut observed_finalizations: BTreeSet<Round> = BTreeSet::new();
        let mut accepted_signed: BTreeSet<(Round, View, Sha256Digest)> = BTreeSet::new();

        // Resolves an attributable certificate's signer bitmap to participant
        // keys; `None` for non-attributable schemes.
        let signer_keys = |certificate: &<S as certificate::Verifier>::Certificate| {
            get_signers::<S>(certificate, participants.len()).map(|signers| {
                signers
                    .iter()
                    .map(|signer| {
                        participants
                            .key(signer)
                            .expect("certificate signer must be a participant")
                            .as_ref()
                            .to_vec()
                    })
                    .collect::<Vec<_>>()
            })
        };

        // Invariant: local_notarize_parent_gaps_are_nullified
        // Before a correct engine emits a notarize vote for a proposal at view
        // v with parent p, it must already have observed a nullification
        // covering every discarded view in (p, v): one nullification covers
        // its own view through the end of its term, and the covering
        // certificate may sit at the notarized parent itself. The dedicated
        // audit targets start from Floor::Genesis, so the covering
        // certificates must appear in their retained history. A future
        // non-genesis audit target must record its floor and begin the
        // required range above that floor.
        //
        // Invariant: intra_term_proposals_never_skip
        // (local-vote form) A proposal at a view other than its term start
        // must extend exactly the preceding view, regardless of coverage.
        //
        // Source: Context's parent documentation states that skipping any view
        // without possessing its nullification could result in a fork; the
        // stable-leader extension advances a nullified view directly to the
        // next term. This is the per-node vote-history strengthening of the
        // certificate-graph chain_consistency invariant.
        let assert_parent_gap_nullified =
            |proposal: &Proposal<Sha256Digest>, observed: &BTreeSet<Round>| {
                let parent = proposal.parent.get();
                let view = proposal.round.view().get();
                // Parent ordering holds unconditionally; a view-0 notarize can
                // never satisfy it (no parent precedes genesis).
                assert!(
                    parent < view,
                    "Invariant violation: local notarize with parent {parent} not below view {view}: observer {observer_bytes:?}, proposal {proposal:?}"
                );
                assert!(
                    term_start(view, term_length) == view || parent + 1 == view,
                    "Invariant violation: local notarize skips a view inside its term: observer {observer_bytes:?}, proposal {proposal:?}"
                );
                let epoch = proposal.round.epoch();
                for skipped in parent.saturating_add(1)..view {
                    let covered = observed
                        .range(
                            Round::new(epoch, View::new(term_start(skipped, term_length)))
                                ..=Round::new(epoch, View::new(skipped)),
                        )
                        .next()
                        .is_some();
                    assert!(
                        covered,
                        "Invariant violation: local notarize skips view {skipped} without covering nullification: observer {observer_bytes:?}, proposal {proposal:?}"
                    );
                }
            };

        for recorded in &events {
            match &recorded.event {
                Event::Activity { valid: false, .. } => {}
                Event::Activity {
                    valid: true,
                    activity,
                } => {
                    // These sets are deliberately updated while walking the
                    // append-only log so later checks establish prior local
                    // observation rather than eventual or cross-node evidence.
                    match activity {
                        Activity::Notarization(certificate) => {
                            observed_notarizations.insert(certificate.proposal.clone());
                        }
                        Activity::Nullification(certificate) => {
                            observed_nullifications.insert(certificate.round());
                        }
                        _ => {}
                    }

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
                            assert_parent_gap_nullified(&vote.proposal, &observed_nullifications);
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

                            // Invariant: local_finalize_requires_matching_notarization
                            // Before a correct engine emits its finalize vote, its
                            // own history must contain a notarization certificate
                            // for the identical full proposal, including the parent.
                            // This intentionally applies to locally signed Finalize
                            // activities, not received Finalization certificates,
                            // which may be learned without the underlying
                            // notarization being reported locally.
                            //
                            // Source: the instantiated voter round's
                            // construct_finalize path requires a stored
                            // notarization and finalizes that notarization's exact
                            // proposal.
                            assert!(
                                observed_notarizations.contains(&vote.proposal),
                                "Invariant violation: local finalize without prior matching notarization: observer {observer_bytes:?}, proposal {:?}",
                                vote.proposal
                            );
                            local_finalizes
                                .entry(vote.proposal.round)
                                .or_default()
                                .insert(vote.proposal.clone());
                        }
                        _ => {}
                    }

                    match activity {
                        Activity::Notarize(vote) if vote.signer() == observer_idx => {
                            // Invariant: own_nullify_is_terminal_for_view_participation
                            // Once a correct engine abandons a view with its own
                            // nullify vote, it must never sign a notarize vote for
                            // that view. The reverse order (notarize, then time
                            // out and nullify) is legal and never flagged.
                            //
                            // Source: the Simplex paper's dummy-vote rule (after
                            // voting for the dummy block a player never votes for
                            // the leader block of that iteration). The voter round
                            // permanently refuses notarize construction once
                            // broadcast_nullify is set.
                            assert!(
                                !own_nullified.contains(&vote.proposal.round),
                                "Invariant violation: local notarize after own nullify: observer {observer_bytes:?}, proposal {:?}",
                                vote.proposal
                            );

                            // Invariant: local_view_entry_requires_certified_predecessor
                            // A correct engine can enter view v only through a
                            // finalization or successful certification of view
                            // v-1, or through an observed nullification that
                            // advances entry directly to v (the next term
                            // start), each reported before any view-v vote can
                            // exist. A bare notarization does not advance the
                            // view, and a nullification inside a stable term
                            // never authorizes the immediately following view.
                            //
                            // Source: the Simplex view-transition rule (leave a
                            // view only with a value or skip certificate),
                            // strengthened by this implementation's
                            // "Notarizations advance the view if-and-only-if the
                            // application certifies them" and the stable-leader
                            // rule that nullification advances to the next term.
                            let view = vote.proposal.round.view().get();
                            if view >= 2 {
                                assert!(
                                    predecessor_evidence.contains(&(view - 1))
                                        || entered_round_via_nullification(
                                            view,
                                            vote.proposal.round.epoch(),
                                            &observed_nullifications,
                                            term_length,
                                        ),
                                    "Invariant violation: local notarize without entry evidence for view {view}: observer {observer_bytes:?}, proposal {:?}",
                                    vote.proposal
                                );
                            }
                        }
                        Activity::Nullify(vote) if vote.signer() == observer_idx => {
                            // Invariant: local_view_entry_requires_certified_predecessor
                            // (see the notarize arm above; nullify votes are
                            // current-view-only in the voter).
                            let view = vote.round.view().get();
                            if view >= 2 {
                                assert!(
                                    predecessor_evidence.contains(&(view - 1))
                                        || entered_round_via_nullification(
                                            view,
                                            vote.round.epoch(),
                                            &observed_nullifications,
                                            term_length,
                                        ),
                                    "Invariant violation: local nullify without entry evidence for view {view}: observer {observer_bytes:?}, round {:?}",
                                    vote.round
                                );
                            }
                            own_nullified.insert(vote.round);
                        }
                        Activity::Finalize(vote) if vote.signer() == observer_idx => {
                            // Invariant: own_nullify_gates_same_term_finalize
                            // Inside one term, a correct engine that abandoned a
                            // view with its own nullify vote may finalize a
                            // later view of that term only after observing a
                            // finalization that heals exactly that gap: at or
                            // above the abandoned view and strictly below the
                            // view being finalized. A finalization at or above
                            // the finalize view is no evidence the gap healed.
                            // A nullify in an earlier term needs no healing
                            // (entry moved through a term boundary), and
                            // same-view nullify+finalize is already fault
                            // evidence.
                            let view = vote.proposal.round.view().get();
                            let epoch = vote.proposal.round.epoch();
                            if view >= 1
                                && let Some(nullified) = own_nullified
                                    .range(
                                        Round::new(epoch, View::new(term_start(view, term_length)))
                                            ..Round::new(epoch, View::new(view)),
                                    )
                                    .next_back()
                            {
                                let healed = observed_finalizations
                                    .range(*nullified..Round::new(epoch, View::new(view)))
                                    .next()
                                    .is_some();
                                assert!(
                                    healed,
                                    "Invariant violation: local finalize after own same-term nullify without healing finalization: observer {observer_bytes:?}, nullified {nullified:?}, proposal {:?}",
                                    vote.proposal
                                );
                            }
                        }
                        Activity::Notarization(certificate) => {
                            notarization_backing.insert((
                                certificate.proposal.clone(),
                                signer_keys(&certificate.certificate),
                            ));
                        }
                        Activity::Certification(certificate) => {
                            let view = certificate.proposal.round.view().get();
                            predecessor_evidence.insert(view);
                            certified_activity_views.insert(view);
                            certified_parents
                                .insert((certificate.proposal.round, certificate.proposal.payload));
                            notarization_backing.insert((
                                certificate.proposal.clone(),
                                signer_keys(&certificate.certificate),
                            ));
                        }
                        Activity::Finalization(certificate) => {
                            let view = certificate.proposal.round.view().get();
                            predecessor_evidence.insert(view);
                            certified_activity_views.insert(view);
                            certified_parents
                                .insert((certificate.proposal.round, certificate.proposal.payload));
                            observed_finalizations.insert(certificate.proposal.round);
                            finalization_backing.insert((
                                certificate.proposal.clone(),
                                signer_keys(&certificate.certificate),
                            ));
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

                    match event {
                        AutomatonEvent::ProposeRequested { context }
                        | AutomatonEvent::VerifyRequested { context, .. } => {
                            // Invariant: own_nullify_is_terminal_for_view_participation
                            // A correct engine never dispatches proposal
                            // construction or verification for a view it already
                            // abandoned with its own nullify vote. Certification
                            // is exempt: it legally continues after a nullify.
                            assert!(
                                !own_nullified.contains(&context.round),
                                "Invariant violation: application request after own nullify: observer {observer_bytes:?}, round {:?}",
                                context.round
                            );

                            // Invariant: automaton_context_parent_certified_with_nullified_gaps
                            // Every application context's parent must be locally
                            // certified: for parent view p > 0 the same log must
                            // already hold a Certification/Finalization for
                            // exactly (p, parent digest) or a successful certify
                            // result for it, plus a covering nullification for
                            // every view in (p, child view) (one nullification
                            // covers its view through the end of its term).
                            // Genesis parents are compared across nodes below.
                            // Scoped to the Floor::Genesis single-epoch audit
                            // targets (the recorded parent omits its epoch).
                            //
                            // Source: "If the container's parent is finalized (or
                            // both notarized and certified) ... and we have
                            // nullifications for all views between", and
                            // Context's parent documentation (skipping a view
                            // without its nullification could fork).
                            let (parent_view, parent_digest) = context.parent;
                            let child_view = context.round.view().get();
                            // Parent ordering holds unconditionally, even when
                            // the child sits at a term start where the
                            // sequential-parent rule below would not bind. A
                            // view-0 context can never satisfy it (no parent
                            // precedes genesis).
                            assert!(
                                parent_view.get() < child_view,
                                "Invariant violation: context parent {parent_view:?} not below child round {:?}: observer {observer_bytes:?}",
                                context.round
                            );
                            // Invariant: intra_term_proposals_never_skip
                            // (context form) A context at a view other than its
                            // term start must extend exactly the preceding
                            // view, even when the context never becomes a vote.
                            assert!(
                                term_start(child_view, term_length) == child_view
                                    || parent_view.get() + 1 == child_view,
                                "Invariant violation: mid-term context skips views: observer {observer_bytes:?}, parent view {parent_view:?}, child round {:?}",
                                context.round
                            );
                            if parent_view.get() == 0 {
                                genesis_parent_digests
                                    .entry(parent_digest)
                                    .or_insert_with(|| observer_bytes.clone());
                            } else {
                                let parent_round = Round::new(context.round.epoch(), parent_view);
                                assert!(
                                    certified_parents.contains(&(parent_round, parent_digest))
                                        || successful_certifications
                                            .contains(&(parent_round, parent_digest)),
                                    "Invariant violation: context parent without local certification: observer {observer_bytes:?}, parent ({parent_view:?}, {parent_digest:?}), child round {:?}",
                                    context.round
                                );
                            }
                            for skipped in parent_view.get().saturating_add(1)..child_view {
                                let covered = observed_nullifications
                                    .range(
                                        Round::new(
                                            context.round.epoch(),
                                            View::new(term_start(skipped, term_length)),
                                        )
                                            ..=Round::new(
                                                context.round.epoch(),
                                                View::new(skipped),
                                            ),
                                    )
                                    .next()
                                    .is_some();
                                assert!(
                                    covered,
                                    "Invariant violation: context skips view {skipped} without covering nullification: observer {observer_bytes:?}, child round {:?}",
                                    context.round
                                );
                            }
                        }
                        _ => {}
                    }

                    match event {
                        AutomatonEvent::VerifyRequested { context, .. } => {
                            // Invariant: verify_requested_only_for_foreign_leader
                            // A correct node never asks its application to verify
                            // in a round it leads: the leader's own payload is
                            // committed through propose, and the voter round
                            // structurally excludes the leader signer from
                            // verification.
                            assert!(
                                &context.leader != observer,
                                "Invariant violation: verify requested in own leadership round {:?}: observer {observer_bytes:?}",
                                context.round
                            );
                        }
                        AutomatonEvent::ProposeRequested { context } => {
                            // Invariant: proposer_never_skips_own_certified_view
                            // A proposer's parent selection stops at the highest
                            // locally certified view, so no Certification or
                            // Finalization already in its log may fall strictly
                            // between the chosen parent and the proposal view.
                            // Verification contexts are exempt: a leader may
                            // legitimately choose a lower parent than this
                            // node's local certification.
                            //
                            // Source: Forced Inclusion (tail-forking resistance):
                            // without a nullification certificate no future
                            // leader can skip a certified view, and the voter's
                            // find_parent stops at the first certified view.
                            let parent_view = context.parent.0.get();
                            let child_view = context.round.view().get();
                            if let Some(&skipped) = certified_activity_views
                                .range(parent_view.saturating_add(1)..child_view)
                                .next()
                            {
                                panic!(
                                    "Invariant violation: proposer skips locally certified view {skipped}: observer {observer_bytes:?}, parent view {parent_view}, child round {:?}",
                                    context.round
                                );
                            }
                        }
                        AutomatonEvent::ProposeCompleted {
                            context,
                            outcome: Completion::Returned(payload),
                        } => {
                            accepted_signed.insert((context.round, context.parent.0, *payload));
                        }
                        AutomatonEvent::VerifyCompleted {
                            context,
                            payload,
                            outcome: Completion::Returned(true),
                        } => {
                            accepted_signed.insert((context.round, context.parent.0, *payload));
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

        certify_evidence.insert(observer_bytes.clone(), successful_certifications);
        acceptance_evidence.insert(observer_bytes, accepted_signed);
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

    // Invariant: stable_term_context_leader_constancy
    // Application contexts inside one leader term must all name the same
    // leader: a term has exactly one leader, and only a term boundary may
    // rotate it. Terms are grouped per epoch with the same independent term
    // arithmetic as the coverage checks.
    let mut term_context_leaders: BTreeMap<(u64, u64), (Round, Vec<u8>)> = BTreeMap::new();
    for (round, leaders) in &context_leaders {
        let view = round.view().get();
        if view == 0 {
            continue;
        }
        let leader = leaders
            .first()
            .expect("context leader sets are non-empty by construction");
        match term_context_leaders.entry((round.epoch().get(), (view - 1) / term_length.get())) {
            Entry::Vacant(entry) => {
                entry.insert((*round, leader.clone()));
            }
            Entry::Occupied(entry) => {
                let (first_round, first_leader) = entry.get();
                assert!(
                    first_leader == leader,
                    "Invariant violation: context leader changes inside a stable term: round {first_round:?} has {first_leader:?} but round {round:?} has {leader:?}"
                );
            }
        }
    }

    // Invariant: context_leader_matches_certificate_derived_leader
    // Bridges the two observation models: every leader named in a correct
    // application context must equal the certificate-derived leader recorded by
    // any summary reporter for that view. The per-model checks above only
    // compare each stream against itself, so a systematic election bug that
    // keeps engines and reporters internally consistent while diverging from
    // each other is invisible to them. When no reporter recorded an entry for
    // the view (view 1 is the normal case: it is entered from the genesis
    // floor and no certificate unlocks it), the leader is derived directly
    // from the configured elector with no certificate, so consistently wrong
    // initial contexts cannot pass by key absence. Certificate-less election
    // is total for the round-robin family; seed-based electors have no audit
    // instantiations.
    //
    // Source: the elector contract requires all honest participants to agree on
    // each round's leader, and both sides apply the same deterministic elector
    // to a verified certificate for the preceding view.
    for (round, leaders) in &context_leaders {
        let context_leader = leaders
            .first()
            .expect("context leader sets are non-empty by construction");
        let mut compared = false;
        for reporter in reporters {
            let recorded = reporter.inner().leaders.lock();
            if let Some(leader) = recorded.get(&round.view()) {
                assert!(
                    leader.as_ref() == context_leader.as_slice(),
                    "Invariant violation: automaton context leader disagrees with certificate-derived leader in round {round:?}: context {context_leader:?}, derived {:?}",
                    leader.as_ref()
                );
                compared = true;
            }
        }
        if compared {
            continue;
        }
        let Some(first) = reporters.first() else {
            continue;
        };
        let elected = first.elector().elect(*round, None);
        let expected = first
            .inner()
            .participants
            .key(elected)
            .expect("elected leader must be a participant");
        assert!(
            expected.as_ref() == context_leader.as_slice(),
            "Invariant violation: automaton context leader disagrees with elector-derived leader in round {round:?}: context {context_leader:?}, derived {:?}",
            expected.as_ref()
        );
    }

    // Invariant: automaton_context_parent_certified_with_nullified_gaps
    // (genesis clause) Every correct engine is configured with the identical
    // genesis, so all parent-view-0 context digests must agree.
    if genesis_parent_digests.len() > 1 {
        panic!(
            "Invariant violation: correct contexts disagree on the genesis parent digest: {genesis_parent_digests:?}"
        );
    }

    // Invariants:
    // - finalization_certificate_quorum_certified
    // - notarization_certificate_quorum_accepted
    //
    // Certificates are backed by the application decisions of the correct
    // participants whose votes formed them. The automaton proxy delivers the
    // result to consensus and records the completion in the same scheduling
    // step, with no yield between the send and the record, so under the
    // deterministic runtime the dependent vote cannot be constructed or
    // broadcast before the completion is in the log. Any observed certificate
    // therefore implies the evidence already exists in each correct signer's
    // log at every stop point.
    //
    // For attributable schemes every certificate signer that is an audited
    // correct node must hold matching evidence: successful certification for
    // finalization signers, and a propose/verify acceptance for notarization
    // signers. Acceptance matches the signed fields only (round, parent view,
    // payload): a signed Proposal does not carry the parent digest, so the
    // match is existential across the recorded full application contexts.
    //
    // For non-attributable schemes signer identities are unavailable; the
    // sound lower bound is that at least quorum(n) - f distinct correct
    // reporters hold matching evidence. The audited reporter set is exactly
    // the correct participants, so at most `n - reporters.len()` signers of
    // any certificate fall outside it and every valid certificate carries at
    // least `quorum - (n - reporters.len())` audited correct signers.
    //
    // Source: "a payload can only be finalized if a quorum of participants
    // certify it" and the Simplex voting rule that honest nodes vote only for
    // proposals they verified (or proposed).
    if let Some(first) = reporters.first() {
        let n = first.inner().participants.len();
        let threshold =
            (bounds::quorum(n as u32) as usize).saturating_sub(n.saturating_sub(reporters.len()));
        for (proposal, signers) in &finalization_backing {
            let key = (proposal.round, proposal.payload);
            if let Some(signers) = signers {
                for signer in signers {
                    if !correct_observers.contains(signer) {
                        continue;
                    }
                    assert!(
                        certify_evidence
                            .get(signer)
                            .is_some_and(|evidence| evidence.contains(&key)),
                        "Invariant violation: finalization signer without successful certification: signer {signer:?}, proposal {proposal:?}"
                    );
                }
            }
            let holders = certify_evidence
                .values()
                .filter(|evidence| evidence.contains(&key))
                .count();
            assert!(
                holders >= threshold,
                "Invariant violation: finalization certificate lacks quorum certification backing: proposal {proposal:?}, holders {holders}, required {threshold}"
            );
        }
        for (proposal, signers) in &notarization_backing {
            let key = (proposal.round, proposal.parent, proposal.payload);
            if let Some(signers) = signers {
                for signer in signers {
                    if !correct_observers.contains(signer) {
                        continue;
                    }
                    assert!(
                        acceptance_evidence
                            .get(signer)
                            .is_some_and(|evidence| evidence.contains(&key)),
                        "Invariant violation: notarization signer without application acceptance: signer {signer:?}, proposal {proposal:?}"
                    );
                }
            }
            let holders = acceptance_evidence
                .values()
                .filter(|evidence| evidence.contains(&key))
                .count();
            assert!(
                holders >= threshold,
                "Invariant violation: notarization certificate lacks quorum acceptance backing: proposal {proposal:?}, holders {holders}, required {threshold}"
            );
        }
    }
}

/// A locally observed notarization makes its exact proposal authoritative for
/// finalization recovery. If the node also retains a quorum of valid finalize
/// votes for that proposal, it must recover a finalization even when it never
/// observed a proposal from the round's leader.
///
/// Scoped to the node whose inbound leader proposals and finalizations the
/// harness omits: that omission is what rules out the benign reasons a correct
/// node can hold votes it cannot use, so this must not run over every audited
/// reporter. A higher finalized view exempts recovery because the batcher
/// stops processing rounds below its floor. The leader is derived from the
/// certificate-less elector of the single-epoch, four-correct-node target.
pub fn check_notarization_unlocks_finalize_quorum<E, S, L>(
    reporter: &RecordingReporter<E, S, L, Sha256Digest>,
) where
    E: CryptoRng,
    S: Scheme<Sha256Digest>,
    L: Elector<S>,
    L::Elector: Clone,
{
    let audit = reporter.audit();
    let quorum = bounds::quorum(
        u32::try_from(reporter.inner().participants.len()).expect("participant count exceeds u32"),
    ) as usize;

    let mut leader_notarizes = BTreeSet::new();
    let mut notarizations = BTreeSet::new();
    let mut finalize_signers: BTreeMap<Proposal<Sha256Digest>, BTreeSet<Participant>> =
        BTreeMap::new();
    let mut finalizations = BTreeSet::new();
    let mut finalized_floor = View::new(0);

    for recorded in audit.events() {
        let Event::Activity {
            valid: true,
            activity,
        } = recorded.event
        else {
            continue;
        };

        match activity {
            Activity::Notarize(vote) => {
                let round = vote.proposal.round;
                if reporter.elector().elect(round, None) == vote.signer() {
                    leader_notarizes.insert(round);
                }
            }
            Activity::Notarization(certificate) => {
                notarizations.insert(certificate.proposal);
            }
            Activity::Finalize(vote) => {
                let signer = vote.signer();
                finalize_signers
                    .entry(vote.proposal)
                    .or_default()
                    .insert(signer);
            }
            Activity::Finalization(certificate) => {
                finalized_floor = finalized_floor.max(certificate.proposal.round.view());
                finalizations.insert(certificate.proposal);
            }
            _ => {}
        }
    }

    for proposal in notarizations {
        let signers = finalize_signers.get(&proposal).map_or(0, BTreeSet::len);
        if leader_notarizes.contains(&proposal.round) || signers < quorum {
            continue;
        }
        assert!(
            finalizations.contains(&proposal) || finalized_floor > proposal.round.view(),
            "Invariant violation: notarization plus finalize quorum without a leader proposal did not produce an exact finalization: observer {:?}, proposal {proposal:?}, signers {signers}, required {quorum}",
            audit.observer().as_ref(),
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
                        },
                    )
                })
                .collect();

            let nullifications = reporter.nullifications.lock();
            let nullification_data = nullifications
                .keys()
                .map(|view| (view.get(), Nullification))
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
    use crate::{id_mock, simplex::SimplexId};
    use commonware_consensus::{
        Reporter as _,
        simplex::{
            elector::{Random, RoundRobin},
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
    use commonware_utils::{NZU32, TestRng, ordered::Set, test_rng};
    use std::time::Duration;

    const N: u32 = 4;
    const Q: usize = 3;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest([byte; 32])
    }

    fn notarization(parent: u64, payload: u8) -> Notarization {
        Notarization {
            payload: digest(payload),
            parent,
        }
    }

    fn nullification() -> Nullification {
        Nullification
    }

    fn finalization(parent: u64, payload: u8) -> Finalization {
        Finalization {
            payload: digest(payload),
            parent,
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
    #[should_panic(expected = "view 1 is nullified but view 5 is finalized in the same term")]
    fn nullification_conflicts_with_term_end_finalization() {
        let r = replica(
            views(vec![
                (1, notarization(0, 0xA)),
                (2, notarization(1, 0xB)),
                (3, notarization(2, 0xC)),
                (4, notarization(3, 0xD)),
                (5, notarization(4, 0xE)),
            ]),
            views(vec![(1, nullification())]),
            views(vec![(5, finalization(4, 0xE))]),
        );
        check::<SimplexId>(TermLength::new(NZU32!(5)), vec![r]);
    }

    #[test]
    fn next_term_finalization_does_not_conflict_with_prior_nullification() {
        let r = replica(
            views(vec![(6, notarization(0, 0xA))]),
            views(vec![(1, nullification())]),
            views(vec![(6, finalization(0, 0xA))]),
        );
        check::<SimplexId>(TermLength::new(NZU32!(5)), vec![r]);
    }

    #[test]
    fn later_nullification_does_not_conflict_with_earlier_finalization() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA))]),
            views(vec![(3, nullification())]),
            views(vec![(1, finalization(0, 0xA))]),
        );
        check::<SimplexId>(TermLength::new(NZU32!(5)), vec![r]);
    }

    #[test]
    fn term_tail_gap_covered_by_single_nullification_passes() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA)), (6, notarization(1, 0xB))]),
            views(vec![(2, nullification())]),
            views(vec![]),
        );
        check::<SimplexId>(TermLength::new(NZU32!(5)), vec![r]);
    }

    #[test]
    #[should_panic(expected = "view 2 has no covering nullification")]
    fn term_tail_gap_without_nullification_is_rejected() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA)), (6, notarization(1, 0xB))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(TermLength::new(NZU32!(5)), vec![r]);
    }

    #[test]
    #[should_panic(expected = "mid-term notarization in view 4 with parent 1")]
    fn intra_term_proposal_skip_is_rejected_despite_coverage() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA)), (4, notarization(1, 0xB))]),
            views(vec![(2, nullification()), (3, nullification())]),
            views(vec![]),
        );
        check::<SimplexId>(TermLength::new(NZU32!(5)), vec![r]);
    }

    #[test]
    fn valid_consolidated_chain_passes() {
        check::<SimplexId>(TermLength::ONE, vec![chain_replica(), chain_replica()]);
    }

    #[test]
    fn notarization_and_nullification_same_view_is_allowed() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA))]),
            views(vec![(1, nullification())]),
            views(vec![]),
        );
        check::<SimplexId>(TermLength::ONE, vec![r]);
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
        check::<SimplexId>(TermLength::ONE, vec![r0, r1]);
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
        check::<SimplexId>(TermLength::ONE, vec![r0, r1]);
    }

    #[test]
    #[should_panic(expected = "view 1 is nullified but view 1 is finalized in the same term")]
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
        check::<SimplexId>(TermLength::ONE, vec![r0, r1]);
    }

    #[test]
    #[should_panic(expected = "finalization without matching notarization")]
    fn finalization_without_notarization_is_rejected() {
        let r = replica(
            views(vec![]),
            views(vec![]),
            views(vec![(1, finalization(0, 0xA))]),
        );
        check::<SimplexId>(TermLength::ONE, vec![r]);
    }

    #[test]
    #[should_panic(expected = "finalization without matching notarization")]
    fn finalization_with_different_notarized_payload_is_rejected() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA))]),
            views(vec![]),
            views(vec![(1, finalization(0, 0xB))]),
        );
        check::<SimplexId>(TermLength::ONE, vec![r]);
    }

    #[test]
    #[should_panic(expected = "finalization without matching notarization")]
    fn finalization_with_different_notarized_parent_is_rejected() {
        let r = replica(
            views(vec![(2, notarization(1, 0xA))]),
            views(vec![]),
            views(vec![(2, finalization(0, 0xA))]),
        );
        check::<SimplexId>(TermLength::ONE, vec![r]);
    }

    #[test]
    #[should_panic(expected = "in view 2 with parent 2")]
    fn parent_must_precede_child() {
        let r = replica(
            views(vec![(2, notarization(2, 0xA))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(TermLength::ONE, vec![r]);
    }

    #[test]
    #[should_panic(expected = "uncertified parent 1")]
    fn parent_must_be_certified() {
        let r = replica(
            views(vec![(2, notarization(1, 0xA))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(TermLength::ONE, vec![r]);
    }

    #[test]
    #[should_panic(expected = "view 2 has no covering nullification")]
    fn every_skipped_view_must_be_nullified() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA)), (3, notarization(1, 0xB))]),
            views(vec![]),
            views(vec![]),
        );
        check::<SimplexId>(TermLength::ONE, vec![r]);
    }

    #[test]
    fn complete_skipped_nullification_range_passes() {
        let r = replica(
            views(vec![(1, notarization(0, 0xA)), (4, notarization(1, 0xB))]),
            views(vec![(2, nullification()), (3, nullification())]),
            views(vec![]),
        );
        check::<SimplexId>(TermLength::ONE, vec![r]);
    }

    #[test]
    #[should_panic(expected = "notarization in view 2 with uncertified parent 1")]
    fn matching_finalization_does_not_change_ancestry_result() {
        let r = replica(
            views(vec![(2, notarization(1, 0xA))]),
            views(vec![]),
            views(vec![(2, finalization(1, 0xA))]),
        );
        check::<SimplexId>(TermLength::ONE, vec![r]);
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

    /// A summary reporter configured like the stable-term harnesses: the
    /// elector carries the checked term length, so recorded leader targets
    /// match the term-aware invariants. No prior history is seeded.
    fn term_vote_reporter(
        participants: &[id_mock::PublicKey],
        schemes: &[id_mock::Scheme],
        term_length: TermLength,
    ) -> Reporter<TestRng, id_mock::Scheme, RoundRobin, Sha256Digest> {
        Reporter::new(
            test_rng(),
            ReporterConfig {
                participants: Set::try_from(participants.to_vec()).expect("unique keys"),
                scheme: schemes[0].clone(),
                elector: RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep_a, rep_b],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep_a, rep_b],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep_a, rep_b],
        );
    }

    #[test]
    #[should_panic(expected = "certificate progression reaches view 3 without")]
    fn certificate_progression_gap_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let rep = vote_reporter(&participants, &schemes);
        rep.certified.lock().clear();
        rep.certified.lock().extend([View::new(1), View::new(3)]);
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
    }

    #[test]
    #[should_panic(expected = "view 1 is nullified but view 3 is finalized in the same term")]
    fn adversarially_observed_same_term_certificates_conflict() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let rep = term_vote_reporter(&participants, &schemes, term_length);
        // Insert the certificates directly: this models a pair observed only
        // by adversarial-mode observers, outside any honest extracted state.
        rep.nullifications
            .lock()
            .insert(View::new(1), nullification_activity(&schemes, 1));
        rep.finalizations
            .lock()
            .insert(View::new(3), finalization_activity(&schemes, 3, 2, 0xA));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            Epoch::new(0),
            term_length,
            &[rep],
        );
    }

    #[test]
    fn next_term_finalization_certificate_does_not_conflict() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let mut rep = term_vote_reporter(&participants, &schemes, term_length);
        rep.report(Activity::Nullification(nullification_activity(&schemes, 1)));
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 6, 0, 0xA,
        )));
        rep.report(Activity::Finalization(finalization_activity(
            &schemes, 6, 0, 0xA,
        )));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            Epoch::new(0),
            term_length,
            &[rep],
        );
    }

    #[test]
    fn later_nullification_certificate_preserves_directionality() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let mut rep = term_vote_reporter(&participants, &schemes, term_length);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 1, 0, 0xA,
        )));
        rep.report(Activity::Finalization(finalization_activity(
            &schemes, 1, 0, 0xA,
        )));
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 2, 1, 0xB,
        )));
        rep.report(Activity::Nullification(nullification_activity(&schemes, 3)));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            Epoch::new(0),
            term_length,
            &[rep],
        );
    }

    #[test]
    #[should_panic(
        expected = "correct signer finalized view 2 after nullifying view 1 in the same term without healing finalization"
    )]
    fn summary_same_term_finalize_after_nullify_without_healing_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let mut rep = term_vote_reporter(&participants, &schemes, term_length);
        rep.certified.lock().insert(View::new(1));
        rep.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(1)).unwrap(),
        ));
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 2, 1, 0xA,
        )));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal(2, 1, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            Epoch::new(0),
            term_length,
            &[rep],
        );
    }

    #[test]
    fn summary_same_term_finalize_after_nullify_with_healing_passes() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let mut rep = term_vote_reporter(&participants, &schemes, term_length);
        rep.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(1)).unwrap(),
        ));
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 1, 0, 0xB,
        )));
        // The healing signers exclude the nullifier: same-view nullify plus
        // finalize by one signer is unconditional equivocation, not healing.
        rep.report(Activity::Finalization(finalization_activity_from(
            &schemes,
            &[1, 2, 3],
            1,
            0,
            0xB,
        )));
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 2, 1, 0xA,
        )));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal(2, 1, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            Epoch::new(0),
            term_length,
            &[rep],
        );
    }

    #[test]
    fn summary_cross_term_finalize_after_nullify_needs_no_healing() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let mut rep = term_vote_reporter(&participants, &schemes, term_length);
        rep.report(Activity::Nullification(nullification_activity(&schemes, 1)));
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 6, 0, 0xA,
        )));
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal(6, 0, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            Epoch::new(0),
            term_length,
            &[rep],
        );
    }

    #[test]
    #[should_panic(expected = "correct leader has conflicting proposal payloads in view 1")]
    fn initial_view_payload_conflict_under_correct_leader_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let mut rep_a = term_vote_reporter(&participants, &schemes, term_length);
        let mut rep_b = term_vote_reporter(&participants, &schemes, term_length);
        // Raw votes only, deliberately no certificate: nothing records a
        // view-1 leader (or supplies an epoch), so only the explicit-epoch
        // elector derivation can bring view 1 into the coherence check.
        rep_a.report(Activity::Notarize(
            Notarize::sign(&schemes[2], proposal(1, 0, 0xA)).unwrap(),
        ));
        rep_b.report(Activity::Notarize(
            Notarize::sign(&schemes[3], proposal(1, 0, 0xB)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            Epoch::new(0),
            term_length,
            &[rep_a, rep_b],
        );
    }

    #[test]
    fn nullification_authorizes_entry_at_next_term_start() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let mut rep = term_vote_reporter(&participants, &schemes, term_length);
        rep.certified.lock().insert(View::new(1));
        rep.report(Activity::Nullification(nullification_activity(&schemes, 2)));
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 6, 1, 0xA,
        )));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            Epoch::new(0),
            term_length,
            &[rep],
        );
    }

    #[test]
    #[should_panic(expected = "certificate progression reaches view 3 without")]
    fn nullification_does_not_authorize_entry_mid_term() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let mut rep = term_vote_reporter(&participants, &schemes, term_length);
        rep.certified.lock().insert(View::new(1));
        rep.report(Activity::Nullification(nullification_activity(&schemes, 2)));
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 3, 2, 0xA,
        )));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            Epoch::new(0),
            term_length,
            &[rep],
        );
    }

    #[test]
    #[should_panic(expected = "certificate progression reaches view 4 without")]
    fn nullification_does_not_authorize_entry_past_term_start() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let mut rep = term_vote_reporter(&participants, &schemes, term_length);
        rep.certified.lock().insert(View::new(1));
        rep.report(Activity::Nullification(nullification_activity(&schemes, 2)));
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 4, 3, 0xA,
        )));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            Epoch::new(0),
            term_length,
            &[rep],
        );
    }

    #[test]
    fn stable_term_keeps_one_leader_until_the_boundary() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let mut rep = term_vote_reporter(&participants, &schemes, term_length);
        for view in 1..=5u64 {
            rep.report(Activity::Notarization(notarization_activity(
                &schemes,
                view,
                view - 1,
                view as u8,
            )));
        }
        // Recorded targets span views 2-6: one leader for the rest of term
        // [1, 5], and a rotation is permitted only at the boundary view 6.
        check_vote_invariants(
            0,
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            Epoch::new(0),
            term_length,
            &[rep],
        );
    }

    #[test]
    #[should_panic(expected = "leader changes inside a stable term")]
    fn leader_change_inside_stable_term_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let mut rep = term_vote_reporter(&participants, &schemes, term_length);
        for view in 1..=5u64 {
            rep.report(Activity::Notarization(notarization_activity(
                &schemes,
                view,
                view - 1,
                view as u8,
            )));
        }
        let recorded = rep
            .leaders
            .lock()
            .get(&View::new(2))
            .cloned()
            .expect("recorded leader");
        let conflicting = participants
            .iter()
            .find(|participant| **participant != recorded)
            .expect("alternative participant")
            .clone();
        rep.leaders.lock().insert(View::new(3), conflicting);
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            Epoch::new(0),
            term_length,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep_a, rep_b],
        );
    }

    #[test]
    #[should_panic(expected = "voted in view 2 without entry evidence at predecessor view 1")]
    fn correct_vote_without_predecessor_certificate_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.certified.lock().clear();
        rep.report(Activity::Notarize(
            Notarize::sign(&schemes[1], proposal(2, 1, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &byzantine,
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep_a, rep_b],
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &byzantine,
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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

    fn finalization_activity_from(
        schemes: &[id_mock::Scheme],
        signers: &[usize],
        view: u64,
        parent: u64,
        payload: u8,
    ) -> SimplexFinalization<id_mock::Scheme, Sha256Digest> {
        assert_eq!(signers.len(), Q);
        let votes: Vec<_> = signers
            .iter()
            .map(|&signer| {
                Finalize::sign(&schemes[signer], proposal(view, parent, payload)).unwrap()
            })
            .collect();
        SimplexFinalization::from_finalizes(&schemes[0], &votes, &Sequential).unwrap()
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

    /// Audit reporter whose elector carries the checked term length, matching
    /// how the stable-term harnesses configure recording reporters.
    fn term_audit_reporter(
        observer: usize,
        participants: &[id_mock::PublicKey],
        schemes: &[id_mock::Scheme],
        term_length: TermLength,
    ) -> AuditReporter {
        RecordingReporter::new(
            test_rng(),
            participants[observer].clone(),
            0,
            ReporterConfig {
                participants: Set::try_from(participants.to_vec()).expect("unique keys"),
                scheme: schemes[observer].clone(),
                elector: RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
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

    fn record_finalize_votes(
        reporter: &mut AuditReporter,
        schemes: &[id_mock::Scheme],
        proposal: &Proposal<Sha256Digest>,
        signers: impl IntoIterator<Item = usize>,
    ) {
        for signer in signers {
            reporter.report(Activity::Finalize(
                Finalize::sign(&schemes[signer], proposal.clone()).unwrap(),
            ));
        }
    }

    #[test]
    #[should_panic(
        expected = "notarization plus finalize quorum without a leader proposal did not produce an exact finalization"
    )]
    fn notarization_without_leader_proposal_must_unlock_finalize_quorum() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(3, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);

        // Match the batcher regression: the complete finalize quorum is
        // buffered before the notarization arrives.
        record_finalize_votes(&mut reporter, &schemes, &proposal, 0..Q);
        reporter.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));

        check_notarization_unlocks_finalize_quorum(&reporter);
    }

    #[test]
    fn recovered_finalization_satisfies_unlocked_finalize_quorum() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(3, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);

        record_finalize_votes(&mut reporter, &schemes, &proposal, 0..Q);
        reporter.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        reporter.report(Activity::Finalization(finalization_activity(
            &schemes, 5, 4, 0xA,
        )));

        check_notarization_unlocks_finalize_quorum(&reporter);
    }

    #[test]
    fn preexisting_finalized_floor_exempts_finalize_recovery() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(3, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);

        reporter.report(Activity::Finalization(finalization_activity(
            &schemes, 6, 5, 0xB,
        )));
        record_finalize_votes(&mut reporter, &schemes, &proposal, 0..Q);
        reporter.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));

        check_notarization_unlocks_finalize_quorum(&reporter);
    }

    #[test]
    fn known_leader_proposal_does_not_arm_future_proposal_recovery() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(3, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        let leader = reporter.elector().elect(proposal.round, None);

        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[usize::from(leader)], proposal.clone()).unwrap(),
        ));
        record_finalize_votes(&mut reporter, &schemes, &proposal, 0..Q);
        reporter.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));

        check_notarization_unlocks_finalize_quorum(&reporter);
    }

    #[test]
    #[should_panic(expected = "notarized multiple exact proposals")]
    fn exact_proposal_non_equivocation_rejects_same_payload_with_different_parents() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 4)));
        for parent in [3, 4] {
            let proposal = proposal(5, parent, 0xA);
            record_propose_success(&reporter, &proposal);
            reporter.report(Activity::Notarize(
                Notarize::sign(&schemes[0], proposal).unwrap(),
            ));
        }
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
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
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
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
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local notarize without successful propose/verify")]
    fn local_notarize_without_application_acceptance_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
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
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    fn rejection_under_another_parent_digest_does_not_override_acceptance() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(1, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 4)));
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
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local finalize without successful certification")]
    fn local_finalize_without_successful_certification_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "certification activity without a true automaton result")]
    fn certification_activity_without_successful_result_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Certification(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    fn failed_certification_at_the_end_of_a_prefix_is_allowed() {
        let (participants, schemes) = vote_fixture();
        let reporter = audit_reporter(0, &participants, &schemes);
        record_certify_result(&reporter, &proposal(5, 4, 0xA), false);
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
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
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
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
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "automaton contexts disagree on leader")]
    fn correct_automaton_contexts_with_different_leaders_are_rejected() {
        let (participants, schemes) = vote_fixture();
        let reporter_a = audit_reporter(0, &participants, &schemes);
        let reporter_b = audit_reporter(1, &participants, &schemes);
        let parent = proposal(4, 3, 0xF);
        record_certify_result(&reporter_a, &parent, true);
        record_certify_result(&reporter_b, &parent, true);
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
        check_fuzz_invariants(TermLength::ONE, &[reporter_a, reporter_b]);
    }

    #[test]
    #[should_panic(expected = "certification/finalize proposal mismatch")]
    fn certification_and_finalize_with_different_parents_are_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let certified = proposal(5, 3, 0xA);
        let finalized = proposal(5, 4, 0xA);
        reporter.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        record_certify_result(&reporter, &certified, true);
        reporter.report(Activity::Certification(notarization_activity(
            &schemes, 5, 3, 0xA,
        )));
        reporter.report(Activity::Finalize(
            Finalize::sign(&schemes[0], finalized).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    fn local_notarize_accepts_complete_prior_parent_gap() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let proposal = proposal(5, 2, 0xA);
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 3)));
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 4)));
        record_propose_success(&reporter, &proposal);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], proposal).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local notarize skips view 4 without covering nullification")]
    fn local_notarize_rejects_missing_parent_gap_nullification() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let proposal = proposal(5, 2, 0xA);
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 3)));
        record_propose_success(&reporter, &proposal);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], proposal).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local finalize without prior matching notarization")]
    fn local_finalize_rejects_notarization_with_different_parent() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let finalized = proposal(5, 4, 0xA);
        reporter.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 3, 0xA,
        )));
        record_certify_result(&reporter, &finalized, true);
        reporter.report(Activity::Finalize(
            Finalize::sign(&schemes[0], finalized).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    fn local_finalize_of_recovered_notarization_does_not_require_gap_history() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let proposal = proposal(5, 2, 0xA);
        // A finalizer may recover the notarization directly; the quorum that
        // formed it proves safe voting without requiring this node to retain
        // each earlier nullification locally.
        reporter.report(Activity::Notarization(notarization_activity_from(
            &schemes,
            &[1, 2, 3],
            5,
            2,
            0xA,
        )));
        record_certify_result(&reporter, &proposal, true);
        reporter.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    fn received_finalization_does_not_require_local_notarization_observation() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(3, &participants, &schemes);
        reporter.report(Activity::Finalization(finalization_activity(
            &schemes, 5, 4, 0xA,
        )));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    fn context_with_certified_parent_and_nullified_gaps_passes() {
        let (participants, schemes) = vote_fixture();
        // Observer 1 is the round-robin leader of round 5, matching the
        // certificate-derived schedule the reported nullifications create.
        let mut reporter = audit_reporter(1, &participants, &schemes);
        record_certify_result(&reporter, &proposal(2, 1, 0xB), true);
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 3)));
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 4)));
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeRequested {
                context: automaton_context_with_parent_digest(
                    participants[1].clone(),
                    &proposal(5, 2, 0xA),
                    digest(0xB),
                ),
            },
        );
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "context parent without local certification")]
    fn context_parent_without_certification_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let reporter = audit_reporter(0, &participants, &schemes);
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeRequested {
                context: automaton_context(participants[0].clone(), &proposal(5, 4, 0xA)),
            },
        );
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "context parent without local certification")]
    fn context_parent_digest_mismatch_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let reporter = audit_reporter(0, &participants, &schemes);
        record_certify_result(&reporter, &proposal(4, 3, 0xB), true);
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeRequested {
                context: automaton_context(participants[0].clone(), &proposal(5, 4, 0xA)),
            },
        );
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "context skips view")]
    fn context_missing_gap_nullification_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        record_certify_result(&reporter, &proposal(2, 1, 0xB), true);
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 3)));
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeRequested {
                context: automaton_context_with_parent_digest(
                    participants[0].clone(),
                    &proposal(5, 2, 0xA),
                    digest(0xB),
                ),
            },
        );
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    fn finalization_evidence_authorizes_verify_context() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Finalization(finalization_activity_from(
            &schemes,
            &[1, 2, 3],
            4,
            3,
            0xF,
        )));
        record_automaton(
            &reporter,
            AutomatonEvent::VerifyRequested {
                context: automaton_context(participants[1].clone(), &proposal(5, 4, 0xA)),
                payload: digest(0xA),
            },
        );
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "disagree on the genesis parent digest")]
    fn diverging_genesis_contexts_are_rejected() {
        let (participants, schemes) = vote_fixture();
        let rep_a = audit_reporter(1, &participants, &schemes);
        let rep_b = audit_reporter(0, &participants, &schemes);
        record_automaton(
            &rep_a,
            AutomatonEvent::ProposeRequested {
                context: automaton_context_with_parent_digest(
                    participants[1].clone(),
                    &proposal(1, 0, 0xA),
                    digest(0xE),
                ),
            },
        );
        record_automaton(
            &rep_b,
            AutomatonEvent::VerifyRequested {
                context: automaton_context_with_parent_digest(
                    participants[1].clone(),
                    &proposal(1, 0, 0xA),
                    digest(0xD),
                ),
                payload: digest(0xA),
            },
        );
        check_fuzz_invariants(TermLength::ONE, &[rep_a, rep_b]);
    }

    #[test]
    #[should_panic(expected = "disagrees with elector-derived leader")]
    fn initial_context_leader_must_match_elector() {
        let (participants, schemes) = vote_fixture();
        let reporter = audit_reporter(0, &participants, &schemes);
        // Epoch-0 rotation elects participant 1 for view 1; no certificate
        // unlocks the initial view, so only direct elector derivation can
        // catch a consistently wrong leader here.
        record_automaton(
            &reporter,
            AutomatonEvent::VerifyRequested {
                context: automaton_context_with_parent_digest(
                    participants[2].clone(),
                    &proposal(1, 0, 0xA),
                    digest(0xB),
                ),
                payload: digest(0xA),
            },
        );
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local notarize without entry evidence for view 5")]
    fn own_notarize_without_predecessor_certificate_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        record_propose_success(&reporter, &proposal);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], proposal).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local nullify without entry evidence for view 5")]
    fn own_nullify_without_predecessor_certificate_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(5)).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local notarize without entry evidence for view 5")]
    fn bare_notarization_is_not_view_entry_evidence() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Notarization(notarization_activity_from(
            &schemes,
            &[1, 2, 3],
            4,
            3,
            0xB,
        )));
        let vote = proposal(5, 4, 0xB);
        record_verify_result(&reporter, participants[1].clone(), &vote, true);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], vote).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(
        expected = "local finalize after own same-term nullify without healing finalization"
    )]
    fn same_term_finalize_after_own_nullify_without_healing_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let proposal = proposal(2, 1, 0xA);
        reporter.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(1)).unwrap(),
        ));
        reporter.report(Activity::Notarization(notarization_activity_from(
            &schemes,
            &[1, 2, 3],
            2,
            1,
            0xA,
        )));
        record_certify_result(&reporter, &proposal, true);
        reporter.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal).unwrap(),
        ));
        check_fuzz_invariants(TermLength::new(NZU32!(5)), std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "mid-term context skips views")]
    fn mid_term_context_skip_is_rejected_despite_coverage() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        // Nullification of view 2 covers views 2-5, but a mid-term context at
        // view 4 must still extend exactly view 3.
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 2)));
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeRequested {
                context: automaton_context_with_parent_digest(
                    participants[0].clone(),
                    &proposal(4, 1, 0xC),
                    digest(0xB),
                ),
            },
        );
        check_fuzz_invariants(TermLength::new(NZU32!(5)), std::slice::from_ref(&reporter));
    }

    #[test]
    fn genesis_term_helpers_are_total() {
        let term_length = TermLength::new(NZU32!(5));
        assert_eq!(term_start(0, term_length), 0);
        assert_eq!(next_term_start(0, term_length), 1);
        assert!(!nullification_covers(0, 0, term_length));
        assert!(!nullification_covers(0, 3, term_length));
        assert_eq!(term_start(1, term_length), 1);
        assert_eq!(term_start(5, term_length), 1);
        assert_eq!(next_term_start(5, term_length), 6);
        assert_eq!(next_term_start(6, term_length), 11);
    }

    #[test]
    #[should_panic(
        expected = "local finalize after own same-term nullify without healing finalization"
    )]
    fn cross_epoch_finalization_does_not_heal_gate() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let proposal_in_gap = proposal(2, 1, 0xA);
        reporter.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(1)).unwrap(),
        ));
        reporter.report(Activity::Notarization(notarization_activity_from(
            &schemes,
            &[1, 2, 3],
            2,
            1,
            0xA,
        )));
        record_certify_result(&reporter, &proposal_in_gap, true);
        // A finalization from another epoch covers the same numeric view but
        // must not heal this epoch's gap.
        let foreign = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::new(0),
            digest(0xB),
        );
        let votes: Vec<_> = [1usize, 2, 3]
            .iter()
            .map(|&signer| Finalize::sign(&schemes[signer], foreign.clone()).unwrap())
            .collect();
        let finalization =
            SimplexFinalization::from_finalizes(&schemes[0], &votes, &Sequential).unwrap();
        reporter.report(Activity::Finalization(finalization));
        reporter.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal_in_gap).unwrap(),
        ));
        check_fuzz_invariants(TermLength::new(NZU32!(5)), std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local notarize with parent 0 not below view 0")]
    fn genesis_notarize_is_rejected_by_parent_ordering() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let genesis_vote = proposal(0, 0, 0xA);
        record_propose_success(&reporter, &genesis_vote);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], genesis_vote).unwrap(),
        ));
        check_fuzz_invariants(TermLength::new(NZU32!(5)), std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "not below child round")]
    fn genesis_context_is_rejected_by_parent_ordering() {
        let (participants, schemes) = vote_fixture();
        let reporter = audit_reporter(0, &participants, &schemes);
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeRequested {
                context: automaton_context_with_parent_digest(
                    participants[0].clone(),
                    &proposal(0, 0, 0xC),
                    digest(0xB),
                ),
            },
        );
        check_fuzz_invariants(TermLength::new(NZU32!(5)), std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local notarize with parent 6 not below view 6")]
    fn term_start_notarize_with_unordered_parent_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let proposal = proposal(6, 6, 0xA);
        record_propose_success(&reporter, &proposal);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], proposal).unwrap(),
        ));
        check_fuzz_invariants(TermLength::new(NZU32!(5)), std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "not below child round")]
    fn term_start_context_with_unordered_parent_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let reporter = audit_reporter(0, &participants, &schemes);
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeRequested {
                context: automaton_context_with_parent_digest(
                    participants[0].clone(),
                    &proposal(6, 7, 0xC),
                    digest(0xB),
                ),
            },
        );
        check_fuzz_invariants(TermLength::new(NZU32!(5)), std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "context leader changes inside a stable term")]
    fn context_leader_change_inside_stable_term_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let reporter = term_audit_reporter(0, &participants, &schemes, TermLength::new(NZU32!(5)));
        record_certify_result(&reporter, &proposal(1, 0, 0xB), true);
        record_certify_result(&reporter, &proposal(2, 1, 0xC), true);
        record_automaton(
            &reporter,
            AutomatonEvent::VerifyRequested {
                context: automaton_context_with_parent_digest(
                    participants[1].clone(),
                    &proposal(2, 1, 0xC),
                    digest(0xB),
                ),
                payload: digest(0xC),
            },
        );
        record_automaton(
            &reporter,
            AutomatonEvent::VerifyRequested {
                context: automaton_context_with_parent_digest(
                    participants[2].clone(),
                    &proposal(3, 2, 0xD),
                    digest(0xC),
                ),
                payload: digest(0xD),
            },
        );
        check_fuzz_invariants(TermLength::new(NZU32!(5)), std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(
        expected = "local finalize after own same-term nullify without healing finalization"
    )]
    fn finalization_at_or_above_finalize_view_does_not_heal_gate() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let proposal = proposal(2, 1, 0xA);
        reporter.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(1)).unwrap(),
        ));
        reporter.report(Activity::Notarization(notarization_activity_from(
            &schemes,
            &[1, 2, 3],
            2,
            1,
            0xA,
        )));
        record_certify_result(&reporter, &proposal, true);
        // A finalization at view 3 lies above the gap [1, 2): it proves
        // nothing about the abandoned view and must not heal the gate.
        reporter.report(Activity::Finalization(finalization_activity_from(
            &schemes,
            &[1, 2, 3],
            3,
            2,
            0xB,
        )));
        reporter.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal).unwrap(),
        ));
        check_fuzz_invariants(TermLength::new(NZU32!(5)), std::slice::from_ref(&reporter));
    }

    #[test]
    fn same_term_finalize_after_own_nullify_with_healing_passes() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let proposal = proposal(2, 1, 0xA);
        reporter.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(1)).unwrap(),
        ));
        // An observed finalization at (or above) the abandoned view heals the
        // gate: nullify(1) then finalize(2) in the same term becomes legal.
        reporter.report(Activity::Finalization(finalization_activity_from(
            &schemes,
            &[1, 2, 3],
            1,
            0,
            0xB,
        )));
        reporter.report(Activity::Notarization(notarization_activity_from(
            &schemes,
            &[1, 2, 3],
            2,
            1,
            0xA,
        )));
        record_certify_result(&reporter, &proposal, true);
        reporter.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal).unwrap(),
        ));
        check_fuzz_invariants(TermLength::new(NZU32!(5)), std::slice::from_ref(&reporter));
    }

    #[test]
    fn certified_predecessor_authorizes_own_vote() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Notarization(notarization_activity_from(
            &schemes,
            &[1, 2, 3],
            4,
            3,
            0xB,
        )));
        record_certify_result(&reporter, &proposal(4, 3, 0xB), true);
        reporter.report(Activity::Certification(notarization_activity_from(
            &schemes,
            &[1, 2, 3],
            4,
            3,
            0xB,
        )));
        let vote = proposal(5, 4, 0xA);
        record_verify_result(&reporter, participants[1].clone(), &vote, true);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], vote).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    fn notarize_then_own_nullify_is_legal() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 4)));
        let vote = proposal(5, 4, 0xA);
        record_propose_success(&reporter, &vote);
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], vote).unwrap(),
        ));
        reporter.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(5)).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "local notarize after own nullify")]
    fn own_notarize_after_own_nullify_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 4)));
        let vote = proposal(5, 4, 0xA);
        record_propose_success(&reporter, &vote);
        reporter.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(5)).unwrap(),
        ));
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], vote).unwrap(),
        ));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "application request after own nullify")]
    fn application_request_after_own_nullify_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        record_certify_result(&reporter, &proposal(4, 3, 0xF), true);
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 4)));
        reporter.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(5)).unwrap(),
        ));
        record_automaton(
            &reporter,
            AutomatonEvent::VerifyRequested {
                context: automaton_context(participants[1].clone(), &proposal(5, 4, 0xA)),
                payload: digest(0xA),
            },
        );
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "verify requested in own leadership round")]
    fn verify_request_in_own_leadership_round_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let reporter = audit_reporter(0, &participants, &schemes);
        record_certify_result(&reporter, &proposal(4, 3, 0xF), true);
        record_automaton(
            &reporter,
            AutomatonEvent::VerifyRequested {
                context: automaton_context(participants[0].clone(), &proposal(5, 4, 0xA)),
                payload: digest(0xA),
            },
        );
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "context leader disagrees with certificate-derived leader")]
    fn context_leader_conflicting_with_recorded_schedule_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let reporter = audit_reporter(0, &participants, &schemes);
        reporter
            .inner()
            .leaders
            .lock()
            .insert(View::new(5), participants[1].clone());
        record_certify_result(&reporter, &proposal(4, 3, 0xF), true);
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeRequested {
                context: automaton_context(participants[0].clone(), &proposal(5, 4, 0xA)),
            },
        );
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    fn finalization_backed_by_quorum_certification_passes() {
        let (participants, schemes) = vote_fixture();
        let mut rep_a = audit_reporter(0, &participants, &schemes);
        let rep_b = audit_reporter(1, &participants, &schemes);
        let proposal = proposal(5, 4, 0xA);
        record_certify_result(&rep_a, &proposal, true);
        record_certify_result(&rep_b, &proposal, true);
        rep_a.report(Activity::Finalization(finalization_activity(
            &schemes, 5, 4, 0xA,
        )));
        check_fuzz_invariants(TermLength::ONE, &[rep_a, rep_b]);
    }

    #[test]
    #[should_panic(expected = "finalization signer without successful certification")]
    fn finalization_signer_without_certification_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Finalization(finalization_activity(
            &schemes, 5, 4, 0xA,
        )));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "notarization signer without application acceptance")]
    fn notarization_signer_without_acceptance_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        reporter.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    fn notarization_signer_acceptance_ignores_parent_digest() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        let vote = proposal(5, 4, 0xA);
        record_verify_result_with_parent_digest(
            &reporter,
            participants[1].clone(),
            &vote,
            digest(0xE),
            true,
        );
        reporter.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    fn proposer_building_on_highest_certified_view_passes() {
        let (participants, schemes) = vote_fixture();
        // Observer 1 is the round-robin leader of round 5, matching the
        // certificate-derived schedule the reported certificates create.
        let mut reporter = audit_reporter(1, &participants, &schemes);
        record_certify_result(&reporter, &proposal(3, 2, 0xC), true);
        reporter.report(Activity::Certification(notarization_activity_from(
            &schemes,
            &[0, 2, 3],
            3,
            2,
            0xC,
        )));
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 4)));
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeRequested {
                context: automaton_context_with_parent_digest(
                    participants[1].clone(),
                    &proposal(5, 3, 0xA),
                    digest(0xC),
                ),
            },
        );
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    #[should_panic(expected = "proposer skips locally certified view 3")]
    fn proposer_skipping_certified_view_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(1, &participants, &schemes);
        record_certify_result(&reporter, &proposal(2, 1, 0xB), true);
        record_certify_result(&reporter, &proposal(3, 2, 0xC), true);
        reporter.report(Activity::Certification(notarization_activity_from(
            &schemes,
            &[0, 2, 3],
            3,
            2,
            0xC,
        )));
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 3)));
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 4)));
        record_automaton(
            &reporter,
            AutomatonEvent::ProposeRequested {
                context: automaton_context_with_parent_digest(
                    participants[1].clone(),
                    &proposal(5, 2, 0xA),
                    digest(0xB),
                ),
            },
        );
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
    }

    #[test]
    fn verifier_may_skip_past_its_certified_view() {
        let (participants, schemes) = vote_fixture();
        let mut reporter = audit_reporter(0, &participants, &schemes);
        record_certify_result(&reporter, &proposal(2, 1, 0xB), true);
        record_certify_result(&reporter, &proposal(3, 2, 0xC), true);
        reporter.report(Activity::Certification(notarization_activity_from(
            &schemes,
            &[1, 2, 3],
            3,
            2,
            0xC,
        )));
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 3)));
        reporter.report(Activity::Nullification(nullification_activity(&schemes, 4)));
        record_automaton(
            &reporter,
            AutomatonEvent::VerifyRequested {
                context: automaton_context_with_parent_digest(
                    participants[1].clone(),
                    &proposal(5, 2, 0xD),
                    digest(0xB),
                ),
                payload: digest(0xD),
            },
        );
        check_fuzz_invariants(TermLength::ONE, std::slice::from_ref(&reporter));
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &byzantine,
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep_a, rep_b],
        );
    }

    #[test]
    #[should_panic(expected = "finalize vote without notarization in view 5")]
    fn finalize_vote_without_notarization_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[1], proposal(5, 4, 0xA)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
    }

    #[test]
    fn byzantine_finalize_vote_without_notarization_is_allowed() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Finalize(
            Finalize::sign(&schemes[0], proposal(5, 4, 0xA)).unwrap(),
        ));
        let byzantine: HashSet<usize> = [0].into_iter().collect();
        check_vote_invariants_with_byzantine(
            &byzantine,
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
    }

    #[test]
    #[should_panic(expected = "nullification certificate at genesis view 0")]
    fn nullified_genesis_view_is_rejected() {
        let r = replica(
            views(vec![]),
            views(vec![(0, nullification())]),
            views(vec![]),
        );
        check::<SimplexId>(TermLength::ONE, vec![r]);
    }

    #[test]
    #[should_panic(expected = "nullify vote at genesis view 0")]
    fn correct_signer_genesis_vote_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[1], round(0)).unwrap(),
        ));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
    }

    #[test]
    fn byzantine_genesis_vote_is_allowed() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Nullify(
            Nullify::sign::<Sha256Digest>(&schemes[0], round(0)).unwrap(),
        ));
        let byzantine: HashSet<usize> = [0].into_iter().collect();
        check_vote_invariants_with_byzantine(
            &byzantine,
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
    }

    #[test]
    #[should_panic(expected = "nullification certificate at genesis view 0")]
    fn nullification_certificate_at_genesis_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Nullification(nullification_activity(&schemes, 0)));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &byzantine,
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
    }

    #[test]
    #[should_panic(expected = "finalize vote without notarization in view 5")]
    fn finalization_certificate_without_notarization_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Finalization(finalization_activity(
            &schemes, 5, 4, 0xA,
        )));
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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
        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
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

    fn threshold_nullification(
        schemes: &[ThresholdScheme],
        view: u64,
    ) -> SimplexNullification<ThresholdScheme> {
        let votes: Vec<_> = schemes[..Q]
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round(view)).unwrap())
            .collect();
        SimplexNullification::from_nullifies(&schemes[0], &votes, &Sequential).unwrap()
    }

    fn threshold_finalization(
        schemes: &[ThresholdScheme],
        view: u64,
        parent: u64,
        payload: u8,
    ) -> SimplexFinalization<ThresholdScheme, Sha256Digest> {
        let votes: Vec<_> = schemes[..Q]
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal(view, parent, payload)).unwrap())
            .collect();
        SimplexFinalization::from_finalizes(&schemes[0], &votes, &Sequential).unwrap()
    }

    type ThresholdAuditReporter =
        RecordingReporter<TestRng, ThresholdScheme, RoundRobin, Sha256Digest>;

    fn threshold_audit_reporter(
        observer: usize,
        participants: &[Ed25519PublicKey],
        schemes: &[ThresholdScheme],
    ) -> ThresholdAuditReporter {
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

    #[test]
    #[should_panic(expected = "certificate-derived leader disagrees with recorded leader")]
    fn recorded_leader_conflicting_with_certificate_derivation_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let mut rep = vote_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(notarization_activity(
            &schemes, 5, 4, 0xA,
        )));
        let derived = rep
            .leaders
            .lock()
            .get(&View::new(6))
            .cloned()
            .expect("leader derived from certificate");
        let conflicting = participants
            .iter()
            .find(|participant| **participant != derived)
            .expect("alternative participant")
            .clone();
        rep.leaders.lock().insert(View::new(6), conflicting);
        check_vote_invariants(
            0,
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[rep],
        );
    }

    #[test]
    #[should_panic(expected = "lacks a recorded leader at its target view 6")]
    fn nullification_recorded_at_wrong_target_is_rejected() {
        let (participants, schemes) = vote_fixture();
        let term_length = TermLength::new(NZU32!(5));
        let mut rep = term_vote_reporter(&participants, &schemes, term_length);
        rep.report(Activity::Nullification(nullification_activity(&schemes, 2)));
        // Model a recording bug that used the rotation target: the election
        // for the term anchor (view 6) is moved to the next-view slot, leaving
        // the derived and recorded key sets disjoint.
        let recorded = rep
            .leaders
            .lock()
            .remove(&View::new(6))
            .expect("recorded target");
        rep.leaders.lock().insert(View::new(3), recorded);
        check_certificate_leader_derivation(
            RoundRobin::default().with_term(term_length, Duration::from_secs(10)),
            term_length,
            &[rep],
        );
    }

    fn record_threshold_certify_success(reporter: &ThresholdAuditReporter) {
        reporter
            .audit()
            .record(Event::Automaton(AutomatonEvent::CertifyCompleted {
                round: round(5),
                payload: digest(0xA),
                outcome: Completion::Returned(true),
            }));
    }

    fn record_threshold_verify_acceptance(
        reporter: &ThresholdAuditReporter,
        leader: Ed25519PublicKey,
    ) {
        reporter
            .audit()
            .record(Event::Automaton(AutomatonEvent::VerifyCompleted {
                context: Context {
                    round: round(5),
                    leader,
                    parent: (View::new(4), digest(0xF)),
                },
                payload: digest(0xA),
                outcome: Completion::Returned(true),
            }));
    }

    fn random_elector_reporter(
        participants: &[Ed25519PublicKey],
        schemes: &[ThresholdScheme],
    ) -> Reporter<TestRng, ThresholdScheme, Random, Sha256Digest> {
        Reporter::new(
            test_rng(),
            ReporterConfig {
                participants: Set::try_from(participants.to_vec()).expect("unique keys"),
                scheme: schemes[0].clone(),
                elector: Random,
            },
        )
    }

    #[test]
    fn seed_dependent_certificate_derivations_agree() {
        let (participants, schemes) = threshold_vote_fixture();
        let mut rep = random_elector_reporter(&participants, &schemes);
        rep.report(Activity::Notarization(threshold_notarization(
            &schemes, 0xA,
        )));
        rep.report(Activity::Nullification(threshold_nullification(
            &schemes, 5,
        )));
        check_certificate_leader_derivation(Random, TermLength::ONE, &[rep]);
    }

    #[test]
    #[should_panic(expected = "retained certificates derive conflicting leaders")]
    fn conflicting_certificate_derivations_are_rejected() {
        let (participants, schemes) = threshold_vote_fixture();
        let mut rep = random_elector_reporter(&participants, &schemes);
        let notarization = threshold_notarization(&schemes, 0xA);
        let elector = Random.build(&rep.participants);
        let expected = elector.elect(round(6), Some(&notarization.certificate));
        rep.report(Activity::Notarization(notarization));

        // Model a seed fork by attaching a certificate body from a round whose
        // seed provably elects a different leader to a view-5 nullification.
        let mismatched = (6..=64)
            .map(|view| threshold_nullification(&schemes, view))
            .find(|certificate| elector.elect(round(6), Some(&certificate.certificate)) != expected)
            .expect("threshold fixture must contain a seed electing another participant");
        let doctored = SimplexNullification::<ThresholdScheme> {
            round: round(5),
            certificate: mismatched.certificate,
        };
        rep.nullifications.lock().insert(View::new(5), doctored);
        check_certificate_leader_derivation(Random, TermLength::ONE, &[rep]);
    }

    // The non-attributable backing tests model the real N4F1C3 audit boundary:
    // correct reporters 1, 2, and 3 with Byzantine prefix participant 0 omitted,
    // so the required holder count is quorum(4) - (4 - 3) = 2.
    #[test]
    fn finalization_with_quorum_certification_backing_passes() {
        let (participants, schemes) = threshold_vote_fixture();
        let mut rep_1 = threshold_audit_reporter(1, &participants, &schemes);
        let rep_2 = threshold_audit_reporter(2, &participants, &schemes);
        let rep_3 = threshold_audit_reporter(3, &participants, &schemes);
        record_threshold_certify_success(&rep_1);
        record_threshold_certify_success(&rep_2);
        rep_1.report(Activity::Finalization(threshold_finalization(
            &schemes, 5, 4, 0xA,
        )));
        check_fuzz_invariants(TermLength::ONE, &[rep_1, rep_2, rep_3]);
    }

    #[test]
    #[should_panic(expected = "finalization certificate lacks quorum certification backing")]
    fn finalization_without_quorum_certification_backing_is_rejected() {
        let (participants, schemes) = threshold_vote_fixture();
        let mut rep_1 = threshold_audit_reporter(1, &participants, &schemes);
        let rep_2 = threshold_audit_reporter(2, &participants, &schemes);
        let rep_3 = threshold_audit_reporter(3, &participants, &schemes);
        record_threshold_certify_success(&rep_1);
        rep_1.report(Activity::Finalization(threshold_finalization(
            &schemes, 5, 4, 0xA,
        )));
        check_fuzz_invariants(TermLength::ONE, &[rep_1, rep_2, rep_3]);
    }

    #[test]
    fn notarization_with_quorum_acceptance_backing_passes() {
        let (participants, schemes) = threshold_vote_fixture();
        let mut rep_1 = threshold_audit_reporter(1, &participants, &schemes);
        let rep_2 = threshold_audit_reporter(2, &participants, &schemes);
        let rep_3 = threshold_audit_reporter(3, &participants, &schemes);
        record_threshold_verify_acceptance(&rep_1, participants[3].clone());
        record_threshold_verify_acceptance(&rep_2, participants[3].clone());
        rep_1.report(Activity::Notarization(threshold_notarization(
            &schemes, 0xA,
        )));
        check_fuzz_invariants(TermLength::ONE, &[rep_1, rep_2, rep_3]);
    }

    #[test]
    #[should_panic(expected = "notarization certificate lacks quorum acceptance backing")]
    fn notarization_without_quorum_acceptance_backing_is_rejected() {
        let (participants, schemes) = threshold_vote_fixture();
        let mut rep_1 = threshold_audit_reporter(1, &participants, &schemes);
        let rep_2 = threshold_audit_reporter(2, &participants, &schemes);
        let rep_3 = threshold_audit_reporter(3, &participants, &schemes);
        record_threshold_verify_acceptance(&rep_1, participants[3].clone());
        rep_1.report(Activity::Notarization(threshold_notarization(
            &schemes, 0xA,
        )));
        check_fuzz_invariants(TermLength::ONE, &[rep_1, rep_2, rep_3]);
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

        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[reporter],
        );
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

        check_vote_invariants_with_byzantine(
            &HashSet::new(),
            RoundRobin::default(),
            Epoch::new(0),
            TermLength::ONE,
            &[reporter],
        );
    }
}
