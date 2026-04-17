//! Mutations that operate on canonical [`Event`] sequences.
//!
//! Counterpart of the legacy [`super`] mutator that works on
//! `Vec<TraceEntry>`. The legacy module remains in place during the
//! migration because its [`super::run`] driver is deeply coupled to
//! [`TraceData`] and the TLC feedback loop; it will be retired together
//! with the rest of the legacy trace shape in task #14.
//!
//! These canonical mutations rearrange [`Event::Deliver`] entries only.
//! [`Event::Propose`], [`Event::Construct`], and [`Event::Timeout`]
//! define the causal skeleton of a trace (a `Propose` produces the
//! payload that `Construct(Notarize)` and subsequent `Deliver`s refer
//! to; a `Construct` must precede its corresponding `Deliver`s from
//! that sender) and are left in place. Mutations that disturb this
//! skeleton are either rejected or never attempted.

use commonware_consensus::{
    simplex::{
        replay::{Event, Trace, Wire},
        types::{Attributable, Certificate, Vote},
    },
    Viewable,
};
use commonware_utils::Participant;
use rand::{seq::SliceRandom, Rng, RngCore};
use std::collections::{HashMap, HashSet};

/// All mutations supported by the canonical mutator.
///
/// A subset of the legacy `Mutation` enum is supported; the rest
/// (byzantine-specific mutations like `Duplicate` and `ReverseRange`
/// that rewrite message content) are left as future work.
///
/// Crate-private because the only supported way to mutate a trace is
/// [`mutate_once`], which enforces the honest-trace invariant and
/// clears stale `expected` snapshots. Tests and higher-level mutation
/// schedulers inside this crate may reach in; external drivers must go
/// through [`mutate_once`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mutation {
    /// Swap two adjacent `Deliver` entries.
    SwapAdjacent,
    /// Reverse a contiguous run of `Deliver` entries.
    ReverseRange,
    /// Delay a single `sender -> receiver` link (all `Deliver` events
    /// matching that pair shift later within a random window).
    DelayLink,
    /// Delay all `Deliver` events with a chosen `from` sender.
    DelaySender,
    /// Delay all `Deliver` events with a chosen `to` receiver.
    DelayRecipient,
}

/// See [`Mutation`] for visibility rationale.
pub(crate) const ALL_MUTATIONS: &[Mutation] = &[
    Mutation::SwapAdjacent,
    Mutation::ReverseRange,
    Mutation::DelayLink,
    Mutation::DelaySender,
    Mutation::DelayRecipient,
];

/// Applies a single randomly-picked mutation in place.
///
/// **Raw primitive — does not enforce
/// [`preserves_first_broadcast_order`] and does not touch
/// [`Trace::expected`].** Use [`mutate_once`] as the safe entry point;
/// this function is `pub(crate)` so it can be unit-tested and composed
/// by future schedulers inside the crate without external callers
/// accidentally producing invalid candidate traces.
///
/// Returns `true` if a mutation succeeded, `false` if no candidate
/// applied (e.g. the trace has fewer than 2 `Deliver` events).
pub(crate) fn apply_mutation<R: RngCore>(events: &mut Vec<Event>, rng: &mut R) -> bool {
    let mut candidates: Vec<Mutation> = ALL_MUTATIONS.to_vec();
    candidates.shuffle(rng);
    for m in candidates {
        if try_mutation(events, rng, m) {
            return true;
        }
    }
    false
}

/// Applies the named mutation.
///
/// **Raw primitive — see [`apply_mutation`] safety notes.** Exposed
/// `pub(crate)` so tests can force a specific mutation type; drivers
/// outside this crate must use [`mutate_once`].
pub(crate) fn try_mutation<R: RngCore>(
    events: &mut Vec<Event>,
    rng: &mut R,
    m: Mutation,
) -> bool {
    match m {
        Mutation::SwapAdjacent => swap_adjacent(events, rng),
        Mutation::ReverseRange => reverse_range(events, rng),
        Mutation::DelayLink => delay_link(events, rng),
        Mutation::DelaySender => delay_sender(events, rng),
        Mutation::DelayRecipient => delay_recipient(events, rng),
    }
}

/// Mutate a canonical [`Trace`] and return the result.
///
/// Returns `None` if no mutation was applicable.
///
/// ## Safety: `expected` is cleared
///
/// Reordering events changes the model's final state, so the
/// parent's [`Trace::expected`] snapshot is **not valid** for the
/// mutated event sequence. This function sets the returned trace's
/// [`Trace::expected`] to [`Snapshot::default`] — it's explicitly a
/// candidate that must be re-validated (e.g., via Quint/TLC feedback
/// and a fresh replay) before `expected` is re-populated.
///
/// An empty `expected` reliably fails strict replay comparison,
/// surfacing any accidental attempt to compare a bare candidate
/// against a replay result.
pub fn mutate_once<R: RngCore>(trace: &Trace, rng: &mut R) -> Option<Trace> {
    use commonware_consensus::simplex::replay::Snapshot;
    let original_events = trace.events.clone();
    let mut mutated = trace.clone();
    if !apply_mutation(&mut mutated.events, rng) {
        return None;
    }
    // Enforce the honest-trace invariant: first-broadcast order must
    // be preserved (see `preserves_first_broadcast_order`).
    if !preserves_first_broadcast_order(&original_events, &mutated.events) {
        return None;
    }
    // Candidate trace — `expected` is stale and must be revalidated.
    mutated.expected = Snapshot::default();
    Some(mutated)
}

// --- Mutations ---------------------------------------------------------

/// Indices of `Event::Deliver` entries in `events`.
fn deliver_indices(events: &[Event]) -> Vec<usize> {
    events
        .iter()
        .enumerate()
        .filter_map(|(i, e)| matches!(e, Event::Deliver { .. }).then_some(i))
        .collect()
}

/// Extract (from, to) for a Deliver event. Panics for non-Deliver.
fn deliver_pair(events: &[Event], idx: usize) -> (Participant, Participant) {
    match &events[idx] {
        Event::Deliver { from, to, .. } => (*from, *to),
        _ => panic!("expected Deliver at idx {idx}"),
    }
}

fn swap_adjacent<R: RngCore>(events: &mut [Event], rng: &mut R) -> bool {
    let delivers = deliver_indices(events);
    // Find an adjacent pair of Deliver indices (i, j) where j > i.
    let mut adjacent_pairs: Vec<(usize, usize)> = Vec::new();
    for w in delivers.windows(2) {
        if w[1] == w[0] + 1 {
            adjacent_pairs.push((w[0], w[1]));
        }
    }
    if adjacent_pairs.is_empty() {
        return false;
    }
    adjacent_pairs.shuffle(rng);
    let (i, j) = adjacent_pairs[0];
    events.swap(i, j);
    true
}

fn reverse_range<R: RngCore>(events: &mut [Event], rng: &mut R) -> bool {
    let delivers = deliver_indices(events);
    if delivers.len() < 2 {
        return false;
    }
    // Pick a contiguous run of Deliver indices (unbroken by non-Deliver
    // events) and reverse it.
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut run_start = delivers[0];
    let mut last = delivers[0];
    for &idx in &delivers[1..] {
        if idx == last + 1 {
            last = idx;
        } else {
            if last > run_start {
                runs.push((run_start, last));
            }
            run_start = idx;
            last = idx;
        }
    }
    if last > run_start {
        runs.push((run_start, last));
    }
    if runs.is_empty() {
        return false;
    }
    runs.shuffle(rng);
    let (lo, hi) = runs[0];
    events[lo..=hi].reverse();
    true
}

fn delay_link<R: RngCore>(events: &mut Vec<Event>, rng: &mut R) -> bool {
    let delivers = deliver_indices(events);
    if delivers.is_empty() {
        return false;
    }
    // Group Deliver indices by (from, to).
    let mut groups: HashMap<(Participant, Participant), Vec<usize>> = HashMap::new();
    for idx in &delivers {
        let pair = deliver_pair(events, *idx);
        groups.entry(pair).or_default().push(*idx);
    }
    let candidates: Vec<_> = groups
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .collect();
    if candidates.is_empty() {
        return false;
    }
    let pick_idx = rng.gen_range(0..candidates.len());
    let (_pair, indices) = &candidates[pick_idx];
    shift_group_later(events, indices, rng)
}

fn delay_sender<R: RngCore>(events: &mut Vec<Event>, rng: &mut R) -> bool {
    let delivers = deliver_indices(events);
    if delivers.is_empty() {
        return false;
    }
    let mut groups: HashMap<Participant, Vec<usize>> = HashMap::new();
    for idx in &delivers {
        let (from, _) = deliver_pair(events, *idx);
        groups.entry(from).or_default().push(*idx);
    }
    let senders: Vec<_> = groups.keys().copied().collect();
    if senders.is_empty() {
        return false;
    }
    let sender = senders[rng.gen_range(0..senders.len())];
    let idxs = groups.remove(&sender).unwrap();
    shift_group_later(events, &idxs, rng)
}

fn delay_recipient<R: RngCore>(events: &mut Vec<Event>, rng: &mut R) -> bool {
    let delivers = deliver_indices(events);
    if delivers.is_empty() {
        return false;
    }
    let mut groups: HashMap<Participant, Vec<usize>> = HashMap::new();
    for idx in &delivers {
        let (_, to) = deliver_pair(events, *idx);
        groups.entry(to).or_default().push(*idx);
    }
    let receivers: Vec<_> = groups.keys().copied().collect();
    if receivers.is_empty() {
        return false;
    }
    let receiver = receivers[rng.gen_range(0..receivers.len())];
    let idxs = groups.remove(&receiver).unwrap();
    shift_group_later(events, &idxs, rng)
}

/// Shift all events at `indices` forward by the same random distance
/// while preserving their relative order. The shift distance is bounded
/// by the distance between the last index and the trace's tail, so the
/// last-in-group stays within bounds.
///
/// Returns `true` if any shift occurred; `false` when the group is
/// empty or already at the tail.
fn shift_group_later<R: RngCore>(
    events: &mut Vec<Event>,
    indices: &[usize],
    rng: &mut R,
) -> bool {
    if indices.is_empty() {
        return false;
    }
    // Sorted ascending — contract with callers who build via iteration.
    debug_assert!(indices.windows(2).all(|w| w[0] < w[1]));
    let n = events.len();
    let last = *indices.last().unwrap();
    if last + 1 >= n {
        return false;
    }
    let max_shift = n - last - 1;
    let shift = rng.gen_range(1..=max_shift);

    // Extract the matching events (in reverse so earlier indices don't
    // shift), then re-insert each at its original position + shift.
    // Re-insertion is done in ascending order so earlier items land
    // before later ones, preserving relative order.
    let mut extracted: Vec<(usize, Event)> = Vec::with_capacity(indices.len());
    for &i in indices.iter().rev() {
        let e = events.remove(i);
        extracted.push((i, e));
    }
    extracted.reverse(); // back to ascending by original index
    for (orig, e) in extracted {
        // After removals preceding this index, the current target is
        // `orig + shift` minus the number of already-re-inserted items
        // ahead of us — but we haven't re-inserted any yet for this
        // iteration because we reverse-extracted. The vector has
        // shrunk by `indices.len()` from the removals; we re-insert at
        // `orig + shift`, clamped to the current length.
        let target = (orig + shift).min(events.len());
        events.insert(target, e);
    }
    true
}

// --- Metadata extraction helpers --------------------------------------
//
// Exposed crate-publicly so other fuzz-level code (mutation schedulers,
// corpus deduplicators) can reason about canonical events without
// re-matching on every variant.

/// Opaque per-event identity used for corpus dedup. Distinguishes
/// every recorded event, including each receiver of a broadcast
/// (`Deliver { to, from, msg }` entries with the same `from` and `msg`
/// but different `to` are *different* identities here).
///
/// Use [`broadcast_identity`] instead when you want to reason about
/// broadcast-level order (what the sender produced), not per-delivery
/// position.
pub fn event_identity(event: &Event) -> String {
    match event {
        Event::Deliver { to, from, msg } => match msg {
            Wire::Vote(v) => format!("D:{}:{}:{}", from.get(), to.get(), vote_identity(v)),
            Wire::Cert(c) => format!("D:{}:{}:{}", from.get(), to.get(), cert_identity(c)),
        },
        Event::Construct { node, vote } => {
            format!("C:{}:{}", node.get(), vote_identity(vote))
        }
        Event::Propose { leader, proposal } => format!(
            "P:{}:{}:{}",
            leader.get(),
            proposal.view().get(),
            payload_hex(&proposal.payload)
        ),
        Event::Timeout { node, view, reason } => {
            format!("T:{}:{}:{:?}", node.get(), view.get(), reason)
        }
    }
}

/// Broadcast-level identity: collapses all `Deliver` events of a given
/// `(sender, message)` to the same key regardless of receiver. Used by
/// [`preserves_first_broadcast_order`] so reordering deliveries (fine
/// for honest traces) does not spuriously violate the invariant.
///
/// For non-`Deliver` events this coincides with [`event_identity`].
pub fn broadcast_identity(event: &Event) -> String {
    match event {
        Event::Deliver { from, msg, .. } => match msg {
            Wire::Vote(v) => format!("B:{}:{}", from.get(), vote_identity(v)),
            Wire::Cert(c) => format!("B:{}:{}", from.get(), cert_identity(c)),
        },
        _ => event_identity(event),
    }
}

fn vote_identity(vote: &Vote<commonware_consensus::simplex::scheme::ed25519::Scheme, commonware_cryptography::sha256::Digest>) -> String {
    match vote {
        Vote::Notarize(n) => format!(
            "N:{}:{}:{}",
            n.signer().get(),
            n.view().get(),
            payload_hex(&n.proposal.payload)
        ),
        Vote::Nullify(n) => format!("U:{}:{}", n.signer().get(), n.view().get()),
        Vote::Finalize(f) => format!(
            "F:{}:{}:{}",
            f.signer().get(),
            f.view().get(),
            payload_hex(&f.proposal.payload)
        ),
    }
}

fn cert_identity(cert: &Certificate<commonware_consensus::simplex::scheme::ed25519::Scheme, commonware_cryptography::sha256::Digest>) -> String {
    match cert {
        Certificate::Notarization(n) => {
            let signers: Vec<u32> = n.certificate.signers.iter().map(|p| p.get()).collect();
            format!(
                "CN:{}:{}:{:?}",
                n.view().get(),
                payload_hex(&n.proposal.payload),
                signers
            )
        }
        Certificate::Nullification(n) => {
            let signers: Vec<u32> = n.certificate.signers.iter().map(|p| p.get()).collect();
            format!("CU:{}:{:?}", n.view().get(), signers)
        }
        Certificate::Finalization(f) => {
            let signers: Vec<u32> = f.certificate.signers.iter().map(|p| p.get()).collect();
            format!(
                "CF:{}:{}:{:?}",
                f.view().get(),
                payload_hex(&f.proposal.payload),
                signers
            )
        }
    }
}

fn payload_hex(d: &commonware_cryptography::sha256::Digest) -> String {
    d.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Whether the mutated event sequence preserves the first-broadcast
/// order present in `original`. Uses [`broadcast_identity`] so that
/// reorderings *across receivers of the same broadcast* do not count
/// as a violation — only the relative order of distinct broadcasts
/// (distinct `(sender, message)` pairs) must be preserved.
///
/// This is an honest-trace invariant: a mutated trace that still
/// satisfies it can only have disturbed network-level delivery order
/// within a given broadcast, not the causal order of distinct
/// broadcasts themselves.
pub fn preserves_first_broadcast_order(original: &[Event], mutated: &[Event]) -> bool {
    let first_seen = |events: &[Event]| -> HashMap<String, usize> {
        let mut out = HashMap::new();
        for (idx, e) in events.iter().enumerate() {
            let id = broadcast_identity(e);
            out.entry(id).or_insert(idx);
        }
        out
    };
    let orig_order: Vec<String> = {
        let mut seen: HashSet<String> = HashSet::new();
        let mut out = Vec::new();
        for e in original {
            let id = broadcast_identity(e);
            if seen.insert(id.clone()) {
                out.push(id);
            }
        }
        out
    };
    let mutated_first = first_seen(mutated);
    let mut prev_idx: Option<usize> = None;
    for id in orig_order {
        let Some(&idx) = mutated_first.get(&id) else {
            return false;
        };
        if prev_idx.is_some_and(|p| idx <= p) {
            return false;
        }
        prev_idx = Some(idx);
    }
    true
}

// --- Canonical TLC mutator driver -------------------------------------

/// Entry point for the canonical trace-mutator binary
/// (`trace_mutator_canonical`).
///
/// Stage 1 stub: the Trace-native TLC feedback loop is implemented in
/// Stage 5 (task #37). Today the legacy driver in `super::run` is the
/// only functional mutator and operates on `TraceData`; this stub is
/// only wired up so the `trace_mutator_canonical` binary compiles and
/// the other three canonical binaries (`replay_canonical_trace`,
/// `validate_canonical_trace_corpus`, `generate_canonical_seeds`) are
/// usable end-to-end.
pub fn run_canonical() -> ! {
    panic!(
        "trace_mutator::canonical::run_canonical is not implemented yet; \
         the Trace-native TLC feedback loop arrives in Stage 5 (task #37). \
         For now use the legacy driver via `cargo run --bin trace_mutator` \
         with canonical seeds produced by `generate_canonical_seeds`."
    );
}

// --- Tests ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{
        simplex::{
            replay::trace::{Timing, Topology},
            scheme::ed25519::Scheme,
            types::{Notarize, Proposal, Vote},
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_runtime::{deterministic, Runner};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn fixture() -> commonware_cryptography::certificate::mocks::Fixture<Scheme> {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(None));
        let cc = captured.clone();
        let runner = deterministic::Runner::seeded(0);
        runner.start(|mut ctx| async move {
            let fx = commonware_consensus::simplex::scheme::ed25519::fixture(
                &mut ctx,
                b"consensus_fuzz",
                4,
            );
            *cc.lock().unwrap() = Some(fx);
        });
        let mut g = captured.lock().unwrap();
        g.take().unwrap()
    }

    fn make_deliver(
        fx: &commonware_cryptography::certificate::mocks::Fixture<Scheme>,
        from: u32,
        to: u32,
        view: u64,
        payload_seed: u8,
    ) -> Event {
        let round = Round::new(Epoch::new(0), View::new(view));
        let proposal = Proposal::new(
            round,
            View::new(view.saturating_sub(1)),
            Sha256Digest([payload_seed; 32]),
        );
        let notarize =
            Notarize::<Scheme, Sha256Digest>::sign(&fx.schemes[from as usize], proposal)
                .unwrap();
        Event::Deliver {
            to: Participant::new(to),
            from: Participant::new(from),
            msg: Wire::Vote(Vote::Notarize(notarize)),
        }
    }

    fn sample_events(fx: &commonware_cryptography::certificate::mocks::Fixture<Scheme>) -> Vec<Event> {
        vec![
            make_deliver(fx, 0, 1, 1, 1),
            make_deliver(fx, 0, 2, 1, 1),
            make_deliver(fx, 0, 3, 1, 1),
            make_deliver(fx, 1, 0, 1, 2),
            make_deliver(fx, 1, 2, 1, 2),
            make_deliver(fx, 1, 3, 1, 2),
            make_deliver(fx, 2, 0, 1, 3),
            make_deliver(fx, 2, 1, 1, 3),
            make_deliver(fx, 2, 3, 1, 3),
        ]
    }

    fn identities(events: &[Event]) -> Vec<String> {
        events.iter().map(event_identity).collect()
    }

    #[test]
    fn swap_adjacent_changes_order() {
        let fx = fixture();
        let mut events = sample_events(&fx);
        let original_ids = identities(&events);
        let mut rng = StdRng::seed_from_u64(42);
        assert!(try_mutation(&mut events, &mut rng, Mutation::SwapAdjacent));
        let new_ids = identities(&events);
        assert_ne!(new_ids, original_ids);
        assert_eq!(events.len(), original_ids.len());
    }

    #[test]
    fn reverse_range_changes_order() {
        let fx = fixture();
        let mut events = sample_events(&fx);
        let original_ids = identities(&events);
        let mut rng = StdRng::seed_from_u64(7);
        assert!(try_mutation(&mut events, &mut rng, Mutation::ReverseRange));
        let new_ids = identities(&events);
        assert_ne!(new_ids, original_ids);
        assert_eq!(events.len(), original_ids.len());
    }

    #[test]
    fn delay_link_preserves_length() {
        let fx = fixture();
        let mut events = sample_events(&fx);
        let original_len = events.len();
        let mut rng = StdRng::seed_from_u64(1234);
        let _ = try_mutation(&mut events, &mut rng, Mutation::DelayLink);
        assert_eq!(events.len(), original_len);
    }

    #[test]
    fn delay_sender_preserves_length() {
        let fx = fixture();
        let mut events = sample_events(&fx);
        let original_len = events.len();
        let mut rng = StdRng::seed_from_u64(55);
        let _ = try_mutation(&mut events, &mut rng, Mutation::DelaySender);
        assert_eq!(events.len(), original_len);
    }

    #[test]
    fn delay_recipient_preserves_length() {
        let fx = fixture();
        let mut events = sample_events(&fx);
        let original_len = events.len();
        let mut rng = StdRng::seed_from_u64(98);
        let _ = try_mutation(&mut events, &mut rng, Mutation::DelayRecipient);
        assert_eq!(events.len(), original_len);
    }

    #[test]
    fn apply_mutation_eventually_succeeds() {
        let fx = fixture();
        let mut events = sample_events(&fx);
        let mut rng = StdRng::seed_from_u64(2026);
        // Over many tries at least one mutation must succeed.
        let mut any = false;
        for _ in 0..50 {
            if apply_mutation(&mut events, &mut rng) {
                any = true;
                break;
            }
        }
        assert!(any);
    }

    #[test]
    fn apply_mutation_fails_on_empty_and_singleton() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut empty: Vec<Event> = Vec::new();
        assert!(!apply_mutation(&mut empty, &mut rng));
        // Singleton: no mutation applies because all mutations need ≥2
        // Deliver events to produce a change.
        let fx = fixture();
        let mut one = vec![make_deliver(&fx, 0, 1, 1, 1)];
        assert!(!apply_mutation(&mut one, &mut rng));
    }

    #[test]
    fn mutate_once_preserves_topology_and_clears_expected() {
        use commonware_consensus::simplex::replay::trace::{CertStateSnapshot, NodeSnapshot};
        use commonware_consensus::simplex::replay::Snapshot;
        use commonware_consensus::types::View;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        let fx = fixture();
        // Build a non-default `expected` snapshot to prove mutate_once
        // clears it.
        let mut nodes = std::collections::BTreeMap::new();
        let mut node = NodeSnapshot::default();
        node.notarizations.insert(
            View::new(1),
            CertStateSnapshot {
                payload: Sha256Digest([9u8; 32]),
                signature_count: Some(3),
            },
        );
        nodes.insert(Participant::new(0), node);
        let expected = Snapshot { nodes };

        let trace = Trace {
            topology: Topology {
                n: 4,
                faults: 0,
                epoch: 0,
                namespace: b"consensus_fuzz".to_vec(),
                timing: Timing::default(),
            },
            events: sample_events(&fx),
            expected,
        };
        let mut rng = StdRng::seed_from_u64(42);
        let mutated = mutate_once(&trace, &mut rng).expect("mutation must succeed");
        assert_eq!(mutated.topology.n, trace.topology.n);
        assert_eq!(mutated.topology.namespace, trace.topology.namespace);
        assert_eq!(mutated.events.len(), trace.events.len());
        assert!(
            mutated.expected.nodes.is_empty(),
            "mutate_once must clear expected (stale after reordering)"
        );
    }

    #[test]
    fn event_identity_distinguishes_senders() {
        let fx = fixture();
        let a = make_deliver(&fx, 0, 1, 1, 7);
        let b = make_deliver(&fx, 2, 1, 1, 7); // different sender
        assert_ne!(event_identity(&a), event_identity(&b));
    }

    #[test]
    fn event_identity_distinguishes_receivers_but_broadcast_identity_does_not() {
        let fx = fixture();
        let to1 = make_deliver(&fx, 0, 1, 1, 7);
        let to2 = make_deliver(&fx, 0, 2, 1, 7); // same broadcast, different receiver
        assert_ne!(
            event_identity(&to1),
            event_identity(&to2),
            "event_identity distinguishes per-receiver"
        );
        assert_eq!(
            broadcast_identity(&to1),
            broadcast_identity(&to2),
            "broadcast_identity collapses across receivers"
        );
    }

    #[test]
    fn preserves_first_broadcast_order_true_for_noop() {
        let fx = fixture();
        let events = sample_events(&fx);
        assert!(preserves_first_broadcast_order(&events, &events));
    }

    #[test]
    fn preserves_first_broadcast_order_allows_per_receiver_reorder() {
        // Rearranging deliveries OF THE SAME broadcast (same sender,
        // same vote) is allowed — broadcast identity ignores `to`.
        let fx = fixture();
        let events = sample_events(&fx);
        // Swap two adjacent deliveries of the first broadcast
        // (from n0 to n1, n2, n3 → rearrange to n2, n1, n3).
        let mut mutated = events.clone();
        mutated.swap(0, 1);
        assert!(preserves_first_broadcast_order(&events, &mutated));
    }

    #[test]
    fn preserves_first_broadcast_order_rejects_distinct_broadcast_swap() {
        // Reordering the first appearance of DISTINCT broadcasts
        // (n0's and n1's notarizes) is a violation.
        let fx = fixture();
        let events = sample_events(&fx);
        let mut mutated = events.clone();
        // Move n1's first broadcast (index 3) before any of n0's.
        let item = mutated.remove(3);
        mutated.insert(0, item);
        assert!(!preserves_first_broadcast_order(&events, &mutated));
    }

    #[test]
    fn shift_group_later_shifts_all_matching_indices() {
        // Regression for the low-severity bug: delay_* mutations must
        // shift every matching delivery by the same amount, not just
        // one. Test `shift_group_later` directly so we're not subject
        // to which sender `delay_sender`'s random group selection
        // happens to pick.
        let fx = fixture();
        let mut events = sample_events(&fx);
        // n0's three deliveries are at indices 0, 1, 2.
        let group = vec![0usize, 1, 2];
        let mut rng = StdRng::seed_from_u64(123);
        assert!(shift_group_later(&mut events, &group, &mut rng));

        let n0_positions: Vec<usize> = events
            .iter()
            .enumerate()
            .filter_map(|(i, e)| match e {
                Event::Deliver { from, .. } if from.get() == 0 => Some(i),
                _ => None,
            })
            .collect();
        assert_eq!(n0_positions.len(), 3, "all three n0 deliveries present");
        // All three must have shifted by the same offset — still
        // consecutive (indices differ by 1).
        assert_eq!(
            n0_positions[1] - n0_positions[0],
            1,
            "n0 deliveries not contiguous after group shift"
        );
        assert_eq!(
            n0_positions[2] - n0_positions[1],
            1,
            "n0 deliveries not contiguous after group shift"
        );
        // And they must have moved forward: not still at 0..=2.
        assert!(
            n0_positions[0] > 0,
            "group shift did not actually move the group"
        );
    }
}
