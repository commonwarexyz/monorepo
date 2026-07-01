//! State-coverage feedback for the Simplex harness.
//!
//! This module adds a second, protocol-aware signal: it projects the end-of-run per-replica
//! state to a set of canonical *state tokens* (`alpha`) and lights, for each
//! token, one counter in a large custom SanitizerCoverage table indexed by a
//! stable hash of the token.
//!
//! The token set is the novelty signal. libFuzzer turns each non-zero counter
//! into a feature independently (with `-use_counters=1`, bucketed by magnitude),
//! so a single fixed feature vector would only ever express per-dimension
//! progress: distinct abstract states that share every counter's bucket collapse.
//! Hashing each token to its own counter instead means a state token never
//! reached before in the campaign lights a previously-zero counter, so the input
//! is retained for protocol-state novelty even when it lights no new code edge.
//!
//! Tokens are structural and `(view, payload)`-aware: payloads are interned to
//! dense class ids so *relationships* between proposals (agreement and
//! equivocation across replicas) are captured, while the random digest bytes
//! that would prevent saturation are abstracted away.
//!
//! `alpha` is a pure function of the run's own state. The deterministic runtime
//! makes that state a deterministic function of the fuzz input, which is what
//! libFuzzer requires of a coverage signal.
use crate::{
    invariants::get_signature_count,
    types::{ProposalData, ReporterReplicaStateData},
    utils::fnv1a_hash,
};
use commonware_consensus::simplex::{
    elector::Config as Elector, mocks::reporter::Reporter, scheme::Scheme,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_runtime::telemetry::traces::collector::RecordedEvent;
use rand_core::CryptoRngCore;
use sancov::Counters;
use std::collections::{BTreeMap, BTreeSet};
use tracing::Level;

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Projects each replica reporter data into a [`ReporterReplicaStateData`], keyed by
/// replica index. Retains per-view certificate facts, signature counts, and the
/// finalized frontier for the state-coverage abstraction below.
pub fn encode_reporter_states<E, S, L>(
    reporters: &[Reporter<E, S, L, Sha256Digest>],
    max_participants: usize,
) -> BTreeMap<String, ReporterReplicaStateData>
where
    E: CryptoRngCore,
    S: Scheme<Sha256Digest>,
    L: Elector<S>,
{
    reporters
        .iter()
        .enumerate()
        .map(|(idx, reporter)| {
            let mut data = ReporterReplicaStateData::default();

            let notarizations = reporter.notarizations.lock();
            for (view, cert) in notarizations.iter() {
                let v = view.get();
                data.notarizations.insert(
                    v,
                    ProposalData {
                        parent: cert.proposal.parent.get(),
                        payload: lower_hex(cert.proposal.payload.as_ref()),
                    },
                );
                data.notarization_signature_counts.insert(
                    v,
                    get_signature_count::<S>(&cert.certificate, max_participants),
                );
                data.last_notarized = data.last_notarized.max(v);
            }
            drop(notarizations);

            let nullifications = reporter.nullifications.lock();
            for (view, cert) in nullifications.iter() {
                let v = view.get();
                data.nullifications.insert(v);
                data.nullification_signature_counts.insert(
                    v,
                    get_signature_count::<S>(&cert.certificate, max_participants),
                );
                data.last_nullified = data.last_nullified.max(v);
            }
            drop(nullifications);

            let finalizations = reporter.finalizations.lock();
            for (view, cert) in finalizations.iter() {
                let v = view.get();
                data.finalizations.insert(
                    v,
                    ProposalData {
                        parent: cert.proposal.parent.get(),
                        payload: lower_hex(cert.proposal.payload.as_ref()),
                    },
                );
                data.finalization_signature_counts.insert(
                    v,
                    get_signature_count::<S>(&cert.certificate, max_participants),
                );
                data.last_finalized = data.last_finalized.max(v);
            }
            drop(finalizations);

            let certified = reporter.certified.lock();
            data.certified = certified.iter().map(|v| v.get()).collect();
            drop(certified);

            data.successful_certifications = data
                .notarizations
                .keys()
                .chain(data.finalizations.keys())
                .copied()
                .collect();

            // Vote maps advance the frontier past the recovered certificates: a
            // replica may have voted in a view that never formed a certificate.
            let notarizes = reporter.notarizes.lock();
            for (view, by_digest) in notarizes.iter() {
                let v = view.get();
                data.last_notarized = data.last_notarized.max(v);
                let count = by_digest
                    .values()
                    .map(|signers| signers.len())
                    .max()
                    .unwrap_or_default();
                if count > 0 {
                    data.notarize_vote_counts.insert(v, count);
                }
            }
            drop(notarizes);

            let nullifies = reporter.nullifies.lock();
            let leaders = reporter.leaders.lock();
            for (view, signers) in nullifies.iter() {
                let v = view.get();
                data.last_nullified = data.last_nullified.max(v);
                data.nullify_vote_counts.insert(v, signers.len());
                if leaders
                    .get(view)
                    .is_some_and(|leader| signers.contains(leader))
                {
                    data.leader_nullify_views.insert(v);
                }
            }
            drop(leaders);
            drop(nullifies);

            let finalizes = reporter.finalizes.lock();
            for (view, by_digest) in finalizes.iter() {
                let v = view.get();
                let count = by_digest
                    .values()
                    .map(|signers| signers.len())
                    .max()
                    .unwrap_or_default();
                if count > 0 {
                    data.finalize_vote_counts.insert(v, count);
                }
            }
            drop(finalizes);

            (idx.to_string(), data)
        })
        .collect()
}

/// Number of counters in the custom SanitizerCoverage table. Each distinct state
/// token maps (by stable hash) to one counter, so a token never reached before in
/// the campaign lights a previously-zero counter and the input is retained. Sized
/// well above the number of structurally-distinct tokens a small Simplex run
/// produces, to keep hash collisions (two states sharing a counter) rare.
const STATE_COUNTERS: usize = 1 << 16;

static COUNTERS: Counters<STATE_COUNTERS> = Counters::new();

/// Raw pointer to the counter bytes.
///
/// SAFETY: `Counters<N>` is `#[repr(transparent)]` over `UnsafeCell<[u8; N]>`
/// (documented and relied upon by the crate itself), so a shared reference
/// aliases a `[u8; N]` with interior mutability. `reset` and `observe` run
/// single-threaded at a run boundary; nothing else touches the table.
fn table() -> *mut u8 {
    &COUNTERS as *const Counters<STATE_COUNTERS> as *mut u8
}

/// Registers the table with the SanitizerCoverage consumer (once) and zeroes it.
///
/// Called at the start of every run so the counters reflect that run alone.
/// Registration touches a sanitizer symbol that only exists under
/// `-fsanitize=fuzzer`, so it is gated to fuzzing builds; the zeroing is a
/// harmless no-op elsewhere.
pub fn reset() {
    #[cfg(fuzzing)]
    {
        use std::sync::Once;
        static REGISTERED: Once = Once::new();
        REGISTERED.call_once(|| COUNTERS.register());
    }
    // SAFETY: see `table`.
    unsafe { core::ptr::write_bytes(table(), 0, STATE_COUNTERS) };
}

/// Lights state tokens plus timeout-reason tokens extracted from runtime metrics.
pub fn observe_with_metrics(states: &BTreeMap<String, ReporterReplicaStateData>, metrics: &str) {
    let mut tokens: BTreeSet<String> = alpha(states).into_iter().collect();
    tokens.extend(timeout_tokens(metrics));
    observe_tokens(tokens);
}

/// Lights bounded tokens for WARN tracing events emitted by Simplex actors.
pub fn observe_warn_events(events: &[RecordedEvent]) {
    observe_tokens(warn_event_tokens(events));
}

fn observe_tokens(tokens: impl IntoIterator<Item = String>) {
    for token in tokens {
        let idx = (fnv1a_hash(token.as_bytes()) % STATE_COUNTERS as u64) as usize;
        // SAFETY: see `table`; `idx < STATE_COUNTERS` by construction.
        unsafe {
            let cell = table().add(idx);
            cell.write(cell.read().saturating_add(1));
        }
    }
}

/// Abstraction function: projects the per-replica state to the canonical set of
/// state tokens that defines its abstract state. Two runs with the same token set
/// are the same abstract state; a run that produces a token not seen before is a
/// new abstract state.
///
/// Payloads are interned to dense class ids by first occurrence in a canonical
/// structural traversal (not by payload value), so agreement and equivocation are
/// captured by `(view, class)` without the random digest bytes preventing
/// saturation.
pub fn alpha(states: &BTreeMap<String, ReporterReplicaStateData>) -> Vec<String> {
    // Assign payload class ids by first occurrence in a canonical structural
    // traversal (replica key order, then view order, notarizations before
    // finalizations). Sorting by payload hex instead would let the random digest
    // bytes pick the labels, so structurally-identical states whose payloads sort
    // differently would get different tokens and fake novelty.
    let mut class: BTreeMap<&str, usize> = BTreeMap::new();
    for replica in states.values() {
        for proposal in replica
            .notarizations
            .values()
            .chain(replica.finalizations.values())
        {
            let next = class.len();
            class.entry(proposal.payload.as_str()).or_insert(next);
        }
    }

    let mut tokens: BTreeSet<String> = BTreeSet::new();

    emit_frontier_spreads(states, &mut tokens);
    emit_certificate_observation_counts(states, &mut tokens);
    emit_vote_counts(states, &mut tokens);

    // Per-replica facts as independent tokens (identity-independent: a fact
    // reached by any replica is the same token). One token per fact, rather than a
    // concatenated per-replica string, keeps the token space a sum of per-fact
    // cardinalities instead of their product.
    for replica in states.values() {
        local_tokens(replica, &class, &mut tokens);
    }

    // Cross-replica certificate facts, keyed by (view, payload-class).
    let mut notarized: BTreeMap<u64, BTreeSet<usize>> = BTreeMap::new();
    let mut finalized: BTreeMap<u64, BTreeSet<usize>> = BTreeMap::new();
    let mut nullified: BTreeSet<u64> = BTreeSet::new();
    for replica in states.values() {
        for (view, proposal) in &replica.notarizations {
            notarized
                .entry(*view)
                .or_default()
                .insert(class[proposal.payload.as_str()]);
        }
        for (view, proposal) in &replica.finalizations {
            finalized
                .entry(*view)
                .or_default()
                .insert(class[proposal.payload.as_str()]);
        }
        nullified.extend(replica.nullifications.iter().copied());
    }
    for (view, classes) in &notarized {
        tokens.insert(format!("global_notarized:{view}:{classes:?}"));
    }
    for (view, classes) in &finalized {
        tokens.insert(format!("global_finalized:{view}:{classes:?}"));
    }
    for view in &nullified {
        tokens.insert(format!("global_nullified:{view}"));
    }
    for view in &nullified {
        if notarized.contains_key(view) {
            tokens.insert(format!("notarized_and_nullified:{view}"));
        }
    }
    let notarize_votes = max_vote_counts(states.values().map(|r| &r.notarize_vote_counts));
    let nullify_votes = max_vote_counts(states.values().map(|r| &r.nullify_vote_counts));
    let finalize_votes = max_vote_counts(states.values().map(|r| &r.finalize_vote_counts));
    let notarized_views = notarized.keys().copied().collect();
    let finalized_views = finalized.keys().copied().collect();
    emit_vote_certificate_relationships(
        &mut tokens,
        &notarized_views,
        &nullified,
        &finalized_views,
        &notarize_votes,
        &nullify_votes,
        &finalize_votes,
    );

    // System-wide frontiers: the max over replicas of each per-replica frontier.
    // These expose "the network has reached view X" as coverage, which the
    // per-replica frontier tokens do not.
    if let Some(view) = states.values().map(|r| r.last_finalized).max() {
        tokens.insert(format!("max_finalized:{view}"));
    }
    if let Some(view) = states.values().map(|r| r.last_notarized).max() {
        tokens.insert(format!("max_notarized:{view}"));
    }
    if let Some(view) = states.values().map(|r| r.last_nullified).max() {
        tokens.insert(format!("max_nullified:{view}"));
    }

    tokens.into_iter().collect()
}

fn warn_event_tokens(events: &[RecordedEvent]) -> Vec<String> {
    let mut tokens = BTreeSet::new();
    let mut counts: BTreeMap<(&'static str, &'static str), u64> = BTreeMap::new();

    for event in events {
        if event.level != Level::WARN {
            continue;
        }
        let Some(actor) = warn_actor(event) else {
            continue;
        };
        let kind = warn_kind(&event.metadata.content);
        tokens.insert(format!("warn_event:{actor}:{kind}"));
        *counts.entry((actor, kind)).or_default() += 1;
        if let Some(view) = event_view(event) {
            tokens.insert(format!(
                "warn_event_view_bucket:{actor}:{kind}:{}",
                span_bucket(view)
            ));
        }
    }

    for ((actor, kind), count) in counts {
        tokens.insert(format!(
            "warn_event_count:{actor}:{kind}:{}",
            span_bucket(count)
        ));
    }

    tokens.into_iter().collect()
}

fn warn_actor(event: &RecordedEvent) -> Option<&'static str> {
    event
        .spans
        .iter()
        .find_map(|span| simplex_span_actor(&span.content))
        .or_else(|| simplex_actor(&event.target))
}

fn simplex_actor(target: &str) -> Option<&'static str> {
    if target.contains("commonware_consensus::simplex::actors::batcher") {
        Some("batcher")
    } else if target.contains("commonware_consensus::simplex::actors::resolver") {
        Some("resolver")
    } else if target.contains("commonware_consensus::simplex::actors::voter") {
        Some("voter")
    } else {
        None
    }
}

fn simplex_span_actor(name: &str) -> Option<&'static str> {
    if name.contains("simplex.batcher") {
        Some("batcher")
    } else if name.contains("simplex.resolver") {
        Some("resolver")
    } else if name.contains("simplex.voter") {
        Some("voter")
    } else {
        None
    }
}

fn warn_kind(message: &str) -> &'static str {
    match message {
        "broadcasting nullification floor" => "broadcasting_nullification_floor",
        "dropped our proposal" => "dropped_our_proposal",
        "proposal failed verification" => "proposal_failed_verification",
        "proposal failed certification" => "proposal_failed_certification",
        "entry certificate not found" => "entry_certificate_not_found",
        "ignoring verified proposal because slot already populated" => {
            "ignoring_verified_proposal_slot_populated"
        }
        "blocking equivocator" => "blocking_equivocator",
        "unknown participant" => "unknown_participant",
        "notarize signer mismatch" => "notarize_signer_mismatch",
        "conflicting notarize" => "conflicting_notarize",
        "invalid signature" => "invalid_signature",
        "nullify signer mismatch" => "nullify_signer_mismatch",
        "nullify after finalize" => "nullify_after_finalize",
        "conflicting nullify" => "conflicting_nullify",
        "finalize signer mismatch" => "finalize_signer_mismatch",
        "finalize after nullify" => "finalize_after_nullify",
        "conflicting finalize" => "conflicting_finalize",
        "decoding error" => "decoding_error",
        "epoch mismatch" => "epoch_mismatch",
        "invalid notarization" => "invalid_notarization",
        "invalid nullification" => "invalid_nullification",
        "invalid finalization" => "invalid_finalization",
        _ => "other",
    }
}

fn event_view(event: &RecordedEvent) -> Option<u64> {
    event_fields(event)
        .find_map(|(name, value)| match name.as_str() {
            "view" | "updated_view" => parse_u64(value),
            "round" => parse_view(value),
            _ => None,
        })
        .or_else(|| {
            event
                .spans
                .iter()
                .flat_map(|span| span.fields.iter())
                .find_map(|(name, value)| (name == "view").then(|| parse_u64(value)).flatten())
        })
}

fn event_fields(event: &RecordedEvent) -> impl Iterator<Item = &(String, String)> {
    event.metadata.fields.iter()
}

fn parse_u64(value: &str) -> Option<u64> {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .parse()
        .ok()
}

fn parse_view(value: &str) -> Option<u64> {
    parse_u64(value).or_else(|| parse_after(value, "View("))
}

fn parse_after(value: &str, marker: &str) -> Option<u64> {
    let start = value.find(marker)? + marker.len();
    let digits: String = value[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// Emits a replica's local state as independent, bounded tokens (one per fact),
/// identity-independent so a fact reached by any replica is the same token.
fn local_tokens(
    replica: &ReporterReplicaStateData,
    class: &BTreeMap<&str, usize>,
    tokens: &mut BTreeSet<String>,
) {
    tokens.insert(format!(
        "replica_frontier:{}:{}:{}",
        replica.last_finalized, replica.last_notarized, replica.last_nullified,
    ));
    for (view, proposal) in &replica.notarizations {
        tokens.insert(format!(
            "replica_notarized:{view}:{}:p{}:{:?}",
            class[proposal.payload.as_str()],
            proposal.parent,
            replica
                .notarization_signature_counts
                .get(view)
                .copied()
                .flatten(),
        ));
        emit_parent_tokens(*view, proposal.parent, tokens);
    }
    for (view, proposal) in &replica.finalizations {
        tokens.insert(format!(
            "replica_finalized:{view}:{}:p{}:{:?}",
            class[proposal.payload.as_str()],
            proposal.parent,
            replica
                .finalization_signature_counts
                .get(view)
                .copied()
                .flatten(),
        ));
        emit_parent_tokens(*view, proposal.parent, tokens);
    }
    for view in &replica.nullifications {
        tokens.insert(format!(
            "replica_nullification:{view}:{:?}",
            replica
                .nullification_signature_counts
                .get(view)
                .copied()
                .flatten(),
        ));
    }
    for view in &replica.leader_nullify_views {
        tokens.insert(format!("leader_nullify:{view}"));
    }
}

fn span_bucket(span: u64) -> u8 {
    match span {
        0 => 0,
        1 => 1,
        2 => 2,
        3..=4 => 3,
        5..=8 => 4,
        _ => 5,
    }
}

fn emit_spread(tokens: &mut BTreeSet<String>, name: &str, values: impl Iterator<Item = u64>) {
    let mut min = u64::MAX;
    let mut max = 0;
    let mut any = false;
    for value in values {
        any = true;
        min = min.min(value);
        max = max.max(value);
    }
    if any {
        tokens.insert(format!("{name}:{}", span_bucket(max - min)));
    }
}

fn emit_frontier_spreads(
    states: &BTreeMap<String, ReporterReplicaStateData>,
    tokens: &mut BTreeSet<String>,
) {
    emit_spread(
        tokens,
        "finalized_spread",
        states.values().map(|r| r.last_finalized),
    );
    emit_spread(
        tokens,
        "notarized_spread",
        states.values().map(|r| r.last_notarized),
    );
    emit_spread(
        tokens,
        "nullified_spread",
        states.values().map(|r| r.last_nullified),
    );
}

fn emit_count_tokens(tokens: &mut BTreeSet<String>, name: &str, counts: &BTreeMap<u64, usize>) {
    for (view, count) in counts {
        tokens.insert(format!("{name}:{view}:{count}"));
    }
}

fn emit_certificate_observation_counts(
    states: &BTreeMap<String, ReporterReplicaStateData>,
    tokens: &mut BTreeSet<String>,
) {
    let mut notarized = BTreeMap::new();
    let mut nullified = BTreeMap::new();
    let mut finalized = BTreeMap::new();
    for replica in states.values() {
        for view in replica.notarizations.keys() {
            *notarized.entry(*view).or_insert(0) += 1;
        }
        for view in &replica.nullifications {
            *nullified.entry(*view).or_insert(0) += 1;
        }
        for view in replica.finalizations.keys() {
            *finalized.entry(*view).or_insert(0) += 1;
        }
    }
    emit_count_tokens(tokens, "notarization_seen", &notarized);
    emit_count_tokens(tokens, "nullification_seen", &nullified);
    emit_count_tokens(tokens, "finalization_seen", &finalized);
}

fn emit_vote_counts(
    states: &BTreeMap<String, ReporterReplicaStateData>,
    tokens: &mut BTreeSet<String>,
) {
    for replica in states.values() {
        emit_count_tokens(tokens, "notarize_votes", &replica.notarize_vote_counts);
        emit_count_tokens(tokens, "nullify_votes", &replica.nullify_vote_counts);
        emit_count_tokens(tokens, "finalize_votes", &replica.finalize_vote_counts);
    }
}

fn max_vote_counts<'a>(
    counts: impl Iterator<Item = &'a BTreeMap<u64, usize>>,
) -> BTreeMap<u64, usize> {
    let mut max_counts = BTreeMap::new();
    for counts in counts {
        for (view, count) in counts {
            let entry = max_counts.entry(*view).or_insert(0);
            *entry = (*entry).max(*count);
        }
    }
    max_counts
}

fn emit_vote_certificate_relationships(
    tokens: &mut BTreeSet<String>,
    notarized: &BTreeSet<u64>,
    nullified: &BTreeSet<u64>,
    finalized: &BTreeSet<u64>,
    notarize_votes: &BTreeMap<u64, usize>,
    nullify_votes: &BTreeMap<u64, usize>,
    finalize_votes: &BTreeMap<u64, usize>,
) {
    emit_vote_certificate_gap(tokens, "notarize", notarize_votes, notarized);
    emit_vote_certificate_gap(tokens, "nullify", nullify_votes, nullified);
    emit_vote_certificate_gap(tokens, "finalize", finalize_votes, finalized);

    for (view, nullify_count) in nullify_votes {
        let Some(finalize_count) = finalize_votes.get(view) else {
            continue;
        };
        let both = (*nullify_count).min(*finalize_count);
        if both > 0 {
            tokens.insert(format!(
                "nullify_and_finalize_votes:{view}:{}",
                span_bucket(both as u64)
            ));
        }
    }
}

fn emit_vote_certificate_gap(
    tokens: &mut BTreeSet<String>,
    kind: &str,
    votes: &BTreeMap<u64, usize>,
    certificates: &BTreeSet<u64>,
) {
    for (view, count) in votes {
        if *count > 0 && !certificates.contains(view) {
            tokens.insert(format!(
                "vote_without_certificate:{kind}:{view}:{}",
                span_bucket(*count as u64)
            ));
        }
    }
    for view in certificates {
        if !votes.contains_key(view) {
            tokens.insert(format!("certificate_without_votes:{kind}:{view}"));
        }
    }
}

fn timeout_tokens(metrics: &str) -> Vec<String> {
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    for line in metrics.lines() {
        if line.starts_with('#') || !line.contains("_timeouts") {
            continue;
        }
        let Some(reason) = timeout_reason(line) else {
            continue;
        };
        let Some(value) = metric_value(line) else {
            continue;
        };
        if value > 0 {
            *counts.entry(reason).or_default() += value;
        }
    }

    let mut tokens = BTreeSet::new();
    for (reason, count) in counts {
        tokens.insert(format!("timeout_reason:{reason}"));
        tokens.insert(format!(
            "timeout_reason_count:{reason}:{}",
            span_bucket(count)
        ));
    }
    tokens.into_iter().collect()
}

fn timeout_reason(line: &str) -> Option<&'static str> {
    let start = line.find("reason=\"")? + "reason=\"".len();
    let reason = &line[start..];
    let end = reason.find('"')?;
    match &reason[..end] {
        "Inactivity" => Some("Inactivity"),
        "LeaderNullify" => Some("LeaderNullify"),
        "LeaderTimeout" => Some("LeaderTimeout"),
        "CertificationTimeout" => Some("CertificationTimeout"),
        "MissingProposal" => Some("MissingProposal"),
        "IgnoredProposal" => Some("IgnoredProposal"),
        "InvalidProposal" => Some("InvalidProposal"),
        "FailedCertification" => Some("FailedCertification"),
        _ => None,
    }
}

fn metric_value(line: &str) -> Option<u64> {
    // prometheus-client currently emits `name labels value` without timestamps,
    // so the last whitespace-delimited field is the sample value.
    let value = line.split_whitespace().last()?;
    if let Ok(value) = value.parse::<u64>() {
        return Some(value);
    }
    let value = value.parse::<f64>().ok()?;
    if value.is_finite() && value > 0.0 {
        Some(value.ceil() as u64)
    } else {
        Some(0)
    }
}

fn emit_parent_tokens(view: u64, parent: u64, tokens: &mut BTreeSet<String>) {
    let gap = view.saturating_sub(parent);
    tokens.insert(format!("parent_gap:{view}:{}", span_bucket(gap)));
    if parent.checked_add(1) == Some(view) {
        tokens.insert(format!("parent_eq_prev:{view}"));
    } else if parent.checked_add(1).is_some_and(|next| next < view) {
        tokens.insert(format!("parent_skips:{view}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replica(
        notarized: &[(u64, &str)],
        finalized: &[(u64, &str)],
        nullified: &[u64],
        last_finalized: u64,
    ) -> ReporterReplicaStateData {
        let mut data = ReporterReplicaStateData {
            last_finalized,
            nullifications: nullified.iter().copied().collect(),
            ..Default::default()
        };
        for &(view, payload) in notarized {
            data.notarizations.insert(
                view,
                ProposalData {
                    parent: 0,
                    payload: payload.to_string(),
                },
            );
        }
        for &(view, payload) in finalized {
            data.finalizations.insert(
                view,
                ProposalData {
                    parent: 0,
                    payload: payload.to_string(),
                },
            );
        }
        data
    }

    #[test]
    fn alpha_is_deterministic() {
        let mut states = BTreeMap::new();
        states.insert(
            "0".into(),
            replica(&[(1, "aa"), (2, "bb")], &[(1, "aa")], &[3], 1),
        );
        assert_eq!(alpha(&states), alpha(&states));
    }

    #[test]
    fn alpha_golden_single_replica() {
        let mut states = BTreeMap::new();
        states.insert("0".into(), replica(&[(1, "aa")], &[(1, "aa")], &[], 1));
        let tokens = alpha(&states);
        // One payload class ("aa" -> 0), parent 0, no signature counts.
        assert!(tokens.contains(&"global_notarized:1:{0}".to_string()));
        assert!(tokens.contains(&"global_finalized:1:{0}".to_string()));
        assert!(tokens.contains(&"replica_frontier:1:0:0".to_string()));
        assert!(tokens.contains(&"replica_notarized:1:0:p0:None".to_string()));
        assert!(tokens.contains(&"replica_finalized:1:0:p0:None".to_string()));
        assert!(tokens.contains(&"max_finalized:1".to_string()));
    }

    #[test]
    fn global_frontiers_are_part_of_state() {
        let mut states = BTreeMap::new();
        states.insert(
            "0".into(),
            ReporterReplicaStateData {
                last_finalized: 5,
                last_notarized: 7,
                last_nullified: 3,
                ..Default::default()
            },
        );
        states.insert(
            "1".into(),
            ReporterReplicaStateData {
                last_finalized: 4,
                last_notarized: 9,
                last_nullified: 6,
                ..Default::default()
            },
        );
        let tokens = alpha(&states);
        // Global frontiers are the max over replicas of each per-replica frontier.
        assert!(tokens.contains(&"max_finalized:5".to_string()));
        assert!(tokens.contains(&"max_notarized:9".to_string()));
        assert!(tokens.contains(&"max_nullified:6".to_string()));
    }

    #[test]
    fn frontier_spread_is_bucketed() {
        let states = BTreeMap::from([
            (
                "0".to_string(),
                ReporterReplicaStateData {
                    last_finalized: 1,
                    last_notarized: 2,
                    last_nullified: 3,
                    ..Default::default()
                },
            ),
            (
                "1".to_string(),
                ReporterReplicaStateData {
                    last_finalized: 5,
                    last_notarized: 10,
                    last_nullified: 4,
                    ..Default::default()
                },
            ),
        ]);
        let tokens = alpha(&states);
        assert!(tokens.contains(&"finalized_spread:3".to_string())); // span 4
        assert!(tokens.contains(&"notarized_spread:4".to_string())); // span 8
        assert!(tokens.contains(&"nullified_spread:1".to_string())); // span 1
    }

    #[test]
    fn certificate_observation_counts_are_tokenized() {
        let mut states = BTreeMap::new();
        states.insert("0".into(), replica(&[(1, "aa")], &[(2, "bb")], &[1], 0));
        states.insert("1".into(), replica(&[(1, "aa")], &[], &[], 0));
        let tokens = alpha(&states);
        assert!(tokens.contains(&"notarization_seen:1:2".to_string()));
        assert!(tokens.contains(&"nullification_seen:1:1".to_string()));
        assert!(tokens.contains(&"finalization_seen:2:1".to_string()));
    }

    #[test]
    fn vote_counts_are_tokenized() {
        let mut data = ReporterReplicaStateData::default();
        data.notarize_vote_counts.insert(1, 2);
        data.nullify_vote_counts.insert(2, 3);
        data.finalize_vote_counts.insert(3, 4);
        let tokens = alpha(&BTreeMap::from([("0".to_string(), data)]));
        assert!(tokens.contains(&"notarize_votes:1:2".to_string()));
        assert!(tokens.contains(&"nullify_votes:2:3".to_string()));
        assert!(tokens.contains(&"finalize_votes:3:4".to_string()));
    }

    #[test]
    fn vote_certificate_relationships_are_tokenized() {
        let mut data = ReporterReplicaStateData::default();
        data.notarize_vote_counts.insert(1, 2);
        data.nullify_vote_counts.insert(2, 3);
        data.finalize_vote_counts.insert(2, 4);
        data.notarizations.insert(
            5,
            ProposalData {
                parent: 4,
                payload: "aa".into(),
            },
        );
        data.nullifications.insert(6);
        data.finalizations.insert(
            7,
            ProposalData {
                parent: 6,
                payload: "bb".into(),
            },
        );

        let tokens = alpha(&BTreeMap::from([("0".to_string(), data)]));
        assert!(tokens.contains(&"vote_without_certificate:notarize:1:2".to_string()));
        assert!(tokens.contains(&"vote_without_certificate:nullify:2:3".to_string()));
        assert!(tokens.contains(&"vote_without_certificate:finalize:2:3".to_string()));
        assert!(tokens.contains(&"certificate_without_votes:notarize:5".to_string()));
        assert!(tokens.contains(&"certificate_without_votes:nullify:6".to_string()));
        assert!(tokens.contains(&"certificate_without_votes:finalize:7".to_string()));
        assert!(tokens.contains(&"nullify_and_finalize_votes:2:3".to_string()));
    }

    #[test]
    fn timeout_metrics_are_tokenized() {
        let metrics = r#"
# HELP simplex_voter_timeouts timed out views
# TYPE simplex_voter_timeouts counter
simplex_voter_timeouts{leader="a",reason="LeaderTimeout"} 2
simplex_voter_timeouts{leader="b",reason="LeaderTimeout"} 3
simplex_voter_timeouts{leader="c",reason="CertificationTimeout"} 0
simplex_voter_timeouts{leader="d",reason="IgnoredProposal"} 1
"#;
        let tokens = timeout_tokens(metrics);
        assert!(tokens.contains(&"timeout_reason:LeaderTimeout".to_string()));
        assert!(tokens.contains(&"timeout_reason_count:LeaderTimeout:4".to_string()));
        assert!(tokens.contains(&"timeout_reason:IgnoredProposal".to_string()));
        assert!(tokens.contains(&"timeout_reason_count:IgnoredProposal:1".to_string()));
        assert!(!tokens.contains(&"timeout_reason:CertificationTimeout".to_string()));
    }

    #[test]
    fn warn_events_are_tokenized() {
        use commonware_runtime::telemetry::traces::collector::EventMetadata;

        let events = vec![
            RecordedEvent {
                level: Level::WARN,
                target: "commonware_consensus::simplex::actors::voter::actor".into(),
                spans: Vec::new(),
                metadata: EventMetadata {
                    content: "proposal failed certification".into(),
                    fields: vec![(
                        "round".into(),
                        "Rnd { epoch: Epoch(333), view: View(5) }".into(),
                    )],
                },
            },
            RecordedEvent {
                level: Level::WARN,
                target: "commonware_p2p".into(),
                spans: vec![EventMetadata {
                    content: "simplex.resolver.fetch".into(),
                    fields: vec![("view".into(), "7".into())],
                }],
                metadata: EventMetadata {
                    content: "invalid signature".into(),
                    fields: Vec::new(),
                },
            },
            RecordedEvent {
                level: Level::WARN,
                target: "commonware_p2p".into(),
                spans: vec![EventMetadata {
                    content: "simplex.batcher.verify_notarizes".into(),
                    fields: vec![("view".into(), "9".into())],
                }],
                metadata: EventMetadata {
                    content: "new warning from block macro".into(),
                    fields: Vec::new(),
                },
            },
            RecordedEvent {
                level: Level::INFO,
                target: "commonware_consensus::simplex::actors::voter::actor".into(),
                spans: Vec::new(),
                metadata: EventMetadata {
                    content: "consensus initialized".into(),
                    fields: Vec::new(),
                },
            },
        ];

        let tokens = warn_event_tokens(&events);
        assert!(tokens.contains(&"warn_event:voter:proposal_failed_certification".to_string()));
        assert!(
            tokens.contains(&"warn_event_count:voter:proposal_failed_certification:1".to_string())
        );
        assert!(tokens
            .contains(&"warn_event_view_bucket:voter:proposal_failed_certification:4".to_string()));
        assert!(tokens.contains(&"warn_event:resolver:invalid_signature".to_string()));
        assert!(tokens.contains(&"warn_event_view_bucket:resolver:invalid_signature:4".to_string()));
        assert!(tokens.contains(&"warn_event:batcher:other".to_string()));
        assert!(tokens.contains(&"warn_event_view_bucket:batcher:other:5".to_string()));
        assert!(!tokens.contains(&"warn_event:voter:consensus_initialized".to_string()));
    }

    #[test]
    fn parent_is_part_of_state() {
        // Same view and payload class, different parent: distinct ancestry must
        // not collapse to the same abstract state.
        let with_parent = |parent| {
            let mut data = ReporterReplicaStateData::default();
            data.notarizations.insert(
                1,
                ProposalData {
                    parent,
                    payload: "aa".into(),
                },
            );
            BTreeMap::from([("0".to_string(), data)])
        };
        assert_ne!(alpha(&with_parent(0)), alpha(&with_parent(9)));
    }

    #[test]
    fn parent_relationships_are_tokenized() {
        let mut data = ReporterReplicaStateData::default();
        data.notarizations.insert(
            3,
            ProposalData {
                parent: 2,
                payload: "aa".into(),
            },
        );
        data.finalizations.insert(
            6,
            ProposalData {
                parent: 2,
                payload: "bb".into(),
            },
        );
        let tokens = alpha(&BTreeMap::from([("0".to_string(), data)]));
        assert!(tokens.contains(&"parent_gap:3:1".to_string()));
        assert!(tokens.contains(&"parent_eq_prev:3".to_string()));
        assert!(tokens.contains(&"parent_gap:6:3".to_string()));
        assert!(tokens.contains(&"parent_skips:6".to_string()));
    }

    #[test]
    fn class_ids_are_structural_not_payload_value() {
        // Same structure (one replica, two views, two distinct payloads, no
        // agreement), only the payload bytes are swapped between views. Class
        // labels must follow the traversal (view 1 -> 0, view 2 -> 1) in both,
        // so the abstract state is identical.
        let mut a = BTreeMap::new();
        a.insert("0".into(), replica(&[(1, "zz"), (2, "aa")], &[], &[], 0));
        let mut b = BTreeMap::new();
        b.insert("0".into(), replica(&[(1, "aa"), (2, "zz")], &[], &[], 0));
        assert_eq!(alpha(&a), alpha(&b));
    }

    #[test]
    fn alpha_emits_cross_replica_facts() {
        let mut states = BTreeMap::new();
        states.insert("0".into(), replica(&[(1, "aa")], &[(1, "aa")], &[2], 1));
        states.insert("1".into(), replica(&[(1, "aa")], &[(1, "aa")], &[2, 3], 1));
        let tokens = alpha(&states);
        assert!(tokens.contains(&"global_notarized:1:{0}".to_string()));
        assert!(tokens.contains(&"global_finalized:1:{0}".to_string()));
        assert!(tokens.contains(&"global_nullified:2".to_string()));
        assert!(tokens.contains(&"global_nullified:3".to_string()));
    }

    #[test]
    fn notarized_and_nullified_view_is_tokenized() {
        let mut states = BTreeMap::new();
        states.insert("0".into(), replica(&[(1, "aa")], &[], &[1], 0));
        let tokens = alpha(&states);
        assert!(tokens.contains(&"notarized_and_nullified:1".to_string()));
    }

    #[test]
    fn leader_nullify_is_tokenized() {
        let mut data = ReporterReplicaStateData::default();
        data.leader_nullify_views.insert(2);
        let states = BTreeMap::from([("0".to_string(), data)]);
        let tokens = alpha(&states);
        assert!(tokens.contains(&"leader_nullify:2".to_string()));
    }

    #[test]
    fn alpha_empty_has_no_tokens() {
        let states = BTreeMap::new();
        assert!(alpha(&states).is_empty());
    }
}
