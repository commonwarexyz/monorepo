//! Backend-agnostic protocol-state observation for the Mallory Q-core.
//!
//! [`state_descriptor`] reduces the honest reporters' agreement state to one
//! `u64` fingerprint. It reads only the shared mock [`Reporter`] and
//! [`crate::state_cov`] projection, so it is independent of any particular
//! adversary backend.
//!
//! # Bounded, exact fingerprints (accepted)
//!
//! This descriptor is an *exact* key: the policy's fixed-size Q-table hashes it
//! into a row, and colliding fingerprints share that row. There is no similarity
//! metric and no approximate nearest-neighbour matching, two states are either
//! the same key or unrelated. That bounded-memory / exact-key tradeoff is
//! deliberate and matches the novelty registries in [`crate::mallory::policy`].
//! The features below are therefore chosen to be *view-relative* (offsets,
//! spreads, and counts against the finalization frontier, never absolute view
//! numbers) so that the same protocol situation at different absolute views maps
//! to the same key and its novelty is a genuine, recurring reward signal,
//! unlike [`crate::state_cov::alpha`], whose tokens embed absolute views and so
//! almost never recur across runs.

use crate::{simplex::Simplex, state_cov};
use commonware_consensus::simplex::mocks::reporter::Reporter;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_runtime::deterministic;
use std::collections::BTreeSet;

/// The honest-reporter type the descriptor reads: the shared mock reporter over
/// the deterministic runtime, a backend's scheme, and its elector.
type HonestReporter<P> =
    Reporter<deterministic::Context, <P as Simplex>::Scheme, <P as Simplex>::Elector, Sha256Digest>;

/// View-relative protocol-state descriptor of the honest reporters: a compact
/// fingerprint of their agreement state as offsets, spreads, and counts relative
/// to the finalization frontier, never absolute view numbers.
pub(crate) fn state_descriptor<P: Simplex>(
    honest: &[HonestReporter<P>],
    max_participants: usize,
) -> u64 {
    let states = state_cov::encode_reporter_states(honest, max_participants);
    if states.is_empty() {
        return 0;
    }
    let max_fin = states.values().map(|r| r.last_finalized).max().unwrap_or(0);
    let min_fin = states.values().map(|r| r.last_finalized).min().unwrap_or(0);
    let max_notar = states.values().map(|r| r.last_notarized).max().unwrap_or(0);
    let max_null = states.values().map(|r| r.last_nullified).max().unwrap_or(0);

    let mut notarized = BTreeSet::new();
    let mut finalized = BTreeSet::new();
    let mut nullified = BTreeSet::new();
    let mut faulty = false;
    for r in states.values() {
        notarized.extend(r.notarizations.keys().copied());
        finalized.extend(r.finalizations.keys().copied());
        nullified.extend(r.nullifications.iter().copied());
        faulty |= !r.faults.is_empty();
    }
    let notar_unfinalized = notarized
        .iter()
        .filter(|v| !finalized.contains(v) && !nullified.contains(v))
        .count();
    let notar_and_nullified = notarized.intersection(&nullified).count();

    // Bucketed, view-relative features packed into one descriptor: notarization
    // depth over the finalized frontier, nullification depth over it, inter-
    // replica finalization spread, count of notarized-but-undecided views, count
    // of notarized-and-nullified (conflict) views, and any recorded equivocation.
    let fin_gap = max_notar.saturating_sub(max_fin).min(3);
    let null_gap = max_null.saturating_sub(max_fin).min(3);
    let fin_spread = max_fin.saturating_sub(min_fin).min(3);
    let unfinalized = (notar_unfinalized as u64).min(3);
    let conflicted = (notar_and_nullified as u64).min(2);

    let mut d = 0u64;
    d = (d << 2) | fin_gap;
    d = (d << 2) | null_gap;
    d = (d << 2) | fin_spread;
    d = (d << 2) | unfinalized;
    d = (d << 2) | conflicted;
    (d << 1) | u64::from(faulty)
}
