//! Mallory: the backend-agnostic adaptive-adversary core for the Simplex fuzz
//! harness.
//!
//! This module owns the backend-agnostic Q-learning core (Mallory-style,
//! arXiv:2305.02601): a bounded tabular Q-policy over a numeric
//! [`ActionId`](policy::ActionId) boundary ([`policy`]) plus the protocol-state
//! observation it rewards ([`state`]). The core sees only numeric action ids, so
//! any fixed, ordered action catalog with an exact state / happens-before
//! fingerprint can drive it; the Mallory runner ([`runner`]) is its sole driver.
//!
//! The Mallory runner ([`runner`]) drives the episode loop over a stable
//! action catalog ([`action`]) under the backend-agnostic Q-core. The catalog
//! covers the NoFault, network-topology (isolate / partition), packet (delay /
//! loss / corrupt / duplicate / reorder), and managed-validator lifecycle
//! (crash-stop / durable restart, see [`lifecycle`]) faults. Byzantine adversary
//! profiles ([`adversary`]) are episode-level ENVIRONMENTS sampled once at setup,
//! not catalog actions -- they replace node 0 with a Byzantine actor for the whole
//! episode and add no catalog id. This module fixes the v1 contract every backend
//! and PR must uphold; the invariants below are documented here as a freeze.
//!
//! # v1 Mallory contract
//!
//! - **One faultable identity.** `n = 4` with exactly one process/lifecycle-
//!   faultable identity, `crate::BYZANTINE_IDX`. No lifecycle or Byzantine
//!   action may target a second node: a second faulty identity in `n = 4,
//!   f = 1` exceeds the tolerated fault bound and would turn a liveness panic
//!   into a harness artifact rather than a finding.
//! - **At most one transient network/packet fault at a time.** Every transient
//!   fault is healed before the next decision, so the step reward is
//!   attributable to a single perturbation.
//! - **Crash-stop is terminal.** A crash-stop action ends the episode; the
//!   crashed engine is not resurrected within that episode.
//! - **Deterministic durations.** All fault durations use deterministic time,
//!   never the failed node's own view (which the fault itself stalls), and all
//!   randomness is drawn from the runtime `commonware_utils::FuzzRng`. A
//!   replayed input reproduces its schedule modulo the campaign-persistent
//!   Q-table.
//! - **Explicit actors only.** No open-ended "other Byzantine actor": every
//!   modeled actor has explicit semantics and explicit oracle treatment (safety
//!   and liveness), so every panic is attributable.
//! - **Bounded, exact fingerprints (accepted).** The Q-table and novelty
//!   registries are fixed-size with exact fingerprint keys; colliding
//!   fingerprints share a row / slot. This bounded-memory, exact-key tradeoff
//!   is deliberate: there is no approximate nearest-neighbour state matching
//!   (documented in [`state`]).

pub(crate) mod action;
pub(crate) mod adversary;
pub(crate) mod lifecycle;
pub(crate) mod log;
pub(crate) mod multiplexer;
pub(crate) mod network;
pub(crate) mod policy;
pub(crate) mod runner;
pub(crate) mod state;
