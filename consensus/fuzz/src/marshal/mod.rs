//! Fuzz models for the marshal mechanism.
//!
//! Two complementary models, each generic over the marshal variant
//! (`StandardHarness` / `CodingHarness`), mirroring how marshal itself splits
//! into `standard` and `coding`:
//!
//! - [`single_node`]: drives one marshal actor in isolation by synthesizing
//!   every input it would receive (blocks, notarizations, finalizations,
//!   restarts) and asserting per-actor delivery invariants.
//! - [`multi_node`]: runs a live `N4F1C3` cluster (three honest validators
//!   plus one byzantine `Disrupter`) wired to real simplex consensus, and
//!   checks marshal liveness (every honest node delivers a target number of
//!   ordered finalized blocks, derived from `required_containers` clamped to a
//!   single-epoch bound) plus cross-node agreement.
//!
//! # Goals, pros, and cons
//!
//! - [`single_node`] -- fuzz the core actor's state machine.
//!   - Pro: adversarial/out-of-order inputs, crash-restart recovery,
//!     durability-ack contracts, precise gap-repair; cheap and deterministic.
//!   - Con: single validator, so coding's peer-shard dissemination,
//!     reconstruction, and validation are unreachable.
//! - [`multi_node`] -- fuzz the live integration with one byzantine node.
//!   - Pro: real consensus plus shard dissemination/reconstruction/validation,
//!     cross-node agreement, and liveness (covers coding's multi-validator paths).
//!   - Con: no node restarts; heavier (fewer iterations) and only valid
//!     consensus orderings.

pub mod multi_node;
pub mod single_node;

pub use multi_node::fuzz_marshal_liveness;
pub use single_node::{fuzz_marshal, MarshalEvent, MarshalFuzzInput, VariantPublish};
