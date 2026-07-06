//! Fuzz harnesses for the marshal mechanism.
//!
//! Each driver is its own libFuzzer target so a single mode's input format
//! owns its whole byte tape and its own corpus (no top-level enum splitting
//! bytes across modes). The drivers:
//!
//! - [`single_node`]: drives one marshal actor in isolation by synthesizing
//!   every input it would receive (blocks, notarizations, finalizations,
//!   restarts) and asserting per-actor delivery invariants. Generic over the
//!   marshal variant (`StandardHarness` / `CodingHarness`), mirroring how
//!   marshal itself splits into `standard` and `coding`. Targets:
//!   `marshal_standard`, `marshal_coding`.
//! - [`multi_node`]: runs a live `N4F1C3` cluster (three honest nodes
//!   plus one byzantine `Disrupter`) wired to real simplex consensus, and
//!   checks marshal liveness (every honest node delivers a target number of
//!   ordered finalized blocks sampled within a single-epoch bound) plus
//!   cross-node agreement. Also per-variant. Targets:
//!   `marshal_liveness_standard`, `marshal_liveness_coding`.
//! - [`inline`]: drives the standard inline block path. Target: `marshal_inline`.
//! - [`store`]: drives the marshal block/certificate store directly. Target:
//!   `marshal_store`.
//!
//! # Goals, pros, and cons
//!
//! - [`single_node`] -- fuzz the core actor's state machine.
//!   - Pro: adversarial/out-of-order inputs, crash-restart recovery,
//!     durability-ack contracts, precise gap-repair; cheap and fast.
//!   - Con: single validator, so coding's peer-shard dissemination,
//!     reconstruction, and validation are unreachable.
//! - [`multi_node`] -- fuzz the live integration with one byzantine node.
//!   - Pro: real consensus plus shard dissemination/reconstruction/validation,
//!     cross-node agreement, and liveness check.
//!   - Con: heavier (fewer iterations) and only valid
//!     consensus orderings.

pub mod inline;
pub mod multi_node;
pub mod single_node;
pub mod store;

pub use inline::{fuzz_marshal_inline, MarshalInlineInput};
pub use multi_node::{fuzz_marshal_liveness, MarshalLivenessInput};
pub use single_node::{fuzz_marshal, MarshalEvent, MarshalFuzzInput, VariantPublish};
pub use store::{fuzz_marshal_store, MarshalStoreInput};
