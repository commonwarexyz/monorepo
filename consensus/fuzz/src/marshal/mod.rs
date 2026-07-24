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
//!   `marshal_single_node_standard`, `marshal_single_node_coding`.
//! - [`multi_node`]: runs live `N4F1C3` clusters wired to real Simplex
//!   consensus. The liveness targets use a Byzantine `Disrupter`; the standard
//!   Twins mutator splits one compromised identity between a full engine and a
//!   `Disrupter`.
//!   Targets: `marshal_multi_node_liveness_standard`,
//!   `marshal_multi_node_liveness_coding`, `marshal_multi_node_twins_standard`,
//!   `marshal_multi_node_twins_randomized_app`.
//! - [`inline`]: drives the standard inline and deferred block paths, including
//!   split-header equivocation. Targets: `marshal_inline_standard`,
//!   `marshal_deferred_standard`.
//! - [`store`]: drives the marshal block/certificate store directly. Target:
//!   `marshal_store_standard`.
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

pub use inline::{MarshalInlineInput, fuzz_marshal_deferred, fuzz_marshal_inline};
pub use multi_node::{
    MarshalLivenessInput, MarshalTwinsInput, fuzz_marshal_liveness, fuzz_marshal_twins,
    fuzz_marshal_twins_id_split_header, fuzz_marshal_twins_randomized_app,
};
pub use single_node::{MarshalEvent, MarshalFuzzInput, VariantPublish, fuzz_marshal_single_node};
pub use store::{MarshalStoreInput, fuzz_marshal_store};
