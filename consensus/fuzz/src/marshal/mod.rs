//! Fuzz harnesses for the marshal mechanism.
//!
//! Each protocol driver is its own libFuzzer target. The general Twins driver
//! shares one corpus across its application and wrapper variants by reserving
//! the final byte of its raw entropy tape as a selector. The drivers:
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
//!   Targets: `marshal_multi_node_liveness_deferred`,
//!   `marshal_multi_node_liveness_coding`, `marshal_multi_node_twins`,
//!   `marshal_multi_node_twins_id_split_header_deferred`,
//!   `marshal_multi_node_twins_id_split_header_inline`.
//! - [`inline`]: drives the standard inline and deferred block paths, including
//!   split-header equivocation. Targets: `marshal_standard_inline`,
//!   `marshal_standard_deferred`.
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
    fuzz_marshal_twins_id_split_header, fuzz_marshal_twins_id_split_header_inline,
};
pub use single_node::{MarshalEvent, MarshalFuzzInput, VariantPublish, fuzz_marshal_single_node};
pub use store::{MarshalStoreInput, fuzz_marshal_store};
