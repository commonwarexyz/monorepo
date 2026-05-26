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
//!   checks marshal liveness (every honest node delivers `required_containers`
//!   ordered finalized blocks) plus cross-node agreement.

pub mod multi_node;
pub mod single_node;

pub use multi_node::fuzz_marshal_liveness;
pub use single_node::{fuzz_marshal, MarshalEvent, MarshalFuzzInput, VariantPublish};
