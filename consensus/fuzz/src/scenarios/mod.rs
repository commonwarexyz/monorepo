//! Scenario-based marshal fuzzing.
//!
//! A run has three phases. Setup builds four validators on the deterministic
//! runtime with the mock certificate scheme and a marshal stack whose wrapper
//! and application come from the chosen scenario. The prefix replays a
//! deterministic program extracted from a standard-marshal test, driving the
//! honest core to an interesting semantic state (missing candidate, pending
//! backfill, divergent same-height certificates, or a pending floor anchor) and
//! returning a certified floor. The fuzzing phase starts the
//! engines from that floor, either honestly (`N4F0C4`) or with node 0 replaced
//! by a full-channel adversary (`N4F1C3`), heals the network at a GST boundary,
//! and checks recovery liveness, block safety, and the scenario's expectations.

mod adversary;
mod elector;
pub(crate) mod environment;
pub(crate) mod input;
pub(crate) mod runner;
#[allow(clippy::module_inception)]
// the concrete scenarios live in scenarios/scenarios.rs by design.
pub(crate) mod scenarios;
mod strategy;

pub use input::{MarshalScenarioPrefixInput, Mode, ScenarioKind};
pub use runner::{fuzz_marshal_scenario_prefix_deferred, fuzz_marshal_scenario_prefix_inline};
