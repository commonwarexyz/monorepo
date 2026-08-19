//! Scenario-based marshal fuzzing.
//!
//! A run has three phases. Setup builds four validators on the deterministic
//! runtime with the mock certificate scheme and a marshal stack; the victim's
//! resolver is built so the prefix can inject scripted backfill deliveries.
//! The prefix replays a deterministic program extracted from a
//! standard-marshal test, driving the honest core to the source state
//! (a certified missing candidate resolved through an armed round-bound
//! fetch). The fuzzing phase seeds the fabricated notarization into every
//! honest engine's voter journal, starts the engines from the genesis floor so
//! startup replay recovers and re-certifies it, either honestly (`N4F0C4`) or
//! with node 0 replaced by a full-channel adversary (`N4F1C3`), heals the
//! network at a GST boundary, and checks recovery liveness, block safety, and
//! the scenario's expectations.

mod adversary;
mod elector;
pub(crate) mod environment;
pub(crate) mod harness;
pub(crate) mod input;
pub(crate) mod recording_resolver;
pub(crate) mod runner;
#[allow(clippy::module_inception)]
// the concrete scenarios live in scenarios/scenarios.rs by design.
pub(crate) mod scenarios;
mod strategy;

pub use input::{MarshalScenarioPrefixInput, ScenarioKind};
pub use runner::{fuzz_marshal_scenario_prefix_deferred, fuzz_marshal_scenario_prefix_inline};
