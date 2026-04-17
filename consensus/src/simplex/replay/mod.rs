//! Record and replay deterministic simplex consensus traces.
//!
//! Enabled by the `replay` cargo feature. Iteration 1 is bound to
//! [`commonware_consensus::simplex::scheme::ed25519`] and
//! [`commonware_cryptography::sha256::Sha256`]; generalization to other
//! schemes is deferred.
//!
//! # Status
//!
//! - [`Trace`] + [`Event`]: typed, scheme-specific DTO with hex-wrapped
//!   signed payloads (no re-signing round-trip).
//! - [`Replayer`]: drives N engines via [`injected::Injector`] channels
//!   and an event-gated [`automaton::ReplayAutomaton`].

pub mod automaton;
pub mod driver;
pub mod injected;
pub mod record;
pub mod recorder;
pub mod trace;

#[cfg(test)]
mod fixture_tests;

pub use automaton::ReplayAutomaton;
pub use driver::replay;
pub use record::{record_honest, RecordConfig};
pub use recorder::{
    ChannelKind, RecordingApp, RecordingReceiver, RecordingSender, Recorder,
};
pub use trace::{Event, Snapshot, Topology, Trace, Wire};
