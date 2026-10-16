//! Deterministic Multimmit test fixtures.
//!
//! These helpers construct one complete epoch committee with real BLS12-381 key material so
//! attached-actor and integration tests can exercise production cryptography end to end. They are
//! test support only and make no attempt to protect key material.

mod application;
mod body;
pub mod cluster;
mod committee;
pub mod facts;
pub mod keys;
pub mod marshaled;
mod recording;
mod scenario;
#[cfg(test)]
mod size_probe;

pub use application::{
    MockApplication, MockApplicationBuilder, MockApplicationLog, MockGate, NoopReporter,
    RecordingBlocker,
};
pub use body::MockBody;
pub use committee::{Committee, CommitteeBuilder};
pub use recording::{RecordingRelay, RecordingReporter};
pub use scenario::{Certified, Scenario};

/// Namespace for committees built without an explicit one.
const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MOCKS";
