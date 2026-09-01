//! Symbolic effect executors a test driver completes machine effects with.

use super::driver::SymbolicVerifier;
use crate::multimmit::machine::{
    capability::Capability,
    durability::{DomainEvent, PersistDirective, PersistJob},
    input::Input,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};

/// A completion chosen by a pluggable symbolic effect executor.
#[derive(Clone, Debug)]
pub(in crate::multimmit::machine) enum Execution<V: Variant, D: Digest> {
    /// Submit a normal completion through the production input path.
    Input(Input<V, D>),
    /// Durably append and acknowledge a persistence job.
    Persist(PersistJob<V, D>),
}

/// Pluggable policy for completing immutable machine effects.
pub(in crate::multimmit::machine) trait Executor<V: Variant, D: Digest> {
    /// Returns a completion when this executor handles `effect`.
    fn execute(&mut self, effect: &Capability<V, D>) -> Option<Execution<V, D>>;
}

impl<V: Variant, D: Digest> Executor<V, D> for SymbolicVerifier<D> {
    fn execute(&mut self, effect: &Capability<V, D>) -> Option<Execution<V, D>> {
        let Capability::Verify(job) = effect else {
            return None;
        };
        Some(Execution::Input(Input::Verified(self.complete(job))))
    }
}

/// Executor that synchronously makes persistence effects durable.
#[derive(Copy, Clone, Debug, Default)]
pub(in crate::multimmit::machine) struct SymbolicPersistence;

impl<V: Variant, D: Digest> Executor<V, D> for SymbolicPersistence {
    fn execute(&mut self, effect: &Capability<V, D>) -> Option<Execution<V, D>> {
        let Capability::Journal(PersistDirective { job, .. }) = effect else {
            return None;
        };
        Some(Execution::Persist(job.clone()))
    }
}

/// Executor that makes persistence effects durable and records their events in journal order.
#[derive(Clone, Debug)]
pub(in crate::multimmit::machine) struct PersistSink<V: Variant, D: Digest> {
    /// Every persisted event, in cursor order.
    pub(in crate::multimmit::machine) events: Vec<DomainEvent<V, D>>,
}

impl<V: Variant, D: Digest> Default for PersistSink<V, D> {
    fn default() -> Self {
        Self { events: Vec::new() }
    }
}

impl<V: Variant, D: Digest> Executor<V, D> for PersistSink<V, D> {
    fn execute(&mut self, effect: &Capability<V, D>) -> Option<Execution<V, D>> {
        let Capability::Journal(PersistDirective { job, .. }) = effect else {
            return None;
        };
        self.events.extend_from_slice(job.events());
        Some(Execution::Persist(job.clone()))
    }
}
