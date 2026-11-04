//! Symbolic effect executors a test driver completes machine effects with.

use super::driver::SymbolicVerifier;
use crate::multimmit::{
    machine::{
        capability::Capability,
        durability::{DomainEvent, PersistDirective, PersistJob},
        input::Input,
    },
    scheme::Scheme,
};
use commonware_cryptography::Digest;

/// A completion chosen by a pluggable symbolic effect executor.
#[derive(Clone, Debug)]
pub(in crate::multimmit::machine) enum Execution<S: Scheme, D: Digest> {
    /// Submit a normal completion through the production input path.
    Input(Input<S, D>),
    /// Durably append and acknowledge a persistence job.
    Persist(PersistJob<S, D>),
}

/// Pluggable policy for completing immutable machine effects.
pub(in crate::multimmit::machine) trait Executor<S: Scheme, D: Digest> {
    /// Returns a completion when this executor handles `effect`.
    fn execute(&mut self, effect: &Capability<S, D>) -> Option<Execution<S, D>>;
}

impl<S: Scheme, D: Digest> Executor<S, D> for SymbolicVerifier<D> {
    fn execute(&mut self, effect: &Capability<S, D>) -> Option<Execution<S, D>> {
        let Capability::Verify(job) = effect else {
            return None;
        };
        Some(Execution::Input(Input::Verified(self.complete(job))))
    }
}

/// Executor that synchronously makes persistence effects durable.
#[derive(Copy, Clone, Debug, Default)]
pub(in crate::multimmit::machine) struct SymbolicPersistence;

impl<S: Scheme, D: Digest> Executor<S, D> for SymbolicPersistence {
    fn execute(&mut self, effect: &Capability<S, D>) -> Option<Execution<S, D>> {
        let Capability::Journal(PersistDirective { job, .. }) = effect else {
            return None;
        };
        Some(Execution::Persist(job.clone()))
    }
}

/// Executor that makes persistence effects durable and records their events in journal order.
#[derive(Clone, Debug)]
pub(in crate::multimmit::machine) struct PersistSink<S: Scheme, D: Digest> {
    /// Every persisted event, in cursor order.
    pub(in crate::multimmit::machine) events: Vec<DomainEvent<S, D>>,
}

impl<S: Scheme, D: Digest> Default for PersistSink<S, D> {
    fn default() -> Self {
        Self { events: Vec::new() }
    }
}

impl<S: Scheme, D: Digest> Executor<S, D> for PersistSink<S, D> {
    fn execute(&mut self, effect: &Capability<S, D>) -> Option<Execution<S, D>> {
        let Capability::Journal(PersistDirective { job, .. }) = effect else {
            return None;
        };
        self.events.extend_from_slice(job.events());
        Some(Execution::Persist(job.clone()))
    }
}
