//! A test ledger of the durable effects the voter issued and the publications it installed and
//! retired.

use super::hooks::Hooks;
use crate::multimmit::{
    actors::voter::persistence::{Hooks as PersistenceHooks, TestGates},
    machine::{DurableEffect, EffectId, Generation, PersistJob},
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_runtime::Clock;
use commonware_utils::sync::Mutex;
use std::{collections::BTreeMap, future::Future, sync::Arc, time::SystemTime};

/// An egress mutation, in the order the voter applied it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TestEvent {
    /// A durable publication was installed in egress.
    Installed(EffectId),
    /// Durable publications were retired from egress.
    Retired(Vec<EffectId>),
}

/// Records what the voter executed and pauses its persistence actor at armed gates.
#[derive(Clone)]
pub(crate) struct TestHooks<V: Variant, D: Digest> {
    effects: Arc<Mutex<BTreeMap<EffectId, DurableEffect<V, D>>>>,
    events: Arc<Mutex<Vec<TestEvent>>>,
    gates: TestGates,
}

impl<V: Variant, D: Digest> Default for TestHooks<V, D> {
    fn default() -> Self {
        Self {
            effects: Arc::default(),
            events: Arc::default(),
            gates: TestGates::default(),
        }
    }
}

impl<V: Variant, D: Digest> TestHooks<V, D> {
    /// Returns these hooks pausing the persistence actor at `gates`.
    pub(crate) fn with_gates(self, gates: TestGates) -> Self {
        Self { gates, ..self }
    }

    /// Returns every durable effect the voter issued, by identity.
    pub(crate) fn effects(&self) -> BTreeMap<EffectId, DurableEffect<V, D>> {
        self.effects.lock().clone()
    }

    /// Returns the egress mutations in order.
    pub(crate) fn events(&self) -> Vec<TestEvent> {
        self.events.lock().clone()
    }
}

impl<V: Variant, D: Digest> Hooks<V, D> for TestHooks<V, D> {
    fn issued(&self, id: EffectId, _generation: Generation, effect: &DurableEffect<V, D>) {
        self.effects.lock().insert(id, effect.clone());
    }

    fn installed(&self, id: EffectId, _generation: Generation) {
        self.events.lock().push(TestEvent::Installed(id));
    }

    fn retired(&self, ids: &[EffectId]) {
        if !ids.is_empty() {
            self.events.lock().push(TestEvent::Retired(ids.to_vec()));
        }
    }
}

impl<V: Variant, D: Digest> PersistenceHooks for TestHooks<V, D> {
    type Point = <TestGates as PersistenceHooks>::Point;

    fn appending<W: Variant, E: Digest>(&self, job: &PersistJob<W, E>) -> Self::Point {
        self.gates.appending(job)
    }

    fn before_append(
        &self,
        point: Self::Point,
        clock: &impl Clock,
    ) -> impl Future<Output = ()> + Send {
        self.gates.before_append(point, clock)
    }

    fn after_append(
        &self,
        point: Self::Point,
        appended_at: SystemTime,
    ) -> impl Future<Output = ()> + Send {
        self.gates.after_append(point, appended_at)
    }

    fn before_start_sync(
        &self,
        point: Self::Point,
        started_at: SystemTime,
    ) -> impl Future<Output = ()> + Send {
        self.gates.before_start_sync(point, started_at)
    }

    fn after_sync(
        &self,
        point: Self::Point,
        clock: &impl Clock,
    ) -> impl Future<Output = ()> + Send {
        self.gates.after_sync(point, clock)
    }
}
