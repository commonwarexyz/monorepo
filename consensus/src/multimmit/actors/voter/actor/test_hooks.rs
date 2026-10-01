//! A test ledger of what the voter executed at its typed boundaries.

use super::hooks::{Hooks, RetentionBoundary};
use crate::{
    multimmit::{
        actors::voter::persistence::{Hooks as PersistenceHooks, JournalPoint, TestGates},
        machine::{
            BarrierAck, DurableEffect, EffectId, Generation, InputTicket, Lane, PersistJob,
            ServicedInput,
        },
        types::ViewProof,
    },
    types::View,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_runtime::Clock;
use commonware_utils::sync::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::Arc,
    time::SystemTime,
};
use tracing::{Span, debug};

/// One execution attempt for a stable durable-effect identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TestDurableAttempt<V: Variant, D: Digest> {
    pub(crate) generation: Generation,
    pub(crate) effect: DurableEffect<V, D>,
}

/// Ordered observations around resolver retention and egress mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TestEvent<V: Variant, D: Digest> {
    /// Core serviced a barrier acknowledgement; the events it caused follow.
    Acknowledged {
        ack: BarrierAck,
    },
    Retained {
        object: ViewProof<V, D>,
        boundary: RetentionBoundary,
    },
    Installed {
        id: EffectId,
        generation: Generation,
    },
    Retired(Vec<EffectId>),
}

/// Every recorded issue attempt for one durable effect, in issue order.
type DurableAttemptLedger<V, D> = BTreeMap<EffectId, Vec<TestDurableAttempt<V, D>>>;

/// Records what the voter executed and pauses its persistence actor at armed gates.
///
/// Debug events named `test ...` carry the tracing context of the point that emitted them.
#[derive(Clone)]
pub(crate) struct TestHooks<V: Variant, D: Digest> {
    durable: Arc<Mutex<DurableAttemptLedger<V, D>>>,
    acknowledgements: Arc<Mutex<BTreeMap<InputTicket, BarrierAck>>>,
    events: Arc<Mutex<Vec<TestEvent<V, D>>>>,
    services: Arc<Mutex<Vec<(u64, Lane)>>>,
    /// Core service cycles completed, counted at each resume after a yield.
    cycles: Arc<Mutex<u64>>,
    pub(crate) work_quanta: Arc<Mutex<usize>>,
    gates: TestGates,
}

impl<V: Variant, D: Digest> Default for TestHooks<V, D> {
    fn default() -> Self {
        Self {
            durable: Arc::new(Mutex::new(BTreeMap::new())),
            acknowledgements: Arc::new(Mutex::new(BTreeMap::new())),
            events: Arc::new(Mutex::new(Vec::new())),
            services: Arc::new(Mutex::new(Vec::new())),
            cycles: Arc::new(Mutex::new(0)),
            work_quanta: Arc::new(Mutex::new(0)),
            gates: TestGates::default(),
        }
    }
}

impl<V: Variant, D: Digest> TestHooks<V, D> {
    /// Returns these hooks pausing the persistence actor at `gates`.
    pub(crate) fn with_gates(self, gates: TestGates) -> Self {
        Self { gates, ..self }
    }

    pub(crate) fn durable_effects(&self) -> BTreeMap<EffectId, Vec<TestDurableAttempt<V, D>>> {
        self.durable.lock().clone()
    }

    pub(crate) fn events(&self) -> Vec<TestEvent<V, D>> {
        self.events.lock().clone()
    }

    pub(crate) fn services(&self) -> Vec<(u64, Lane)> {
        self.services.lock().clone()
    }

    pub(crate) fn live_publications(&self) -> BTreeSet<EffectId> {
        let mut live = BTreeSet::new();
        for event in self.events.lock().iter() {
            match event {
                TestEvent::Installed { id, .. } => {
                    live.insert(*id);
                }
                TestEvent::Retired(ids) => {
                    for id in ids {
                        live.remove(id);
                    }
                }
                TestEvent::Acknowledged { .. } | TestEvent::Retained { .. } => {}
            }
        }
        live
    }

    fn record(&self, event: TestEvent<V, D>) {
        self.events.lock().push(event);
    }
}

impl<V: Variant, D: Digest> Hooks<V, D> for TestHooks<V, D> {
    fn cycle_started(&self) {
        debug!("test core cycle started");
    }

    fn resumed(&self) {
        *self.cycles.lock() += 1;
    }

    fn serviced(&self, input: &ServicedInput<V, D>) {
        let cycle = *self.cycles.lock();
        self.services.lock().push((cycle, input.lane));
        let ack = self.acknowledgements.lock().remove(&input.ticket);
        if let Some(ack) = ack {
            self.record(TestEvent::Acknowledged { ack });
        }
    }

    fn dispatching(&self, root: &Span, view: View) {
        debug!(
            test_root = root.id().map_or(0, |id| id.into_u64()),
            current_view = view.get(),
            "test captured input dispatch"
        );
    }

    fn working(&self, root: &Span, view: View) {
        debug!(
            view = view.get(),
            test_root = root.id().map_or(0, |id| id.into_u64()),
            "test machine-owned work"
        );
        *self.work_quanta.lock() += 1;
    }

    fn production_timer_armed(&self, root: &Span) {
        debug!(
            test_root = root.id().map_or(0, |id| id.into_u64()),
            "test production timer armed"
        );
    }

    fn acknowledged(&self, ticket: InputTicket, ack: BarrierAck) {
        self.acknowledgements.lock().insert(ticket, ack);
    }

    fn issued(&self, id: EffectId, generation: Generation, effect: &DurableEffect<V, D>) {
        self.durable
            .lock()
            .entry(id)
            .or_default()
            .push(TestDurableAttempt {
                generation,
                effect: effect.clone(),
            });
    }

    fn retained(&self, proof: &ViewProof<V, D>, boundary: RetentionBoundary) {
        self.record(TestEvent::Retained {
            object: proof.clone(),
            boundary,
        });
    }

    fn installed(&self, id: EffectId, generation: Generation) {
        self.record(TestEvent::Installed { id, generation });
    }

    fn retired(&self, ids: &[EffectId]) {
        if !ids.is_empty() {
            self.record(TestEvent::Retired(ids.to_vec()));
        }
    }
}

impl<V: Variant, D: Digest> PersistenceHooks for TestHooks<V, D> {
    type Point = JournalPoint;

    fn appending<W: Variant, E: Digest>(&self, job: &PersistJob<W, E>) -> JournalPoint {
        self.gates.appending(job)
    }

    fn before_append(
        &self,
        point: JournalPoint,
        clock: &impl Clock,
    ) -> impl Future<Output = ()> + Send {
        self.gates.before_append(point, clock)
    }

    fn after_append(
        &self,
        point: JournalPoint,
        appended_at: SystemTime,
    ) -> impl Future<Output = ()> + Send {
        self.gates.after_append(point, appended_at)
    }

    fn before_start_sync(
        &self,
        point: JournalPoint,
        started_at: SystemTime,
    ) -> impl Future<Output = ()> + Send {
        self.gates.before_start_sync(point, started_at)
    }

    fn after_sync(
        &self,
        point: JournalPoint,
        clock: &impl Clock,
    ) -> impl Future<Output = ()> + Send {
        self.gates.after_sync(point, clock)
    }

    fn before_roll(&self, clock: &impl Clock) -> impl Future<Output = ()> + Send {
        self.gates.before_roll(clock)
    }

    fn before_prune(&self, clock: &impl Clock) -> impl Future<Output = u64> + Send {
        self.gates.before_prune(clock)
    }

    fn after_prune(&self, ordinal: u64, clock: &impl Clock) -> impl Future<Output = ()> + Send {
        self.gates.after_prune(ordinal, clock)
    }
}
