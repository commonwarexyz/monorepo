//! Test gates that pause the persistence actor at its storage operations.

use super::hooks::Hooks;
use crate::multimmit::machine::{BatchId, Change, Cursor, EffectId, Generation, PersistJob};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_runtime::Clock;
use commonware_utils::{channel::oneshot, sync::Mutex};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

/// Gates that pause the persistence actor at its storage operations and record its appends.
#[derive(Clone, Default)]
pub(crate) struct TestGates {
    append: Arc<Mutex<Option<GateWaiter>>>,
    after_append: Arc<Mutex<Option<GateWaiter>>>,
    start_sync: Arc<Mutex<Option<GateWaiter>>>,
    after_sync: Arc<Mutex<Option<GateWaiter>>>,
    roll: Arc<Mutex<Option<GateWaiter>>>,
    before_prune: Arc<Mutex<Option<GateWaiter>>>,
    after_prune: Arc<Mutex<Option<GateWaiter>>>,
    appends: Arc<Mutex<Vec<JournalPoint>>>,
    appended_at: Arc<Mutex<Vec<SystemTime>>>,
    append_ordinal: Arc<AtomicU64>,
    sync_ordinal: Arc<AtomicU64>,
    after_sync_ordinal: Arc<AtomicU64>,
    roll_ordinal: Arc<AtomicU64>,
    prune_ordinal: Arc<AtomicU64>,
}

struct GateWaiter {
    target: GateTarget,
    entered: oneshot::Sender<SystemTime>,
    release: oneshot::Receiver<()>,
}

#[derive(Clone, Copy)]
enum GateTarget {
    Coordinate {
        generation: Generation,
        cursor: Cursor,
    },
    Retires(EffectId),
    Ordinal(u64),
}

/// Content-independent identity of one attempted append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct JournalPoint {
    pub(crate) ordinal: u64,
    pub(crate) barrier: BatchId,
    pub(crate) generation: Generation,
    pub(crate) previous: Cursor,
    pub(crate) result: Cursor,
}

/// Controller for one armed storage suspension point.
pub(crate) struct TestGate {
    entered: Option<oneshot::Receiver<SystemTime>>,
    release: Option<oneshot::Sender<()>>,
}

impl TestGates {
    pub(crate) fn appends(&self) -> Vec<JournalPoint> {
        self.appends.lock().clone()
    }

    /// Returns when each append was written, in append order.
    pub(crate) fn appended_at(&self) -> Vec<SystemTime> {
        self.appended_at.lock().clone()
    }

    pub(crate) fn arm_append_covering(&self, generation: Generation, cursor: Cursor) -> TestGate {
        Self::arm(&self.append, GateTarget::Coordinate { generation, cursor })
    }

    pub(crate) fn arm_after_append(&self) -> TestGate {
        Self::arm(
            &self.after_append,
            GateTarget::Ordinal(self.append_ordinal.load(Ordering::SeqCst)),
        )
    }

    pub(crate) fn arm_start_sync_covering(
        &self,
        generation: Generation,
        cursor: Cursor,
    ) -> TestGate {
        Self::arm(
            &self.start_sync,
            GateTarget::Coordinate { generation, cursor },
        )
    }

    pub(crate) fn arm_after_sync_covering(
        &self,
        generation: Generation,
        cursor: Cursor,
    ) -> TestGate {
        Self::arm(
            &self.after_sync,
            GateTarget::Coordinate { generation, cursor },
        )
    }

    pub(crate) fn arm_after_sync_retiring(&self, effect: EffectId) -> TestGate {
        Self::arm(&self.after_sync, GateTarget::Retires(effect))
    }

    pub(crate) fn arm_next_append(&self) -> TestGate {
        Self::arm(
            &self.append,
            GateTarget::Ordinal(self.append_ordinal.load(Ordering::SeqCst)),
        )
    }

    pub(crate) fn arm_next_start_sync(&self) -> TestGate {
        Self::arm(
            &self.start_sync,
            GateTarget::Ordinal(self.sync_ordinal.load(Ordering::SeqCst)),
        )
    }

    pub(crate) fn arm_next_after_sync(&self) -> TestGate {
        Self::arm(
            &self.after_sync,
            GateTarget::Ordinal(self.after_sync_ordinal.load(Ordering::SeqCst)),
        )
    }

    pub(crate) fn arm_next_roll(&self) -> TestGate {
        Self::arm(
            &self.roll,
            GateTarget::Ordinal(self.roll_ordinal.load(Ordering::SeqCst)),
        )
    }

    pub(crate) fn arm_next_before_prune(&self) -> TestGate {
        Self::arm(
            &self.before_prune,
            GateTarget::Ordinal(self.prune_ordinal.load(Ordering::SeqCst)),
        )
    }

    pub(crate) fn arm_next_after_prune(&self) -> TestGate {
        Self::arm(
            &self.after_prune,
            GateTarget::Ordinal(self.prune_ordinal.load(Ordering::SeqCst)),
        )
    }

    fn arm(slot: &Mutex<Option<GateWaiter>>, target: GateTarget) -> TestGate {
        let (entered_sender, entered) = oneshot::channel();
        let (release, release_receiver) = oneshot::channel();
        let mut slot = slot.lock();
        assert!(slot.is_none(), "journal test gate is already armed");
        *slot = Some(GateWaiter {
            target,
            entered: entered_sender,
            release: release_receiver,
        });
        TestGate {
            entered: Some(entered),
            release: Some(release),
        }
    }

    async fn wait_ordinal(slot: &Mutex<Option<GateWaiter>>, ordinal: u64, entered_at: SystemTime) {
        let waiter = {
            let mut slot = slot.lock();
            if slot.as_ref().is_some_and(
                |waiter| !matches!(waiter.target, GateTarget::Ordinal(target) if target == ordinal),
            ) {
                return;
            }
            slot.take()
        };
        Self::hold(waiter, entered_at).await;
    }

    async fn wait(
        slot: &Mutex<Option<GateWaiter>>,
        point: JournalPoint,
        ordinal: u64,
        append: bool,
        entered_at: SystemTime,
    ) {
        let waiter = {
            let mut slot = slot.lock();
            if let Some(waiter) = slot.as_mut() {
                match waiter.target {
                    GateTarget::Coordinate { generation, cursor }
                        if generation != point.generation
                            || cursor > point.result
                            || (append && cursor <= point.previous) =>
                    {
                        return;
                    }
                    GateTarget::Retires(_) => return,
                    GateTarget::Ordinal(target) if target != ordinal => return,
                    GateTarget::Coordinate { .. } | GateTarget::Ordinal(_) => {}
                }
            }
            slot.take()
        };
        Self::hold(waiter, entered_at).await;
    }

    async fn hold(waiter: Option<GateWaiter>, entered_at: SystemTime) {
        let Some(waiter) = waiter else {
            return;
        };
        let _ = waiter.entered.send(entered_at);
        let _ = waiter.release.await;
    }
}

impl Hooks for TestGates {
    type Point = JournalPoint;

    fn appending<V: Variant, D: Digest>(&self, job: &PersistJob<V, D>) -> JournalPoint {
        let point = JournalPoint {
            ordinal: self.append_ordinal.fetch_add(1, Ordering::SeqCst),
            barrier: job.id(),
            generation: job.generation(),
            previous: job.previous(),
            result: job.last_cursor(),
        };
        self.appends.lock().push(point);
        let retires = |change: &Change<V, D>, effect| match change {
            Change::DaCertificateAdvanced {
                retired_publications: retired,
                ..
            }
            | Change::ArtifactForwarded {
                retired_publications: retired,
                ..
            }
            | Change::ViewAdvanced {
                retired_publications: retired,
                ..
            } => retired.contains(&effect),
            Change::FinalityFloorAdvanced {
                retired_publications,
                ..
            } => retired_publications.contains(&effect),
            _ => false,
        };
        let mut after_sync = self.after_sync.lock();
        if after_sync.as_ref().is_some_and(|waiter| {
            matches!(waiter.target, GateTarget::Retires(effect)
                if job.events().iter().any(|event| retires(event.change(), effect)))
        }) {
            after_sync.as_mut().expect("checked above").target = GateTarget::Coordinate {
                generation: point.generation,
                cursor: point.result,
            };
        }
        point
    }

    async fn before_append(&self, point: JournalPoint, clock: &impl Clock) {
        Self::wait(&self.append, point, point.ordinal, true, clock.current()).await;
    }

    async fn after_append(&self, point: JournalPoint, appended_at: SystemTime) {
        self.appended_at.lock().push(appended_at);
        Self::wait(&self.after_append, point, point.ordinal, true, appended_at).await;
    }

    async fn before_start_sync(&self, point: JournalPoint, started_at: SystemTime) {
        let ordinal = self.sync_ordinal.fetch_add(1, Ordering::SeqCst);
        Self::wait(&self.start_sync, point, ordinal, false, started_at).await;
    }

    async fn after_sync(&self, point: JournalPoint, clock: &impl Clock) {
        let ordinal = self.after_sync_ordinal.fetch_add(1, Ordering::SeqCst);
        Self::wait(&self.after_sync, point, ordinal, false, clock.current()).await;
    }

    async fn before_roll(&self, clock: &impl Clock) {
        let ordinal = self.roll_ordinal.fetch_add(1, Ordering::SeqCst);
        Self::wait_ordinal(&self.roll, ordinal, clock.current()).await;
    }

    async fn before_prune(&self, clock: &impl Clock) -> u64 {
        let ordinal = self.prune_ordinal.fetch_add(1, Ordering::SeqCst);
        Self::wait_ordinal(&self.before_prune, ordinal, clock.current()).await;
        ordinal
    }

    async fn after_prune(&self, ordinal: u64, clock: &impl Clock) {
        Self::wait_ordinal(&self.after_prune, ordinal, clock.current()).await;
    }
}

impl TestGate {
    pub(crate) async fn wait_entered(&mut self) {
        let _ = self
            .entered
            .take()
            .expect("journal test gate is awaited once")
            .await
            .expect("journal owner reaches the armed gate");
    }

    pub(super) async fn wait_entered_at(&mut self) -> SystemTime {
        self.entered
            .take()
            .expect("journal test gate is awaited once")
            .await
            .expect("journal owner reaches the armed gate")
    }

    pub(crate) fn release(mut self) {
        let _ = self
            .release
            .take()
            .expect("journal test gate is released once")
            .send(());
    }
}
