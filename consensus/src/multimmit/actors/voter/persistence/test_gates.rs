//! Test gates that pause the persistence actor at its storage operations.

use super::hooks::Hooks;
use crate::multimmit::machine::PersistJob;
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
///
/// Each gate pauses the next occurrence of its operation after it is armed, identified by that
/// operation's ordinal.
#[derive(Clone, Default)]
pub(crate) struct TestGates {
    append: Arc<Mutex<Option<GateWaiter>>>,
    after_append: Arc<Mutex<Option<GateWaiter>>>,
    start_sync: Arc<Mutex<Option<GateWaiter>>>,
    after_sync: Arc<Mutex<Option<GateWaiter>>>,
    appended_at: Arc<Mutex<Vec<SystemTime>>>,
    append_ordinal: Arc<AtomicU64>,
    sync_ordinal: Arc<AtomicU64>,
    after_sync_ordinal: Arc<AtomicU64>,
}

struct GateWaiter {
    ordinal: u64,
    entered: oneshot::Sender<SystemTime>,
    release: oneshot::Receiver<()>,
}

/// Controller for one armed storage suspension point.
pub(crate) struct TestGate {
    entered: Option<oneshot::Receiver<SystemTime>>,
    release: Option<oneshot::Sender<()>>,
}

impl TestGates {
    /// Returns when each append was written, in append order.
    pub(crate) fn appended_at(&self) -> Vec<SystemTime> {
        self.appended_at.lock().clone()
    }

    pub(crate) fn arm_next_append(&self) -> TestGate {
        Self::arm(&self.append, &self.append_ordinal)
    }

    pub(crate) fn arm_after_append(&self) -> TestGate {
        Self::arm(&self.after_append, &self.append_ordinal)
    }

    pub(crate) fn arm_next_start_sync(&self) -> TestGate {
        Self::arm(&self.start_sync, &self.sync_ordinal)
    }

    pub(crate) fn arm_next_after_sync(&self) -> TestGate {
        Self::arm(&self.after_sync, &self.after_sync_ordinal)
    }

    fn arm(slot: &Mutex<Option<GateWaiter>>, next: &AtomicU64) -> TestGate {
        let (entered_sender, entered) = oneshot::channel();
        let (release, release_receiver) = oneshot::channel();
        let mut slot = slot.lock();
        assert!(slot.is_none(), "journal test gate is already armed");
        *slot = Some(GateWaiter {
            ordinal: next.load(Ordering::SeqCst),
            entered: entered_sender,
            release: release_receiver,
        });
        TestGate {
            entered: Some(entered),
            release: Some(release),
        }
    }

    /// Pauses at `slot` when its armed gate targets `ordinal`.
    async fn wait(slot: &Mutex<Option<GateWaiter>>, ordinal: u64, entered_at: SystemTime) {
        let waiter = {
            let mut slot = slot.lock();
            if slot.as_ref().is_none_or(|waiter| waiter.ordinal != ordinal) {
                return;
            }
            slot.take().expect("checked above")
        };
        let _ = waiter.entered.send(entered_at);
        let _ = waiter.release.await;
    }
}

impl Hooks for TestGates {
    /// The append's ordinal.
    type Point = u64;

    fn appending<V: Variant, D: Digest>(&self, _job: &PersistJob<V, D>) -> u64 {
        self.append_ordinal.fetch_add(1, Ordering::SeqCst)
    }

    async fn before_append(&self, ordinal: u64, clock: &impl Clock) {
        Self::wait(&self.append, ordinal, clock.current()).await;
    }

    async fn after_append(&self, ordinal: u64, appended_at: SystemTime) {
        self.appended_at.lock().push(appended_at);
        Self::wait(&self.after_append, ordinal, appended_at).await;
    }

    async fn before_start_sync(&self, _ordinal: u64, started_at: SystemTime) {
        let ordinal = self.sync_ordinal.fetch_add(1, Ordering::SeqCst);
        Self::wait(&self.start_sync, ordinal, started_at).await;
    }

    async fn after_sync(&self, _ordinal: u64, clock: &impl Clock) {
        let ordinal = self.after_sync_ordinal.fetch_add(1, Ordering::SeqCst);
        Self::wait(&self.after_sync, ordinal, clock.current()).await;
    }
}

impl TestGate {
    pub(crate) async fn wait_entered(&mut self) {
        let _ = self.wait_entered_at().await;
    }

    pub(crate) async fn wait_entered_at(&mut self) -> SystemTime {
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
