use crate::{marshal::core::durability::Durable as _, types::Round};
use commonware_cryptography::Digest;
use commonware_macros::select;
use commonware_runtime::Handle;
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use std::{collections::HashMap, sync::Arc};
use tracing::debug;

/// A proposal staged for its relay broadcast.
pub(crate) struct Staged<B> {
    /// The block, shared with the relay send and the eventual persist.
    pub(crate) block: Arc<B>,
    /// Delivers the durable-sync handle once marshal persists the block.
    pub(crate) ack: oneshot::Sender<Handle<()>>,
    /// Whether the block was already sent to peers while held, so the lock-in
    /// broadcast only persists it.
    pub(crate) sent: bool,
}

/// Result of an in-flight certification gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GateOutcome {
    /// The gate produced a verdict that applies to the notarized proposal.
    Ready(bool),
    /// The gate's result does not apply to the notarized proposal.
    Recover,
}

/// The registries behind [`Gates`], sharing one lock.
struct Inner<D: Digest, B> {
    /// In-flight certification gate tasks, consumed by certification.
    certifications: HashMap<(Round, D), oneshot::Receiver<GateOutcome>>,
    /// Proposals staged for their relay broadcast, consumed by the lock-in
    /// broadcast (or by certification when it arrives first).
    proposals: HashMap<(Round, D), Staged<B>>,
}

/// A shared, thread-safe registry of in-flight certification gate tasks and
/// staged proposals.
///
/// Each entry is keyed by `(Round, D)` where `D` is a commitment or digest
/// identifying the block. The gate task's [`oneshot::Receiver`] is consumed by
/// certification. [`GateOutcome::Ready`] carries a verdict that applies to the
/// notarized proposal. [`GateOutcome::Recover`] means the completed work does
/// not apply, so certification must use its recovery path. A dropped sender
/// also triggers recovery because the task did not complete.
/// Storage sync failures are fatal to the local marshal state and must panic
/// before resolving the task.
///
/// Tasks are inserted when a block enters proposal or verification handling and
/// taken (consumed) when certification is ready to act on the result. A staged
/// proposal holds the block itself until consensus locks it in with a propose
/// broadcast via [`crate::Relay::broadcast`] (or certification demands
/// durability first), keeping marshal's mailbox free of any propose-time
/// handshake. Stale entries are pruned after finalization via
/// [`retain_after`](Self::retain_after).
#[derive(Clone)]
pub(crate) struct Gates<D: Digest, B> {
    inner: Arc<Mutex<Inner<D, B>>>,
}

impl<D: Digest, B> Default for Gates<D, B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Digest, B> Gates<D, B> {
    /// Creates an empty registry.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                certifications: HashMap::new(),
                proposals: HashMap::new(),
            })),
        }
    }

    /// Registers a certification gate task for the block identified by `(round, digest)`.
    pub(crate) fn insert(&self, round: Round, digest: D, task: oneshot::Receiver<GateOutcome>) {
        self.inner
            .lock()
            .certifications
            .insert((round, digest), task);
    }

    /// Removes and returns the certification gate task for `(round, digest)`, if present.
    #[cfg(test)]
    pub(crate) fn take(&self, round: Round, digest: D) -> Option<oneshot::Receiver<GateOutcome>> {
        self.inner.lock().certifications.remove(&(round, digest))
    }

    /// Removes and returns the staged proposal for `(round, digest)`, if present.
    ///
    /// The taken block and ack are handed to marshal exactly once: by the lock-in
    /// broadcast, or by certification if it arrives first.
    pub(crate) fn take_staged(&self, round: Round, digest: D) -> Option<Staged<B>> {
        self.inner.lock().proposals.remove(&(round, digest))
    }

    /// Returns the staged proposal for `(round, digest)` for a send that does not
    /// persist it, and marks it sent so the lock-in broadcast only persists it.
    ///
    /// Returns `None` when no proposal is staged or the staged proposal was already
    /// sent, so each staged block goes out at most once.
    ///
    /// The entry stays staged: a held candidate may still be abandoned, so it is stored only by the
    /// lock-in broadcast or by certification.
    pub(crate) fn send_staged(&self, round: Round, digest: D) -> Option<Arc<B>> {
        let mut inner = self.inner.lock();
        let staged = inner.proposals.get_mut(&(round, digest))?;
        if staged.sent {
            return None;
        }
        staged.sent = true;
        Some(staged.block.clone())
    }

    /// Removes and returns the certification gate task for `(round, id)`, if present, and
    /// hands the staged proposal it waits on to `persist` without broadcasting it.
    ///
    /// A staged proposal that was never locked in by a propose broadcast cannot
    /// resolve its certification gate. Certification demands durability, so
    /// `persist` stores the block and delivers the durable-sync handle through the
    /// staged ack. Nothing is persisted when no proposal is staged (the lock-in
    /// broadcast already took it).
    ///
    /// A stage of the same block can run concurrently with certification, for example from a
    /// prepare build that completed as consensus abandoned it. The gate and the staged
    /// proposal are therefore removed under one lock, so the returned gate waits on an ack
    /// that `persist` receives here or that the lock-in broadcast already took. A later stage
    /// of the same block only leaves entries that pruning discards.
    pub(crate) fn claim(
        &self,
        round: Round,
        id: D,
        persist: impl FnOnce(Arc<B>, oneshot::Sender<Handle<()>>),
    ) -> Option<oneshot::Receiver<GateOutcome>> {
        let (gate, staged) = {
            let mut inner = self.inner.lock();
            (
                inner.certifications.remove(&(round, id)),
                inner.proposals.remove(&(round, id)),
            )
        };
        if let Some(Staged { block, ack, .. }) = staged {
            persist(block, ack);
        }
        gate
    }

    /// Discards all entries whose round is at or before `finalized_round`.
    ///
    /// A discarded staged proposal drops its ack, which abandons the propose
    /// durability handshake for that (already decided) round.
    pub(crate) fn retain_after(&self, finalized_round: &Round) {
        let mut inner = self.inner.lock();
        inner
            .certifications
            .retain(|(round, _), _| round > finalized_round);
        inner
            .proposals
            .retain(|(round, _), _| round > finalized_round);
    }

    /// Stages `block` for its relay broadcast and completes the propose
    /// durability handshake for `(round, id)`.
    ///
    /// Registers a certification gate and the staged block, publishes `id` to
    /// consensus through `publish`, then awaits the durable-sync handle so
    /// [`certify`](crate::CertifiableAutomaton::certify) can require durability
    /// before the finalize vote. Both registrations happen before `id` is
    /// published so the relay broadcast and `certify` always find them.
    ///
    /// The handle arrives once marshal persists the staged block, which happens
    /// when consensus locks it in with a propose broadcast, or at certification
    /// if that arrives first, so this await can outlive the round. A real
    /// sync failure panics here (the fatal policy, annotated with `name`). A
    /// dropped ack means the marshal actor is gone, the staged entry was pruned
    /// without ever being taken, or the same block was staged again for the
    /// round. The first two leave the gate unresolved, so `certify` falls back
    /// to its recovery fetch. Staging again also replaces the gate, so `certify`
    /// awaits the later stage's gate instead.
    pub(crate) async fn stage(
        &self,
        round: Round,
        id: D,
        block: Arc<B>,
        publish: impl FnOnce(D),
        name: &'static str,
    ) {
        let (durable_tx, durable_rx) = oneshot::channel();
        let (ack, persist) = oneshot::channel();
        {
            let mut inner = self.inner.lock();
            inner.certifications.insert((round, id), durable_rx);

            // An id names one block, so a block staged again for the round, such as a
            // re-proposed epoch boundary block, stays sent if a prepare broadcast sent it.
            let sent = inner
                .proposals
                .get(&(round, id))
                .is_some_and(|staged| staged.sent);
            inner
                .proposals
                .insert((round, id), Staged { block, ack, sent });
        }
        publish(id);
        let Ok(handle) = persist.await else {
            return;
        };
        if !handle.durable(round, name).await {
            return;
        }
        durable_tx.send_lossy(GateOutcome::Ready(true));
        debug!(?round, ?id, name, "block durable");
    }
}

/// Resolves a deferred verification's certification gate from the joined `(verdict, durable)`
/// result of running application verification concurrently with the candidate store.
///
/// `verdict` is the application validity (`None` when verification stopped early). A false verdict
/// is a live rejection that needs no durability. A true verdict requires the store to be durable;
/// `durable` is false only when the marshal actor is gone at shutdown (a real sync failure panics
/// at its source), so a true-but-not-durable result abandons the gate. Returns the verdict to
/// publish, or `None` to leave the gate unresolved.
pub(crate) const fn resolve(verdict: Option<bool>, durable: bool) -> Option<bool> {
    match verdict {
        Some(true) if !durable => None,
        other => other,
    }
}

/// Forwards `input` while `output` still has a receiver.
///
/// If the output receiver closes first, the input operation is canceled.
pub(crate) async fn forward<T, U>(
    mut output: oneshot::Sender<T>,
    input: oneshot::Receiver<U>,
    map: impl FnOnce(U) -> Option<T>,
) {
    let result = select! {
        _ = output.closed() => return,
        result = input => result,
    };
    if let Ok(value) = result
        && let Some(value) = map(value)
    {
        output.send_lossy(value);
    }
}

/// Drives a certification gate `task` to a certify verdict, recovering through `fallback` when the
/// gate cannot speak for the notarized proposal.
///
/// A ready verdict is published on `tx`. [`GateOutcome::Recover`] or a dropped sender triggers
/// `fallback`, whose receiver is awaited and published instead. A consensus-dropped receiver
/// (`tx.closed()`) abandons the work.
pub(crate) async fn drive<D, F>(
    mut tx: oneshot::Sender<bool>,
    task: oneshot::Receiver<GateOutcome>,
    round: Round,
    id: D,
    fallback: F,
) where
    D: Digest,
    F: FnOnce() -> oneshot::Receiver<bool>,
{
    let result = select! {
        _ = tx.closed() => {
            debug!(
                reason = "consensus dropped receiver",
                "skipping certification"
            );
            return;
        },
        result = task => result,
    };
    match result {
        Ok(GateOutcome::Ready(result)) => {
            tx.send_lossy(result);
        }
        Ok(GateOutcome::Recover) | Err(_) => {
            debug!(
                ?round,
                ?id,
                "certification gate requires recovery, falling back to embedded context"
            );
            let fallback = fallback();
            let result = select! {
                _ = tx.closed() => {
                    debug!(
                        reason = "consensus dropped receiver",
                        "skipping certification"
                    );
                    return;
                },
                result = fallback => result,
            };
            if let Ok(result) = result {
                tx.send_lossy(result);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Epoch, View};
    use commonware_cryptography::{Hasher, Sha256, sha256::Digest as Sha256Digest};
    use commonware_runtime::{Runner, Spawner, Supervisor, deterministic};
    use futures::FutureExt as _;

    type D = Sha256Digest;
    type TestGates = Gates<D, u64>;

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn pending_task() -> oneshot::Receiver<GateOutcome> {
        let (_tx, rx) = oneshot::channel();
        rx
    }

    fn no_fallback() -> oneshot::Receiver<bool> {
        unreachable!("certification must not fall back")
    }

    #[test]
    fn test_insert_and_take_returns_task() {
        let tasks = TestGates::new();
        let digest = Sha256::hash(&[b"block"]);
        tasks.insert(round(1), digest, pending_task());

        assert!(tasks.take(round(1), digest).is_some());
        assert!(
            tasks.take(round(1), digest).is_none(),
            "taking twice should yield None"
        );
    }

    #[test]
    fn test_take_absent_key_is_none() {
        let tasks = TestGates::new();
        assert!(tasks.take(round(1), Sha256::hash(&[b"missing"])).is_none());
    }

    #[test]
    fn test_take_distinguishes_rounds_and_digests() {
        let tasks = TestGates::new();
        let digest_a = Sha256::hash(&[b"a"]);
        let digest_b = Sha256::hash(&[b"b"]);
        tasks.insert(round(1), digest_a, pending_task());
        tasks.insert(round(2), digest_a, pending_task());
        tasks.insert(round(1), digest_b, pending_task());

        assert!(tasks.take(round(1), digest_a).is_some());
        assert!(tasks.take(round(2), digest_a).is_some());
        assert!(tasks.take(round(1), digest_b).is_some());
    }

    #[test]
    fn test_retain_after_drops_at_and_below_boundary() {
        let tasks = TestGates::new();
        let digest = Sha256::hash(&[b"block"]);
        tasks.insert(round(1), digest, pending_task());
        tasks.insert(round(2), digest, pending_task());
        tasks.insert(round(3), digest, pending_task());

        tasks.retain_after(&round(2));

        assert!(
            tasks.take(round(1), digest).is_none(),
            "tasks strictly below boundary should be dropped"
        );
        assert!(
            tasks.take(round(2), digest).is_none(),
            "tasks at boundary should be dropped"
        );
        assert!(
            tasks.take(round(3), digest).is_some(),
            "tasks strictly above boundary should be retained"
        );
    }

    #[test]
    fn test_retain_after_spans_epochs() {
        let tasks = TestGates::new();
        let digest = Sha256::hash(&[b"block"]);
        let early = Round::new(Epoch::zero(), View::new(100));
        let late = Round::new(Epoch::new(1), View::zero());
        tasks.insert(early, digest, pending_task());
        tasks.insert(late, digest, pending_task());

        tasks.retain_after(&early);

        assert!(
            tasks.take(early, digest).is_none(),
            "task at boundary must be dropped"
        );
        assert!(
            tasks.take(late, digest).is_some(),
            "task in later epoch must outlive an earlier boundary"
        );
    }

    #[test]
    fn test_retain_after_empty_map_is_noop() {
        let tasks = TestGates::new();
        tasks.retain_after(&round(5));
        assert!(tasks.take(round(5), Sha256::hash(&[b"x"])).is_none());
    }

    #[test]
    fn test_default_matches_new() {
        let default = <TestGates as Default>::default();
        let digest = Sha256::hash(&[b"block"]);
        default.insert(round(1), digest, pending_task());
        assert!(default.take(round(1), digest).is_some());
    }

    #[test]
    fn test_resolve() {
        // Verification stopped early: nothing to publish regardless of durability.
        assert_eq!(resolve(None, true), None);
        assert_eq!(resolve(None, false), None);
        // A false app verdict is a live rejection that needs no durability.
        assert_eq!(resolve(Some(false), false), Some(false));
        assert_eq!(resolve(Some(false), true), Some(false));
        // A true verdict publishes only once the store is durable.
        assert_eq!(resolve(Some(true), true), Some(true));
        assert_eq!(resolve(Some(true), false), None);
    }

    #[test]
    fn test_forward_cancels_input_when_output_closes() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            let (input_tx, input_rx) = oneshot::channel::<bool>();
            let (output_tx, output_rx) = oneshot::channel::<bool>();
            drop(output_rx);

            forward(output_tx, input_rx, Some).await;

            assert!(input_tx.is_closed());
        });
    }

    #[test]
    fn test_forward_cancels_in_flight_input_when_output_closes() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (input_tx, input_rx) = oneshot::channel::<bool>();
            let (output_tx, output_rx) = oneshot::channel::<bool>();
            let (started_tx, started_rx) = oneshot::channel();
            let forwarder = context.child("forwarder").spawn(|_| async move {
                started_tx.send_lossy(());
                forward(output_tx, input_rx, Some).await;
            });

            started_rx.await.expect("forwarder should start");
            assert!(!input_tx.is_closed());
            drop(output_rx);
            forwarder.await.expect("forwarder should stop");
            assert!(input_tx.is_closed());
        });
    }

    #[test]
    fn test_drive_adopts_ready_verdict_without_fallback() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            for verdict in [true, false] {
                let digest = Sha256::hash(&[b"block"]);
                let (task_tx, task_rx) = oneshot::channel();
                let (tx, rx) = oneshot::channel();
                task_tx.send_lossy(GateOutcome::Ready(verdict));
                drive(tx, task_rx, round(1), digest, no_fallback).await;
                assert_eq!(rx.await.expect("verdict published"), verdict);
            }
        });
    }

    #[test]
    fn test_drive_recover_publishes_fallback_verdict() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            let digest = Sha256::hash(&[b"block"]);
            let (task_tx, task_rx) = oneshot::channel();
            let (tx, rx) = oneshot::channel();
            task_tx.send_lossy(GateOutcome::Recover);
            let (fallback_tx, fallback_rx) = oneshot::channel();
            fallback_tx.send_lossy(true);
            drive(tx, task_rx, round(1), digest, || fallback_rx).await;
            assert!(rx.await.expect("fallback verdict published"));
        });
    }

    #[test]
    fn test_drive_dropped_sender_publishes_fallback_verdict() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            let digest = Sha256::hash(&[b"block"]);
            let (task_tx, task_rx) = oneshot::channel();
            let (tx, rx) = oneshot::channel();
            drop(task_tx);
            let (fallback_tx, fallback_rx) = oneshot::channel();
            fallback_tx.send_lossy(false);
            drive(tx, task_rx, round(1), digest, || fallback_rx).await;
            assert!(!rx.await.expect("fallback verdict published"));
        });
    }

    #[test]
    fn test_drive_abandons_when_consensus_receiver_dropped() {
        let runner = deterministic::Runner::default();
        runner.start(|_| async move {
            let digest = Sha256::hash(&[b"block"]);
            let (_task_tx, task_rx) = oneshot::channel();
            let (tx, rx) = oneshot::channel();
            drop(rx);
            drive(tx, task_rx, round(1), digest, no_fallback).await;
        });
    }

    #[test]
    fn test_stage_handshake() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let gates = TestGates::new();
            let digest = Sha256::hash(&[b"block"]);
            let (tx, rx) = oneshot::channel();

            context.spawn({
                let gates = gates.clone();
                move |_| async move {
                    gates
                        .stage(
                            round(1),
                            digest,
                            Arc::new(7),
                            |id| {
                                tx.send_lossy(id);
                            },
                            "test",
                        )
                        .await;
                }
            });

            // The id is published only after the gate and staged block are registered.
            assert_eq!(rx.await.expect("id published"), digest);
            let gate = gates.take(round(1), digest).expect("gate registered");
            let Staged { block, ack, sent } =
                gates.take_staged(round(1), digest).expect("block staged");
            assert_eq!(*block, 7);
            assert!(!sent, "a staged block starts unsent");
            assert!(
                gates.take_staged(round(1), digest).is_none(),
                "taking twice should yield None"
            );

            // Delivering a durable handle resolves the gate.
            ack.send_lossy(Handle::ready(Ok(())));
            assert_eq!(gate.await.expect("gate resolved"), GateOutcome::Ready(true));
        });
    }

    /// Certification claims a gate together with the staged proposal it waits on. Staging the
    /// same block again while the claimed proposal is persisted must not leave the claimed gate
    /// waiting on the later stage's ack, which nothing persists.
    #[test]
    fn test_claim_takes_gate_with_staged_proposal() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let gates = TestGates::new();
            let digest = Sha256::hash(&[b"block"]);
            let (tx, rx) = oneshot::channel();
            let stage = context.child("stage").spawn({
                let gates = gates.clone();
                move |_| async move {
                    gates
                        .stage(
                            round(1),
                            digest,
                            Arc::new(7),
                            |id| {
                                tx.send_lossy(id);
                            },
                            "test",
                        )
                        .await;
                }
            });
            assert_eq!(rx.await.expect("id published"), digest);

            // The second stage registers while the claimed proposal is persisted and then
            // stays pending, so only the first stage can resolve a gate.
            let mut restage = Box::pin(gates.stage(round(1), digest, Arc::new(7), |_| {}, "test"));
            let gate = gates
                .claim(round(1), digest, |block, ack| {
                    assert_eq!(*block, 7);
                    assert!((&mut restage).now_or_never().is_none());
                    ack.send_lossy(Handle::ready(Ok(())));
                })
                .expect("gate registered");

            // The first stage finishes once its proposal is durable, so the claimed gate must
            // already hold its outcome.
            stage.await.expect("first stage completes");
            assert_eq!(
                gate.now_or_never()
                    .map(|outcome| outcome.expect("gate resolved")),
                Some(GateOutcome::Ready(true)),
                "the claimed gate must belong to the persisted proposal",
            );
        });
    }

    /// Sending a staged block keeps it staged and marks it sent. Staging the same block for the
    /// same round again, as when a re-proposed epoch boundary block is proposed again after its
    /// handoff parent is replaced, keeps that mark, so the lock-in broadcast does not send the
    /// block a second time and a repeated prepare relay does not send it either.
    #[test]
    fn test_send_staged_marks_sent_and_keeps_entry() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let gates = TestGates::new();
            let digest = Sha256::hash(&[b"block"]);
            for send in [true, false] {
                let (tx, rx) = oneshot::channel();
                context.child("stage").spawn({
                    let gates = gates.clone();
                    move |_| async move {
                        gates
                            .stage(
                                round(1),
                                digest,
                                Arc::new(7),
                                |id| {
                                    tx.send_lossy(id);
                                },
                                "test",
                            )
                            .await;
                    }
                });
                assert_eq!(rx.await.expect("id published"), digest);
                if send {
                    assert!(
                        gates
                            .send_staged(round(1), Sha256::hash(&[b"other"]))
                            .is_none()
                    );
                    let block = gates.send_staged(round(1), digest).expect("block staged");
                    assert_eq!(*block, 7);
                }
            }

            // A sent block is not handed out for another send.
            assert!(
                gates.send_staged(round(1), digest).is_none(),
                "a sent block must not be sent again"
            );

            // The entry survives the send and the second staging, so the lock-in
            // broadcast only persists it.
            let Staged { sent, .. } = gates.take_staged(round(1), digest).expect("still staged");
            assert!(sent, "a sent block must stay marked sent when staged again");
        });
    }

    #[test]
    fn test_retain_after_drops_staged_and_abandons_handshake() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let gates = TestGates::new();
            let digest = Sha256::hash(&[b"block"]);
            let (tx, rx) = oneshot::channel();

            context.spawn({
                let gates = gates.clone();
                move |_| async move {
                    gates
                        .stage(
                            round(1),
                            digest,
                            Arc::new(7),
                            |id| {
                                tx.send_lossy(id);
                            },
                            "test",
                        )
                        .await;
                }
            });
            assert_eq!(rx.await.expect("id published"), digest);

            // Pruning drops the staged ack, leaving the gate unresolved.
            let gate = gates.take(round(1), digest).expect("gate registered");
            gates.retain_after(&round(1));
            assert!(gates.take_staged(round(1), digest).is_none());
            assert!(gate.await.is_err(), "gate must be abandoned, not resolved");
        });
    }
}
