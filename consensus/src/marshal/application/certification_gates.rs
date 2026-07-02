use crate::{marshal::core::durability::await_durable, types::Round};
use commonware_macros::select;
use commonware_runtime::Handle;
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use std::{collections::HashMap, fmt::Debug, future::Future, hash::Hash, sync::Arc};
use tracing::debug;

type CertificationGateMap<D> = HashMap<(Round, D), oneshot::Receiver<bool>>;

/// A shared, thread-safe registry of in-flight certification gate tasks.
///
/// Each task is keyed by `(Round, D)` where `D` is a commitment or digest
/// identifying the block. The associated [`oneshot::Receiver<bool>`] is
/// consumed by certification and resolves to `true` only when that path may cast
/// a finalize vote: local proposal durability has completed, or verification
/// accepted the block and completed the required durable store. A resolved
/// `false` records a live local rejection. A dropped sender means the task did
/// not complete, so certification may fall back to its recovery fetch path.
/// Storage sync failures are fatal to the local marshal state and must panic
/// before resolving the task.
///
/// Tasks are inserted when a block enters proposal or verification handling and
/// taken (consumed) when certification is ready to act on the result. Stale
/// entries are pruned after finalization via [`retain_after`](Self::retain_after).
#[derive(Clone)]
pub(crate) struct CertificationGates<D>
where
    D: Eq + Hash,
{
    inner: Arc<Mutex<CertificationGateMap<D>>>,
}

impl<D> Default for CertificationGates<D>
where
    D: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<D> CertificationGates<D>
where
    D: Eq + Hash,
{
    /// Creates an empty task registry.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Registers a certification gate task for the block identified by `(round, digest)`.
    pub(crate) fn insert(&self, round: Round, digest: D, task: oneshot::Receiver<bool>) {
        self.inner.lock().insert((round, digest), task);
    }

    /// Removes and returns the certification gate task for `(round, digest)`, if present.
    pub(crate) fn take(&self, round: Round, digest: D) -> Option<oneshot::Receiver<bool>> {
        self.inner.lock().remove(&(round, digest))
    }

    /// Discards all tasks whose round is at or before `finalized_round`.
    pub(crate) fn retain_after(&self, finalized_round: &Round) {
        self.inner
            .lock()
            .retain(|(task_round, _), _| task_round > finalized_round);
    }
}

impl<D> CertificationGates<D>
where
    D: Eq + Hash + Copy,
{
    /// Completes the propose durability handshake for `(round, id)`.
    ///
    /// Registers a certification gate, publishes `id` to consensus on `tx`, then awaits the
    /// started block sync so [`certify`](crate::CertifiableAutomaton::certify) can require
    /// durability before the finalize vote. The gate is registered before `id` is published so
    /// `certify` always finds it.
    ///
    /// `persist` is the sync-handle receiver returned by `marshal.proposed`/`verified_deferred`,
    /// already enqueued by the caller so a later `forward` is ordered after it. A real sync failure
    /// panics here (the fatal policy, annotated with `name`); a dropped receiver or a runtime
    /// shutdown means the marshal actor is gone, so the gate is left unresolved and `certify`
    /// falls back to its recovery fetch.
    pub(crate) async fn persist_and_defer(
        &self,
        round: Round,
        id: D,
        tx: oneshot::Sender<D>,
        persist: oneshot::Receiver<Handle<()>>,
        name: &'static str,
    ) where
        D: Debug,
    {
        let (durable_tx, durable_rx) = oneshot::channel();
        self.insert(round, id, durable_rx);
        let _ = tx.send_lossy(id);
        let Ok(handle) = persist.await else {
            return;
        };
        if !await_durable(handle, name).await {
            return;
        }
        durable_tx.send_lossy(true);
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
pub(crate) const fn gate_verdict(verdict: Option<bool>, durable: bool) -> Option<bool> {
    match verdict {
        Some(true) if !durable => None,
        other => other,
    }
}

/// Drives a certification gate `task` to a certify verdict, recovering through `fallback` after an
/// unclean restart.
///
/// A resolved verdict is published on `tx`. A dropped sender (the in-memory task is gone after
/// restart) triggers `fallback`, whose receiver is awaited and published instead. A
/// consensus-dropped receiver (`tx.closed()`) abandons the work.
pub(crate) async fn drive_certify_gate<D, F, Fut>(
    mut tx: oneshot::Sender<bool>,
    task: oneshot::Receiver<bool>,
    round: Round,
    id: D,
    fallback: F,
) where
    D: Debug,
    F: FnOnce() -> Fut,
    Fut: Future<Output = oneshot::Receiver<bool>>,
{
    let result = select! {
        _ = tx.closed() => {
            debug!(reason = "consensus dropped receiver", "skipping certification");
            return;
        },
        result = task => result,
    };
    match result {
        Ok(result) => {
            tx.send_lossy(result);
        }
        Err(_) => {
            debug!(
                ?round,
                ?id,
                "certification gate task closed before certification, falling back to embedded context"
            );
            let fallback = fallback().await;
            let result = select! {
                _ = tx.closed() => {
                    debug!(reason = "consensus dropped receiver", "skipping certification");
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
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Hasher, Sha256};

    type D = Sha256Digest;

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn pending_task() -> oneshot::Receiver<bool> {
        let (_tx, rx) = oneshot::channel();
        rx
    }

    #[test]
    fn test_insert_and_take_returns_task() {
        let tasks = CertificationGates::<D>::new();
        let digest = Sha256::hash(b"block");
        tasks.insert(round(1), digest, pending_task());

        assert!(tasks.take(round(1), digest).is_some());
        assert!(
            tasks.take(round(1), digest).is_none(),
            "taking twice should yield None"
        );
    }

    #[test]
    fn test_take_absent_key_is_none() {
        let tasks = CertificationGates::<D>::new();
        assert!(tasks.take(round(1), Sha256::hash(b"missing")).is_none());
    }

    #[test]
    fn test_take_distinguishes_rounds_and_digests() {
        let tasks = CertificationGates::<D>::new();
        let digest_a = Sha256::hash(b"a");
        let digest_b = Sha256::hash(b"b");
        tasks.insert(round(1), digest_a, pending_task());
        tasks.insert(round(2), digest_a, pending_task());
        tasks.insert(round(1), digest_b, pending_task());

        assert!(tasks.take(round(1), digest_a).is_some());
        assert!(tasks.take(round(2), digest_a).is_some());
        assert!(tasks.take(round(1), digest_b).is_some());
    }

    #[test]
    fn test_retain_after_drops_at_and_below_boundary() {
        let tasks = CertificationGates::<D>::new();
        let digest = Sha256::hash(b"block");
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
        let tasks = CertificationGates::<D>::new();
        let digest = Sha256::hash(b"block");
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
        let tasks = CertificationGates::<D>::new();
        tasks.retain_after(&round(5));
        assert!(tasks.take(round(5), Sha256::hash(b"x")).is_none());
    }

    #[test]
    fn test_default_matches_new() {
        let default = <CertificationGates<D> as Default>::default();
        let digest = Sha256::hash(b"block");
        default.insert(round(1), digest, pending_task());
        assert!(default.take(round(1), digest).is_some());
    }

    #[test]
    fn test_gate_verdict() {
        // Verification stopped early: nothing to publish regardless of durability.
        assert_eq!(gate_verdict(None, true), None);
        assert_eq!(gate_verdict(None, false), None);
        // A false app verdict is a live rejection that needs no durability.
        assert_eq!(gate_verdict(Some(false), false), Some(false));
        assert_eq!(gate_verdict(Some(false), true), Some(false));
        // A true verdict publishes only once the store is durable.
        assert_eq!(gate_verdict(Some(true), true), Some(true));
        assert_eq!(gate_verdict(Some(true), false), None);
    }
}
