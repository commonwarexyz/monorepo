use crate::types::Round;
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use std::{collections::HashMap, hash::Hash, sync::Arc};

type VerificationTaskMap<D> = HashMap<(Round, D), oneshot::Receiver<bool>>;

/// A shared, thread-safe registry of local verification receivers.
///
/// Each `(Round, D)` entry stores the receiver that `certify()` should await.
/// The receiver may still be pending, or it may already be resolved if local
/// verification completed before certification asked for the result.
///
/// Stale entries are pruned after finalization via [`retain_after`](Self::retain_after).
#[derive(Clone)]
pub(crate) struct VerificationTasks<D>
where
    D: Eq + Hash,
{
    inner: Arc<Mutex<VerificationTaskMap<D>>>,
}

impl<D> Default for VerificationTasks<D>
where
    D: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<D> VerificationTasks<D>
where
    D: Eq + Hash,
{
    /// Creates an empty task registry.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Registers a verification receiver for `(round, digest)`.
    pub(crate) fn insert(&self, round: Round, digest: D, task: oneshot::Receiver<bool>) {
        self.inner.lock().insert((round, digest), task);
    }

    /// Registers an already-completed verification result for `(round, digest)`.
    pub(crate) fn insert_resolved(&self, round: Round, digest: D, result: bool) {
        let (tx, rx) = oneshot::channel();
        tx.send_lossy(result);
        self.insert(round, digest, rx);
    }

    /// Removes and returns the verification receiver for `(round, digest)`, if present.
    pub(crate) fn take(&self, round: Round, digest: D) -> Option<oneshot::Receiver<bool>> {
        self.inner.lock().remove(&(round, digest))
    }

    /// Discards all state whose round is at or before `finalized_round`.
    pub(crate) fn retain_after(&self, finalized_round: &Round) {
        self.inner
            .lock()
            .retain(|(task_round, _), _| task_round > finalized_round);
    }
}
