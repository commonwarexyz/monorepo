use crate::types::Round;
use commonware_utils::{channel::oneshot, sync::Mutex};
use std::{collections::HashMap, hash::Hash, sync::Arc};

type VerificationTaskMap<D> = HashMap<(Round, D), oneshot::Receiver<bool>>;

/// A shared, thread-safe registry of in-flight block verification tasks.
///
/// Each task is keyed by `(Round, D)` where `D` is a commitment or digest
/// identifying the block under verification. The associated
/// [`oneshot::Receiver<bool>`] resolves to `true` when the block passes
/// deferred verification, or `false` otherwise.
///
/// Tasks are inserted when a block enters the verification pipeline and
/// taken (consumed) when the marshal is ready to act on the result. Stale
/// entries are pruned after finalization via [`retain_after`](Self::retain_after).
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

    /// Registers a verification task for the block identified by `(round, digest)`.
    pub(crate) fn insert(&self, round: Round, digest: D, task: oneshot::Receiver<bool>) {
        self.inner.lock().insert((round, digest), task);
    }

    /// Removes and returns the verification task for `(round, digest)`, if present.
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
