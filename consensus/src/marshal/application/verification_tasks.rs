use crate::types::Round;
use commonware_utils::{
    channel::oneshot,
    sync::Mutex,
};
use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
    sync::Arc,
};

type VerificationTaskMap<D> = HashMap<(Round, D), oneshot::Receiver<bool>>;
type VerificationOutcomeMap<D> = BTreeMap<Round, HashMap<D, bool>>;

/// A shared, thread-safe registry of local verification state.
///
/// For each `(Round, D)` key, the registry may hold:
/// - an in-flight verification task
/// - a completed local verification outcome
///
/// Stale entries are pruned after finalization via [`retain_after`](Self::retain_after).
#[derive(Clone)]
pub(crate) struct VerificationTasks<D>
where
    D: Clone + Eq + Hash,
{
    inner: Arc<Mutex<Inner<D>>>,
}

struct Inner<D>
where
    D: Clone + Eq + Hash,
{
    tasks: VerificationTaskMap<D>,
    outcomes: VerificationOutcomeMap<D>,
}

impl<D> Default for VerificationTasks<D>
where
    D: Clone + Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<D> VerificationTasks<D>
where
    D: Clone + Eq + Hash,
{
    /// Creates an empty task registry.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                tasks: HashMap::new(),
                outcomes: BTreeMap::new(),
            })),
        }
    }

    /// Registers a verification task for the block identified by `(round, digest)`.
    pub(crate) fn insert(&self, round: Round, digest: D, task: oneshot::Receiver<bool>) {
        self.inner.lock().tasks.insert((round, digest), task);
    }

    /// Removes and returns the verification task for `(round, digest)`, if present.
    pub(crate) fn take(&self, round: Round, digest: D) -> Option<oneshot::Receiver<bool>> {
        self.inner.lock().tasks.remove(&(round, digest))
    }

    /// Returns the completed local verification outcome for `(round, digest)`, if present.
    pub(crate) fn outcome(&self, round: Round, digest: &D) -> Option<bool> {
        self.inner
            .lock()
            .outcomes
            .get(&round)
            .and_then(|outcomes| outcomes.get(digest).copied())
    }

    /// Records the completed local verification outcome for `(round, digest)`.
    pub(crate) fn finish(&self, round: Round, digest: D, result: bool) {
        let mut inner = self.inner.lock();
        inner.tasks.remove(&(round, digest.clone()));
        inner
            .outcomes
            .entry(round)
            .or_default()
            .insert(digest.clone(), result);
    }

    /// Discards all state whose round is at or before `finalized_round`.
    pub(crate) fn retain_after(&self, finalized_round: &Round) {
        let mut inner = self.inner.lock();
        inner
            .tasks
            .retain(|(task_round, _), _| task_round > finalized_round);
        inner
            .outcomes
            .retain(|outcome_round, _| outcome_round > finalized_round);
    }
}
