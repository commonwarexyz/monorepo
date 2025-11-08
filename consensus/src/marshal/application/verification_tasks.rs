use crate::types::Round;
use commonware_utils::{channel::oneshot, sync::Mutex};
use std::{collections::HashMap, hash::Hash, sync::Arc};

type VerificationTaskMap<D> = HashMap<(Round, D), oneshot::Receiver<bool>>;

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
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn insert(&self, round: Round, digest: D, task: oneshot::Receiver<bool>) {
        self.inner.lock().insert((round, digest), task);
    }

    pub(crate) fn take(&self, round: Round, digest: D) -> Option<oneshot::Receiver<bool>> {
        self.inner.lock().remove(&(round, digest))
    }

    pub(crate) fn retain_after(&self, finalized_round: &Round) {
        self.inner
            .lock()
            .retain(|(task_round, _), _| task_round > finalized_round);
    }
}
