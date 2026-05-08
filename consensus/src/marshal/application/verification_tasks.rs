use crate::types::Round;
use commonware_utils::{channel::oneshot, sync::Mutex};
use futures::FutureExt;
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

    /// Removes and returns a completed verification result for `(round, digest)`, if present.
    ///
    /// Pending or closed tasks are discarded and reported as absent.
    pub(crate) fn take_ready(&self, round: Round, digest: D) -> Option<bool> {
        self.inner
            .lock()
            .remove(&(round, digest))?
            .now_or_never()?
            .ok()
    }

    /// Discards all tasks whose round is at or before `finalized_round`.
    pub(crate) fn retain_after(&self, finalized_round: &Round) {
        self.inner
            .lock()
            .retain(|(task_round, _), _| task_round > finalized_round);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Epoch, View};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Hasher, Sha256};
    use commonware_utils::channel::fallible::OneshotExt;

    type D = Sha256Digest;

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn pending_task() -> oneshot::Receiver<bool> {
        let (_tx, rx) = oneshot::channel();
        rx
    }

    fn ready_task(value: bool) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        tx.send_lossy(value);
        rx
    }

    #[test]
    fn test_insert_and_take_ready_returns_task() {
        let tasks = VerificationTasks::<D>::new();
        let digest = Sha256::hash(b"block");
        tasks.insert(round(1), digest, ready_task(true));

        assert_eq!(tasks.take_ready(round(1), digest), Some(true));
        assert!(
            tasks.take_ready(round(1), digest).is_none(),
            "taking a ready task twice should yield None"
        );
    }

    #[test]
    fn test_take_absent_key_is_none() {
        let tasks = VerificationTasks::<D>::new();
        assert!(tasks
            .take_ready(round(1), Sha256::hash(b"missing"))
            .is_none());
    }

    #[test]
    fn test_take_ready_discards_pending_task() {
        let tasks = VerificationTasks::<D>::new();
        let digest = Sha256::hash(b"block");
        tasks.insert(round(1), digest, pending_task());

        assert_eq!(tasks.take_ready(round(1), digest), None);
        assert!(
            tasks.take_ready(round(1), digest).is_none(),
            "pending task should be discarded"
        );
    }

    #[test]
    fn test_take_distinguishes_rounds_and_digests() {
        let tasks = VerificationTasks::<D>::new();
        let digest_a = Sha256::hash(b"a");
        let digest_b = Sha256::hash(b"b");
        tasks.insert(round(1), digest_a, ready_task(true));
        tasks.insert(round(2), digest_a, ready_task(false));
        tasks.insert(round(1), digest_b, ready_task(true));

        assert_eq!(tasks.take_ready(round(1), digest_a), Some(true));
        assert_eq!(tasks.take_ready(round(2), digest_a), Some(false));
        assert_eq!(tasks.take_ready(round(1), digest_b), Some(true));
    }

    #[test]
    fn test_retain_after_drops_at_and_below_boundary() {
        let tasks = VerificationTasks::<D>::new();
        let digest = Sha256::hash(b"block");
        tasks.insert(round(1), digest, ready_task(true));
        tasks.insert(round(2), digest, ready_task(true));
        tasks.insert(round(3), digest, ready_task(true));

        tasks.retain_after(&round(2));

        assert!(
            tasks.take_ready(round(1), digest).is_none(),
            "tasks strictly below boundary should be dropped"
        );
        assert!(
            tasks.take_ready(round(2), digest).is_none(),
            "tasks at boundary should be dropped"
        );
        assert_eq!(tasks.take_ready(round(3), digest), Some(true));
    }

    #[test]
    fn test_retain_after_spans_epochs() {
        let tasks = VerificationTasks::<D>::new();
        let digest = Sha256::hash(b"block");
        let early = Round::new(Epoch::zero(), View::new(100));
        let late = Round::new(Epoch::new(1), View::zero());
        tasks.insert(early, digest, ready_task(true));
        tasks.insert(late, digest, ready_task(true));

        tasks.retain_after(&early);

        assert!(
            tasks.take_ready(early, digest).is_none(),
            "task at boundary must be dropped"
        );
        assert_eq!(tasks.take_ready(late, digest), Some(true));
    }

    #[test]
    fn test_retain_after_empty_map_is_noop() {
        let tasks = VerificationTasks::<D>::new();
        tasks.retain_after(&round(5));
        assert!(tasks.take_ready(round(5), Sha256::hash(b"x")).is_none());
    }

    #[test]
    fn test_default_matches_new() {
        let default = <VerificationTasks<D> as Default>::default();
        let digest = Sha256::hash(b"block");
        default.insert(round(1), digest, ready_task(true));
        assert_eq!(default.take_ready(round(1), digest), Some(true));
    }
}
