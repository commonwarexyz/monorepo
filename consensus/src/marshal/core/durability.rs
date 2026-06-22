//! Helpers for overlapping durable syncs with consensus progress.
//!
//! A marshal write starts its fsync eagerly: the archive spawns the sync and
//! returns a [`Handle`] that only *observes* completion. [`SharedSync`] is the
//! generic piece: a policy-free fan-out that lets a single started [`Handle`] be
//! awaited by many parties. [`SyncRegistry`] indexes those shared syncs by round
//! (tagged with the block digest) for reuse and pruning. [`observe_sync`] is the
//! marshal *policy* applied to a sync's result: a failure is fatal, so it panics
//! rather than yielding a recoverable error.

use crate::types::Round;
use commonware_runtime::Handle;
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use std::{
    collections::{btree_map, BTreeMap},
    future::Future,
    sync::Arc,
};
use tracing::debug;

/// Result of a durable sync.
pub(crate) type SyncResult = Result<(), commonware_runtime::Error>;

/// Logs a successful sync and panics on failure.
///
/// Sync failures are fatal to local storage state and must never be turned into a
/// recoverable verdict, so they panic rather than return. This is the policy
/// applied to a [`SharedSync`] driver's result and to inline sync awaits.
pub(crate) fn observe_sync(result: SyncResult, round: Round, name: &str) {
    match result {
        Ok(()) => debug!(?round, name, "cached"),
        Err(e) => panic!("failed to sync {name}: {e}"),
    }
}

/// Completion state shared between the driver future and every awaiter.
struct State {
    /// Set once the sync completes successfully; later awaiters then resolve immediately.
    durable: bool,
    /// Awaiters signaled when the sync completes.
    waiters: Vec<oneshot::Sender<SyncResult>>,
}

/// A started durable sync whose completion can be awaited by many parties.
///
/// This is a policy-free fan-out over a single [`Handle`]. [`SharedSync::observe`]
/// returns the shared handle together with a driver future the caller must run to
/// completion (by pushing it into a pool or spawning it). The driver awaits the
/// underlying [`Handle`] and yields its [`SyncResult`] to that single owner, while
/// [`SharedSync::wait`] hands out [`Handle`]s that resolve once the sync is
/// durable (callable any number of times). The owner decides what a failure
/// means; in marshal that is [`observe_sync`] (a fatal panic). Cloning is cheap
/// (it shares completion state).
#[derive(Clone)]
pub(crate) struct SharedSync {
    state: Arc<Mutex<State>>,
}

impl SharedSync {
    /// Builds a shared sync over a freshly started `sync`, returning the shared
    /// handle plus the driver future that observes it.
    ///
    /// The caller must run the returned future to completion (push it into a pool
    /// or spawn it); it yields the sync's [`SyncResult`] to that single owner. On
    /// success every awaiter is signaled; on failure the error is handed only to
    /// the driver's owner (it is never cloned across awaiters), and pending
    /// awaiters resolve as closed.
    pub(crate) fn observe(sync: Handle<()>) -> (Self, impl Future<Output = SyncResult>) {
        let state = Arc::new(Mutex::new(State {
            durable: false,
            waiters: Vec::new(),
        }));
        let shared = state.clone();
        let drive = async move {
            let result = sync.await;
            let waiters = {
                let mut shared = shared.lock();
                shared.durable = result.is_ok();
                std::mem::take(&mut shared.waiters)
            };
            if result.is_ok() {
                for waiter in waiters {
                    waiter.send_lossy(Ok(()));
                }
            }
            // On failure, `waiters` drop here and their receivers observe closure.
            result
        };
        (Self { state }, drive)
    }

    /// A handle that resolves once the sync is durable.
    pub(crate) fn wait(&self) -> Handle<()> {
        let mut state = self.state.lock();
        if state.durable {
            return Handle::ready(Ok(()));
        }
        let (waiter, receiver) = oneshot::channel();
        state.waiters.push(waiter);
        Handle::from_receiver(receiver)
    }
}

/// A registry of in-flight durable syncs, keyed by round and tagged with the
/// block digest each one covers.
///
/// Entries below the prune floor are dropped and never re-admitted, mirroring the
/// view-indexed caches these syncs shadow. The marshal actor holds two: one for
/// verified-block syncs (reused by the matching notarized/certified write) and
/// one for notarization-certificate syncs (joined into the certify barrier).
pub(crate) struct SyncRegistry<D> {
    floor: Round,
    syncs: BTreeMap<Round, (D, SharedSync)>,
}

impl<D: Copy + PartialEq> SyncRegistry<D> {
    pub(crate) const fn new() -> Self {
        Self {
            floor: Round::zero(),
            syncs: BTreeMap::new(),
        }
    }

    /// The digest registered at `round`, if any.
    pub(crate) fn digest(&self, round: Round) -> Option<D> {
        self.syncs.get(&round).map(|(digest, _)| *digest)
    }

    /// Whether a sync is registered for `(round, digest)`.
    pub(crate) fn covers(&self, round: Round, digest: D) -> bool {
        self.syncs
            .get(&round)
            .is_some_and(|(tracked, _)| *tracked == digest)
    }

    /// A handle that resolves once the sync registered for `(round, digest)` is
    /// durable, if one is registered for that digest.
    pub(crate) fn wait(&self, round: Round, digest: D) -> Option<Handle<()>> {
        self.syncs
            .get(&round)
            .filter(|(tracked, _)| *tracked == digest)
            .map(|(_, sync)| sync.wait())
    }

    /// Registers `sync` under `(round, digest)`.
    ///
    /// A no-op when the round is below the prune floor, or when the round is
    /// already occupied (an equivocation keeps the first sync). The caller's
    /// driver observes the sync to completion regardless of whether it is tracked.
    pub(crate) fn register(&mut self, round: Round, digest: D, sync: SharedSync) {
        if round < self.floor {
            return;
        }
        if let btree_map::Entry::Vacant(entry) = self.syncs.entry(round) {
            entry.insert((digest, sync));
        }
    }

    /// Removes and returns the entry registered at `round`.
    pub(crate) fn take(&mut self, round: Round) -> Option<(D, SharedSync)> {
        self.syncs.remove(&round)
    }

    /// Raises the prune floor to `round`, dropping every entry below it.
    pub(crate) fn prune(&mut self, round: Round) {
        if round > self.floor {
            self.floor = round;
        }
        self.syncs = self.syncs.split_off(&self.floor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Epoch, View};
    use commonware_cryptography::{sha256::Digest as Sha256Digest, Hasher, Sha256};
    use commonware_runtime::{deterministic, Runner as _, Spawner as _};

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn digest(seed: &[u8]) -> Sha256Digest {
        Sha256::hash(seed)
    }

    /// A `SharedSync` whose driver is intentionally not run; the registry tests
    /// exercise only the map semantics, never a sync's completion.
    fn pending_sync() -> SharedSync {
        SharedSync::observe(Handle::ready(Ok(()))).0
    }

    #[test]
    fn test_shared_sync_fans_out_to_all_waiters() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (shared, drive) = SharedSync::observe(Handle::ready(Ok(())));
            context.spawn(move |_| async move {
                let _ = drive.await;
            });

            // Two awaiters registered before completion both resolve.
            let a = shared.wait();
            let b = shared.wait();
            a.await.expect("first waiter");
            b.await.expect("second waiter");

            // An awaiter registered after completion resolves immediately.
            shared.wait().await.expect("late waiter");

            // A clone shares the same completed state.
            shared.clone().wait().await.expect("cloned waiter");
        });
    }

    #[test]
    #[should_panic(expected = "failed to sync test")]
    fn test_observe_sync_panics_on_failure() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let (shared, drive) =
                SharedSync::observe(Handle::ready(Err(commonware_runtime::Error::Closed)));
            // The driver yields the failure to its owner, which applies the fatal
            // policy via `observe_sync`.
            context.spawn(move |_| async move { observe_sync(drive.await, round(1), "test") });
            let _ = shared.wait().await;
        });
    }

    #[test]
    fn test_registry_lookup_by_round_and_digest() {
        let mut registry = SyncRegistry::<Sha256Digest>::new();
        let a = digest(b"a");
        registry.register(round(1), a, pending_sync());

        assert_eq!(registry.digest(round(1)), Some(a));
        assert!(registry.covers(round(1), a));
        assert!(registry.wait(round(1), a).is_some());

        // A different digest at the same round does not match.
        assert!(!registry.covers(round(1), digest(b"b")));
        assert!(registry.wait(round(1), digest(b"b")).is_none());

        // An unregistered round is absent.
        assert_eq!(registry.digest(round(2)), None);
        assert!(!registry.covers(round(2), a));
    }

    #[test]
    fn test_registry_keeps_first_sync_on_equivocation() {
        let mut registry = SyncRegistry::<Sha256Digest>::new();
        let (a, b) = (digest(b"a"), digest(b"b"));
        registry.register(round(1), a, pending_sync());
        registry.register(round(1), b, pending_sync());

        assert_eq!(registry.digest(round(1)), Some(a), "first sync is kept");
        assert!(!registry.covers(round(1), b));
    }

    #[test]
    fn test_registry_does_not_admit_below_floor() {
        let mut registry = SyncRegistry::<Sha256Digest>::new();
        registry.prune(round(5));

        registry.register(round(4), digest(b"a"), pending_sync());
        assert_eq!(registry.digest(round(4)), None, "below floor is rejected");

        registry.register(round(5), digest(b"b"), pending_sync());
        assert!(
            registry.covers(round(5), digest(b"b")),
            "at floor is admitted"
        );
    }

    #[test]
    fn test_registry_take_removes_entry() {
        let mut registry = SyncRegistry::<Sha256Digest>::new();
        let a = digest(b"a");
        registry.register(round(1), a, pending_sync());

        let taken = registry.take(round(1)).expect("entry present");
        assert_eq!(taken.0, a);
        assert!(
            registry.take(round(1)).is_none(),
            "taking twice yields None"
        );
        assert_eq!(registry.digest(round(1)), None);
    }

    #[test]
    fn test_registry_prune_drops_below_floor() {
        let mut registry = SyncRegistry::<Sha256Digest>::new();
        registry.register(round(1), digest(b"a"), pending_sync());
        registry.register(round(2), digest(b"b"), pending_sync());
        registry.register(round(3), digest(b"c"), pending_sync());

        registry.prune(round(2));

        assert_eq!(registry.digest(round(1)), None, "below floor dropped");
        assert!(registry.covers(round(2), digest(b"b")), "at floor retained");
        assert!(
            registry.covers(round(3), digest(b"c")),
            "above floor retained"
        );
    }
}
