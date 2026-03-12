//! Startup state sync orchestration for [`Stateful`](super::Stateful).
//!
//! When a validator joins a running network, its databases are empty and
//! must be populated before it can propose or verify blocks. The
//! [`Coordinator`] gates consensus participation until the sync engine
//! signals completion.
//!
//! # Lifecycle
//!
//! ```text
//! Waiting ──update_targets()──> Running ──completion──> Ready
//!    │                            │                       ^
//!    └────────mark_ready()────────┴────failure───────────┘
//! ```
//!
//! All validators start in `Waiting`. Two paths lead to `Ready`:
//!
//! - **Genesis (epoch 0, building on height 0)**: the wrapper detects
//!   this in `propose`/`verify` and calls [`Coordinator::mark_ready`].
//!   No sync engine is started.
//! - **Catching up**: finalization reports drive sync target updates via
//!   [`Coordinator::update_targets`]. The first call launches the sync
//!   engine (`Waiting -> Running`). Subsequent calls forward targets
//!   via best-effort `try_send`. When the sync engine signals
//!   completion, the coordinator transitions to `Ready`.

use super::db::{SyncHandle, SyncableDatabaseSet};
use commonware_runtime::{
    signal::{Signal, Signaler},
    Clock, Metrics, Spawner,
};
use commonware_utils::{
    channel::{mpsc, oneshot},
    sync::Mutex,
};
use rand::Rng;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// Configuration for starting a database sync engine.
#[derive(Clone)]
pub struct Config<D: SyncableDatabaseSet> {
    /// Per-database sync engine configuration.
    pub sync_configs: D::SyncConfigs,
    /// Per-database resolver instances for fetching state from peers.
    pub sync_resolvers: D::SyncResolvers,
}

/// One-shot readiness gate shared by all [`Stateful`](super::Stateful)
/// clones.
///
/// Uses an [`AtomicBool`] for the fast path (checked on every
/// `propose`/`verify` call) and a [`Signal`] for async waiters that
/// arrive before readiness. Once marked ready, the gate is permanent.
#[derive(Clone)]
struct Gate {
    /// Fast-path check: `true` once sync is complete.
    ready: Arc<AtomicBool>,
    /// Async waiter for `verify` calls that arrive before readiness.
    signal: Signal,
    /// Consumed once when transitioning to ready.
    signaler: Arc<Mutex<Option<Signaler>>>,
}

impl Gate {
    /// Create a new gate in the not-ready state.
    fn new() -> Self {
        let (signaler, signal) = Signaler::new();
        Self {
            ready: Arc::new(AtomicBool::new(false)),
            signal,
            signaler: Arc::new(Mutex::new(Some(signaler))),
        }
    }

    /// Returns `true` if sync has completed.
    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Pends until sync completes. Returns immediately if already ready.
    async fn wait_until_ready(&self) {
        if self.is_ready() {
            return;
        }
        let mut signal = self.signal.clone();
        let _ = (&mut signal).await;
    }

    /// Transition to ready, waking all waiters. Idempotent.
    fn mark_ready(&self) {
        if self.ready.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(signaler) = self.signaler.lock().take() {
            signaler.signal(0);
        }
    }
}

/// Internal state machine for the sync lifecycle.
enum State<D: SyncableDatabaseSet> {
    /// Sync configured but not yet started. Holds the config needed to
    /// launch the sync engine on the first
    /// [`Coordinator::update_targets`] call.
    Waiting(Config<D>),
    /// Sync engine is running. Target updates are forwarded to it.
    Running,
    /// Sync completed (or skipped for genesis). Permanent.
    Ready,
}

/// Orchestrates startup database sync for [`Stateful`](super::Stateful).
///
/// Shared (via `Clone`) across all `Stateful` clones so that
/// finalization-driven target updates from the reporter path and
/// readiness checks from the propose/verify path operate on the same
/// state.
///
/// # Thread Safety
///
/// All public methods are synchronous and lock-free on the fast path
/// (`is_ready` checks the atomic). State transitions acquire a mutex
/// but never hold it across await points.
#[derive(Clone)]
pub(crate) struct Coordinator<E, D>
where
    E: Rng + Spawner + Metrics + Clock,
    D: SyncableDatabaseSet,
{
    /// Runtime context for spawning the completion watcher task.
    context: E,
    /// Databases to sync.
    databases: D,
    /// Gate gate checked by propose/verify.
    readiness: Gate,
    /// Current lifecycle state.
    state: Arc<Mutex<State<D>>>,
    /// Sender into the running sync engine's target-update channel.
    /// `None` when not in `Running` state.
    target_sender: Arc<Mutex<Option<mpsc::Sender<D::SyncTargets>>>>,
}

impl<E, D> Coordinator<E, D>
where
    E: Rng + Spawner + Metrics + Clock,
    D: SyncableDatabaseSet,
{
    /// Create a new coordinator in the `Waiting` state.
    pub(crate) fn new(context: E, databases: D, config: Config<D>) -> Self {
        Self {
            context,
            databases,
            readiness: Gate::new(),
            state: Arc::new(Mutex::new(State::Waiting(config))),
            target_sender: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns `true` if sync has completed. Lock-free fast path.
    pub(crate) fn is_ready(&self) -> bool {
        self.readiness.is_ready()
    }

    /// Pends until sync completes. Returns immediately if already ready.
    pub(crate) async fn wait_until_ready(&self) {
        self.readiness.wait_until_ready().await;
    }

    /// Mark sync as complete without running the sync engine.
    ///
    /// Called by the wrapper when the first propose/verify is for
    /// genesis (epoch 0, parent height 0) -- there is no prior state
    /// to sync.
    pub(crate) fn mark_ready(&self) {
        self.readiness.mark_ready();
        *self.state.lock() = State::Ready;
    }

    /// Start the sync engine with the given config and initial targets.
    fn launch_sync(
        &self,
        config: &Config<D>,
        initial_targets: D::SyncTargets,
    ) -> Result<SyncHandle<D::SyncTargets, D::SyncError>, D::SyncError> {
        self.databases.start_sync(
            self.context.clone(),
            config.sync_configs.clone(),
            config.sync_resolvers.clone(),
            initial_targets,
        )
    }

    /// Spawn a task that waits for the sync engine to complete, then
    /// marks readiness and cleans up.
    fn spawn_completion_watcher(
        &self,
        config: Config<D>,
        completion: oneshot::Receiver<Result<(), D::SyncError>>,
    ) {
        let readiness = self.readiness.clone();
        let state = self.state.clone();
        let target_sender = self.target_sender.clone();

        self.context
            .clone()
            .with_label("stateful_sync_completion")
            .spawn(move |_| async move {
                match completion.await {
                    Ok(Ok(())) => {
                        readiness.mark_ready();
                        *target_sender.lock() = None;
                        *state.lock() = State::Ready;
                    }
                    Ok(Err(err)) => {
                        tracing::warn!(?err, "state sync failed");
                        *target_sender.lock() = None;
                        *state.lock() = State::Waiting(config);
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "state sync completion channel closed");
                        *target_sender.lock() = None;
                        *state.lock() = State::Waiting(config);
                    }
                }
            });
    }

    /// Forward sync targets extracted from a finalized block.
    ///
    /// - **First call** (`Waiting`): launches the sync engine with
    ///   `targets` as the initial target and transitions to `Running`.
    /// - **Subsequent calls** (`Running`): best-effort forwards via
    ///   `try_send`. If the channel is full, the target is dropped --
    ///   the next finalization will provide a newer one.
    /// - **After completion** (`Ready`): no-op.
    pub(crate) fn update_targets(&self, targets: D::SyncTargets) {
        if self.readiness.is_ready() {
            return;
        }

        let mut state = self.state.lock();
        match &*state {
            State::Ready => {}
            State::Waiting(config) => {
                let handle = match self.launch_sync(config, targets) {
                    Ok(handle) => handle,
                    Err(err) => {
                        tracing::warn!(?err, "state sync failed to start");
                        return;
                    }
                };
                let config = config.clone();
                *self.target_sender.lock() = Some(handle.target_updates);
                *state = State::Running;
                drop(state);
                self.spawn_completion_watcher(config, handle.completion);
            }
            State::Running => {
                drop(state);
                if let Some(sender) = &*self.target_sender.lock() {
                    let _ = sender.try_send(targets);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::db::DatabaseSet;
    use commonware_macros::select;
    use commonware_runtime::{deterministic, Runner as _};
    use std::time::Duration;

    #[derive(Clone, Default)]
    #[allow(clippy::type_complexity)]
    struct MockDatabaseSet {
        started_with: Arc<Mutex<Vec<u64>>>,
        forwarded_updates: Arc<Mutex<Vec<u64>>>,
        completion_sender: Arc<Mutex<Option<oneshot::Sender<Result<(), MockSyncError>>>>>,
        start_failures_remaining: Arc<Mutex<usize>>,
    }

    impl MockDatabaseSet {
        fn with_start_failures(start_failures: usize) -> Self {
            Self {
                started_with: Arc::new(Mutex::new(Vec::new())),
                forwarded_updates: Arc::new(Mutex::new(Vec::new())),
                completion_sender: Arc::new(Mutex::new(None)),
                start_failures_remaining: Arc::new(Mutex::new(start_failures)),
            }
        }

        fn started_with(&self) -> Vec<u64> {
            self.started_with.lock().clone()
        }

        fn forwarded_updates(&self) -> Vec<u64> {
            self.forwarded_updates.lock().clone()
        }

        fn complete_sync(&self) {
            if let Some(sender) = self.completion_sender.lock().take() {
                let _ = sender.send(Ok(()));
            }
        }

        fn fail_sync(&self) {
            if let Some(sender) = self.completion_sender.lock().take() {
                let _ = sender.send(Err(MockSyncError));
            }
        }

        fn close_sync(&self) {
            let _ = self.completion_sender.lock().take();
        }
    }

    #[derive(Debug)]
    struct MockSyncError;

    impl DatabaseSet for MockDatabaseSet {
        type Unmerkleized = ();
        type Merkleized = ();

        async fn new_batches(&self) -> Self::Unmerkleized {}
        fn fork_batches(_parent: &Self::Merkleized) -> Self::Unmerkleized {}
        async fn finalize(&self, _batches: Self::Merkleized) {}
    }

    impl SyncableDatabaseSet for MockDatabaseSet {
        type SyncConfigs = ();
        type SyncResolvers = ();
        type SyncTargets = u64;
        type SyncError = MockSyncError;

        fn start_sync<RT>(
            &self,
            context: RT,
            _sync_configs: Self::SyncConfigs,
            _sync_resolvers: Self::SyncResolvers,
            initial_targets: Self::SyncTargets,
        ) -> Result<SyncHandle<Self::SyncTargets, Self::SyncError>, Self::SyncError>
        where
            RT: Rng + Spawner + Metrics + Clock,
        {
            self.started_with.lock().push(initial_targets);
            let mut start_failures_remaining = self.start_failures_remaining.lock();
            if *start_failures_remaining > 0 {
                *start_failures_remaining -= 1;
                return Err(MockSyncError);
            }

            let updates = self.forwarded_updates.clone();
            let (target_updates, mut target_updates_rx) = mpsc::channel(8);
            context
                .with_label("mock_sync_updates")
                .spawn(move |_| async move {
                    while let Some(target) = target_updates_rx.recv().await {
                        updates.lock().push(target);
                    }
                });

            let (completion_sender, completion) = oneshot::channel();
            *self.completion_sender.lock() = Some(completion_sender);

            Ok(SyncHandle {
                target_updates,
                completion,
            })
        }
    }

    #[test]
    fn mark_ready_is_immediate() {
        deterministic::Runner::default().start(|context| async move {
            let coordinator = Coordinator::new(
                context.clone(),
                MockDatabaseSet::default(),
                Config {
                    sync_configs: (),
                    sync_resolvers: (),
                },
            );
            assert!(!coordinator.is_ready());
            coordinator.mark_ready();
            assert!(coordinator.is_ready());

            select! {
                _ = coordinator.wait_until_ready() => {},
                _ = context.sleep(Duration::from_millis(1)) => {
                    panic!("readiness wait unexpectedly blocked");
                },
            }
        });
    }

    #[test]
    fn sync_starts_on_first_update_and_forwards() {
        deterministic::Runner::default().start(|context| async move {
            let databases = MockDatabaseSet::default();
            let coordinator = Coordinator::new(
                context.clone(),
                databases.clone(),
                Config {
                    sync_configs: (),
                    sync_resolvers: (),
                },
            );

            assert!(!coordinator.is_ready());

            coordinator.update_targets(10);
            context.sleep(Duration::from_millis(1)).await;
            assert_eq!(databases.started_with(), vec![10]);

            coordinator.update_targets(11);
            for _ in 0..5 {
                if databases.forwarded_updates() == vec![11] {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(databases.forwarded_updates(), vec![11]);

            databases.complete_sync();
            context.sleep(Duration::from_millis(1)).await;

            select! {
                _ = coordinator.wait_until_ready() => {},
                _ = context.sleep(Duration::from_millis(1)) => {
                    panic!("readiness was not signaled after sync completion");
                },
            }
        });
    }

    #[derive(Clone, Default)]
    struct MockBackpressuredDatabaseSet {
        started_with: Arc<Mutex<Vec<u64>>>,
    }

    impl DatabaseSet for MockBackpressuredDatabaseSet {
        type Unmerkleized = ();
        type Merkleized = ();

        async fn new_batches(&self) -> Self::Unmerkleized {}
        fn fork_batches(_parent: &Self::Merkleized) -> Self::Unmerkleized {}
        async fn finalize(&self, _batches: Self::Merkleized) {}
    }

    impl SyncableDatabaseSet for MockBackpressuredDatabaseSet {
        type SyncConfigs = ();
        type SyncResolvers = ();
        type SyncTargets = u64;
        type SyncError = MockSyncError;

        fn start_sync<RT>(
            &self,
            _context: RT,
            _sync_configs: Self::SyncConfigs,
            _sync_resolvers: Self::SyncResolvers,
            initial_targets: Self::SyncTargets,
        ) -> Result<SyncHandle<Self::SyncTargets, Self::SyncError>, Self::SyncError>
        where
            RT: Rng + Spawner + Metrics + Clock,
        {
            self.started_with.lock().push(initial_targets);
            let (target_updates, _target_updates_rx) = mpsc::channel(1);
            let (_completion_sender, completion) = oneshot::channel();

            Ok(SyncHandle {
                target_updates,
                completion,
            })
        }
    }

    #[test]
    fn target_updates_do_not_block_under_backpressure() {
        deterministic::Runner::default().start(|context| async move {
            let databases = MockBackpressuredDatabaseSet::default();
            let coordinator = Coordinator::new(
                context.clone(),
                databases,
                Config {
                    sync_configs: (),
                    sync_resolvers: (),
                },
            );

            coordinator.update_targets(10);
            coordinator.update_targets(11);
            context.sleep(Duration::from_millis(1)).await;

            // Synchronous try_send -- must not block even when channel is full.
            coordinator.update_targets(12);
        });
    }

    #[test]
    fn sync_completion_error_does_not_panic() {
        deterministic::Runner::default().start(|context| async move {
            let databases = MockDatabaseSet::default();
            let coordinator = Coordinator::new(
                context.clone(),
                databases.clone(),
                Config {
                    sync_configs: (),
                    sync_resolvers: (),
                },
            );

            coordinator.update_targets(10);
            context.sleep(Duration::from_millis(1)).await;

            databases.fail_sync();
            context.sleep(Duration::from_millis(1)).await;

            assert!(!coordinator.is_ready());
            coordinator.update_targets(11);
            context.sleep(Duration::from_millis(1)).await;
            assert_eq!(databases.started_with(), vec![10, 11]);
        });
    }

    #[test]
    fn sync_completion_channel_close_does_not_panic() {
        deterministic::Runner::default().start(|context| async move {
            let databases = MockDatabaseSet::default();
            let coordinator = Coordinator::new(
                context.clone(),
                databases.clone(),
                Config {
                    sync_configs: (),
                    sync_resolvers: (),
                },
            );

            coordinator.update_targets(10);
            context.sleep(Duration::from_millis(1)).await;

            databases.close_sync();
            context.sleep(Duration::from_millis(1)).await;

            assert!(!coordinator.is_ready());
            coordinator.update_targets(11);
            context.sleep(Duration::from_millis(1)).await;
            assert_eq!(databases.started_with(), vec![10, 11]);
        });
    }

    #[test]
    fn sync_start_failure_does_not_panic() {
        deterministic::Runner::default().start(|context| async move {
            let databases = MockDatabaseSet::with_start_failures(1);
            let coordinator = Coordinator::new(
                context.clone(),
                databases.clone(),
                Config {
                    sync_configs: (),
                    sync_resolvers: (),
                },
            );

            coordinator.update_targets(10);
            assert!(!coordinator.is_ready());

            coordinator.update_targets(11);
            context.sleep(Duration::from_millis(1)).await;
            assert_eq!(databases.started_with(), vec![10, 11]);
        });
    }
}
