//! Internal state sync orchestration for [`Stateful`](super::wrapper::Stateful).

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

/// Startup sync configuration for a [`SyncableDatabaseSet`].
pub struct Config<D: SyncableDatabaseSet> {
    /// Per-database sync engine configuration.
    pub sync_configs: D::SyncConfigs,
    /// Per-database resolver instances.
    pub sync_resolvers: D::SyncResolvers,
    /// Optional initial target. When absent, sync starts on first finalization.
    pub initial_targets: Option<D::SyncTargets>,
}

/// One-shot readiness gate shared by all `Stateful` clones.
///
/// Before sync completion, `wait_until_ready` pends cheaply on `signal`.
/// After completion, the atomic fast-path returns immediately.
#[derive(Clone)]
struct Readiness {
    /// Fast-path readiness check used on every propose/verify call.
    ready: Arc<AtomicBool>,
    /// One-shot waiter for calls that arrive before readiness.
    signal: Signal,
    /// One-shot signaler consumed when transitioning to ready.
    signaler: Arc<Mutex<Option<Signaler>>>,
}

impl Readiness {
    fn new(ready: bool) -> Self {
        if ready {
            return Self {
                ready: Arc::new(AtomicBool::new(true)),
                signal: Signal::Closed(0),
                signaler: Arc::new(Mutex::new(None)),
            };
        }

        let (signaler, signal) = Signaler::new();
        Self {
            ready: Arc::new(AtomicBool::new(false)),
            signal,
            signaler: Arc::new(Mutex::new(Some(signaler))),
        }
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    async fn wait_until_ready(&self) {
        if self.is_ready() {
            return;
        }

        let mut signal = self.signal.clone();
        let _ = (&mut signal).await;
    }

    fn mark_ready(&self) {
        if self.ready.swap(true, Ordering::AcqRel) {
            return;
        }

        if let Some(signaler) = self.signaler.lock().take() {
            let _ = signaler.signal(0);
        }
    }
}

/// Captured values needed to launch sync when the first target appears.
#[derive(Clone)]
struct LaunchConfig<D: SyncableDatabaseSet> {
    sync_configs: D::SyncConfigs,
    sync_resolvers: D::SyncResolvers,
}

/// Coalesces target updates while the forwarding task is busy.
///
/// We keep only the latest pending target to avoid backpressuring `report()`.
struct TargetForwarder<T> {
    /// Active sender into the running sync engine.
    sender: Option<mpsc::Sender<T>>,
    /// Latest not-yet-forwarded target.
    pending: Option<T>,
    /// Whether a flush task is currently draining `pending`.
    flushing: bool,
}

impl<T> Default for TargetForwarder<T> {
    fn default() -> Self {
        Self {
            sender: None,
            pending: None,
            flushing: false,
        }
    }
}

impl<T> TargetForwarder<T> {
    /// Install the sender for a running sync session and clear transient state.
    fn transition_to_running(&mut self, sender: mpsc::Sender<T>) {
        self.sender = Some(sender);
        self.pending = None;
        self.flushing = false;
    }

    /// Clear all forwarding state when sync stops or completes.
    fn transition_to_idle(&mut self) {
        self.sender = None;
        self.pending = None;
        self.flushing = false;
    }

    /// Consume the next pending target and stop the flush loop if empty.
    fn take_pending_for_flush(&mut self) -> Option<T> {
        let target = self.pending.take();
        if target.is_none() {
            self.flushing = false;
        }
        target
    }
}

/// Lifecycle for startup sync orchestration.
enum State<D: SyncableDatabaseSet> {
    /// Sync is disabled; readiness is permanently true.
    Disabled,
    /// Sync is configured but has not started yet.
    Waiting(LaunchConfig<D>),
    /// Sync is running and readiness is still false.
    Running,
    /// Sync completed successfully; readiness is permanently true.
    Ready,
}

/// Work extracted from the state lock so async sends happen lock-free.
enum UpdateAction<T, E> {
    None,
    Started(oneshot::Receiver<Result<(), E>>),
    Forward(T),
}

/// Shared sync coordinator used by all [`Stateful`](super::wrapper::Stateful) clones.
#[derive(Clone)]
pub(crate) struct Coordinator<E, D>
where
    E: Rng + Spawner + Metrics + Clock,
    D: SyncableDatabaseSet,
{
    context: E,
    databases: D,
    readiness: Readiness,
    state: Arc<Mutex<State<D>>>,
    target_forwarder: Arc<Mutex<TargetForwarder<D::SyncTargets>>>,
}

impl<E, D> Coordinator<E, D>
where
    E: Rng + Spawner + Metrics + Clock,
    D: SyncableDatabaseSet,
{
    pub(crate) fn new(context: E, databases: D, config: Option<Config<D>>) -> Self {
        let (state, readiness, initial_targets) = match config {
            None => (State::Disabled, Readiness::new(true), None),
            Some(config) => (
                State::Waiting(LaunchConfig {
                    sync_configs: config.sync_configs,
                    sync_resolvers: config.sync_resolvers,
                }),
                Readiness::new(false),
                config.initial_targets,
            ),
        };

        let coordinator = Self {
            context,
            databases,
            readiness,
            state: Arc::new(Mutex::new(state)),
            target_forwarder: Arc::new(Mutex::new(TargetForwarder::default())),
        };

        if let Some(initial_targets) = initial_targets {
            let completion = {
                let mut state = coordinator.state.lock();
                let State::Waiting(launch_config) = &*state else {
                    unreachable!("initial targets require waiting sync state");
                };

                let sync_handle = coordinator.launch_sync(launch_config, initial_targets);
                coordinator.set_target_sender(sync_handle.target_updates);
                *state = State::Running;
                sync_handle.completion
            };
            coordinator.spawn_completion_watcher(completion);
        }

        coordinator
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.readiness.is_ready()
    }

    pub(crate) async fn wait_until_ready(&self) {
        self.readiness.wait_until_ready().await;
    }

    fn launch_sync(
        &self,
        launch_config: &LaunchConfig<D>,
        initial_targets: D::SyncTargets,
    ) -> SyncHandle<D::SyncTargets, D::SyncError> {
        self.databases
            .start_sync(
                self.context.clone(),
                launch_config.sync_configs.clone(),
                launch_config.sync_resolvers.clone(),
                initial_targets,
            )
            .expect("state sync failed to start")
    }

    fn set_target_sender(&self, sender: mpsc::Sender<D::SyncTargets>) {
        let mut forwarder = self.target_forwarder.lock();
        forwarder.transition_to_running(sender);
    }

    /// Spawn a best-effort forwarding loop for coalesced target updates.
    fn spawn_target_flush(&self, sender: mpsc::Sender<D::SyncTargets>) {
        let forwarder = self.target_forwarder.clone();

        self.context
            .clone()
            .with_label("stateful_sync_target_flush")
            .spawn(move |_| async move {
                loop {
                    let target = {
                        let mut forwarder = forwarder.lock();
                        match forwarder.take_pending_for_flush() {
                            Some(target) => target,
                            None => return,
                        }
                    };

                    if sender.send(target).await.is_err() {
                        let mut forwarder = forwarder.lock();
                        forwarder.transition_to_idle();
                        return;
                    }
                }
            });
    }

    /// Queue a target update without blocking the caller.
    ///
    /// If a flush is already in flight, this overwrites the pending value so
    /// sync chases the latest finalized tip.
    fn enqueue_target_update(&self, targets: D::SyncTargets) {
        let sender = {
            let mut forwarder = self.target_forwarder.lock();
            let Some(sender) = forwarder.sender.clone() else {
                return;
            };

            // Keep only the latest update while a flush is in flight.
            forwarder.pending = Some(targets);
            if forwarder.flushing {
                return;
            }
            forwarder.flushing = true;
            sender
        };

        self.spawn_target_flush(sender);
    }

    fn spawn_completion_watcher(&self, completion: oneshot::Receiver<Result<(), D::SyncError>>) {
        let readiness = self.readiness.clone();
        let state = self.state.clone();
        let target_forwarder = self.target_forwarder.clone();

        self.context
            .clone()
            .with_label("stateful_sync_completion")
            .spawn(move |_| async move {
                match completion.await {
                    Ok(Ok(())) => {
                        readiness.mark_ready();
                        *state.lock() = State::Ready;
                        let mut forwarder = target_forwarder.lock();
                        forwarder.transition_to_idle();
                    }
                    Ok(Err(err)) => panic!("state sync failed: {err:?}"),
                    Err(err) => panic!("state sync completion channel closed: {err}"),
                }
            });
    }

    pub(crate) async fn update_targets(&self, targets: D::SyncTargets) {
        if self.readiness.is_ready() {
            return;
        }

        let action = {
            let mut state = self.state.lock();
            match &mut *state {
                State::Disabled | State::Ready => UpdateAction::None,
                State::Waiting(launch_config) => {
                    let sync_handle = self.launch_sync(launch_config, targets.clone());
                    self.set_target_sender(sync_handle.target_updates);
                    *state = State::Running;
                    UpdateAction::Started(sync_handle.completion)
                }
                State::Running => UpdateAction::Forward(targets),
            }
        };

        match action {
            UpdateAction::None => {}
            UpdateAction::Started(completion) => self.spawn_completion_watcher(completion),
            UpdateAction::Forward(targets) => self.enqueue_target_update(targets),
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
    struct MockDatabaseSet {
        started_with: Arc<Mutex<Vec<u64>>>,
        forwarded_updates: Arc<Mutex<Vec<u64>>>,
        completion_sender: Arc<Mutex<Option<oneshot::Sender<Result<(), MockSyncError>>>>>,
    }

    impl MockDatabaseSet {
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
    fn sync_disabled_is_immediately_ready() {
        deterministic::Runner::default().start(|context| async move {
            let coordinator = Coordinator::new(context.clone(), MockDatabaseSet::default(), None);
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
    fn sync_starts_on_finalization_and_forwards_updates() {
        deterministic::Runner::default().start(|context| async move {
            let databases = MockDatabaseSet::default();
            let coordinator = Coordinator::new(
                context.clone(),
                databases.clone(),
                Some(Config {
                    sync_configs: (),
                    sync_resolvers: (),
                    initial_targets: None,
                }),
            );

            select! {
                _ = coordinator.wait_until_ready() => {
                    panic!("sync should not be ready before start");
                },
                _ = context.sleep(Duration::from_millis(1)) => {},
            }

            coordinator.update_targets(10).await;
            context.sleep(Duration::from_millis(1)).await;
            assert_eq!(databases.started_with(), vec![10]);

            coordinator.update_targets(11).await;
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
    fn sync_target_updates_do_not_block_report_path_under_backpressure() {
        deterministic::Runner::default().start(|context| async move {
            let databases = MockBackpressuredDatabaseSet::default();
            let coordinator = Coordinator::new(
                context.clone(),
                databases,
                Some(Config {
                    sync_configs: (),
                    sync_resolvers: (),
                    initial_targets: None,
                }),
            );

            coordinator.update_targets(10).await;

            // Fill the bounded target-update channel.
            coordinator.update_targets(11).await;
            context.sleep(Duration::from_millis(1)).await;

            select! {
                _ = coordinator.update_targets(12) => {},
                _ = context.sleep(Duration::from_millis(1)) => {
                    panic!("target update blocked while channel was backpressured");
                },
            }
        });
    }
}
