//! A deterministic runtime that randomly selects tasks to run based on a seed
//!
//! # Panics
//!
//! If any task panics, the runtime will panic (and shutdown).
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic, Metrics};
//!
//! let executor =  deterministic::Runner::default();
//! executor.start(|context| async move {
//!     println!("Parent started");
//!     let result = context.with_label("child").spawn(|_| async move {
//!         println!("Child started");
//!         "hello"
//!     });
//!     println!("Child result: {:?}", result.await);
//!     println!("Parent exited");
//!     println!("Auditor state: {}", context.auditor().state());
//! });
//! ```

use crate::{
    network::{
        audited::Network as AuditedNetwork, deterministic::Network as DeterministicNetwork,
        metered::Network as MeteredNetwork,
    },
    storage::{
        audited::Storage as AuditedStorage, memory::Storage as MemStorage,
        metered::Storage as MeteredStorage,
    },
    telemetry::metrics::task::Label,
    utils::{
        signal::{Signal, Stopper},
        Aborter,
    },
    Clock, Error, Handle, ListenerOf, METRICS_PREFIX,
};
use commonware_macros::select;
use commonware_utils::{hex, SystemTimeExt};
use futures::{
    task::{waker, ArcWake},
    Future,
};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::{Metric, Registry},
};
use rand::{prelude::SliceRandom, rngs::StdRng, CryptoRng, RngCore, SeedableRng};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BinaryHeap},
    mem::{replace, take},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{self, Poll, Waker},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::trace;

#[derive(Debug)]
struct Metrics {
    tasks_spawned: Family<Label, Counter>,
    tasks_running: Family<Label, Gauge>,
    task_polls: Family<Label, Counter>,

    network_bandwidth: Counter,
}

impl Metrics {
    pub fn init(registry: &mut Registry) -> Self {
        let metrics = Self {
            task_polls: Family::default(),
            tasks_spawned: Family::default(),
            tasks_running: Family::default(),
            network_bandwidth: Counter::default(),
        };
        registry.register(
            "tasks_spawned",
            "Total number of tasks spawned",
            metrics.tasks_spawned.clone(),
        );
        registry.register(
            "tasks_running",
            "Number of tasks currently running",
            metrics.tasks_running.clone(),
        );
        registry.register(
            "task_polls",
            "Total number of task polls",
            metrics.task_polls.clone(),
        );
        registry.register(
            "bandwidth",
            "Total amount of data sent over network",
            metrics.network_bandwidth.clone(),
        );
        metrics
    }
}

/// A SHA-256 digest.
type Digest = [u8; 32];

/// Track the state of the runtime for determinism auditing.
pub struct Auditor {
    digest: Mutex<Digest>,
}

impl Default for Auditor {
    fn default() -> Self {
        Self {
            digest: Digest::default().into(),
        }
    }
}

impl Auditor {
    /// Record that an event happened.
    /// This auditor's hash will be updated with the event's `label` and
    /// whatever other data is passed in the `payload` closure.
    pub(crate) fn event<F>(&self, label: &'static [u8], payload: F)
    where
        F: FnOnce(&mut Sha256),
    {
        let mut digest = self.digest.lock().unwrap();

        let mut hasher = Sha256::new();
        hasher.update(digest.as_ref());
        hasher.update(label);
        payload(&mut hasher);

        *digest = hasher.finalize().into();
    }

    /// Generate a representation of the current state of the runtime.
    ///
    /// This can be used to ensure that logic running on top
    /// of the runtime is interacting deterministically.
    pub fn state(&self) -> String {
        let hash = self.digest.lock().unwrap();
        hex(hash.as_ref())
    }
}

/// Configuration for the `deterministic` runtime.
#[derive(Clone)]
pub struct Config {
    /// Seed for the random number generator.
    seed: u64,

    /// The cycle duration determines how much time is advanced after each iteration of the event
    /// loop. This is useful to prevent starvation if some task never yields.
    cycle: Duration,

    /// If the runtime is still executing at this point (i.e. a test hasn't stopped), panic.
    timeout: Option<Duration>,
}

impl Config {
    /// Returns a new [Config] with default values.
    pub fn new() -> Self {
        Self {
            seed: 42,
            cycle: Duration::from_millis(1),
            timeout: None,
        }
    }

    // Setters
    /// See [Config]
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }
    /// See [Config]
    pub fn with_cycle(mut self, cycle: Duration) -> Self {
        self.cycle = cycle;
        self
    }
    /// See [Config]
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    // Getters
    /// See [Config]
    pub fn seed(&self) -> u64 {
        self.seed
    }
    /// See [Config]
    pub fn cycle(&self) -> Duration {
        self.cycle
    }
    /// See [Config]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Assert that the configuration is valid.
    pub fn assert(&self) {
        assert!(
            self.cycle != Duration::default() || self.timeout.is_none(),
            "cycle duration must be non-zero when timeout is set",
        );
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic runtime that randomly selects tasks to run based on a seed.
pub struct Executor {
    registry: Mutex<Registry>,
    cycle: Duration,
    deadline: Option<SystemTime>,
    metrics: Arc<Metrics>,
    auditor: Arc<Auditor>,
    rng: Mutex<StdRng>,
    time: Mutex<SystemTime>,
    tasks: Arc<Tasks>,
    sleeping: Mutex<BinaryHeap<Alarm>>,
    shutdown: Mutex<Stopper>,
}

/// An artifact that can be used to recover the state of the runtime.
///
/// This is useful when mocking unclean shutdown (while retaining deterministic behavior).
pub struct Checkpoint {
    cycle: Duration,
    deadline: Option<SystemTime>,
    auditor: Arc<Auditor>,
    rng: Mutex<StdRng>,
    time: Mutex<SystemTime>,
    storage: Arc<Storage>,
}

#[allow(clippy::large_enum_variant)]
enum State {
    Config(Config),
    Checkpoint(Checkpoint),
}

/// Implementation of [crate::Runner] for the `deterministic` runtime.
pub struct Runner {
    state: State,
}

impl From<Config> for Runner {
    fn from(cfg: Config) -> Self {
        Self::new(cfg)
    }
}

impl From<Checkpoint> for Runner {
    fn from(checkpoint: Checkpoint) -> Self {
        Self {
            state: State::Checkpoint(checkpoint),
        }
    }
}

impl Runner {
    /// Initialize a new `deterministic` runtime with the given seed and cycle duration.
    pub fn new(cfg: Config) -> Self {
        // Ensure config is valid
        cfg.assert();
        Runner {
            state: State::Config(cfg),
        }
    }

    /// Initialize a new `deterministic` runtime with the default configuration
    /// and the provided seed.
    pub fn seeded(seed: u64) -> Self {
        let cfg = Config {
            seed,
            ..Config::default()
        };
        Self::new(cfg)
    }

    /// Initialize a new `deterministic` runtime with the default configuration
    /// but exit after the given timeout.
    pub fn timed(timeout: Duration) -> Self {
        let cfg = Config {
            timeout: Some(timeout),
            ..Config::default()
        };
        Self::new(cfg)
    }

    /// Like [crate::Runner::start], but also returns a [Checkpoint] that can be used
    /// to recover the state of the runtime in a subsequent run.
    pub fn start_and_recover<F, Fut>(self, f: F) -> (Fut::Output, Checkpoint)
    where
        F: FnOnce(Context) -> Fut,
        Fut: Future,
    {
        // Setup context and return strong reference to executor
        let (context, executor) = match self.state {
            State::Config(config) => Context::new(config),
            State::Checkpoint(checkpoint) => Context::recover(checkpoint),
        };

        // Pin root task to the heap
        let storage = context.storage.clone();
        let mut root = Box::pin(f(context));

        // Register the root task
        Tasks::register_root(&executor.tasks);

        // Process tasks until root task completes or progress stalls
        let mut iter = 0;
        let output = loop {
            // Ensure we have not exceeded our deadline
            {
                let current = executor.time.lock().unwrap();
                if let Some(deadline) = executor.deadline {
                    if *current >= deadline {
                        panic!("runtime timeout");
                    }
                }
            }

            // Drain all ready tasks
            let mut queue = executor.tasks.drain();

            // Shuffle tasks (if more than one)
            if queue.len() > 1 {
                let mut rng = executor.rng.lock().unwrap();
                queue.shuffle(&mut *rng);
            }

            // Run all snapshotted tasks
            //
            // This approach is more efficient than randomly selecting a task one-at-a-time
            // because it ensures we don't pull the same pending task multiple times in a row (without
            // processing a different task required for other tasks to make progress).
            trace!(iter, tasks = queue.len(), "starting loop");
            let mut output = None;
            for id in queue {
                // Lookup the task (it may have completed already)
                let Some(task) = executor.tasks.get(id) else {
                    trace!(id, "skipping missing task");
                    continue;
                };

                // Record task for auditing
                executor.auditor.event(b"process_task", |hasher| {
                    hasher.update(task.id.to_be_bytes());
                    hasher.update(task.label.name().as_bytes());
                });
                executor.metrics.task_polls.get_or_create(&task.label).inc();
                trace!(id, "processing task");

                // Prepare task for polling
                let waker = waker(Arc::new(TaskWaker {
                    id,
                    tasks: Arc::downgrade(&executor.tasks),
                }));
                let mut cx = task::Context::from_waker(&waker);

                // Poll the task
                match &task.mode {
                    Mode::Root => {
                        // Poll the root task
                        if let Poll::Ready(result) = root.as_mut().poll(&mut cx) {
                            trace!(id, "root task is complete");
                            output = Some(result);
                            break;
                        }
                    }
                    Mode::Work(future) => {
                        // Get the future (if it still exists)
                        let mut fut_opt = future.lock().unwrap();
                        let Some(fut) = fut_opt.as_mut() else {
                            trace!(id, "skipping already complete task");

                            // Remove the future
                            executor.tasks.remove(id);
                            continue;
                        };

                        // Poll the task
                        if fut.as_mut().poll(&mut cx).is_ready() {
                            trace!(id, "task is complete");

                            // Remove the future
                            executor.tasks.remove(id);
                            *fut_opt = None;
                            continue;
                        }
                    }
                }

                // Try again later if task is still pending
                trace!(id, "task is still pending");
            }

            // If the root task has completed, exit as soon as possible
            if let Some(output) = output {
                break output;
            }

            // Advance time by cycle
            //
            // This approach prevents starvation if some task never yields (to approximate this,
            // duration can be set to 1ns).
            let mut current;
            {
                let mut time = executor.time.lock().unwrap();
                *time = time
                    .checked_add(executor.cycle)
                    .expect("executor time overflowed");
                current = *time;
            }
            trace!(now = current.epoch_millis(), "time advanced");

            // Skip time if there is nothing to do
            if executor.tasks.ready() == 0 {
                let mut skip = None;
                {
                    let sleeping = executor.sleeping.lock().unwrap();
                    if let Some(next) = sleeping.peek() {
                        if next.time > current {
                            skip = Some(next.time);
                        }
                    }
                }
                if let Some(skip_time) = skip {
                    {
                        let mut time = executor.time.lock().unwrap();
                        *time = skip_time;
                        current = *time;
                    }
                    trace!(now = current.epoch_millis(), "time skipped");
                }
            }

            // Wake all sleeping tasks that are ready
            {
                let mut sleeping = executor.sleeping.lock().unwrap();
                while let Some(next) = sleeping.peek() {
                    if next.time <= current {
                        let sleeper = sleeping.pop().unwrap();
                        sleeper.waker.wake();
                    } else {
                        break;
                    }
                }
            }

            // If there are no tasks to run after advancing time, the executor is stalled
            // and will never finish.
            if executor.tasks.ready() == 0 {
                panic!("runtime stalled");
            }
            iter += 1;
        };

        // Clear remaining tasks from the executor.
        //
        // It is critical that we wait to drop the strong
        // reference to executor until after we have dropped
        // all tasks (as they may attempt to upgrade their weak
        // reference to the executor during drop).
        executor.sleeping.lock().unwrap().clear(); // included in tasks
        let tasks = executor.tasks.clear();
        for task in tasks {
            let Mode::Work(future) = &task.mode else {
                continue;
            };
            *future.lock().unwrap() = None;
        }

        // Assert the context doesn't escape the start() function (behavior
        // is undefined in this case)
        assert!(
            Arc::weak_count(&executor) == 0,
            "executor still has weak references"
        );

        // Extract the executor from the Arc
        let executor = Arc::into_inner(executor).expect("executor still has strong references");

        // Construct a checkpoint that can be used to restart the runtime
        let checkpoint = Checkpoint {
            cycle: executor.cycle,
            deadline: executor.deadline,
            auditor: executor.auditor,
            rng: executor.rng,
            time: executor.time,
            storage,
        };

        (output, checkpoint)
    }
}

impl Default for Runner {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl crate::Runner for Runner {
    type Context = Context;

    fn start<F, Fut>(self, f: F) -> Fut::Output
    where
        F: FnOnce(Self::Context) -> Fut,
        Fut: Future,
    {
        let (output, _) = self.start_and_recover(f);
        output
    }
}

/// The mode of a [Task].
enum Mode {
    Root,
    Work(Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>>),
}

/// A future being executed by the [Executor].
struct Task {
    id: u128,
    label: Label,

    mode: Mode,
}

/// A waker for a [Task].
struct TaskWaker {
    id: u128,

    tasks: Weak<Tasks>,
}

impl ArcWake for TaskWaker {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        // Upgrade the weak reference to re-enqueue this task.
        // If upgrade fails, the task queue has been dropped and no action is required.
        //
        // This can happen if some data is passed into the runtime and it drops after the runtime exits.
        if let Some(tasks) = arc_self.tasks.upgrade() {
            tasks.queue(arc_self.id);
        }
    }
}

/// A collection of [Task]s that are being executed by the [Executor].
struct Tasks {
    /// The next task id.
    counter: Mutex<u128>,
    /// Tasks ready to be polled.
    ready: Mutex<Vec<u128>>,
    /// All running tasks.
    running: Mutex<BTreeMap<u128, Arc<Task>>>,
}

impl Tasks {
    /// Create a new task queue.
    fn new() -> Self {
        Self {
            counter: Mutex::new(0),
            ready: Mutex::new(Vec::new()),
            running: Mutex::new(BTreeMap::new()),
        }
    }

    /// Increment the task counter and return the old value.
    fn increment(&self) -> u128 {
        let mut counter = self.counter.lock().unwrap();
        let old = *counter;
        *counter = counter.checked_add(1).expect("task counter overflow");
        old
    }

    /// Register the root task.
    ///
    /// If the root task has already been registered, this function will panic.
    fn register_root(arc_self: &Arc<Self>) {
        let id = arc_self.increment();
        let task = Arc::new(Task {
            id,
            label: Label::root(),
            mode: Mode::Root,
        });
        arc_self.register(id, task);
    }

    /// Register a non-root task to be executed.
    fn register_work(
        arc_self: &Arc<Self>,
        label: Label,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) {
        let id = arc_self.increment();
        let task = Arc::new(Task {
            id,
            label,
            mode: Mode::Work(Mutex::new(Some(future))),
        });
        arc_self.register(id, task);
    }

    /// Register a new task to be executed.
    fn register(&self, id: u128, task: Arc<Task>) {
        // Track as running until completion
        self.running.lock().unwrap().insert(id, task);

        // Add to ready
        self.queue(id);
    }

    /// Enqueue an already registered task to be executed.
    fn queue(&self, id: u128) {
        let mut ready = self.ready.lock().unwrap();
        ready.push(id);
    }

    /// Drain all ready tasks.
    fn drain(&self) -> Vec<u128> {
        let mut queue = self.ready.lock().unwrap();
        let len = queue.len();
        replace(&mut *queue, Vec::with_capacity(len))
    }

    /// The number of ready tasks.
    fn ready(&self) -> usize {
        self.ready.lock().unwrap().len()
    }

    /// Lookup a task.
    ///
    /// We must return cloned here because we cannot hold the running lock while polling a task (will
    /// deadlock if [Self::register_work] is called).
    fn get(&self, id: u128) -> Option<Arc<Task>> {
        let running = self.running.lock().unwrap();
        running.get(&id).cloned()
    }

    /// Remove a task.
    fn remove(&self, id: u128) {
        self.running.lock().unwrap().remove(&id);
    }

    /// Clear all tasks.
    fn clear(&self) -> Vec<Arc<Task>> {
        // Clear ready
        self.ready.lock().unwrap().clear();

        // Clear running tasks
        let running: BTreeMap<u128, Arc<Task>> = {
            let mut running = self.running.lock().unwrap();
            take(&mut *running)
        };
        running.into_values().collect()
    }
}

type Network = MeteredNetwork<AuditedNetwork<DeterministicNetwork>>;
type Storage = MeteredStorage<AuditedStorage<MemStorage>>;

/// Implementation of [crate::Spawner], [crate::Clock],
/// [crate::Network], and [crate::Storage] for the `deterministic`
/// runtime.
pub struct Context {
    name: String,
    spawned: bool,
    executor: Weak<Executor>,
    network: Arc<Network>,
    storage: Arc<Storage>,
    children: Arc<Mutex<Vec<Aborter>>>,
}

impl Context {
    fn new(cfg: Config) -> (Self, Arc<Executor>) {
        // Create a new registry
        let mut registry = Registry::default();
        let runtime_registry = registry.sub_registry_with_prefix(METRICS_PREFIX);

        // Initialize runtime
        let metrics = Arc::new(Metrics::init(runtime_registry));
        let start_time = UNIX_EPOCH;
        let deadline = cfg
            .timeout
            .map(|timeout| start_time.checked_add(timeout).expect("timeout overflowed"));
        let auditor = Arc::new(Auditor::default());
        let storage = MeteredStorage::new(
            AuditedStorage::new(MemStorage::default(), auditor.clone()),
            runtime_registry,
        );
        let network = AuditedNetwork::new(DeterministicNetwork::default(), auditor.clone());
        let network = MeteredNetwork::new(network, runtime_registry);

        let executor = Arc::new(Executor {
            registry: Mutex::new(registry),
            cycle: cfg.cycle,
            deadline,
            metrics: metrics.clone(),
            auditor: auditor.clone(),
            rng: Mutex::new(StdRng::seed_from_u64(cfg.seed)),
            time: Mutex::new(start_time),
            tasks: Arc::new(Tasks::new()),
            sleeping: Mutex::new(BinaryHeap::new()),
            shutdown: Mutex::new(Stopper::default()),
        });

        (
            Self {
                name: String::new(),
                spawned: false,
                executor: Arc::downgrade(&executor),
                network: Arc::new(network),
                storage: Arc::new(storage),
                children: Arc::new(Mutex::new(Vec::new())),
            },
            executor,
        )
    }

    /// Recover the inner state (deadline, metrics, auditor, rng, synced storage, etc.) from the
    /// current runtime and use it to initialize a new instance of the runtime. A recovered runtime
    /// does not inherit the current runtime's pending tasks, unsynced storage, network connections, nor
    /// its shutdown signaler.
    ///
    /// This is useful for performing a deterministic simulation that spans multiple runtime instantiations,
    /// like simulating unclean shutdown (which involves repeatedly halting the runtime at unexpected intervals).
    ///
    /// It is only permitted to call this method after the runtime has finished (i.e. once `start` returns)
    /// and only permitted to do once (otherwise multiple recovered runtimes will share the same inner state).
    /// If either one of these conditions is violated, this method will panic.
    fn recover(checkpoint: Checkpoint) -> (Self, Arc<Executor>) {
        // Rebuild metrics
        let mut registry = Registry::default();
        let runtime_registry = registry.sub_registry_with_prefix(METRICS_PREFIX);
        let metrics = Arc::new(Metrics::init(runtime_registry));

        // Copy state
        let network =
            AuditedNetwork::new(DeterministicNetwork::default(), checkpoint.auditor.clone());
        let network = MeteredNetwork::new(network, runtime_registry);

        let executor = Arc::new(Executor {
            // Copied from the checkpoint
            cycle: checkpoint.cycle,
            deadline: checkpoint.deadline,
            auditor: checkpoint.auditor,
            rng: checkpoint.rng,
            time: checkpoint.time,

            // New state for the new runtime
            registry: Mutex::new(registry),
            metrics: metrics.clone(),
            tasks: Arc::new(Tasks::new()),
            sleeping: Mutex::new(BinaryHeap::new()),
            shutdown: Mutex::new(Stopper::default()),
        });
        (
            Self {
                name: String::new(),
                spawned: false,
                executor: Arc::downgrade(&executor),
                network: Arc::new(network),
                storage: checkpoint.storage,
                children: Arc::new(Mutex::new(Vec::new())),
            },
            executor,
        )
    }

    /// Upgrade Weak reference to [Executor].
    fn executor(&self) -> Arc<Executor> {
        self.executor.upgrade().expect("executor already dropped")
    }

    /// Get a reference to [Metrics].
    fn metrics(&self) -> Arc<Metrics> {
        self.executor().metrics.clone()
    }

    /// Get a reference to the [Auditor].
    pub fn auditor(&self) -> Arc<Auditor> {
        self.executor().auditor.clone()
    }
}

impl Clone for Context {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            spawned: false,
            executor: self.executor.clone(),
            network: self.network.clone(),
            storage: self.storage.clone(),
            children: self.children.clone(),
        }
    }
}

impl crate::Spawner for Context {
    fn spawn<F, Fut, T>(mut self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a context only spawns one task
        assert!(!self.spawned, "already spawned");

        // Get metrics
        let (label, metric) = spawn_metrics!(self, future);

        // Set up the task
        let executor = self.executor();

        // Give spawned task its own empty children list
        let children = Arc::new(Mutex::new(Vec::new()));
        self.children = children.clone();

        let future = f(self);
        let (f, handle) = Handle::init_future(future, metric, false, children);

        // Spawn the task
        Tasks::register_work(&executor.tasks, label, Box::pin(f));
        handle
    }

    fn spawn_ref<F, T>(&mut self) -> impl FnOnce(F) -> Handle<T> + 'static
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a context only spawns one task
        assert!(!self.spawned, "already spawned");
        self.spawned = true;

        // Get metrics
        let (label, metric) = spawn_metrics!(self, future);

        // Set up the task
        let executor = self.executor();

        move |f: F| {
            // Give spawned task its own empty children list
            let (f, handle) =
                Handle::init_future(f, metric, false, Arc::new(Mutex::new(Vec::new())));

            // Spawn the task
            Tasks::register_work(&executor.tasks, label, Box::pin(f));
            handle
        }
    }

    fn spawn_child<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Store parent's children list
        let parent_children = self.children.clone();

        // Spawn the child
        let child_handle = self.spawn(f);

        // Register this child with the parent
        if let Some(aborter) = child_handle.aborter() {
            parent_children.lock().unwrap().push(aborter);
        }

        child_handle
    }

    fn spawn_blocking<F, T>(self, dedicated: bool, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> T + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a context only spawns one task
        assert!(!self.spawned, "already spawned");

        // Get metrics
        let (label, metric) = spawn_metrics!(self, blocking, dedicated);

        // Initialize the blocking task
        let executor = self.executor();
        let (f, handle) = Handle::init_blocking(|| f(self), metric, false);

        // Spawn the task
        let f = async move { f() };
        Tasks::register_work(&executor.tasks, label, Box::pin(f));
        handle
    }

    fn spawn_blocking_ref<F, T>(&mut self, dedicated: bool) -> impl FnOnce(F) -> Handle<T> + 'static
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a context only spawns one task
        assert!(!self.spawned, "already spawned");
        self.spawned = true;

        // Get metrics
        let (label, metric) = spawn_metrics!(self, blocking, dedicated);

        // Set up the task
        let executor = self.executor();
        move |f: F| {
            let (f, handle) = Handle::init_blocking(f, metric, false);

            // Spawn the task
            let f = async move { f() };
            Tasks::register_work(&executor.tasks, label, Box::pin(f));
            handle
        }
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        let executor = self.executor();
        executor.auditor.event(b"stop", |hasher| {
            hasher.update(value.to_be_bytes());
        });
        let stop_resolved = {
            let mut shutdown = executor.shutdown.lock().unwrap();
            shutdown.stop(value)
        };

        // Wait for all tasks to complete or the timeout to fire
        let timeout_future = match timeout {
            Some(duration) => futures::future::Either::Left(self.sleep(duration)),
            None => futures::future::Either::Right(futures::future::pending()),
        };
        select! {
            result = stop_resolved => {
                result.map_err(|_| Error::Closed)?;
                Ok(())
            },
            _ = timeout_future => {
                Err(Error::Timeout)
            }
        }
    }

    fn stopped(&self) -> Signal {
        let executor = self.executor();
        executor.auditor.event(b"stopped", |_| {});
        let stopped = executor.shutdown.lock().unwrap().stopped();
        stopped
    }
}

impl crate::Metrics for Context {
    fn with_label(&self, label: &str) -> Self {
        let name = {
            let prefix = self.name.clone();
            if prefix.is_empty() {
                label.to_string()
            } else {
                format!("{prefix}_{label}")
            }
        };
        assert!(
            !name.starts_with(METRICS_PREFIX),
            "using runtime label is not allowed"
        );
        Self {
            name,
            spawned: false,
            executor: self.executor.clone(),
            network: self.network.clone(),
            storage: self.storage.clone(),
            children: self.children.clone(),
        }
    }

    fn label(&self) -> String {
        self.name.clone()
    }

    fn register<N: Into<String>, H: Into<String>>(&self, name: N, help: H, metric: impl Metric) {
        // Prepare args
        let name = name.into();
        let help = help.into();

        // Register metric
        let executor = self.executor();
        executor.auditor.event(b"register", |hasher| {
            hasher.update(name.as_bytes());
            hasher.update(help.as_bytes());
        });
        let prefixed_name = {
            let prefix = &self.name;
            if prefix.is_empty() {
                name
            } else {
                format!("{}_{}", *prefix, name)
            }
        };
        executor
            .registry
            .lock()
            .unwrap()
            .register(prefixed_name, help, metric);
    }

    fn encode(&self) -> String {
        let executor = self.executor();
        executor.auditor.event(b"encode", |_| {});
        let mut buffer = String::new();
        encode(&mut buffer, &executor.registry.lock().unwrap()).expect("encoding failed");
        buffer
    }
}

struct Sleeper {
    executor: Weak<Executor>,
    time: SystemTime,
    registered: bool,
}

impl Sleeper {
    /// Upgrade Weak reference to [Executor].
    fn executor(&self) -> Arc<Executor> {
        self.executor.upgrade().expect("executor already dropped")
    }
}

struct Alarm {
    time: SystemTime,
    waker: Waker,
}

impl PartialEq for Alarm {
    fn eq(&self, other: &Self) -> bool {
        self.time.eq(&other.time)
    }
}

impl Eq for Alarm {}

impl PartialOrd for Alarm {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Alarm {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse the ordering for min-heap
        other.time.cmp(&self.time)
    }
}

impl Future for Sleeper {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let executor = self.executor();
        {
            let current_time = *executor.time.lock().unwrap();
            if current_time >= self.time {
                return Poll::Ready(());
            }
        }
        if !self.registered {
            self.registered = true;
            executor.sleeping.lock().unwrap().push(Alarm {
                time: self.time,
                waker: cx.waker().clone(),
            });
        }
        Poll::Pending
    }
}

impl Clock for Context {
    fn current(&self) -> SystemTime {
        *self.executor().time.lock().unwrap()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        let deadline = self
            .current()
            .checked_add(duration)
            .expect("overflow when setting wake time");
        self.sleep_until(deadline)
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        Sleeper {
            executor: self.executor.clone(),

            time: deadline,
            registered: false,
        }
    }
}

impl GClock for Context {
    type Instant = SystemTime;

    fn now(&self) -> Self::Instant {
        self.current()
    }
}

impl ReasonablyRealtime for Context {}

impl crate::Network for Context {
    type Listener = ListenerOf<Network>;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        self.network.bind(socket).await
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), Error> {
        self.network.dial(socket).await
    }
}

impl RngCore for Context {
    fn next_u32(&mut self) -> u32 {
        let executor = self.executor();
        executor.auditor.event(b"rand", |hasher| {
            hasher.update(b"next_u32");
        });
        let result = executor.rng.lock().unwrap().next_u32();
        result
    }

    fn next_u64(&mut self) -> u64 {
        let executor = self.executor();
        executor.auditor.event(b"rand", |hasher| {
            hasher.update(b"next_u64");
        });
        let result = executor.rng.lock().unwrap().next_u64();
        result
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let executor = self.executor();
        executor.auditor.event(b"rand", |hasher| {
            hasher.update(b"fill_bytes");
        });
        executor.rng.lock().unwrap().fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        let executor = self.executor();
        executor.auditor.event(b"rand", |hasher| {
            hasher.update(b"try_fill_bytes");
        });
        let result = executor.rng.lock().unwrap().try_fill_bytes(dest);
        result
    }
}

impl CryptoRng for Context {}

impl crate::Storage for Context {
    type Blob = <Storage as crate::Storage>::Blob;

    async fn open(&self, partition: &str, name: &[u8]) -> Result<(Self::Blob, u64), Error> {
        self.storage.open(partition, name).await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.storage.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.storage.scan(partition).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, utils::run_tasks, Blob, Runner as _, Storage};
    use commonware_macros::test_traced;
    use futures::task::noop_waker;

    fn run_with_seed(seed: u64) -> (String, Vec<usize>) {
        let executor = deterministic::Runner::seeded(seed);
        run_tasks(5, executor)
    }

    #[test]
    fn test_same_seed_same_order() {
        // Generate initial outputs
        let mut outputs = Vec::new();
        for seed in 0..1000 {
            let output = run_with_seed(seed);
            outputs.push(output);
        }

        // Ensure they match
        for seed in 0..1000 {
            let output = run_with_seed(seed);
            assert_eq!(output, outputs[seed as usize]);
        }
    }

    #[test_traced("TRACE")]
    fn test_different_seeds_different_order() {
        let output1 = run_with_seed(12345);
        let output2 = run_with_seed(54321);
        assert_ne!(output1, output2);
    }

    #[test]
    fn test_alarm_min_heap() {
        // Populate heap
        let now = SystemTime::now();
        let alarms = vec![
            Alarm {
                time: now + Duration::new(10, 0),
                waker: noop_waker(),
            },
            Alarm {
                time: now + Duration::new(5, 0),
                waker: noop_waker(),
            },
            Alarm {
                time: now + Duration::new(15, 0),
                waker: noop_waker(),
            },
            Alarm {
                time: now + Duration::new(5, 0),
                waker: noop_waker(),
            },
        ];
        let mut heap = BinaryHeap::new();
        for alarm in alarms {
            heap.push(alarm);
        }

        // Verify min-heap
        let mut sorted_times = Vec::new();
        while let Some(alarm) = heap.pop() {
            sorted_times.push(alarm.time);
        }
        assert_eq!(
            sorted_times,
            vec![
                now + Duration::new(5, 0),
                now + Duration::new(5, 0),
                now + Duration::new(10, 0),
                now + Duration::new(15, 0),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "runtime timeout")]
    fn test_timeout() {
        let executor = deterministic::Runner::timed(Duration::from_secs(10));
        executor.start(|context| async move {
            loop {
                context.sleep(Duration::from_secs(1)).await;
            }
        });
    }

    #[test]
    #[should_panic(expected = "cycle duration must be non-zero when timeout is set")]
    fn test_bad_timeout() {
        let cfg = Config {
            timeout: Some(Duration::default()),
            cycle: Duration::default(),
            ..Config::default()
        };
        deterministic::Runner::new(cfg);
    }

    #[test]
    fn test_recover_synced_storage_persists() {
        // Initialize the first runtime
        let executor1 = deterministic::Runner::default();
        let partition = "test_partition";
        let name = b"test_blob";
        let data = b"Hello, world!";

        // Run some tasks, sync storage, and recover the runtime
        let (state, checkpoint) = executor1.start_and_recover(|context| async move {
            let (blob, _) = context.open(partition, name).await.unwrap();
            blob.write_at(Vec::from(data), 0).await.unwrap();
            blob.sync().await.unwrap();
            context.auditor().state()
        });

        // Verify auditor state is the same
        assert_eq!(state, checkpoint.auditor.state());

        // Check that synced storage persists after recovery
        let executor = Runner::from(checkpoint);
        executor.start(|context| async move {
            let (blob, len) = context.open(partition, name).await.unwrap();
            assert_eq!(len, data.len() as u64);
            let read = blob.read_at(vec![0; data.len()], 0).await.unwrap();
            assert_eq!(read.as_ref(), data);
        });
    }

    #[test]
    fn test_recover_unsynced_storage_does_not_persist() {
        // Initialize the first runtime
        let executor = deterministic::Runner::default();
        let partition = "test_partition";
        let name = b"test_blob";
        let data = Vec::from("Hello, world!");

        // Run some tasks without syncing storage
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let context = context.clone();
            let (blob, _) = context.open(partition, name).await.unwrap();
            blob.write_at(data, 0).await.unwrap();
        });

        // Recover the runtime
        let executor = Runner::from(checkpoint);

        // Check that unsynced storage does not persist after recovery
        executor.start(|context| async move {
            let (_, len) = context.open(partition, name).await.unwrap();
            assert_eq!(len, 0);
        });
    }

    #[test]
    #[should_panic(expected = "executor still has weak references")]
    fn test_context_return() {
        // Initialize runtime
        let executor = deterministic::Runner::default();

        // Start runtime
        let context = executor.start(|context| async move {
            // Attempt to recover before the runtime has finished
            context
        });

        // Should never get this far
        drop(context);
    }

    #[test]
    fn test_default_time_zero() {
        // Initialize runtime
        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            // Check that the time is zero
            assert_eq!(
                context.current().duration_since(UNIX_EPOCH).unwrap(),
                Duration::ZERO
            );
        });
    }
}
