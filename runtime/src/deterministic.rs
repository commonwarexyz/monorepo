//! A deterministic runtime that randomly selects tasks to run based on a seed
//!
//! # Panics
//!
//! Unless configured otherwise, any task panic will lead to a runtime panic.
//!
//! # External Processes
//!
//! When testing an application that interacts with some external process, it can appear to
//! the runtime that progress has stalled because no pending tasks can make progress and/or
//! that futures resolve at variable latency (which in turn triggers non-deterministic execution).
//!
//! To support such applications, the runtime can be built with the `external` feature to both
//! sleep for each [Config::cycle] (opting to wait if all futures are pending) and to constrain
//! the resolution latency of any future (with `pace()`).
//!
//! **Applications that do not interact with external processes (or are able to mock them) should never
//! need to enable this feature. It is commonly used when testing consensus with external execution environments
//! that use their own runtime (but are deterministic over some set of inputs).**
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
        supervision::Tree,
        Panicker,
    },
    Clock, Error, Execution, Handle, ListenerOf, Panicked, METRICS_PREFIX,
};
#[cfg(feature = "external")]
use crate::{Blocker, Pacer};
use commonware_codec::Encode;
use commonware_macros::select;
use commonware_utils::{hex, time::SYSTEM_TIME_PRECISION, SystemTimeExt};
#[cfg(feature = "external")]
use futures::task::noop_waker;
use futures::{
    future::BoxFuture,
    task::{waker, ArcWake},
    Future, FutureExt,
};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
#[cfg(feature = "external")]
use pin_project::pin_project;
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::{Metric, Registry},
};
use rand::{prelude::SliceRandom, rngs::StdRng, CryptoRng, RngCore, SeedableRng};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BinaryHeap, HashMap},
    mem::{replace, take},
    net::{IpAddr, SocketAddr},
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{self, Poll, Waker},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{info_span, trace, Instrument};

#[derive(Debug)]
struct Metrics {
    iterations: Counter,
    tasks_spawned: Family<Label, Counter>,
    tasks_running: Family<Label, Gauge>,
    task_polls: Family<Label, Counter>,

    network_bandwidth: Counter,
}

impl Metrics {
    pub fn init(registry: &mut Registry) -> Self {
        let metrics = Self {
            iterations: Counter::default(),
            task_polls: Family::default(),
            tasks_spawned: Family::default(),
            tasks_running: Family::default(),
            network_bandwidth: Counter::default(),
        };
        registry.register(
            "iterations",
            "Total number of iterations",
            metrics.iterations.clone(),
        );
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

    /// Whether spawned tasks should catch panics instead of propagating them.
    catch_panics: bool,
}

impl Config {
    /// Returns a new [Config] with default values.
    pub const fn new() -> Self {
        Self {
            seed: 42,
            cycle: Duration::from_millis(1),
            timeout: None,
            catch_panics: false,
        }
    }

    // Setters
    /// See [Config]
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }
    /// See [Config]
    pub const fn with_cycle(mut self, cycle: Duration) -> Self {
        self.cycle = cycle;
        self
    }
    /// See [Config]
    pub const fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }
    /// See [Config]
    pub const fn with_catch_panics(mut self, catch_panics: bool) -> Self {
        self.catch_panics = catch_panics;
        self
    }

    // Getters
    /// See [Config]
    pub const fn seed(&self) -> u64 {
        self.seed
    }
    /// See [Config]
    pub const fn cycle(&self) -> Duration {
        self.cycle
    }
    /// See [Config]
    pub const fn timeout(&self) -> Option<Duration> {
        self.timeout
    }
    /// See [Config]
    pub const fn catch_panics(&self) -> bool {
        self.catch_panics
    }

    /// Assert that the configuration is valid.
    pub fn assert(&self) {
        assert!(
            self.cycle != Duration::default() || self.timeout.is_none(),
            "cycle duration must be non-zero when timeout is set",
        );
        assert!(
            self.cycle >= SYSTEM_TIME_PRECISION,
            "cycle duration must be greater than or equal to system time precision"
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
    panicker: Panicker,
    dns: Mutex<HashMap<String, Vec<IpAddr>>>,
}

impl Executor {
    /// Advance simulated time by [Config::cycle].
    ///
    /// When built with the `external` feature, sleep for [Config::cycle] to let
    /// external processes make progress.
    fn advance_time(&self) -> SystemTime {
        #[cfg(feature = "external")]
        std::thread::sleep(self.cycle);

        let mut time = self.time.lock().unwrap();
        *time = time
            .checked_add(self.cycle)
            .expect("executor time overflowed");
        let now = *time;
        trace!(now = now.epoch_millis(), "time advanced");
        now
    }

    /// When idle, jump directly to the next actionable time.
    ///
    /// When built with the `external` feature, never skip ahead (to ensure we poll all pending tasks
    /// every [Config::cycle]).
    fn skip_idle_time(&self, current: SystemTime) -> SystemTime {
        if cfg!(feature = "external") || self.tasks.ready() != 0 {
            return current;
        }

        let mut skip_until = None;
        {
            let sleeping = self.sleeping.lock().unwrap();
            if let Some(next) = sleeping.peek() {
                if next.time > current {
                    skip_until = Some(next.time);
                }
            }
        }

        skip_until.map_or(current, |deadline| {
            let mut time = self.time.lock().unwrap();
            *time = deadline;
            let now = *time;
            trace!(now = now.epoch_millis(), "time skipped");
            now
        })
    }

    /// Wake any sleepers whose deadlines have elapsed.
    fn wake_ready_sleepers(&self, current: SystemTime) {
        let mut sleeping = self.sleeping.lock().unwrap();
        while let Some(next) = sleeping.peek() {
            if next.time <= current {
                let sleeper = sleeping.pop().unwrap();
                sleeper.waker.wake();
            } else {
                break;
            }
        }
    }

    /// Ensure the runtime is making progress.
    ///
    /// When built with the `external` feature, always poll pending tasks after the passage of time.
    fn assert_liveness(&self) {
        if cfg!(feature = "external") || self.tasks.ready() != 0 {
            return;
        }

        panic!("runtime stalled");
    }
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
    dns: Mutex<HashMap<String, Vec<IpAddr>>>,
    catch_panics: bool,
}

impl Checkpoint {
    /// Get a reference to the [Auditor].
    pub fn auditor(&self) -> Arc<Auditor> {
        self.auditor.clone()
    }
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
        Self {
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
        let (context, executor, panicked) = match self.state {
            State::Config(config) => Context::new(config),
            State::Checkpoint(checkpoint) => Context::recover(checkpoint),
        };

        // Pin root task to the heap
        let storage = context.storage.clone();
        let mut root = Box::pin(panicked.interrupt(f(context)));

        // Register the root task
        Tasks::register_root(&executor.tasks);

        // Process tasks until root task completes or progress stalls.
        // Wrap the loop in catch_unwind to ensure task cleanup runs even if the loop or a task panics.
        let result = catch_unwind(AssertUnwindSafe(|| loop {
            // Ensure we have not exceeded our deadline
            {
                let current = executor.time.lock().unwrap();
                if let Some(deadline) = executor.deadline {
                    if *current >= deadline {
                        // Drop the lock before panicking to avoid mutex poisoning.
                        drop(current);
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
            trace!(
                iter = executor.metrics.iterations.get(),
                tasks = queue.len(),
                "starting loop"
            );
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

            // Advance time (skipping ahead if no tasks are ready yet)
            let mut current = executor.advance_time();
            current = executor.skip_idle_time(current);

            // Wake sleepers and ensure we continue to make progress
            executor.wake_ready_sleepers(current);
            executor.assert_liveness();

            // Record that we completed another iteration of the event loop.
            executor.metrics.iterations.inc();
        }));

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

        // Drop the root task to release any Context references it may still hold.
        // This is necessary when the loop exits early (e.g., timeout) while the
        // root future is still Pending and holds captured variables with Context references.
        drop(root);

        // Assert the context doesn't escape the start() function (behavior
        // is undefined in this case)
        assert!(
            Arc::weak_count(&executor) == 0,
            "executor still has weak references"
        );

        // Handle the result — resume the original panic after cleanup if one was caught.
        let output = match result {
            Ok(output) => output,
            Err(payload) => resume_unwind(payload),
        };

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
            dns: executor.dns,
            catch_panics: executor.panicker.catch(),
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
    const fn new() -> Self {
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
    executor: Weak<Executor>,
    network: Arc<Network>,
    storage: Arc<Storage>,
    tree: Arc<Tree>,
    execution: Execution,
    instrumented: bool,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        let (child, _) = Tree::child(&self.tree);
        Self {
            name: self.name.clone(),
            executor: self.executor.clone(),
            network: self.network.clone(),
            storage: self.storage.clone(),

            tree: child,
            execution: Execution::default(),
            instrumented: false,
        }
    }
}

impl Context {
    fn new(cfg: Config) -> (Self, Arc<Executor>, Panicked) {
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

        // Initialize panicker
        let (panicker, panicked) = Panicker::new(cfg.catch_panics);

        let executor = Arc::new(Executor {
            registry: Mutex::new(registry),
            cycle: cfg.cycle,
            deadline,
            metrics,
            auditor,
            rng: Mutex::new(StdRng::seed_from_u64(cfg.seed)),
            time: Mutex::new(start_time),
            tasks: Arc::new(Tasks::new()),
            sleeping: Mutex::new(BinaryHeap::new()),
            shutdown: Mutex::new(Stopper::default()),
            panicker,
            dns: Mutex::new(HashMap::new()),
        });

        (
            Self {
                name: String::new(),
                executor: Arc::downgrade(&executor),
                network: Arc::new(network),
                storage: Arc::new(storage),
                tree: Tree::root(),
                execution: Execution::default(),
                instrumented: false,
            },
            executor,
            panicked,
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
    fn recover(checkpoint: Checkpoint) -> (Self, Arc<Executor>, Panicked) {
        // Rebuild metrics
        let mut registry = Registry::default();
        let runtime_registry = registry.sub_registry_with_prefix(METRICS_PREFIX);
        let metrics = Arc::new(Metrics::init(runtime_registry));

        // Copy state
        let network =
            AuditedNetwork::new(DeterministicNetwork::default(), checkpoint.auditor.clone());
        let network = MeteredNetwork::new(network, runtime_registry);

        // Initialize panicker
        let (panicker, panicked) = Panicker::new(checkpoint.catch_panics);

        let executor = Arc::new(Executor {
            // Copied from the checkpoint
            cycle: checkpoint.cycle,
            deadline: checkpoint.deadline,
            auditor: checkpoint.auditor,
            rng: checkpoint.rng,
            time: checkpoint.time,
            dns: checkpoint.dns,

            // New state for the new runtime
            registry: Mutex::new(registry),
            metrics,
            tasks: Arc::new(Tasks::new()),
            sleeping: Mutex::new(BinaryHeap::new()),
            shutdown: Mutex::new(Stopper::default()),
            panicker,
        });
        (
            Self {
                name: String::new(),
                executor: Arc::downgrade(&executor),
                network: Arc::new(network),
                storage: checkpoint.storage,
                tree: Tree::root(),
                execution: Execution::default(),
                instrumented: false,
            },
            executor,
            panicked,
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

    /// Register a DNS mapping for a hostname.
    ///
    /// If `addrs` is `None`, the mapping is removed.
    /// If `addrs` is `Some`, the mapping is added or updated.
    pub fn resolver_register(&self, host: impl Into<String>, addrs: Option<Vec<IpAddr>>) {
        // Update the auditor
        let executor = self.executor();
        let host = host.into();
        executor.auditor.event(b"resolver_register", |hasher| {
            hasher.update(host.as_bytes());
            hasher.update(addrs.encode());
        });

        // Update the DNS mapping
        let mut dns = executor.dns.lock().unwrap();
        match addrs {
            Some(addrs) => {
                dns.insert(host, addrs);
            }
            None => {
                dns.remove(&host);
            }
        }
    }
}

impl crate::Spawner for Context {
    fn dedicated(mut self) -> Self {
        self.execution = Execution::Dedicated;
        self
    }

    fn shared(mut self, blocking: bool) -> Self {
        self.execution = Execution::Shared(blocking);
        self
    }

    fn instrumented(mut self) -> Self {
        self.instrumented = true;
        self
    }

    fn spawn<F, Fut, T>(mut self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Get metrics
        let (label, metric) = spawn_metrics!(self);

        // Track supervision before resetting configuration
        let parent = Arc::clone(&self.tree);
        let is_instrumented = self.instrumented;
        self.execution = Execution::default();
        self.instrumented = false;
        let (child, aborted) = Tree::child(&parent);
        if aborted {
            return Handle::closed(metric);
        }
        self.tree = child;

        // Spawn the task (we don't care about Model)
        let executor = self.executor();
        let future: BoxFuture<'_, T> = if is_instrumented {
            f(self)
                .instrument(info_span!(parent: None, "task", name = %label.name()))
                .boxed()
        } else {
            f(self).boxed()
        };
        let (f, handle) = Handle::init(
            future,
            metric,
            executor.panicker.clone(),
            Arc::clone(&parent),
        );
        Tasks::register_work(&executor.tasks, label, Box::pin(f));

        // Register the task on the parent
        if let Some(aborter) = handle.aborter() {
            parent.register(aborter);
        }

        handle
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
        let timeout_future = timeout.map_or_else(
            || futures::future::Either::Right(futures::future::pending()),
            |duration| futures::future::Either::Left(self.sleep(duration)),
        );
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
            ..self.clone()
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

/// A future that resolves when a given target time is reached.
///
/// If the future is not ready at the target time, the future is blocked until the target time is reached.
#[cfg(feature = "external")]
#[pin_project]
struct Waiter<F: Future> {
    executor: Weak<Executor>,
    target: SystemTime,
    #[pin]
    future: F,
    ready: Option<F::Output>,
    started: bool,
    registered: bool,
}

#[cfg(feature = "external")]
impl<F> Future for Waiter<F>
where
    F: Future + Send,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        // Poll once with a noop waker so the future can register interest or start work
        // without being able to wake this task before the sampled delay expires. Any ready
        // value is cached and only released after the clock reaches `self.target`.
        if !*this.started {
            *this.started = true;
            let waker = noop_waker();
            let mut cx_noop = task::Context::from_waker(&waker);
            if let Poll::Ready(value) = this.future.as_mut().poll(&mut cx_noop) {
                *this.ready = Some(value);
            }
        }

        // Only allow the task to progress once the sampled delay has elapsed.
        let executor = this.executor.upgrade().expect("executor already dropped");
        let current_time = *executor.time.lock().unwrap();
        if current_time < *this.target {
            // Register exactly once with the deterministic sleeper queue so the executor
            // wakes us once the clock reaches the scheduled target time.
            if !*this.registered {
                *this.registered = true;
                executor.sleeping.lock().unwrap().push(Alarm {
                    time: *this.target,
                    waker: cx.waker().clone(),
                });
            }
            return Poll::Pending;
        }

        // If the underlying future completed during the noop pre-poll, surface the cached value.
        if let Some(value) = this.ready.take() {
            return Poll::Ready(value);
        }

        // Block the current thread until the future reschedules itself, keeping polling
        // deterministic with respect to executor time.
        let blocker = Blocker::new();
        loop {
            let waker = waker(blocker.clone());
            let mut cx_block = task::Context::from_waker(&waker);
            match this.future.as_mut().poll(&mut cx_block) {
                Poll::Ready(value) => {
                    break Poll::Ready(value);
                }
                Poll::Pending => blocker.wait(),
            }
        }
    }
}

#[cfg(feature = "external")]
impl Pacer for Context {
    fn pace<'a, F, T>(&'a self, latency: Duration, future: F) -> impl Future<Output = T> + Send + 'a
    where
        F: Future<Output = T> + Send + 'a,
        T: Send + 'a,
    {
        // Compute target time
        let target = self
            .executor()
            .time
            .lock()
            .unwrap()
            .checked_add(latency)
            .expect("overflow when setting wake time");

        Waiter {
            executor: self.executor.clone(),
            target,
            future,
            ready: None,
            started: false,
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

impl crate::Resolver for Context {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, Error> {
        // Get the record
        let executor = self.executor();
        let dns = executor.dns.lock().unwrap();
        let result = dns.get(host).cloned();
        drop(dns);

        // Update the auditor
        executor.auditor.event(b"resolve", |hasher| {
            hasher.update(host.as_bytes());
            hasher.update(result.encode());
        });
        result.ok_or_else(|| Error::ResolveFailed(host.to_string()))
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
    #[cfg(feature = "external")]
    use crate::FutureExt;
    #[cfg(feature = "external")]
    use crate::Spawner;
    use crate::{
        deterministic, reschedule, utils::run_tasks, Blob, Metrics, Resolver, Runner as _, Storage,
    };
    use commonware_macros::test_traced;
    #[cfg(not(feature = "external"))]
    use futures::future::pending;
    #[cfg(feature = "external")]
    use futures::{channel::mpsc, SinkExt, StreamExt};
    use futures::{channel::oneshot, task::noop_waker};

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
    #[should_panic(
        expected = "cycle duration must be greater than or equal to system time precision"
    )]
    fn test_bad_cycle() {
        let cfg = Config {
            cycle: SYSTEM_TIME_PRECISION - Duration::from_nanos(1),
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
    #[should_panic(expected = "goodbye")]
    fn test_recover_panic_handling() {
        // Initialize the first runtime
        let executor1 = deterministic::Runner::default();
        let (_, checkpoint) = executor1.start_and_recover(|_| async move {
            reschedule().await;
        });

        // Ensure that panic setting is preserved
        let executor = Runner::from(checkpoint);
        executor.start(|_| async move {
            panic!("goodbye");
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
    fn test_recover_dns_mappings_persist() {
        // Initialize the first runtime
        let executor = deterministic::Runner::default();
        let host = "example.com";
        let addrs = vec![
            IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2)),
        ];

        // Register DNS mapping and recover the runtime
        let (state, checkpoint) = executor.start_and_recover({
            let addrs = addrs.clone();
            |context| async move {
                context.resolver_register(host, Some(addrs));
                context.auditor().state()
            }
        });

        // Verify auditor state is the same
        assert_eq!(state, checkpoint.auditor.state());

        // Check that DNS mappings persist after recovery
        let executor = Runner::from(checkpoint);
        executor.start(move |context| async move {
            let resolved = context.resolve(host).await.unwrap();
            assert_eq!(resolved, addrs);
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

    #[cfg(not(feature = "external"))]
    #[test]
    #[should_panic(expected = "runtime stalled")]
    fn test_stall() {
        // Initialize runtime
        let executor = deterministic::Runner::default();

        // Start runtime
        executor.start(|_| async move {
            pending::<()>().await;
        });
    }

    #[cfg(not(feature = "external"))]
    #[test]
    #[should_panic(expected = "runtime stalled")]
    fn test_external_simulated() {
        // Initialize runtime
        let executor = deterministic::Runner::default();

        // Create a thread that waits for 1 second
        let (tx, rx) = oneshot::channel();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(1));
            tx.send(()).unwrap();
        });

        // Start runtime
        executor.start(|_| async move {
            rx.await.unwrap();
        });
    }

    #[cfg(feature = "external")]
    #[test]
    fn test_external_realtime() {
        // Initialize runtime
        let executor = deterministic::Runner::default();

        // Create a thread that waits for 1 second
        let (tx, rx) = oneshot::channel();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(1));
            tx.send(()).unwrap();
        });

        // Start runtime
        executor.start(|_| async move {
            rx.await.unwrap();
        });
    }

    #[cfg(feature = "external")]
    #[test]
    fn test_external_realtime_variable() {
        // Initialize runtime
        let executor = deterministic::Runner::default();

        // Start runtime
        executor.start(|context| async move {
            // Initialize test
            let start_real = SystemTime::now();
            let start_sim = context.current();
            let (first_tx, first_rx) = oneshot::channel();
            let (second_tx, second_rx) = oneshot::channel();
            let (mut results_tx, mut results_rx) = mpsc::channel(2);

            // Create a thread that waits for 1 second
            let first_wait = Duration::from_secs(1);
            std::thread::spawn(move || {
                std::thread::sleep(first_wait);
                first_tx.send(()).unwrap();
            });

            // Create a thread
            std::thread::spawn(move || {
                std::thread::sleep(Duration::ZERO);
                second_tx.send(()).unwrap();
            });

            // Wait for a delay sampled before the external send occurs
            let first = context.clone().spawn({
                let mut results_tx = results_tx.clone();
                move |context| async move {
                    first_rx.pace(&context, Duration::ZERO).await.unwrap();
                    let elapsed_real = SystemTime::now().duration_since(start_real).unwrap();
                    assert!(elapsed_real > first_wait);
                    let elapsed_sim = context.current().duration_since(start_sim).unwrap();
                    assert!(elapsed_sim < first_wait);
                    results_tx.send(1).await.unwrap();
                }
            });

            // Wait for a delay sampled after the external send occurs
            let second = context.clone().spawn(move |context| async move {
                second_rx.pace(&context, first_wait).await.unwrap();
                let elapsed_real = SystemTime::now().duration_since(start_real).unwrap();
                assert!(elapsed_real >= first_wait);
                let elapsed_sim = context.current().duration_since(start_sim).unwrap();
                assert!(elapsed_sim >= first_wait);
                results_tx.send(2).await.unwrap();
            });

            // Wait for both tasks to complete
            second.await.unwrap();
            first.await.unwrap();

            // Ensure order is correct
            let mut results = Vec::new();
            for _ in 0..2 {
                results.push(results_rx.next().await.unwrap());
            }
            assert_eq!(results, vec![1, 2]);
        });
    }

    #[cfg(not(feature = "external"))]
    #[test]
    fn test_simulated_skip() {
        // Initialize runtime
        let executor = deterministic::Runner::default();

        // Start runtime
        executor.start(|context| async move {
            context.sleep(Duration::from_secs(1)).await;

            // Check if we skipped
            let metrics = context.encode();
            let iterations = metrics
                .lines()
                .find_map(|line| {
                    line.strip_prefix("runtime_iterations_total ")
                        .and_then(|value| value.trim().parse::<u64>().ok())
                })
                .expect("missing runtime_iterations_total metric");
            assert!(iterations < 10);
        });
    }

    #[cfg(feature = "external")]
    #[test]
    fn test_realtime_no_skip() {
        // Initialize runtime
        let executor = deterministic::Runner::default();

        // Start runtime
        executor.start(|context| async move {
            context.sleep(Duration::from_secs(1)).await;

            // Check if we skipped
            let metrics = context.encode();
            let iterations = metrics
                .lines()
                .find_map(|line| {
                    line.strip_prefix("runtime_iterations_total ")
                        .and_then(|value| value.trim().parse::<u64>().ok())
                })
                .expect("missing runtime_iterations_total metric");
            assert!(iterations > 500);
        });
    }
}
