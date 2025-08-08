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
    utils::signal::{Signal, Stopper},
    Clock, Error, Handle, ListenerOf, METRICS_PREFIX,
};
use commonware_macros::select;
use commonware_utils::{hex, SystemTimeExt};
use futures::{
    task::{waker_ref, ArcWake},
    Future,
};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use prometheus_client::{
    encoding::text::encode,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::{Metric, Registry},
};
use rand::{prelude::SliceRandom, rngs::StdRng, CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::{
    collections::{BinaryHeap, HashMap},
    mem::replace,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{self, Poll, Waker},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::trace;

/// Map of names to blob contents.
pub type Partition = HashMap<Vec<u8>, Vec<u8>>;

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

/// Track the state of the runtime for determinism auditing.
pub struct Auditor {
    hash: Mutex<Vec<u8>>,
}

impl Default for Auditor {
    fn default() -> Self {
        Self {
            hash: Vec::new().into(),
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
        let mut hash = self.hash.lock().unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(label);
        payload(&mut hasher);

        *hash = hasher.finalize().to_vec();
    }

    /// Generate a representation of the current state of the runtime.
    ///
    /// This can be used to ensure that logic running on top
    /// of the runtime is interacting deterministically.
    pub fn state(&self) -> String {
        let hash = self.hash.lock().unwrap().clone();
        hex(&hash)
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
    partitions: Mutex<HashMap<String, Partition>>,
    shutdown: Mutex<Stopper>,
    finished: Mutex<bool>,
    recovered: Mutex<bool>,
}

enum State {
    Config(Config),
    Context(Context),
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

impl From<Context> for Runner {
    fn from(context: Context) -> Self {
        Self {
            state: State::Context(context),
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
        // Setup context (depending on how the runtime was initialized)
        let context = match self.state {
            State::Config(config) => Context::new(config),
            State::Context(context) => context,
        };

        // Pin root task to the heap
        let executor = context.executor.clone();
        let mut root = Box::pin(f(context));

        // Register the root task
        Tasks::register_root(&executor.tasks);

        // Process tasks until root task completes or progress stalls
        let mut iter = 0;
        loop {
            // Ensure we have not exceeded our deadline
            {
                let current = executor.time.lock().unwrap();
                if let Some(deadline) = executor.deadline {
                    if *current >= deadline {
                        panic!("runtime timeout");
                    }
                }
            }

            // Snapshot available tasks
            let mut tasks = executor.tasks.drain();

            // Shuffle tasks
            {
                let mut rng = executor.rng.lock().unwrap();
                tasks.shuffle(&mut *rng);
            }

            // Run all snapshotted tasks
            //
            // This approach is more efficient than randomly selecting a task one-at-a-time
            // because it ensures we don't pull the same pending task multiple times in a row (without
            // processing a different task required for other tasks to make progress).
            trace!(iter, tasks = tasks.len(), "starting loop");
            for task in tasks {
                // Record task for auditing
                executor.auditor.event(b"process_task", |hasher| {
                    hasher.update(task.id.to_be_bytes());
                    hasher.update(task.label.name().as_bytes());
                });
                trace!(id = task.id, "processing task");

                // Record task poll
                executor.metrics.task_polls.get_or_create(&task.label).inc();

                // Prepare task for polling
                let waker = waker_ref(&task);
                let mut cx = task::Context::from_waker(&waker);
                match &task.operation {
                    Operation::Root => {
                        // Poll the root task
                        if let Poll::Ready(output) = root.as_mut().poll(&mut cx) {
                            trace!(id = task.id, "task is complete");
                            *executor.finished.lock().unwrap() = true;
                            return output;
                        }
                    }
                    Operation::Work { future, completed } => {
                        // If task is completed, skip it
                        if *completed.lock().unwrap() {
                            trace!(id = task.id, "dropping already complete task");
                            continue;
                        }

                        // Poll the task
                        let mut fut = future.lock().unwrap();
                        if fut.as_mut().poll(&mut cx).is_ready() {
                            trace!(id = task.id, "task is complete");
                            *completed.lock().unwrap() = true;
                            continue;
                        }
                    }
                }

                // Try again later if task is still pending
                trace!(id = task.id, "task is still pending");
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
            if executor.tasks.len() == 0 {
                let mut skip = None;
                {
                    let sleeping = executor.sleeping.lock().unwrap();
                    if let Some(next) = sleeping.peek() {
                        if next.time > current {
                            skip = Some(next.time);
                        }
                    }
                }
                if skip.is_some() {
                    {
                        let mut time = executor.time.lock().unwrap();
                        *time = skip.unwrap();
                        current = *time;
                    }
                    trace!(now = current.epoch_millis(), "time skipped");
                }
            }

            // Wake all sleeping tasks that are ready
            let mut to_wake = Vec::new();
            let mut remaining;
            {
                let mut sleeping = executor.sleeping.lock().unwrap();
                while let Some(next) = sleeping.peek() {
                    if next.time <= current {
                        let sleeper = sleeping.pop().unwrap();
                        to_wake.push(sleeper.waker);
                    } else {
                        break;
                    }
                }
                remaining = sleeping.len();
            }
            for waker in to_wake {
                waker.wake();
            }

            // Account for remaining tasks
            remaining += executor.tasks.len();

            // If there are no tasks to run and no tasks sleeping, the executor is stalled
            // and will never finish.
            if remaining == 0 {
                panic!("runtime stalled");
            }
            iter += 1;
        }
    }
}

/// The operation that a task is performing.
enum Operation {
    Root,
    Work {
        future: Mutex<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
        completed: Mutex<bool>,
    },
}

/// A task that is being executed by the runtime.
struct Task {
    id: u128,
    label: Label,
    tasks: Weak<Tasks>,

    operation: Operation,
}

impl ArcWake for Task {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        // Upgrade the weak reference to re-enqueue this task.
        // If upgrade fails, the task queue has been dropped and no action is required.
        if let Some(tasks) = arc_self.tasks.upgrade() {
            tasks.enqueue(arc_self.clone());
        }
    }
}

/// A task queue that is used to manage the tasks that are being executed by the runtime.
struct Tasks {
    /// The current task counter.
    counter: Mutex<u128>,
    /// The queue of tasks that are waiting to be executed.
    queue: Mutex<Vec<Arc<Task>>>,
    /// Indicates whether the root task has been registered.
    root_registered: Mutex<bool>,
}

impl Tasks {
    /// Create a new task queue.
    fn new() -> Self {
        Self {
            counter: Mutex::new(0),
            queue: Mutex::new(Vec::new()),
            root_registered: Mutex::new(false),
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
        {
            let mut registered = arc_self.root_registered.lock().unwrap();
            assert!(!*registered, "root already registered");
            *registered = true;
        }
        let id = arc_self.increment();
        let mut queue = arc_self.queue.lock().unwrap();
        queue.push(Arc::new(Task {
            id,
            label: Label::root(),
            tasks: Arc::downgrade(arc_self),
            operation: Operation::Root,
        }));
    }

    /// Register a new task to be executed.
    fn register_work(
        arc_self: &Arc<Self>,
        label: Label,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) {
        let id = arc_self.increment();
        let mut queue = arc_self.queue.lock().unwrap();
        queue.push(Arc::new(Task {
            id,
            label,
            tasks: Arc::downgrade(arc_self),
            operation: Operation::Work {
                future: Mutex::new(future),
                completed: Mutex::new(false),
            },
        }));
    }

    /// Enqueue an already registered task to be executed.
    fn enqueue(&self, task: Arc<Task>) {
        let mut queue = self.queue.lock().unwrap();
        queue.push(task);
    }

    /// Dequeue all tasks that are ready to execute.
    fn drain(&self) -> Vec<Arc<Task>> {
        let mut queue = self.queue.lock().unwrap();
        let len = queue.len();
        replace(&mut *queue, Vec::with_capacity(len))
    }

    /// Get the number of tasks in the queue.
    fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
}

type Network = MeteredNetwork<AuditedNetwork<DeterministicNetwork>>;

/// Implementation of [crate::Spawner], [crate::Clock],
/// [crate::Network], and [crate::Storage] for the `deterministic`
/// runtime.
pub struct Context {
    name: String,
    spawned: bool,
    executor: Arc<Executor>,
    network: Arc<Network>,
    storage: MeteredStorage<AuditedStorage<MemStorage>>,
}

impl Default for Context {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl Context {
    pub fn new(cfg: Config) -> Self {
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
            partitions: Mutex::new(HashMap::new()),
            shutdown: Mutex::new(Stopper::default()),
            finished: Mutex::new(false),
            recovered: Mutex::new(false),
        });

        Context {
            name: String::new(),
            spawned: false,
            executor: executor.clone(),
            network: Arc::new(network),
            storage,
        }
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
    pub fn recover(self) -> Self {
        // Ensure we are finished
        if !*self.executor.finished.lock().unwrap() {
            panic!("execution is not finished");
        }

        // Ensure runtime has not already been recovered
        {
            let mut recovered = self.executor.recovered.lock().unwrap();
            if *recovered {
                panic!("runtime has already been recovered");
            }
            *recovered = true;
        }

        // Rebuild metrics
        let mut registry = Registry::default();
        let runtime_registry = registry.sub_registry_with_prefix(METRICS_PREFIX);
        let metrics = Arc::new(Metrics::init(runtime_registry));

        // Copy state
        let auditor = self.executor.auditor.clone();
        let network = AuditedNetwork::new(DeterministicNetwork::default(), auditor.clone());
        let network = MeteredNetwork::new(network, runtime_registry);

        let executor = Arc::new(Executor {
            // Copied from the current runtime
            cycle: self.executor.cycle,
            deadline: self.executor.deadline,
            auditor: auditor.clone(),
            rng: Mutex::new(self.executor.rng.lock().unwrap().clone()),
            time: Mutex::new(*self.executor.time.lock().unwrap()),
            partitions: Mutex::new(self.executor.partitions.lock().unwrap().clone()),

            // New state for the new runtime
            registry: Mutex::new(registry),
            metrics: metrics.clone(),
            tasks: Arc::new(Tasks::new()),
            sleeping: Mutex::new(BinaryHeap::new()),
            shutdown: Mutex::new(Stopper::default()),
            finished: Mutex::new(false),
            recovered: Mutex::new(false),
        });
        Self {
            name: String::new(),
            spawned: false,
            executor,
            network: Arc::new(network),
            storage: self.storage,
        }
    }

    pub fn auditor(&self) -> &Auditor {
        &self.executor.auditor
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
        }
    }
}

impl crate::Spawner for Context {
    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a context only spawns one task
        assert!(!self.spawned, "already spawned");

        // Get metrics
        let (label, gauge) = spawn_metrics!(self, future);

        // Set up the task
        let executor = self.executor.clone();
        let future = f(self);
        let (f, handle) = Handle::init_future(future, gauge, false);

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
        let (label, gauge) = spawn_metrics!(self, future);

        // Set up the task
        let executor = self.executor.clone();
        move |f: F| {
            let (f, handle) = Handle::init_future(f, gauge, false);

            // Spawn the task
            Tasks::register_work(&executor.tasks, label, Box::pin(f));
            handle
        }
    }

    fn spawn_blocking<F, T>(self, dedicated: bool, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> T + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a context only spawns one task
        assert!(!self.spawned, "already spawned");

        // Get metrics
        let (label, gauge) = spawn_metrics!(self, blocking, dedicated);

        // Initialize the blocking task
        let executor = self.executor.clone();
        let (f, handle) = Handle::init_blocking(|| f(self), gauge, false);

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
        let (label, gauge) = spawn_metrics!(self, blocking, dedicated);

        // Set up the task
        let executor = self.executor.clone();
        move |f: F| {
            let (f, handle) = Handle::init_blocking(f, gauge, false);

            // Spawn the task
            let f = async move { f() };
            Tasks::register_work(&executor.tasks, label, Box::pin(f));
            handle
        }
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        self.executor.auditor.event(b"stop", |hasher| {
            hasher.update(value.to_be_bytes());
        });
        let stop_resolved = {
            let mut shutdown = self.executor.shutdown.lock().unwrap();
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
        self.executor.auditor.event(b"stopped", |_| {});
        self.executor.shutdown.lock().unwrap().stopped()
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
        self.executor.auditor.event(b"register", |hasher| {
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
        self.executor
            .registry
            .lock()
            .unwrap()
            .register(prefixed_name, help, metric)
    }

    fn encode(&self) -> String {
        self.executor.auditor.event(b"encode", |_| {});
        let mut buffer = String::new();
        encode(&mut buffer, &self.executor.registry.lock().unwrap()).expect("encoding failed");
        buffer
    }
}

struct Sleeper {
    executor: Arc<Executor>,
    time: SystemTime,
    registered: bool,
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
        {
            let current_time = *self.executor.time.lock().unwrap();
            if current_time >= self.time {
                return Poll::Ready(());
            }
        }
        if !self.registered {
            self.registered = true;
            self.executor.sleeping.lock().unwrap().push(Alarm {
                time: self.time,
                waker: cx.waker().clone(),
            });
        }
        Poll::Pending
    }
}

impl Clock for Context {
    fn current(&self) -> SystemTime {
        *self.executor.time.lock().unwrap()
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
        self.executor.auditor.event(b"rand", |hasher| {
            hasher.update(b"next_u32");
        });
        self.executor.rng.lock().unwrap().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.executor.auditor.event(b"rand", |hasher| {
            hasher.update(b"next_u64");
        });
        self.executor.rng.lock().unwrap().next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.executor.auditor.event(b"rand", |hasher| {
            hasher.update(b"fill_bytes");
        });
        self.executor.rng.lock().unwrap().fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.executor.auditor.event(b"rand", |hasher| {
            hasher.update(b"try_fill_bytes");
        });
        self.executor.rng.lock().unwrap().try_fill_bytes(dest)
    }
}

impl CryptoRng for Context {}

impl crate::Storage for Context {
    type Blob = <MeteredStorage<AuditedStorage<MemStorage>> as crate::Storage>::Blob;

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
        let (context, state) = executor1.start(|context| async move {
            let (blob, _) = context.open(partition, name).await.unwrap();
            blob.write_at(Vec::from(data), 0).await.unwrap();
            blob.sync().await.unwrap();
            let state = context.auditor().state();
            (context, state)
        });
        let recovered_context = context.recover();

        // Verify auditor state is the same
        assert_eq!(state, recovered_context.auditor().state());

        // Check that synced storage persists after recovery
        let executor = Runner::from(recovered_context);
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
        let context = executor.start(|context| async move {
            let context = context.clone();
            let (blob, _) = context.open(partition, name).await.unwrap();
            blob.write_at(data, 0).await.unwrap();
            // Intentionally do not call sync() here
            context
        });

        // Recover the runtime
        let context = context.recover();
        let executor = Runner::from(context);

        // Check that unsynced storage does not persist after recovery
        executor.start(|context| async move {
            let (_, len) = context.open(partition, name).await.unwrap();
            assert_eq!(len, 0);
        });
    }

    #[test]
    #[should_panic(expected = "execution is not finished")]
    fn test_recover_before_finish_panics() {
        // Initialize runtime
        let executor = deterministic::Runner::default();

        // Start runtime
        executor.start(|context| async move {
            // Attempt to recover before the runtime has finished
            context.recover();
        });
    }

    #[test]
    #[should_panic(expected = "runtime has already been recovered")]
    fn test_recover_twice_panics() {
        // Initialize runtime
        let executor = deterministic::Runner::default();

        // Finish runtime
        let context = executor.start(|context| async move { context });

        // Recover for the first time
        let cloned_context = context.clone();
        context.recover();

        // Attempt to recover again using the same context
        cloned_context.recover();
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
