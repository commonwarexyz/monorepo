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
    future::AbortHandle,
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

impl Drop for Executor {
    fn drop(&mut self) {
        // Force shutdown in a specific order to break all circular references

        // Step 1: Clear sleeping tasks to drop any wakers
        self.sleeping.lock().unwrap().clear();

        // Step 2: Mark executor as finished to prevent new tasks
        *self.finished.lock().unwrap() = true;

        // Step 3: Shutdown all tasks to break circular references
        self.tasks.shutdown();

        // Step 4: Clear all partitions
        self.partitions.lock().unwrap().clear();

        // Note: If this Drop is not being called, it means there are still
        // Arc<Executor> references being held somewhere, likely by contexts
        // captured in futures or wakers stored in channels.
    }
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
        let executor = context.exec();
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

            // Clean up completed tasks periodically to prevent memory accumulation
            // Run more frequently (every 10 iterations) to prevent memory buildup
            if iter % 10 == 0 {
                executor.tasks.cleanup_completed();
            }
            
            // Also compact the sleeping tasks heap periodically
            // BinaryHeap doesn't expose capacity, so we periodically rebuild it
            // to ensure it doesn't hold onto excessive memory
            if iter % 100 == 0 {
                let mut sleeping = executor.sleeping.lock().unwrap();
                let items: Vec<_> = sleeping.drain().collect();
                *sleeping = BinaryHeap::from(items);
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
                        let mut fut_opt = future.lock().unwrap();
                        if let Some(ref mut fut) = *fut_opt {
                            if fut.as_mut().poll(&mut cx).is_ready() {
                                trace!(id = task.id, "task is complete");
                                *completed.lock().unwrap() = true;
                                // Drop the future to free memory
                                *fut_opt = None;
                                continue;
                            }
                        } else {
                            // Future was already dropped, skip
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
        future: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>>,
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
    /// All tasks that have been created (for cleanup on shutdown).
    all_tasks: Mutex<Vec<Weak<Task>>>,
    /// Indicates whether the root task has been registered.
    root_registered: Mutex<bool>,
}

impl Tasks {
    /// Create a new task queue.
    fn new() -> Self {
        Self {
            counter: Mutex::new(0),
            queue: Mutex::new(Vec::new()),
            all_tasks: Mutex::new(Vec::new()),
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
        let task = Arc::new(Task {
            id,
            label: Label::root(),
            tasks: Arc::downgrade(arc_self),
            operation: Operation::Root,
        });

        // Track this task for cleanup
        arc_self
            .all_tasks
            .lock()
            .unwrap()
            .push(Arc::downgrade(&task));

        // Add to queue
        arc_self.queue.lock().unwrap().push(task);
    }

    /// Register a new task to be executed.
    fn register_work(
        arc_self: &Arc<Self>,
        label: Label,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) {
        let id = arc_self.increment();
        let task = Arc::new(Task {
            id,
            label,
            tasks: Arc::downgrade(arc_self),
            operation: Operation::Work {
                future: Mutex::new(Some(future)),
                completed: Mutex::new(false),
            },
        });

        // Track this task for cleanup
        arc_self
            .all_tasks
            .lock()
            .unwrap()
            .push(Arc::downgrade(&task));

        // Add to queue
        arc_self.queue.lock().unwrap().push(task);
    }

    /// Enqueue an already registered task to be executed.
    fn enqueue(&self, task: Arc<Task>) {
        // Don't enqueue completed tasks to prevent memory accumulation
        if let Operation::Work { completed, .. } = &task.operation {
            if *completed.lock().unwrap() {
                return;
            }
        }

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

    /// Remove completed tasks from the queue to free memory.
    /// This is called periodically during execution to prevent memory accumulation.
    fn cleanup_completed(&self) {
        let mut queue = self.queue.lock().unwrap();

        // Filter out completed tasks and drop their futures immediately
        queue.retain(|task| {
            match &task.operation {
                Operation::Root => true, // Keep root task
                Operation::Work { completed, future } => {
                    let is_completed = *completed.lock().unwrap();
                    if is_completed {
                        // Drop the future to free memory
                        *future.lock().unwrap() = None;
                        false // Remove from queue
                    } else {
                        true // Keep in queue
                    }
                }
            }
        });
        drop(queue);

        // Clean up all_tasks more aggressively
        let mut all_tasks = self.all_tasks.lock().unwrap();
        
        // First, drop futures for any completed tasks
        for weak_task in all_tasks.iter() {
            if let Some(task) = weak_task.upgrade() {
                if let Operation::Work { completed, future } = &task.operation {
                    if *completed.lock().unwrap() {
                        *future.lock().unwrap() = None;
                    }
                }
            }
        }
        
        // Then remove all weak references that can't be upgraded
        // This includes completed tasks and tasks that have been dropped
        all_tasks.retain(|weak_task| weak_task.strong_count() > 0);
        
        // Shrink the vector to free unused capacity
        all_tasks.shrink_to_fit();
    }

    /// Forcibly shutdown all tasks and clear the queue.
    /// This is called when the executor is dropped to prevent memory leaks.
    fn shutdown(&self) {
        // Step 1: Clear the queue first to drop Arc<Task> references
        // This is important because tasks in the queue hold strong references
        self.queue.lock().unwrap().clear();
        
        // Step 2: Now mark all tasks as completed and drop their futures
        // We do this after clearing the queue to avoid any re-enqueueing
        {
            let all_tasks = self.all_tasks.lock().unwrap();
            for weak_task in all_tasks.iter() {
                if let Some(task) = weak_task.upgrade() {
                    // This means there's still a strong reference somewhere
                    // Force-drop the future to break circular references
                    if let Operation::Work { future, completed } = &task.operation {
                        *completed.lock().unwrap() = true;
                        *future.lock().unwrap() = None;
                    }
                }
            }
        }
        
        // Step 3: Clear all tracked weak references
        // This frees the memory used by the weak reference vector
        self.all_tasks.lock().unwrap().clear();
        
        // Step 4: Reset all state to initial values
        *self.counter.lock().unwrap() = 0;
        *self.root_registered.lock().unwrap() = false;
    }
}

type Network = MeteredNetwork<AuditedNetwork<DeterministicNetwork>>;

/// Implementation of [crate::Spawner], [crate::Clock],
/// [crate::Network], and [crate::Storage] for the `deterministic`
/// runtime.
pub struct Context {
    name: String,
    spawned: bool,
    // Weak reference to break cycles when contexts are captured by futures
    executor: Weak<Executor>,
    // Root contexts hold a strong reference so recovery works after start() returns
    owner: Option<Arc<Executor>>,
    network: Arc<Network>,
    storage: MeteredStorage<AuditedStorage<MemStorage>>,
    // Cache commonly-used handles to avoid upgrading Weak for simple access
    metrics: Arc<Metrics>,
    auditor: Arc<Auditor>,
    children: Arc<Mutex<Vec<AbortHandle>>>,
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
            executor: Arc::downgrade(&executor),
            owner: Some(executor.clone()),
            network: Arc::new(network),
            storage,
            metrics,
            auditor,
            children: Arc::new(Mutex::new(Vec::new())),
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
        if !self.exec().finished.lock().unwrap().clone() {
            panic!("execution is not finished");
        }

        // Ensure runtime has not already been recovered
        {
            let exec = self.exec();
            let mut recovered = exec.recovered.lock().unwrap();
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
        let auditor = self.auditor.clone();
        let network = AuditedNetwork::new(DeterministicNetwork::default(), auditor.clone());
        let network = MeteredNetwork::new(network, runtime_registry);

        let executor = Arc::new(Executor {
            // Copied from the current runtime
            cycle: self.exec().cycle,
            deadline: self.exec().deadline,
            auditor: auditor.clone(),
            rng: Mutex::new(self.exec().rng.lock().unwrap().clone()),
            time: Mutex::new(*self.exec().time.lock().unwrap()),
            partitions: Mutex::new(self.exec().partitions.lock().unwrap().clone()),

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
            executor: Arc::downgrade(&executor),
            owner: Some(executor.clone()),
            network: Arc::new(network),
            storage: self.storage,
            metrics,
            auditor,
            children: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn auditor(&self) -> &Auditor {
        &self.auditor
    }

    // Upgrade executor Weak reference; panic if unavailable
    fn exec(&self) -> Arc<Executor> {
        self.executor
            .upgrade()
            .expect("executor dropped while context still in use")
    }

    // Make a detached context without a strong Executor owner
    fn detached(mut self) -> Self {
        self.owner = None;
        self
    }

    // Access metrics in a uniform way for macros
    fn metrics_handle(&self) -> &Metrics {
        &self.metrics
    }
}

impl Clone for Context {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            spawned: false,
            executor: self.executor.clone(),
            // Preserve owner for clones; tasks use detached() to avoid cycles
            owner: self.owner.clone(),
            network: self.network.clone(),
            storage: self.storage.clone(),
            metrics: self.metrics.clone(),
            auditor: self.auditor.clone(),
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
        let (label, gauge) = spawn_metrics!(self, future);

        // Set up the task
        let executor = self.exec();

        // Give spawned task its own empty children list
        let children = Arc::new(Mutex::new(Vec::new()));
        self.children = children.clone();

        // Detach the context handed to the spawned task to avoid cycles
        let future = f(self.detached());
        let (f, handle) = Handle::init_future(future, gauge, false, children);

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
        let executor = self.exec();

        move |f: F| {
            // Give spawned task its own empty children list
            let (f, handle) =
                Handle::init_future(f, gauge, false, Arc::new(Mutex::new(Vec::new())));

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
        if let Some(abort_handle) = child_handle.abort_handle() {
            parent_children.lock().unwrap().push(abort_handle);
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
        let (label, gauge) = spawn_metrics!(self, blocking, dedicated);

        // Initialize the blocking task
        let executor = self.exec();
        let (f, handle) = Handle::init_blocking(|| f(self.detached()), gauge, false);

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
        let executor = self.exec();
        move |f: F| {
            let (f, handle) = Handle::init_blocking(f, gauge, false);

            // Spawn the task
            let f = async move { f() };
            Tasks::register_work(&executor.tasks, label, Box::pin(f));
            handle
        }
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        self.auditor.event(b"stop", |hasher| {
            hasher.update(value.to_be_bytes());
        });
        let stop_resolved = {
            let exec = self.exec();
            let mut shutdown = exec.shutdown.lock().unwrap();
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
        self.auditor.event(b"stopped", |_| {});
        self.exec().shutdown.lock().unwrap().stopped()
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
            // Preserve owner for labeled contexts; tasks use detached() to avoid cycles
            owner: self.owner.clone(),
            network: self.network.clone(),
            storage: self.storage.clone(),
            metrics: self.metrics.clone(),
            auditor: self.auditor.clone(),
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
        self.auditor.event(b"register", |hasher| {
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
        self.exec()
            .registry
            .lock()
            .unwrap()
            .register(prefixed_name, help, metric)
    }

    fn encode(&self) -> String {
        self.auditor.event(b"encode", |_| {});
        let mut buffer = String::new();
        encode(&mut buffer, &self.exec().registry.lock().unwrap()).expect("encoding failed");
        buffer
    }
}

struct Sleeper {
    executor: Weak<Executor>,
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
        if let Some(exec) = self.executor.upgrade() {
            {
                let current_time = *exec.time.lock().unwrap();
                if current_time >= self.time {
                    return Poll::Ready(());
                }
            }
            if !self.registered {
                self.registered = true;
                exec.sleeping.lock().unwrap().push(Alarm {
                    time: self.time,
                    waker: cx.waker().clone(),
                });
            }
            Poll::Pending
        } else {
            // Executor dropped; treat sleep as complete
            Poll::Ready(())
        }
    }
}

impl Clock for Context {
    fn current(&self) -> SystemTime {
        *self.exec().time.lock().unwrap()
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
        self.auditor.event(b"rand", |hasher| {
            hasher.update(b"next_u32");
        });
        self.exec().rng.lock().unwrap().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.auditor.event(b"rand", |hasher| {
            hasher.update(b"next_u64");
        });
        self.exec().rng.lock().unwrap().next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.auditor.event(b"rand", |hasher| {
            hasher.update(b"fill_bytes");
        });
        self.exec().rng.lock().unwrap().fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.auditor.event(b"rand", |hasher| {
            hasher.update(b"try_fill_bytes");
        });
        self.exec().rng.lock().unwrap().try_fill_bytes(dest)
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
    use crate::{deterministic, utils::run_tasks, Blob, Metrics, Runner as _, Spawner, Storage};
    use commonware_macros::test_traced;
    use futures::task::noop_waker;
    use futures::StreamExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    #[test]
    fn test_memory_leak_spawned_tasks() {
        // This test demonstrates that completed tasks accumulate in memory
        // across multiple runtime iterations when tasks are spawned.

        for iteration in 0..5 {
            let executor = deterministic::Runner::default();

            executor.start(|context| async move {
                // Spawn multiple tasks that complete immediately
                for i in 0..100 {
                    context
                        .with_label(&format!("task_{}", i))
                        .spawn(|_| async move {
                            // Task completes immediately
                        });
                }

                // Give tasks time to complete
                context.sleep(Duration::from_millis(10)).await;
            });

            // After the executor finishes, check how many tasks remain in memory
            // Note: We can't directly access the task queue from here, but we can
            // observe memory growth through repeated iterations
            println!("Iteration {} completed", iteration);
        }

        // In a properly functioning runtime, memory should be freed after each iteration
        // But currently, completed tasks persist in memory
    }

    #[test]
    fn test_memory_leak_nested_spawns() {
        // This test demonstrates memory accumulation with nested task spawns

        for iteration in 0..3 {
            let executor = deterministic::Runner::default();

            executor.start(|context| async move {
                // Spawn tasks that spawn other tasks
                for i in 0..50 {
                    context
                        .with_label(&format!("parent_{}", i))
                        .spawn(move |context| async move {
                            // Each parent spawns children
                            for j in 0..10 {
                                context.with_label(&format!("child_{}_{}", i, j)).spawn(
                                    |_| async move {
                                        // Child task completes immediately
                                    },
                                );
                            }
                        });
                }

                // Let all tasks complete
                context.sleep(Duration::from_millis(100)).await;
            });

            println!("Iteration {} with nested spawns completed", iteration);
        }
    }

    #[test]
    fn test_memory_leak_long_lived_tasks() {
        // This test demonstrates that even long-lived tasks that eventually complete
        // still accumulate in memory

        use futures::channel::mpsc;

        for iteration in 0..3 {
            let executor = deterministic::Runner::default();

            executor.start(|context| async move {
                let mut handles = Vec::new();

                // Spawn tasks with channels that keep them alive
                for i in 0..50 {
                    let (tx, mut rx) = mpsc::unbounded::<()>();

                    let handle = context.with_label(&format!("long_task_{}", i)).spawn(
                        move |_| async move {
                            // Task waits for channel to close
                            while let Some(_) = rx.next().await {
                                // Process messages
                            }
                        },
                    );

                    handles.push((handle, tx));
                }

                // Let tasks run for a bit
                context.sleep(Duration::from_millis(10)).await;

                // Drop all senders to let tasks complete
                drop(handles);

                // Give tasks time to complete
                context.sleep(Duration::from_millis(10)).await;
            });

            println!("Iteration {} with long-lived tasks completed", iteration);
        }
    }

    #[test]
    fn test_runtime_accumulates_across_iterations() {
        // This test demonstrates memory accumulation across multiple runtime iterations
        // simulating what happens in the fuzzer

        use std::sync::Arc;

        // Track total allocations across iterations
        static TOTAL_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
        static TOTAL_FREED: AtomicUsize = AtomicUsize::new(0);

        struct TrackedAllocation {
            size: usize,
        }

        impl TrackedAllocation {
            fn new(size: usize) -> Self {
                TOTAL_ALLOCATED.fetch_add(size, Ordering::SeqCst);
                Self { size }
            }
        }

        impl Drop for TrackedAllocation {
            fn drop(&mut self) {
                TOTAL_FREED.fetch_add(self.size, Ordering::SeqCst);
            }
        }

        // Simulate multiple fuzzer iterations
        for iteration in 0..10 {
            let executor = deterministic::Runner::default();

            executor.start(|context| async move {
                // Spawn many tasks, each allocating memory
                for i in 0..100 {
                    // Each task allocates 1KB
                    let allocation = Arc::new(TrackedAllocation::new(1024));

                    context
                        .with_label(&format!("task_{}_{}", iteration, i))
                        .spawn(move |context| async move {
                            let _alloc = allocation;

                            // Spawn a nested task
                            context.with_label("nested").spawn(|_| async move {
                                // Nested task completes immediately
                            });

                            // Task completes
                        });
                }

                // Let all tasks complete
                context.sleep(Duration::from_millis(10)).await;
            });

            // Runtime dropped here
        }

        let allocated = TOTAL_ALLOCATED.load(Ordering::SeqCst);
        let freed = TOTAL_FREED.load(Ordering::SeqCst);

        println!("Total allocated: {} KB", allocated / 1024);
        println!("Total freed: {} KB", freed / 1024);
        println!("Leaked: {} KB", (allocated - freed) / 1024);

        // All memory should be freed after runtimes are dropped
        assert_eq!(
            allocated,
            freed,
            "Memory leak detected: {} bytes leaked",
            allocated - freed
        );
    }

    #[test]
    fn test_circular_reference_prevents_cleanup() {
        // This test shows how circular references between tasks prevent cleanup

        use futures::channel::mpsc;
        use std::sync::Arc;

        static TASK_DROPS: AtomicUsize = AtomicUsize::new(0);

        struct TrackedResource {
            _id: usize,
        }

        impl Drop for TrackedResource {
            fn drop(&mut self) {
                TASK_DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        // Initialize counter
        TASK_DROPS.store(0, Ordering::SeqCst);

        for iteration in 0..3 {
            println!("\n=== Iteration {} ===", iteration);

            // Reset counter for this iteration
            let initial_drops = TASK_DROPS.load(Ordering::SeqCst);

            {
                let executor = deterministic::Runner::default();

                executor.start(|context| async move {
                    // Create tasks with circular dependencies through channels
                    let (tx1, mut rx1) = mpsc::unbounded::<()>();
                    let (tx2, mut rx2) = mpsc::unbounded::<()>();

                    // Only create the resources inside the tasks, not outside
                    // This ensures they're only held by the tasks

                    // Task 1 holds tx2 and waits on rx1
                    context.with_label("task1").spawn(move |_| async move {
                        let _resource = Arc::new(TrackedResource {
                            _id: iteration * 2 + 1,
                        });
                        let _tx = tx2; // Holds reference to task2's channel
                        while let Some(_) = rx1.next().await {}
                    });

                    // Task 2 holds tx1 and waits on rx2
                    context.with_label("task2").spawn(move |_| async move {
                        let _resource = Arc::new(TrackedResource {
                            _id: iteration * 2 + 2,
                        });
                        let _tx = tx1; // Holds reference to task1's channel
                        while let Some(_) = rx2.next().await {}
                    });

                    // Let tasks start
                    context.sleep(Duration::from_millis(10)).await;

                    // Tasks are now deadlocked in a circular wait
                    // They won't complete even though we're exiting
                });

                // Executor drops here and should clean up the tasks
            }

            let drops_after = TASK_DROPS.load(Ordering::SeqCst);
            let iteration_drops = drops_after - initial_drops;
            println!(
                "Iteration {}: {} resources dropped",
                iteration, iteration_drops
            );

            // With our fixes, resources should be freed when executor drops
            if iteration_drops == 2 {
                println!("SUCCESS: Circular references were cleaned up!");
            } else {
                println!("WARNING: Expected 2 drops, got {}", iteration_drops);
            }
        }

        // Final check
        println!("\n=== Final Results ===");
        let final_drops = TASK_DROPS.load(Ordering::SeqCst);
        println!("Total resources dropped: {}/6", final_drops);

        assert_eq!(
            final_drops, 6,
            "All resources should be freed with executor cleanup"
        );
    }

    #[test]
    fn test_simulated_network_pattern_leak() {
        // This test simulates the pattern from the p2p simulated network
        // where tasks spawn other tasks and create channels between them

        use futures::channel::mpsc;
        use std::sync::Arc;

        static RESOURCE_DROPS: AtomicUsize = AtomicUsize::new(0);

        struct NetworkResource {
            _id: usize,
        }

        impl Drop for NetworkResource {
            fn drop(&mut self) {
                RESOURCE_DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        // Simulate multiple fuzzer iterations
        for iteration in 0..5 {
            println!("\n=== Iteration {} ===", iteration);
            let initial_drops = RESOURCE_DROPS.load(Ordering::SeqCst);

            let executor = deterministic::Runner::default();

            executor.start(|context| async move {
                // Simulate creating peers (like in the network)
                let mut peer_channels = Vec::new();

                for peer_id in 0..5 {
                    let resource = Arc::new(NetworkResource { _id: peer_id });

                    // Each peer has a router task (like Peer::new)
                    let (control_tx, mut control_rx) = mpsc::unbounded::<()>();
                    let (inbox_tx, mut inbox_rx) = mpsc::unbounded::<()>();

                    let r1 = resource.clone();
                    context
                        .with_label(&format!("peer_{}_router", peer_id))
                        .spawn(move |_| async move {
                            let _resource = r1;
                            // Router waits for messages
                            loop {
                                futures::select! {
                                    _ = control_rx.next() => {},
                                    _ = inbox_rx.next() => {},
                                }
                            }
                        });

                    // Each peer also has a listener task
                    let r2 = resource.clone();
                    let inbox_tx_clone = inbox_tx.clone();
                    context
                        .with_label(&format!("peer_{}_listener", peer_id))
                        .spawn(move |context| async move {
                            let _resource = r2;
                            // Listener spawns receiver tasks
                            for i in 0..3 {
                                let tx = inbox_tx_clone.clone();
                                context.with_label(&format!("receiver_{}", i)).spawn(
                                    move |_| async move {
                                        // Receiver holds channel reference
                                        let _tx = tx;
                                    },
                                );
                            }
                        });

                    peer_channels.push((control_tx, inbox_tx));
                }

                // Simulate creating links between peers
                for i in 0..5 {
                    for j in 0..5 {
                        if i != j {
                            let (link_tx, mut link_rx) = mpsc::unbounded::<()>();

                            // Link task (like Link::new)
                            context.with_label(&format!("link_{}_{}", i, j)).spawn(
                                move |_| async move {
                                    // Link waits for messages
                                    while let Some(_) = link_rx.next().await {}
                                },
                            );

                            // Store link channel (would normally be in Link struct)
                            drop(link_tx); // In real code, this would be stored
                        }
                    }
                }

                // Let everything run
                context.sleep(Duration::from_millis(10)).await;

                // Drop peer channels - but tasks may still hold references
                drop(peer_channels);
            });

            // Runtime drops here
            let drops_after = RESOURCE_DROPS.load(Ordering::SeqCst);
            let iteration_drops = drops_after - initial_drops;
            println!(
                "Resources freed in iteration {}: {}",
                iteration, iteration_drops
            );

            if iteration_drops < 5 {
                println!("WARNING: Not all resources freed! Potential memory leak.");
            }
        }

        let total_drops = RESOURCE_DROPS.load(Ordering::SeqCst);
        println!("\nTotal resources dropped: {}/25", total_drops);

        // With 5 iterations of 5 peers each, we should have 25 drops
        // But circular references may prevent some from being freed
        if total_drops < 25 {
            println!(
                "MEMORY LEAK CONFIRMED: {} resources leaked",
                25 - total_drops
            );
        }
    }

    #[test]
    fn test_tokio_vs_deterministic_cleanup() {
        // This test compares how Tokio and the deterministic runtime handle cleanup
        // Note: This test documents the behavior difference

        use futures::channel::mpsc;
        use std::sync::Arc;

        println!("\n=== Testing Deterministic Runtime Cleanup ===");

        static DETERMINISTIC_DROPS: AtomicUsize = AtomicUsize::new(0);

        struct DeterministicResource {
            _id: usize,
        }

        impl Drop for DeterministicResource {
            fn drop(&mut self) {
                DETERMINISTIC_DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        // Test with deterministic runtime
        {
            let executor = deterministic::Runner::default();

            executor.start(|context| async move {
                let (tx1, mut rx1) = mpsc::unbounded::<()>();
                let (tx2, mut rx2) = mpsc::unbounded::<()>();

                let resource1 = Arc::new(DeterministicResource { _id: 1 });
                let resource2 = Arc::new(DeterministicResource { _id: 2 });

                // Create circular reference through channels
                let r1 = resource1.clone();
                context.with_label("task1").spawn(move |_| async move {
                    let _resource = r1;
                    let _tx = tx2; // Holds reference to task2's channel
                    while let Some(_) = rx1.next().await {}
                });

                let r2 = resource2.clone();
                context.with_label("task2").spawn(move |_| async move {
                    let _resource = r2;
                    let _tx = tx1; // Holds reference to task1's channel
                    while let Some(_) = rx2.next().await {}
                });

                context.sleep(Duration::from_millis(1)).await;
            });
        }

        println!(
            "Deterministic runtime dropped {} resources",
            DETERMINISTIC_DROPS.load(Ordering::SeqCst)
        );

        // With Tokio, the behavior is different:
        // 1. When the runtime is dropped, it signals all tasks to shut down
        // 2. It drops the task handles it owns
        // 3. Tasks that are blocked on I/O or channels are forcibly cancelled
        // 4. The Drop implementations of futures are called during cancellation
        //
        // Key differences:
        // - Tokio uses JoinHandles which, when dropped, detach the task but don't keep it alive
        // - Tokio's runtime shutdown forcibly drops all task futures
        // - Tokio doesn't maintain strong references to completed tasks

        println!("\n=== How Tokio Prevents This Leak ===");
        println!("1. Task Detachment: When JoinHandles are dropped, tasks are detached");
        println!("2. Runtime Shutdown: Forcibly cancels all running tasks");
        println!("3. No Task Queue Persistence: Completed tasks are immediately freed");
        println!("4. Weak References: Uses Weak refs where possible to avoid cycles");
    }

    #[test]
    fn test_runtime_shutdown_behavior() {
        // This test demonstrates what happens when we try to forcibly shutdown

        use std::sync::Arc;

        static CLEANUP_DROPS: AtomicUsize = AtomicUsize::new(0);

        struct CleanupResource {
            id: usize,
        }

        impl Drop for CleanupResource {
            fn drop(&mut self) {
                println!("Dropping resource {}", self.id);
                CLEANUP_DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        // Test: Can we force cleanup by aborting handles?
        {
            let executor = deterministic::Runner::default();
            let mut handles = Vec::new();

            executor.start(|context| async move {
                for i in 0..5 {
                    let resource = Arc::new(CleanupResource { id: i });

                    // Spawn task and keep handle
                    let handle =
                        context
                            .with_label(&format!("task_{}", i))
                            .spawn(move |_| async move {
                                let _resource = resource;
                                // Infinite loop
                                loop {
                                    futures::pending!();
                                }
                            });

                    handles.push(handle);
                }

                // Try to abort all tasks
                for handle in &handles {
                    handle.abort();
                }

                // Give time for aborts to process
                context.sleep(Duration::from_millis(10)).await;

                // Check if resources were freed
                let drops = CLEANUP_DROPS.load(Ordering::SeqCst);
                println!("Resources dropped after abort: {}", drops);
            });
        }

        let final_drops = CLEANUP_DROPS.load(Ordering::SeqCst);
        println!("Total resources dropped: {}", final_drops);

        // This shows that even with abort(), resources may not be freed
        // if the runtime doesn't properly handle task cancellation
    }

    #[test]
    fn test_executor_drop_cleans_up_tasks() {
        // This test verifies that dropping the executor properly cleans up tasks

        use futures::channel::mpsc;
        use std::sync::Arc;

        static DROP_COUNT: AtomicUsize = AtomicUsize::new(0);

        struct DropTracker {
            _id: usize,
        }

        impl Drop for DropTracker {
            fn drop(&mut self) {
                DROP_COUNT.fetch_add(1, Ordering::SeqCst);
            }
        }

        DROP_COUNT.store(0, Ordering::SeqCst);

        {
            let executor = deterministic::Runner::default();

            executor.start(|context| async move {
                // Create circular references similar to the network pattern
                let (tx1, mut rx1) = mpsc::unbounded::<()>();
                let (tx2, mut rx2) = mpsc::unbounded::<()>();

                let tracker1 = Arc::new(DropTracker { _id: 1 });
                let tracker2 = Arc::new(DropTracker { _id: 2 });

                let t1 = tracker1.clone();
                context.with_label("task1").spawn(move |_| async move {
                    let _tracker = t1;
                    let _tx = tx2;
                    while let Some(_) = rx1.next().await {}
                });

                let t2 = tracker2.clone();
                context.with_label("task2").spawn(move |_| async move {
                    let _tracker = t2;
                    let _tx = tx1;
                    while let Some(_) = rx2.next().await {}
                });

                // Don't wait for tasks to complete - they're deadlocked
                context.sleep(Duration::from_millis(1)).await;
            });

            // Executor drops here - should forcibly clean up tasks
        }

        // Give a moment for drops to happen
        std::thread::sleep(std::time::Duration::from_millis(10));

        let drops = DROP_COUNT.load(Ordering::SeqCst);
        println!("Drops after executor dropped: {}", drops);

        // With our fixes, the executor's Drop impl should break circular references
        assert_eq!(
            drops, 2,
            "Executor should have cleaned up circular references"
        );
    }

    #[test]
    fn test_waker_keeps_completed_tasks_alive() {
        // This test shows that wakers can keep completed tasks in memory

        use std::sync::Arc;

        let executor = deterministic::Runner::default();

        executor.start(|context| async move {
            let _executor_ref = context.exec();

            // Create a custom waker that we can control
            struct WakerHolder {
                waker: Option<std::task::Waker>,
            }

            let holder = Arc::new(Mutex::new(WakerHolder { waker: None }));
            let holder_clone = holder.clone();

            // Spawn a task and capture its waker
            context.with_label("test_task").spawn(move |_| async move {
                // Get our own waker
                futures::future::poll_fn(|cx| {
                    holder_clone.lock().unwrap().waker = Some(cx.waker().clone());
                    std::task::Poll::Ready(())
                })
                .await;
            });

            // Let the task complete
            context.sleep(Duration::from_millis(10)).await;

            // Now wake the completed task multiple times
            for _ in 0..5 {
                if let Some(ref waker) = holder.lock().unwrap().waker {
                    waker.wake_by_ref();
                }
                context.sleep(Duration::from_millis(1)).await;
            }

            // The completed task may be re-enqueued despite being complete
            // This is one way tasks can accumulate in memory
        });
    }
}
