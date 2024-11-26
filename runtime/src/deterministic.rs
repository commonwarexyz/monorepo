//! A deterministic runtime that randomly selects tasks to run based on a seed
//!
//! # Panics
//!
//! If any task panics, the runtime will panic (and shutdown).
//!
//! # Example
//!
//! ```rust
//! use commonware_runtime::{Spawner, Runner, deterministic::Executor};
//!
//! let (executor, runtime, auditor) = Executor::default();
//! executor.start(async move {
//!     println!("Parent started");
//!     let result = runtime.spawn("child", async move {
//!         println!("Child started");
//!         "hello"
//!     });
//!     println!("Child result: {:?}", result.await);
//!     println!("Parent exited");
//! });
//! println!("Auditor state: {}", auditor.state());
//! ```

use crate::{
    mock_channel::{self, ByteSink, ByteStream},
    utils::Signaler,
    Clock,
    Error,
    Handle,
    Signal,
};
use bytes::Bytes;
use commonware_utils::hex;
use futures::{
    channel::mpsc,
    task::{waker_ref, ArcWake},
    SinkExt, StreamExt,
};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::Registry,
};
use rand::{prelude::SliceRandom, rngs::StdRng, CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::{
    collections::{BinaryHeap, HashMap},
    future::Future,
    mem::replace,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Range,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{self, Poll, Waker},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::trace;

/// Range of ephemeral ports assigned to dialers.
const EPHEMERAL_PORT_RANGE: Range<u16> = 32768..61000;

const ROOT_TASK: &str = "root";

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Work {
    label: String,
}

#[derive(Debug)]
struct Metrics {
    tasks_spawned: Family<Work, Counter>,
    tasks_running: Family<Work, Gauge>,
    task_polls: Family<Work, Counter>,

    network_bandwidth: Counter,

    open_blobs: Gauge,
    storage_reads: Counter,
    storage_read_bandwidth: Counter,
    storage_writes: Counter,
    storage_write_bandwidth: Counter,
}

impl Metrics {
    pub fn init(registry: Arc<Mutex<Registry>>) -> Self {
        let metrics = Self {
            task_polls: Family::default(),
            tasks_running: Family::default(),
            tasks_spawned: Family::default(),
            network_bandwidth: Counter::default(),
            open_blobs: Gauge::default(),
            storage_reads: Counter::default(),
            storage_read_bandwidth: Counter::default(),
            storage_writes: Counter::default(),
            storage_write_bandwidth: Counter::default(),
        };
        {
            let mut registry = registry.lock().unwrap();
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
            registry.register(
                "open_blobs",
                "Number of open blobs",
                metrics.open_blobs.clone(),
            );
            registry.register(
                "storage_reads",
                "Total number of disk reads",
                metrics.storage_reads.clone(),
            );
            registry.register(
                "storage_read_bandwidth",
                "Total amount of data read from disk",
                metrics.storage_read_bandwidth.clone(),
            );
            registry.register(
                "storage_writes",
                "Total number of disk writes",
                metrics.storage_writes.clone(),
            );
            registry.register(
                "storage_write_bandwidth",
                "Total amount of data written to disk",
                metrics.storage_write_bandwidth.clone(),
            );
        }
        metrics
    }
}

/// Track the state of the runtime for determinism auditing.
pub struct Auditor {
    hash: Mutex<Vec<u8>>,
}

impl Auditor {
    fn new() -> Self {
        Self {
            hash: Mutex::new(Vec::new()),
        }
    }

    fn process_task(&self, task: u128, label: &str) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"process_task");
        hasher.update(task.to_be_bytes());
        hasher.update(label.as_bytes());
        *hash = hasher.finalize().to_vec();
    }

    fn stop(&self, value: i32) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"stop");
        hasher.update(value.to_be_bytes());
        *hash = hasher.finalize().to_vec();
    }

    fn stopped(&self) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"stopped");
        *hash = hasher.finalize().to_vec();
    }

    fn bind(&self, address: SocketAddr) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"bind");
        hasher.update(address.to_string().as_bytes());
        *hash = hasher.finalize().to_vec();
    }

    fn dial(&self, dialer: SocketAddr, dialee: SocketAddr) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"dial");
        hasher.update(dialer.to_string().as_bytes());
        hasher.update(dialee.to_string().as_bytes());
        *hash = hasher.finalize().to_vec();
    }

    fn accept(&self, dialee: SocketAddr, dialer: SocketAddr) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"accept");
        hasher.update(dialee.to_string().as_bytes());
        hasher.update(dialer.to_string().as_bytes());
        *hash = hasher.finalize().to_vec();
    }

    fn send(&self, sender: SocketAddr, receiver: SocketAddr, message: Bytes) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"send");
        hasher.update(sender.to_string().as_bytes());
        hasher.update(receiver.to_string().as_bytes());
        hasher.update(&message);
        *hash = hasher.finalize().to_vec();
    }

    fn recv(&self, receiver: SocketAddr, sender: SocketAddr, message: Bytes) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"recv");
        hasher.update(receiver.to_string().as_bytes());
        hasher.update(sender.to_string().as_bytes());
        hasher.update(&message);
        *hash = hasher.finalize().to_vec();
    }

    fn rand(&self, method: String) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"rand");
        hasher.update(method.as_bytes());
        *hash = hasher.finalize().to_vec();
    }

    fn open(&self, partition: &str, name: &[u8]) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"open");
        hasher.update(partition.as_bytes());
        hasher.update(name);
        *hash = hasher.finalize().to_vec();
    }

    fn remove(&self, partition: &str, name: Option<&[u8]>) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"remove");
        hasher.update(partition.as_bytes());
        if let Some(name) = name {
            hasher.update(name);
        }
        *hash = hasher.finalize().to_vec();
    }

    fn scan(&self, partition: &str) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"scan");
        hasher.update(partition.as_bytes());
        *hash = hasher.finalize().to_vec();
    }

    fn len(&self, partition: &str, name: &[u8]) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"len");
        hasher.update(partition.as_bytes());
        hasher.update(name);
        *hash = hasher.finalize().to_vec();
    }

    fn read_at(&self, partition: &str, name: &[u8], buf: usize, offset: u64) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"read_at");
        hasher.update(partition.as_bytes());
        hasher.update(name);
        hasher.update(buf.to_be_bytes());
        hasher.update(offset.to_be_bytes());
        *hash = hasher.finalize().to_vec();
    }

    fn write_at(&self, partition: &str, name: &[u8], buf: &[u8], offset: u64) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"write_at");
        hasher.update(partition.as_bytes());
        hasher.update(name);
        hasher.update(buf);
        hasher.update(offset.to_be_bytes());
        *hash = hasher.finalize().to_vec();
    }

    fn truncate(&self, partition: &str, name: &[u8], size: u64) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"truncate");
        hasher.update(partition.as_bytes());
        hasher.update(name);
        hasher.update(size.to_be_bytes());
        *hash = hasher.finalize().to_vec();
    }

    fn sync(&self, partition: &str, name: &[u8]) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"sync");
        hasher.update(partition.as_bytes());
        hasher.update(name);
        *hash = hasher.finalize().to_vec();
    }

    fn close(&self, partition: &str, name: &[u8]) {
        let mut hash = self.hash.lock().unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&*hash);
        hasher.update(b"close");
        hasher.update(partition.as_bytes());
        hasher.update(name);
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

struct Task {
    id: u128,
    label: String,

    tasks: Arc<Tasks>,

    root: bool,
    future: Mutex<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,

    completed: Mutex<bool>,
}

impl ArcWake for Task {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.tasks.enqueue(arc_self.clone());
    }
}

struct Tasks {
    counter: Mutex<u128>,
    queue: Mutex<Vec<Arc<Task>>>,
}

impl Tasks {
    fn register(
        arc_self: &Arc<Self>,
        label: &str,
        root: bool,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) {
        let mut queue = arc_self.queue.lock().unwrap();
        let id = {
            let mut l = arc_self.counter.lock().unwrap();
            let old = *l;
            *l = l.checked_add(1).expect("task counter overflow");
            old
        };
        queue.push(Arc::new(Task {
            id,
            label: label.to_string(),
            root,
            future: Mutex::new(future),
            tasks: arc_self.clone(),
            completed: Mutex::new(false),
        }));
    }

    fn enqueue(&self, task: Arc<Task>) {
        let mut queue = self.queue.lock().unwrap();
        queue.push(task);
    }

    fn drain(&self) -> Vec<Arc<Task>> {
        let mut queue = self.queue.lock().unwrap();
        let len = queue.len();
        replace(&mut *queue, Vec::with_capacity(len))
    }

    fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
}

/// Configuration for the `deterministic` runtime.
#[derive(Clone)]
pub struct Config {
    /// Registry for metrics.
    pub registry: Arc<Mutex<Registry>>,

    /// Seed for the random number generator.
    pub seed: u64,

    /// The cycle duration determines how much time is advanced after each iteration of the event
    /// loop. This is useful to prevent starvation if some task never yields.
    pub cycle: Duration,

    /// If the runtime is still executing at this point (i.e. a test hasn't stopped), panic.
    pub timeout: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            registry: Arc::new(Mutex::new(Registry::default())),
            seed: 42,
            cycle: Duration::from_millis(1),
            timeout: None,
        }
    }
}

/// Deterministic runtime that randomly selects tasks to run based on a seed.
pub struct Executor {
    cycle: Duration,
    deadline: Option<SystemTime>,
    metrics: Arc<Metrics>,
    auditor: Arc<Auditor>,
    rng: Mutex<StdRng>,
    prefix: Mutex<String>,
    time: Mutex<SystemTime>,
    tasks: Arc<Tasks>,
    sleeping: Mutex<BinaryHeap<Alarm>>,
    partitions: Mutex<HashMap<String, Partition>>,
    signaler: Mutex<Signaler>,
    signal: Signal,
}

impl Executor {
    /// Initialize a new `deterministic` runtime with the given seed and cycle duration.
    pub fn init(cfg: Config) -> (Runner, Context, Arc<Auditor>) {
        // Ensure config is valid
        if cfg.timeout.is_some() && cfg.cycle == Duration::default() {
            panic!("cycle duration must be non-zero when timeout is set");
        }

        // Initialize runtime
        let metrics = Arc::new(Metrics::init(cfg.registry));
        let auditor = Arc::new(Auditor::new());
        let start_time = UNIX_EPOCH;
        let deadline = cfg
            .timeout
            .map(|timeout| start_time.checked_add(timeout).expect("timeout overflowed"));
        let (signaler, signal) = Signaler::new();
        let executor = Arc::new(Self {
            cycle: cfg.cycle,
            deadline,
            metrics: metrics.clone(),
            auditor: auditor.clone(),
            rng: Mutex::new(StdRng::seed_from_u64(cfg.seed)),
            prefix: Mutex::new(String::new()),
            time: Mutex::new(start_time),
            tasks: Arc::new(Tasks {
                queue: Mutex::new(Vec::new()),
                counter: Mutex::new(0),
            }),
            sleeping: Mutex::new(BinaryHeap::new()),
            partitions: Mutex::new(HashMap::new()),
            signaler: Mutex::new(signaler),
            signal,
        });
        (
            Runner {
                executor: executor.clone(),
            },
            Context {
                executor,
                networking: Arc::new(Networking::new(metrics, auditor.clone())),
            },
            auditor,
        )
    }

    /// Initialize a new `deterministic` runtime with the default configuration
    /// and the provided seed.
    pub fn seeded(seed: u64) -> (Runner, Context, Arc<Auditor>) {
        let cfg = Config {
            seed,
            ..Config::default()
        };
        Self::init(cfg)
    }

    /// Initialize a new `deterministic` runtime with the default configuration
    /// but exit after the given timeout.
    pub fn timed(timeout: Duration) -> (Runner, Context, Arc<Auditor>) {
        let cfg = Config {
            timeout: Some(timeout),
            ..Config::default()
        };
        Self::init(cfg)
    }

    /// Initialize a new `deterministic` runtime with the default configuration.
    // We'd love to implement the trait but we can't because of the return type.
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> (Runner, Context, Arc<Auditor>) {
        Self::init(Config::default())
    }
}

/// Implementation of [`crate::Runner`] for the `deterministic` runtime.
pub struct Runner {
    executor: Arc<Executor>,
}

impl crate::Runner for Runner {
    fn start<F>(self, f: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        // Add root task to the queue
        let output = Arc::new(Mutex::new(None));
        Tasks::register(
            &self.executor.tasks,
            ROOT_TASK,
            true,
            Box::pin({
                let output = output.clone();
                async move {
                    *output.lock().unwrap() = Some(f.await);
                }
            }),
        );

        // Process tasks until root task completes or progress stalls
        let mut iter = 0;
        loop {
            // Ensure we have not exceeded our deadline
            {
                let current = self.executor.time.lock().unwrap();
                if let Some(deadline) = self.executor.deadline {
                    if *current >= deadline {
                        panic!("runtime timeout");
                    }
                }
            }

            // Snapshot available tasks
            let mut tasks = self.executor.tasks.drain();

            // Shuffle tasks
            {
                let mut rng = self.executor.rng.lock().unwrap();
                tasks.shuffle(&mut *rng);
            }

            // Run all snapshotted tasks
            //
            // This approach is more efficient than randomly selecting a task one-at-a-time
            // because it ensures we don't pull the same pending task multiple times in a row (without
            // processing a different task required for other tasks to make progress).
            trace!(iter, tasks = tasks.len(), "starting loop");
            for task in tasks {
                // Set current task prefix
                {
                    let mut prefix = self.executor.prefix.lock().unwrap();
                    prefix.clone_from(&task.label);
                }

                // Record task for auditing
                self.executor.auditor.process_task(task.id, &task.label);

                // Check if task is already complete
                if *task.completed.lock().unwrap() {
                    trace!(id = task.id, "skipping already completed task");
                    continue;
                }
                trace!(id = task.id, "processing task");

                // Prepare task for polling
                let waker = waker_ref(&task);
                let mut context = task::Context::from_waker(&waker);
                let mut future = task.future.lock().unwrap();

                // Record task poll
                self.executor
                    .metrics
                    .task_polls
                    .get_or_create(&Work {
                        label: task.label.clone(),
                    })
                    .inc();

                // Task is re-queued in its `wake_by_ref` implementation as soon as we poll here (regardless
                // of whether it is Pending/Ready).
                let pending = future.as_mut().poll(&mut context).is_pending();
                if pending {
                    trace!(id = task.id, "task is still pending");
                    continue;
                }

                // Mark task as completed
                *task.completed.lock().unwrap() = true;
                trace!(id = task.id, "task is complete");

                // Root task completed
                if task.root {
                    return output.lock().unwrap().take().unwrap();
                }
            }

            // Advance time by cycle
            //
            // This approach prevents starvation if some task never yields (to approximate this,
            // duration can be set to 1ns).
            let mut current;
            {
                let mut time = self.executor.time.lock().unwrap();
                *time = time
                    .checked_add(self.executor.cycle)
                    .expect("executor time overflowed");
                current = *time;
            }
            trace!(
                now = current.duration_since(UNIX_EPOCH).unwrap().as_millis(),
                "time advanced",
            );

            // Skip time if there is nothing to do
            if self.executor.tasks.len() == 0 {
                let mut skip = None;
                {
                    let sleeping = self.executor.sleeping.lock().unwrap();
                    if let Some(next) = sleeping.peek() {
                        if next.time > current {
                            skip = Some(next.time);
                        }
                    }
                }
                if skip.is_some() {
                    {
                        let mut time = self.executor.time.lock().unwrap();
                        *time = skip.unwrap();
                        current = *time;
                    }
                    trace!(
                        now = current.duration_since(UNIX_EPOCH).unwrap().as_millis(),
                        "time skipped",
                    );
                }
            }

            // Wake all sleeping tasks that are ready
            let mut to_wake = Vec::new();
            let mut remaining;
            {
                let mut sleeping = self.executor.sleeping.lock().unwrap();
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
            remaining += self.executor.tasks.len();

            // If there are no tasks to run and no tasks sleeping, the executor is stalled
            // and will never finish.
            if remaining == 0 {
                panic!("runtime stalled");
            }
            iter += 1;
        }
    }
}

/// Implementation of [`crate::Spawner`], [`crate::Clock`],
/// [`crate::Network`], and [`crate::Storage`] for the `deterministic`
/// runtime.
#[derive(Clone)]
pub struct Context {
    executor: Arc<Executor>,
    networking: Arc<Networking>,
}

impl crate::Spawner for Context {
    fn spawn<F, T>(&self, label: &str, f: F) -> Handle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let label = {
            let prefix = self.executor.prefix.lock().unwrap();
            if prefix.is_empty() || *prefix == ROOT_TASK {
                label.to_string()
            } else {
                format!("{}_{}", *prefix, label)
            }
        };
        if label == ROOT_TASK {
            panic!("root task cannot be spawned");
        }
        let work = Work {
            label: label.clone(),
        };
        self.executor
            .metrics
            .tasks_spawned
            .get_or_create(&work)
            .inc();
        let gauge = self
            .executor
            .metrics
            .tasks_running
            .get_or_create(&work)
            .clone();
        let (f, handle) = Handle::init(f, gauge, false);
        Tasks::register(&self.executor.tasks, &label, false, Box::pin(f));
        handle
    }

    fn stop(&self, value: i32) {
        self.executor.auditor.stop(value);
        self.executor.signaler.lock().unwrap().signal(value);
    }

    fn stopped(&self) -> Signal {
        self.executor.auditor.stopped();
        self.executor.signal.clone()
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
        let time = self
            .current()
            .checked_add(duration)
            .expect("overflow when setting wake time");
        Sleeper {
            executor: self.executor.clone(),

            time,
            registered: false,
        }
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

type Dialable = mpsc::UnboundedSender<(
    SocketAddr,
    ByteSink,   // Dialee -> Dialer
    ByteStream, // Dialer -> Dialee
)>;

/// Implementation of [`crate::Network`] for the `deterministic` runtime.
///
/// When a dialer connects to a dialee, the dialee is given a new ephemeral port
/// from the range `32768..61000`. To keep things simple, it is not possible to
/// bind to an ephemeral port. Likewise, if ports are not reused and when exhausted,
/// the runtime will panic.
struct Networking {
    metrics: Arc<Metrics>,
    auditor: Arc<Auditor>,
    ephemeral: Mutex<u16>,
    listeners: Mutex<HashMap<SocketAddr, Dialable>>,
}

impl Networking {
    fn new(metrics: Arc<Metrics>, auditor: Arc<Auditor>) -> Self {
        Self {
            metrics,
            auditor,
            ephemeral: Mutex::new(EPHEMERAL_PORT_RANGE.start),
            listeners: Mutex::new(HashMap::new()),
        }
    }

    fn bind(&self, socket: SocketAddr) -> Result<Listener, Error> {
        self.auditor.bind(socket);

        // Ensure the port is not in the ephemeral range
        if EPHEMERAL_PORT_RANGE.contains(&socket.port()) {
            return Err(Error::BindFailed);
        }

        // Ensure the port is not already bound
        let mut listeners = self.listeners.lock().unwrap();
        if listeners.contains_key(&socket) {
            return Err(Error::BindFailed);
        }

        // Bind the socket
        let (sender, receiver) = mpsc::unbounded();
        listeners.insert(socket, sender);
        Ok(Listener {
            auditor: self.auditor.clone(),
            address: socket,
            listener: receiver,
            metrics: self.metrics.clone(),
        })
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(Sink, Stream), Error> {
        // Assign dialer a port from the ephemeral range
        let dialer = {
            let mut ephemeral = self.ephemeral.lock().unwrap();
            let dialer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *ephemeral);
            *ephemeral = ephemeral
                .checked_add(1)
                .expect("ephemeral port range exhausted");
            dialer
        };
        self.auditor.dial(dialer, socket);

        // Get dialee
        let mut sender = {
            let listeners = self.listeners.lock().unwrap();
            let sender = listeners.get(&socket).ok_or(Error::ConnectionFailed)?;
            sender.clone()
        };

        // Construct connection
        let (dialer_sender, dialer_receiver) = mock_channel::new();
        let (dialee_sender, dialee_receiver) = mock_channel::new();
        sender
            .send((dialer, dialer_sender, dialee_receiver))
            .await
            .map_err(|_| Error::ConnectionFailed)?;
        Ok((
            Sink {
                metrics: self.metrics.clone(),
                auditor: self.auditor.clone(),
                me: dialer,
                peer: socket,
                sender: dialee_sender,
            },
            Stream {
                auditor: self.auditor.clone(),
                me: dialer,
                peer: socket,
                receiver: dialer_receiver,
            },
        ))
    }
}

impl crate::Network<Listener, Sink, Stream> for Context {
    async fn bind(&self, socket: SocketAddr) -> Result<Listener, Error> {
        self.networking.bind(socket)
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(Sink, Stream), Error> {
        self.networking.dial(socket).await
    }
}

/// Implementation of [`crate::Listener`] for the `deterministic` runtime.
pub struct Listener {
    metrics: Arc<Metrics>,
    auditor: Arc<Auditor>,
    address: SocketAddr,
    listener: mpsc::UnboundedReceiver<(
        SocketAddr,
        ByteSink,
        ByteStream,
    )>,
}

impl crate::Listener<Sink, Stream> for Listener {
    async fn accept(&mut self) -> Result<(SocketAddr, Sink, Stream), Error> {
        let (socket, sender, receiver) = self.listener.next().await.ok_or(Error::ReadFailed)?;
        self.auditor.accept(self.address, socket);
        Ok((
            socket,
            Sink {
                metrics: self.metrics.clone(),
                auditor: self.auditor.clone(),
                me: self.address,
                peer: socket,
                sender,
            },
            Stream {
                auditor: self.auditor.clone(),
                me: self.address,
                peer: socket,
                receiver,
            },
        ))
    }
}

/// Implementation of [`crate::Sink`] for the `deterministic` runtime.
pub struct Sink {
    metrics: Arc<Metrics>,
    auditor: Arc<Auditor>,
    me: SocketAddr,
    peer: SocketAddr,
    sender: ByteSink,
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.auditor.send(self.me, self.peer, Bytes::copy_from_slice(msg));
        self.sender.send(msg)
            .await
            .map_err(|_| Error::SendFailed)?;
        self.metrics.network_bandwidth.inc_by(msg.len() as u64);
        Ok(())
    }
}

/// Implementation of [`crate::Stream`] for the `deterministic` runtime.
pub struct Stream {
    auditor: Arc<Auditor>,
    me: SocketAddr,
    peer: SocketAddr,
    receiver: ByteStream,
}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.receiver.recv(buf).await
            .map_err(|_| Error::RecvFailed)?;
        self.auditor.recv(self.me, self.peer, Bytes::copy_from_slice(buf));
        Ok(())
    }
}

impl RngCore for Context {
    fn next_u32(&mut self) -> u32 {
        self.executor.auditor.rand("next_u32".to_string());
        self.executor.rng.lock().unwrap().next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.executor.auditor.rand("next_u64".to_string());
        self.executor.rng.lock().unwrap().next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.executor.auditor.rand("fill_bytes".to_string());
        self.executor.rng.lock().unwrap().fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.executor.auditor.rand("try_fill_bytes".to_string());
        self.executor.rng.lock().unwrap().try_fill_bytes(dest)
    }
}

impl CryptoRng for Context {}

struct Partition {
    blobs: HashMap<Vec<u8>, Vec<u8>>,
}

impl Partition {
    fn new() -> Self {
        Self {
            blobs: HashMap::new(),
        }
    }
}

/// Implementation of [`crate::Blob`] for the `deterministic` runtime.
pub struct Blob {
    executor: Arc<Executor>,

    partition: String,
    name: Vec<u8>,

    // For content to be updated for future opens,
    // it must be synced back to the partition (occurs on
    // `sync` and `close`).
    content: Arc<RwLock<Vec<u8>>>,
}

impl Blob {
    fn new(executor: Arc<Executor>, partition: String, name: &[u8], content: Vec<u8>) -> Self {
        executor.metrics.open_blobs.inc();
        Self {
            executor,
            partition,
            name: name.into(),
            content: Arc::new(RwLock::new(content)),
        }
    }
}

impl Clone for Blob {
    fn clone(&self) -> Self {
        // We implement `Clone` manually to ensure the `open_blobs` gauge is updated.
        self.executor.metrics.open_blobs.inc();
        Self {
            executor: self.executor.clone(),
            partition: self.partition.clone(),
            name: self.name.clone(),
            content: self.content.clone(),
        }
    }
}

impl crate::Storage<Blob> for Context {
    async fn open(&self, partition: &str, name: &[u8]) -> Result<Blob, Error> {
        self.executor.auditor.open(partition, name);
        let mut partitions = self.executor.partitions.lock().unwrap();
        let partition_entry = partitions
            .entry(partition.into())
            .or_insert_with(Partition::new);
        let content = partition_entry.blobs.entry(name.into()).or_default();
        Ok(Blob::new(
            self.executor.clone(),
            partition.into(),
            name,
            content.clone(),
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.executor.auditor.remove(partition, name);
        let mut partitions = self.executor.partitions.lock().unwrap();
        match name {
            Some(name) => {
                partitions
                    .get_mut(partition)
                    .ok_or(Error::PartitionMissing(partition.into()))?
                    .blobs
                    .remove(name)
                    .ok_or(Error::BlobMissing(partition.into(), hex(name)))?;
            }
            None => {
                partitions
                    .remove(partition)
                    .ok_or(Error::PartitionMissing(partition.into()))?;
            }
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.executor.auditor.scan(partition);
        let partitions = self.executor.partitions.lock().unwrap();
        let partition = partitions
            .get(partition)
            .ok_or(Error::PartitionMissing(partition.into()))?;
        let mut results = Vec::with_capacity(partition.blobs.len());
        for name in partition.blobs.keys() {
            results.push(name.clone());
        }
        results.sort(); // deterministic output
        Ok(results)
    }
}

impl crate::Blob for Blob {
    async fn len(&self) -> Result<u64, Error> {
        self.executor.auditor.len(&self.partition, &self.name);
        let content = self.content.read().unwrap();
        Ok(content.len() as u64)
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        let buf_len = buf.len();
        self.executor
            .auditor
            .read_at(&self.partition, &self.name, buf_len, offset);
        let offset = offset.try_into().map_err(|_| Error::OffsetOverflow)?;
        let content = self.content.read().unwrap();
        let content_len = content.len();
        if offset + buf_len > content_len {
            return Err(Error::BlobInsufficientLength);
        }
        buf.copy_from_slice(&content[offset..offset + buf_len]);
        self.executor.metrics.storage_reads.inc();
        self.executor
            .metrics
            .storage_read_bandwidth
            .inc_by(buf_len as u64);
        Ok(())
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> Result<(), Error> {
        self.executor
            .auditor
            .write_at(&self.partition, &self.name, buf, offset);
        let offset = offset.try_into().map_err(|_| Error::OffsetOverflow)?;
        let mut content = self.content.write().unwrap();
        let required = offset + buf.len();
        if required > content.len() {
            content.resize(required, 0);
        }
        content[offset..offset + buf.len()].copy_from_slice(buf);
        self.executor.metrics.storage_writes.inc();
        self.executor
            .metrics
            .storage_write_bandwidth
            .inc_by(buf.len() as u64);
        Ok(())
    }

    async fn truncate(&self, len: u64) -> Result<(), Error> {
        self.executor
            .auditor
            .truncate(&self.partition, &self.name, len);
        let len = len.try_into().map_err(|_| Error::OffsetOverflow)?;
        let mut content = self.content.write().unwrap();
        content.truncate(len);
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        // Create new content for partition
        //
        // Doing this first means we don't need to hold both the content
        // lock and the partition lock at the same time.
        let new_content = self.content.read().unwrap().clone();

        // Update partition content
        self.executor.auditor.sync(&self.partition, &self.name);
        let mut partitions = self.executor.partitions.lock().unwrap();
        let partition = partitions
            .get_mut(&self.partition)
            .ok_or(Error::PartitionMissing(self.partition.clone()))?;
        let content = partition
            .blobs
            .get_mut(&self.name)
            .ok_or(Error::BlobMissing(self.partition.clone(), hex(&self.name)))?;
        *content = new_content;
        Ok(())
    }

    async fn close(self) -> Result<(), Error> {
        self.executor.auditor.close(&self.partition, &self.name);
        self.sync().await?;
        Ok(())
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        self.executor.metrics.open_blobs.dec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{utils::run_tasks, Runner, Spawner};
    use commonware_macros::test_traced;
    use futures::task::noop_waker;

    fn run_with_seed(seed: u64) -> (String, Vec<usize>) {
        let (executor, runtime, auditor) = Executor::seeded(seed);
        let messages = run_tasks(5, executor, runtime);
        (auditor.state(), messages)
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
        let (executor, runtime, _) = Executor::timed(Duration::from_secs(10));
        executor.start(async move {
            loop {
                runtime.sleep(Duration::from_secs(1)).await;
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
        let (_, _, _) = Executor::init(cfg);
    }

    #[test]
    #[should_panic(expected = "root task cannot be spawned")]
    fn test_spawn_root_task() {
        let (executor, context, _) = Executor::default();
        executor.start(async move {
            let _ = context
                .spawn(ROOT_TASK, async move {
                    // This task should never run
                    panic!("root task should not run");
                })
                .await;
            panic!("root task should not be spawned");
        });
    }
}
