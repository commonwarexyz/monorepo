//! Single-threaded executor that interleaves task polling with the io_uring
//! event loop.
//!
//! The thread that calls [crate::Runner::start] runs both the task executor
//! and the io_uring event loop: each iteration polls every ready task, then
//! services the ring via [IoUringLoop::turn] so completions wake tasks and
//! staged submissions reach the kernel. When nothing is runnable, the thread
//! parks via [IoUringLoop::park] until a completion arrives, a timer fires, a
//! producer enqueues work, or another thread wakes a task.
//!
//! Ordinary tasks run inline on the executor thread. Tasks spawned with
//! [crate::Spawner::dedicated] or [crate::Spawner::shared] with
//! `blocking == true` run as the root of a [Worker] on their own thread with
//! its own ring, so blocking work cannot starve the executor thread and the
//! task's context still submits IO thread-locally. (Blocking shared tasks
//! currently alias dedicated ones; a shared blocking pool may replace this.)
//! Resources created on one worker (blobs, sockets, listeners) are bound to
//! that worker's thread and must not be driven from another. Cross-thread
//! interactions that do not submit ring operations (waking a task from a
//! helper thread, registering a sleeper alarm, delivering a stop signal)
//! remain supported through each loop's latched wake state.

use super::{IoUringLoop, RingConfig, driver::Affine, new_ring, waker::Waker as RingWaker};
#[cfg(feature = "external")]
use crate::Pacer;
use crate::{
    BufferPool, BufferPoolConfig, Clock, Error, Execution, Handle, METRICS_PREFIX, Name, SinkOf,
    StreamOf, child_label,
    network::{
        iouring::{Config as NetworkConfig, Network as IoUringNetwork},
        metered::Network as MeteredNetwork,
    },
    prefixed_name,
    process::metered::Metrics as MeteredProcess,
    signal::Signal,
    storage::{iouring::Storage as IoUringStorage, metered::Storage as MeteredStorage},
    telemetry::metrics::{
        CounterFamily, GaugeFamily, Metric, Register, Registered, Registry, add_attribute, raw,
        task::Label, validate_label,
    },
    utils::{self, Panicker, signal::Stopper, supervision::Tree},
};
use commonware_macros::{select, stability};
#[stability(BETA)]
use commonware_parallel::Rayon;
use commonware_utils::{channel::oneshot, sync::Mutex, sys_rng};
use futures::{
    FutureExt as _,
    future::{AbortHandle, Abortable, Aborted},
    task::{ArcWake, waker},
};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use rand_core::{Rng, TryCryptoRng, TryRng};
use rayon::ThreadPoolBuilder;
use std::{
    cell::RefCell,
    collections::BinaryHeap,
    convert::Infallible,
    env,
    future::Future,
    mem::{ManuallyDrop, replace, take},
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{self, Poll, Waker},
    time::{Duration, Instant, SystemTime},
};

cfg_if::cfg_if! {
    if #[cfg(test)] {
        // Use a smaller ring in tests to reduce `io_uring_setup` failures
        // under parallel test load due to mlock/resource limits.
        const DEFAULT_RING_SIZE: u32 = 128;
    } else {
        const DEFAULT_RING_SIZE: u32 = 1024;
    }
}

/// Far-future cap for sleep durations so conversions to [Instant] cannot
/// overflow (e.g. when sleeping until [SystemTime::limit]).
///
/// [SystemTime::limit]: commonware_utils::SystemTimeExt::limit
const MAX_SLEEP: Duration = Duration::from_secs(30 * 365 * 24 * 60 * 60);

#[derive(Debug)]
struct Metrics {
    tasks_spawned: CounterFamily<Label>,
    tasks_running: GaugeFamily<Label>,
}

impl Metrics {
    pub fn init(registry: &mut impl Register) -> Self {
        Self {
            tasks_spawned: registry.register(
                "tasks_spawned",
                "Total number of tasks spawned",
                raw::Family::default(),
            ),
            tasks_running: registry.register(
                "tasks_running",
                "Number of tasks currently running",
                raw::Family::default(),
            ),
        }
    }
}

/// Configuration for the `iouring` runtime.
#[derive(Clone)]
pub struct Config {
    /// Configuration for the runtime's io_uring instance.
    ///
    /// One ring serves all storage and network I/O, so its `size` bounds the
    /// number of concurrently in-flight logical operations (each in-flight
    /// send, recv, accept, connect, read, write, or sync consumes one slot).
    /// `single_issuer` is always enabled by the runtime because the runtime
    /// thread creates the ring and is its only submitter, and
    /// `max_request_timeout` is raised to at least `read_write_timeout` and
    /// `connect_timeout` so network deadlines are never clamped.
    ring: RingConfig,

    /// Whether or not to catch panics.
    catch_panics: bool,

    /// Base directory for all storage operations.
    storage_directory: PathBuf,

    /// Stack size to use for runtime-owned threads.
    ///
    /// Defaults to the system stack size when the current platform exposes it,
    /// and otherwise falls back to Rust's default spawned-thread stack size.
    ///
    /// See [utils::thread::system_thread_stack_size].
    thread_stack_size: usize,

    /// Network configuration.
    network_cfg: NetworkConfig,

    /// Explicit buffer pool configuration for network I/O, if provided.
    network_buffer_pool_cfg: Option<BufferPoolConfig>,

    /// Explicit buffer pool configuration for storage I/O, if provided.
    storage_buffer_pool_cfg: Option<BufferPoolConfig>,
}

impl Config {
    /// Returns a new [Config] with default values.
    pub fn new() -> Self {
        let rng = sys_rng().next_u64();
        let storage_directory = env::temp_dir().join(format!("commonware_iouring_runtime_{rng}"));
        Self {
            ring: RingConfig {
                size: DEFAULT_RING_SIZE,
                ..Default::default()
            },
            catch_panics: false,
            storage_directory,
            thread_stack_size: utils::thread::system_thread_stack_size(),
            network_cfg: NetworkConfig::default(),
            network_buffer_pool_cfg: None,
            storage_buffer_pool_cfg: None,
        }
    }

    // Setters
    /// See [Config]
    pub const fn with_ring(mut self, ring: RingConfig) -> Self {
        self.ring = ring;
        self
    }
    /// See [Config]
    pub const fn with_catch_panics(mut self, b: bool) -> Self {
        self.catch_panics = b;
        self
    }
    /// See [Config]
    pub fn with_storage_directory(mut self, p: impl Into<PathBuf>) -> Self {
        self.storage_directory = p.into();
        self
    }
    /// See [Config]
    pub const fn with_thread_stack_size(mut self, n: usize) -> Self {
        self.thread_stack_size = n;
        self
    }
    /// See [Config]
    pub const fn with_connect_timeout(mut self, d: Duration) -> Self {
        self.network_cfg.connect_timeout = d;
        self
    }
    /// See [Config]
    pub const fn with_read_write_timeout(mut self, d: Duration) -> Self {
        self.network_cfg.read_write_timeout = d;
        self
    }
    /// See [Config]
    pub const fn with_tcp_nodelay(mut self, n: Option<bool>) -> Self {
        self.network_cfg.tcp_nodelay = n;
        self
    }
    /// See [Config]
    pub const fn with_zero_linger(mut self, l: bool) -> Self {
        self.network_cfg.zero_linger = l;
        self
    }
    /// See [Config]
    pub const fn with_read_buffer_size(mut self, n: usize) -> Self {
        self.network_cfg.read_buffer_size = n;
        self
    }
    /// See [Config]
    pub fn with_network_buffer_pool_config(mut self, cfg: BufferPoolConfig) -> Self {
        self.network_buffer_pool_cfg = Some(cfg);
        self
    }
    /// See [Config]
    pub fn with_storage_buffer_pool_config(mut self, cfg: BufferPoolConfig) -> Self {
        self.storage_buffer_pool_cfg = Some(cfg);
        self
    }

    // Getters
    /// See [Config]
    pub const fn ring(&self) -> &RingConfig {
        &self.ring
    }
    /// See [Config]
    pub const fn catch_panics(&self) -> bool {
        self.catch_panics
    }
    /// See [Config]
    pub const fn storage_directory(&self) -> &PathBuf {
        &self.storage_directory
    }
    /// See [Config]
    pub const fn thread_stack_size(&self) -> usize {
        self.thread_stack_size
    }
    /// See [Config]
    pub const fn read_write_timeout(&self) -> Duration {
        self.network_cfg.read_write_timeout
    }
    /// See [Config]
    pub const fn tcp_nodelay(&self) -> Option<bool> {
        self.network_cfg.tcp_nodelay
    }
    /// See [Config]
    pub const fn zero_linger(&self) -> bool {
        self.network_cfg.zero_linger
    }
    /// See [Config]
    pub const fn read_buffer_size(&self) -> usize {
        self.network_cfg.read_buffer_size
    }

    /// Returns the network buffer pool config, using the network default when
    /// not explicitly configured.
    fn resolved_network_buffer_pool_config(&self) -> BufferPoolConfig {
        self.network_buffer_pool_cfg
            .clone()
            .unwrap_or_else(BufferPoolConfig::for_network)
    }

    /// Returns the storage buffer pool config, using the storage default when
    /// not explicitly configured.
    fn resolved_storage_buffer_pool_config(&self) -> BufferPoolConfig {
        self.storage_buffer_pool_cfg
            .clone()
            .unwrap_or_else(BufferPoolConfig::for_storage)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

/// State shared by every worker thread of one runtime instance.
struct Globals {
    /// Configuration template used to construct workers.
    cfg: Config,
    registry: Registry,
    metrics: Arc<Metrics>,
    shutdown: Mutex<Stopper>,
    panicker: Panicker,
    network_buffer_pool: BufferPool,
    storage_buffer_pool: BufferPool,
    /// Threads running dedicated workers, joined when the root worker exits.
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

/// Runtime state shared by every [Context] on one worker thread.
pub struct Executor {
    globals: Arc<Globals>,
    tasks: Arc<Tasks>,
    sleeping: Mutex<BinaryHeap<Alarm>>,
}

impl Executor {
    /// Register a sleeper alarm.
    ///
    /// If the alarm becomes the earliest deadline, the runtime thread is woken
    /// so a park in progress recomputes its timeout: without this, an alarm
    /// registered from another thread while the runtime is parked would not
    /// fire until the previous park deadline elapsed.
    fn register_alarm(&self, alarm: Alarm) {
        let earliest = {
            let mut sleeping = self.sleeping.lock();
            let earliest = sleeping.peek().is_none_or(|next| alarm.time < next.time);
            sleeping.push(alarm);
            earliest
        };
        if earliest {
            self.tasks.unpark.wake();
        }
    }

    /// Wake any sleepers whose deadlines have elapsed.
    fn wake_ready_sleepers(&self, current: Instant) {
        let mut sleeping = self.sleeping.lock();
        while let Some(next) = sleeping.peek() {
            if next.time <= current {
                let sleeper = sleeping.pop().unwrap();
                sleeper.waker.wake();
            } else {
                break;
            }
        }
    }

    /// Return the delay until the next sleeper alarm, if any.
    fn next_alarm(&self) -> Option<Duration> {
        let sleeping = self.sleeping.lock();
        sleeping
            .peek()
            .map(|alarm| alarm.time.saturating_duration_since(Instant::now()))
    }
}

/// A single-threaded executor bound to a ring owned by its thread.
///
/// The thread calling [crate::Runner::start] runs one worker for the root
/// task, and every dedicated (or blocking shared) task runs on a worker of
/// its own thread. All op state a worker's tasks submit IO through is local
/// to its thread, so the driver's thread-affinity invariants hold per worker.
struct Worker {
    executor: Arc<Executor>,
    io: Arc<super::driver::Driver>,
    ioloop: IoUringLoop,
    ring: io_uring::IoUring,
    storage: Storage,
    network: Network,
}

impl Worker {
    /// Create a worker on the current thread: the ring, driver, and all op
    /// state become owned by this thread.
    ///
    /// Every worker registers its metric families under the same names, so
    /// worker metrics aggregate into the runtime-wide families.
    ///
    /// Panics if the ring cannot be created.
    fn new(globals: Arc<Globals>) -> Self {
        let mut registry = globals.registry.clone();
        let mut runtime_registry = registry.sub_registry(METRICS_PREFIX);

        // The worker thread creates the ring and is its only submitter, so
        // single issuer mode is always sound here.
        let mut ring_cfg = globals.cfg.ring.clone();
        ring_cfg.single_issuer = true;
        ring_cfg.max_request_timeout = ring_cfg
            .max_request_timeout
            .max(globals.cfg.network_cfg.read_write_timeout)
            .max(globals.cfg.network_cfg.connect_timeout);
        let (io, ioloop) =
            IoUringLoop::new(ring_cfg, &mut runtime_registry.sub_registry("iouring"));
        let ring = new_ring(&ioloop.cfg).unwrap_or_else(|err| {
            panic!(
                "unable to create io_uring instance ({err}): this runtime requires Linux 6.1+ \
                 (IORING_SETUP_SINGLE_ISSUER and IORING_SETUP_DEFER_TASKRUN)"
            )
        });

        // Initialize storage and network against this worker's driver.
        let storage = MeteredStorage::new(
            IoUringStorage::new(
                globals.cfg.storage_directory.clone(),
                io.clone(),
                globals.storage_buffer_pool.clone(),
            ),
            &mut runtime_registry,
        );
        let network = MeteredNetwork::new(
            IoUringNetwork::new(
                globals.cfg.network_cfg.clone(),
                io.clone(),
                globals.network_buffer_pool.clone(),
            ),
            &mut runtime_registry,
        );

        let executor = Arc::new(Executor {
            tasks: Arc::new(Tasks::new(ioloop.waker.clone())),
            sleeping: Mutex::new(BinaryHeap::new()),
            globals,
        });
        Self {
            executor,
            io,
            ioloop,
            ring,
            storage,
            network,
        }
    }

    /// Build a context rooted at `tree` for tasks on this worker.
    fn context(&self, name: String, attributes: Vec<(String, String)>, tree: Arc<Tree>) -> Context {
        Context {
            name,
            attributes,
            executor: Arc::downgrade(&self.executor),
            storage: self.storage.clone(),
            network: self.network.clone(),
            network_buffer_pool: self.executor.globals.network_buffer_pool.clone(),
            storage_buffer_pool: self.executor.globals.storage_buffer_pool.clone(),
            tree,
            execution: Execution::default(),
        }
    }

    /// Drive `root` to completion, interleaving task polling with the ring,
    /// then tear the worker down: abort `tree`, clear remaining tasks, and
    /// drain in-flight ring work before the ring is destroyed.
    ///
    /// A panic from the loop or teardown is resumed only after the ring is
    /// quiesced.
    fn run<F>(self, root: F, tree: Arc<Tree>) -> F::Output
    where
        F: Future,
    {
        let Self {
            executor,
            io,
            mut ioloop,
            mut ring,
            storage,
            network,
        } = self;
        let mut root = Box::pin(root);

        // Build the root task's waker (the root starts ready).
        let root_waker = Tasks::root_waker(&executor.tasks);

        // Process tasks until the root task completes.
        // Wrap the loop in catch_unwind to ensure task cleanup runs even if the loop or a task panics.
        let result = catch_unwind(AssertUnwindSafe(|| {
            loop {
                // Drain all ready tasks. Wakes that arrive while this snapshot
                // is being polled land in the next snapshot. The queue holds
                // the tasks themselves, so polling needs no registry lookup.
                //
                // Tasks run before the root so a task registered ahead of the
                // root's poll (e.g. the process-metrics collector) is polled
                // even if the root never yields.
                for task in executor.tasks.drain() {
                    let slot = task.slot();
                    if task.poll() {
                        executor.tasks.remove(slot);
                    }
                }

                // The root future lives on this stack frame, not in the
                // arena, so its typed output is captured un-erased.
                if executor.tasks.take_root_ready() {
                    let mut cx = task::Context::from_waker(&root_waker);
                    if let Poll::Ready(result) = root.as_mut().poll(&mut cx) {
                        break result;
                    }
                }

                // Service the ring: completions wake tasks and staged submissions
                // reach the kernel before the executor considers parking.
                ioloop.turn(&mut ring);

                // Wake sleepers whose deadlines have elapsed.
                executor.wake_ready_sleepers(Instant::now());

                // If any task became ready, keep polling instead of parking.
                if executor.tasks.has_ready() {
                    continue;
                }

                // Park until a completion arrives, a wake is published, or the
                // next timer (ring timeout wheel or sleeper alarm) is due.
                ioloop.park(&mut ring, executor.next_alarm());

                // Fire any sleepers that became due while parked.
                executor.wake_ready_sleepers(Instant::now());
            }
        }));

        // Abort every task spawned under this worker's root so registrations
        // racing teardown observe the abort.
        tree.abort();

        // Clear remaining tasks and the root: task futures run arbitrary user
        // drop code, and a panic here must not skip the drain below while the
        // waiter slab still owns kernel-referenced buffers, so capture it and
        // resume after the ring is quiesced.
        //
        // It is critical that we wait to drop the strong reference to executor
        // until after we have dropped all tasks (as they may attempt to
        // upgrade their weak reference to the executor during drop).
        let teardown = catch_unwind(AssertUnwindSafe(|| {
            executor.sleeping.lock().clear();
            for task in executor.tasks.clear() {
                task.clear();
            }

            // Drop the root task (and the worker's own handles) to release
            // any Context references still held.
            drop(root);
            drop(storage);
            drop(network);
        }));

        // Close the driver so late admissions fail with their kind-specific
        // error, then drain in-flight ring work so kernel-owned buffers and
        // descriptors are released before the ring is destroyed. Dropping the
        // tasks above already orphaned abandoned operations (eagerly
        // requesting their cancellation), so e.g. an idle recv does not hold
        // its waiter slot until its deadline.
        //
        // A panic inside the drain itself (an unrecoverable ring error) must
        // not unwind past this point: the slab would be freed while the kernel
        // may still write into its buffers, so abort instead.
        for waker in io.close() {
            waker.wake();
        }
        drop(io);
        if catch_unwind(AssertUnwindSafe(|| ioloop.drain(&mut ring))).is_err() {
            eprintln!("io_uring drain panicked with operations in flight, aborting");
            std::process::abort();
        }

        // Assert the context doesn't escape the worker (behavior is undefined
        // in this case)
        assert!(
            Arc::weak_count(&executor) == 0,
            "executor still has weak references"
        );

        // Handle the result — resume the original panic after cleanup if one
        // was caught, preferring it over a panic from task teardown.
        match (result, teardown) {
            (Err(payload), _) => resume_unwind(payload),
            (Ok(_), Err(payload)) => resume_unwind(payload),
            (Ok(output), Ok(())) => output,
        }
    }
}

/// Implementation of [crate::Runner] for the `iouring` runtime.
pub struct Runner {
    cfg: Config,
}

impl Default for Runner {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl Runner {
    /// Initialize a new `iouring` runtime with the given configuration.
    pub const fn new(cfg: Config) -> Self {
        Self { cfg }
    }
}

impl crate::Runner for Runner {
    type Context = Context;

    fn start<F, Fut>(self, f: F) -> Fut::Output
    where
        F: FnOnce(Self::Context) -> Fut,
        Fut: Future,
    {
        // Create a new registry
        let registry = Registry::new();
        let mut root_registry = registry.clone();
        let mut runtime_registry = root_registry.sub_registry(METRICS_PREFIX);

        // Initialize metrics and panicker
        let metrics = Arc::new(Metrics::init(&mut runtime_registry));
        let (panicker, panicked) = Panicker::new(self.cfg.catch_panics);

        // Initialize buffer pools
        let network_buffer_pool = BufferPool::new(
            self.cfg.resolved_network_buffer_pool_config(),
            &mut runtime_registry.sub_registry("network_buffer_pool"),
        );
        let storage_buffer_pool = BufferPool::new(
            self.cfg.resolved_storage_buffer_pool_config(),
            &mut runtime_registry.sub_registry("storage_buffer_pool"),
        );

        // Make any storage a prior process left in the page cache crash-durable before we open it,
        // so the data read during init is durable.
        if let Err(e) = crate::storage::sync(&self.cfg.storage_directory) {
            panic!(
                "failed to sync storage filesystem at startup ({}): {e}",
                self.cfg.storage_directory.display()
            );
        }

        // Initialize the state shared by every worker and run the root task's
        // worker on this thread.
        let globals = Arc::new(Globals {
            cfg: self.cfg,
            registry,
            metrics,
            shutdown: Mutex::new(Stopper::default()),
            panicker,
            network_buffer_pool,
            storage_buffer_pool,
            workers: Mutex::new(Vec::new()),
        });
        let worker = Worker::new(Arc::clone(&globals));

        // Collect process metrics.
        //
        // We prefer to collect process metrics outside of `Context` because
        // we are using `runtime_registry` rather than the one provided by `Context`.
        let process = MeteredProcess::init(&mut runtime_registry);
        let process_executor = Arc::downgrade(&worker.executor);
        let collector = process.collect(move |duration| Sleeper {
            executor: process_executor.clone(),
            time: Instant::now() + duration.min(MAX_SLEEP),
            registered: false,
        });
        let _ = Tasks::register(&worker.executor.tasks, collector);

        // Get metrics
        let label = Label::root();
        globals.metrics.tasks_spawned.get_or_create(&label).inc();
        let gauge = globals.metrics.tasks_running.get_or_create(&label).clone();

        // Build the root context and drive the root task on this worker.
        let root_tree = Tree::root();
        let context = worker.context(label.name(), Vec::new(), root_tree.clone());
        let output = worker.run(panicked.interrupt(f(context)), root_tree);

        // Join dedicated worker threads: the tree abort above cascaded to
        // their roots, so each worker winds down once it observes the abort.
        // Workers can spawn workers, so drain until the registry stays empty.
        // A worker infrastructure panic is resumed only after every thread
        // has been joined.
        let mut worker_panic = None;
        loop {
            let workers = take(&mut *globals.workers.lock());
            if workers.is_empty() {
                break;
            }
            for worker in workers {
                if let Err(payload) = worker.join() {
                    let _ = worker_panic.get_or_insert(payload);
                }
            }
        }
        if let Some(payload) = worker_panic {
            resume_unwind(payload);
        }

        gauge.dec();
        output
    }
}

/// Type-erased boundary for a task in the arena.
///
/// The concrete future lives inline in the task's single `Arc` allocation,
/// so the only dynamic dispatch on the poll path is this trait: inside the
/// monomorphized [TaskCell] methods the compiler sees the concrete future
/// type end to end.
trait Erased: Send + Sync {
    /// Poll the stored future, returning true when this call completed it
    /// (the caller then frees the task's arena slot).
    fn poll(self: Arc<Self>) -> bool;

    /// Resolve the task without polling: drop the future in place (which
    /// resolves any join handle with [Error::Closed]).
    fn clear(&self);

    /// The arena slot owning this task.
    fn slot(&self) -> usize;
}

/// A spawned task: one allocation holding the concrete future and the
/// identity behind its raw-vtable waker. Results reach the task's handle
/// through the wrapper built by [Handle::init], not through the cell.
struct TaskCell<F>
where
    F: Future<Output = ()>,
{
    /// Arena slot to free at completion.
    slot: usize,
    /// Re-enqueue target for wakes.
    tasks: Weak<Tasks>,
    /// The future, polled and cleared only on the executor thread (spawns
    /// run inline, so no lock is needed).
    ///
    /// `None` once the future completed or teardown cleared it.
    future: Affine<RefCell<Option<F>>>,
}

impl<F> TaskCell<F>
where
    F: Future<Output = ()> + Send + 'static,
{
    /// Waker vtable sharing the task's own allocation: cloning bumps the
    /// task's strong count and waking enqueues the task pointer directly, so
    /// wakes carry no id and polls need no registry lookup.
    const VTABLE: task::RawWakerVTable = task::RawWakerVTable::new(
        Self::waker_clone,
        Self::waker_wake,
        Self::waker_wake_by_ref,
        Self::waker_drop,
    );

    /// Manufacture a waker backed by this task's allocation.
    ///
    /// Waker identity is (data pointer, vtable), both stable for the task's
    /// lifetime, so every poll presents an identical waker and
    /// `Waker::will_wake` fast paths (e.g. the driver's slot refreshes) hold.
    fn waker(self: &Arc<Self>) -> task::Waker {
        let ptr = Arc::into_raw(Arc::clone(self)).cast::<()>();
        // SAFETY: the vtable functions uphold the RawWaker contract over the
        // Arc reference encoded in `ptr`.
        unsafe { task::Waker::from_raw(task::RawWaker::new(ptr, &Self::VTABLE)) }
    }

    unsafe fn waker_clone(ptr: *const ()) -> task::RawWaker {
        // SAFETY: `ptr` encodes an Arc<Self> reference from [Self::waker].
        unsafe { Arc::increment_strong_count(ptr.cast::<Self>()) };
        task::RawWaker::new(ptr, &Self::VTABLE)
    }

    unsafe fn waker_wake(ptr: *const ()) {
        // SAFETY: consumes the waker's Arc reference.
        let cell = unsafe { Arc::from_raw(ptr.cast::<Self>()) };
        cell.enqueue();
    }

    unsafe fn waker_wake_by_ref(ptr: *const ()) {
        // SAFETY: borrows the waker's Arc reference without consuming it.
        let cell = unsafe { ManuallyDrop::new(Arc::from_raw(ptr.cast::<Self>())) };
        cell.enqueue();
    }

    unsafe fn waker_drop(ptr: *const ()) {
        // SAFETY: releases the waker's Arc reference.
        drop(unsafe { Arc::from_raw(ptr.cast::<Self>()) });
    }

    /// Re-enqueue this task for polling.
    ///
    /// If the upgrade fails, the runtime already exited and the wake is a
    /// no-op (e.g. data holding a waker dropped after `start` returned).
    fn enqueue(self: &Arc<Self>) {
        if let Some(tasks) = self.tasks.upgrade() {
            tasks.queue(Arc::clone(self) as Arc<dyn Erased>);
        }
    }
}

impl<F> Erased for TaskCell<F>
where
    F: Future<Output = ()> + Send + 'static,
{
    fn poll(self: Arc<Self>) -> bool {
        let waker = self.waker();
        let mut cx = task::Context::from_waker(&waker);
        self.future.with(|cell| {
            let mut slot = cell.borrow_mut();
            // A duplicate wake may re-poll a completed task: its slot was
            // already freed, so report no completion.
            let Some(future) = slot.as_mut() else {
                return false;
            };
            // SAFETY: the future lives inside this task's Arc allocation and
            // is never moved out of it: completion (below) and teardown
            // ([Erased::clear]) both drop it in place by overwriting the
            // option with None.
            let future = unsafe { Pin::new_unchecked(future) };
            match future.poll(&mut cx) {
                Poll::Ready(()) => {
                    *slot = None;
                    true
                }
                Poll::Pending => false,
            }
        })
    }

    fn clear(&self) {
        self.future.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }

    fn slot(&self) -> usize {
        self.slot
    }
}

/// A waker for the root task, which lives on the runtime thread's stack (so
/// its typed output is captured un-erased) rather than in the arena.
struct RootWaker {
    tasks: Weak<Tasks>,
}

impl ArcWake for RootWaker {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        // If the upgrade fails, the runtime already exited.
        if let Some(tasks) = arc_self.tasks.upgrade() {
            tasks.queue_root();
        }
    }
}

/// The arena of running tasks, plus whether the executor has shut down.
struct Running {
    /// Task slots; freed slots are recycled through `free`.
    slots: Vec<Option<Arc<dyn Erased>>>,
    /// Recycled slot indices.
    free: Vec<usize>,
    /// Set once the executor clears the arena at teardown. Registrations that
    /// race teardown are rejected (resolving their handles with
    /// [Error::Closed]) instead of leaking into an arena nothing will ever
    /// poll again.
    closed: bool,
}

/// The tasks being executed by the [Executor].
struct Tasks {
    /// Tasks ready to be polled, queued by pointer (no ids, no lookups).
    ready: Mutex<Vec<Arc<dyn Erased>>>,
    /// Whether the root task is ready to be polled. Starts true for the
    /// kickoff poll.
    root_ready: AtomicBool,
    /// The arena owning all running tasks (for teardown enumeration).
    running: Mutex<Running>,
    /// Wakes the runtime thread when a task becomes ready.
    ///
    /// Latches the event loop's out-of-band wake state so a parked executor
    /// (futex or `submit_and_wait`) observes the enqueue from any thread.
    unpark: RingWaker,
}

impl Tasks {
    /// Create a new task queue.
    const fn new(unpark: RingWaker) -> Self {
        Self {
            ready: Mutex::new(Vec::new()),
            root_ready: AtomicBool::new(true),
            running: Mutex::new(Running {
                slots: Vec::new(),
                free: Vec::new(),
                closed: false,
            }),
            unpark,
        }
    }

    /// Build the root task's waker.
    fn root_waker(arc_self: &Arc<Self>) -> task::Waker {
        waker(Arc::new(RootWaker {
            tasks: Arc::downgrade(arc_self),
        }))
    }

    /// Register a task for `future` and queue its first poll.
    ///
    /// Returns false (dropping the future) when the executor is already
    /// tearing down.
    fn register<F>(arc_self: &Arc<Self>, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let cell = {
            let mut running = arc_self.running.lock();
            if running.closed {
                return false;
            }
            let slot = running.free.pop().unwrap_or_else(|| {
                running.slots.push(None);
                running.slots.len() - 1
            });
            let cell = Arc::new(TaskCell {
                slot,
                tasks: Arc::downgrade(arc_self),
                future: Affine::new(RefCell::new(Some(future))),
            });
            running.slots[slot] = Some(Arc::clone(&cell) as Arc<dyn Erased>);
            cell
        };

        // Queue the first poll.
        arc_self.queue(cell as Arc<dyn Erased>);
        true
    }

    /// Enqueue an already registered task to be polled.
    fn queue(&self, task: Arc<dyn Erased>) {
        self.ready.lock().push(task);

        // Wake the runtime thread in case it is parked. Wakes from the runtime
        // thread itself only latch the (already awake) wake state.
        self.unpark.wake();
    }

    /// Mark the root task ready to be polled.
    fn queue_root(&self) {
        self.root_ready.store(true, Ordering::Release);
        self.unpark.wake();
    }

    /// Take the root task's readiness.
    fn take_root_ready(&self) -> bool {
        self.root_ready.swap(false, Ordering::Acquire)
    }

    /// Drain all ready tasks.
    fn drain(&self) -> Vec<Arc<dyn Erased>> {
        let mut queue = self.ready.lock();
        let len = queue.len();
        replace(&mut *queue, Vec::with_capacity(len))
    }

    /// Whether any task (including the root) is ready to be polled.
    fn has_ready(&self) -> bool {
        self.root_ready.load(Ordering::Acquire) || !self.ready.lock().is_empty()
    }

    /// Free a completed task's arena slot.
    fn remove(&self, slot: usize) {
        let mut running = self.running.lock();
        if running.closed {
            return;
        }
        running.slots[slot] = None;
        running.free.push(slot);
    }

    /// Clear all tasks and reject future registrations.
    fn clear(&self) -> Vec<Arc<dyn Erased>> {
        // Clear ready
        self.ready.lock().clear();

        // Clear running tasks and close the arena so registrations racing
        // teardown are rejected rather than leaked.
        let slots = {
            let mut running = self.running.lock();
            running.closed = true;
            running.free.clear();
            take(&mut running.slots)
        };
        slots.into_iter().flatten().collect()
    }
}

type Storage = MeteredStorage<IoUringStorage>;
type Network = MeteredNetwork<IoUringNetwork>;

/// Implementation of [crate::Spawner], [crate::Clock],
/// [crate::Network], and [crate::Storage] for the `iouring`
/// runtime.
pub struct Context {
    name: String,
    attributes: Vec<(String, String)>,
    executor: Weak<Executor>,
    storage: Storage,
    network: Network,
    network_buffer_pool: BufferPool,
    storage_buffer_pool: BufferPool,
    tree: Arc<Tree>,
    execution: Execution,
}

impl Context {
    /// Upgrade the weak reference to the [Executor].
    fn executor(&self) -> Arc<Executor> {
        self.executor.upgrade().expect("executor already dropped")
    }

    /// Access the [Metrics] of the runtime.
    fn metrics(&self) -> Arc<Metrics> {
        self.executor().globals.metrics.clone()
    }

    /// Run `f` as the root task of a worker on its own thread.
    ///
    /// The handle is assembled from parts on the caller: the wrapper that
    /// owns the result sender only exists once the worker thread has built
    /// its ring. Panics on the worker thread outside the task itself (e.g.
    /// ring creation failure) resolve the handle with [Error::Closed] and
    /// are resumed when the runtime joins its workers at teardown.
    fn spawn_worker<F, Fut, T>(
        self,
        f: F,
        metric: utils::MetricHandle,
        parent: Arc<Tree>,
    ) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Drop the parent-worker context pieces (storage, network, executor
        // reference): the task's context is rebuilt against its own worker.
        let Self {
            name,
            attributes,
            executor,
            tree,
            ..
        } = self;
        let globals = {
            let executor = executor.upgrade().expect("executor already dropped");
            Arc::clone(&executor.globals)
        };

        let (sender, receiver) = oneshot::channel();
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let handle = Handle::from_parts(receiver, abort_handle, metric.clone());
        if let Some(aborter) = handle.aborter() {
            parent.register(aborter);
        }

        // Run the worker until the task completes or teardown aborts it.
        let thread_globals = Arc::clone(&globals);
        let worker = utils::thread::spawn(globals.cfg.thread_stack_size, move || {
            let worker = Worker::new(Arc::clone(&thread_globals));
            let context = worker.context(name, attributes, Arc::clone(&tree));

            // Wrap the future with panic catching, abort support, and
            // cleanup, mirroring the wrapper [Handle::init] builds for
            // executor tasks.
            let panicker = thread_globals.panicker.clone();
            let wrapped = async move {
                let result = Abortable::new(
                    AssertUnwindSafe(f(context)).catch_unwind(),
                    abort_registration,
                )
                .await;
                match result {
                    Ok(Ok(value)) => {
                        let _ = sender.send(Ok(value));
                    }
                    Ok(Err(panic)) => {
                        panicker.notify(panic);
                        let _ = sender.send(Err(Error::Exited));
                    }
                    Err(Aborted) => {}
                }
                metric.finish();
            };
            worker.run(wrapped, tree);
        });
        globals.workers.lock().push(worker);

        handle
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

    fn spawn<F, Fut, T>(mut self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Get metrics
        let (_, metric) = spawn_metrics!(self);

        // Track supervision before resetting configuration
        let parent = Arc::clone(&self.tree);
        let past = self.execution;
        self.execution = Execution::default();
        let (child, aborted) = Tree::child(&parent);
        if aborted {
            return Handle::closed(metric);
        }
        self.tree = child;

        // Dedicated tasks (and, until a shared blocking pool lands, blocking
        // shared tasks) run as the root of a worker on their own thread: the
        // worker owns its own ring, so the task's context submits IO without
        // touching this thread's loop.
        if !matches!(past, Execution::Shared(false)) {
            return self.spawn_worker(f, metric, parent);
        }

        // Wrap the future with panic catching, abort support, and cleanup.
        let executor = self.executor();
        let future = f(self);
        let (task, handle) = Handle::init(
            future,
            metric.clone(),
            executor.globals.panicker.clone(),
            Arc::clone(&parent),
        );

        // Register the task, unless the executor is already tearing down.
        if !Tasks::register(&executor.tasks, task) {
            return Handle::closed(metric);
        }

        // Register the task on the parent
        if let Some(aborter) = handle.aborter() {
            parent.register(aborter);
        }

        handle
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        let stop_resolved = {
            let executor = self.executor();
            let mut shutdown = executor.globals.shutdown.lock();
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
            _ = timeout_future => Err(Error::Timeout),
        }
    }

    fn stopped(&self) -> Signal {
        self.executor().globals.shutdown.lock().stopped()
    }
}

/// Rayon workers execute compute-only work and never submit ring operations,
/// so the pool is backed by plain OS threads (one per unit of parallelism)
/// rather than runtime tasks: [crate::Spawner::dedicated] is unavailable on
/// this runtime, and pool completions wake awaiting tasks through the loop's
/// latched cross-thread wake state.
#[stability(BETA)]
impl crate::Strategizer for Context {
    fn strategy(&self, parallelism: NonZeroUsize) -> Rayon {
        let stack_size = self.executor().globals.cfg.thread_stack_size;
        let pool = ThreadPoolBuilder::new()
            .num_threads(parallelism.get())
            .spawn_handler(move |thread| {
                let stack_size = thread.stack_size().unwrap_or(stack_size);
                utils::thread::spawn(stack_size, move || thread.run());
                Ok(())
            })
            .build()
            .expect("failed to create io_uring Rayon thread pool");
        Rayon::with_pool(Arc::new(pool))
    }
}

impl crate::Supervisor for Context {
    fn child(&self, label: &'static str) -> Self {
        let (tree, _) = Tree::child(&self.tree);
        Self {
            name: child_label(&self.name, label),
            attributes: self.attributes.clone(),
            executor: self.executor.clone(),
            storage: self.storage.clone(),
            network: self.network.clone(),
            network_buffer_pool: self.network_buffer_pool.clone(),
            storage_buffer_pool: self.storage_buffer_pool.clone(),
            tree,
            execution: Execution::default(),
        }
    }

    fn with_attribute(mut self, key: &'static str, value: impl std::fmt::Display) -> Self {
        // Validate label format (must match [a-zA-Z][a-zA-Z0-9_]*)
        validate_label(key);

        // Add the attribute to the list of attributes
        add_attribute(&mut self.attributes, key, value);
        self
    }

    fn name(&self) -> Name {
        Name {
            label: self.name.clone(),
            attributes: self.attributes.clone(),
        }
    }
}

impl crate::Metrics for Context {
    fn register<N: Into<String>, H: Into<String>, M: Metric>(
        &self,
        name: N,
        help: H,
        metric: M,
    ) -> Registered<M> {
        let name = name.into();
        let help = help.into();
        let metric = Arc::new(metric);
        self.executor().globals.registry.register(
            prefixed_name(&self.name, &name),
            help,
            self.attributes.clone(),
            metric,
        )
    }

    fn encode(&self) -> String {
        self.executor().globals.registry.encode()
    }
}

/// A future that resolves once a deadline has passed.
///
/// Deadlines are tracked on the monotonic clock: wall-clock inputs (e.g.
/// [Clock::sleep_until]) are converted once at creation, so a system clock
/// step can neither strand a sleeper nor fire it early.
struct Sleeper {
    executor: Weak<Executor>,
    time: Instant,
    registered: bool,
}

struct Alarm {
    time: Instant,
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
        if Instant::now() >= self.time {
            return Poll::Ready(());
        }
        if !self.registered {
            self.registered = true;
            let executor = self.executor.upgrade().expect("executor already dropped");
            executor.register_alarm(Alarm {
                time: self.time,
                waker: cx.waker().clone(),
            });
        }
        Poll::Pending
    }
}

impl Clock for Context {
    fn current(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        Sleeper {
            executor: self.executor.clone(),
            time: Instant::now() + duration.min(MAX_SLEEP),
            registered: false,
        }
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        // Convert the wall-clock deadline to a monotonic one exactly once so
        // later system clock steps do not move the wakeup.
        let delay = deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        self.sleep(delay)
    }
}

#[cfg(feature = "external")]
impl Pacer for Context {
    fn pace<'a, F, T>(
        &'a self,
        _latency: Duration,
        future: F,
    ) -> impl Future<Output = T> + Send + 'a
    where
        F: Future<Output = T> + Send + 'a,
        T: Send + 'a,
    {
        // Execute the future immediately
        future
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
    type Listener = <Network as crate::Network>::Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        self.network.bind(socket).await
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(SinkOf<Self>, StreamOf<Self>), Error> {
        self.network.dial(socket).await
    }
}

impl crate::Resolver for Context {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, Error> {
        // Uses the host's DNS configuration via the system's libc resolver.
        // `getaddrinfo` is blocking, so resolution runs on a short-lived
        // helper thread.
        //
        // The `:0` port is required by `to_socket_addrs` but is not used for
        // DNS resolution.
        let host_port = format!("{host}:0");
        let (tx, rx) = oneshot::channel();
        utils::thread::spawn(self.executor().globals.cfg.thread_stack_size, move || {
            let result = std::net::ToSocketAddrs::to_socket_addrs(host_port.as_str())
                .map(|addrs| addrs.map(|addr| addr.ip()).collect::<Vec<_>>())
                .map_err(|e| Error::ResolveFailed(e.to_string()));
            let _ = tx.send(result);
        });
        rx.await
            .map_err(|_| Error::ResolveFailed("resolver thread exited".into()))?
    }
}

impl TryRng for Context {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(sys_rng().next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(sys_rng().next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        sys_rng().fill_bytes(dest);
        Ok(())
    }
}

impl TryCryptoRng for Context {}

impl crate::Storage for Context {
    type Blob = <Storage as crate::Storage>::Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        self.storage.open_versioned(partition, name, versions).await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.storage.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.storage.scan(partition).await
    }
}

impl crate::BufferPooler for Context {
    fn network_buffer_pool(&self) -> &BufferPool {
        &self.network_buffer_pool
    }

    fn storage_buffer_pool(&self) -> &BufferPool {
        &self.storage_buffer_pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Blob as _, IoBuf, Listener as _, Metrics as _, Network as _, Resolver as _, Runner as _,
        Sink as _, Spawner as _, Storage as _, Strategizer as _, Stream as _, Supervisor as _,
    };
    use commonware_parallel::Strategy as _;
    use commonware_utils::{NZUsize, channel::oneshot};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    /// A dedicated task runs on its own worker with its own ring: storage
    /// and network operations issued from it must work end to end, including
    /// against a listener owned by another worker.
    #[test]
    fn test_dedicated_worker_io() {
        Runner::default().start(|context| async move {
            // Bind a listener on the root worker.
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            // The dedicated task writes durable storage through its own ring
            // and dials the root worker's listener over real TCP.
            let dedicated =
                context
                    .child("dedicated")
                    .dedicated()
                    .spawn(move |context| async move {
                        let (blob, len) = context.open("partition", b"blob").await.unwrap();
                        assert_eq!(len, 0);
                        blob.write_at(0, IoBuf::from(b"hello")).await.unwrap();
                        blob.sync().await.unwrap();
                        let read = blob.read_at(0, 5).await.unwrap();
                        assert_eq!(read.coalesce(), b"hello");

                        let (mut sink, mut stream) = context.dial(addr).await.unwrap();
                        sink.send(IoBuf::from(b"ping")).await.unwrap();
                        let response = stream.recv(4).await.unwrap();
                        assert_eq!(response.coalesce(), b"pong");
                    });

            // Serve the dedicated task's connection from the root worker.
            let (_, mut sink, mut stream) = listener.accept().await.unwrap();
            let msg = stream.recv(4).await.unwrap();
            assert_eq!(msg.coalesce(), b"ping");
            sink.send(IoBuf::from(b"pong")).await.unwrap();

            dedicated.await.unwrap();
        });
    }

    /// Aborting a dedicated task tears its worker down promptly, and the
    /// runtime joins the worker thread at teardown.
    #[test]
    fn test_dedicated_worker_abort() {
        let start = std::time::Instant::now();
        Runner::default().start(|context| async move {
            let handle = context
                .child("dedicated")
                .dedicated()
                .spawn(|context| async move {
                    loop {
                        context.sleep(Duration::from_millis(10)).await;
                    }
                });
            context.sleep(Duration::from_millis(50)).await;
            handle.abort();
            assert!(matches!(handle.await, Err(Error::Closed)));
        });
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "worker teardown took {:?}",
            start.elapsed()
        );
    }

    /// Until a shared blocking pool lands, blocking shared tasks alias
    /// dedicated ones: std-blocking work must not starve the root executor.
    #[test]
    fn test_spawn_blocking_runs_off_thread() {
        Runner::default().start(|context| async move {
            let blocking = context
                .child("blocking")
                .shared(true)
                .spawn(|_| async move {
                    std::thread::sleep(Duration::from_millis(200));
                    42
                });

            // The root worker keeps making progress while the blocking task
            // holds its own thread.
            let start = std::time::Instant::now();
            context.sleep(Duration::from_millis(20)).await;
            assert!(start.elapsed() < Duration::from_millis(150));

            assert_eq!(blocking.await.unwrap(), 42);
        });
    }

    #[test]
    fn test_network_echo() {
        // Exercise bind, accept, dial, send, and recv end-to-end on the
        // runtime's own ring (all connection setup goes through io_uring).
        let executor = Runner::default();
        executor.start(|context| async move {
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            let server = context.child("server").spawn(move |_| async move {
                let (_, mut sink, mut stream) = listener.accept().await.unwrap();
                let msg = stream.recv(5).await.unwrap();
                assert_eq!(msg.coalesce(), b"hello");
                sink.send(IoBuf::from(b"world")).await.unwrap();
            });

            let (mut sink, mut stream) = context.dial(addr).await.unwrap();
            sink.send(IoBuf::from(b"hello")).await.unwrap();
            let response = stream.recv(5).await.unwrap();
            assert_eq!(response.coalesce(), b"world");
            server.await.unwrap();
        });
    }

    #[test]
    fn test_network_recv_timeout() {
        // Exercise a network deadline expiring while the executor drives
        // the ring (turn/park path): the recv must report a timeout close
        // to the configured budget instead of stalling.
        let op_timeout = Duration::from_millis(100);
        let cfg = Config::default().with_read_write_timeout(op_timeout);
        Runner::new(cfg).start(|context| async move {
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            let server = context.child("server").spawn(move |_| async move {
                let (_, sink, mut stream) = listener.accept().await.unwrap();
                let result = stream.recv(1).await;
                assert!(matches!(result, Err(Error::Timeout)));
                // Keep the connection alive until the recv resolves.
                drop(sink);
            });

            // Dial but never send, so the server's recv can only expire.
            let start = std::time::Instant::now();
            let (_sink, _stream) = context.dial(addr).await.unwrap();
            server.await.unwrap();
            let elapsed = start.elapsed();
            assert!(elapsed >= op_timeout);
            assert!(elapsed < op_timeout * 30, "recv timeout took {elapsed:?}");
        });
    }

    #[test]
    fn test_fast_teardown_with_inflight_recv() {
        // A recv still in flight when the root task returns must not delay
        // teardown until its (60s) deadline: teardown cancels operations
        // whose tasks were dropped.
        let start = std::time::Instant::now();
        let cfg = Config::default().with_read_write_timeout(Duration::from_secs(60));
        Runner::new(cfg).start(|context| async move {
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            context.child("server").spawn(move |_| async move {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                // Never receives data; aborted when the root returns.
                let _ = stream.recv(1).await;
            });

            let (_sink, _stream) = context.dial(addr).await.unwrap();
            // Give the server's recv a chance to reach the kernel.
            context.sleep(Duration::from_millis(50)).await;
        });
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "teardown took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn test_accept_survives_reissue() {
        // An accept that waits longer than the read/write timeout is
        // transparently reissued: a connection arriving after several
        // reissue cycles must still be accepted.
        let op_timeout = Duration::from_millis(50);
        let cfg = Config::default().with_read_write_timeout(op_timeout);
        Runner::new(cfg).start(|context| async move {
            let mut listener = context
                .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            let server = context.child("server").spawn(move |_| async move {
                let (_, _sink, mut stream) = listener.accept().await.unwrap();
                let msg = stream.recv(4).await.unwrap();
                assert_eq!(msg.coalesce(), b"ping");
            });

            // Wait through multiple accept deadlines before connecting.
            context.sleep(op_timeout * 4).await;
            let (mut sink, _stream) = context.dial(addr).await.unwrap();
            sink.send(IoBuf::from(b"ping")).await.unwrap();
            server.await.unwrap();
        });
    }

    #[test]
    fn test_cross_thread_wake() {
        // Verify a foreign thread can wake the runtime thread out of its
        // park: the sleep gives the runtime time to park (so the alarm is
        // registered from another thread against a parked runtime), and
        // the oneshot send must then unblock the root task.
        let executor = Runner::default();
        executor.start(|context| async move {
            let start = std::time::Instant::now();
            let (tx, rx) = oneshot::channel();
            let thread = std::thread::spawn(move || {
                futures::executor::block_on(context.sleep(Duration::from_millis(50)));
                tx.send(42).unwrap();
            });
            assert_eq!(rx.await.unwrap(), 42);

            // Join so the thread's context clone drops before teardown
            // asserts that no context escaped the runtime.
            thread.join().unwrap();

            // The wake must arrive promptly after the 50ms sleep, not at
            // the runtime's next unrelated park deadline.
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "cross-thread wake took {:?}",
                start.elapsed()
            );
        });
    }

    #[test]
    fn test_process_rss_metric() {
        let executor = Runner::default();
        executor.start(|context| async move {
            loop {
                // Wait for RSS metric to be available
                let metrics = context.encode();
                if !metrics.contains("runtime_process_rss") {
                    context.sleep(Duration::from_millis(100)).await;
                    continue;
                }

                // Verify the RSS value is eventually populated (greater than 0)
                for line in metrics.lines() {
                    if line.starts_with("runtime_process_rss")
                        && !line.starts_with("runtime_process_rss{")
                    {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let rss_value: i64 =
                                parts[1].parse().expect("Failed to parse RSS value");
                            if rss_value > 0 {
                                return;
                            }
                        }
                    }
                }
            }
        });
    }

    #[test]
    fn test_resolver() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let addrs = context.resolve("localhost").await.unwrap();
            assert!(!addrs.is_empty());
            for addr in addrs {
                assert!(
                    addr == IpAddr::V4(Ipv4Addr::LOCALHOST)
                        || addr == IpAddr::V6(Ipv6Addr::LOCALHOST)
                );
            }
        });
    }

    /// Pool work runs on dedicated worker threads, so awaiting a spawned
    /// strategy task exercises the loop's cross-thread wake path.
    #[test]
    fn test_parallel_strategy_spawn_completes() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let strategy = context.child("pool").strategy(NZUsize!(2)).manual();
            assert_eq!(strategy.parallelism(), 2);

            let output = strategy
                .spawn(|strategy| strategy.map_collect_vec(0..2, |i| i + 1))
                .await;

            assert_eq!(output, vec![1, 2]);
        });
    }
}
