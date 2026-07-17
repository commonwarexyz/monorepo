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
//! Every task runs inline on the executor thread. Tasks spawned with
//! [crate::Spawner::dedicated] or [crate::Spawner::shared] with
//! `blocking == true` are temporarily unsupported and panic at spawn: the
//! single-threaded executor cannot absorb blocking work, and the runtime
//! manages no worker threads to offload it to. Support is planned to return
//! with a blocking pool. Cross-thread interactions that do not submit ring
//! operations (waking a task from a helper thread, registering a sleeper
//! alarm, delivering a stop signal) remain supported through the loop's
//! latched wake state.

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
    utils::{self, Join, Panicker, signal::Stopper, supervision::Tree},
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

/// Runtime state shared by every [Context].
pub struct Executor {
    registry: Registry,
    metrics: Arc<Metrics>,
    tasks: Arc<Tasks>,
    sleeping: Mutex<BinaryHeap<Alarm>>,
    shutdown: Mutex<Stopper>,
    panicker: Panicker,
    thread_stack_size: usize,
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
        let mut registry = Registry::new();
        let mut runtime_registry = registry.sub_registry(METRICS_PREFIX);

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

        // Initialize the io_uring event loop and create the ring on this
        // thread. The runtime thread is the ring's only submitter, so single
        // issuer mode is always sound here.
        let mut ring_cfg = self.cfg.ring.clone();
        ring_cfg.single_issuer = true;
        ring_cfg.max_request_timeout = ring_cfg
            .max_request_timeout
            .max(self.cfg.network_cfg.read_write_timeout)
            .max(self.cfg.network_cfg.connect_timeout);
        let (io, mut ioloop) =
            IoUringLoop::new(ring_cfg, &mut runtime_registry.sub_registry("iouring"));
        let mut ring = new_ring(&ioloop.cfg).unwrap_or_else(|err| {
            panic!(
                "unable to create io_uring instance ({err}): this runtime requires Linux 6.1+ \
                 (IORING_SETUP_SINGLE_ISSUER and IORING_SETUP_DEFER_TASKRUN)"
            )
        });

        // Initialize storage
        let storage = MeteredStorage::new(
            IoUringStorage::new(
                self.cfg.storage_directory.clone(),
                io.clone(),
                storage_buffer_pool.clone(),
            ),
            &mut runtime_registry,
        );

        // Initialize network
        let network = MeteredNetwork::new(
            IoUringNetwork::new(
                self.cfg.network_cfg.clone(),
                io.clone(),
                network_buffer_pool.clone(),
            ),
            &mut runtime_registry,
        );

        // Initialize executor
        let executor = Arc::new(Executor {
            registry,
            metrics,
            tasks: Arc::new(Tasks::new(ioloop.waker.clone())),
            sleeping: Mutex::new(BinaryHeap::new()),
            shutdown: Mutex::new(Stopper::default()),
            panicker,
            thread_stack_size: self.cfg.thread_stack_size,
        });

        // Collect process metrics.
        //
        // We prefer to collect process metrics outside of `Context` because
        // we are using `runtime_registry` rather than the one provided by `Context`.
        let process = MeteredProcess::init(&mut runtime_registry);
        let process_executor = Arc::downgrade(&executor);
        let collector = process.collect(move |duration| Sleeper {
            executor: process_executor.clone(),
            time: Instant::now() + duration.min(MAX_SLEEP),
            registered: false,
        });
        let _ = Tasks::register(&executor.tasks, async move {
            collector.await;
            Ok(())
        });

        // Get metrics
        let label = Label::root();
        executor.metrics.tasks_spawned.get_or_create(&label).inc();
        let gauge = executor.metrics.tasks_running.get_or_create(&label).clone();

        // Build the root context and pin the root task to the heap
        let root_tree = Tree::root();
        let context = Context {
            name: label.name(),
            attributes: Vec::new(),
            executor: Arc::downgrade(&executor),
            storage,
            network,
            network_buffer_pool,
            storage_buffer_pool,
            tree: root_tree.clone(),
            execution: Execution::default(),
        };
        let mut root = Box::pin(panicked.interrupt(f(context)));

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

        // Abort every task spawned under the root context so registrations
        // racing teardown observe the abort.
        root_tree.abort();

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

            // Drop the root task to release any Context references it may
            // still hold.
            drop(root);
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

        // Assert the context doesn't escape the start() function (behavior
        // is undefined in this case)
        assert!(
            Arc::weak_count(&executor) == 0,
            "executor still has weak references"
        );

        // Handle the result — resume the original panic after cleanup if one
        // was caught, preferring it over a panic from task teardown.
        let output = match (result, teardown) {
            (Err(payload), _) => resume_unwind(payload),
            (Ok(_), Err(payload)) => resume_unwind(payload),
            (Ok(output), Ok(())) => output,
        };
        gauge.dec();

        output
    }
}

/// Type-erased boundary for a task in the arena.
///
/// The concrete future and its join state live inline in the task's single
/// `Arc` allocation, so the only dynamic dispatch on the poll path is this
/// trait: inside the monomorphized [TaskCell] methods the compiler sees the
/// concrete future type end to end.
trait Erased: Send + Sync {
    /// Poll the stored future, returning true when this call completed it
    /// (the caller then frees the task's arena slot).
    fn poll(self: Arc<Self>) -> bool;

    /// Resolve the task without polling: drop the future in place and park a
    /// [Error::Closed] result for any join handle.
    fn clear(&self);

    /// The arena slot owning this task.
    fn slot(&self) -> usize;
}

/// Result rendezvous between a task and its [Handle].
enum JoinState<T> {
    /// The task is still running; the handle's waker parks here.
    Pending(Option<task::Waker>),
    /// The terminal result is parked for the handle.
    Ready(Result<T, Error>),
    /// The handle already took the result.
    Taken,
}

/// A spawned task: one allocation holding the concrete future, the join
/// state its handle polls, and the identity behind its raw-vtable waker.
struct TaskCell<F, T>
where
    F: Future<Output = Result<T, Error>>,
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
    /// Parked result and handle waker. Handles are polled on the executor
    /// thread (tasks run inline); off-thread polls panic like every other
    /// runtime operation.
    join: Affine<RefCell<JoinState<T>>>,
}

impl<F, T> TaskCell<F, T>
where
    F: Future<Output = Result<T, Error>> + Send + 'static,
    T: Send + 'static,
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

    /// Park `result` for the handle and wake it.
    ///
    /// Tolerates an already-resolved join so completion and teardown can both
    /// call it.
    fn finish(&self, result: Result<T, Error>) {
        let waker = self.join.with(|join| {
            let mut join = join.borrow_mut();
            let JoinState::Pending(waker) = &mut *join else {
                return None;
            };
            let waker = waker.take();
            *join = JoinState::Ready(result);
            waker
        });
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<F, T> Erased for TaskCell<F, T>
where
    F: Future<Output = Result<T, Error>> + Send + 'static,
    T: Send + 'static,
{
    fn poll(self: Arc<Self>) -> bool {
        let waker = self.waker();
        let mut cx = task::Context::from_waker(&waker);
        let polled = self.future.with(|cell| {
            let mut slot = cell.borrow_mut();
            // A duplicate wake may re-poll a completed task: its slot was
            // already freed, so report no completion.
            let future = slot.as_mut()?;
            // SAFETY: the future lives inside this task's Arc allocation and
            // is never moved out of it: completion (below) and teardown
            // ([Erased::clear]) both drop it in place by overwriting the
            // option with None.
            let future = unsafe { Pin::new_unchecked(future) };
            match future.poll(&mut cx) {
                Poll::Ready(result) => {
                    *slot = None;
                    Some(Some(result))
                }
                Poll::Pending => Some(None),
            }
        });
        match polled {
            // Completed on this poll: park the result and free the slot.
            Some(Some(result)) => {
                self.finish(result);
                true
            }
            // Still pending.
            Some(None) => false,
            // Already completed by an earlier poll.
            None => false,
        }
    }

    fn clear(&self) {
        self.future.with(|cell| {
            *cell.borrow_mut() = None;
        });
        self.finish(Err(Error::Closed));
    }

    fn slot(&self) -> usize {
        self.slot
    }
}

impl<F, T> Join<T> for TaskCell<F, T>
where
    F: Future<Output = Result<T, Error>> + Send + 'static,
    T: Send + 'static,
{
    fn poll_join(&self, cx: &mut task::Context<'_>) -> Poll<Result<T, Error>> {
        self.join.with(|join| {
            let mut join = join.borrow_mut();
            match &mut *join {
                JoinState::Pending(waker) => {
                    match waker {
                        Some(waker) => waker.clone_from(cx.waker()),
                        None => *waker = Some(cx.waker().clone()),
                    }
                    Poll::Pending
                }
                JoinState::Ready(_) => {
                    let JoinState::Ready(result) = std::mem::replace(&mut *join, JoinState::Taken)
                    else {
                        unreachable!("join state verified ready above");
                    };
                    Poll::Ready(result)
                }
                // Match the receiver-backed handle: polling after the result
                // was taken resolves closed.
                JoinState::Taken => Poll::Ready(Err(Error::Closed)),
            }
        })
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

    /// Register a task for `future`, returning its cell (which doubles as
    /// the join point for the spawner's handle).
    ///
    /// Returns `None` when the executor is already tearing down.
    fn register<F, T>(arc_self: &Arc<Self>, future: F) -> Option<Arc<TaskCell<F, T>>>
    where
        F: Future<Output = Result<T, Error>> + Send + 'static,
        T: Send + 'static,
    {
        let cell = {
            let mut running = arc_self.running.lock();
            if running.closed {
                return None;
            }
            let slot = running.free.pop().unwrap_or_else(|| {
                running.slots.push(None);
                running.slots.len() - 1
            });
            let cell = Arc::new(TaskCell {
                slot,
                tasks: Arc::downgrade(arc_self),
                future: Affine::new(RefCell::new(Some(future))),
                join: Affine::new(RefCell::new(JoinState::Pending(None))),
            });
            running.slots[slot] = Some(Arc::clone(&cell) as Arc<dyn Erased>);
            cell
        };

        // Queue the first poll.
        arc_self.queue(Arc::clone(&cell) as Arc<dyn Erased>);
        Some(cell)
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
        self.executor().metrics.clone()
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

        // The single-threaded executor cannot absorb blocking work, and the
        // runtime manages no worker threads to offload it to. Support is
        // planned to return with a blocking pool.
        if !matches!(past, Execution::Shared(false)) {
            panic!(
                "blocking and dedicated tasks are temporarily unsupported on the io_uring runtime"
            );
        }

        // Wrap the future with panic catching, abort support, and cleanup.
        // The task cell parks the result for the handle directly, so no
        // completion channel is allocated.
        let executor = self.executor();
        let future = f(self);
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        let panicker = executor.panicker.clone();
        let tree = Arc::clone(&parent);
        let metric_handle = metric.clone();
        let wrapped = async move {
            let result =
                Abortable::new(AssertUnwindSafe(future).catch_unwind(), abort_registration).await;
            let output = match result {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(panic)) => {
                    panicker.notify(panic);
                    Err(Error::Exited)
                }
                Err(Aborted) => Err(Error::Closed),
            };

            // Mark the task as aborted and abort all descendants.
            tree.abort();

            // Finish the metric.
            metric_handle.finish();

            output
        };

        // Register the task; its cell doubles as the handle's join point.
        let handle = match Tasks::register(&executor.tasks, wrapped) {
            Some(cell) => Handle::from_join(cell, abort_handle, metric),
            None => Handle::closed(metric),
        };

        // Register the task on the parent
        if let Some(aborter) = handle.aborter() {
            parent.register(aborter);
        }

        handle
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        let stop_resolved = {
            let executor = self.executor();
            let mut shutdown = executor.shutdown.lock();
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
        self.executor().shutdown.lock().stopped()
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
        let stack_size = self.executor().thread_stack_size;
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
        self.executor().registry.register(
            prefixed_name(&self.name, &name),
            help,
            self.attributes.clone(),
            metric,
        )
    }

    fn encode(&self) -> String {
        self.executor().registry.encode()
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
        utils::thread::spawn(self.executor().thread_stack_size, move || {
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
    use crate::{Runner as _, Spawner as _, Supervisor as _};

    #[test]
    #[should_panic(expected = "temporarily unsupported on the io_uring runtime")]
    fn test_spawn_blocking_panics() {
        Runner::default().start(|context| async move {
            context.child("blocking").shared(true).spawn(|_| async {});
        });
    }

    #[test]
    #[should_panic(expected = "temporarily unsupported on the io_uring runtime")]
    fn test_spawn_dedicated_panics() {
        Runner::default().start(|context| async move {
            context.child("dedicated").dedicated().spawn(|_| async {});
        });
    }
}
