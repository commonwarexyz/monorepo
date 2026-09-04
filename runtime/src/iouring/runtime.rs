//! Native worker execution and runner-wide lifecycle.
//!
//! One worker owns its ring, task arena, admission queue, ordinary operation
//! results, and sleeper deadlines. Its [`Scope`] installs checked thread-local
//! access for short transitions. Polls, callbacks, and destruction run after
//! releasing local state. The calling thread runs the ordinary worker.
//!
//! [`Shared`] contains only runner-wide configuration and existing synchronized
//! services. Dedicated and blocking tasks create one-off workers registered
//! before receiving their user payload. Runner shutdown closes that registry,
//! drains the ordinary worker, then waits for every accepted worker cleanup.
//!
//! ```text
//! Runner::start thread                  one-off worker thread
//! --------------------                 ---------------------
//! Shared -> Registry <- responsibility  Shared
//! Scope -> Local                        Scope -> Local
//!          tasks, timers                          tasks, timers
//!          admissions, operations                 admissions, operations
//!          Driver -> ring                         Driver -> ring
//! ```

use super::{
    admission::Admissions,
    callbacks::{Panic, Panics, RetirementGuard},
    driver::{Completed, Driver},
    mailbox::{Mailbox, Message},
    operation::Operations,
    request::{RequestOutput, RetiredResources},
    sleep::{Sleep, Timers},
    spinner::{Config as SpinnerConfig, Spinner},
    task::{self, Runnable, Running, Target, Task, Tasks},
    timeout::TimeoutWheel,
    waker::SUBMISSION_SEQ_MASK,
};
#[cfg(feature = "external")]
use crate::Pacer;
use crate::{
    BlobLayout, BlobVersion, BufferPool, BufferPoolConfig, Clock, Error, Execution, Handle,
    METRICS_PREFIX, Name, SinkOf, Spawner as _, StreamOf, Supervisor as _, child_label,
    network::{
        iouring::{Config as NetworkConfig, Network},
        metered::Network as MeteredNetwork,
    },
    prefixed_name,
    process::metered::Metrics as ProcessMetrics,
    signal::Signal,
    storage::{
        iouring::{Config as StorageConfig, Storage},
        metered::Storage as MeteredStorage,
    },
    telemetry::metrics::{
        CounterFamily, Gauge, GaugeFamily, Metric, Register, Registered,
        Registry as MetricsRegistry, add_attribute, raw, task::Label, validate_label,
    },
    utils::{self, MetricHandle, Panicked, Panicker, signal::Stopper, supervision::Tree},
};
use commonware_macros::select;
use commonware_parallel::Rayon;
use commonware_utils::{
    NZUsize,
    channel::oneshot,
    sync::{Condvar, Mutex},
    sys_rng,
};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use rand_core::{Rng, TryCryptoRng, TryRng};
use rayon::ThreadPoolBuilder;
use std::{
    cell::RefCell,
    convert::Infallible,
    env,
    future::Future,
    mem,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    num::NonZeroUsize,
    ops::RangeInclusive,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    path::PathBuf,
    pin::Pin,
    rc::Rc,
    sync::{Arc, Weak, mpsc},
    task::{Context as TaskContext, Poll, Waker},
    thread,
    time::{Duration, Instant, SystemTime},
};

/// Configuration of each worker's io_uring instance and operation timing wheel.
///
/// The runtime requires Linux 6.1 or newer and always uses single-issuer mode
/// with deferred task work. The same configuration applies to ordinary and
/// one-off workers. The wheel horizon is derived from network timeout policy.
#[derive(Clone, Debug)]
pub struct RingConfig {
    /// Requested waiter capacity, rounded up to the next power of two.
    ///
    /// Must be nonzero and round to at most 32,768. Defaults to 128. The runtime
    /// chooses 1024 for its production default and 128 when built for tests.
    pub size: u32,
    /// Nonzero operation deadline granularity, defaulting to 5 milliseconds.
    ///
    /// Smaller ticks improve precision but increase wheel storage and service
    /// frequency. Configuration must fit within 1,048,576 wheel slots.
    pub timeout_wheel_tick: Duration,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            size: 128,
            timeout_wheel_tick: Duration::from_millis(5),
        }
    }
}

/// Configuration for the native io_uring runtime.
///
/// One ordinary worker runs on the thread calling [`crate::Runner::start`].
/// Tasks marked dedicated or blocking each receive a fresh thread and ring.
/// Shutdown completes retained writes and syncs without a configured time limit.
#[derive(Clone)]
pub struct Config {
    /// Per-worker ring capacity and operation wheel tick.
    ring_config: RingConfig,
    /// Idle spinning policy, shared by all workers.
    idle_spinner: SpinnerConfig,
    /// Stack size for one-off worker and Rayon threads.
    thread_stack_size: usize,
    /// Whether user task panics report Exited instead of failing the runner.
    catch_panics: bool,
    /// Base directory held while storage resources or requests remain alive.
    storage_directory: PathBuf,
    /// Accepted blob layouts, defaulting to the complete supported range.
    storage_blob_layouts: RangeInclusive<BlobLayout>,
    /// Optional TCP_NODELAY override, defaulting to Some(true).
    tcp_nodelay: Option<bool>,
    /// Request immediate reset on socket close, defaulting to true.
    zero_linger: bool,
    /// Whole-call outbound connection deadline, defaulting to 10 seconds.
    connect_timeout: Duration,
    /// Whole-call send and receive deadline, defaulting to 60 seconds.
    read_write_timeout: Duration,
    /// Network receive buffering capacity, defaulting to 64 KiB.
    read_buffer_size: usize,
    /// Optional network pool override, otherwise configured for one worker.
    network_buffer_pool_cfg: Option<BufferPoolConfig>,
    /// Optional storage pool override, otherwise configured for one worker.
    storage_buffer_pool_cfg: Option<BufferPoolConfig>,
}

impl Config {
    /// Return the default runtime configuration with a generated temporary directory.
    pub fn new() -> Self {
        let ring_config = RingConfig {
            size: if cfg!(test) { 128 } else { 1024 },
            ..RingConfig::default()
        };
        let rng = sys_rng().next_u64();
        Self {
            ring_config,
            idle_spinner: SpinnerConfig::default(),
            thread_stack_size: utils::thread::system_thread_stack_size(),
            catch_panics: false,
            storage_directory: env::temp_dir().join(format!("commonware_iouring_runtime_{rng}")),
            storage_blob_layouts: BlobLayout::ALL,
            tcp_nodelay: Some(true),
            zero_linger: true,
            connect_timeout: Duration::from_secs(10),
            read_write_timeout: Duration::from_secs(60),
            read_buffer_size: 64 * 1024,
            network_buffer_pool_cfg: None,
            storage_buffer_pool_cfg: None,
        }
    }

    /// Set ring capacity and deadline granularity. See [`RingConfig`].
    pub const fn with_ring_config(mut self, config: RingConfig) -> Self {
        self.ring_config = config;
        self
    }

    /// Set idle spinning policy. Use [`SpinnerConfig::disabled`] to disable it.
    pub const fn with_idle_spinner(mut self, config: SpinnerConfig) -> Self {
        self.idle_spinner = config;
        self
    }

    /// Set one-off worker and Rayon thread stack size.
    pub const fn with_thread_stack_size(mut self, size: usize) -> Self {
        self.thread_stack_size = size;
        self
    }

    /// Set whether user task panics are caught. Infrastructure failures remain fatal.
    pub const fn with_catch_panics(mut self, catch: bool) -> Self {
        self.catch_panics = catch;
        self
    }

    /// Set the outbound connection timeout, including admission and retries.
    ///
    /// Must be nonzero and no greater than 30 years. The maximum configured
    /// network timeout must fit the wheel slot limit in [`RingConfig`].
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the send and receive timeout, including admission and partial progress.
    ///
    /// Must be nonzero and no greater than 30 years. The maximum configured
    /// network timeout must fit the wheel slot limit in [`RingConfig`].
    pub const fn with_read_write_timeout(mut self, timeout: Duration) -> Self {
        self.read_write_timeout = timeout;
        self
    }

    /// Set the best-effort TCP_NODELAY override. None leaves the system default.
    pub const fn with_tcp_nodelay(mut self, enabled: Option<bool>) -> Self {
        self.tcp_nodelay = enabled;
        self
    }

    /// Set whether sockets request zero linger when configured.
    pub const fn with_zero_linger(mut self, enabled: bool) -> Self {
        self.zero_linger = enabled;
        self
    }

    /// Set the network receive buffer size in bytes.
    pub const fn with_read_buffer_size(mut self, size: usize) -> Self {
        self.read_buffer_size = size;
        self
    }

    /// Set the storage directory, created and held when the runner starts.
    pub fn with_storage_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.storage_directory = directory.into();
        self
    }

    /// Set the blob layouts accepted by storage.
    ///
    /// New blobs use the latest layout in this range. Existing blobs outside
    /// it fail to open with [`crate::Error::BlobLayoutMismatch`]. Restrict the
    /// range to what a rollback target can read before first opening storage.
    ///
    /// # Panics
    ///
    /// Panics if `layouts` is empty.
    pub fn with_storage_blob_layouts(mut self, layouts: RangeInclusive<BlobLayout>) -> Self {
        assert!(
            !layouts.is_empty(),
            "storage blob layouts must be non-empty"
        );
        self.storage_blob_layouts = layouts;
        self
    }

    /// Override the network buffer pool configuration.
    pub fn with_network_buffer_pool_config(mut self, config: BufferPoolConfig) -> Self {
        self.network_buffer_pool_cfg = Some(config);
        self
    }

    /// Override the storage buffer pool configuration.
    pub fn with_storage_buffer_pool_config(mut self, config: BufferPoolConfig) -> Self {
        self.storage_buffer_pool_cfg = Some(config);
        self
    }

    /// Return per-worker ring configuration.
    pub const fn ring_config(&self) -> &RingConfig {
        &self.ring_config
    }

    /// Return per-worker idle spinning configuration.
    pub const fn idle_spinner(&self) -> &SpinnerConfig {
        &self.idle_spinner
    }

    /// Return the configured one-off worker and Rayon thread stack size.
    pub const fn thread_stack_size(&self) -> usize {
        self.thread_stack_size
    }

    /// Return whether user task panics are caught.
    pub const fn catch_panics(&self) -> bool {
        self.catch_panics
    }

    /// Return the whole-call outbound connection timeout.
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Return the whole-call send and receive timeout.
    pub const fn read_write_timeout(&self) -> Duration {
        self.read_write_timeout
    }

    /// Return the TCP_NODELAY override.
    pub const fn tcp_nodelay(&self) -> Option<bool> {
        self.tcp_nodelay
    }

    /// Return whether sockets request zero linger.
    pub const fn zero_linger(&self) -> bool {
        self.zero_linger
    }

    /// Return the network receive buffer size.
    pub const fn read_buffer_size(&self) -> usize {
        self.read_buffer_size
    }

    /// Return the storage directory retained by the runtime's storage resources.
    pub const fn storage_directory(&self) -> &PathBuf {
        &self.storage_directory
    }

    /// Return the accepted blob layout range.
    pub const fn storage_blob_layouts(&self) -> &RangeInclusive<BlobLayout> {
        &self.storage_blob_layouts
    }

    /// Validate and normalize settings before acquiring any startup resources.
    fn validate(&mut self) {
        assert!(self.ring_config.size != 0, "ring size must be nonzero");
        self.ring_config.size = self
            .ring_config
            .size
            .checked_next_power_of_two()
            .expect("ring size overflow");
        assert!(self.ring_config.size <= 32_768, "ring size exceeds 32768");
        assert!(
            !self.storage_blob_layouts.is_empty(),
            "storage blob layouts must be non-empty"
        );
        assert!(
            !self.connect_timeout.is_zero(),
            "connect timeout must be nonzero"
        );
        assert!(
            !self.read_write_timeout.is_zero(),
            "read/write timeout must be nonzero"
        );
        TimeoutWheel::validate_layout(self.max_timeout(), self.ring_config.timeout_wheel_tick)
            .expect("invalid io_uring operation deadline layout");
    }

    /// Largest network timeout supported by every worker's operation wheel.
    fn max_timeout(&self) -> Duration {
        self.connect_timeout.max(self.read_write_timeout)
    }

    /// Resolve default network pool parallelism for one ordinary worker.
    fn resolved_network_buffer_pool_config(&self) -> BufferPoolConfig {
        self.network_buffer_pool_cfg
            .clone()
            .unwrap_or_else(|| BufferPoolConfig::for_network().with_parallelism(NZUsize!(1)))
    }

    /// Resolve default storage pool parallelism for one ordinary worker.
    fn resolved_storage_buffer_pool_config(&self) -> BufferPoolConfig {
        self.storage_buffer_pool_cfg
            .clone()
            .unwrap_or_else(|| BufferPoolConfig::for_storage().with_parallelism(NZUsize!(1)))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

/// Task counters shared by all workers in one runner.
struct TaskMetrics {
    /// Number of tasks created, including rejected spawns.
    tasks_spawned: CounterFamily<Label>,
    /// Number of tasks that have not completed or been aborted.
    tasks_running: GaugeFamily<Label>,
}

impl TaskMetrics {
    /// Register task families beneath the runtime metrics namespace.
    fn new(registry: &mut impl Register) -> Self {
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

/// Admission and completion barrier for one-off worker runtime cleanup.
#[derive(Default)]
struct Registry {
    state: Mutex<WorkerCount>,
    idle: Condvar,
    #[cfg(test)]
    after_release: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

#[derive(Default)]
struct WorkerCount {
    closed: bool,
    active: usize,
}

impl Registry {
    /// Admission and counting share one lock so shutdown cannot miss a launch.
    fn admit(self: &Arc<Self>) -> Option<ActiveWorker> {
        let mut state = self.state.lock();
        if state.closed {
            return None;
        }
        state.active += 1;
        Some(ActiveWorker(self.clone()))
    }

    fn close(&self) {
        self.state.lock().closed = true;
    }

    /// Called after the owning worker has completed its own retirement.
    fn wait(&self) {
        let mut state = self.state.lock();
        while state.active != 0 {
            self.idle.wait(&mut state);
        }
    }
}

/// Does not own Shared, so releasing this responsibility cannot retain storage.
struct ActiveWorker(Arc<Registry>);

impl Drop for ActiveWorker {
    fn drop(&mut self) {
        let mut state = self.0.state.lock();
        state.active -= 1;
        if state.active == 0 {
            self.0.idle.notify_all();
        }
        drop(state);
        #[cfg(test)]
        {
            let after_release = self.0.after_release.lock().take();
            if let Some(after_release) = after_release {
                after_release();
            }
        }
    }
}

/// Field order disposes of rejected task and runtime owners before tracking ends.
struct Launch {
    task: Pin<Box<dyn Runnable>>,
    shared: Arc<Shared>,
    active: ActiveWorker,
}

/// Runner-wide services shared by ordinary and one-off workers.
pub(super) struct Shared {
    /// Validated configuration, immutable after startup.
    cfg: Config,
    /// User-visible metrics registry.
    registry: MetricsRegistry,
    /// Task counters and running gauges.
    metrics: TaskMetrics,
    /// Aggregate active requests, updated with each worker's own count delta.
    pending_operations: Gauge,
    /// Existing stop signal and acknowledgement state.
    shutdown: Mutex<Stopper>,
    /// User task panic policy and root notification.
    panicker: Panicker,
    /// Synchronized creation and closure of one-off workers.
    workers: Arc<Registry>,
    /// Deterministic coverage for thread-creation failure before payload transfer.
    #[cfg(test)]
    fail_launch: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_transfer: std::sync::atomic::AtomicBool,
    /// Deterministic coverage for native initialization failure after launch.
    #[cfg(test)]
    fail_startup: std::sync::atomic::AtomicBool,
    /// Metered storage with its metadata lock and directory hold.
    storage: MeteredStorage<Storage>,
    /// Metered native socket adapter.
    network: MeteredNetwork<Network>,
    /// Shared allocation pool for network reads.
    network_buffer_pool: BufferPool,
    /// Shared allocation pool for storage reads.
    storage_buffer_pool: BufferPool,
}

impl Shared {
    /// Transfer cleanup responsibility only after native thread creation succeeds.
    fn launch(
        self: &Arc<Self>,
        task: Pin<Box<dyn Runnable>>,
    ) -> Result<(), Pin<Box<dyn Runnable>>> {
        let Some(active) = self.workers.admit() else {
            return Err(task);
        };
        let payload = Launch {
            task,
            shared: self.clone(),
            active,
        };
        let (sender, receiver) = mpsc::channel::<Launch>();
        #[cfg(test)]
        let receiver = if self
            .fail_transfer
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            // Disconnect the actual payload channel before publication. The
            // native entry receives a separate, already-disconnected channel.
            drop(receiver);
            let (_, disconnected) = mpsc::channel::<Launch>();
            disconnected
        } else {
            receiver
        };
        let injected = {
            #[cfg(test)]
            {
                self.fail_launch
                    .swap(false, std::sync::atomic::Ordering::Relaxed)
            }
            #[cfg(not(test))]
            {
                false
            }
        };
        // The entry closure owns only the receiver. On creation failure the
        // caller still owns the payload and its completion responsibility.
        let launched = if injected {
            Err(std::io::Error::other("injected worker launch failure"))
        } else {
            thread::Builder::new()
                .stack_size(self.cfg.thread_stack_size)
                .spawn(move || {
                    if let Ok(Launch {
                        task,
                        shared,
                        active,
                    }) = receiver.recv()
                    {
                        run_one_off(shared, task);
                        // run_one_off consumed every runtime-owned Shared reference
                        // and published failure before this release. Native TLS
                        // destruction is outside the runtime completion boundary.
                        drop(active);
                    }
                })
        };
        match launched {
            Ok(thread) => drop(thread),
            Err(error) => {
                drop(payload);
                panic!("failed to spawn io_uring worker: {error}");
            }
        }
        if let Err(error) = sender.send(payload) {
            self.panicker
                .notify_fatal(Box::new("io_uring worker payload transfer failed"));
            drop(error.0);
        }
        Ok(())
    }
}

/// Runtime capabilities and supervision context for the current task.
///
/// Ordinary children target this context's origin worker. Dedicated and blocking
/// tasks rebind their contexts before the user closure runs, so their ordinary
/// descendants use that worker. Resources may move between workers between I/O
/// operations. A polled operation or registered sleep stays bound to its worker.
pub struct Context {
    /// User-facing task and metric namespace.
    name: String,
    /// Validated metric attributes inherited by children.
    attributes: Vec<(String, String)>,
    /// Shared services and runner-wide lifecycle state.
    shared: Arc<Shared>,
    /// Origin for ordinary spawns, without extending worker lifetime.
    origin: Weak<Mailbox>,
    /// This context's node in the mandatory supervision tree.
    tree: Arc<Tree>,
    /// Placement requested for the next consumed spawn.
    execution: Execution,
}

impl Context {
    /// Access shared task metric families for the common spawn helper.
    fn metrics(&self) -> &TaskMetrics {
        &self.shared.metrics
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
        let (_, metric) = spawn_metrics!(self);
        let parent = self.tree.clone();
        let execution = self.execution;
        self.execution = Execution::default();
        let (child, aborted) = Tree::child(&parent);
        if aborted {
            return Handle::closed(metric);
        }
        self.tree = child;
        let shared = self.shared.clone();
        let origin = self.origin.clone();
        let future = async move {
            // Construction belongs to the selected worker and is covered by
            // the same panic boundary as the concrete user future's polls.
            if matches!(execution, Execution::Dedicated | Execution::Shared(true)) {
                let local = current().expect("dedicated task requires an io_uring worker");
                self.origin = Arc::downgrade(&local.borrow().mailbox);
            }
            f(self).await
        };
        let (future, handle) =
            Handle::init_local(future, metric, shared.panicker.clone(), parent.clone());
        if let Some(aborter) = handle.aborter() {
            parent.register(aborter);
        }
        let cell = Task::boxed(future);
        let result = if matches!(execution, Execution::Dedicated | Execution::Shared(true)) {
            shared.launch(cell)
        } else {
            task::register(&origin, cell)
        };
        if let Err(cell) = result {
            // Rejection after closure follows the caller's panic boundary.
            drop(cell);
        }
        handle
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        let resolved = self.shared.shutdown.lock().stop(value);
        let timeout = timeout.map_or_else(
            || futures::future::Either::Right(futures::future::pending()),
            |duration| futures::future::Either::Left(self.sleep(duration)),
        );
        select! {
            result = resolved => result.map_err(|_| Error::Closed),
            _ = timeout => Err(Error::Timeout),
        }
    }

    fn stopped(&self) -> Signal {
        self.shared.shutdown.lock().stopped()
    }
}

impl crate::Strategizer for Context {
    fn strategy(&self, parallelism: NonZeroUsize) -> Rayon {
        let pool = ThreadPoolBuilder::new()
            .num_threads(parallelism.get())
            .stack_size(self.shared.cfg.thread_stack_size)
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
            shared: self.shared.clone(),
            origin: self.origin.clone(),
            tree,
            execution: Execution::default(),
        }
    }

    fn with_attribute(mut self, key: &'static str, value: impl std::fmt::Display) -> Self {
        validate_label(key);
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
        self.shared.registry.register(
            prefixed_name(&self.name, &name.into()),
            help.into(),
            self.attributes.clone(),
            Arc::new(metric),
        )
    }

    fn encode(&self) -> String {
        self.shared.registry.encode()
    }
}

impl Clock for Context {
    fn current(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        Sleep::new(duration)
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        Sleep::until(deadline)
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
    type Listener = <MeteredNetwork<Network> as crate::Network>::Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        self.shared.network.bind(socket).await
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(SinkOf<Self>, StreamOf<Self>), Error> {
        self.shared.network.dial(socket).await
    }
}

impl crate::Resolver for Context {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, Error> {
        let host = host.to_owned();
        self.child("resolver")
            .shared(true)
            .spawn(move |_| async move {
                (host.as_str(), 0)
                    .to_socket_addrs()
                    .map(|addresses| addresses.map(|address| address.ip()).collect())
                    .map_err(|error| Error::ResolveFailed(error.to_string()))
            })
            .await
            .map_err(|error| Error::ResolveFailed(error.to_string()))?
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
    type Blob = <MeteredStorage<Storage> as crate::Storage>::Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<BlobVersion>,
    ) -> Result<(Self::Blob, u64, BlobVersion), Error> {
        self.shared
            .storage
            .open_versioned(partition, name, versions)
            .await
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.shared.storage.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.shared.storage.scan(partition).await
    }
}

impl crate::BufferPooler for Context {
    fn network_buffer_pool(&self) -> &BufferPool {
        &self.shared.network_buffer_pool
    }

    fn storage_buffer_pool(&self) -> &BufferPool {
        &self.shared.storage_buffer_pool
    }
}

/// Detached sync result and the sender that publishes it outside Local.
type SyncResult = (oneshot::Sender<Result<(), Error>>, Result<(), Error>);

/// Mutable execution state accessed only by its owning worker thread.
pub(super) struct Local {
    /// Ring owner, retained through synchronous waits and kernel retirement.
    pub(super) driver: Option<Driver>,
    /// Concrete task cells and FIFO ready tokens.
    pub(super) tasks: Tasks,
    /// FIFO capacity registrations, independent of active ring waiters.
    pub(super) admissions: Admissions,
    /// Ordinary observers and retained results, independent of waiter capacity.
    pub(super) operations: Operations,
    /// Sleeper registrations and deadlines.
    pub(super) timers: Timers,
    /// Reject new registration while allowing idempotent cancellation.
    pub(super) closing: bool,
    /// Shared monotonic sample for the current service turn.
    pub(super) now: Instant,
    /// Root notification, taken before a root poll and never cleared afterward.
    pub(super) root_ready: bool,
    /// Whether root wakes may still schedule a poll.
    pub(super) root_live: bool,
    /// Strong mailbox ownership retained through kernel retirement.
    pub(super) mailbox: Arc<Mailbox>,
    /// Ownership detached from local transitions before callbacks run.
    pub(super) deferred: Deferred,
    /// Driver outputs awaiting operation-slab reconciliation.
    pub(super) completed: Vec<Completed>,
    /// Runner configuration, metrics, and shared adapters.
    shared: Arc<Shared>,
    /// This worker's contribution currently included in the aggregate gauge.
    reported_pending: usize,
}

impl Local {
    /// Construct a ring on the thread that will own all its submissions.
    fn new(shared: Arc<Shared>) -> std::io::Result<Self> {
        #[cfg(test)]
        if shared
            .fail_startup
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            return Err(std::io::Error::other(
                "injected native worker initialization failure",
            ));
        }
        let mailbox = Arc::new(Mailbox::new()?);
        let now = Instant::now();
        let driver = Driver::new(
            &shared.cfg.ring_config,
            shared.cfg.max_timeout(),
            mailbox.waker.clone(),
            now,
        )?;
        Ok(Self {
            driver: Some(driver),
            tasks: Tasks::default(),
            admissions: Admissions::new(),
            operations: Operations::default(),
            timers: Timers::new(),
            closing: false,
            now,
            root_ready: true,
            root_live: true,
            mailbox,
            deferred: Deferred::default(),
            completed: Vec::new(),
            shared,
            reported_pending: 0,
        })
    }

    /// Update aggregate pending-operation metrics using only this worker's delta.
    fn update_pending(&mut self) {
        let pending = self.driver.as_ref().unwrap().len();
        if pending > self.reported_pending {
            self.shared
                .pending_operations
                .inc_by((pending - self.reported_pending) as _);
        } else if pending < self.reported_pending {
            self.shared
                .pending_operations
                .dec_by((self.reported_pending - pending) as _);
        }
        self.reported_pending = pending;
    }

    /// Whether task polling or callbacks prevent the worker from parking.
    fn is_ready(&self) -> bool {
        self.tasks.is_ready()
            || (self.root_live && self.root_ready)
            || !self.completed.is_empty()
            || !self.deferred.is_empty()
    }

    /// Earliest absolute deadline across operations, admission, and sleepers.
    fn next_deadline(&mut self) -> Option<Instant> {
        [
            self.driver.as_mut().unwrap().next_deadline(),
            self.admissions.next_deadline(),
            self.timers.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }
}

thread_local! {
    /// Checked access to the one worker allowed on the current thread.
    static CURRENT: RefCell<Option<Rc<RefCell<Local>>>> = const { RefCell::new(None) };
}

/// Thread-local worker access, cleared after mandatory cleanup on every exit.
struct Scope;

impl Scope {
    /// Reject nesting before any directory hold, pool, thread, or ring is created.
    fn assert_vacant() {
        CURRENT.with(|current| {
            assert!(
                current.borrow().is_none(),
                "nested io_uring runtime entry is not supported"
            );
        });
    }

    /// Install one worker, retaining the entry check as a defensive invariant.
    fn install(local: Rc<RefCell<Local>>) -> Self {
        CURRENT.with(|current| {
            let mut current = current.borrow_mut();
            assert!(current.is_none(), "nested io_uring worker scope");
            *current = Some(local);
        });
        Self
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            current.borrow_mut().take();
        });
    }
}

/// Return the current worker for a short owner-local transition.
pub(super) fn current() -> Option<Rc<RefCell<Local>>> {
    CURRENT.with(|current| current.borrow().clone())
}

/// Reusable typed callback storage detached from Local before invocation.
#[derive(Default)]
pub(super) struct Deferred {
    /// Notifications for tasks observing completed local transitions.
    pub(super) wakes: Vec<Waker>,
    /// Wakers whose registrations were replaced or cancelled.
    pub(super) drops: Vec<Waker>,
    /// Results whose observation has ended.
    pub(super) outputs: Vec<RequestOutput>,
    /// Buffers and descriptors no longer used by the kernel.
    pub(super) resources: Vec<RetiredResources>,
    /// Detached durable-sync publications.
    pub(super) sync_results: Vec<SyncResult>,
}

impl Deferred {
    /// Transfer pending ownership without executing callbacks under Local.
    const fn take(&mut self, local: &mut Local) {
        mem::swap(self, &mut local.deferred);
    }

    const fn is_empty(&self) -> bool {
        self.wakes.is_empty()
            && self.drops.is_empty()
            && self.outputs.is_empty()
            && self.resources.is_empty()
            && self.sync_results.is_empty()
    }

    /// Run each callback independently, preserving later mandatory cleanup.
    fn run(&mut self, panics: &mut Panics) {
        for waker in self.wakes.drain(..) {
            panics.run(|| waker.wake());
        }
        for waker in self.drops.drain(..) {
            panics.run(|| drop(waker));
        }
        for output in self.outputs.drain(..) {
            panics.run(|| drop(output));
        }
        for resources in self.resources.drain(..) {
            panics.run(|| drop(resources));
        }
        for (sender, output) in self.sync_results.drain(..) {
            panics.run(|| {
                let _ = sender.send(output);
            });
        }
    }
}

/// Worker cleanup owner, installed before exposing the thread-local scope.
struct Worker {
    /// Local state retained until its driver has drained and been destroyed.
    local: Rc<RefCell<Local>>,
    /// Cleared only after local cleanup, including during an unexpected unwind.
    scope: Option<Scope>,
    /// Reusable deferred callback batches.
    deferred: Deferred,
    /// First poll, infrastructure, or callback failure.
    panics: Panics,
    /// Retained mailbox batch, reversed once so bounded pops remain FIFO.
    inbox: Vec<Message>,
    /// Number of whole mailbox batches transferred to owner-local storage.
    processed_seq: u32,
    /// False until kernel retirement and callback cleanup have finished.
    finished: bool,
}

impl Worker {
    /// Install TLS only after constructing a cleanup owner.
    fn new(local: Local) -> Self {
        let local = Rc::new(RefCell::new(local));
        let mut worker = Self {
            local: local.clone(),
            scope: None,
            deferred: Deferred::default(),
            panics: Panics::default(),
            inbox: Vec::new(),
            processed_seq: 0,
            finished: false,
        };
        worker.scope = Some(Scope::install(local));
        worker
    }

    /// Detach one callback batch and run it outside the local borrow.
    fn callbacks(&mut self) {
        self.deferred.take(&mut self.local.borrow_mut());
        self.deferred.run(&mut self.panics);
    }

    /// Close all publication paths before invoking any user destructor.
    fn begin_close(&mut self) {
        let mailbox = {
            let mut local = self.local.borrow_mut();
            local.closing = true;
            local.root_live = false;
            local.mailbox.clone()
        };
        let messages = mailbox.close();
        if !messages.is_empty() {
            self.processed_seq = self.processed_seq.wrapping_add(1) & SUBMISSION_SEQ_MASK;
        }
        for message in messages {
            task::contain(|| drop(message));
        }
        for message in self.inbox.drain(..) {
            task::contain(|| drop(message));
        }
    }

    /// Cancel observers and finish all kernel-visible work before releasing TLS.
    fn cleanup(&mut self) {
        if self.finished {
            return;
        }
        // Protect every retirement transition, including observer removal
        // before the first drain turn, against unexpected infrastructure unwind.
        let mut retirement = RetirementGuard::new();
        self.begin_close();
        let mut tasks = Vec::new();
        self.local.borrow_mut().tasks.clear(&mut tasks);
        for Running { cell, waker, .. } in tasks {
            task::contain(|| drop(cell));
            self.panics.run(|| drop(waker));
        }
        {
            let mut local = self.local.borrow_mut();
            local.close_operations();
            let Local {
                admissions,
                timers,
                deferred,
                driver,
                ..
            } = &mut *local;
            admissions.clear(&mut deferred.drops);
            timers.clear(&mut deferred.drops);
            driver.as_mut().unwrap().close();
            local.apply_completions();
            local.update_pending();
        }
        self.callbacks();

        // Any unexpected infrastructure unwind during retirement must abort
        // before a request can release memory still referenced by the kernel.
        // Arbitrary callbacks are isolated outside each short driver borrow.
        loop {
            {
                let mut local = self.local.borrow_mut();
                local.now = Instant::now();
                let Local {
                    driver,
                    completed,
                    now,
                    ..
                } = &mut *local;
                driver
                    .as_mut()
                    .unwrap()
                    .service(*now, false, completed)
                    .expect("io_uring shutdown service failed");
                local.apply_completions();
                local.update_pending();
            }
            self.callbacks();
            let mut local = self.local.borrow_mut();
            // Callbacks can enqueue another batch. Keep TLS installed until
            // both ownership lanes and kernel retirement reach quiescence.
            if !local.deferred.is_empty() || !self.deferred.is_empty() {
                continue;
            }
            if local.driver.as_ref().unwrap().is_empty() {
                break;
            }
            let deadline = local.next_deadline();
            // Parking only enters the kernel and invokes no user callbacks.
            // Keeping the driver in Local preserves the cleanup owner on unwind.
            let parked = local
                .driver
                .as_mut()
                .unwrap()
                .park(self.processed_seq, deadline);
            drop(local);
            parked.expect("io_uring shutdown wait failed");
        }
        retirement.disarm();
        let driver = self.local.borrow_mut().driver.take();
        self.panics.run(|| drop(driver));
        self.finished = true;
        self.scope.take();
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.cleanup();
        // During an existing unwind the outer one-off boundary reports the
        // primary failure. Panics drops any secondary cleanup payload safely.
    }
}

impl Worker {
    /// Apply at most one bounded slice of a retained foreign batch.
    fn messages(&mut self, mailbox: &Arc<Mailbox>, woke: bool) {
        if self.inbox.is_empty()
            && (woke || mailbox.waker.pending(self.processed_seq))
            && mailbox.take(&mut self.inbox)
        {
            // Count transfer once, not each message application. Reversing
            // allows bounded FIFO processing without shifting the remainder.
            self.processed_seq = self.processed_seq.wrapping_add(1) & SUBMISSION_SEQ_MASK;
            self.inbox.reverse();
        }
        for _ in 0..64 {
            let Some(message) = self.inbox.pop() else {
                break;
            };
            match message {
                Message::Spawn(cell) => {
                    if let Err(cell) = task::register(&Arc::downgrade(mailbox), cell) {
                        task::contain(|| drop(cell));
                    }
                }
                Message::Wake(target) => {
                    let mut local = self.local.borrow_mut();
                    match target {
                        Target::Root if local.root_live => local.root_ready = true,
                        Target::Task(id) => local.tasks.wake(id),
                        Target::Root => {}
                    }
                }
                Message::CancelAdmission(id) => self.local.borrow_mut().cancel_admission(id),
                Message::OrphanOperation(id) => self.local.borrow_mut().orphan_operation(id),
                Message::CancelTimer(id) => {
                    let mut local = self.local.borrow_mut();
                    if let Some(waker) = local.timers.cancel(id) {
                        local.deferred.drops.push(waker);
                    }
                }
            }
        }
    }

    /// Service the ring and all local deadline sources using one time sample.
    fn service(&mut self, defer_kernel_service: bool) -> bool {
        let mut local = self.local.borrow_mut();
        local.now = Instant::now();
        let Local {
            now,
            driver,
            completed,
            ..
        } = &mut *local;
        let woke = driver
            .as_mut()
            .unwrap()
            .service(*now, defer_kernel_service, completed)
            .expect("io_uring driver service failed");
        local.apply_completions();
        let Local {
            timers,
            now,
            deferred,
            ..
        } = &mut *local;
        timers.expire(*now, &mut deferred.wakes);
        local.update_pending();
        woke
    }

    /// Drive tasks and one separately pinned root through bounded service turns.
    fn drive<Fut: Future>(
        &mut self,
        mut root: Pin<&mut Fut>,
        root_waker: &Waker,
        mut interrupts: Option<&mut Panicked>,
    ) -> Result<Fut::Output, Panic> {
        let mailbox = self.local.borrow().mailbox.clone();
        let spinner_cfg = self.local.borrow().shared.cfg.idle_spinner.clone();
        let mut spinner = Spinner::new(&spinner_cfg, || mailbox.waker.pending(self.processed_seq));
        let max_spin =
            Duration::from_micros(spinner_cfg.max_budget_us.try_into().unwrap_or(u64::MAX));
        loop {
            if self.panics.is_pending() {
                return Err(self.panics.take().unwrap());
            }
            for _ in 0..64 {
                if !self.local.borrow().tasks.is_ready() {
                    break;
                }
                let Some(mut running) = self.local.borrow_mut().tasks.take() else {
                    // A stale ready token consumes budget too, bounding the
                    // distance to the next driver service point under churn.
                    continue;
                };
                // The inner wrapper handles user polling policy. This boundary
                // also catches destruction performed by the abort wrapper.
                let poll = task::contain(|| {
                    running
                        .cell
                        .as_mut()
                        .poll(&mut TaskContext::from_waker(&running.waker))
                });
                if matches!(poll, Some(Poll::Pending)) {
                    self.local.borrow_mut().tasks.pending(running);
                } else {
                    self.local.borrow_mut().tasks.complete(running.id);
                    let Running { cell, waker, .. } = running;
                    task::contain(|| drop(cell));
                    self.panics.run(|| drop(waker));
                }
                if self.panics.is_pending() {
                    return Err(self.panics.take().unwrap());
                }
            }

            let poll_root = {
                let mut local = self.local.borrow_mut();
                local.root_live && mem::take(&mut local.root_ready)
            };
            if poll_root {
                let mut cx = TaskContext::from_waker(root_waker);
                if let Some(interrupts) = interrupts.as_mut()
                    && let Poll::Ready(Some(panic)) = interrupts.poll_panic(&mut cx)
                {
                    return Err(panic);
                }
                // A wake during this poll sets root_ready again. Pending must
                // not clear it, including a wake caused by the root itself.
                if let Poll::Ready(output) = root.as_mut().poll(&mut cx) {
                    self.local.borrow_mut().root_live = false;
                    return Ok(output);
                }
            }

            let defer = !self.local.borrow().is_ready()
                && self.inbox.is_empty()
                && !mailbox.waker.pending(self.processed_seq);
            let woke = self.service(defer);
            self.messages(&mailbox, woke);
            self.callbacks();
            if self.panics.is_pending() {
                return Err(self.panics.take().unwrap());
            }

            let (ready, needs_kernel, pending_submissions, deadline) = {
                let mut local = self.local.borrow_mut();
                (
                    local.is_ready(),
                    local.driver.as_ref().unwrap().needs_kernel_service(),
                    local.driver.as_ref().unwrap().has_pending_submissions(),
                    local.next_deadline(),
                )
            };
            if ready
                || pending_submissions
                || !self.inbox.is_empty()
                || mailbox.waker.pending(self.processed_seq)
            {
                if defer && needs_kernel {
                    // Callbacks and incoming work can invalidate the idle
                    // decision. Satisfy deferred GETEVENTS before polling again.
                    self.service(false);
                    self.callbacks();
                }
                continue;
            }
            // Busy turns use only service's time sample. Take a fresh sample
            // at this actual idle boundary after any elapsed callback time.
            let now = Instant::now();
            if deadline.is_some_and(|deadline| deadline <= now) {
                if defer && needs_kernel {
                    self.service(false);
                    self.callbacks();
                }
                continue;
            }

            if needs_kernel {
                let result = self
                    .local
                    .borrow_mut()
                    .driver
                    .as_mut()
                    .unwrap()
                    .park(self.processed_seq, deadline);
                if !result.expect("io_uring kernel wait failed") {
                    self.service(false);
                    self.callbacks();
                }
            } else {
                // A future timer by itself uses a timed futex wait. Spinning
                // is skipped when it could consume the remaining deadline.
                let near_deadline = deadline
                    .is_some_and(|deadline| deadline.saturating_duration_since(now) <= max_spin);
                if !near_deadline && spinner.spin(|| mailbox.waker.pending(self.processed_seq)) {
                    continue;
                }
                if let Some(duration) = mailbox.waker.park_idle_until(self.processed_seq, deadline)
                {
                    spinner.on_wake(duration);
                }
            }
        }
    }
}

/// Run one worker with a stack-pinned root and complete every ownership boundary.
fn run_worker<F, Fut>(
    shared: Arc<Shared>,
    build: F,
    service: Option<Pin<Box<dyn Runnable>>>,
    root_tree: Option<Arc<Tree>>,
    mut interrupts: Option<Panicked>,
) -> Result<Fut::Output, Panic>
where
    F: FnOnce(&Arc<Mailbox>) -> Fut,
    Fut: Future,
{
    let owning_runner = root_tree.is_some();
    let startup = catch_unwind(AssertUnwindSafe(|| Local::new(shared.clone())));
    let local = match startup {
        Ok(Ok(local)) => local,
        error => {
            let mut panics = Panics::default();
            panics.retain(match error {
                Err(panic) => panic,
                Ok(Err(error)) => Box::new(format!(
                    "failed to create native io_uring worker (Linux 6.1 with SINGLE_ISSUER and DEFER_TASKRUN is required): {error}"
                )),
                Ok(Ok(_)) => unreachable!(),
            });
            // Startup failures do not unwind through a user closure or its
            // captured values. Each rejected payload is destroyed in isolation.
            panics.run(|| drop(build));
            panics.run(|| drop(service));
            return Err(panics.take().unwrap());
        }
    };
    let mut worker = Worker::new(local);
    let mailbox = worker.local.borrow().mailbox.clone();
    if let Some(service) = service
        && let Err(service) = task::register(&Arc::downgrade(&mailbox), service)
    {
        worker.panics.run(|| drop(service));
    }
    let root_waker = task::Wake::waker(Arc::downgrade(&mailbox), Target::Root);
    let constructed = catch_unwind(AssertUnwindSafe(|| build(&mailbox)));
    let mut root = match constructed {
        Ok(future) => Some(mem::ManuallyDrop::new(future)),
        Err(panic) => {
            worker.panics.retain(panic);
            None
        }
    };
    let mut output = None;
    if let Some(root) = root.as_mut() {
        // SAFETY: `root` refers to storage owned by the stack-local Option above.
        // That Option is not moved or replaced after this projection. Only this
        // worker polls the future, and it is destroyed in place below before
        // its stack storage or Scope is released. ManuallyDrop prevents an
        // infrastructure unwind from implicitly destroying the pinned future.
        let pinned = unsafe { Pin::new_unchecked(&mut **root) };
        match catch_unwind(AssertUnwindSafe(|| {
            worker.drive(pinned, &root_waker, interrupts.as_mut())
        })) {
            Ok(Ok(value)) => output = Some(value),
            Ok(Err(panic)) | Err(panic) => worker.panics.retain(panic),
        }
    }
    // Stop accepting one-off launches before destroying the root's descendants.
    if owning_runner {
        shared.workers.close();
    }
    worker.begin_close();
    if let Some(tree) = root_tree {
        worker.panics.run(|| tree.abort());
    }
    if let Some(root) = root.as_mut() {
        worker.panics.run(|| {
            // SAFETY: The future remains in the same stack storage used by the
            // pinned projection above. Polling has ended and no reference to it
            // survives. This is its only destruction, since the containing
            // ManuallyDrop has no automatic future destructor.
            unsafe { mem::ManuallyDrop::drop(root) };
        });
    }
    worker.panics.run(|| drop(root_waker));
    worker.cleanup();
    if owning_runner {
        shared.workers.wait();
    }
    // Every accepted worker has published failure before releasing its count.
    // Sender objects can still survive in escaped contexts, so close explicitly.
    if let Some(interrupts) = interrupts.as_mut()
        && let Some(panic) = interrupts.close()
    {
        worker.panics.retain(panic);
    }
    worker.panics.run(|| drop(interrupts));
    if let Some(panic) = worker.panics.take() {
        // A failure may arrive after a successful root poll. Its output can own
        // arbitrary destructors, so dispose of it without hiding the first panic.
        worker.panics.run(|| drop(output));
        return Err(panic);
    }
    Ok(output.expect("worker root ended without an output or failure"))
}

/// Adapt an already concrete one-off task cell to the worker's root interface.
struct TaskRoot {
    /// One pinned allocation with the monomorphized execution wrapper inside.
    cell: Option<Pin<Box<dyn Runnable>>>,
}

impl Future for TaskRoot {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        task::contain(|| self.cell.as_mut().unwrap().as_mut().poll(cx)).unwrap_or(Poll::Ready(()))
    }
}

impl Drop for TaskRoot {
    fn drop(&mut self) {
        task::contain(|| drop(self.cell.take()));
    }
}

/// Report an infrastructure failure only after that worker's mandatory cleanup.
fn run_one_off(shared: Arc<Shared>, cell: Pin<Box<dyn Runnable>>) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        run_worker(
            shared.clone(),
            |_| TaskRoot { cell: Some(cell) },
            None,
            None,
            None,
        )
    }));
    if let Err(panic) = result.unwrap_or_else(Err) {
        shared.panicker.notify_fatal(panic);
    }
}

/// Native io_uring runner executing ordinary tasks on its calling thread.
///
/// The root future need not be Send. Spawned futures are Send before placement,
/// then exclusively polled and destroyed by their selected worker. The runner
/// waits for one-off runtime cleanup and retained writes and syncs before
/// returning or resuming a panic. Native thread-local destruction may follow.
pub struct Runner {
    /// Settings validated before any runtime resources are created.
    cfg: Config,
}

impl Runner {
    /// Construct a runner without acquiring storage or creating a ring.
    pub const fn new(cfg: Config) -> Self {
        Self { cfg }
    }
}

impl Default for Runner {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl crate::Runner for Runner {
    type Context = Context;

    fn start<F, Fut>(mut self, f: F) -> Fut::Output
    where
        F: FnOnce(Context) -> Fut,
        Fut: Future,
    {
        Scope::assert_vacant();
        self.cfg.validate();
        let mut registry = MetricsRegistry::new();
        let mut runtime_registry = registry.sub_registry(METRICS_PREFIX);
        let metrics = TaskMetrics::new(&mut runtime_registry);
        let pending_operations = runtime_registry.register(
            "pending_operations",
            "Number of active logical requests across io_uring workers",
            raw::Gauge::default(),
        );
        let process = ProcessMetrics::init(&mut runtime_registry);
        let network_buffer_pool = BufferPool::new(
            self.cfg.resolved_network_buffer_pool_config(),
            &mut runtime_registry.sub_registry("network_buffer_pool"),
        );
        let storage_buffer_pool = BufferPool::new(
            self.cfg.resolved_storage_buffer_pool_config(),
            &mut runtime_registry.sub_registry("storage_buffer_pool"),
        );
        let storage = Storage::new(
            StorageConfig {
                storage_directory: self.cfg.storage_directory.clone(),
                blob_layouts: self.cfg.storage_blob_layouts.clone(),
            },
            storage_buffer_pool.clone(),
        );
        // Storage construction acquires the directory hold first. This sync
        // therefore includes any straggling writes from a preceding runner.
        crate::storage::sync(&self.cfg.storage_directory).unwrap_or_else(|error| {
            panic!(
                "failed to sync storage filesystem at startup ({}): {error}",
                self.cfg.storage_directory.display()
            );
        });
        let storage = MeteredStorage::new(storage, &mut runtime_registry);
        let network = MeteredNetwork::new(
            Network::new(
                NetworkConfig {
                    tcp_nodelay: self.cfg.tcp_nodelay,
                    zero_linger: self.cfg.zero_linger,
                    connect_timeout: self.cfg.connect_timeout,
                    read_write_timeout: self.cfg.read_write_timeout,
                    read_buffer_size: self.cfg.read_buffer_size,
                },
                network_buffer_pool.clone(),
            ),
            &mut runtime_registry,
        );
        let (panicker, tasks) = Panicker::new(self.cfg.catch_panics);
        let shared = Arc::new(Shared {
            cfg: self.cfg,
            registry,
            metrics,
            pending_operations,
            shutdown: Mutex::new(Stopper::default()),
            panicker,
            workers: Arc::new(Registry::default()),
            #[cfg(test)]
            fail_launch: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_startup: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_transfer: std::sync::atomic::AtomicBool::new(false),
            storage,
            network,
            network_buffer_pool,
            storage_buffer_pool,
        });
        let label = Label::root();
        shared.metrics.tasks_spawned.get_or_create(&label).inc();
        let metric = MetricHandle::new(shared.metrics.tasks_running.get_or_create(&label).clone());
        let tree = Tree::root();
        let context_shared = shared.clone();
        let context_tree = tree.clone();
        let output = run_worker(
            shared,
            move |mailbox| {
                f(Context {
                    name: label.name(),
                    attributes: Vec::new(),
                    shared: context_shared,
                    origin: Arc::downgrade(mailbox),
                    tree: context_tree,
                    execution: Execution::default(),
                })
            },
            Some(Task::boxed(process.collect(Sleep::new))),
            Some(tree),
            Some(tasks),
        );
        metric.finish();
        match output {
            Ok(output) => output,
            Err(panic) => resume_unwind(panic),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Metrics as _, Resolver as _, Runner as _, utils::extract_panic_message};
    use futures::{
        executor::block_on,
        future::{pending, poll_fn},
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct DropFlag(Arc<AtomicUsize>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn config() -> Config {
        Config::new().with_idle_spinner(SpinnerConfig::disabled())
    }

    #[test]
    fn root_borrows_non_send_state_across_pending_poll() {
        let state = Rc::new(std::cell::Cell::new(0));
        let text = String::from("borrowed root output");
        let origin = thread::current().id();
        let output = Runner::new(config()).start(|context| {
            let state = &state;
            let text = &text;
            async move {
                // Holding an Rc reference across suspension exercises both the
                // borrowed root lifetime and its lack of a Send requirement.
                context.sleep(Duration::from_millis(1)).await;
                assert_eq!(thread::current().id(), origin);
                state.set(state.get() + 1);
                text.as_str()
            }
        });
        assert_eq!(output, "borrowed root output");
        assert_eq!(state.get(), 1);
    }

    #[test]
    fn resolver_handles_numeric_hosts_and_invalid_input() {
        let escaped = Runner::new(config()).start(|context| async move {
            // Numeric hosts and embedded NUL avoid external DNS dependencies
            // while covering address families and the resolver error mapping.
            for host in ["127.0.0.1", "::1"] {
                assert_eq!(
                    context.resolve(host).await.unwrap(),
                    vec![host.parse::<IpAddr>().unwrap()]
                );
            }
            assert!(matches!(
                context.resolve("\0").await,
                Err(Error::ResolveFailed(_))
            ));
            context
        });
        assert!(matches!(
            block_on(escaped.resolve("127.0.0.1")),
            Err(Error::ResolveFailed(_))
        ));
    }

    #[test]
    fn nested_same_directory_rejected_before_closure_and_outer_remains_usable() {
        let config = config();
        let directory = config.storage_directory().clone();
        Runner::new(config).start(|context| async move {
            let called = Arc::new(AtomicBool::new(false));
            let nested_called = called.clone();
            let rejected = catch_unwind(AssertUnwindSafe(|| {
                Runner::new(Config::new().with_storage_directory(directory)).start(move |_| {
                    nested_called.store(true, Ordering::SeqCst);
                    async {}
                });
            }));
            assert!(rejected.is_err());
            assert!(!called.load(Ordering::SeqCst));
            assert_eq!(
                context
                    .child("after_rejection")
                    .spawn(|_| async { 7 })
                    .await
                    .unwrap(),
                7
            );
            context.sleep(Duration::from_millis(1)).await;
        });
        assert!(current().is_none());
    }

    #[test]
    fn root_self_wake_survives_pending_poll() {
        Runner::new(config()).start(|_| async move {
            let mut polls = 0;
            poll_fn(|cx| {
                polls += 1;
                if polls == 1000 {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
            assert_eq!(polls, 1000);
        });
    }

    #[test]
    fn execution_modes_rebind_ordinary_descendants() {
        let ordinary = thread::current().id();
        Runner::new(config()).start(|context| async move {
            for mode in [
                Execution::Shared(false),
                Execution::Dedicated,
                Execution::Shared(true),
            ] {
                let child = context.child("mode");
                let child = match mode {
                    Execution::Dedicated => child.dedicated(),
                    Execution::Shared(blocking) => child.shared(blocking),
                };
                let (parent, nested) = child
                    .spawn(|context| async move {
                        let parent = thread::current().id();
                        let nested = context
                            .child("ordinary_child")
                            .spawn(|_| async { thread::current().id() })
                            .await
                            .unwrap();
                        (parent, nested)
                    })
                    .await
                    .unwrap();
                assert_eq!(parent, nested);
                assert_eq!(parent == ordinary, matches!(mode, Execution::Shared(false)));
            }
        });
    }

    #[test]
    fn root_constructor_panic_drops_unpolled_tasks_and_clears_scope() {
        let drops = Arc::new(AtomicUsize::new(0));
        let payload = DropFlag(drops.clone());
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(config()).start(move |context| -> std::future::Pending<()> {
                context.child("never_polled").spawn(move |_| async move {
                    let _payload = payload;
                    pending::<()>().await;
                });
                panic!("root constructor failed");
            });
        }));
        assert!(result.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(current().is_none());
        assert_eq!(Runner::new(config()).start(|_| async { 9 }), 9);
    }

    #[test]
    fn root_poll_failure_survives_a_second_panic_during_future_destruction() {
        struct FailingRoot;
        impl Future for FailingRoot {
            type Output = ();

            fn poll(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<()> {
                panic!("primary root poll failure");
            }
        }
        impl Drop for FailingRoot {
            fn drop(&mut self) {
                panic!("secondary root destruction failure");
            }
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(config()).start(|_| FailingRoot);
        }));
        let panic = result.expect_err("root poll must fail the runner");
        assert_eq!(extract_panic_message(&*panic), "primary root poll failure");
        assert!(current().is_none());
    }

    #[test]
    fn retained_descendant_context_is_closed_before_parent_result() {
        Runner::new(config()).start(|context| async move {
            let retained = context
                .child("parent")
                .spawn(|context| async move { context.child("retained") })
                .await
                .unwrap();
            let invoked = Arc::new(AtomicBool::new(false));
            let called = invoked.clone();
            let result = retained
                .spawn(move |_| {
                    called.store(true, Ordering::SeqCst);
                    async {}
                })
                .await;
            assert!(matches!(result, Err(Error::Closed)));
            assert!(!invoked.load(Ordering::SeqCst));
            let metrics = context.encode();
            assert!(
                metrics
                    .lines()
                    .filter(|line| line.starts_with("runtime_tasks_running{")
                        && line.contains("parent"))
                    .all(|line| line.ends_with(" 0"))
            );
        });
    }

    #[test]
    fn closure_panics_are_caught_on_selected_workers() {
        Runner::new(config().with_catch_panics(true)).start(|context| async move {
            for blocking in [false, true] {
                let result = context
                    .child("panic")
                    .shared(blocking)
                    .spawn(|_| -> std::future::Ready<()> {
                        panic!("task constructor failed");
                    })
                    .await;
                assert!(matches!(result, Err(Error::Exited)));
            }
        });
    }

    #[test]
    fn foreign_context_can_spawn_await_and_abort_ordinary_work() {
        let ordinary = thread::current().id();
        Runner::new(config()).start(|context| async move {
            let remote = context.child("foreign");
            let (finished, completion) = oneshot::channel();
            let foreign = thread::spawn(move || {
                let executed = block_on(
                    remote
                        .child("owned")
                        .spawn(|_| async { thread::current().id() }),
                )
                .unwrap();
                assert_eq!(executed, ordinary);
                let aborted = remote.child("aborted").spawn(|_| pending::<()>());
                aborted.abort();
                assert!(block_on(aborted).is_err());
                finished.send(()).unwrap();
            });
            completion.await.unwrap();
            foreign.join().unwrap();
        });
    }

    #[test]
    fn one_off_infrastructure_failure_interrupts_pending_root() {
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(config().with_catch_panics(true)).start(|context| async move {
                context.shared.fail_startup.store(true, Ordering::Relaxed);
                context
                    .child("failed_native_startup")
                    .shared(true)
                    .spawn(|_| async {});
                pending::<()>().await;
            });
        }));
        let panic = result.expect_err("infrastructure failure must interrupt the root");
        assert!(
            extract_panic_message(&*panic)
                .contains("injected native worker initialization failure")
        );
    }

    #[test]
    fn completed_one_off_worker_does_not_close_sibling_registry() {
        Runner::new(config()).start(|context| async move {
            context
                .child("first")
                .dedicated()
                .spawn(|_| async {})
                .await
                .unwrap();
            let result = context
                .child("second")
                .dedicated()
                .spawn(|context| async move {
                    context
                        .child("nested")
                        .dedicated()
                        .spawn(|_| async { 11 })
                        .await
                        .unwrap()
                })
                .await
                .unwrap();
            assert_eq!(result, 11);
        });
    }

    #[test]
    fn completed_workers_release_tracking_before_subsequent_launches() {
        Runner::new(config()).start(|context| async move {
            for _ in 0..8 {
                context
                    .child("finished")
                    .shared(true)
                    .spawn(|_| async {})
                    .await
                    .unwrap();
                poll_fn(|cx| {
                    if context.shared.workers.state.lock().active == 0 {
                        Poll::Ready(())
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
            }
        });
    }

    #[test]
    fn closed_runner_rejects_one_off_payload_without_invoking_closure() {
        let escaped = Runner::new(config()).start(|context| async { context });
        let drops = Arc::new(AtomicUsize::new(0));
        let payload = DropFlag(drops.clone());
        let handle =
            escaped
                .child("closed")
                .shared(true)
                .spawn(move |_| -> std::future::Ready<()> {
                    let _payload = payload;
                    panic!("closed worker invoked user closure");
                });
        assert!(matches!(block_on(handle), Err(Error::Closed)));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn launch_failure_destroys_reentrant_payload_after_unlocking_registry() {
        struct ReentrantDrop {
            context: Option<Context>,
            drops: Arc<AtomicUsize>,
        }
        impl Drop for ReentrantDrop {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                self.context
                    .take()
                    .unwrap()
                    .shared(true)
                    .spawn(|_| async {});
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let observed = drops.clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(config()).start(move |context| async move {
                let payload = ReentrantDrop {
                    context: Some(context.child("reentrant")),
                    drops,
                };
                context.shared.fail_launch.store(true, Ordering::Relaxed);
                let failed =
                    context
                        .child("failed_launch")
                        .shared(true)
                        .spawn(move |_| async move {
                            let _payload = payload;
                        });
                assert!(matches!(failed.await, Err(Error::Closed)));
            });
        }));
        assert!(result.is_err());
        assert_eq!(observed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failure_queued_before_barrier_close_is_retained() {
        let (panicker, mut panicked) = Panicker::new(true);
        panicker.notify_fatal(Box::new("late worker panic"));
        assert_eq!(
            panicked.close().unwrap().downcast_ref::<&str>(),
            Some(&"late worker panic")
        );
    }

    #[test]
    fn config_validation_bounds_ring_and_wheel_before_startup() {
        let mut rounded = config().with_ring_config(RingConfig {
            size: 3,
            ..RingConfig::default()
        });
        rounded.validate();
        assert_eq!(rounded.ring_config.size, 4);
        for size in [0, 32_769, u32::MAX] {
            let mut invalid = config().with_ring_config(RingConfig {
                size,
                ..RingConfig::default()
            });
            assert!(catch_unwind(AssertUnwindSafe(|| invalid.validate())).is_err());
        }
        for timeout in [
            Duration::ZERO,
            TimeoutWheel::MAX_TIMEOUT + Duration::from_nanos(1),
        ] {
            for mut invalid in [
                config().with_connect_timeout(timeout),
                config().with_read_write_timeout(timeout),
            ] {
                assert!(catch_unwind(AssertUnwindSafe(|| invalid.validate())).is_err());
            }
        }
        for tick in [Duration::ZERO, Duration::from_nanos(1), Duration::MAX] {
            let invalid = config().with_ring_config(RingConfig {
                timeout_wheel_tick: tick,
                ..RingConfig::default()
            });
            let directory = invalid.storage_directory().clone();
            assert!(!directory.exists());
            let called = AtomicBool::new(false);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    Runner::new(invalid).start(|_| {
                        called.store(true, Ordering::SeqCst);
                        async {}
                    });
                }))
                .is_err()
            );
            // Invalid layouts must fail before acquiring storage resources or
            // invoking user code, even when slot arithmetic overflows.
            assert!(!called.load(Ordering::SeqCst));
            assert!(!directory.exists());
        }
        let mut boundary = config()
            .with_connect_timeout(TimeoutWheel::MAX_TIMEOUT)
            .with_read_write_timeout(TimeoutWheel::MAX_TIMEOUT)
            .with_ring_config(RingConfig {
                timeout_wheel_tick: Duration::from_secs(3600),
                ..RingConfig::default()
            });
        boundary.validate();
    }
    #[test]
    fn finished_worker_tls_can_wait_for_live_root_work() {
        struct OnExit {
            context: Option<Context>,
            entered: Option<oneshot::Sender<()>>,
            release: Option<oneshot::Receiver<()>>,
            done: Option<oneshot::Sender<()>>,
        }

        impl Drop for OnExit {
            fn drop(&mut self) {
                // The root awaits done_rx before returning, keeping admission open.
                // A panic escaping this TLS destructor would abort the process.
                let context = self.context.take().unwrap();
                let release = self.release.take().unwrap();
                let handle = context.spawn(move |_| async move {
                    release.await.unwrap();
                });
                self.entered.take().unwrap().send(()).unwrap();
                futures::executor::block_on(handle).unwrap();
                self.done.take().unwrap().send(()).unwrap();
            }
        }

        thread_local! {
            static EXIT: RefCell<Option<OnExit>> = const { RefCell::new(None) };
        }

        Runner::new(config()).start(|context| async move {
            let (entered, entered_rx) = oneshot::channel();
            let (release, release_rx) = oneshot::channel();
            let (done, done_rx) = oneshot::channel();
            let exit_context = context.child("tls_dependency");
            context
                .child("first_worker")
                .dedicated()
                .spawn(move |_| async move {
                    EXIT.with(|slot| {
                        *slot.borrow_mut() = Some(OnExit {
                            context: Some(exit_context),
                            entered: Some(entered),
                            release: Some(release_rx),
                            done: Some(done),
                        });
                    });
                })
                .await
                .unwrap();
            entered_rx.await.unwrap();
            let second = context
                .child("second_worker")
                .dedicated()
                .spawn(|_| async {});
            release.send(()).unwrap();
            second.await.unwrap();
            done_rx.await.unwrap();
        });
    }

    #[test]
    fn final_callbacks_finish_before_tls_removal() {
        struct Chain {
            remaining: usize,
            drops: Arc<AtomicUsize>,
        }
        // This waker owns a reentrant destructor, which Waker::noop cannot model.
        #[allow(clippy::manual_noop_waker)]
        impl std::task::Wake for Chain {
            fn wake(self: Arc<Self>) {}
        }
        impl Drop for Chain {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                let local = current().expect("callback ran after TLS removal");
                if self.remaining == 0 {
                    panic!("terminal callback panic");
                }
                // Each destructor generates another ownership batch. No Local
                // reference escapes shutdown or postpones its final destruction.
                local
                    .borrow_mut()
                    .deferred
                    .drops
                    .push(Waker::from(Arc::new(Self {
                        remaining: self.remaining - 1,
                        drops: self.drops.clone(),
                    })));
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let observed = drops.clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            Runner::new(config()).start(|_| async move {
                current()
                    .unwrap()
                    .borrow_mut()
                    .deferred
                    .drops
                    .push(Waker::from(Arc::new(Chain {
                        remaining: 8,
                        drops,
                    })));
                panic!("primary root panic");
            });
        }));
        assert_eq!(
            extract_panic_message(&*result.unwrap_err()),
            "primary root panic"
        );
        assert_eq!(observed.load(Ordering::SeqCst), 9);
    }
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod lifecycle_tests;
