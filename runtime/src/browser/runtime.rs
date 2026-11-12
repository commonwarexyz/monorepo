use super::{
    timer::Timer,
    webrtc::{self, Endpoint},
};
use crate::{
    Clock, Error, Execution, Handle, METRICS_PREFIX, Name, child_label, prefixed_name,
    signal::Signal,
    telemetry::metrics::{
        CounterFamily, GaugeFamily, Metric, Register, Registered, Registry, add_attribute, raw,
        task::Label, validate_label,
    },
    utils::{FactoryGuard, MetricHandle, Panicker, signal::Stopper, supervision::Tree},
};
use commonware_macros::select;
use commonware_utils::{sync::Mutex, sys_rng};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use js_sys::futures::spawn_local;
use rand_core::{Rng, TryCryptoRng, TryRng};
use std::{
    convert::Infallible,
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime},
};

#[derive(Debug)]
struct Metrics {
    tasks_spawned: CounterFamily<Label>,
    tasks_running: GaugeFamily<Label>,
}

impl Metrics {
    fn init(registry: &mut impl Register) -> Self {
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

/// Configuration for the `browser` runtime.
#[derive(Clone, Debug)]
pub struct Config {
    /// URLs of the STUN servers an endpoint asks for its public address, such as
    /// `stun:stun.example.com:3478`.
    ///
    /// Without one, an address lists only the sockets of the device's own network
    /// interfaces. Unless one of those is public, other networks cannot reach the page.
    ///
    /// Defaults to none.
    stun_servers: Vec<String>,

    /// Maximum number of bytes a connection holds for its reader beyond what the reader has
    /// requested.
    ///
    /// A connection that receives more than this is closed.
    ///
    /// Defaults to 4 MiB.
    receive_buffer_size: usize,
}

impl Config {
    /// Returns a new [Config] with default values.
    pub const fn new() -> Self {
        Self {
            stun_servers: Vec::new(),
            receive_buffer_size: 4 * 1024 * 1024,
        }
    }

    // Setters
    /// See [Config]
    pub fn with_stun_servers(mut self, stun_servers: Vec<String>) -> Self {
        self.stun_servers = stun_servers;
        self
    }
    /// See [Config]
    pub const fn with_receive_buffer_size(mut self, receive_buffer_size: usize) -> Self {
        self.receive_buffer_size = receive_buffer_size;
        self
    }

    // Getters
    /// See [Config]
    pub fn stun_servers(&self) -> &[String] {
        &self.stun_servers
    }
    /// See [Config]
    pub const fn receive_buffer_size(&self) -> usize {
        self.receive_buffer_size
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

/// State shared by every [Context] of a run.
struct Executor {
    registry: Registry,
    metrics: Metrics,
    shutdown: Mutex<Stopper>,
    panicker: Panicker,
    timer: Timer,
    cfg: Config,
}

/// Aborts a run's tasks and stops its timer when [Runner::start] completes or is dropped.
struct Shutdown {
    tree: Arc<Tree>,
    timer: Timer,
    metric: MetricHandle,
}

impl Drop for Shutdown {
    fn drop(&mut self) {
        self.tree.abort();
        self.timer.stop();
        self.metric.finish();
    }
}

/// Runs a root task on the page's event loop.
///
/// A page cannot block its event loop, so this runner does not implement [crate::Runner].
pub struct Runner {
    cfg: Config,
}

impl Default for Runner {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl Runner {
    /// Initialize a new `browser` runtime with the given configuration.
    pub const fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    /// Start running a root task.
    ///
    /// The returned future completes with the output of the root task. The root task runs
    /// wherever that future is polled, so it may hold values that are not [Send], such as a
    /// JavaScript callback. A spawned task cannot.
    ///
    /// When the returned future completes or is dropped, every spawned task is aborted. An
    /// aborted task is destroyed the next time the event loop runs it.
    ///
    /// A [Context] kept past that point cannot spawn tasks, and nothing wakes its sleeps. A
    /// [Sink](super::Sink) or [Stream](super::Stream) kept past it keeps its connection open.
    pub async fn start<F, Fut>(self, f: F) -> Fut::Output
    where
        F: FnOnce(Context) -> Fut,
        Fut: Future,
    {
        // Create a new registry
        let mut registry = Registry::new();
        let mut runtime_registry = registry.sub_registry(METRICS_PREFIX);
        let metrics = Metrics::init(&mut runtime_registry);

        // Initialize panicker
        let (panicker, panicked) = Panicker::new(false);

        // Start the timer
        let timer = Timer::default();
        spawn_local(timer.clone().run());

        // Initialize executor
        let executor = Arc::new(Executor {
            registry,
            metrics,
            shutdown: Mutex::new(Stopper::default()),
            panicker,
            timer: timer.clone(),
            cfg: self.cfg,
        });

        // Get metrics
        let label = Label::root();
        executor.metrics.tasks_spawned.get_or_create(&label).inc();
        let metric =
            MetricHandle::new(executor.metrics.tasks_running.get_or_create(&label).clone());

        // Run the future
        let tree = Tree::root();
        let _shutdown = Shutdown {
            tree: tree.clone(),
            timer,
            metric,
        };
        let root = f(Context {
            name: label.name().to_string(),
            attributes: Vec::new(),
            executor,
            tree,
        });
        panicked.interrupt(root).await
    }
}

/// Implementation of [crate::Spawner], [crate::Clock], and [crate::Metrics] for the
/// `browser` runtime.
///
/// [Context::bind] opens the endpoints that connect it to other pages.
pub struct Context {
    name: String,
    attributes: Vec<(String, String)>,
    executor: Arc<Executor>,
    tree: Arc<Tree>,
}

impl Context {
    /// Access the [Metrics] of the runtime.
    fn metrics(&self) -> &Metrics {
        &self.executor.metrics
    }

    /// Open an endpoint that connects this page to one other page.
    ///
    /// The endpoint's [Address](super::Address) tells the other page how to reach this one.
    /// [Endpoint::dial] connects the pages once this page has the other page's address.
    pub fn bind(&self) -> impl Future<Output = Result<Endpoint, Error>> + Send + 'static + use<> {
        webrtc::bind(self.executor.cfg.clone())
    }
}

impl crate::Spawner for Context {
    fn dedicated(self) -> Self {
        self
    }

    fn shared(self, _blocking: bool) -> Self {
        self
    }

    fn spawn<F, Fut, T>(mut self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Get metrics
        let (_, metric) = spawn_metrics!(
            Label::task(self.name.clone(), Execution::default()),
            @make self
        );

        // Track supervision
        let parent = Arc::clone(&self.tree);
        let (child, aborted) = Tree::child(&parent);
        if aborted {
            return Handle::closed(metric);
        }
        self.tree = child;

        // The factory runs user code. If it unwinds, the guard finishes the running gauge and
        // closes the supervision node the wrapper never received.
        let panicker = self.executor.panicker.clone();
        let guard = FactoryGuard::new(&parent, metric);
        let future = f(self);
        let (f, handle) = Handle::init(future, guard.disarm(), panicker, Arc::clone(&parent));

        // Spawn the task
        spawn_local(f);
        handle
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        let stop_resolved = {
            let mut shutdown = self.executor.shutdown.lock();
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
        self.executor.shutdown.lock().stopped()
    }
}

impl crate::Supervisor for Context {
    fn child(&self, label: &'static str) -> Self {
        let (tree, _) = Tree::child(&self.tree);
        Self {
            name: child_label(&self.name, label),
            attributes: self.attributes.clone(),
            executor: self.executor.clone(),
            tree,
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
        self.executor.registry.register(
            prefixed_name(&self.name, &name),
            help,
            self.attributes.clone(),
            metric,
        )
    }

    fn encode(&self) -> String {
        self.executor.registry.encode()
    }
}

impl Clock for Context {
    fn current(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(js_sys::Date::now() as u64)
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static + use<> {
        self.executor.timer.sleep(duration)
    }

    fn sleep_until(
        &self,
        deadline: SystemTime,
    ) -> impl Future<Output = ()> + Send + 'static + use<> {
        let duration_until_deadline = deadline.duration_since(self.current()).unwrap_or_default();
        self.executor.timer.sleep(duration_until_deadline)
    }
}

impl GClock for Context {
    type Instant = SystemTime;

    fn now(&self) -> Self::Instant {
        self.current()
    }
}

impl ReasonablyRealtime for Context {}

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
