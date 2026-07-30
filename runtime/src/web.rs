//! Experimental single-threaded browser runtime.
//!
//! This module is `ALPHA`. Its API may change as browser lifecycle and transport support mature.

use crate::{
    BufferPool, BufferPoolConfig, BufferPooler, Clock, Error, Execution, Handle, Metrics, Name,
    Spawner, Supervisor,
    signal::Signal,
    telemetry::metrics::{
        CounterFamily, GaugeFamily, Metric, Register, Registered, Registry, add_attribute,
        prefixed_name, raw, task::Label, validate_label,
    },
    utils::{MetricHandle, signal::Stopper, supervision::Tree},
};
use commonware_macros::select;
use commonware_utils::sys_rng;
use governor::clock::{Clock as GovernorClock, ReasonablyRealtime};
use rand_core::{Rng, TryCryptoRng, TryRng};
use std::{
    cell::{Cell, RefCell},
    convert::Infallible,
    future::Future,
    pin::Pin,
    rc::{Rc, Weak},
    sync::Arc,
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, SystemTime},
};
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{Performance, Window};

const MAX_TIMER_DELAY_MS: f64 = i32::MAX as f64;

#[derive(Debug)]
struct TaskMetrics {
    tasks_spawned: CounterFamily<Label>,
    tasks_running: GaugeFamily<Label>,
}

impl TaskMetrics {
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

struct Executor {
    registry: Registry,
    metrics: TaskMetrics,
    shutdown: RefCell<Stopper>,
    window: Window,
    performance: Performance,
    wall_anchor: SystemTime,
    monotonic_anchor_ms: f64,
    network_buffer_pool: BufferPool,
    storage_buffer_pool: BufferPool,
}

/// Browser event-loop runtime.
#[derive(Clone)]
pub struct Runtime {
    executor: Rc<Executor>,
}

impl Runtime {
    /// Create a runtime attached to the current browser window.
    pub fn new() -> Result<Self, Error> {
        let window = web_sys::window()
            .ok_or_else(|| Error::TransportFailed("browser window unavailable".into()))?;
        let performance = window
            .performance()
            .ok_or_else(|| Error::TransportFailed("browser performance clock unavailable".into()))?;

        let mut registry = Registry::new();
        let mut runtime_registry = registry.sub_registry(crate::telemetry::metrics::METRICS_PREFIX);
        let metrics = TaskMetrics::new(&mut runtime_registry);
        let network_buffer_pool = BufferPool::new(
            BufferPoolConfig::for_network().with_thread_cache_disabled(),
            &mut runtime_registry.sub_registry("network_buffer_pool"),
        );
        let storage_buffer_pool = BufferPool::new(
            BufferPoolConfig::for_storage().with_thread_cache_disabled(),
            &mut runtime_registry.sub_registry("storage_buffer_pool"),
        );

        Ok(Self {
            executor: Rc::new(Executor {
                registry,
                metrics,
                shutdown: RefCell::new(Stopper::default()),
                window,
                wall_anchor: SystemTime::now(),
                monotonic_anchor_ms: performance.now(),
                performance,
                network_buffer_pool,
                storage_buffer_pool,
            }),
        })
    }

    /// Spawn the supervised root task on the browser event loop.
    pub fn spawn_root<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Context) -> Fut + 'static,
        Fut: Future<Output = T> + 'static,
        T: 'static,
    {
        let label = Label::root();
        self.executor
            .metrics
            .tasks_spawned
            .get_or_create(&label)
            .inc();
        let metric = MetricHandle::new(
            self.executor
                .metrics
                .tasks_running
                .get_or_create(&label)
                .clone(),
        );
        let tree = Tree::root();
        let context = Context {
            name: label.name(),
            attributes: Vec::new(),
            executor: Rc::clone(&self.executor),
            tree: Arc::clone(&tree),
            execution: Execution::default(),
        };
        let (task, handle) = Handle::init_local(f(context), metric, tree);
        wasm_bindgen_futures::spawn_local(task);
        handle
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new().expect("web runtime requires a browser window")
    }
}

/// Capabilities available to browser tasks.
#[derive(Clone)]
pub struct Context {
    name: String,
    attributes: Vec<(String, String)>,
    executor: Rc<Executor>,
    tree: Arc<Tree>,
    execution: Execution,
}

impl Context {
    fn metrics(&self) -> &TaskMetrics {
        &self.executor.metrics
    }
}

impl Supervisor for Context {
    fn name(&self) -> Name {
        Name {
            label: self.name.clone(),
            attributes: self.attributes.clone(),
        }
    }

    fn child(&self, label: &'static str) -> Self {
        let (tree, _) = Tree::child(&self.tree);
        Self {
            name: crate::telemetry::metrics::child_label(&self.name, label),
            attributes: self.attributes.clone(),
            executor: Rc::clone(&self.executor),
            tree,
            execution: Execution::default(),
        }
    }

    fn with_attribute(mut self, key: &'static str, value: impl std::fmt::Display) -> Self {
        validate_label(key);
        add_attribute(&mut self.attributes, key, value);
        self
    }
}

impl Spawner for Context {
    fn spawn<F, Fut, T>(mut self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + 'static,
        Fut: Future<Output = T> + 'static,
        T: 'static,
    {
        let (_, metric) = crate::spawn_metrics!(self);
        let parent = Arc::clone(&self.tree);
        self.execution = Execution::default();
        let (child, aborted) = Tree::child(&parent);
        if aborted {
            return Handle::closed(metric);
        }
        self.tree = child;

        let (task, handle) = Handle::init_local(f(self), metric, Arc::clone(&parent));
        wasm_bindgen_futures::spawn_local(task);
        if let Some(aborter) = handle.aborter() {
            parent.register(aborter);
        }
        handle
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        let completion = self.executor.shutdown.borrow_mut().stop(value);
        let timeout_future = timeout.map_or_else(
            || futures::future::Either::Right(futures::future::pending()),
            |duration| futures::future::Either::Left(self.sleep(duration)),
        );
        select! {
            result = completion => result.map_err(|_| Error::Closed),
            _ = timeout_future => Err(Error::Timeout),
        }
    }

    fn stopped(&self) -> Signal {
        self.executor.shutdown.borrow().stopped()
    }
}

impl Metrics for Context {
    fn register<N: Into<String>, H: Into<String>, M: Metric>(
        &self,
        name: N,
        help: H,
        metric: M,
    ) -> Registered<M> {
        self.executor.registry.register(
            prefixed_name(&self.name, &name.into()),
            help.into(),
            self.attributes.clone(),
            Arc::new(metric),
        )
    }

    fn encode(&self) -> String {
        self.executor.registry.encode()
    }
}

impl Clock for Context {
    fn current(&self) -> SystemTime {
        let elapsed_ms = (self.executor.performance.now() - self.executor.monotonic_anchor_ms).max(0.0);
        self.executor.wall_anchor + Duration::from_secs_f64(elapsed_ms / 1_000.0)
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + 'static {
        BrowserSleep::new(
            self.executor.window.clone(),
            self.executor.performance.clone(),
            duration,
        )
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + 'static {
        self.sleep(deadline.duration_since(self.current()).unwrap_or_default())
    }
}

impl GovernorClock for Context {
    type Instant = SystemTime;

    fn now(&self) -> Self::Instant {
        self.current()
    }
}

impl ReasonablyRealtime for Context {}

impl BufferPooler for Context {
    fn network_buffer_pool(&self) -> &BufferPool {
        &self.executor.network_buffer_pool
    }

    fn storage_buffer_pool(&self) -> &BufferPool {
        &self.executor.storage_buffer_pool
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

struct SleepState {
    window: Window,
    performance: Performance,
    deadline_ms: f64,
    timer_id: Cell<Option<i32>>,
    done: Cell<bool>,
    waker: RefCell<Option<Waker>>,
    callback: RefCell<Option<Closure<dyn FnMut()>>>,
}

impl SleepState {
    fn schedule(state: &Rc<Self>) {
        let remaining_ms = (state.deadline_ms - state.performance.now()).max(0.0);
        if remaining_ms == 0.0 {
            state.done.set(true);
            if let Some(waker) = state.waker.borrow_mut().take() {
                waker.wake();
            }
            return;
        }

        let delay_ms = remaining_ms.min(MAX_TIMER_DELAY_MS).ceil() as i32;
        let callback = state.callback.borrow();
        let callback = callback.as_ref().expect("sleep callback initialized");
        let timer_id = state
            .window
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.as_ref().unchecked_ref(),
                delay_ms,
            )
            .expect("setTimeout failed");
        state.timer_id.set(Some(timer_id));
    }
}

struct BrowserSleep {
    state: Rc<SleepState>,
}

impl BrowserSleep {
    fn new(window: Window, performance: Performance, duration: Duration) -> Self {
        let state = Rc::new(SleepState {
            window,
            deadline_ms: performance.now() + duration.as_secs_f64() * 1_000.0,
            performance,
            timer_id: Cell::new(None),
            done: Cell::new(duration.is_zero()),
            waker: RefCell::new(None),
            callback: RefCell::new(None),
        });
        let weak: Weak<SleepState> = Rc::downgrade(&state);
        let callback = Closure::new(move || {
            let Some(state) = weak.upgrade() else {
                return;
            };
            state.timer_id.set(None);
            SleepState::schedule(&state);
        });
        *state.callback.borrow_mut() = Some(callback);
        if !duration.is_zero() {
            SleepState::schedule(&state);
        }
        Self { state }
    }
}

impl Future for BrowserSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        if self.state.done.get() {
            return Poll::Ready(());
        }
        *self.state.waker.borrow_mut() = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for BrowserSleep {
    fn drop(&mut self) {
        if let Some(timer_id) = self.state.timer_id.take() {
            self.state.window.clear_timeout_with_handle(timer_id);
        }
        self.state.callback.borrow_mut().take();
        self.state.waker.borrow_mut().take();
    }
}
