use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use prometheus_client::{
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::Registry,
};
use tokio::runtime::Handle as TokioHandle;

use crate::{Handle, Signal, Signaler};

use super::metrics::Work;

#[derive(Clone)]
pub(super) struct Spawner {
    cfg: Config,
    pub(super) label: String,
    spawned: bool,
    metrics: Arc<SpawnerMetrics>,
    signaler: Arc<Mutex<Signaler>>,
    signal: Signal,
    runtime: Arc<TokioHandle>,
}

#[derive(Clone)]
pub(super) struct Config {
    pub(super) catch_panics: bool,
}

impl Spawner {
    pub(super) fn new(
        label: String,
        cfg: Config,
        reg: &mut Registry,
        runtime: Arc<TokioHandle>,
    ) -> Self {
        let (signaler, signal) = Signaler::new();
        Self {
            cfg,
            label,
            spawned: false,
            metrics: Arc::new(SpawnerMetrics::new(reg)),
            signaler: Arc::new(Mutex::new(signaler)),
            signal,
            runtime,
        }
    }

    pub(super) fn with_label(&self, label: String) -> Self {
        Self {
            cfg: self.cfg.clone(),
            label,
            spawned: false,
            metrics: self.metrics.clone(),
            signaler: self.signaler.clone(),
            signal: self.signal.clone(),
            runtime: self.runtime.clone(),
        }
    }
}

struct SpawnerMetrics {
    tasks_spawned: Family<Work, Counter>,
    tasks_running: Family<Work, Gauge>,
    blocking_tasks_spawned: Family<Work, Counter>,
    blocking_tasks_running: Family<Work, Gauge>,
}

impl SpawnerMetrics {
    fn new(registry: &mut Registry) -> Self {
        let metrics = Self {
            tasks_spawned: Family::default(),
            tasks_running: Family::default(),
            blocking_tasks_spawned: Family::default(),
            blocking_tasks_running: Family::default(),
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
            "blocking_tasks_spawned",
            "Total number of blocking tasks spawned",
            metrics.blocking_tasks_spawned.clone(),
        );
        registry.register(
            "blocking_tasks_running",
            "Number of blocking tasks currently running",
            metrics.blocking_tasks_running.clone(),
        );
        metrics
    }
}

impl crate::Spawner for Spawner {
    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a spawner only spawns one task
        assert!(!self.spawned, "already spawned");

        // Get metrics
        let work = Work {
            label: self.label.clone(),
        };
        self.metrics.tasks_spawned.get_or_create(&work).inc();
        let gauge = self.metrics.tasks_running.get_or_create(&work).clone();

        // Set up the task
        let catch_panics = self.cfg.catch_panics;
        let runtime = self.runtime.clone();
        let future = f(self);
        let (f, handle) = Handle::init(future, gauge, catch_panics);

        // Spawn the task
        runtime.spawn(f);
        handle
    }

    fn spawn_ref<F, T>(&mut self) -> impl FnOnce(F) -> Handle<T> + 'static
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a spawner only spawns one task
        assert!(!self.spawned, "already spawned");
        self.spawned = true;

        // Get metrics
        let work = Work {
            label: self.label.clone(),
        };
        self.metrics.tasks_spawned.get_or_create(&work).inc();
        let gauge = self.metrics.tasks_running.get_or_create(&work).clone();

        // Set up the task
        let runtime = self.runtime.clone();
        let catch_panics = self.cfg.catch_panics;

        move |f: F| {
            let (f, handle) = Handle::init(f, gauge, catch_panics);

            // Spawn the task
            runtime.spawn(f);
            handle
        }
    }

    fn spawn_blocking<F, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        // Ensure a spawner only spawns one task
        assert!(!self.spawned, "already spawned");

        // Get metrics
        let work = Work {
            label: self.label.clone(),
        };
        self.metrics
            .blocking_tasks_spawned
            .get_or_create(&work)
            .inc();
        let gauge = self
            .metrics
            .blocking_tasks_running
            .get_or_create(&work)
            .clone();

        // Initialize the blocking task using the new function
        let (f, handle) = Handle::init_blocking(f, gauge, self.cfg.catch_panics);

        // Spawn the blocking task
        self.runtime.spawn_blocking(f);
        handle
    }

    fn stop(&self, value: i32) {
        self.signaler.lock().unwrap().signal(value);
    }

    fn stopped(&self) -> Signal {
        self.signal.clone()
    }
}
