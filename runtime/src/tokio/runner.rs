#[cfg(feature = "iouring")]
use crate::storage::iouring::{Config as IoUringConfig, Storage as IoUringStorage};
#[cfg(not(feature = "iouring"))]
use crate::storage::tokio::{Config as TokioStorageConfig, Storage as TokioStorage};

use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use crate::storage::metered::Storage as MeteredStorage;
use prometheus_client::registry::Registry;
use tokio::runtime::Builder;

use crate::Signaler;

use super::{metrics::Metrics, Config, Context, Executor};

/// Implementation of [crate::Runner] for the [tokio] runtime.
pub struct Runner {
    cfg: Config,
}

impl Default for Runner {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl Runner {
    /// Initialize a new [tokio] runtime with the given number of threads.
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }
}

impl From<Config> for Runner {
    fn from(cfg: Config) -> Self {
        Self::new(cfg)
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
        let mut registry = Registry::default();
        let runtime_registry = registry.sub_registry_with_prefix(crate::METRICS_PREFIX);

        // Initialize runtime
        let metrics = Arc::new(Metrics::init(runtime_registry));
        let runtime = Builder::new_multi_thread()
            .worker_threads(self.cfg.worker_threads)
            .max_blocking_threads(self.cfg.max_blocking_threads)
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime");
        let (signaler, signal) = Signaler::new();

        #[cfg(feature = "iouring")]
        let storage = MeteredStorage::new(
            IoUringStorage::start(&IoUringConfig {
                storage_directory: self.cfg.storage_directory.clone(),
                ring_config: Default::default(),
            }),
            runtime_registry,
        );

        #[cfg(not(feature = "iouring"))]
        let storage = MeteredStorage::new(
            TokioStorage::new(TokioStorageConfig::new(
                self.cfg.storage_directory.clone(),
                self.cfg.maximum_buffer_size,
            )),
            runtime_registry,
        );

        let executor = Arc::new(Executor {
            cfg: self.cfg,
            registry: Mutex::new(registry),
            metrics,
            runtime,
            signaler: Mutex::new(signaler),
            signal,
        });

        let context = Context {
            storage,
            label: String::new(),
            spawned: false,
            executor: executor.clone(),
        };

        executor.runtime.block_on(f(context))
    }
}
