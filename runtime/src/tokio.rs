//! A production-focused runtime based on [Tokio](https://tokio.rs) with
//! secure randomness.
//!
//! # Example
//! ```rust
//! use commonware_runtime::{Spawner, Runner, tokio::Executor};
//!
//! let (runner, context) = Executor::init(2);
//! runner.start(async move {
//!     println!("Parent started");
//!     let result = context.spawn(async move {
//!         println!("Child started");
//!         "hello"
//!     });
//!     println!("Child result: {:?}", result.await);
//!     println!("Parent exited");
//! });
//! ```

use crate::Handle;
use rand::{rngs::OsRng, RngCore};
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::runtime::{Builder, Runtime};

/// Runtime based on Tokio.
pub struct Executor {
    runtime: Runtime,
}

impl Executor {
    /// Initialize a new `tokio` runtime with the given number of threads.
    pub fn init(threads: usize) -> (Runner, Context) {
        let runtime = Builder::new_multi_thread()
            .worker_threads(threads)
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime");
        let executor = Arc::new(Self { runtime });
        (
            Runner {
                executor: executor.clone(),
            },
            Context { executor },
        )
    }
}

/// Implementation of [`crate::Runner`] for the `tokio` runtime.
pub struct Runner {
    executor: Arc<Executor>,
}

impl crate::Runner for Runner {
    fn start<F>(self, f: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.executor.runtime.block_on(f)
    }
}

/// Implementation of [`crate::Spawner`] and [`crate::Clock`]
/// for the `tokio` runtime.
#[derive(Clone)]
pub struct Context {
    executor: Arc<Executor>,
}

impl crate::Spawner for Context {
    fn spawn<F, T>(&self, f: F) -> Handle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let (f, handle) = Handle::init(f);
        self.executor.runtime.spawn(f);
        handle
    }
}

impl crate::Clock for Context {
    fn current(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        tokio::time::sleep(duration)
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        let now = SystemTime::now();
        let duration_until_deadline = match deadline.duration_since(now) {
            Ok(duration) => duration,
            Err(_) => Duration::from_secs(0), // Deadline is in the past
        };
        let target_instant = tokio::time::Instant::now() + duration_until_deadline;
        tokio::time::sleep_until(target_instant)
    }
}

impl RngCore for Context {
    fn next_u32(&mut self) -> u32 {
        OsRng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        OsRng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        OsRng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        OsRng.try_fill_bytes(dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::run_tasks;

    #[test]
    fn test_runs_tasks() {
        let (runner, context) = Executor::init(1);
        run_tasks(10, runner, context);
    }
}
