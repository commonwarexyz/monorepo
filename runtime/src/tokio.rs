//! A non-deterministic runtime based on Tokio with secure randomness.
//!
//! # Example
//! ```rust
//! use commonware_runtime::{Spawner, Runner, tokio::{Executor, reschedule}};
//!
//! let (runner, context) = Executor::init(2);
//! runner.start(async move {
//!     context.spawn(async move {
//!         println!("Child started");
//!         for _ in 0..5 {
//!           // Simulate work
//!           reschedule().await;
//!         }
//!         println!("Child completed");
//!     });
//!
//!     println!("Parent started");
//!     for _ in 0..3 {
//!       // Simulate work
//!       reschedule().await;
//!     }
//!     println!("Parent completed");
//! });
//! ```

use rand::{rngs::OsRng, RngCore};
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::runtime::{Builder, Runtime};

pub struct Executor {
    runtime: Runtime,
}

impl Executor {
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

#[derive(Clone)]
pub struct Context {
    executor: Arc<Executor>,
}

impl crate::Spawner for Context {
    fn spawn<F>(&self, f: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.executor.runtime.spawn(f);
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

pub async fn reschedule() {
    tokio::task::yield_now().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Clock, Runner, Spawner};
    use tokio::sync::mpsc;

    async fn task(name: &'static str, messages: mpsc::UnboundedSender<&'static str>) {
        for _ in 0..5 {
            reschedule().await;
        }
        messages.send(name).unwrap();
    }

    #[test]
    fn test_executor_runs_tasks() {
        let (runner, context) = Executor::init(1);
        runner.start(async move {
            // Randomly schedule tasks
            let (sender, mut receiver) = mpsc::unbounded_channel();
            context.spawn(task("Task 1", sender.clone()));
            context.spawn(task("Task 2", sender.clone()));
            context.spawn(task("Task 3", sender));

            // Collect output order
            let mut output = Vec::new();
            while let Some(message) = receiver.recv().await {
                output.push(message);
            }
            assert_eq!(output.len(), 3);
        });
    }

    #[test]
    fn test_clock_sleep() {
        let (runner, context) = Executor::init(1);
        runner.start(async move {
            // Capture initial time
            let start = context.current();
            context.sleep(Duration::from_millis(100)).await;

            // Ensure sleep duration is at least 100ms
            let end = context.current();
            assert!(end.duration_since(start).unwrap() >= Duration::from_millis(100));
        });
    }
}
