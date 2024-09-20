//! Execute asynchronous tasks with a configurable scheduler.
//!
//! This crate provides a collection of runtimes that can be
//! used to execute asynchronous tasks in a variety of ways. For production use,
//! the `tokio` module provides a runtime backed by [Tokio](https://tokio.rs).
//! For testing and simulation, the `deterministic` module provides a runtime
//! that allows for deterministic execution of tasks (given a fixed seed).
//!
//! # Status
//!
//! `commonware-runtime` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

pub mod deterministic;
pub mod tokio;

mod utils;
use bytes::Bytes;
pub use utils::{reschedule, timeout, Handle};

use std::{
    future::Future,
    net::SocketAddr,
    time::{Duration, SystemTime},
};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("exited")]
    Exited,
    #[error("closed")]
    Closed,
    #[error("timeout")]
    Timeout,
}

/// Interface that any task scheduler must implement to start
/// running tasks.
pub trait Runner {
    /// Start running a root task.
    fn start<F>(self, f: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}

/// Interface that any task scheduler must implement to spawn
/// sub-tasks in a given root task.
pub trait Spawner: Clone + Send + Sync + 'static {
    /// Enqueues a task to be executed.
    ///
    /// Unlike a future, a spawned task will start executing immediately (even if the caller
    /// does not await the handle).
    fn spawn<F, T>(&self, f: F) -> Handle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static;
}

/// Interface that any task scheduler must implement to provide
/// time-based operations.
///
/// It is necessary to mock time to provide deterministic execution
/// of arbitrary tasks.
pub trait Clock: Clone + Send + Sync + 'static {
    /// Returns the current time.
    fn current(&self) -> SystemTime;

    /// Sleep for the given duration.
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static;

    /// Sleep until the given deadline.
    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static;
}

pub trait Network<L, S>: Clone + Send + Sync + 'static
where
    L: Listener<S>,
    S: Stream,
{
    fn bind(&self, socket: SocketAddr) -> L;
    fn dial(&self, socket: SocketAddr) -> Result<S, Error>;
}

pub trait Listener<S>: Clone + Send + Sync + 'static
where
    S: Stream,
{
    fn accept(&self) -> Result<S, Error>;
}

pub trait Stream: Clone + Send + Sync + 'static {
    fn send(&self, msg: Bytes) -> impl Future<Output = Result<(), Error>> + Send + 'static;
    fn recv(&self) -> impl Future<Output = Result<Bytes, Error>> + Send + 'static;
}

/// Macro to select the first future that completes.
///
/// It is not possible to use duplicate variable names with the macro.
#[macro_export]
macro_rules! select {
    (
        $(
            $var:ident = $fut:expr => $block:block
        ),+ $(,)?
    ) => {{
        use futures::{pin_mut, select_biased, FutureExt};
        $(
            // Fuse each future and assign it to the provided variable
            let $var = $fut.fuse();
            pin_mut!($var);
        )+

        // Use `futures::select_biased!` to await the first future that completes
        select_biased! {
            $(
                $var = $var => $block,
            )+
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::Mutex;
    use utils::reschedule;

    fn test_error_future(runner: impl Runner) {
        async fn error_future() -> Result<&'static str, &'static str> {
            Err("An error occurred")
        }
        let result = runner.start(error_future());
        assert_eq!(result, Err("An error occurred"));
    }

    fn test_clock_sleep(runner: impl Runner, context: impl Spawner + Clock) {
        runner.start(async move {
            // Capture initial time
            let start = context.current();
            let sleep_duration = Duration::from_millis(10);
            context.sleep(sleep_duration).await;

            // After run, time should have advanced
            let end = context.current();
            assert!(end.duration_since(start).unwrap() >= sleep_duration);
        });
    }

    fn test_clock_sleep_until(runner: impl Runner, context: impl Spawner + Clock) {
        runner.start(async move {
            // Trigger sleep
            let now = context.current();
            context.sleep_until(now + Duration::from_millis(100)).await;

            // Ensure slept duration has elapsed
            let elapsed = now.elapsed().unwrap();
            assert!(elapsed >= Duration::from_millis(100));
        });
    }

    fn test_root_finishes(runner: impl Runner, context: impl Spawner) {
        runner.start(async move {
            context.spawn(async move {
                loop {
                    reschedule().await;
                }
            });
        });
    }

    fn test_spawn_abort(runner: impl Runner, context: impl Spawner) {
        runner.start(async move {
            let handle = context.spawn(async move {
                loop {
                    reschedule().await;
                }
            });
            handle.abort();
            assert_eq!(handle.await, Err(Error::Closed));
        });
    }

    fn test_panic_aborts_root(runner: impl Runner) {
        let result = catch_unwind(AssertUnwindSafe(|| {
            runner.start(async move {
                panic!("blah");
            });
        }));
        result.unwrap_err();
    }

    fn test_panic_aborts_spawn(runner: impl Runner, context: impl Spawner) {
        let result = runner.start(async move {
            let result = context.spawn(async move {
                panic!("blah");
            });
            assert_eq!(result.await, Err(Error::Exited));
            Result::<(), Error>::Ok(())
        });

        // Ensure panic was caught
        result.unwrap();
    }

    fn test_select(runner: impl Runner, context: impl Spawner) {
        runner.start(async move {
            let output = Mutex::new(0);
            select! {
                v1 = context.spawn(async { 1 }) => {
                    *output.lock().unwrap() = v1.unwrap();
                },
                v2 = context.spawn(async { 2 }) => {
                    *output.lock().unwrap() = v2.unwrap();
                },
            };
            assert_eq!(*output.lock().unwrap(), 1);
        });
    }

    fn test_timeout(runner: impl Runner, context: impl Spawner + Clock) {
        runner.start(async move {
            let timeout = timeout(context, Duration::from_millis(10), async {
                loop {
                    reschedule().await;
                }
            });
            let result = timeout.await.unwrap_err();
            assert_eq!(result, Error::Timeout);
        });
    }

    #[test]
    fn test_deterministic() {
        {
            let (runner, _) = deterministic::Executor::init(1, Duration::from_millis(1));
            test_error_future(runner);
        }
        {
            let (runner, context) = deterministic::Executor::init(1, Duration::from_millis(1));
            assert_eq!(context.current(), SystemTime::UNIX_EPOCH);
            test_clock_sleep(runner, context);
        }
        {
            let (runner, context) = deterministic::Executor::init(1, Duration::from_millis(1));
            test_clock_sleep_until(runner, context);
        }
        {
            let (runner, context) = deterministic::Executor::init(1, Duration::from_millis(1));
            test_root_finishes(runner, context);
        }
        {
            let (runner, context) = deterministic::Executor::init(1, Duration::from_millis(1));
            test_spawn_abort(runner, context);
        }
        {
            let (runner, _) = deterministic::Executor::init(1, Duration::from_millis(1));
            test_panic_aborts_root(runner);
        }
        {
            let (runner, context) = deterministic::Executor::init(1, Duration::from_millis(1));
            test_panic_aborts_spawn(runner, context);
        }
        {
            let (runner, context) = deterministic::Executor::init(1, Duration::from_millis(1));
            test_select(runner, context);
        }
        {
            let (runner, context) = deterministic::Executor::init(1, Duration::from_millis(1));
            test_timeout(runner, context);
        }
    }

    #[test]
    fn test_tokio() {
        {
            let (runner, _) = tokio::Executor::init(1);
            test_error_future(runner);
        }
        {
            let (runner, context) = tokio::Executor::init(1);
            test_clock_sleep(runner, context);
        }
        {
            let (runner, context) = tokio::Executor::init(1);
            test_clock_sleep_until(runner, context);
        }
        {
            let (runner, context) = tokio::Executor::init(1);
            test_root_finishes(runner, context);
        }
        {
            let (runner, context) = tokio::Executor::init(1);
            test_spawn_abort(runner, context);
        }
        {
            let (runner, _) = tokio::Executor::init(1);
            test_panic_aborts_root(runner);
        }
        {
            let (runner, context) = tokio::Executor::init(1);
            test_panic_aborts_spawn(runner, context);
        }
        {
            let (runner, context) = tokio::Executor::init(1);
            test_select(runner, context);
        }
        {
            let (runner, context) = tokio::Executor::init(1);
            test_timeout(runner, context);
        }
    }
}
