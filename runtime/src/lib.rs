//! TBD

pub mod deterministic;
pub mod tokio;

mod utils;
pub use utils::{reschedule, Handle};

use std::{
    any::Any,
    future::Future,
    time::{Duration, SystemTime},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("exited: {0:?}")]
    Exited(Box<dyn Any + Send + 'static>),
    #[error("closed")]
    Closed,
}

pub trait Runner {
    fn start<F>(self, f: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}

pub trait Spawner: Clone + Send + 'static {
    fn spawn<F, T>(&self, f: F) -> Handle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static;
}

pub trait Clock: Clone + Send + 'static {
    fn current(&self) -> SystemTime;
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static;
    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};
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
            result.await.unwrap_err();
            Result::<(), Error>::Ok(())
        });

        // Ensure panic was caught
        result.unwrap();
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
            let (runner, _) = deterministic::Executor::init(1, Duration::from_millis(1));
            test_panic_aborts_root(runner);
        }
        {
            let (runner, context) = deterministic::Executor::init(1, Duration::from_millis(1));
            test_panic_aborts_spawn(runner, context);
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
            let (runner, _) = tokio::Executor::init(1);
            test_panic_aborts_root(runner);
        }
        {
            let (runner, context) = tokio::Executor::init(1);
            test_panic_aborts_spawn(runner, context);
        }
    }
}
