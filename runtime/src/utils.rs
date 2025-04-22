//! Utility functions for interacting with any runtime.

#[cfg(test)]
use crate::Runner;
use crate::{Error, Metrics, Spawner};
#[cfg(test)]
use futures::stream::{FuturesUnordered, StreamExt};
use futures::{
    channel::oneshot,
    future::Shared,
    stream::{AbortHandle, Abortable},
    FutureExt,
};
use prometheus_client::metrics::gauge::Gauge;
use rayon::{ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};
use std::{
    any::Any,
    future::Future,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::{Arc, Once},
    task::{Context, Poll},
};
use tracing::error;

/// Yield control back to the runtime.
pub async fn reschedule() {
    struct Reschedule {
        yielded: bool,
    }

    impl Future for Reschedule {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    Reschedule { yielded: false }.await
}

fn extract_panic_message(err: &(dyn Any + Send)) -> String {
    if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else {
        format!("{:?}", err)
    }
}

/// Handle to a spawned task.
pub struct Handle<T>
where
    T: Send + 'static,
{
    aborter: Option<AbortHandle>,
    receiver: oneshot::Receiver<Result<T, Error>>,

    running: Gauge,
    once: Arc<Once>,
}

impl<T> Handle<T>
where
    T: Send + 'static,
{
    pub(crate) fn init<F>(
        f: F,
        running: Gauge,
        catch_panic: bool,
    ) -> (impl Future<Output = ()>, Self)
    where
        F: Future<Output = T> + Send + 'static,
    {
        // Increment running counter
        running.inc();

        // Initialize channels to handle result/abort
        let once = Arc::new(Once::new());
        let (sender, receiver) = oneshot::channel();
        let (aborter, abort_registration) = AbortHandle::new_pair();

        // Wrap the future to handle panics
        let wrapped = {
            let once = once.clone();
            let running = running.clone();
            async move {
                // Run future
                let result = AssertUnwindSafe(f).catch_unwind().await;

                // Decrement running counter
                once.call_once(|| {
                    running.dec();
                });

                // Handle result
                let result = match result {
                    Ok(result) => Ok(result),
                    Err(err) => {
                        if !catch_panic {
                            resume_unwind(err);
                        }
                        let err = extract_panic_message(&*err);
                        error!(?err, "task panicked");
                        Err(Error::Exited)
                    }
                };
                let _ = sender.send(result);
            }
        };

        // Make the future abortable
        let abortable = Abortable::new(wrapped, abort_registration);
        (
            abortable.map(|_| ()),
            Self {
                aborter: Some(aborter),
                receiver,

                running,
                once,
            },
        )
    }

    pub(crate) fn init_blocking<F>(f: F, running: Gauge, catch_panic: bool) -> (impl FnOnce(), Self)
    where
        F: FnOnce() -> T + Send + 'static,
    {
        // Increment the running tasks gauge
        running.inc();

        // Initialize channel to handle result
        let once = Arc::new(Once::new());
        let (sender, receiver) = oneshot::channel();

        // Wrap the closure with panic handling
        let f = {
            let once = once.clone();
            let running = running.clone();
            move || {
                // Run blocking task
                let result = catch_unwind(AssertUnwindSafe(f));

                // Decrement running counter
                once.call_once(|| {
                    running.dec();
                });

                // Handle result
                let result = match result {
                    Ok(value) => Ok(value),
                    Err(err) => {
                        if !catch_panic {
                            resume_unwind(err);
                        }
                        let err = extract_panic_message(&*err);
                        error!(?err, "blocking task panicked");
                        Err(Error::Exited)
                    }
                };
                let _ = sender.send(result);
            }
        };

        // Return the task and handle
        (
            f,
            Self {
                aborter: None,
                receiver,

                running,
                once,
            },
        )
    }

    /// Abort the task (if not blocking).
    pub fn abort(&self) {
        // Get aborter and abort
        let Some(aborter) = &self.aborter else {
            return;
        };
        aborter.abort();

        // Decrement running counter
        self.once.call_once(|| {
            self.running.dec();
        });
    }
}

impl<T> Future for Handle<T>
where
    T: Send + 'static,
{
    type Output = Result<T, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(Ok(value))) => {
                self.once.call_once(|| {
                    self.running.dec();
                });
                Poll::Ready(Ok(value))
            }
            Poll::Ready(Ok(Err(err))) => {
                self.once.call_once(|| {
                    self.running.dec();
                });
                Poll::Ready(Err(err))
            }
            Poll::Ready(Err(_)) => {
                self.once.call_once(|| {
                    self.running.dec();
                });
                Poll::Ready(Err(Error::Closed))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A one-time broadcast that can be awaited by many tasks. It is often used for
/// coordinating shutdown across many tasks.
///
/// To minimize the overhead of tracking outstanding signals (which only return once),
/// it is recommended to wait on a reference to it (i.e. `&mut signal`) instead of
/// cloning it multiple times in a given task (i.e. in each iteration of a loop).
pub type Signal = Shared<oneshot::Receiver<i32>>;

/// Coordinates a one-time signal across many tasks.
///
/// # Example
///
/// ## Basic Usage
///
/// ```rust
/// use commonware_runtime::{Spawner, Runner, Signaler, deterministic::Executor};
///
/// let (executor, _, _) = Executor::default();
/// executor.start(async move {
///     // Setup signaler and get future
///     let (mut signaler, signal) = Signaler::new();
///
///     // Signal shutdown
///     signaler.signal(2);
///
///     // Wait for shutdown in task
///     let sig = signal.await.unwrap();
///     println!("Received signal: {}", sig);
/// });
/// ```
///
/// ## Advanced Usage
///
/// While `Futures::Shared` is efficient, there is still meaningful overhead
/// to cloning it (i.e. in each iteration of a loop). To avoid
/// a performance regression from introducing `Signaler`, it is recommended
/// to wait on a reference to `Signal` (i.e. `&mut signal`).
///
/// ```rust
/// use commonware_macros::select;
/// use commonware_runtime::{Clock, Spawner, Runner, Signaler, deterministic::Executor, Metrics};
/// use futures::channel::oneshot;
/// use std::time::Duration;
///
/// let (executor, context, _) = Executor::default();
/// executor.start(async move {
///     // Setup signaler and get future
///     let (mut signaler, mut signal) = Signaler::new();
///
///     // Loop on the signal until resolved
///     let (tx, rx) = oneshot::channel();
///     context.with_label("waiter").spawn(|context| async move {
///         loop {
///             // Wait for signal or sleep
///             select! {
///                  sig = &mut signal => {
///                      println!("Received signal: {}", sig.unwrap());
///                      break;
///                  },
///                  _ = context.sleep(Duration::from_secs(1)) => {},
///             };
///         }
///         let _ = tx.send(());
///     });
///
///     // Send signal
///     signaler.signal(9);
///
///     // Wait for task
///     rx.await.expect("shutdown signaled");
/// });
/// ```
pub struct Signaler {
    tx: Option<oneshot::Sender<i32>>,
}

impl Signaler {
    /// Create a new `Signaler`.
    ///
    /// Returns a `Signaler` and a `Signal` that will resolve when `signal` is called.
    pub fn new() -> (Self, Signal) {
        let (tx, rx) = oneshot::channel();
        (Self { tx: Some(tx) }, rx.shared())
    }

    /// Resolve the `Signal` for all waiters (if not already resolved).
    pub fn signal(&mut self, value: i32) {
        if let Some(stop_tx) = self.tx.take() {
            let _ = stop_tx.send(value);
        }
    }
}

/// Creates a [rayon]-compatible thread pool with [Spawner::spawn_blocking].
///
/// # Arguments
/// - `context`: The runtime context implementing the [Spawner] trait.
/// - `concurrency`: The number of tasks to execute concurrently in the pool.
///
/// # Returns
/// A `Result` containing the configured [rayon::ThreadPool] or a [rayon::ThreadPoolBuildError] if the pool cannot be built.
pub fn create_pool<S: Spawner + Metrics>(
    context: S,
    concurrency: usize,
) -> Result<ThreadPool, ThreadPoolBuildError> {
    ThreadPoolBuilder::new()
        .num_threads(concurrency)
        .spawn_handler(move |thread| {
            context
                .with_label("rayon-thread")
                .spawn_blocking(move || thread.run());
            Ok(())
        })
        .build()
}

#[cfg(test)]
async fn task(i: usize) -> usize {
    for _ in 0..5 {
        reschedule().await;
    }
    i
}

#[cfg(test)]
pub fn run_tasks(tasks: usize, runner: impl Runner, context: impl Spawner) -> Vec<usize> {
    runner.start(async move {
        // Randomly schedule tasks
        let mut handles = FuturesUnordered::new();
        for i in 0..=tasks - 1 {
            handles.push(context.clone().spawn(move |_| task(i)));
        }

        // Collect output order
        let mut outputs = Vec::new();
        while let Some(result) = handles.next().await {
            outputs.push(result.unwrap());
        }
        assert_eq!(outputs.len(), tasks);
        outputs
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{tokio::Executor, Metrics};
    use commonware_macros::test_traced;
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    #[test_traced]
    fn test_create_pool() {
        let (executor, context) = Executor::default();
        executor.start(async move {
            // Create a thread pool with 4 threads
            let pool = create_pool(context.with_label("pool"), 4).unwrap();

            // Create a vector of numbers
            let v: Vec<_> = (0..10000).collect();

            // Use the thread pool to sum the numbers
            pool.install(|| {
                assert_eq!(v.par_iter().sum::<i32>(), 10000 * 9999 / 2);
            });
        });
    }
}
