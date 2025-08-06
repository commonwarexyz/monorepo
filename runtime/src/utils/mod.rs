//! Utility functions for interacting with any runtime.

#[cfg(test)]
use crate::Runner;
use crate::{Metrics, Spawner};
#[cfg(test)]
use futures::stream::{FuturesUnordered, StreamExt};
use futures::{channel::oneshot, future::Shared, FutureExt};
use rayon::{ThreadPool as RThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};
use std::{
    any::Any,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

pub mod buffer;

mod handle;
pub use handle::Handle;

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
        format!("{err:?}")
    }
}

/// A one-time broadcast that can be awaited by many tasks. It is often used for
/// coordinating shutdown across many tasks.
///
/// Each Signal tracks its lifecycle to enable proper shutdown coordination.
/// To minimize overhead, it is recommended to wait on a reference to it
/// (i.e. `&mut signal`) in loops rather than creating multiple `Signal`s.
///
/// # Example
///
/// ## Basic Usage
///
/// ```rust
/// use commonware_runtime::{Spawner, Runner, Signaler, deterministic};
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Setup signaler and get future
///     let (signaler, signal) = Signaler::new();
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
/// use commonware_runtime::{Clock, Spawner, Runner, Signaler, deterministic, Metrics};
/// use futures::channel::oneshot;
/// use std::time::Duration;
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Setup signaler and get future
///     let (signaler, mut signal) = Signaler::new();
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
#[derive(Clone)]
pub enum Signal {
    /// A live signal that will resolve when the signaler signals completion.
    Live(LiveSignal),
    /// A pre-resolved signal with a known value.
    Resolved { value: i32 },
}

/// A live signal with completion tracking.
#[derive(Clone)]
pub struct LiveSignal {
    inner: Shared<oneshot::Receiver<i32>>,
    _guard: Arc<SignalGuard>,
}

struct SignalGuard {
    tx: Option<oneshot::Sender<()>>,
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Future for Signal {
    type Output = Result<i32, oneshot::Canceled>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Signal::Live(live) => Pin::new(&mut live.inner).poll(cx),
            Signal::Resolved { value } => Poll::Ready(Ok(*value)),
        }
    }
}

/// Coordinates a one-time signal across many tasks.
pub struct Signaler {
    tx: oneshot::Sender<i32>,
    completion_rx: oneshot::Receiver<()>,
}

impl Signaler {
    /// Create a new `Signaler`.
    ///
    /// Returns a `Signaler` and a `Signal` that will resolve when `signal` is called.
    pub fn new() -> (Self, Signal) {
        let (tx, rx) = oneshot::channel();
        let (completion_tx, completion_rx) = oneshot::channel();

        let signaler = Self { tx, completion_rx };
        let signal = Signal::Live(LiveSignal {
            inner: rx.shared(),
            _guard: Arc::new(SignalGuard {
                tx: Some(completion_tx),
            }),
        });

        (signaler, signal)
    }

    /// Resolve all `Signal`s associated with this `Signaler`.
    pub fn signal(self, value: i32) -> oneshot::Receiver<()> {
        let _ = self.tx.send(value);
        self.completion_rx
    }
}

/// Manages shutdown state for a runtime executor.
pub enum ShutdownState {
    /// The runtime is running and stop has not been called yet.
    Running { signaler: Signaler, signal: Signal },
    /// Stop has been called but completion is still pending.
    Stopping {
        stop_value: i32,
        completion: Shared<oneshot::Receiver<()>>,
    },
    /// Stop has completed.
    Stopped { stop_value: i32 },
}

impl ShutdownState {
    /// Create a new shutdown state in running mode.
    pub fn new() -> Self {
        let (signaler, signal) = Signaler::new();
        Self::Running { signaler, signal }
    }

    /// Get the signal for runtime users to await.
    pub fn stopped(&self) -> Signal {
        match self {
            Self::Running { signal, .. } => signal.clone(),
            Self::Stopping { stop_value, .. } | Self::Stopped { stop_value } => {
                Signal::Resolved { value: *stop_value }
            }
        }
    }

    /// Initiate shutdown returning a completion future.
    /// Returns `None` if stop has already completed.
    pub fn stop(&mut self, value: i32) -> Option<Shared<oneshot::Receiver<()>>> {
        match std::mem::replace(self, Self::Stopped { stop_value: value }) {
            Self::Running { signaler, .. } => {
                let completion_rx = signaler.signal(value);
                let shared_completion = completion_rx.shared();
                *self = Self::Stopping {
                    stop_value: value,
                    completion: shared_completion.clone(),
                };
                Some(shared_completion)
            }
            Self::Stopping {
                stop_value,
                completion,
            } => {
                *self = Self::Stopping {
                    stop_value,
                    completion: completion.clone(),
                };
                Some(completion)
            }
            Self::Stopped { stop_value } => {
                *self = Self::Stopped { stop_value };
                None
            }
        }
    }

    /// Mark shutdown as finished. This should be called after the completion future resolves.
    pub fn finished(&mut self) {
        if let Self::Stopping { stop_value, .. } = self {
            *self = Self::Stopped {
                stop_value: *stop_value,
            };
        }
    }
}

impl Default for ShutdownState {
    fn default() -> Self {
        Self::new()
    }
}

/// A clone-able wrapper around a [rayon]-compatible thread pool.
pub type ThreadPool = Arc<RThreadPool>;

/// Creates a clone-able [rayon]-compatible thread pool with [Spawner::spawn_blocking].
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
    let pool = ThreadPoolBuilder::new()
        .num_threads(concurrency)
        .spawn_handler(move |thread| {
            // Tasks spawned in a thread pool are expected to run longer than any single
            // task and thus should be provisioned as a dedicated thread.
            context
                .with_label("rayon-thread")
                .spawn_blocking(true, move |_| thread.run());
            Ok(())
        })
        .build()?;

    Ok(Arc::new(pool))
}

/// Async reader–writer lock.
///
/// Powered by [async_lock::RwLock], `RwLock` provides both fair writer acquisition
/// and `try_read` / `try_write` without waiting (without any runtime-specific dependencies).
///
/// Usage:
/// ```rust
/// use commonware_runtime::{Spawner, Runner, Signaler, deterministic, RwLock};
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Create a new RwLock
///     let lock = RwLock::new(2);
///
///     // many concurrent readers
///     let r1 = lock.read().await;
///     let r2 = lock.read().await;
///     assert_eq!(*r1 + *r2, 4);
///
///     // exclusive writer
///     drop((r1, r2));
///     let mut w = lock.write().await;
///     *w += 1;
/// });
/// ```
pub struct RwLock<T>(async_lock::RwLock<T>);

/// Shared guard returned by [RwLock::read].
pub type RwLockReadGuard<'a, T> = async_lock::RwLockReadGuard<'a, T>;

/// Exclusive guard returned by [RwLock::write].
pub type RwLockWriteGuard<'a, T> = async_lock::RwLockWriteGuard<'a, T>;

impl<T> RwLock<T> {
    /// Create a new lock.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self(async_lock::RwLock::new(value))
    }

    /// Acquire a shared read guard.
    #[inline]
    pub async fn read(&self) -> RwLockReadGuard<'_, T> {
        self.0.read().await
    }

    /// Acquire an exclusive write guard.
    #[inline]
    pub async fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.0.write().await
    }

    /// Try to get a read guard without waiting.
    #[inline]
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        self.0.try_read()
    }

    /// Try to get a write guard without waiting.
    #[inline]
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        self.0.try_write()
    }

    /// Get mutable access without locking (requires `&mut self`).
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.0.get_mut()
    }

    /// Consume the lock, returning the inner value.
    #[inline]
    pub fn into_inner(self) -> T {
        self.0.into_inner()
    }
}

#[cfg(test)]
async fn task(i: usize) -> usize {
    for _ in 0..5 {
        reschedule().await;
    }
    i
}

#[cfg(test)]
pub fn run_tasks(tasks: usize, runner: crate::deterministic::Runner) -> (String, Vec<usize>) {
    runner.start(|context| async move {
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
        (context.auditor().state(), outputs)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, tokio, Metrics};
    use commonware_macros::test_traced;
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    #[test_traced]
    fn test_create_pool() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
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

    #[test_traced]
    fn test_rwlock() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Create a new RwLock
            let lock = RwLock::new(100);

            // many concurrent readers
            let r1 = lock.read().await;
            let r2 = lock.read().await;
            assert_eq!(*r1 + *r2, 200);

            // exclusive writer
            drop((r1, r2)); // all readers must go away
            let mut w = lock.write().await;
            *w += 1;

            // Check the value
            assert_eq!(*w, 101);
        });
    }
}
