//! Utility functions for interacting with any runtime.

use crate::Error;
#[cfg(test)]
use crate::{Runner, Spawner};
#[cfg(test)]
use futures::stream::{FuturesUnordered, StreamExt};
use futures::{
    channel::oneshot,
    future::Shared,
    stream::{AbortHandle, Abortable},
    FutureExt,
};
use prometheus_client::metrics::gauge::Gauge;
use std::{
    any::Any,
    future::Future,
    panic::{resume_unwind, AssertUnwindSafe},
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
    aborter: AbortHandle,
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
                aborter,
                receiver,

                running,
                once,
            },
        )
    }

    pub fn abort(&self) {
        // Stop task
        self.aborter.abort();

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
        Pin::new(&mut self.receiver)
            .poll(cx)
            .map(|res| res.map_err(|_| Error::Closed).and_then(|r| r))
    }
}

/// Coordinates a one-time signal across many tasks.
///
/// # Example
///
/// ```rust
/// use commonware_runtime::{Spawner, Runner, Signaler, deterministic::Executor};
///
/// let (executor, _, _) = Executor::default();
/// executor.start(async move {
///     // Setup signaler and get future
///     let mut signaler = Signaler::new();
///     let receiver = signaler.signaled();
///
///     // Signal shutdown
///     signaler.signal();
///
///     // Wait for shutdown in task
///     receiver.await.expect("shutdown signaled");
/// });
/// ```
pub struct Signaler {
    tx: Option<oneshot::Sender<()>>,
}

impl Signaler {
    /// Create a new `Signaler`.
    ///
    /// Get a future that resolves when the `Signaler` is signaled.
    ///
    /// Although this function is safe to call multiple times (or in a loop),
    /// it incurs some performance overhead to do so. It is instead recommended
    /// to call this function once and to wait on the returned future (using a
    /// lighter weight mechanism in each iteration of a loop).
    pub fn new() -> (Self, Shared<oneshot::Receiver<()>>) {
        let (tx, rx) = oneshot::channel();
        (Self { tx: Some(tx) }, rx.shared())
    }

    /// Signal the `Signaler`.
    pub fn signal(&mut self) {
        if let Some(stop_tx) = self.tx.take() {
            let _ = stop_tx.send(());
        }
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
pub fn run_tasks(tasks: usize, runner: impl Runner, context: impl Spawner) -> Vec<usize> {
    runner.start(async move {
        // Randomly schedule tasks
        let mut handles = FuturesUnordered::new();
        for i in 0..tasks - 1 {
            handles.push(context.spawn("test", task(i)));
        }
        handles.push(context.spawn("test", task(tasks - 1)));

        // Collect output order
        let mut outputs = Vec::new();
        while let Some(result) = handles.next().await {
            outputs.push(result.unwrap());
        }
        assert_eq!(outputs.len(), tasks);
        outputs
    })
}
