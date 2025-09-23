use crate::{utils::extract_panic_message, Error};
use futures::{
    channel::oneshot,
    stream::{AbortHandle, Abortable},
    FutureExt as _,
};
use prometheus_client::metrics::gauge::Gauge;
use std::{
    future::Future,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::{Arc, Mutex, Once},
    task::{Context, Poll},
};
use tracing::error;

/// Handle to a spawned task.
pub struct Handle<T>
where
    T: Send + 'static,
{
    abort_handle: Option<AbortHandle>,
    receiver: oneshot::Receiver<Result<T, Error>>,
    metrics: HandleMetrics,
}

impl<T> Handle<T>
where
    T: Send + 'static,
{
    pub(crate) fn init_future<F>(
        f: F,
        metrics: HandleMetrics,
        catch_panic: bool,
        children: Arc<Mutex<Vec<Aborter>>>,
    ) -> (impl Future<Output = ()>, Self)
    where
        F: Future<Output = T> + Send + 'static,
    {
        // Initialize channels to handle result/abort
        let (sender, receiver) = oneshot::channel();
        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        // Wrap the future to handle panics
        let wrapped = async move {
            // Run future
            let result = AssertUnwindSafe(f).catch_unwind().await;

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
        };

        // Make the future abortable
        let abortable = {
            let metrics = metrics.clone();
            Abortable::new(wrapped, abort_registration).map(move |_| {
                // Abort all children
                for aborter in children.lock().unwrap().drain(..) {
                    aborter.abort();
                }

                // Mark the task as finished
                metrics.finish();
            })
        };

        (
            abortable,
            Self {
                abort_handle: Some(abort_handle),
                receiver,
                metrics,
            },
        )
    }

    pub(crate) fn init_blocking<F>(
        f: F,
        metrics: HandleMetrics,
        catch_panic: bool,
    ) -> (impl FnOnce(), Self)
    where
        F: FnOnce() -> T + Send + 'static,
    {
        // Initialize channel to handle result
        let (sender, receiver) = oneshot::channel();

        // Wrap the closure with panic handling
        let f = {
            let metrics = metrics.clone();
            move || {
                // Run blocking task
                let result = catch_unwind(AssertUnwindSafe(f));

                // Handle result
                let result = match result {
                    Ok(value) => Ok(value),
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

                // Mark the task as finished
                metrics.finish();
            }
        };

        // Return the task and handle
        (
            f,
            Self {
                abort_handle: None,
                receiver,
                metrics,
            },
        )
    }

    /// Abort the task (if not blocking).
    pub fn abort(&self) {
        // Get abort handle and abort the task
        let Some(abort_handle) = &self.abort_handle else {
            return;
        };
        abort_handle.abort();

        // Mark the task as finished
        self.metrics.finish();
    }

    /// Returns a helper that aborts the task and updates metrics consistently.
    pub(crate) fn aborter(&self) -> Option<Aborter> {
        self.abort_handle
            .clone()
            .map(|inner| Aborter::new(inner, self.metrics.clone()))
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
            .map(|result| result.unwrap_or_else(|_| Err(Error::Closed)))
    }
}

/// Tracks the metrics state associated with a spawned task handle.
#[derive(Clone)]
pub(crate) struct HandleMetrics {
    gauge: Gauge,
    finished: Arc<Once>,
}

impl HandleMetrics {
    /// Increments the supplied gauge and returns a guard responsible for
    /// eventually decrementing it.
    pub(crate) fn new(gauge: Gauge) -> Self {
        gauge.inc();

        Self {
            gauge,
            finished: Arc::new(Once::new()),
        }
    }

    /// Marks the task handle as completed and decrements the gauge once.
    ///
    /// This method is idempotent, additional calls are ignored so completion
    /// and abort paths can invoke it independently.
    pub(crate) fn finish(&self) {
        let gauge = self.gauge.clone();
        self.finished.call_once(move || {
            gauge.dec();
        });
    }
}

/// Couples an [`AbortHandle`] with its metrics guard so aborted tasks clean up gauges.
pub(crate) struct Aborter {
    inner: AbortHandle,
    metrics: HandleMetrics,
}

impl Aborter {
    /// Creates a new guard for the provided abort handle and metrics tracker.
    pub(crate) fn new(inner: AbortHandle, metrics: HandleMetrics) -> Self {
        Self { inner, metrics }
    }

    /// Aborts the task and records completion in the metrics gauge.
    pub(crate) fn abort(self) {
        self.inner.abort();
        self.metrics.finish();
    }
}
}
