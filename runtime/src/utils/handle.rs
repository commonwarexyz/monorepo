use crate::{supervision::Tree, utils::extract_panic_message, Error};
use futures::{
    channel::oneshot,
    future::{select, Either},
    pin_mut,
    stream::{AbortHandle, Abortable},
    FutureExt as _,
};
use prometheus_client::metrics::gauge::Gauge;
use std::{
    any::Any,
    future::Future,
    panic::{resume_unwind, AssertUnwindSafe},
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
    metric: MetricHandle,
}

impl<T> Handle<T>
where
    T: Send + 'static,
{
    pub(crate) fn init<F>(
        f: F,
        metric: MetricHandle,
        panicker: Panicker,
        tree: Arc<Tree>,
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
                Err(panic) => {
                    panicker.notify(panic);
                    Err(Error::Exited)
                }
            };
            let _ = sender.send(result);
        };

        // Make the future abortable
        let metric_handle = metric.clone();
        let abortable = Abortable::new(wrapped, abort_registration).map(move |_| {
            // Mark the task as aborted and abort all descendants.
            tree.abort();

            // Finish the metric.
            metric_handle.finish();
        });

        (
            abortable,
            Self {
                abort_handle: Some(abort_handle),
                receiver,
                metric,
            },
        )
    }

    /// Returns a handle that resolves to [`Error::Closed`] without spawning work.
    pub(crate) fn closed(metric: MetricHandle) -> Self {
        // Mark the task as finished immediately so gauges remain accurate.
        metric.finish();

        // Create a receiver that will yield `Err(Error::Closed)` when awaited.
        let (sender, receiver) = oneshot::channel();
        drop(sender);

        Self {
            abort_handle: None,
            receiver,
            metric,
        }
    }

    /// Abort the task (if not blocking).
    pub fn abort(&self) {
        // Get abort handle and abort the task
        let Some(abort_handle) = &self.abort_handle else {
            return;
        };
        abort_handle.abort();

        // We might never poll the future again after aborting it, so run the
        // metric cleanup right away
        self.metric.finish();
    }

    /// Returns a helper that aborts the task and updates metrics consistently.
    pub(crate) fn aborter(&self) -> Option<Aborter> {
        self.abort_handle
            .clone()
            .map(|inner| Aborter::new(inner, self.metric.clone()))
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

/// Tracks the metric state associated with a spawned task handle.
#[derive(Clone)]
pub(crate) struct MetricHandle {
    gauge: Gauge,
    finished: Arc<Once>,
}

impl MetricHandle {
    /// Increments the supplied gauge and returns a handle responsible for
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

/// A panic emitted by a spawned task.
pub type Panic = Box<dyn Any + Send + 'static>;

/// Notifies the runtime when a spawned task panics, so it can propagate the failure.
#[derive(Clone)]
pub(crate) struct Panicker {
    catch: bool,
    sender: Arc<Mutex<Option<oneshot::Sender<Panic>>>>,
}

impl Panicker {
    /// Creates a new [Panicker].
    pub(crate) fn new(catch: bool) -> (Self, Panicked) {
        let (sender, receiver) = oneshot::channel();
        let panicker = Self {
            catch,
            sender: Arc::new(Mutex::new(Some(sender))),
        };
        let panicked = Panicked { receiver };
        (panicker, panicked)
    }

    /// Returns whether the [Panicker] is configured to catch panics.
    pub(crate) const fn catch(&self) -> bool {
        self.catch
    }

    /// Notifies the [Panicker] that a panic has occurred.
    pub(crate) fn notify(&self, panic: Box<dyn Any + Send + 'static>) {
        // Log the panic
        let err = extract_panic_message(&*panic);
        error!(?err, "task panicked");

        // If we are catching panics, just return
        if self.catch {
            return;
        }

        // If we've already sent a panic, ignore the new one
        let mut sender = self.sender.lock().unwrap();
        let Some(sender) = sender.take() else {
            return;
        };

        // Send the panic
        let _ = sender.send(panic);
    }
}

/// A handle that will be notified when a panic occurs.
pub(crate) struct Panicked {
    receiver: oneshot::Receiver<Panic>,
}

impl Panicked {
    /// Polls a task that should be interrupted by a panic.
    pub(crate) async fn interrupt<Fut>(self, task: Fut) -> Fut::Output
    where
        Fut: Future,
    {
        // Wait for task to complete or panic
        let panicked = self.receiver;
        pin_mut!(panicked);
        pin_mut!(task);
        match select(panicked, task).await {
            Either::Left((panic, task)) => match panic {
                // If there is a panic, resume the unwind
                Ok(panic) => {
                    resume_unwind(panic);
                }
                // If there can never be a panic (oneshot is closed), wait for the task to complete
                // and return the output
                Err(_) => task.await,
            },
            Either::Right((output, _)) => {
                // Return the output
                output
            }
        }
    }
}

/// Couples an [`AbortHandle`] with its metric handle so aborted tasks clean up gauges.
pub(crate) struct Aborter {
    inner: AbortHandle,
    metric: MetricHandle,
}

impl Aborter {
    /// Creates a new [`Aborter`] for the provided abort handle and metric handle.
    pub(crate) const fn new(inner: AbortHandle, metric: MetricHandle) -> Self {
        Self { inner, metric }
    }

    /// Aborts the task and records completion in the metric gauge.
    pub(crate) fn abort(self) {
        self.inner.abort();

        // We might never poll the future again after aborting it, so run the
        // metric cleanup right away
        self.metric.finish();
    }
}

#[cfg(test)]
mod tests {
    use crate::{deterministic, Metrics, Runner, Spawner};
    use futures::future;

    const METRIC_PREFIX: &str = "runtime_tasks_running{";

    fn running_tasks_for_label(metrics: &str, label: &str) -> Option<u64> {
        let label_fragment = format!("name=\"{label}\"");
        metrics.lines().find_map(|line| {
            if line.starts_with(METRIC_PREFIX) && line.contains(&label_fragment) {
                line.rsplit_once(' ')
                    .and_then(|(_, value)| value.trim().parse::<u64>().ok())
            } else {
                None
            }
        })
    }

    #[test]
    fn tasks_running_decreased_after_completion() {
        const LABEL: &str = "tasks_running_after_completion";

        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let context = context.with_label(LABEL);
            let handle = context.clone().spawn(|_| async move { "done" });

            let metrics = context.encode();
            assert_eq!(
                running_tasks_for_label(&metrics, LABEL),
                Some(1),
                "expected tasks_running gauge to be 1 before completion: {metrics}",
            );

            let output = handle.await.expect("task failed");
            assert_eq!(output, "done");

            let metrics = context.encode();
            assert_eq!(
                running_tasks_for_label(&metrics, LABEL),
                Some(0),
                "expected tasks_running gauge to return to 0 after completion: {metrics}",
            );
        });
    }

    #[test]
    fn tasks_running_unchanged_when_handle_dropped() {
        const LABEL: &str = "tasks_running_unchanged";

        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let context = context.with_label(LABEL);
            let handle = context.clone().spawn(|_| async move {
                future::pending::<()>().await;
            });

            let metrics = context.encode();
            assert_eq!(
                running_tasks_for_label(&metrics, LABEL),
                Some(1),
                "expected tasks_running gauge to be 1 before dropping handle: {metrics}",
            );

            drop(handle);

            let metrics = context.encode();
            assert_eq!(
                running_tasks_for_label(&metrics, LABEL),
                Some(1),
                "dropping handle should not finish metrics: {metrics}",
            );
        });
    }

    #[test]
    fn tasks_running_decreased_immediately_on_abort_via_handle() {
        const LABEL: &str = "tasks_running_abort_via_handle";

        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let context = context.with_label(LABEL);
            let handle = context.clone().spawn(|_| async move {
                future::pending::<()>().await;
            });

            let metrics = context.encode();
            assert_eq!(
                running_tasks_for_label(&metrics, LABEL),
                Some(1),
                "expected tasks_running gauge to be 1 before abort: {metrics}",
            );

            handle.abort();

            let metrics = context.encode();
            assert_eq!(
                running_tasks_for_label(&metrics, LABEL),
                Some(0),
                "expected tasks_running gauge to return to 0 after abort: {metrics}",
            );
        });
    }

    #[test]
    fn tasks_running_decreased_after_blocking_completion() {
        const LABEL: &str = "tasks_running_after_blocking_completion";

        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let context = context.with_label(LABEL);

            let blocking_handle = context.clone().shared(true).spawn(|_| async move {
                // Simulate some blocking work
                42
            });

            let metrics = context.encode();
            assert_eq!(
                running_tasks_for_label(&metrics, LABEL),
                Some(1),
                "expected tasks_running gauge to be 1 while blocking task runs: {metrics}",
            );

            let result = blocking_handle.await.expect("blocking task failed");
            assert_eq!(result, 42);

            let metrics = context.encode();
            assert_eq!(
                running_tasks_for_label(&metrics, LABEL),
                Some(0),
                "expected tasks_running gauge to return to 0 after blocking task completes: {metrics}",
            );
        });
    }

    #[test]
    fn tasks_running_decreased_immediately_on_abort_via_aborter() {
        const LABEL: &str = "tasks_running_abort_via_aborter";

        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let context = context.with_label(LABEL);
            let handle = context.clone().spawn(|_| async move {
                future::pending::<()>().await;
            });

            let metrics = context.encode();
            assert_eq!(
                running_tasks_for_label(&metrics, LABEL),
                Some(1),
                "expected tasks_running gauge to be 1 before abort: {metrics}",
            );

            let aborter = handle.aborter().unwrap();
            aborter.abort();

            let metrics = context.encode();
            assert_eq!(
                running_tasks_for_label(&metrics, LABEL),
                Some(0),
                "expected tasks_running gauge to return to 0 after abort: {metrics}",
            );
        });
    }
}
