use crate::{
    Error,
    telemetry::metrics::raw::Gauge,
    utils::{extract_panic_message, supervision::Tree},
};
use commonware_utils::{
    channel::oneshot,
    sync::{Mutex, Once},
};
use futures::{
    FutureExt as _,
    future::{Either, poll_fn, select},
    pin_mut,
    stream::{AbortHandle, Abortable, Aborted},
};
use std::{
    any::Any,
    future::Future,
    panic::{AssertUnwindSafe, resume_unwind},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tracing::error;

/// Handle to an asynchronous result.
///
/// Handles returned by [`crate::Spawner::spawn`] abort the spawned task. Completion handles only
/// stop waiting when aborted, resolving to [`Error::Aborted`], and do not cancel the underlying
/// work.
pub struct Handle<T>
where
    T: Send + 'static,
{
    state: HandleState<T>,
}

/// Distinguishes handles that own spawned work from handles that only wait on completion.
enum HandleState<T>
where
    T: Send + 'static,
{
    Task {
        receiver: oneshot::Receiver<Result<T, Error>>,
        abort_handle: AbortHandle,
        metric: MetricHandle,
    },
    Completion {
        future: Abortable<Completion<T>>,
        abort_handle: AbortHandle,
    },
}

/// Aborts every owned handle when a group is no longer supervised.
struct HandleGroup<T>(Vec<Handle<T>>)
where
    T: Send + 'static;

impl<T> Drop for HandleGroup<T>
where
    T: Send + 'static,
{
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

/// Normalizes receiver-backed and future-backed completions behind one abortable future.
enum Completion<T>
where
    T: Send + 'static,
{
    Receiver(oneshot::Receiver<Result<T, Error>>),
    Future(Pin<Box<dyn Future<Output = Result<T, Error>> + Send + 'static>>),
}

impl<T> Unpin for Completion<T> where T: Send + 'static {}

impl<T> Future for Completion<T>
where
    T: Send + 'static,
{
    type Output = Result<T, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Receiver(receiver) => Pin::new(receiver)
                .poll(cx)
                .map(|result| result.unwrap_or(Err(Error::Closed))),
            Self::Future(future) => future.as_mut().poll(cx),
        }
    }
}

impl<T> Handle<T>
where
    T: Send + 'static,
{
    #[inline(always)]
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

        // Wrap the future with panic catching, abort support, and cleanup.
        //
        // Everything is done in a single async block (and the function is marked
        // #[inline(always)]) so that stack usage is `size_of(F) + constant` rather than
        // `N * size_of(F)` (which is what a combinator chain produces in debug builds).
        let metric_handle = metric.clone();
        let task = async move {
            // Run future with panic catching and abort support
            let result =
                Abortable::new(AssertUnwindSafe(f).catch_unwind(), abort_registration).await;

            // Mark the task as aborted and abort all descendants before
            // publishing the result: a handle awaited on another worker can
            // resume as soon as the send lands, and any spawn it then issues
            // from a context derived from the consumed one must observe the
            // closure.
            tree.abort();

            // Handle result
            match result {
                Ok(Ok(result)) => {
                    let _ = sender.send(Ok(result));
                }
                Ok(Err(panic)) => {
                    // An undeliverable payload here means the root completed
                    // on another thread in the same instant. The executors
                    // using this wrapper have no later shutdown path to
                    // route it through, so it is logged and dropped.
                    let _ = panicker.notify(panic);
                    let _ = sender.send(Err(Error::Exited));
                }
                Err(Aborted) => {}
            }

            // Finish the metric.
            metric_handle.finish();
        };

        (
            task,
            Self {
                state: HandleState::Task {
                    receiver,
                    abort_handle,
                    metric,
                },
            },
        )
    }

    /// Returns a task handle assembled from its parts.
    ///
    /// Used by executors that build the result channel before the task's
    /// wrapper exists (e.g. work deferred to a thread that has not started
    /// yet): the wrapper on the remote side owns `sender` and the paired
    /// abort registration, mirroring what [Handle::init] builds inline.
    // The only caller lives in the ALPHA-scoped `iouring` module, so the
    // allowance must cover every configuration that compiles the caller out:
    // the feature being disabled, or any stability level above ALPHA.
    #[cfg_attr(
        any(
            not(all(target_os = "linux", feature = "iouring")),
            commonware_stability_BETA,
            commonware_stability_GAMMA,
            commonware_stability_DELTA,
            commonware_stability_EPSILON,
            commonware_stability_RESERVED
        ),
        allow(dead_code)
    )]
    pub(crate) const fn from_parts(
        receiver: oneshot::Receiver<Result<T, Error>>,
        abort_handle: AbortHandle,
        metric: MetricHandle,
    ) -> Self {
        Self {
            state: HandleState::Task {
                receiver,
                abort_handle,
                metric,
            },
        }
    }

    /// Returns a handle backed by a completion receiver.
    pub fn from_receiver(receiver: oneshot::Receiver<Result<T, Error>>) -> Self {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        Self {
            state: HandleState::Completion {
                future: Abortable::new(Completion::Receiver(receiver), abort_registration),
                abort_handle,
            },
        }
    }

    /// Returns a handle backed by a completion future.
    pub fn from_future<F>(future: F) -> Self
    where
        F: Future<Output = Result<T, Error>> + Send + 'static,
    {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        Self {
            state: HandleState::Completion {
                future: Abortable::new(Completion::Future(Box::pin(future)), abort_registration),
                abort_handle,
            },
        }
    }

    /// Returns a handle that is already complete.
    pub fn ready(result: Result<T, Error>) -> Self {
        let (sender, receiver) = oneshot::channel();
        let _ = sender.send(result);
        Self::from_receiver(receiver)
    }

    /// Waits for the first handle to complete and aborts all handles before returning.
    ///
    /// Dropping the returned future also aborts every handle. Selection is biased toward handles
    /// that appear earlier in the iterator.
    ///
    /// Runtime supervision already aborts a task's descendants when that task exits. This method
    /// is intended for an owned group whose teardown boundary is the first handle completion,
    /// independent of whether the caller exits immediately afterward.
    ///
    /// # Examples
    ///
    /// ```
    /// # futures::executor::block_on(async {
    /// use commonware_runtime::Handle;
    ///
    /// let handles = [
    ///     Handle::ready(Ok(7)),
    ///     Handle::from_future(futures::future::pending()),
    /// ];
    /// assert_eq!(Handle::select(handles).await.unwrap(), 7);
    /// # });
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if `handles` is empty.
    pub fn select(
        handles: impl IntoIterator<Item = Self>,
    ) -> impl Future<Output = Result<T, Error>> + Send + 'static {
        // Construct the guard before returning so dropping the future without polling still aborts
        // every handle.
        let mut handles = HandleGroup(handles.into_iter().collect::<Vec<_>>());

        async move {
            if handles.0.is_empty() {
                return Err(Error::Closed);
            }

            poll_fn(move |cx| {
                for handle in &mut handles.0 {
                    if let Poll::Ready(result) = Pin::new(handle).poll(cx) {
                        return Poll::Ready(result);
                    }
                }
                Poll::Pending
            })
            .await
        }
    }

    /// Returns a handle that resolves to [`Error::Closed`] without spawning work.
    pub(crate) fn closed(metric: MetricHandle) -> Self {
        // Mark the task as finished immediately so gauges remain accurate.
        metric.finish();

        // Create a receiver that will yield `Err(Error::Closed)` when awaited.
        let (sender, receiver) = oneshot::channel();
        drop(sender);

        Self::from_receiver(receiver)
    }

    /// Abort the spawned task or stop waiting for a completion.
    pub fn abort(&self) {
        match &self.state {
            HandleState::Task {
                abort_handle,
                metric,
                ..
            } => {
                abort_handle.abort();

                // We might never poll the future again after aborting it, so run the
                // metric cleanup right away.
                metric.finish();
            }
            HandleState::Completion { abort_handle, .. } => {
                abort_handle.abort();
            }
        }
    }

    /// Returns a helper that aborts the task and updates metrics consistently.
    pub(crate) fn aborter(&self) -> Option<Aborter> {
        match &self.state {
            HandleState::Task {
                abort_handle,
                metric,
                ..
            } => Some(Aborter::new(abort_handle.clone(), metric.clone())),
            HandleState::Completion { .. } => None,
        }
    }
}

impl<T> Future for Handle<T>
where
    T: Send + 'static,
{
    type Output = Result<T, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.state {
            HandleState::Task { receiver, .. } => Pin::new(receiver)
                .poll(cx)
                .map(|result| result.unwrap_or_else(|_| Err(Error::Closed))),
            HandleState::Completion { future, .. } => Pin::new(future)
                .poll(cx)
                .map(|result| result.unwrap_or(Err(Error::Aborted))),
        }
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
    #[commonware_macros::stability(ALPHA)]
    pub(crate) const fn catch(&self) -> bool {
        self.catch
    }

    /// Notify the runtime of a task panic.
    ///
    /// Returns the payload when it could not be delivered: panics are not
    /// being caught, no earlier panic claimed the interrupt, but the root
    /// future (and its receiver) is already gone. Callers with a later
    /// shutdown path should route the returned payload through it rather
    /// than let the panic vanish.
    pub(crate) fn notify(
        &self,
        panic: Box<dyn Any + Send + 'static>,
    ) -> Option<Box<dyn Any + Send + 'static>> {
        // Log the panic
        let err = extract_panic_message(&*panic);
        error!(?err, "task panicked");

        // If we are catching panics, the payload is absorbed by policy.
        if self.catch {
            return None;
        }

        // If we've already sent a panic, later ones rank below it.
        let sender = self.sender.lock().take()?;

        // Send the panic. A dead receiver hands the payload back.
        sender.send(panic).err()
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
    use super::Handle;
    use crate::{Error, Metrics as _, Runner, Spawner, Supervisor as _, deterministic};
    use commonware_utils::channel::oneshot;
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
            let handle = context.child(LABEL).spawn(|_| async move { "done" });

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
            let handle = context.child(LABEL).spawn(|_| async move {
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
            let handle = context.child(LABEL).spawn(|_| async move {
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
    fn select_aborts_remaining_tasks() {
        const LABEL: &str = "tasks_running_select_remaining";

        deterministic::Runner::default().start(|context| async move {
            let completed = context.child("select_completed").spawn(|_| async {});
            let pending = context.child(LABEL).spawn(|_| future::pending());

            Handle::select([completed, pending])
                .await
                .expect("task failed");

            let metrics = context.encode();
            assert_eq!(
                running_tasks_for_label(&metrics, LABEL),
                Some(0),
                "select should abort remaining tasks: {metrics}",
            );
        });
    }

    #[test]
    fn select_empty_returns_closed() {
        deterministic::Runner::default().start(|_| async move {
            assert!(matches!(Handle::<()>::select([]).await, Err(Error::Closed)));
        });
    }

    #[test]
    fn dropping_select_aborts_tasks_before_polling() {
        const FIRST_LABEL: &str = "tasks_running_select_drop_first";
        const SECOND_LABEL: &str = "tasks_running_select_drop_second";

        deterministic::Runner::default().start(|context| async move {
            let first = context
                .child(FIRST_LABEL)
                .spawn(|_| future::pending::<()>());
            let second = context
                .child(SECOND_LABEL)
                .spawn(|_| future::pending::<()>());

            drop(Handle::select([first, second]));

            let metrics = context.encode();
            assert_eq!(running_tasks_for_label(&metrics, FIRST_LABEL), Some(0));
            assert_eq!(running_tasks_for_label(&metrics, SECOND_LABEL), Some(0));
        });
    }

    #[test]
    fn completion_handle_abort_stops_waiting() {
        deterministic::Runner::default().start(|_| async move {
            let (sender, receiver) = oneshot::channel();
            let handle = Handle::from_receiver(receiver);

            handle.abort();

            assert!(sender.send(Ok(())).is_ok());
            assert!(matches!(handle.await, Err(Error::Aborted)));
        });
    }

    #[test]
    fn tasks_running_decreased_after_blocking_completion() {
        const LABEL: &str = "tasks_running_after_blocking_completion";

        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            let blocking_handle = context.child(LABEL).shared(true).spawn(|_| async move {
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
            let handle = context.child(LABEL).spawn(|_| async move {
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
