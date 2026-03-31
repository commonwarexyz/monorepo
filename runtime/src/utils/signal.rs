//! Mechanisms for coordinating actions across many tasks.

use commonware_utils::channel::oneshot::{self, error::RecvError};
use futures::{future::Shared, FutureExt};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// A one-time broadcast that can be awaited by many tasks. It is often used for
/// coordinating graceful stopping across many tasks.
///
/// Each [Signal] tracks its lifecycle to enable proper stop coordination.
/// To minimize overhead, it is recommended to wait on a reference to it
/// (i.e. `&mut signal`) in loops rather than creating multiple `Signal`s.
///
/// # Example
///
/// ## Basic Usage
///
/// ```rust
/// use commonware_runtime::{Spawner, Runner, StopReason, deterministic, signal::Signaler};
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Setup signaler and get future
///     let (signaler, signal) = Signaler::new();
///
///     // Signal stopping
///     signaler.signal(StopReason::Requested(2));
///
///     // Wait for the stop reason in the task
///     let sig = signal.await.unwrap();
///     assert_eq!(sig, StopReason::Requested(2));
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
/// _Note: Polling the same `Signal` after it has resolved will always panic.
/// When waiting on a reference to a `Signal`, ensure it is either fused
/// or not polled again after it has yielded a result._
///
/// ```rust
/// use commonware_macros::select;
/// use commonware_runtime::{
///     Clock, Metrics, Spawner, Runner, StopReason, deterministic, signal::Signaler,
/// };
/// use commonware_utils::channel::oneshot;
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
///         // Wait for signal or sleep
///         loop {
///             select! {
///                 sig = &mut signal => {
///                     assert_eq!(sig.unwrap(), StopReason::Requested(9));
///                     break;
///                 },
///                 _ = context.sleep(Duration::from_secs(1)) => {},
///             }
///         }
///         let _ = tx.send(());
///     });
///
///     // Send signal
///     signaler.signal(StopReason::Requested(9));
///
///     // Wait for task
///     rx.await.expect("stop signaled");
/// });
/// ```
#[derive(Clone)]
pub enum Signal<R> {
    /// A signal that will resolve when the signaler marks it as resolved.
    Open(Receiver<R>),
    /// A signal that has been resolved with a known value.
    Closed(R),
}

impl<R: Clone + Unpin> Future for Signal<R> {
    type Output = Result<R, RecvError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Open(live) => Pin::new(&mut live.inner).poll(cx),
            Self::Closed(value) => Poll::Ready(Ok(value.clone())),
        }
    }
}

/// An open [Signal] with completion tracking.
#[derive(Clone)]
pub struct Receiver<R> {
    inner: Shared<oneshot::Receiver<R>>,
    _guard: Arc<Guard>,
}

/// A guard used to coordinate the resolution of a [Signal].
struct Guard {
    tx: Option<oneshot::Sender<()>>,
}

impl Guard {
    /// Create a new [Guard] that will resolve when the [Signaler] marks it as resolved.
    pub const fn new(completion_tx: oneshot::Sender<()>) -> Self {
        Self {
            tx: Some(completion_tx),
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Coordinates a one-time signal across many tasks.
pub struct Signaler<R> {
    tx: oneshot::Sender<R>,
    completion_rx: oneshot::Receiver<()>,
}

impl<R: Clone> Signaler<R> {
    /// Create a new [Signaler].
    ///
    /// Returns a [Signaler] and a [Signal] that will resolve when [Signaler::signal] is called.
    pub fn new() -> (Self, Signal<R>) {
        let (tx, rx) = oneshot::channel();
        let (completion_tx, completion_rx) = oneshot::channel();

        let signaler = Self { tx, completion_rx };
        let signal = Signal::Open(Receiver {
            inner: rx.shared(),
            _guard: Arc::new(Guard::new(completion_tx)),
        });

        (signaler, signal)
    }

    /// Resolve all [Signal]s associated with this [Signaler].
    pub fn signal(self, reason: R) -> oneshot::Receiver<()> {
        let _ = self.tx.send(reason);
        self.completion_rx
    }
}

/// Employs [Signaler] to coordinate graceful stopping of many tasks.
pub enum Stopper<R> {
    /// The stopper is running and stop has not been called yet.
    Running {
        // We must use an Option here because we need to move the signaler out of the
        // Running state when stopping.
        signaler: Option<Signaler<R>>,
        signal: Signal<R>,
    },
    /// Stopping has begun and completion is pending or resolved.
    Stopped {
        reason: R,
        completion: Shared<oneshot::Receiver<()>>,
    },
}

impl<R: Clone> Stopper<R> {
    /// Create a new stopper in running mode.
    pub fn new() -> Self {
        let (signaler, signal) = Signaler::new();
        Self::Running {
            signaler: Some(signaler),
            signal,
        }
    }

    /// Get the signal for users to await.
    pub fn stopped(&self) -> Signal<R> {
        match self {
            Self::Running { signal, .. } => signal.clone(),
            Self::Stopped { reason, .. } => Signal::Closed(reason.clone()),
        }
    }

    /// Begin stopping with the provided reason, returning the shared completion
    /// future that resolves once all already-open signals are dropped.
    ///
    /// Always returns a completion future, even if stopping has already begun.
    /// If so, this returns the same shared completion future that will resolve
    /// immediately if already completed, and preserves the first stop reason.
    pub fn stop(&mut self, reason: R) -> Shared<oneshot::Receiver<()>> {
        match self {
            Self::Running { signaler, .. } => {
                // Take the signaler out of the Option (it is always populated in Running)
                let sig = signaler.take().unwrap();

                // Signal stopping and get the completion receiver
                let completion_rx = sig.signal(reason.clone());
                let shared_completion = completion_rx.shared();

                // Transition to Stopped state
                *self = Self::Stopped {
                    reason,
                    completion: shared_completion.clone(),
                };

                shared_completion
            }
            Self::Stopped { completion, .. } => {
                // Ignore later stop reasons and return the first one used.

                // Return existing completion (may already be resolved)
                completion.clone()
            }
        }
    }
}

impl<R: Clone> Default for Stopper<R> {
    fn default() -> Self {
        Self::new()
    }
}
