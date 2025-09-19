//! Mechanisms for coordinating actions across many tasks.

use futures::{channel::oneshot, future::Shared, FutureExt};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// A one-time broadcast that can be awaited by many tasks. It is often used for
/// coordinating shutdown across many tasks.
///
/// Each [Signal] tracks its lifecycle to enable proper shutdown coordination.
/// To minimize overhead, it is recommended to wait on a reference to it
/// (i.e. `&mut signal`) in loops rather than creating multiple `Signal`s.
///
/// # Example
///
/// ## Basic Usage
///
/// ```rust
/// use commonware_runtime::{Spawner, Runner, deterministic, signal::Signaler};
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
/// _Note: Polling the same `Signal` after it has resolved will always panic.
/// When waiting on a reference to a `Signal`, ensure it is either fused
/// or not polled again after it has yielded a result._
///
/// ```rust
/// use commonware_macros::select;
/// use commonware_runtime::{Clock, Spawner, Runner, deterministic, Metrics, signal::Signaler};
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
    /// A signal that will resolve when the signaler marks it as resolved.
    Open(Receiver),
    /// A signal that has been resolved with a known value.
    Closed(i32),
}

impl Future for Signal {
    type Output = Result<i32, oneshot::Canceled>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Signal::Open(live) => Pin::new(&mut live.inner).poll(cx),
            Signal::Closed(value) => Poll::Ready(Ok(*value)),
        }
    }
}

/// An open [Signal] with completion tracking.
#[derive(Clone)]
pub struct Receiver {
    inner: Shared<oneshot::Receiver<i32>>,
    _guard: Arc<Guard>,
}

/// A guard used to coordinate the resolution of a [Signal].
struct Guard {
    tx: Option<oneshot::Sender<()>>,
}

impl Guard {
    /// Create a new [Guard] that will resolve when the [Signaler] marks it as resolved.
    pub fn new(completion_tx: oneshot::Sender<()>) -> Self {
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
pub struct Signaler {
    tx: oneshot::Sender<i32>,
    completion_rx: oneshot::Receiver<()>,
}

impl Signaler {
    /// Create a new [Signaler].
    ///
    /// Returns a [Signaler] and a [Signal] that will resolve when [Signaler::signal] is called.
    pub fn new() -> (Self, Signal) {
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
    pub fn signal(self, value: i32) -> oneshot::Receiver<()> {
        let _ = self.tx.send(value);
        self.completion_rx
    }
}

/// Employs [Signaler] to coordinate the graceful shutdown of many tasks.
pub enum Stopper {
    /// The stopper is running and stop has not been called yet.
    Running {
        // We must use an Option here because we need to move the signaler out of the
        // Running state when stopping.
        signaler: Option<Signaler>,
        signal: Signal,
    },
    /// Stop has been called and completion is pending or resolved.
    Stopped {
        stop_value: i32,
        completion: Shared<oneshot::Receiver<()>>,
    },
}

impl Stopper {
    /// Create a new stopper in running mode.
    pub fn new() -> Self {
        let (signaler, signal) = Signaler::new();
        Self::Running {
            signaler: Some(signaler),
            signal,
        }
    }

    /// Get the signal for runtime users to await.
    pub fn stopped(&self) -> Signal {
        match self {
            Self::Running { signal, .. } => signal.clone(),
            Self::Stopped { stop_value, .. } => Signal::Closed(*stop_value),
        }
    }

    /// Initiate shutdown returning a completion future.
    /// Always returns a completion future, even if stop was already called.
    /// If stop was already called, returns the same shared completion future
    /// that will resolve immediately if already completed.
    pub fn stop(&mut self, value: i32) -> Shared<oneshot::Receiver<()>> {
        match self {
            Self::Running { signaler, .. } => {
                // Take the signaler out of the Option (it is always populated in Running)
                let sig = signaler.take().unwrap();

                // Signal shutdown and get the completion receiver
                let completion_rx = sig.signal(value);
                let shared_completion = completion_rx.shared();

                // Transition to Stopped state
                *self = Self::Stopped {
                    stop_value: value,
                    completion: shared_completion.clone(),
                };

                shared_completion
            }
            Self::Stopped { completion, .. } => {
                // Ignore the stop value (always return the first used)

                // Return existing completion (may already be resolved)
                completion.clone()
            }
        }
    }
}

impl Default for Stopper {
    fn default() -> Self {
        Self::new()
    }
}
