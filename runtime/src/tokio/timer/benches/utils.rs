//! Shared backend adapters and coordination for timer benchmarks.

use crate::Backend;
use commonware_runtime::{Clock as _, tokio as commonware_tokio};
use commonware_utils::sync::{Condvar, Mutex};
use std::{
    future::Future,
    io,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime},
};

/// Heap-allocated sleep used to give both timer backends the same harness cost.
pub(crate) type BenchSleep = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Backend deadline forms bracketed by monotonic clock observations.
#[derive(Clone, Copy)]
pub(crate) struct DeadlinePair {
    /// Wall-clock deadline consumed by the Commonware clock.
    pub(crate) wall: SystemTime,
    /// Monotonic deadline consumed directly by Tokio.
    pub(crate) tokio: tokio::time::Instant,
    /// Exact Tokio origin or conservative Commonware lower bound.
    pub(crate) measurement_origin: Instant,
    /// Selected backend deadline used for lateness and scheduling cutoffs.
    pub(crate) measurement_deadline: Instant,
    /// Commonware wall-to-monotonic mapping uncertainty, when applicable.
    /// Backend sleep construction remains part of measured lateness.
    pub(crate) clock_pair_span: Option<Duration>,
}

impl DeadlinePair {
    /// Constructs both backend forms and retains the selected measurement pair.
    pub(crate) fn new(backend: Backend, target: Duration) -> Self {
        // The monotonic observations bracket the wall-clock snapshot. Using
        // the preceding value for Commonware prevents valid callbacks from
        // being classified early, while the span bounds mapping overstatement.
        // Later backend construction remains part of observed lateness.
        let commonware_origin = Instant::now();
        let wall_origin = SystemTime::now();
        let tokio_origin = tokio::time::Instant::now();
        let wall = wall_origin + target;
        let tokio = tokio_origin + target;
        let tokio_origin = tokio_origin.into_std();
        let (measurement_origin, measurement_deadline, clock_pair_span) = match backend {
            Backend::Commonware => (
                commonware_origin,
                commonware_origin + target,
                Some(tokio_origin.saturating_duration_since(commonware_origin)),
            ),
            Backend::Tokio => (tokio_origin, tokio.into_std(), None),
        };
        Self {
            wall,
            tokio,
            measurement_origin,
            measurement_deadline,
            clock_pair_span,
        }
    }
}

/// Constructs a relative sleep through the selected backend.
pub(crate) fn sleep_for(
    clock: &commonware_tokio::Context,
    backend: Backend,
    duration: Duration,
) -> BenchSleep {
    match backend {
        Backend::Commonware => Box::pin(clock.sleep(duration)),
        Backend::Tokio => Box::pin(tokio::time::sleep(duration)),
    }
}

/// Constructs an absolute sleep through the selected backend.
pub(crate) fn sleep_until(
    clock: &commonware_tokio::Context,
    backend: Backend,
    wall_deadline: SystemTime,
    tokio_deadline: tokio::time::Instant,
) -> BenchSleep {
    match backend {
        Backend::Commonware => Box::pin(clock.sleep_until(wall_deadline)),
        Backend::Tokio => Box::pin(tokio::time::sleep_until(tokio_deadline)),
    }
}

/// Constructs a wall-clock sleep while preserving equivalent backend work.
pub(crate) fn sleep_until_wall(
    clock: &commonware_tokio::Context,
    backend: Backend,
    wall_deadline: SystemTime,
) -> BenchSleep {
    match backend {
        Backend::Commonware => Box::pin(clock.sleep_until(wall_deadline)),
        Backend::Tokio => {
            // Mirror Commonware's wall-clock snapshot before delegating to the
            // relative Tokio sleep constructor.
            let duration = wall_deadline
                .duration_since(SystemTime::now())
                .unwrap_or_default();
            Box::pin(tokio::time::sleep(duration))
        }
    }
}

/// Polls a sleep once so lazy backends register before timing continues.
pub(crate) fn poll_once(sleep: &mut BenchSleep) -> Poll<()> {
    let waker = futures::task::noop_waker_ref();
    let mut context = Context::from_waker(waker);
    sleep.as_mut().poll(&mut context)
}

/// Tracks time between runs of the always-runnable fairness peer.
pub(crate) struct PeerGap {
    /// Most recent time the peer observed scheduling progress.
    previous_run: Instant,
    /// Largest interval observed after timer callbacks began.
    maximum: Duration,
}

impl PeerGap {
    /// Starts tracking from the peer's initialized and acknowledged state.
    pub(crate) const fn new(previous_run: Instant) -> Self {
        Self {
            previous_run,
            maximum: Duration::ZERO,
        }
    }

    /// Records one run and returns whether every callback has completed.
    pub(crate) fn observe(
        &mut self,
        now: Instant,
        callbacks_started: bool,
        callbacks_completed: bool,
    ) -> bool {
        if callbacks_started {
            self.maximum = self
                .maximum
                .max(now.saturating_duration_since(self.previous_run));
        }
        self.previous_run = now;
        callbacks_completed
    }

    /// Returns the largest scheduling gap observed after callbacks began.
    pub(crate) const fn maximum(&self) -> Duration {
        self.maximum
    }
}

/// Returns dispatch lateness while rejecting an early timer callback.
pub(crate) fn dispatch_lateness(observed: Duration, target: Duration) -> io::Result<Duration> {
    observed.checked_sub(target).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "storm timer fired before its requested deadline",
        )
    })
}

/// Cancelable coordination for dedicated cancellation producers.
pub(crate) struct ProducerGate {
    /// Protected arrival count and release decision.
    state: Mutex<ProducerState>,
    /// Wakes the coordinator or every waiting producer.
    changed: Condvar,
}

/// State protected by [`ProducerGate`].
struct ProducerState {
    /// Producers that completed registration.
    ready: usize,
    /// Whether producers should wait, cancel, or start measurement.
    release: ProducerRelease,
}

/// Coordinator decision observed by every cancellation producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProducerRelease {
    /// A producer failure requires waiting producers to discard their timers.
    Cancel,
    /// Every producer may begin cancellation.
    Start,
    /// Registration is still in progress.
    Waiting,
}

impl ProducerGate {
    /// Creates a gate with no registered producer.
    pub(crate) const fn new() -> Self {
        Self {
            state: Mutex::new(ProducerState {
                ready: 0,
                release: ProducerRelease::Waiting,
            }),
            changed: Condvar::new(),
        }
    }

    /// Registers one arrival and returns whether cancellation should start.
    pub(crate) fn arrive_and_wait(&self) -> bool {
        let mut state = self.state.lock();
        state.ready += 1;
        self.changed.notify_all();
        while state.release == ProducerRelease::Waiting {
            self.changed.wait(&mut state);
        }
        state.release == ProducerRelease::Start
    }

    /// Waits until every producer arrives or setup is canceled.
    pub(crate) fn wait_until_ready(&self, producers: usize) -> bool {
        let mut state = self.state.lock();
        while state.ready < producers && state.release == ProducerRelease::Waiting {
            self.changed.wait(&mut state);
        }
        state.ready == producers && state.release != ProducerRelease::Cancel
    }

    /// Releases producers unless setup was already canceled.
    pub(crate) fn start(&self) {
        self.release(ProducerRelease::Start);
    }

    /// Dominates any prior decision and releases producers without measurement.
    ///
    /// Replacing `Start` records that an already-released producer panicked.
    /// Producers that left the gate continue and expose the panic through join.
    pub(crate) fn cancel(&self) {
        self.release(ProducerRelease::Cancel);
    }

    /// Cancels waiting producers before resuming a producer panic.
    pub(crate) fn cancel_on_unwind<T>(&self, work: impl FnOnce() -> T) -> T {
        match catch_unwind(AssertUnwindSafe(work)) {
            Ok(output) => output,
            Err(payload) => {
                self.cancel();
                resume_unwind(payload);
            }
        }
    }

    /// Publishes one decision while preserving cancellation dominance.
    fn release(&self, release: ProducerRelease) {
        let mut state = self.state.lock();
        if release == ProducerRelease::Cancel || state.release == ProducerRelease::Waiting {
            state.release = release;
        }
        self.changed.notify_all();
    }
}
