//! Equivalent sleep construction for benchmarked timer backends.

use crate::Backend;
use commonware_runtime::{Clock as _, tokio as commonware_tokio};
use std::{
    future::Future,
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
