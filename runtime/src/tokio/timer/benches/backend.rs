//! Equivalent sleep construction for benchmarked timer backends.

use crate::Backend;
use commonware_runtime::{Clock as _, tokio as commonware_tokio};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

/// Heap-allocated sleep used to give both timer backends the same harness cost.
pub(crate) type BenchSleep = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

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
