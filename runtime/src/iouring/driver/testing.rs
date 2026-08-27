//! A single-threaded harness for tests that drive the loop
//! directly (loop, network, and storage unit tests).

use super::*;
use crate::telemetry::metrics::Registry;
use futures::task::{ArcWake, waker as arc_waker};
use std::{
    future::Future,
    pin::{Pin, pin},
    sync::Arc,
    task::{Context, Poll},
};

/// Task waker that latches the loop's out-of-band wake, mirroring how the
/// runtime executor's task wakers unpark the loop.
pub(crate) struct Unpark(Waker);

impl ArcWake for Unpark {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.0.wake();
    }
}

/// Single-threaded loop harness driving `turn`/`park` interleaved with
/// polling a future, mirroring the runtime executor's structure.
pub(crate) struct TestLoop {
    pub(crate) handle: Handle,
    /// The owned driver, taken by [TestLoop::shutdown] (drain consumes it).
    driver: Option<Driver>,
}

impl TestLoop {
    /// Create a loop harness with a 60-second timeout horizon.
    pub(crate) fn new(cfg: RingConfig) -> Self {
        Self::new_with_max_request_timeout(cfg, Duration::from_secs(60))
    }

    /// Create a loop harness with the provided timeout horizon.
    pub(crate) fn new_with_max_request_timeout(
        cfg: RingConfig,
        max_request_timeout: Duration,
    ) -> Self {
        let mut registry = Registry::default();
        let (driver, handle) = Driver::new(cfg, max_request_timeout, &mut registry)
            .expect("unable to create io_uring instance");
        Self {
            handle,
            driver: Some(driver),
        }
    }

    /// Access the owned driver.
    ///
    /// Panics after [TestLoop::shutdown].
    pub(crate) fn driver(&mut self) -> &mut Driver {
        self.driver.as_mut().expect("driver already drained")
    }

    /// Build a waker that latches the loop's out-of-band wake, or a noop
    /// waker once the driver is drained (parked results resolve without
    /// one).
    fn waker(&self) -> std::task::Waker {
        self.driver
            .as_ref()
            .map_or_else(futures::task::noop_waker, |driver| {
                arc_waker(Arc::new(Unpark(driver.waker())))
            })
    }

    /// Drive `fut` to completion, servicing the ring between polls.
    pub(crate) fn block_on<F: Future>(&mut self, fut: F) -> F::Output {
        let waker = self.waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = pin!(fut);
        loop {
            if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
                return output;
            }
            let driver = self.driver.as_mut().expect("future pending after shutdown");
            driver.turn();
            driver.park(None);
        }
    }

    /// Close the driver and drain in-flight work, as runtime teardown does.
    pub(crate) fn shutdown(&mut self) {
        let Some(driver) = self.driver.take() else {
            return;
        };
        // Mirror the runtime's teardown: a waker panic must not skip the
        // drain (drain panics abort inside [Driver::drain]).
        let wakers = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| driver.close()));
        driver.drain();
        if let Err(payload) = wakers {
            std::panic::resume_unwind(payload);
        }
    }

    /// Number of tracked logical operations, including Ready tickets.
    pub(crate) fn tracked(&self) -> usize {
        self.handle.with(|ops| ops.operation_count())
    }

    /// Number of waiters still progressing.
    pub(crate) fn pending(&self) -> usize {
        self.handle.with(|ops| ops.waiters.pending())
    }
}

impl Drop for TestLoop {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Poll `fut` exactly once with a loop-latching waker.
pub(crate) fn poll_once<F: Future + Unpin>(harness: &TestLoop, fut: &mut F) -> Poll<F::Output> {
    let waker = harness.waker();
    let mut cx = Context::from_waker(&waker);
    Pin::new(fut).poll(&mut cx)
}
