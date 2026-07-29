//! Tokio-backed fallback timers for unsupported native targets.

use crate::utils::Panicker;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};
use tokio::runtime::Builder;

/// No-op builder setup on targets that use Tokio timers.
pub(crate) struct Setup;

impl Setup {
    /// Creates fallback setup without worker affinity state.
    pub(crate) const fn new(_worker_threads: usize) -> Self {
        Self
    }

    /// Leaves the Tokio builder unchanged.
    pub(crate) const fn configure(&self, _builder: &mut Builder) {}
}

/// Tokio-backed timer facade for unsupported native targets.
pub(crate) struct Timer;

impl Timer {
    /// Creates a fallback service without descriptors or driver tasks.
    pub(crate) fn new(setup: Setup, _panicker: Panicker) -> Result<Self, InitError> {
        // Consuming setup keeps the facade identical to native targets without
        // retaining runtime affinity state on fallback targets.
        let _ = setup;
        Ok(Self)
    }

    /// Eagerly constructs a Tokio sleep for nonzero durations.
    pub(crate) fn sleep(&self, duration: Duration) -> Sleep {
        if duration.is_zero() {
            return Sleep { inner: None };
        }
        // Tokio fixes its monotonic deadline at construction, which preserves
        // the Clock contract even when the returned future is polled later.
        Sleep {
            inner: Some(Box::pin(tokio::time::sleep(duration))),
        }
    }

    /// Snapshots a wall-clock deadline once before constructing its sleep.
    pub(crate) fn sleep_until(&self, deadline: SystemTime) -> Sleep {
        // Wall time is read once, so later clock adjustments cannot move the
        // monotonic deadline retained by Tokio's sleep.
        let remaining = deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        self.sleep(remaining)
    }
}

/// Infallible fallback initialization error.
#[derive(Debug)]
pub(crate) enum InitError {}

impl std::fmt::Display for InitError {
    fn fmt(&self, _formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}

/// Concrete fallback future with eager Tokio sleep construction.
pub(crate) struct Sleep {
    /// Absent for immediate completion and present for a Tokio timer.
    inner: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner
            .as_mut()
            .map_or(Poll::Ready(()), |sleep| sleep.as_mut().poll(context))
    }
}

#[cfg(test)]
mod tests;
