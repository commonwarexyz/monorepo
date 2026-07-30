//! Tokio-backed fallback timers for unsupported native targets.

use crate::utils::Panicker;
use std::{
    future::Future,
    time::{Duration, SystemTime},
};
use thiserror::Error;
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
    pub(crate) fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        // Construct outside the async block so Tokio fixes the monotonic
        // deadline now, even when the returned future is polled later.
        let sleep = if duration.is_zero() {
            None
        } else {
            Some(tokio::time::sleep(duration))
        };

        async move {
            match sleep {
                Some(sleep) => sleep.await,
                None => tokio::task::coop::consume_budget().await,
            }
        }
    }

    /// Snapshots a wall-clock deadline once before constructing its sleep.
    pub(crate) fn sleep_until(
        &self,
        deadline: SystemTime,
    ) -> impl Future<Output = ()> + Send + 'static {
        // Wall time is read once, so later clock adjustments cannot move the
        // monotonic deadline retained by Tokio's sleep.
        let remaining = deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        self.sleep(remaining)
    }
}

/// Infallible fallback initialization error.
#[derive(Debug, Error)]
pub(crate) enum InitError {}

#[cfg(test)]
mod tests;
