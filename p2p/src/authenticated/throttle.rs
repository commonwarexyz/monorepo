//! Per-connection rate limiting and metrics for inbound messages.

use commonware_runtime::{
    Clock, RateLimiter,
    telemetry::metrics::{CounterFamily, raw::Counter},
};
use std::hash::Hash;

/// Rate limiter and counters for one inbound message type on one connection.
pub(crate) struct Throttle<E: Clock> {
    rate_limiter: RateLimiter<E>,
    received: Counter,
    rate_limited: Counter,
}

impl<E: Clock> Throttle<E> {
    pub(crate) fn new<L: Clone + Hash + Eq>(
        rate_limiter: RateLimiter<E>,
        received: &CounterFamily<L>,
        rate_limited: &CounterFamily<L>,
        label: &L,
    ) -> Self {
        Self {
            rate_limiter,
            received: received.get_or_create_owned(label),
            rate_limited: rate_limited.get_or_create_owned(label),
        }
    }

    /// Records a received message and, if `limit` is set, waits out any rate limit.
    pub(crate) async fn receive(&self, context: &E, limit: bool) {
        self.received.inc();
        if limit && let Err(wait_until) = self.rate_limiter.check() {
            self.rate_limited.inc();
            let wait_duration = wait_until.wait_time_from(context.now());
            context.sleep(wait_duration).await;
        }
    }
}
