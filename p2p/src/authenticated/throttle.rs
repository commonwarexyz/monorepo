//! Per-connection rate limiting and metrics for inbound messages.

use commonware_runtime::{
    Clock, RateLimiter,
    telemetry::metrics::{CounterFamily, raw::Counter},
};
use std::hash::Hash;

/// Rate limiter and counters for one inbound message type on one connection.
pub(crate) struct Throttle<E: Clock> {
    limiter: RateLimiter<E>,
    received: Counter,
    limited: Counter,
}

impl<E: Clock> Throttle<E> {
    pub(crate) fn new<L: Clone + Hash + Eq>(
        limiter: RateLimiter<E>,
        received: &CounterFamily<L>,
        limited: &CounterFamily<L>,
        label: &L,
    ) -> Self {
        Self {
            limiter,
            received: received.get_or_create_owned(label),
            limited: limited.get_or_create_owned(label),
        }
    }

    /// Records a received message and, if `limit` is set, waits until the rate limiter
    /// admits it.
    pub(crate) async fn receive(&self, limit: bool) {
        self.received.inc();
        if !limit || self.limiter.check().is_ok() {
            return;
        }
        self.limited.inc();

        // A rejected check does not consume a cell, so wait until one is taken
        let clock = self.limiter.clock();
        while let Err(not_until) = self.limiter.check() {
            clock.sleep_until(not_until.earliest_possible()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        Quota, Runner as _, Supervisor as _, deterministic, telemetry::metrics::MetricsExt as _,
    };
    use commonware_utils::NZU32;
    use std::time::Duration;

    type Label = [(&'static str, &'static str); 1];
    const LABEL: Label = [("message", "data_0")];

    #[test]
    fn test_receive() {
        deterministic::Runner::default().start(|context| async move {
            let received: CounterFamily<Label> = context.family("received", "received");
            let limited: CounterFamily<Label> = context.family("limited", "limited");
            let quota = Quota::per_second(NZU32!(1));
            let limiter = RateLimiter::direct_with_clock(quota, context.child("limiter"));
            let throttle = Throttle::new(limiter, &received, &limited, &LABEL);
            let count = |family: &CounterFamily<Label>| family.get(&LABEL).unwrap().get();

            // Both series exist at zero before any message
            assert_eq!(count(&received), 0);
            assert_eq!(count(&limited), 0);

            // The first limited message consumes the burst without waiting
            let start = context.current();
            throttle.receive(true).await;
            assert_eq!(context.current(), start);

            // An unlimited message skips the exhausted limiter
            throttle.receive(false).await;
            assert_eq!(context.current(), start);
            assert_eq!(count(&limited), 0);

            // A limited message over quota is counted and waits for the next cell
            throttle.receive(true).await;
            assert_eq!(context.current(), start + Duration::from_secs(1));
            assert_eq!(count(&received), 3);
            assert_eq!(count(&limited), 1);
        });
    }

    #[test]
    fn test_receive_flood_admits_quota() {
        deterministic::Runner::default().start(|context| async move {
            let received: CounterFamily<Label> = context.family("received", "received");
            let limited: CounterFamily<Label> = context.family("limited", "limited");
            let quota = Quota::per_second(NZU32!(1));
            let limiter = RateLimiter::direct_with_clock(quota, context.child("limiter"));
            let throttle = Throttle::new(limiter, &received, &limited, &LABEL);

            // Each delayed message takes its own cell, so a flood is admitted one per period
            let start = context.current();
            for i in 0..5 {
                throttle.receive(true).await;
                assert_eq!(context.current(), start + Duration::from_secs(i));
            }
            assert_eq!(received.get(&LABEL).unwrap().get(), 5);
            assert_eq!(limited.get(&LABEL).unwrap().get(), 4);
        });
    }
}
