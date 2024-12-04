//! Make concurrent requests to peers limited by rate and prioritized by performance.

use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::Clock;
use commonware_utils::PrioritySet;
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota,
    RateLimiter,
};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, SystemTime},
};

/// Unique identifier for a request.
///
/// Once u64 requests have been made, the ID wraps around (resetting to zero).
/// As long as there are less than u64 requests outstanding, this should not be
/// an issue.
pub type ID = u64;

/// Configuration for `Requester`.
pub struct Config<C: Scheme> {
    /// Cryptographic primitives.
    pub crypto: C,

    /// Rate limit for requests per participant.
    pub rate_limit: Quota,

    /// Initial expected performance for new participants.
    pub initial: Duration,

    /// Timeout for requests.
    pub timeout: Duration,
}

/// Send rate-limited requests to peers prioritized by performance.
pub struct Requester<E: Clock + GClock, C: Scheme> {
    runtime: E,
    crypto: C,
    initial: Duration,
    timeout: Duration,

    rate_limiter:
        RateLimiter<PublicKey, HashMapStateStore<PublicKey>, E, NoOpMiddleware<E::Instant>>,
    participants: PrioritySet<PublicKey, u128>,
    excluded: HashSet<PublicKey>,

    id: ID,
    requests: HashMap<ID, (PublicKey, SystemTime)>,
    deadlines: PrioritySet<ID, SystemTime>,
}

impl<E: Clock + GClock, C: Scheme> Requester<E, C> {
    /// Create a new requester.
    pub fn new(runtime: E, config: Config<C>) -> Self {
        let rate_limiter = RateLimiter::hashmap_with_clock(config.rate_limit, &runtime);
        Self {
            runtime,
            crypto: config.crypto,
            initial: config.initial,
            timeout: config.timeout,

            rate_limiter,
            participants: PrioritySet::new(),
            excluded: HashSet::new(),

            id: 0,
            requests: HashMap::new(),
            deadlines: PrioritySet::new(),
        }
    }

    /// Indicate which participants can be sent requests.
    pub fn reconcile(&mut self, participants: &[PublicKey]) {
        self.participants
            .reconcile(participants, self.initial.as_millis());
        self.rate_limiter.shrink_to_fit();
    }

    /// Once a participant is added to skip, it is never removed.
    pub fn skip(&mut self, participant: PublicKey) {
        self.excluded.insert(participant);
    }

    /// Ask for a participant to handle a request.
    pub fn request(&mut self) -> Option<(PublicKey, ID)> {
        // Look for a participant that can handle request
        for (participant, _) in self.participants.iter() {
            // Check if me
            if *participant == self.crypto.public_key() {
                continue;
            }

            // Check if excluded
            if self.excluded.contains(participant) {
                continue;
            }

            // Check if rate limit is exceeded (and update rate limiter if not)
            if self.rate_limiter.check_key(participant).is_err() {
                continue;
            }

            // Compute ID
            //
            // As long as we don't have u64 requests outstanding, this is ok.
            let id = self.id;
            self.id = self.id.wrapping_add(1);

            // Record request issuance time
            let now = self.runtime.current();
            self.requests.insert(id, (participant.clone(), now));
            let deadline = now.checked_add(self.timeout).expect("time overflowed");
            self.deadlines.put(id, deadline);
            return Some((participant.clone(), id));
        }
        None
    }

    /// Resolve an outstanding request.
    pub fn resolved(&mut self, id: ID) {
        // Remove request
        let Some((participant, start)) = self.cancel(id) else {
            return;
        };

        // Get elapsed time
        let Ok(elapsed) = self.runtime.current().duration_since(start) else {
            return;
        };
        let elapsed = elapsed.as_millis();

        // Calculate new performance using exponential moving average
        let Some(past) = self.participants.get(&participant) else {
            return;
        };
        let performance = past.saturating_add(elapsed) / 2;
        self.participants.put(participant, performance);
    }

    /// Timeout an outstanding request.
    pub fn timeout(&mut self, id: ID) {
        let Some((participant, _)) = self.cancel(id) else {
            return;
        };

        // Calculate new performance using exponential moving average
        let Some(past) = self.participants.get(&participant) else {
            return;
        };
        let performance = past.saturating_add(self.timeout.as_millis()) / 2;
        self.participants.put(participant.clone(), performance);
    }

    /// Drop an outstanding request (returning the participant and start time, if exists).
    pub fn cancel(&mut self, id: ID) -> Option<(PublicKey, SystemTime)> {
        let (participant, start) = self.requests.remove(&id)?;
        self.deadlines.remove(&id);
        Some((participant, start))
    }

    /// Get the next outstanding ID and deadline.
    pub fn next(&self) -> Option<(ID, SystemTime)> {
        let (id, deadline) = self.deadlines.iter().next()?;
        Some((*id, *deadline))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Ed25519;
    use commonware_runtime::deterministic::Executor;
    use commonware_runtime::Runner;
    use governor::Quota;
    use std::num::NonZeroU32;
    use std::time::Duration;

    #[test]
    fn test_requester_basic() {
        // Instantiate runtime
        let (executor, runtime, _auditor) = Executor::seeded(0);
        executor.start(async move {
            // Create requester
            let scheme = Ed25519::from_seed(0);
            let me = scheme.public_key();
            let timeout = Duration::from_secs(5);
            let config = Config {
                crypto: scheme,
                rate_limit: Quota::per_second(NonZeroU32::new(1).unwrap()),
                initial: Duration::from_millis(100),
                timeout,
            };
            let mut requester = Requester::new(runtime.clone(), config);

            // Request before any participants
            assert_eq!(requester.request(), None);

            // Ensure we aren't waiting
            assert_eq!(requester.next(), None);

            // Initialize requester
            let other = Ed25519::from_seed(1).public_key();
            requester.reconcile(&[me, other.clone()]);

            // Get request
            let current = runtime.current();
            let (participant, id) = requester.request().expect("failed to get participant");
            assert_eq!(id, 0);
            assert_eq!(participant, other);

            // Check deadline
            let (id, deadline) = requester.next().expect("failed to get deadline");
            assert_eq!(id, 0);
            assert_eq!(deadline, current + timeout);

            // Try to make another request (would exceed rate limit and can't do self)
            assert_eq!(requester.request(), None);

            // Simulate processing time
            runtime.sleep(Duration::from_millis(10)).await;

            // Mark request as resolved
            requester.resolved(id);

            // Ensure no more requests
            assert_eq!(requester.request(), None);

            // Ensure can't make another request
            assert_eq!(requester.request(), None);

            // Wait for rate limit to reset
            runtime.sleep(Duration::from_secs(1)).await;

            // Get request
            let (participant, id) = requester.request().expect("failed to get participant");
            assert_eq!(participant, other);
            assert_eq!(id, 1);

            // Timeout request
            requester.timeout(id);

            // Ensure no more requests
            assert_eq!(requester.request(), None);

            // Sleep until reset
            runtime.sleep(Duration::from_secs(2)).await;

            // Get request
            let (participant, id) = requester.request().expect("failed to get participant");
            assert_eq!(participant, other);
            assert_eq!(id, 2);

            // Cancel request
            assert!(requester.cancel(id).is_some());

            // Ensure no more requests
            assert_eq!(requester.next(), None);
        });
    }

    #[test]
    fn test_requester_multiple() {
        // Instantiate runtime
        let (executor, runtime, _auditor) = Executor::seeded(0);
        executor.start(async move {
            // Create requester
            let scheme = Ed25519::from_seed(0);
            let me = scheme.public_key();
            let timeout = Duration::from_secs(5);
            let config = Config {
                crypto: scheme,
                rate_limit: Quota::per_second(NonZeroU32::new(1).unwrap()),
                initial: Duration::from_millis(100),
                timeout,
            };
            let mut requester = Requester::new(runtime.clone(), config);

            // Request before any participants
            assert_eq!(requester.request(), None);

            // Ensure we aren't waiting
            assert_eq!(requester.next(), None);

            // Initialize requester
            let other1 = Ed25519::from_seed(1).public_key();
            let other2 = Ed25519::from_seed(2).public_key();
            requester.reconcile(&[me.clone(), other1.clone(), other2.clone()]);

            // Get request
            let (participant, id) = requester.request().expect("failed to get participant");
            assert_eq!(id, 0);
            if participant == other2 {
                requester.timeout(id);
            } else {
                panic!("unexpected participant");
            }

            // Get request
            let (participant, id) = requester.request().expect("failed to get participant");
            assert_eq!(id, 1);
            if participant == other1 {
                runtime.sleep(Duration::from_millis(10)).await;
                requester.resolved(id);
            } else {
                panic!("unexpected participant");
            }

            // Try to make another request (would exceed rate limit and can't do self)
            assert_eq!(requester.request(), None);

            // Wait for rate limit to reset
            runtime.sleep(Duration::from_secs(1)).await;

            // Get request
            let (participant, id) = requester.request().expect("failed to get participant");
            assert_eq!(participant, other1);
            assert_eq!(id, 2);

            // Cancel request
            assert!(requester.cancel(id).is_some());

            // Add another participant
            let other3 = Ed25519::from_seed(3).public_key();
            requester.reconcile(&[me, other1.clone(), other2.clone(), other3.clone()]);

            // Get request (new should be prioritized because lower default time)
            let (participant, id) = requester.request().expect("failed to get participant");
            assert_eq!(participant, other3);
            assert_eq!(id, 3);
        });
    }
}
