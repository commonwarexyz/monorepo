//! Requester for sending rate-limited requests to peers.

use super::{Config, PeerLabel};
use commonware_cryptography::PublicKey;
use commonware_runtime::{
    telemetry::metrics::status::{CounterExt, GaugeExt, Status},
    Clock, Metrics, RateLimiter,
};
use commonware_utils::PrioritySet;
use either::Either;
use governor::clock::Clock as GClock;
use rand::{seq::SliceRandom, Rng};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, SystemTime},
};
use thiserror::Error;

/// Unique identifier for a request.
///
/// Once u64 requests have been made, the ID wraps around (resetting to zero).
/// As long as there are less than u64 requests outstanding, this should not be
/// an issue.
pub type ID = u64;

/// Error returned when a request cannot be made.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    /// No eligible participants exist (all blocked, excluded, filtered out, or none registered).
    #[error("no eligible participants")]
    NoEligibleParticipants,
    /// Participants exist but are rate-limited. Retry after this duration.
    #[error("rate limited, retry after {0:?}")]
    RateLimited(Duration),
}

/// Send rate-limited requests to peers prioritized by performance.
///
/// Requester attempts to saturate the bandwidth (inferred by rate limit)
/// of the most performant peers (based on our latency observations). To encourage
/// exploration, set the value of `initial` to less than the expected latency of
/// performant peers and/or periodically set `shuffle` in `request`.
pub struct Requester<E: Clock + GClock + Rng + Metrics, P: PublicKey> {
    context: E,
    me: Option<P>,
    metrics: super::Metrics,
    initial: Duration,
    timeout: Duration,

    // Participants to exclude from requests
    excluded: HashSet<P>,

    // Rate limiter for participants
    rate_limiter: RateLimiter<P, E>,
    // Participants and their performance (lower is better)
    participants: PrioritySet<P, u128>,

    // Next ID to use for a request
    id: ID,
    // Outstanding requests (ID -> (participant, start time))
    requests: HashMap<ID, (P, SystemTime)>,
    // Deadlines for outstanding requests (ID -> deadline)
    deadlines: PrioritySet<ID, SystemTime>,
}

/// Request responded from handling an ID.
///
/// When handling a request, the requester will remove the request and return
/// this struct in case we want to `resolve` or `timeout` the request. This approach
/// makes it impossible to forget to remove a handled request if it doesn't warrant
/// updating the performance of the participant.
pub struct Request<P: PublicKey> {
    /// Unique identifier for the request.
    pub id: ID,

    /// Participant that handled the request.
    pub participant: P,

    /// Time the request was issued.
    start: SystemTime,
}

impl<E: Clock + GClock + Rng + Metrics, P: PublicKey> Requester<E, P> {
    /// Create a new requester.
    pub fn new(context: E, config: Config<P>) -> Self {
        let rate_limiter = RateLimiter::hashmap_with_clock(config.rate_limit, context.clone());

        // TODO(#1833): Metrics should use embedded context
        let metrics = super::Metrics::init(context.clone());
        Self {
            context,
            me: config.me,
            metrics,
            initial: config.initial,
            timeout: config.timeout,

            excluded: HashSet::new(),

            rate_limiter,
            participants: PrioritySet::new(),

            id: 0,
            requests: HashMap::new(),
            deadlines: PrioritySet::new(),
        }
    }

    /// Indicate which participants can be sent requests.
    pub fn reconcile(&mut self, participants: &[P]) {
        self.participants
            .reconcile(participants, self.initial.as_millis());
        self.rate_limiter.shrink_to_fit();
    }

    /// Skip a participant for future requests.
    ///
    /// Participants added to this list will never be removed (even if dropped
    /// during `reconcile`, in case they are re-added later).
    pub fn block(&mut self, participant: P) {
        self.excluded.insert(participant);
    }

    /// Ask for a participant to handle a request.
    ///
    /// If `shuffle` is true, the order of participants is shuffled before
    /// a request is made. This is typically used when a request to the preferred
    /// participant fails.
    ///
    /// Returns `Ok((participant, id))` if a request can be made, or an error if
    /// no peers are eligible or all eligible peers are rate-limited.
    pub fn request(&mut self, shuffle: bool) -> Result<(P, ID), Error> {
        self.request_inner(shuffle, None::<fn(&P) -> bool>)
    }

    /// Ask for a participant to handle a request, filtered by a predicate.
    ///
    /// If `shuffle` is true, the order of participants is shuffled before
    /// a request is made. This is typically used when a request to the preferred
    /// participant fails.
    ///
    /// Only participants for which `filter` returns `true` will be considered.
    /// This is useful when the caller knows which specific peers have the data.
    ///
    /// Returns `Ok((participant, id))` if a request can be made, or an error if
    /// no peers are eligible or all eligible peers are rate-limited.
    pub fn request_filtered(
        &mut self,
        shuffle: bool,
        filter: impl Fn(&P) -> bool,
    ) -> Result<(P, ID), Error> {
        self.request_inner(shuffle, Some(filter))
    }

    fn request_inner(
        &mut self,
        shuffle: bool,
        filter: Option<impl Fn(&P) -> bool>,
    ) -> Result<(P, ID), Error> {
        // Prepare participant iterator
        let participant_iter = if shuffle {
            let mut participants = self.participants.iter().collect::<Vec<_>>();
            participants.shuffle(&mut self.context);
            Either::Left(participants.into_iter())
        } else {
            Either::Right(self.participants.iter())
        };

        // Look for a participant that can handle request
        let mut next = None;
        for (participant, _) in participant_iter {
            // Check if me
            if Some(participant) == self.me.as_ref() {
                continue;
            }

            // Check if excluded
            if self.excluded.contains(participant) {
                continue;
            }

            // Check if passes filter (if provided)
            if let Some(ref filter) = filter {
                if !filter(participant) {
                    continue;
                }
            }

            // Check if rate limit is exceeded (and update rate limiter if not)
            if let Err(limit) = self.rate_limiter.check_key(participant) {
                next = Some(limit.wait_time_from(self.context.now()));
                continue;
            }

            // Compute ID
            let id = self.id;
            self.id = self.id.wrapping_add(1);

            // Record request issuance time
            let now = self.context.current();
            self.requests.insert(id, (participant.clone(), now));
            let deadline = now.checked_add(self.timeout).expect("time overflowed");
            self.deadlines.put(id, deadline);

            // Increment metric if-and-only-if request is successful
            self.metrics.created.inc(Status::Success);
            return Ok((participant.clone(), id));
        }

        // Increment failed metric if no participants are available
        self.metrics.created.inc(Status::Failure);

        next.map_or_else(
            || Err(Error::NoEligibleParticipants),
            |wait| Err(Error::RateLimited(wait)),
        )
    }

    /// Calculate a participant's new priority using exponential moving average.
    fn update(&mut self, participant: P, elapsed: Duration) {
        let Some(past) = self.participants.get(&participant) else {
            return;
        };
        let next = past.saturating_add(elapsed.as_millis()) / 2;
        let _ = self
            .metrics
            .performance
            .get_or_create(&PeerLabel::from(&participant))
            .try_set(next);
        self.participants.put(participant, next);
    }

    /// Drop an outstanding request regardless of who it was intended for.
    pub fn cancel(&mut self, id: ID) -> Option<Request<P>> {
        let (participant, start) = self.requests.remove(&id)?;
        self.deadlines.remove(&id);
        Some(Request {
            id,
            participant,
            start,
        })
    }

    /// Handle a request by ID, ensuring the provided `participant` was
    /// associated with said ID.
    ///
    /// If the request was outstanding, a `Request` is returned that can
    /// either be resolved or timed out.
    pub fn handle(&mut self, participant: &P, id: ID) -> Option<Request<P>> {
        // Confirm ID exists and is for the participant
        let (expected, _) = self.requests.get(&id)?;
        if expected != participant {
            return None;
        }

        // If expected, remove
        self.cancel(id)
    }

    /// Resolve an outstanding request.
    pub fn resolve(&mut self, request: Request<P>) {
        // Get elapsed time
        //
        // If we can't compute the elapsed time for some reason (i.e. current time does
        // not monotonically increase), we should still credit the participant for a
        // timely response.
        let elapsed = self
            .context
            .current()
            .duration_since(request.start)
            .unwrap_or_default();

        // Update performance
        self.update(request.participant, elapsed);
        self.metrics.requests.inc(Status::Success);
        self.metrics.resolves.observe(elapsed.as_secs_f64());
    }

    /// Timeout an outstanding request.
    pub fn timeout(&mut self, request: Request<P>) {
        self.update(request.participant, self.timeout);
        self.metrics.requests.inc(Status::Timeout);
    }

    /// Fail an outstanding request and penalize the request
    /// participant with the timeout duration.
    ///
    /// This is used when we fail to send a request to a participant.
    pub fn fail(&mut self, request: Request<P>) {
        self.update(request.participant, self.timeout);
        self.metrics.requests.inc(Status::Failure);
    }

    /// Get the next outstanding ID and deadline.
    pub fn next(&self) -> Option<(ID, SystemTime)> {
        let (id, deadline) = self.deadlines.peek()?;
        Some((*id, *deadline))
    }

    /// Get the number of outstanding requests.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Get the number of blocked participants.
    pub fn len_blocked(&self) -> usize {
        self.excluded.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{ed25519::PrivateKey, PrivateKeyExt as _, Signer as _};
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::NZU32;
    use governor::Quota;
    use std::time::Duration;

    #[test]
    fn test_requester_basic() {
        // Instantiate context
        let executor = deterministic::Runner::seeded(0);
        executor.start(|context| async move {
            // Create requester
            let scheme = PrivateKey::from_seed(0);
            let me = scheme.public_key();
            let timeout = Duration::from_secs(5);
            let config = Config {
                me: Some(scheme.public_key()),
                rate_limit: Quota::per_second(NZU32!(1)),
                initial: Duration::from_millis(100),
                timeout,
            };
            let mut requester = Requester::new(context.clone(), config);

            // Request before any participants
            assert_eq!(requester.request(false), Err(Error::NoEligibleParticipants));
            assert_eq!(requester.len(), 0);

            // Ensure we aren't waiting
            assert_eq!(requester.next(), None);

            // Handle non-existent request
            assert!(requester.handle(&me, 0).is_none());

            // Initialize requester
            let other = PrivateKey::from_seed(1).public_key();
            requester.reconcile(&[me.clone(), other.clone()]);

            // Get request
            let current = context.current();
            let (participant, id) = requester.request(false).expect("failed to get participant");
            assert_eq!(id, 0);
            assert_eq!(participant, other);

            // Check deadline
            let (id, deadline) = requester.next().expect("failed to get deadline");
            assert_eq!(id, 0);
            assert_eq!(deadline, current + timeout);
            assert_eq!(requester.len(), 1);

            // Try to make another request (would exceed rate limit and can't do self)
            assert_eq!(
                requester.request(false),
                Err(Error::RateLimited(Duration::from_secs(1)))
            );

            // Simulate processing time
            context.sleep(Duration::from_millis(10)).await;

            // Mark request as resolved with wrong participant
            assert!(requester.handle(&me, id).is_none());

            // Mark request as resolved
            let request = requester
                .handle(&participant, id)
                .expect("failed to get request");
            assert_eq!(request.id, id);
            requester.resolve(request);

            // Ensure no more requests
            assert_eq!(
                requester.request(false),
                Err(Error::RateLimited(Duration::from_millis(990)))
            );

            // Ensure can't make another request
            assert_eq!(
                requester.request(false),
                Err(Error::RateLimited(Duration::from_millis(990)))
            );

            // Wait for rate limit to reset
            context.sleep(Duration::from_secs(1)).await;

            // Get request
            let (participant, id) = requester.request(false).expect("failed to get participant");
            assert_eq!(participant, other);
            assert_eq!(id, 1);

            // Timeout request
            let request = requester
                .handle(&participant, id)
                .expect("failed to get request");
            requester.timeout(request);

            // Ensure no more requests
            assert_eq!(
                requester.request(false),
                Err(Error::RateLimited(Duration::from_secs(1)))
            );

            // Sleep until reset
            context.sleep(Duration::from_secs(1)).await;

            // Get request
            let (participant, id) = requester.request(false).expect("failed to get participant");
            assert_eq!(participant, other);
            assert_eq!(id, 2);

            // Cancel request
            assert!(requester.cancel(id).is_some());

            // Ensure no more requests
            assert_eq!(requester.next(), None);
            assert_eq!(requester.len(), 0);

            // Sleep until reset
            context.sleep(Duration::from_secs(1)).await;

            // Block participant
            requester.block(other);

            // Get request
            assert_eq!(requester.request(false), Err(Error::NoEligibleParticipants));
        });
    }

    #[test]
    fn test_requester_multiple() {
        // Instantiate context
        let executor = deterministic::Runner::seeded(0);
        executor.start(|context| async move {
            // Create requester
            let scheme = PrivateKey::from_seed(0);
            let me = scheme.public_key();
            let timeout = Duration::from_secs(5);
            let config = Config {
                me: Some(scheme.public_key()),
                rate_limit: Quota::per_second(NZU32!(1)),
                initial: Duration::from_millis(100),
                timeout,
            };
            let mut requester = Requester::new(context.clone(), config);

            // Request before any participants
            assert_eq!(requester.request(false), Err(Error::NoEligibleParticipants));

            // Ensure we aren't waiting
            assert_eq!(requester.next(), None);

            // Initialize requester
            let other1 = PrivateKey::from_seed(1).public_key();
            let other2 = PrivateKey::from_seed(2).public_key();
            requester.reconcile(&[me.clone(), other1.clone(), other2.clone()]);

            // Get request
            let (participant, id) = requester.request(false).expect("failed to get participant");
            assert_eq!(id, 0);
            if participant == other1 {
                let request = requester
                    .handle(&participant, id)
                    .expect("failed to get request");
                requester.timeout(request);
            } else {
                panic!("unexpected participant");
            }

            // Get request
            let (participant, id) = requester.request(false).expect("failed to get participant");
            assert_eq!(id, 1);
            if participant == other2 {
                context.sleep(Duration::from_millis(10)).await;
                let request = requester
                    .handle(&participant, id)
                    .expect("failed to get request");
                requester.resolve(request);
            } else {
                panic!("unexpected participant");
            }

            // Try to make another request (would exceed rate limit and can't do self)
            assert_eq!(
                requester.request(false),
                Err(Error::RateLimited(Duration::from_millis(990)))
            );

            // Wait for rate limit to reset
            context.sleep(Duration::from_secs(1)).await;

            // Get request
            let (participant, id) = requester.request(false).expect("failed to get participant");
            assert_eq!(participant, other2);
            assert_eq!(id, 2);

            // Cancel request
            assert!(requester.cancel(id).is_some());

            // Add another participant
            let other3 = PrivateKey::from_seed(3).public_key();
            requester.reconcile(&[me, other1, other2.clone(), other3.clone()]);

            // Get request (new should be prioritized because lower default time)
            let (participant, id) = requester.request(false).expect("failed to get participant");
            assert_eq!(participant, other3);
            assert_eq!(id, 3);

            // Wait until eventually get slower participant
            context.sleep(Duration::from_secs(1)).await;
            loop {
                // Shuffle participants
                let (participant, _) = requester.request(true).unwrap();
                if participant == other2 {
                    break;
                }

                // Sleep until reset
                context.sleep(Duration::from_secs(1)).await;
            }
        });
    }

    #[test]
    fn test_requester_filter() {
        let executor = deterministic::Runner::seeded(0);
        executor.start(|context| async move {
            // Create requester
            let scheme = PrivateKey::from_seed(0);
            let me = scheme.public_key();
            let config = Config {
                me: Some(me.clone()),
                rate_limit: Quota::per_second(NZU32!(10)),
                initial: Duration::from_millis(100),
                timeout: Duration::from_secs(5),
            };
            let mut requester = Requester::new(context.clone(), config);

            // Add participants
            let other1 = PrivateKey::from_seed(1).public_key();
            let other2 = PrivateKey::from_seed(2).public_key();
            let other3 = PrivateKey::from_seed(3).public_key();
            requester.reconcile(&[me.clone(), other1.clone(), other2.clone(), other3.clone()]);

            // Filter restricts to specified participants
            let allowed = HashSet::from([other2.clone()]);
            let (participant, _) = requester
                .request_filtered(false, |p| allowed.contains(p))
                .unwrap();
            assert_eq!(participant, other2);

            // Wait for rate limit reset
            context.sleep(Duration::from_secs(1)).await;

            // Filter with multiple participants
            let allowed = HashSet::from([other1.clone(), other3.clone()]);
            let (participant, _) = requester
                .request_filtered(false, |p| allowed.contains(p))
                .unwrap();
            assert!(participant != other2);

            // Wait for rate limit reset
            context.sleep(Duration::from_secs(1)).await;

            // Filter that rejects all returns error
            assert_eq!(
                requester.request_filtered(false, |_| false),
                Err(Error::NoEligibleParticipants)
            );

            // Filter with non-existent participant returns error
            let unknown = PrivateKey::from_seed(99).public_key();
            assert_eq!(
                requester.request_filtered(false, |p| *p == unknown),
                Err(Error::NoEligibleParticipants)
            );

            // Filter combined with blocked (excluded) set
            requester.block(other1.clone());
            let allowed = HashSet::from([other1.clone(), other2.clone()]);
            let (participant, _) = requester
                .request_filtered(false, |p| allowed.contains(p))
                .unwrap();
            assert_eq!(participant, other2); // other1 is excluded

            // Wait for rate limit reset
            context.sleep(Duration::from_secs(1)).await;

            // Filter with self returns error (self is skipped)
            assert_eq!(
                requester.request_filtered(false, |p| *p == me),
                Err(Error::NoEligibleParticipants)
            );

            // Rate-limited filtered participant returns RateLimited, not NoEligibleParticipants
            // (this distinction is important for callers to decide wait vs fallback)
            // Exhaust the rate limit (10 per second) for other2
            for _ in 0..10 {
                requester.request_filtered(false, |p| *p == other2).unwrap();
            }
            // Now other2 is rate-limited, should get RateLimited
            let result = requester.request_filtered(false, |p| *p == other2);
            assert!(matches!(result, Err(Error::RateLimited(_))));

            // Wait for rate limit reset
            context.sleep(Duration::from_secs(1)).await;

            // Shuffle with filter produces variety while respecting filter
            let allowed = HashSet::from([other2.clone(), other3.clone()]);
            let mut seen = HashSet::new();
            for _ in 0..20 {
                context.sleep(Duration::from_secs(1)).await;
                let (participant, _) = requester
                    .request_filtered(true, |p| allowed.contains(p))
                    .unwrap();
                assert!(allowed.contains(&participant));
                seen.insert(participant);
            }
            assert_eq!(seen.len(), 2);
        });
    }
}
