//! Make concurrent requests to peers limited by rate and prioritized by performance.

use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::Clock;
use commonware_utils::PriorityQueue;
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota,
    RateLimiter,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
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
    pub crypto: C,
    pub rate_limit: Quota,
    pub initial: Duration,
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
    participants: PriorityQueue<PublicKey, u128>,
    excluded: HashSet<PublicKey>,

    id: ID,
    requests: HashMap<ID, (PublicKey, SystemTime)>,
    deadlines: BTreeMap<SystemTime, BTreeSet<ID>>,
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
            participants: PriorityQueue::new(),
            excluded: HashSet::new(),

            id: 0,
            requests: HashMap::new(),
            deadlines: BTreeMap::new(),
        }
    }

    /// Update the participants that can handle requests.
    pub fn update(&mut self, participants: &[PublicKey]) {
        self.participants
            .retain(participants, self.initial.as_millis());
        self.rate_limiter.shrink_to_fit();
    }

    /// Once a participant is added to skip, it is never removed.
    pub fn skip(&mut self, participant: PublicKey) {
        self.excluded.insert(participant);
    }

    /// Remove an outstanding request.
    fn remove(&mut self, id: ID) -> Option<(PublicKey, SystemTime)> {
        let (participant, start) = self.requests.remove(&id)?;
        self.deadlines.get_mut(&start).map(|ids| ids.remove(&id));
        Some((participant, start))
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
            let deadline = now.checked_add(self.timeout).expect("time overflowed");
            self.requests.insert(id, (participant.clone(), now));
            self.deadlines.entry(deadline).or_default().insert(id);
            return Some((participant.clone(), id));
        }
        None
    }

    /// Resolve an outstanding request.
    pub fn resolved(&mut self, id: ID) {
        // Remove request
        let Some((participant, start)) = self.remove(id) else {
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
        let performance = past / 2 + elapsed / 2;
        self.participants.put(participant, performance);
    }

    /// Timeout an outstanding request.
    pub fn timeout(&mut self, id: ID) {
        let Some((participant, _)) = self.remove(id) else {
            return;
        };

        // Calculate new performance using exponential moving average
        let Some(past) = self.participants.get(&participant) else {
            return;
        };
        let performance = past / 2 + self.timeout.as_millis() / 2;
        self.participants.put(participant.clone(), performance);
    }

    /// Cancel an outstanding request.
    pub fn cancel(&mut self, id: ID) {
        self.remove(id);
    }

    /// Get the next outstanding deadline and ID.
    pub fn next(&self) -> Option<(SystemTime, ID)> {
        let (deadline, ids) = self.deadlines.first_key_value()?;
        let id = *ids.first().unwrap();
        Some((*deadline, id))
    }
}
