use commonware_cryptography::{PublicKey, Scheme};
use commonware_runtime::Clock;
use commonware_utils::PriorityQueue;
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota,
    RateLimiter,
};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    time::{Duration, SystemTime},
};

pub struct Config<C: Scheme> {
    pub crypto: C,
    pub rate_limit: Quota,
    pub initial: Duration,
    pub timeout: Duration,
}

pub struct RequestManager<E: Clock + GClock, C: Scheme, K: Hash + Eq + Clone> {
    runtime: E,
    crypto: C,
    initial: Duration,
    timeout: Duration,

    rate_limiter:
        RateLimiter<PublicKey, HashMapStateStore<PublicKey>, E, NoOpMiddleware<E::Instant>>,
    sent: HashMap<K, HashMap<PublicKey, SystemTime>>,
    participants: PriorityQueue<PublicKey, u128>,
    excluded: HashSet<PublicKey>,
}

impl<E: Clock + GClock, C: Scheme, K: Hash + Eq + Clone> RequestManager<E, C, K> {
    // TODO: track timeouts centrally to allow concurrent requests (track by key and participant)
    // TODO: how to handle "batch requests" (don't have a single key nor can they always be broken up...ex: give me block hash + 10 parents)
    pub fn new(runtime: E, config: Config<C>) -> Self {
        let rate_limiter = RateLimiter::hashmap_with_clock(config.rate_limit, &runtime);
        Self {
            runtime,
            crypto: config.crypto,
            initial: config.initial,
            timeout: config.timeout,

            rate_limiter,
            sent: HashMap::new(),
            participants: PriorityQueue::new(),
            excluded: HashSet::new(),
        }
    }

    pub fn retain(&mut self, participants: &[PublicKey]) {
        self.participants
            .retain(participants, self.initial.as_millis());
    }

    /// Once a participant is added to skip, it is never removed.
    pub fn skip(&mut self, participant: PublicKey) {
        self.excluded.insert(participant);
    }

    pub fn resolved(&mut self, key: &K, participant: &PublicKey) {
        // Get start time
        let Some(mut sent) = self.sent.remove(key) else {
            return;
        };
        let Some(start) = sent.remove(participant) else {
            return;
        };
        let Ok(elapsed) = self.runtime.current().duration_since(start) else {
            return;
        };
        let elapsed = elapsed.as_millis();

        // Calculate new performance using exponential moving average
        let Some(past) = self.participants.get(participant) else {
            return;
        };
        let performance = (past + elapsed) / 2;
        self.participants.put(participant.clone(), performance);
    }

    pub fn timeout(&mut self, participant: &PublicKey) {
        // Calculate new performance using exponential moving average
        let Some(past) = self.participants.get(participant) else {
            return;
        };
        let performance = (past + self.timeout.as_millis()) / 2;
        self.participants.put(participant.clone(), performance);
    }

    pub fn cancel(&mut self, key: &K) {
        self.sent.remove(key);
    }

    pub fn next(&mut self, key: K) -> Option<(PublicKey, SystemTime)> {
        // Create entry if missing
        let entry = self.sent.entry(key.clone()).or_default();
        for (participant, _) in self.participants.iter() {
            // Check if me
            if *participant == self.crypto.public_key() {
                continue;
            }

            // Check if excluded
            if self.excluded.contains(participant) {
                continue;
            }

            // Check if already sent this request
            if entry.contains_key(participant) {
                continue;
            }

            // Check if rate limit is exceeded (and update rate limiter if not)
            if self.rate_limiter.check_key(participant).is_err() {
                continue;
            }

            // Record request issuance time
            let now = self.runtime.current();
            entry.insert(participant.clone(), now);
            let deadline = now.checked_add(self.timeout).expect("time overflowed");
            return Some((participant.clone(), deadline));
        }

        // Reset sent requests and try again later
        self.sent.remove(&key);
        self.rate_limiter.shrink_to_fit();
        None
    }
}
