use commonware_cryptography::PublicKey;
use commonware_runtime::Clock;
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota,
    RateLimiter,
};
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    time::SystemTime,
};

pub struct RequestManager<E: Clock + GClock, K: Hash + Eq + Clone> {
    me: PublicKey,
    runtime: E,
    rate_limiter:
        RateLimiter<PublicKey, HashMapStateStore<PublicKey>, E, NoOpMiddleware<E::Instant>>,
    sent: HashMap<K, HashMap<PublicKey, SystemTime>>,
    participants: Vec<PublicKey>,
    excluded: HashSet<PublicKey>,
}

impl<E: Clock + GClock, K: Hash + Eq + Clone> RequestManager<E, K> {
    pub fn new(runtime: E, me: PublicKey, rate_limit: Quota) -> Self {
        let rate_limiter = RateLimiter::hashmap_with_clock(rate_limit, &runtime);
        Self {
            me,
            runtime,
            rate_limiter,
            sent: HashMap::new(),
            participants: Vec::new(),
            excluded: HashSet::new(),
        }
    }

    pub fn retain(&mut self, public_keys: &[PublicKey]) {
        self.participants = public_keys.to_vec();
    }

    pub fn exclude(&mut self, public_key: PublicKey) {
        self.excluded.insert(public_key);
    }

    pub fn resolved(&mut self, key: &K, public_key: &PublicKey) {
        let Some(mut sent) = self.sent.remove(key) else {
            return;
        };
        let Some(start) = sent.remove(public_key) else {
            return;
        };
        let Ok(elapsed) = self.runtime.current().duration_since(start) else {
            return;
        };
    }

    pub fn cancel(&mut self, key: &K) {
        self.sent.remove(key);
    }

    pub fn select(&mut self, key: K) -> Option<PublicKey> {
        // Create entry if missing
        let entry = self.sent.entry(key.clone()).or_default();
        for public_key in &self.participants {
            // Check if me
            if *public_key == self.me {
                continue;
            }

            // Check if excluded
            if self.excluded.contains(public_key) {
                continue;
            }

            // Check if already sent this request
            if entry.contains_key(public_key) {
                continue;
            }

            // Check if rate limit is exceeded (and update rate limiter if not)
            if self.rate_limiter.check_key(public_key).is_err() {
                continue;
            }

            // Record request issuance time
            let now = self.runtime.current();
            entry.insert(public_key.clone(), now);
            return Some(public_key.clone());
        }

        // Reset sent requests and try again later
        self.sent.remove(&key);
        self.rate_limiter.shrink_to_fit();
        None
    }
}
