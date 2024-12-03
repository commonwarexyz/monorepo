use std::collections::HashSet;

use commonware_cryptography::PublicKey;
use governor::{
    clock::Clock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota, RateLimiter,
};

pub struct RequestManager<E: Clock> {
    me: PublicKey,
    rate_limiter:
        RateLimiter<PublicKey, HashMapStateStore<PublicKey>, E, NoOpMiddleware<E::Instant>>,
    sent: HashSet<PublicKey>,
    participants: Vec<PublicKey>,
    excluded: HashSet<PublicKey>,
}

impl<E: Clock> RequestManager<E> {
    pub fn new(runtime: E, me: PublicKey, rate_limit: Quota) -> Self {
        let rate_limiter = RateLimiter::hashmap_with_clock(rate_limit, &runtime);
        Self {
            me,
            rate_limiter,
            sent: HashSet::new(),
            participants: Vec::new(),
            excluded: HashSet::new(),
        }
    }

    pub fn reset(&mut self) {
        self.rate_limiter.shrink_to_fit();
        self.sent.clear();
    }

    pub fn retain(&mut self, public_keys: &[PublicKey]) {
        self.participants = public_keys.to_vec();
    }

    pub fn exclude(&mut self, public_key: PublicKey) {
        self.excluded.insert(public_key);
    }

    pub fn select(&mut self) -> Option<PublicKey> {
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
            if self.sent.contains(public_key) {
                continue;
            }

            // Check if rate limit is exceeded (and update rate limiter if not)
            if self.rate_limiter.check_key(public_key).is_err() {
                continue;
            }
            self.sent.insert(public_key.clone());
            return Some(public_key.clone());
        }
        None
    }
}
