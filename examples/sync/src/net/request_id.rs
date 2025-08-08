use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// Unique identifier for correlating requests with responses.
pub type RequestId = u64;

/// Generates monotonically increasing request IDs.
#[derive(Debug, Clone)]
pub struct Generator {
    counter: Arc<AtomicU64>,
}

impl Default for Generator {
    fn default() -> Self {
        Self::new()
    }
}

impl Generator {
    pub fn new() -> Self {
        Generator {
            counter: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn next(&self) -> RequestId {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}
