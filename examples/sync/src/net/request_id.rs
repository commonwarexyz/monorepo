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
        Self {
            counter: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn next(&self) -> RequestId {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::Generator;

    #[test]
    fn test_request_id_generation() {
        let requester = Generator::new();
        let id1 = requester.next();
        let id2 = requester.next();
        let id3 = requester.next();

        // Request IDs should be monotonically increasing
        assert!(id2 > id1);
        assert!(id3 > id2);

        // Should be consecutive since we're using a single Requester
        assert_eq!(id2, id1 + 1);
        assert_eq!(id3, id2 + 1);
    }
}
