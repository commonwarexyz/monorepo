//! Configuration for `Requester`.
use commonware_utils::Array;
use governor::Quota;
use std::time::Duration;

/// Configuration for the requester.
pub struct Config<C: Array> {
    /// Cryptographic primitives.
    pub me: C,

    /// Rate limit for requests per participant.
    pub rate_limit: Quota,

    /// Initial expected performance for new participants.
    pub initial: Duration,

    /// Timeout for requests.
    pub timeout: Duration,
}
