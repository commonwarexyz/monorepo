//! Configuration for `Requester`.

use commonware_cryptography::Scheme;
use governor::Quota;
use std::time::Duration;

/// Configuration for the requester.
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
