//! Configuration for `Requester`.

use commonware_cryptography::PublicKey;
use governor::Quota;
use std::time::Duration;

/// Configuration for the requester.
pub struct Config<P: PublicKey> {
    /// Local identity of the participant (if any).
    pub me: Option<P>,

    /// Rate limit for requests per participant.
    pub rate_limit: Quota,

    /// Initial expected performance for new participants.
    pub initial: Duration,

    /// Timeout for requests.
    pub timeout: Duration,
}
