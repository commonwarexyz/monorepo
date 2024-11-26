mod actor;
mod ingress;
mod priority_queue;

use crate::Supervisor;
pub use actor::Actor;
use bytes::Bytes;
use commonware_cryptography::Scheme;
use governor::Quota;
pub use ingress::Mailbox;
use std::time::Duration;

pub struct Config<C: Scheme, S: Supervisor> {
    pub crypto: C,
    pub supervisor: S,

    pub namespace: Bytes,
    pub activity_timeout: u64,
    pub fetch_timeout: Duration,
    pub max_fetch_count: u64,
    pub max_fetch_size: usize,
    pub fetch_rate_per_peer: Quota,
}
