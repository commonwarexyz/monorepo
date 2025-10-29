mod actor;
mod ingress;

use crate::{simplex::signing_scheme::Scheme, types::Epoch};
pub use actor::Actor;
use commonware_cryptography::PublicKey;
use commonware_p2p::Blocker;
use commonware_utils::set::Set;
use governor::Quota;
pub use ingress::Mailbox;
#[cfg(test)]
pub use ingress::Message;
use std::time::Duration;

pub struct Config<P: PublicKey, S: Scheme, B: Blocker> {
    pub me: P,
    pub participants: Set<P>,
    pub scheme: S,

    pub blocker: B,

    pub epoch: Epoch,
    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
    pub activity_timeout: u64,
    pub fetch_timeout: Duration,
    pub max_fetch_count: usize,
    pub fetch_rate_per_peer: Quota,
    pub fetch_concurrent: usize,
}
