mod actor;
mod ingress;
mod state;

use crate::types::Epoch;
pub use actor::Actor;
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::Blocker;
use commonware_parallel::Bridge;
pub use ingress::Mailbox;
#[cfg(test)]
pub use ingress::MailboxMessage;
use std::time::Duration;

pub struct Config<S: Scheme, B: Blocker, T: Bridge> {
    pub scheme: S,

    pub blocker: B,

    /// Strategy for parallel operations.
    pub strategy: T,

    pub epoch: Epoch,
    pub mailbox_size: usize,
    pub fetch_concurrent: usize,
    pub fetch_timeout: Duration,
}
