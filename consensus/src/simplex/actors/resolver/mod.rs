mod actor;
mod ingress;
mod state;

use crate::types::Epoch;
pub use actor::Actor;
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::Blocker;
pub use ingress::Mailbox;
use std::time::Duration;

pub struct Config<S: Scheme, B: Blocker> {
    pub scheme: S,

    pub blocker: B,

    pub epoch: Epoch,
    pub namespace: Vec<u8>,
    pub mailbox_size: usize,
    pub fetch_concurrent: usize,
    pub fetch_timeout: Duration,
}
