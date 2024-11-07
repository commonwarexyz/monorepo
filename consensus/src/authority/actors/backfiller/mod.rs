mod actor;
mod ingress;

use crate::Automaton;
pub use actor::Actor;
use bytes::Bytes;
use commonware_cryptography::{Hasher, Scheme};
use governor::Quota;
pub use ingress::{Mailbox, Message};
use std::time::Duration;

pub struct Config<C: Scheme, H: Hasher, A: Automaton> {
    pub crypto: C,
    pub hasher: H,
    pub application: A,
    pub namespace: Bytes,
    pub fetch_timeout: Duration,
    pub max_fetch_count: u32,
    pub max_fetch_size: usize,
    pub fetch_rate_per_peer: Quota,
}
