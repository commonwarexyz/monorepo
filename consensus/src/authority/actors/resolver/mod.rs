mod actor;
mod ingress;

use crate::Automaton;
pub use actor::Actor;
use bytes::Bytes;
use commonware_cryptography::{Hasher, Scheme};
pub use ingress::{Mailbox, Message};

pub struct Config<C: Scheme, H: Hasher, A: Automaton> {
    pub crypto: C,
    pub hasher: H,
    pub application: A,
    pub namespace: Bytes,

    pub max_fetch_count: u64,
    pub max_fetch_size: usize,
}
