mod actor;
mod ingress;

use crate::{Application, Hasher};
pub use actor::Actor;

use bytes::Bytes;
use commonware_cryptography::Scheme;
pub use ingress::{Mailbox, Message};
use std::time::Duration;

pub struct Config<C: Scheme, H: Hasher, A: Application> {
    pub crypto: C,
    pub hasher: H,
    pub application: A,
    pub namespace: Bytes,
    pub fetch_timeout: Duration,
    pub max_fetch_count: u64,
    pub max_fetch_size: usize,
}
