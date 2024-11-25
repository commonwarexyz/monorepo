mod actor;
mod ingress;

use crate::{authority::View, Automaton, Supervisor};
pub use actor::Actor;
use bytes::Bytes;
use commonware_cryptography::{Hasher, Scheme};
pub use ingress::{Mailbox, Message};
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Config<C: Scheme, H: Hasher, A: Automaton, S: Supervisor> {
    pub crypto: C,
    pub hasher: H,
    pub application: A,
    pub supervisor: S,

    pub registry: Arc<Mutex<Registry>>,
    pub namespace: Bytes,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub activity_timeout: View,
    pub replay_concurrency: usize,
}
