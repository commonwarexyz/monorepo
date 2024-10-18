mod actor;
mod ingress;

pub use actor::Actor;
use commonware_cryptography::Scheme;
pub use ingress::{Mailbox, Message};

use crate::{Application, Finalizer, Hasher, Supervisor, View};
use bytes::Bytes;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Config<C: Scheme, H: Hasher, A: Application + Supervisor + Finalizer> {
    pub crypto: C,
    pub hasher: H,
    pub application: A,
    pub registry: Arc<Mutex<Registry>>,
    pub namespace: Bytes,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub null_vote_retry: Duration,
    pub activity_timeout: View,
}
