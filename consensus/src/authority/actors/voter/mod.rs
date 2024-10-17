mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::{Mailbox, Message};

use crate::View;
use bytes::Bytes;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Config {
    pub registry: Arc<Mutex<Registry>>,
    pub namespace: Bytes,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub null_vote_retry: Duration,
    pub activity_timeout: View,
}
