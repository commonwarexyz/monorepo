mod actor;
mod ingress;

use crate::Supervisor;
pub use actor::Actor;
use bytes::Bytes;
use commonware_cryptography::Scheme;
use governor::Quota;
pub use ingress::Mailbox;
use prometheus_client::registry::Registry;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

pub struct Config<C: Scheme, S: Supervisor> {
    pub crypto: C,
    pub supervisor: S,

    pub registry: Arc<Mutex<Registry>>,
    pub namespace: Bytes,
    pub mailbox_size: usize,
    pub activity_timeout: u64,
    pub fetch_timeout: Duration,
    pub max_fetch_count: usize,
    pub max_fetch_size: usize,
    pub fetch_rate_per_peer: Quota,
    pub fetch_concurrent: usize,
}
