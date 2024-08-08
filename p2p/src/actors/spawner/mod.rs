use governor::Quota;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::Mailbox;

pub struct Config {
    pub registry: Arc<Mutex<Registry>>,
    pub mailbox_size: usize,
    pub gossip_bit_vec_frequency: Duration,
    pub allowed_bit_vec_rate: Quota,
    pub allowed_peers_rate: Quota,
}
