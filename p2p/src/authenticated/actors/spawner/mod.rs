use governor::Quota;
use std::time::Duration;

mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::Mailbox;

pub struct Config {
    pub mailbox_size: usize,
    pub gossip_bit_vec_frequency: Duration,
    pub allowed_bit_vec_rate: Quota,
    pub max_peer_set_size: usize,
    pub allowed_peers_rate: Quota,
    pub peer_gossip_max_count: usize,
}
