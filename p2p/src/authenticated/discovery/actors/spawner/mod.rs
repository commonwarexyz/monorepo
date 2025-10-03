use commonware_cryptography::PublicKey;
use governor::Quota;
use std::time::Duration;

mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::Message;

use crate::authenticated::discovery::types::PeerValidator;

/// Configuration for the spawner [Actor].
pub struct Config<C: PublicKey> {
    pub mailbox_size: usize,
    pub gossip_bit_vec_frequency: Duration,
    pub allowed_bit_vec_rate: Quota,
    pub max_peer_set_size: usize,
    pub allowed_peers_rate: Quota,
    pub peer_gossip_max_count: usize,
    pub peer_validator: PeerValidator<C>,
}
