use crate::authenticated::discovery::types::InfoVerifier;
use commonware_cryptography::PublicKey;
use governor::Quota;
use std::time::Duration;

mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::Message;

/// Configuration for the spawner [Actor].
pub struct Config<C: PublicKey> {
    pub mailbox_size: usize,
    pub gossip_bit_vec_frequency: Duration,
    pub allowed_bit_vec_rate: Quota,
    pub max_peer_set_size: u64,
    pub allowed_peers_rate: Quota,
    pub peer_gossip_max_count: usize,
    pub info_verifier: InfoVerifier<C>,
    /// Whether to rate limit outbound messages using the same rate as inbound.
    /// When enabled, outbound messages are delayed if they exceed the per-channel rate limit,
    /// preventing the remote peer from rate limiting us.
    pub rate_limit_outbound: bool,
}
