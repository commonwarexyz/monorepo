use crate::authenticated::discovery::types::InfoVerifier;
use commonware_cryptography::PublicKey;
use std::{num::NonZeroUsize, time::Duration};

mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::Message;

/// Configuration for the spawner [Actor].
pub struct Config<C: PublicKey> {
    pub mailbox_size: usize,
    pub send_batch_size: NonZeroUsize,
    pub gossip_bit_vec_frequency: Duration,
    pub max_peer_set_size: u64,
    pub peer_gossip_max_count: usize,
    pub info_verifier: InfoVerifier<C>,
}
