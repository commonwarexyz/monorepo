use crate::authenticated::discovery::types::InfoVerifier;
use commonware_cryptography::PublicKey;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};

mod actor;
mod ingress;

pub use actor::Actor;
pub use ingress::Message;

/// Configuration for the spawner [Actor].
pub struct Config<C: PublicKey> {
    pub mailbox_size: NonZeroUsize,
    pub gossip_bit_vec_frequency: Duration,
    pub max_peer_set_size: NonZeroU64,
    pub peer_gossip_max_count: NonZeroUsize,
    pub info_verifier: InfoVerifier<C>,
}
