use crate::authenticated::discovery::types::InfoVerifier;
use commonware_cryptography::PublicKey;
use std::{num::NonZeroUsize, time::Duration};

mod actor;

pub use actor::Actor;

/// Messages processed by the spawner [Actor], carrying this protocol's reservations.
pub type Message<Si, St, P> =
    crate::authenticated::spawner::Message<Si, St, P, super::tracker::Reservation<P>>;

/// Configuration for the spawner [Actor].
pub struct Config<C: PublicKey> {
    pub mailbox_size: NonZeroUsize,
    pub send_batch_size: NonZeroUsize,
    pub gossip_bit_vec_frequency: Duration,
    pub max_peer_set_size: u64,
    pub peer_gossip_max_count: usize,
    pub info_verifier: InfoVerifier<C>,
}
