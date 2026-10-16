//! Tracker

use crate::authenticated::discovery::{config::Bootstrapper, types::Info};
use commonware_cryptography::PublicKey;
use std::{num::NonZeroUsize, time::Duration};

mod actor;
mod bit_set;
mod directory;
pub(crate) mod ingress;
mod metadata;
mod metrics;
mod record;
mod reservation;

pub use actor::Actor;
#[cfg(test)]
pub(crate) use ingress::Message;
pub use ingress::{Mailbox, Oracle};
pub use metadata::Metadata;
pub use reservation::Reservation;

#[derive(Clone, Debug)]
pub struct Config<C: PublicKey> {
    pub myself: Info<C>,
    pub bootstrappers: Vec<Bootstrapper<C>>,
    pub allow_private_ips: bool,
    pub allow_dns: bool,
    pub mailbox_size: NonZeroUsize,
    pub max_peers_per_set: usize,
    pub tracked_peer_sets: NonZeroUsize,
    pub peer_connection_cooldown: Duration,
    pub peer_gossip_max_count: usize,
    pub dial_fail_limit: usize,
    pub block_duration: Duration,
}
