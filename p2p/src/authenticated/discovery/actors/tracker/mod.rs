//! Tracker

use crate::{authenticated::discovery::config::Bootstrapper, Ingress};
use commonware_cryptography::Signer;
use std::{num::NonZeroUsize, time::Duration};

mod actor;
mod directory;
pub(crate) mod ingress;
mod metadata;
mod metrics;
mod record;
mod reservation;
mod set;

pub use actor::Actor;
pub use ingress::{Message, Oracle};
pub use metadata::Metadata;
pub use reservation::Reservation;

#[derive(Clone, Debug)]
pub struct Config<C: Signer> {
    pub crypto: C,
    pub namespace: Vec<u8>,
    pub address: Ingress,
    pub bootstrappers: Vec<Bootstrapper<C::PublicKey>>,
    pub allow_private_ips: bool,
    pub allow_dns: bool,
    pub synchrony_bound: Duration,
    pub tracked_peer_sets: NonZeroUsize,
    pub max_peer_set_size: u64,
    pub peer_connection_cooldown: Duration,
    pub peer_gossip_max_count: usize,
    pub dial_fail_limit: usize,
    pub block_duration: Duration,
}
