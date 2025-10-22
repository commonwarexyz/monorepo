//! Tracker

use crate::authenticated::discovery::config::Bootstrapper;
use commonware_cryptography::Signer;
use governor::Quota;
use std::{net::SocketAddr, time::Duration};

mod actor;
mod directory;
mod ingress;
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
    pub address: SocketAddr,
    pub bootstrappers: Vec<Bootstrapper<C::PublicKey>>,
    pub allow_private_ips: bool,
    pub synchrony_bound: Duration,
    pub tracked_peer_sets: usize,
    pub max_peer_set_size: u64,
    pub allowed_connection_rate_per_peer: Quota,
    pub peer_gossip_max_count: usize,
    pub dial_fail_limit: usize,
}
