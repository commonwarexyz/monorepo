//! Tracker

use commonware_cryptography::Signer;
use governor::Quota;
use std::net::SocketAddr;

pub mod actor;
mod directory;
mod ingress;
mod metadata;
mod metrics;
mod record;
mod reservation;

pub use actor::Actor;
pub use ingress::{Mailbox, Oracle};
pub use metadata::Metadata;
pub use reservation::Reservation;

#[derive(Clone, Debug)]
pub struct Config<C: Signer> {
    pub crypto: C,
    pub address: SocketAddr,
    pub mailbox_size: usize,
    pub tracked_peer_sets: usize,
    pub max_peer_set_size: usize,
    pub allowed_connection_rate_per_peer: Quota,
    pub allow_private_ips: bool,
}
