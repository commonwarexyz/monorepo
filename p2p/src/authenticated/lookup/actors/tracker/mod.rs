//! Tracker

use commonware_cryptography::Signer;
use governor::Quota;
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
};

pub mod actor;
mod directory;
mod ingress;
mod metadata;
mod metrics;
mod record;
mod reservation;

pub use actor::Actor;
pub use ingress::{Message, Oracle};
pub use metadata::Metadata;
pub use reservation::Reservation;

#[derive(Clone, Debug)]
pub struct Config<C: Signer> {
    pub crypto: C,
    pub address: SocketAddr,
    pub mailbox_size: usize,
    pub tracked_peer_sets: usize,
    pub allowed_connection_rate_per_peer: Quota,
    pub allow_private_ips: bool,
    pub registered_ips: Option<Arc<RwLock<HashSet<IpAddr>>>>,
}
