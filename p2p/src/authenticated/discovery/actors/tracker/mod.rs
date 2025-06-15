//! Tracker

use crate::authenticated::discovery::config::Bootstrapper;
use commonware_cryptography::Signer;
use governor::Quota;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use thiserror::Error;

mod actor;
mod directory;
mod ingress;
mod metadata;
mod metrics;
mod record;
mod reservation;
mod set;

pub use actor::Actor;
pub use ingress::{Mailbox, Oracle};
pub use metadata::Metadata;
pub use reservation::Reservation;

#[derive(Clone, Debug)]
pub struct Config<C: Signer> {
    pub crypto: C,
    pub namespace: Vec<u8>,
    pub address: SocketAddr,
    pub bootstrappers: Vec<Bootstrapper<C::PublicKey>>,
    pub allow_private_ips: bool,
    pub mailbox_size: usize,
    pub synchrony_bound: Duration,
    pub tracked_peer_sets: usize,
    pub max_peer_set_size: usize,
    pub allowed_connection_rate_per_peer: Quota,
    pub peer_gossip_max_count: usize,
    pub dial_fail_limit: usize,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("too many peers: {0}")]
    TooManyPeers(usize),
    #[error("private IPs not allowed: {0}")]
    PrivateIPsNotAllowed(IpAddr),
    #[error("received self")]
    ReceivedSelf,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("synchrony bound violated")]
    SynchronyBound,
}
