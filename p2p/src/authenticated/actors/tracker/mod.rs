//! Tracker

use crate::authenticated::config::Bootstrapper;
use commonware_cryptography::Scheme;
use governor::Quota;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

mod actor;
mod address_record;
mod ingress;
mod peer_set;

pub use actor::Actor;
pub use ingress::{Mailbox, Oracle, Reservation};

pub struct Config<C: Scheme> {
    pub crypto: C,
    pub namespace: Vec<u8>,
    pub address: SocketAddr,
    pub bootstrappers: Vec<Bootstrapper<C::PublicKey>>,
    pub allow_private_ips: bool,
    pub mailbox_size: usize,
    pub synchrony_bound: Duration,
    pub tracked_peer_sets: usize,
    pub allowed_connection_rate_per_peer: Quota,
    pub peer_gossip_max_count: usize,
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
    #[error("peervec length mismatch: expected {0} bytes, got {1}")]
    BitVecLengthMismatch(usize, usize),
    #[error("peervec has extra bit")]
    BitVecExtraBit,
}
