//! Tracker

use crate::config::Bootstrapper;
use commonware_cryptography::Scheme;
use governor::Quota;
use prometheus_client::registry::Registry;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

mod actor;
mod address;
mod ingress;

pub use actor::Actor;
pub use ingress::{Mailbox, Oracle, Reservation};

pub struct Config<C: Scheme> {
    pub crypto: C,
    pub registry: Arc<Mutex<Registry>>,
    pub address: SocketAddr,
    pub bootstrappers: Vec<Bootstrapper>,
    pub allow_private_ips: bool,
    pub mailbox_size: usize,
    pub tracked_peer_sets: usize,
    pub allowed_connection_rate_per_peer: Quota,
    pub peer_gossip_max_count: usize,
}

#[derive(Debug)]
pub enum Error {
    InvalidIPLength(usize),
    TooManyPeers(usize),
    PrivateIPsNotAllowed(IpAddr),
    PeerUnsigned,
    InvalidPublicKey,
    ReceivedSelf,
    InvalidSignature,
    BitVecLengthMismatch(usize, usize),
    BitVecExtraBit,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidIPLength(size) => write!(f, "invalid IP length: {}", size),
            Error::TooManyPeers(size) => write!(f, "too many peers: {}", size),
            Error::PrivateIPsNotAllowed(ip) => write!(f, "private IPs not allowed: {}", ip),
            Error::PeerUnsigned => write!(f, "network peer unsigned"),
            Error::InvalidPublicKey => write!(f, "invalid public key"),
            Error::ReceivedSelf => write!(f, "received self"),
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::BitVecLengthMismatch(expected, actual) => {
                write!(
                    f,
                    "peervec length mismatch: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Error::BitVecExtraBit => {
                write!(f, "peervec has extra bit")
            }
        }
    }
}

impl std::error::Error for Error {}
