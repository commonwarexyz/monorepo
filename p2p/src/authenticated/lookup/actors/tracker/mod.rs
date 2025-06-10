//! Tracker

use crate::authenticated::lookup::config::Bootstrapper;
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
pub use ingress::{Message, Oracle};
pub use metadata::Metadata;
pub use reservation::Reservation;

#[derive(Clone, Debug)]
pub struct Config<C: Signer> {
    pub crypto: C,
    pub namespace: Vec<u8>,
    pub address: SocketAddr,
    pub bootstrappers: Vec<Bootstrapper<C::PublicKey>>,
    pub mailbox_size: usize,
    pub tracked_peer_sets: usize,
    pub max_peer_set_size: usize,
    pub allowed_connection_rate_per_peer: Quota,
}

// TODO danlaine: use or remove
// #[derive(Error, Debug)]
// pub enum Error {
//     #[error("too many peers: {0}")]
//     TooManyPeers(usize),
//     #[error("private IPs not allowed: {0}")]
//     PrivateIPsNotAllowed(IpAddr),
//     #[error("received self")]
//     ReceivedSelf,
//     #[error("invalid signature")]
//     InvalidSignature,
//     #[error("synchrony bound violated")]
//     SynchronyBound,
// }
