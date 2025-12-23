//! Tracker

use crate::authenticated::Mailbox;
use commonware_cryptography::Signer;
use commonware_runtime::Quota;
use std::{collections::HashSet, net::IpAddr};

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
    pub tracked_peer_sets: usize,
    pub allowed_connection_rate_per_peer: Quota,
    pub allow_private_ips: bool,
    pub allow_dns: bool,
    pub listener: Mailbox<HashSet<IpAddr>>,
}
