//! Tracker

use crate::authenticated::Mailbox;
use commonware_cryptography::Signer;
use std::{collections::HashSet, net::IpAddr, num::NonZeroUsize, time::Duration};

pub mod actor;
mod directory;
pub(crate) mod ingress;
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
    pub tracked_peer_sets: NonZeroUsize,
    pub peer_connection_cooldown: Duration,
    pub allow_private_ips: bool,
    pub allow_dns: bool,
    pub bypass_ip_check: bool,
    pub listener: Mailbox<HashSet<IpAddr>>,
    pub block_duration: Duration,
}
