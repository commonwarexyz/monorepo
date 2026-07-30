//! Tracker

use commonware_cryptography::Signer;
use std::{num::NonZeroUsize, time::Duration};

pub mod actor;
mod directory;
pub(crate) mod ingress;
mod metadata;
mod metrics;
mod record;
mod reservation;

pub use actor::Actor;
#[cfg(test)]
pub(crate) use ingress::Message;
pub use ingress::{Mailbox, Oracle};
pub use metadata::Metadata;
pub use reservation::Reservation;

#[derive(Clone, Debug)]
pub struct Config<C: Signer> {
    pub crypto: C,
    pub mailbox_size: NonZeroUsize,
    pub tracked_peer_sets: NonZeroUsize,
    pub peer_connection_cooldown: Duration,
    pub block_duration: Duration,
}
