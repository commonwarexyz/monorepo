//! Tracker

use crate::authenticated::Mailbox;
use commonware_cryptography::Signer;
use commonware_utils::channel::actor::{
    Backpressure, MessagePolicy, Overflow as ActorOverflow,
};
use std::{
    collections::HashSet,
    net::IpAddr,
    num::NonZeroUsize,
    ops::Deref,
    time::Duration,
};

pub mod actor;
mod directory;
pub(crate) mod ingress;
mod metadata;
mod metrics;
mod record;
mod reservation;

pub use actor::Actor;
pub(crate) use ingress::Message;
pub use ingress::Oracle;
pub use metadata::Metadata;
pub use reservation::Reservation;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ListenableIps(pub(crate) HashSet<IpAddr>);

impl Deref for ListenableIps {
    type Target = HashSet<IpAddr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl MessagePolicy for ListenableIps {
    fn handle(overflow: &mut ActorOverflow<'_, Self>, message: Self) -> Backpressure {
        let result = overflow.replace_last(message, |_| true);
        overflow.replace_or_spill(result)
    }
}

#[derive(Clone, Debug)]
pub struct Config<C: Signer> {
    pub crypto: C,
    pub tracked_peer_sets: NonZeroUsize,
    pub mailbox_size: usize,
    pub peer_connection_cooldown: Duration,
    pub allow_private_ips: bool,
    pub allow_dns: bool,
    pub bypass_ip_check: bool,
    pub(crate) listener: Mailbox<ListenableIps>,
    pub block_duration: Duration,
}
