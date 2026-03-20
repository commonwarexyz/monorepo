//! The resolver is responsible for ensuring that the voter has all the certificates it needs to
//! make progress. The voter is voting in a view and has a "floor" view which is the latest
//! certified (or finalized) view that it knows about. Thus, it either requires evidence of
//! nullification for every intermediate view, or a higher floor. It will request nullifications for
//! these views from the resolver. Other nodes will either serve such nullifications, or higher floors.

mod actor;
mod ingress;
mod state;

use crate::types::Epoch;
pub use actor::Actor;
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use core::num::NonZeroU64;
pub use ingress::Mailbox;
#[cfg(test)]
pub use ingress::MailboxMessage;
use std::time::Duration;

pub struct Config<S: Scheme, B: Blocker, T: Strategy> {
    pub scheme: S,

    pub blocker: B,

    /// Strategy for parallel operations.
    pub strategy: T,

    pub epoch: Epoch,
    pub mailbox_size: usize,
    pub fetch_concurrent: usize,
    pub fetch_timeout: Duration,
    pub term_length: NonZeroU64,
}
