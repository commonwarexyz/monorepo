//! Fetches missing L-QCs, tip histories, producer headers and blocks, locally first and then
//! from peers.
//!
//! # Request lifecycle
//!
//! 1. Register: a request becomes a waiter keyed by the peer-visible [`BackfillKey`] it needs.
//!    Waiters of one key share its local recheck and its network fetch.
//! 2. Local recheck: the first waiter of a key looks the value up in the catalog and body
//!    stores, and completes every waiter of the key on a hit.
//! 3. Network fetch: on a miss, each waiter subscribes to the key through the
//!    `commonware_resolver` engine.
//! 4. Validate: a delivered value is decoded and checked against its key once, here. Blocks and
//!    segments leave backfill in types that carry the checks ([`CustodiedBlock`] and the
//!    checked block-segment prefix), so consumers do not repeat them.
//! 5. Stage: blocks a waiter needs in custody are staged into the catalog's temporary custody,
//!    and a peer L-QC is verified and admitted before its waiters complete.
//! 6. Complete: every waiter of the key that the value satisfies completes; the resolver learns
//!    whether the delivery was valid.
//!
//! # Serving
//!
//! The [`BackfillBridge`] forwards peer requests to the [`serve`] actor, which answers them from
//! local custody independently of backfill intake.
//!
//! # Backpressure
//!
//! When the mailbox is full, a network delivery is answered as ambiguous so the resolver retries
//! it without penalizing the peer, and certified-block hints are dropped; a later request still
//! fetches the block. Requests whose caller is gone are discarded.
//!
//! [`BackfillKey`]: crate::multimmit::marshal::BackfillKey

mod actor;
mod mailbox;
mod rechecks;
mod registry;
pub(crate) mod serve;
mod staging;
mod validate;
mod verifications;
mod waiter;

pub(crate) use actor::{Actor, Config};
pub use mailbox::BackfillBridge;
pub(crate) use mailbox::{Error, Mailbox};
pub(crate) use validate::{SharedHeaders, SharedHistory};
pub use waiter::BackfillSubscriber;
pub(crate) use waiter::CustodiedBlock;

#[cfg(test)]
mod tests;
