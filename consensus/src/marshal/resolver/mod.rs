//! Resolver backfill helpers shared by all marshal variants.
//!
//! Marshal has two networking paths:
//! - `ingress`, which accepts deliveries from local subsystems (e.g. the resolver engine handing
//!   a block to the actor)
//! - `resolver`, which issues outbound fetches when we need data stored on remote peers
//!
//! This module powers the second path. It exposes a single helper for wiring up a
//! [`commonware_resolver::p2p::Engine`] and lets each marshal variant plug in its own message
//! handler while reusing the same transport plumbing.

use crate::types::{Height, Round};
use commonware_actor::Feedback;
use commonware_cryptography::{Digest, PublicKey};
use commonware_utils::vec::NonEmptyVec;

pub mod handler;
pub mod p2p;

pub use handler::{FetchRequest, FetchRequestKind, Receiver};

/// Resolver interface used by marshal.
///
/// Fetch construction is restricted to [`FetchRequest`], whose constructors
/// keep the peer-visible request and local processing annotation in sync.
pub trait Resolver<D: Digest>: Clone + Send + 'static {
    /// Type used to identify peers for targeted fetches.
    type PublicKey: PublicKey;

    /// Initiate a fetch.
    fn fetch(&mut self, fetch: FetchRequest<D>) -> Feedback;

    /// Initiate fetches for a batch of keys.
    fn fetch_all(&mut self, fetches: Vec<FetchRequest<D>>) -> Feedback;

    /// Initiate a fetch restricted to specific target peers.
    fn fetch_targeted(
        &mut self,
        fetch: FetchRequest<D>,
        targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback;

    /// Retain fetches above the processed height floor.
    fn retain_above_height(&mut self, height: Height) -> Feedback;

    /// Retain fetches above the processed round floor.
    fn retain_above_round(&mut self, round: Round) -> Feedback;
}
