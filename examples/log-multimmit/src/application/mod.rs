//! The application attached to consensus.
//!
//! - Propose: build a block of junk bytes, stage it with marshal, and return its body digest.
//! - Verify: wait until marshal holds the complete block durably (this node's own block once its
//!   staging is on disk, a peer's once marshal receives and stores it), then check it matches the
//!   header consensus signs.
//!
//! Marshal's relay, not the application, broadcasts blocks once consensus signs them.

mod actor;
mod block;
mod mailbox;
mod reporter;

use crate::bench::Schedule;
pub use actor::Actor;
pub use block::{Block, Body};
use commonware_consensus::multimmit::{marshal, types::ChainId};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, ed25519};
pub use mailbox::Mailbox;
pub use reporter::OutputReporter;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};

/// Marshal mailbox type used by this example.
pub type Marshal = marshal::Mailbox<Sha256, MinPk, Body>;

/// Marshal's relay, which broadcasts this node's staged blocks to peers.
pub type Relay = marshal::Relay<Sha256, Body, ed25519::PublicKey>;

/// How a producer shapes its blocks.
#[derive(Clone, Debug)]
pub struct Production {
    /// Bytes of junk data placed in every block body.
    pub body_size: usize,
    /// Minimum time between two blocks this producer builds; zero builds as fast as block
    /// custody admits.
    pub interval: Duration,
    /// Independent payload arrival rate per producer; absent means saturated input.
    pub offered_bytes_per_second: Option<NonZeroU64>,
    /// Finite benchmark arrivals, mutually exclusive with the constant input rate.
    pub schedule: Option<Schedule>,
}

/// Configuration for the application [`Actor`].
pub struct Config {
    /// Seed mixed into every junk body.
    pub seed: u64,
    /// How this producer shapes its blocks.
    pub production: Production,
    /// Most recent local blocks tracked from input submission to finality and ordering.
    pub tracked_blocks: NonZeroUsize,
    /// This node's producer chain, if it produces.
    pub producer_chain: Option<ChainId>,
    /// Consensus quorum when a benchmark is configured; see [`crate::bench`].
    pub benchmark_quorum: Option<NonZeroUsize>,
    /// Messages buffered by the actor's mailbox.
    pub mailbox_size: NonZeroUsize,
}
