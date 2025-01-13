//! This crate contains all logic typically implemented by an application developer.
//! This includes things like how to produce/verify blocks and how to identify which
//! participants are active at a given view.

use commonware_consensus::simplex::Prover;
use commonware_cryptography::{
    bls12381::primitives::{group, poly},
    Hasher, PublicKey,
};

mod actor;
pub use actor::Application;
mod ingress;
mod supervisor;

/// Configuration for the application.
pub struct Config<H: Hasher> {
    /// Hashing scheme to use.
    pub hasher: H,

    /// Prover used to decode opaque proofs from consensus.
    pub prover: Prover<H>,

    pub identity: poly::Public,

    /// Participants active in consensus.
    pub participants: Vec<PublicKey>,

    pub share: group::Share,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,
}
