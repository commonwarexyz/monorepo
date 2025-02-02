//! This crate contains all logic typically implemented by an application developer.
//! This includes things like how to produce/verify blocks and how to identify which
//! participants are active at a given view.

use commonware_consensus::simplex::Prover;
use commonware_cryptography::{Hasher, PublicKey, Scheme};

mod actor;
pub use actor::Application;
mod ingress;
mod supervisor;

/// Configuration for the application.
pub struct Config<C: Scheme, H: Hasher> {
    /// Hashing scheme to use.
    pub hasher: H,

    /// Prover used to decode opaque proofs from consensus.
    pub prover: Prover<C, H::Digest>,

    /// Participants active in consensus.
    pub participants: Vec<C::PublicKey>,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,
}
