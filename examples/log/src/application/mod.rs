//! This crate contains all logic typically implemented by an application developer.
//! This includes things like how to produce/verify blocks and how to identify which
//! participants are active at a given view.

use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Hasher,
};
use commonware_utils::set::Ordered;

mod actor;
pub use actor::Application;
mod ingress;
mod reporter;

pub type Scheme = commonware_consensus::simplex::signing_scheme::ed25519::Scheme;

/// Configuration for the application.
pub struct Config<H: Hasher> {
    /// Hashing scheme to use.
    pub hasher: H,

    /// Participants active in consensus.
    pub participants: Ordered<PublicKey>,

    /// Our private key.
    pub private_key: PrivateKey,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,
}
