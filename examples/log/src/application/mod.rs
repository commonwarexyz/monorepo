//! This crate contains all logic typically implemented by an application developer.
//! This includes things like how to produce/verify blocks and how to identify which
//! participants are active at a given view.

use commonware_cryptography::Hasher;

mod actor;
pub use actor::Application;
mod ingress;
mod reporter;

pub type Scheme = commonware_consensus::simplex::scheme::ed25519::Scheme;

/// Configuration for the application.
pub struct Config<H: Hasher> {
    /// Hashing scheme to use.
    pub hasher: H,

    /// Signing scheme for this network.
    pub scheme: Scheme,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,
}
