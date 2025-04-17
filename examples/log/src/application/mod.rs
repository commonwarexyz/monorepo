//! This crate contains all logic typically implemented by an application developer.
//! This includes things like how to produce/verify blocks and how to identify which
//! participants are active at a given view.

use commonware_cryptography::Hasher;

mod actor;
pub use actor::Application;
use commonware_utils::Array;
mod ingress;
mod supervisor;

/// Configuration for the application.
pub struct Config<P: Array, H: Hasher> {
    /// Hashing scheme to use.
    pub hasher: H,

    /// Namespace of the application.
    pub namespace: Vec<u8>,

    /// Participants active in consensus.
    pub participants: Vec<P>,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,
}
