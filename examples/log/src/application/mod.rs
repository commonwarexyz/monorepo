//! This crate contains all logic typically implemented by an application developer.
//! This includes things like how to produce/verify blocks and how to identify which
//! participants are active at a given view.

use commonware_cryptography::{Hasher, PendingHasher};
use std::num::NonZeroUsize;

mod actor;
pub use actor::Application;
mod ingress;
mod reporter;

pub type Scheme = commonware_consensus::simplex::scheme::ed25519::Scheme;

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Returns the initial payload for the single consensus epoch.
pub fn genesis<H: Hasher>() -> H::Digest {
    // Use the hash of the genesis message as the initial payload.
    //
    // Since this example does not verify that proposed messages link to a
    // parent, this only seeds the consensus floor.
    let mut hasher = H::default();
    hasher.update(GENESIS).finalize()
}

/// Configuration for the application.
pub struct Config<H: Hasher> {
    /// Hashing scheme to use.
    pub hasher: H,

    /// Signing scheme for this network.
    pub scheme: Scheme,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: NonZeroUsize,
}
