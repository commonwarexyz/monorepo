//! This crate contains all logic typically implemented by an application developer.
//! This includes things like how to produce/verify blocks and how to identify which
//! participants are active at a given view.

use crate::Scheme;
use commonware_cryptography::Hasher;

mod actor;
pub use actor::Application;
use commonware_runtime::{Sink, Stream};
use commonware_stream::encrypted::{Receiver, Sender};
mod ingress;

/// Configuration for the application.
pub struct Config<H: Hasher, Si: Sink, St: Stream> {
    pub indexer: (Sender<Si>, Receiver<St>),

    /// Hashing scheme to use.
    pub hasher: H,

    /// Signing scheme for this network.
    pub this_network: Scheme,

    /// Certificate verifier for the other network.
    pub other_network: Scheme,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,
}
