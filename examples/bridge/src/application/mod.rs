//! This crate contains all logic typically implemented by an application developer.
//! This includes things like how to produce/verify blocks and how to identify which
//! participants are active at a given view.

use commonware_cryptography::{
    bls12381::primitives::{group, poly},
    Hasher,
};
use commonware_utils::Array;

mod actor;
pub use actor::Application;
use commonware_runtime::{Sink, Stream};
use commonware_stream::public_key::Connection;
mod ingress;
mod supervisor;

/// Configuration for the application.
pub struct Config<H: Hasher, Si: Sink, St: Stream, P: Array> {
    pub indexer: Connection<Si, St>,

    /// Hashing scheme to use.
    pub hasher: H,

    pub namespace: Vec<u8>,
    pub identity: poly::Public,
    pub other_identity: group::Public,

    /// Participants active in consensus.
    pub participants: Vec<P>,

    pub share: group::Share,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,
}
