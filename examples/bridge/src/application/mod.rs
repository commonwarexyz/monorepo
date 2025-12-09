//! This crate contains all logic typically implemented by an application developer.
//! This includes things like how to produce/verify blocks and how to identify which
//! participants are active at a given view.

use commonware_cryptography::{
    bls12381::primitives::{
        group,
        poly::Public,
        variant::{MinSig, Variant},
    },
    ed25519::PublicKey,
    Hasher,
};

mod actor;
pub use actor::Application;
use commonware_runtime::{Sink, Stream};
use commonware_stream::{Receiver, Sender};
use commonware_utils::ordered::Set;
mod ingress;

/// Configuration for the application.
pub struct Config<H: Hasher, Si: Sink, St: Stream> {
    pub indexer: (Sender<Si>, Receiver<St>),

    /// Hashing scheme to use.
    pub hasher: H,

    pub namespace: Vec<u8>,
    pub identity: Public<MinSig>,
    pub other_public: <MinSig as Variant>::Public,

    /// Participants active in consensus.
    pub participants: Set<PublicKey>,

    pub share: group::Share,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,
}
