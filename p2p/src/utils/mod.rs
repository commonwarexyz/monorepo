//! Utility functions for exchanging messages with many peers.

use crate::Provider;
use commonware_cryptography::PublicKey;
use commonware_utils::{
    channel::{
        fallible::FallibleExt,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
    },
    ordered::Set,
};

pub mod codec;
pub mod limited;
pub mod mux;

/// A [Provider] over a static set of peers.
#[derive(Debug, Clone)]
pub struct StaticProvider<P: PublicKey> {
    id: u64,
    peers: Set<P>,
    #[allow(clippy::type_complexity)]
    senders: Vec<UnboundedSender<(u64, Set<P>, Set<P>)>>,
}

impl<P: PublicKey> StaticProvider<P> {
    /// Create a new [StaticProvider] with the given ID and peers.
    pub const fn new(id: u64, peers: Set<P>) -> Self {
        Self {
            id,
            peers,
            senders: vec![],
        }
    }
}

impl<P: PublicKey> Provider for StaticProvider<P> {
    type PublicKey = P;

    async fn peer_set(&mut self, id: u64) -> Option<Set<P>> {
        assert_eq!(id, self.id);
        Some(self.peers.clone())
    }

    async fn subscribe(&mut self) -> UnboundedReceiver<(u64, Set<P>, Set<P>)> {
        let (sender, receiver) = mpsc::unbounded_channel();
        sender.send_lossy((self.id, self.peers.clone(), self.peers.clone()));
        self.senders.push(sender); // prevent the receiver from closing
        receiver
    }
}
