//! Utility functions for exchanging messages with many peers.

use commonware_cryptography::PublicKey;
use commonware_utils::set::Ordered;
use futures::channel::mpsc::{unbounded, UnboundedReceiver};

use crate::Manager;

pub mod codec;
pub mod mux;
pub mod requester;

#[derive(Debug, Clone)]
pub struct StaticManager<P: PublicKey> {
    id: u64,
    peers: Ordered<P>,
}

impl<P: PublicKey> StaticManager<P> {
    pub fn new(id: u64, peers: Ordered<P>) -> Self {
        Self { id, peers }
    }
}

impl<P: PublicKey> Manager for StaticManager<P> {
    type PublicKey = P;
    type Peers = Ordered<P>;

    async fn update(&mut self, _: u64, peers: Ordered<P>) {
        self.peers = peers;
    }

    async fn peer_set(&mut self, _: u64) -> Option<Ordered<P>> {
        Some(self.peers.clone())
    }

    async fn subscribe(&mut self) -> UnboundedReceiver<(u64, Ordered<P>, Ordered<P>)> {
        let (sender, receiver) = unbounded();
        let _ = sender.unbounded_send((self.id, self.peers.clone(), self.peers.clone()));
        receiver
    }
}
