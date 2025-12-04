//! Utility functions for exchanging messages with many peers.

use crate::Manager;
use commonware_cryptography::PublicKey;
use commonware_utils::set::Ordered;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};

pub mod codec;
pub mod mux;
pub mod requester;

/// A [Manager] over a static set of peers.
#[derive(Debug, Clone)]
pub struct StaticManager<P: PublicKey> {
    id: u64,
    peers: Ordered<P>,
    #[allow(clippy::type_complexity)]
    senders: Vec<UnboundedSender<(u64, Ordered<P>, Ordered<P>)>>,
}

impl<P: PublicKey> StaticManager<P> {
    /// Create a new [StaticManager] with the given ID and peers.
    pub const fn new(id: u64, peers: Ordered<P>) -> Self {
        Self {
            id,
            peers,
            senders: vec![],
        }
    }
}

impl<P: PublicKey> Manager for StaticManager<P> {
    type PublicKey = P;
    type Peers = Ordered<P>;

    async fn update(&mut self, _: u64, _: Ordered<P>) {
        panic!("updates are not supported");
    }

    async fn peer_set(&mut self, id: u64) -> Option<Ordered<P>> {
        assert_eq!(id, self.id);
        Some(self.peers.clone())
    }

    async fn subscribe(&mut self) -> UnboundedReceiver<(u64, Ordered<P>, Ordered<P>)> {
        let (sender, receiver) = unbounded();
        let _ = sender.unbounded_send((self.id, self.peers.clone(), self.peers.clone()));
        self.senders.push(sender); // prevent the receiver from closing
        receiver
    }
}
