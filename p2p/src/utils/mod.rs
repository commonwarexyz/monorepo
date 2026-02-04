//! Utility functions for exchanging messages with many peers.

use crate::{Manager, PeerSetProvider};
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

/// A [Manager] over a static set of peers.
#[derive(Debug, Clone)]
pub struct StaticManager<P: PublicKey> {
    id: u64,
    peers: Set<P>,
    #[allow(clippy::type_complexity)]
    senders: Vec<UnboundedSender<(u64, Set<P>, Set<P>)>>,
}

impl<P: PublicKey> StaticManager<P> {
    /// Create a new [StaticManager] with the given ID and peers.
    pub const fn new(id: u64, peers: Set<P>) -> Self {
        Self {
            id,
            peers,
            senders: vec![],
        }
    }
}

impl<P: PublicKey> PeerSetProvider for StaticManager<P> {
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

impl<P: PublicKey> Manager for StaticManager<P> {
    async fn update(&mut self, _: u64, _: Set<P>) {
        panic!("updates are not supported");
    }
}
