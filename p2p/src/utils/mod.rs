//! Utility functions for exchanging messages with many peers.

use crate::{PeerSetUpdate, Provider, TrackedPeers};
use commonware_cryptography::PublicKey;
use commonware_utils::{
    channel::{
        fallible::FallibleExt,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
    },
    ordered::Set,
};

pub mod codec;
pub mod interleave;
pub mod limited;
#[cfg(feature = "mocks")]
pub mod mocks;
pub mod mux;

/// Primary and secondary peer memberships at one peer set index.
///
/// Import as `PeerSetsAtIndexBase` (or similar) and define a local
/// `type PeerSetsAtIndex<P> = PeerSetsAtIndexBase<...>` with the primary/secondary types you use.
pub(crate) struct PeerSetsAtIndex<Primary, Secondary> {
    pub(crate) primary: Primary,
    pub(crate) secondary: Secondary,
}

/// A [Provider] over a static set of peers.
#[derive(Debug, Clone)]
pub struct StaticProvider<P: PublicKey> {
    id: u64,
    peers: Set<P>,
    senders: Vec<UnboundedSender<PeerSetUpdate<P>>>,
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

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<P>> {
        assert_eq!(id, self.id);
        Some(TrackedPeers::primary(self.peers.clone()))
    }

    async fn subscribe(&mut self) -> UnboundedReceiver<PeerSetUpdate<P>> {
        let (sender, receiver) = mpsc::unbounded_channel();
        sender.send_lossy(PeerSetUpdate {
            index: self.id,
            latest: TrackedPeers::new(self.peers.clone(), Set::default()),
            all: TrackedPeers::new(self.peers.clone(), Set::default()),
        });
        self.senders.push(sender); // prevent the receiver from closing
        receiver
    }
}
