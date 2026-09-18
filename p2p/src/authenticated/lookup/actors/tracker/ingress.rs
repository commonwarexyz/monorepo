use super::Reservation;
use crate::{
    AddressableTrackedPeers, BlockedSubscription, Ingress, PeerSetSubscription, TrackedPeers,
    authenticated::{
        dialing::Dialable,
        lookup::actors::{peer, tracker::Metadata},
    },
    sizing::peer_set_size,
    types::Address,
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_cryptography::PublicKey;
use commonware_utils::{
    NZUsize,
    channel::{mpsc, oneshot, ring},
    ordered::{Map, Set},
};
use std::{collections::VecDeque, net::IpAddr};

/// Messages that can be sent to the tracker actor.
#[derive(Debug)]
pub enum Message<C: PublicKey> {
    // ---------- Used by oracle ----------
    /// Register a peer set at a given index.
    Register {
        index: u64,
        peers: AddressableTrackedPeers<C>,
    },

    /// Update addresses for multiple peers without creating a new peer set.
    Overwrite { peers: Map<C, Address> },

    // ---------- Used by peer set provider ----------
    /// Fetch primary and secondary peers for a given ID.
    PeerSet {
        /// The index of the peer set to fetch.
        index: u64,
        /// One-shot channel to send the tracked peers.
        responder: oneshot::Sender<Option<TrackedPeers<C>>>,
    },
    /// Subscribe to notifications when new peer sets are added.
    Subscribe {
        /// One-shot channel to send the subscription receiver.
        responder: oneshot::Sender<PeerSetSubscription<C>>,
    },

    // ---------- Used by blocker ----------
    /// Block a peer, disconnecting them if currently connected and preventing future connections
    /// for as long as the peer remains in at least one active peer set.
    Block { public_key: C },
    /// Subscribe to the set of peers this node currently blocks.
    SubscribeBlocked { sender: ring::Sender<Set<C>> },

    // ---------- Used by peer ----------
    /// Notify the tracker that a peer has been successfully connected.
    Connect {
        /// The public key of the peer.
        public_key: C,

        /// The mailbox of the peer actor.
        peer: peer::Mailbox,
    },

    // ---------- Used by dialer ----------
    /// Request a list of dialable peers.
    Dialable {
        /// One-shot channel to send the dialable peers and next query deadline.
        responder: oneshot::Sender<Dialable<C>>,
    },

    /// Request a reservation for a particular peer to dial.
    ///
    /// The tracker will respond with an [`Option<(Reservation<C>, Ingress)>`], which will be
    /// `None` if the reservation cannot be granted (e.g., if the peer is already connected,
    /// blocked or already has an active reservation).
    Dial {
        /// The public key of the peer to reserve.
        public_key: C,

        /// Sender to respond with the reservation and ingress address.
        reservation: oneshot::Sender<Option<(Reservation<C>, Ingress)>>,
    },

    // ---------- Used by listener ----------
    /// Check if a peer is acceptable (can accept an incoming connection from them).
    Acceptable {
        /// The public key of the peer to check.
        public_key: C,

        /// The IP address the peer connected from.
        source_ip: IpAddr,

        /// The sender to respond with whether the peer is acceptable.
        responder: oneshot::Sender<bool>,
    },

    /// Request a reservation for a particular peer.
    ///
    /// The tracker will respond with an [`Option<Reservation<C>>`], which will be `None` if  the
    /// reservation cannot be granted (e.g., if the peer is already connected, blocked or already
    /// has an active reservation).
    Listen {
        /// The public key of the peer to reserve.
        public_key: C,

        /// The IP address the peer connected from.
        source_ip: IpAddr,

        /// The sender to respond with the reservation.
        reservation: oneshot::Sender<Option<Reservation<C>>>,
    },

    // ---------- Used by reservation ----------
    /// Release a reservation.
    Release {
        /// The metadata of the reservation to release.
        metadata: Metadata<C>,
    },
}

impl<C: PublicKey> Policy for Message<C> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

/// Mailbox for sending messages to the tracker actor.
#[derive(Clone, Debug)]
pub struct Mailbox<C: PublicKey>(mailbox::Sender<Message<C>>);

impl<C: PublicKey> Mailbox<C> {
    pub(crate) const fn new(sender: mailbox::Sender<Message<C>>) -> Self {
        Self(sender)
    }

    /// Send a `Connect` message to the tracker.
    pub(crate) fn connect(&self, public_key: C, peer: peer::Mailbox) -> Feedback {
        self.0.enqueue(Message::Connect { public_key, peer })
    }

    /// Request dialable peers from the tracker.
    ///
    /// Returns an empty response if the tracker is shut down.
    pub(crate) async fn dialable(&self) -> Dialable<C> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.0.enqueue(Message::Dialable { responder });
        receiver.await.unwrap_or_default()
    }

    /// Send a `Dial` message to the tracker.
    ///
    /// Returns `None` if the tracker is shut down.
    pub(crate) async fn dial(&self, public_key: C) -> Option<(Reservation<C>, Ingress)> {
        let (reservation, receiver) = oneshot::channel();
        let _ = self.0.enqueue(Message::Dial {
            public_key,
            reservation,
        });
        receiver.await.ok().flatten()
    }

    /// Send an `Acceptable` message to the tracker.
    ///
    /// Returns `false` if the tracker is shut down.
    pub(crate) async fn acceptable(&self, public_key: C, source_ip: IpAddr) -> bool {
        let (responder, receiver) = oneshot::channel();
        let _ = self.0.enqueue(Message::Acceptable {
            public_key,
            source_ip,
            responder,
        });
        receiver.await.unwrap_or(false)
    }

    /// Send a `Listen` message to the tracker.
    ///
    /// Returns `None` if the tracker is shut down.
    pub(crate) async fn listen(&self, public_key: C, source_ip: IpAddr) -> Option<Reservation<C>> {
        let (reservation, receiver) = oneshot::channel();
        let _ = self.0.enqueue(Message::Listen {
            public_key,
            source_ip,
            reservation,
        });
        receiver.await.ok().flatten()
    }
}

/// Allows releasing reservations
#[derive(Clone, Debug)]
pub struct Releaser<C: PublicKey> {
    sender: mailbox::Sender<Message<C>>,
}

impl<C: PublicKey> Releaser<C> {
    /// Create a new releaser.
    pub(crate) const fn new(sender: mailbox::Sender<Message<C>>) -> Self {
        Self { sender }
    }

    /// Release a reservation.
    pub fn release(&mut self, metadata: Metadata<C>) -> Feedback {
        self.sender.enqueue(Message::Release { metadata })
    }
}

/// Mechanism to register authorized peers.
///
/// Peers that are not explicitly authorized
/// will be blocked by commonware-p2p.
#[derive(Debug, Clone)]
pub struct Oracle<C: PublicKey> {
    sender: mailbox::Sender<Message<C>>,
    local: C,
    max_peers_per_set: usize,
}

impl<C: PublicKey> Oracle<C> {
    pub(super) const fn new(
        sender: mailbox::Sender<Message<C>>,
        local: C,
        max_peers_per_set: usize,
    ) -> Self {
        Self {
            sender,
            local,
            max_peers_per_set,
        }
    }

    /// The bounded channel capacities are derived from `max_peers_per_set`, so enforce the bound
    /// before enqueueing an update that would violate that sizing invariant.
    fn assert_peer_set_size(&self, peers: &AddressableTrackedPeers<C>) {
        let peer_count = peer_set_size(
            peers.primary.keys().iter(),
            peers.secondary.keys().iter(),
            Some(&self.local),
        );
        assert!(
            peer_count <= self.max_peers_per_set,
            "peer set too large: {peer_count} > {}",
            self.max_peers_per_set
        );
    }
}

impl<C: PublicKey> crate::Provider for Oracle<C> {
    type PublicKey = C;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::PeerSet {
            index: id,
            responder,
        });
        receiver.await.ok().flatten()
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
        let (responder, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Subscribe { responder });
        receiver.await.unwrap_or_else(|_| {
            let (_, rx) = mpsc::unbounded_channel();
            rx
        })
    }
}

impl<C: PublicKey> crate::AddressableManager for Oracle<C> {
    fn track<R>(&mut self, index: u64, peers: R) -> Feedback
    where
        R: Into<AddressableTrackedPeers<Self::PublicKey>> + Send,
    {
        let peers = peers.into();
        self.assert_peer_set_size(&peers);
        self.sender.enqueue(Message::Register { index, peers })
    }

    fn overwrite(&mut self, peers: Map<Self::PublicKey, Address>) -> Feedback {
        self.sender.enqueue(Message::Overwrite { peers })
    }
}

impl<C: PublicKey> crate::Blocker for Oracle<C> {
    type PublicKey = C;

    fn block(&mut self, public_key: Self::PublicKey) -> Feedback {
        self.sender.enqueue(Message::Block { public_key })
    }

    fn blocked(&mut self) -> BlockedSubscription<Self::PublicKey> {
        let (sender, receiver) = ring::channel(NZUsize!(1));
        let _ = self.sender.enqueue(Message::SubscribeBlocked { sender });
        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AddressableManager as _;
    use commonware_cryptography::{
        Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_utils::{NZUsize, ordered::Map};
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    #[should_panic(expected = "peer set too large: 3 > 2")]
    fn test_peer_set_limit_includes_local_identity() {
        let local = PrivateKey::from_seed(0).public_key();
        let (sender, _receiver) =
            mailbox::new::<Message<PublicKey>>(crate::utils::mocks::Metrics, NZUsize!(1));
        let mut oracle = Oracle::new(sender, local, 2);
        let peer_1 = PrivateKey::from_seed(1).public_key();
        let peer_2 = PrivateKey::from_seed(2).public_key();
        let addr_1 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1001);
        let addr_2 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1002);
        let peers = AddressableTrackedPeers::new(
            Map::try_from([(peer_1, addr_1.into())]).unwrap(),
            Map::try_from([(peer_2, addr_2.into())]).unwrap(),
        );

        oracle.track(0, peers);
    }
}
