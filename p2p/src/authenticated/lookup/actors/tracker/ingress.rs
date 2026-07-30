use super::Reservation;
use crate::{
    Advertisement, PeerEndpoint, PeerSetSubscription, Reachability, ReachableTrackedPeers,
    TrackedPeers,
    authenticated::{
        dialing::Dialable,
        lookup::actors::{peer, tracker::Metadata},
    },
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_cryptography::PublicKey;
use commonware_macros::stability;
use commonware_utils::{
    PlatformSend,
    channel::{mpsc, oneshot},
    ordered::Map,
};
use std::collections::VecDeque;

type DialReservation<C, E> = Option<(Reservation<C, E>, Advertisement<E>)>;

/// Messages that can be sent to the tracker actor.
#[derive(Debug)]
pub enum Message<C: PublicKey, E: PeerEndpoint = crate::Ingress> {
    // ---------- Used by oracle ----------
    /// Register a peer set at a given index.
    Register {
        index: u64,
        peers: ReachableTrackedPeers<C, E>,
    },

    /// Update addresses for multiple peers without creating a new peer set.
    Overwrite { peers: Map<C, Reachability<E>> },

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
        reservation: oneshot::Sender<DialReservation<C, E>>,
    },

    /// Reserve a connection established outside the autonomous transport actors.
    Attach {
        /// Authenticated peer identity.
        public_key: C,
        /// Whether the connection was accepted inbound.
        inbound: bool,
        /// Sender to respond with a reservation.
        reservation: oneshot::Sender<Option<Reservation<C, E>>>,
    },

    // ---------- Used by listener ----------
    /// Check if a peer is acceptable (can accept an incoming connection from them).
    Acceptable {
        /// The public key of the peer to check.
        public_key: C,

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

        /// The sender to respond with the reservation.
        reservation: oneshot::Sender<Option<Reservation<C, E>>>,
    },

    // ---------- Used by reservation ----------
    /// Release a reservation.
    Release {
        /// The metadata of the reservation to release.
        metadata: Metadata<C>,
    },
}

impl<C: PublicKey, E: PeerEndpoint> Policy for Message<C, E> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

/// Mailbox for sending messages to the tracker actor.
#[derive(Clone, Debug)]
pub struct Mailbox<C: PublicKey, E: PeerEndpoint = crate::Ingress>(mailbox::Sender<Message<C, E>>);

impl<C: PublicKey, E: PeerEndpoint> Mailbox<C, E> {
    pub(crate) const fn new(sender: mailbox::Sender<Message<C, E>>) -> Self {
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
    pub(crate) async fn dial(
        &self,
        public_key: C,
    ) -> Option<(Reservation<C, E>, Advertisement<E>)> {
        let (reservation, receiver) = oneshot::channel();
        let _ = self.0.enqueue(Message::Dial {
            public_key,
            reservation,
        });
        receiver.await.ok().flatten()
    }

    /// Reserve an externally established connection.
    pub(crate) async fn attach(&self, public_key: C, inbound: bool) -> Option<Reservation<C, E>> {
        let (reservation, receiver) = oneshot::channel();
        let _ = self.0.enqueue(Message::Attach {
            public_key,
            inbound,
            reservation,
        });
        receiver.await.ok().flatten()
    }

    /// Send an `Acceptable` message to the tracker.
    ///
    /// Returns `false` if the tracker is shut down.
    pub(crate) async fn acceptable(&self, public_key: C) -> bool {
        let (responder, receiver) = oneshot::channel();
        let _ = self.0.enqueue(Message::Acceptable {
            public_key,
            responder,
        });
        receiver.await.unwrap_or(false)
    }

    /// Send a `Listen` message to the tracker.
    ///
    /// Returns `None` if the tracker is shut down.
    pub(crate) async fn listen(&self, public_key: C) -> Option<Reservation<C, E>> {
        let (reservation, receiver) = oneshot::channel();
        let _ = self.0.enqueue(Message::Listen {
            public_key,
            reservation,
        });
        receiver.await.ok().flatten()
    }
}

/// Allows releasing reservations
#[derive(Clone, Debug)]
pub struct Releaser<C: PublicKey, E: PeerEndpoint = crate::Ingress> {
    sender: mailbox::Sender<Message<C, E>>,
}

impl<C: PublicKey, E: PeerEndpoint> Releaser<C, E> {
    /// Create a new releaser.
    pub(crate) const fn new(sender: mailbox::Sender<Message<C, E>>) -> Self {
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
pub struct Oracle<C: PublicKey, E: PeerEndpoint = crate::Ingress> {
    sender: mailbox::Sender<Message<C, E>>,
}

impl<C: PublicKey, E: PeerEndpoint> Oracle<C, E> {
    pub(super) const fn new(sender: mailbox::Sender<Message<C, E>>) -> Self {
        Self { sender }
    }
}

impl<C: PublicKey, E: PeerEndpoint> crate::Provider for Oracle<C, E> {
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

#[stability(ALPHA)]
impl<C: PublicKey, E: PeerEndpoint> crate::ReachabilityManager for Oracle<C, E> {
    type Endpoint = E;

    fn track<R>(&mut self, index: u64, peers: R) -> Feedback
    where
        R: Into<ReachableTrackedPeers<Self::PublicKey, E>> + PlatformSend,
    {
        self.sender.enqueue(Message::Register {
            index,
            peers: peers.into(),
        })
    }

    fn overwrite(&mut self, peers: Map<Self::PublicKey, Reachability<E>>) -> Feedback {
        self.sender.enqueue(Message::Overwrite { peers })
    }
}

impl<C: PublicKey> crate::AddressableManager for Oracle<C, crate::Ingress> {
    fn track<R>(&mut self, index: u64, peers: R) -> Feedback
    where
        R: Into<crate::AddressableTrackedPeers<Self::PublicKey>> + PlatformSend,
    {
        let peers = peers.into();
        self.sender.enqueue(Message::Register {
            index,
            peers: ReachableTrackedPeers::new(
                legacy_reachability(peers.primary),
                legacy_reachability(peers.secondary),
            ),
        })
    }

    fn overwrite(&mut self, peers: Map<Self::PublicKey, crate::Address>) -> Feedback {
        self.sender.enqueue(Message::Overwrite {
            peers: legacy_reachability(peers),
        })
    }
}

fn legacy_reachability<C: PublicKey>(
    peers: Map<C, crate::Address>,
) -> Map<C, Reachability<crate::Ingress>> {
    Map::from_iter_dedup(peers.into_iter().map(|(peer, address)| {
        let advertisement = Advertisement::new(vec![address.ingress()])
            .expect("a single endpoint is a valid advertisement");
        (peer, Reachability::Dialable(advertisement))
    }))
}

impl<C: PublicKey, E: PeerEndpoint> crate::Blocker for Oracle<C, E> {
    type PublicKey = C;

    fn block(&mut self, public_key: Self::PublicKey) -> Feedback {
        self.sender.enqueue(Message::Block { public_key })
    }
}
