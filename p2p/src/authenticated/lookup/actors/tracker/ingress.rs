use super::Reservation;
use crate::authenticated::{
    lookup::actors::{peer, tracker::Metadata},
    mailbox::UnboundedMailbox,
    Mailbox,
};
use commonware_cryptography::PublicKey;
use commonware_utils::set::OrderedAssociated;
use futures::channel::oneshot;
use std::net::SocketAddr;

/// Messages that can be sent to the tracker actor.
pub enum Message<C: PublicKey> {
    // ---------- Used by oracle ----------
    /// Register a peer set at a given index.
    Register {
        index: u64,
        peers: OrderedAssociated<C, SocketAddr>,
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
        peer: Mailbox<peer::Message>,
    },

    // ---------- Used by dialer ----------
    /// Request a list of dialable peers.
    Dialable {
        /// One-shot channel to send the list of dialable peers.
        responder: oneshot::Sender<Vec<C>>,
    },

    /// Request a reservation for a particular peer to dial.
    ///
    /// The tracker will respond with an [`Option<Reservation<C>>`], which will be `None` if the
    /// reservation cannot be granted (e.g., if the peer is already connected, blocked or already
    /// has an active reservation).
    Dial {
        /// The public key of the peer to reserve.
        public_key: C,

        /// sender to respond with the reservation.
        reservation: oneshot::Sender<Option<Reservation<C>>>,
    },

    // ---------- Used by listener ----------
    /// Check if we should listen to a peer.
    Listenable {
        /// The public key of the peer to check.
        public_key: C,

        /// The sender to respond with the listenable status.
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
        reservation: oneshot::Sender<Option<Reservation<C>>>,
    },

    // ---------- Used by reservation ----------
    /// Release a reservation.
    Release {
        /// The metadata of the reservation to release.
        metadata: Metadata<C>,
    },
}

impl<C: PublicKey> UnboundedMailbox<Message<C>> {
    /// Send a `Connect` message to the tracker.
    pub fn connect(&mut self, public_key: C, peer: Mailbox<peer::Message>) {
        self.send(Message::Connect { public_key, peer }).unwrap();
    }

    /// Send a `Block` message to the tracker.
    pub async fn dialable(&mut self) -> Vec<C> {
        let (sender, receiver) = oneshot::channel();
        self.send(Message::Dialable { responder: sender }).unwrap();
        receiver.await.unwrap()
    }

    /// Send a `Dial` message to the tracker.
    pub async fn dial(&mut self, public_key: C) -> Option<Reservation<C>> {
        let (tx, rx) = oneshot::channel();
        self.send(Message::Dial {
            public_key,
            reservation: tx,
        })
        .unwrap();
        rx.await.unwrap()
    }

    /// Send a `Listenable` message to the tracker.
    pub async fn listenable(&mut self, public_key: C) -> bool {
        let (tx, rx) = oneshot::channel();
        self.send(Message::Listenable {
            public_key,
            responder: tx,
        })
        .unwrap();
        rx.await.unwrap()
    }

    /// Send a `Listen` message to the tracker.
    pub async fn listen(&mut self, public_key: C) -> Option<Reservation<C>> {
        let (tx, rx) = oneshot::channel();
        self.send(Message::Listen {
            public_key,
            reservation: tx,
        })
        .unwrap();
        rx.await.unwrap()
    }
}

/// Allows releasing reservations
#[derive(Clone)]
pub struct Releaser<C: PublicKey> {
    sender: UnboundedMailbox<Message<C>>,
}

impl<C: PublicKey> Releaser<C> {
    /// Create a new releaser.
    pub(super) fn new(sender: UnboundedMailbox<Message<C>>) -> Self {
        Self { sender }
    }

    /// Release a reservation.
    pub fn release(&mut self, metadata: Metadata<C>) {
        let _ = self.sender.send(Message::Release { metadata });
    }
}

/// Mechanism to register authorized peers.
///
/// Peers that are not explicitly authorized
/// will be blocked by commonware-p2p.
#[derive(Clone)]
pub struct Oracle<C: PublicKey> {
    sender: UnboundedMailbox<Message<C>>,
}

impl<C: PublicKey> Oracle<C> {
    pub(super) fn new(sender: UnboundedMailbox<Message<C>>) -> Self {
        Self { sender }
    }

    /// Register a set of authorized peers at a given index.
    ///
    /// # Parameters
    ///
    /// * `index` - Index of the set of authorized peers (like a blockchain height).
    ///   Should be monotonically increasing.
    /// * `peers` - Vector of authorized peers at an `index`.
    ///   Each element is a tuple containing the public key and the socket address of the peer.
    ///   The peer must be dialable at and dial from the given socket address.
    pub async fn register(&mut self, index: u64, peers: OrderedAssociated<C, SocketAddr>) {
        let _ = self.sender.send(Message::Register { index, peers });
    }
}

impl<C: PublicKey> crate::Blocker for Oracle<C> {
    type PublicKey = C;

    async fn block(&mut self, public_key: Self::PublicKey) {
        let _ = self.sender.send(Message::Block { public_key });
    }
}
