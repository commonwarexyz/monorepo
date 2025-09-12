use super::Reservation;
use crate::authenticated::{
    lookup::actors::{peer, tracker::Metadata},
    Mailbox,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Metrics, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::net::SocketAddr;

/// Messages that can be sent to the tracker actor.
pub enum Message<E: Spawner + Metrics, C: PublicKey> {
    // ---------- Used by oracle ----------
    /// Register a peer set at a given index.
    Register {
        index: u64,
        peers: Vec<(C, SocketAddr)>,
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
    /// The tracker will respond with an [Option<Reservation<E, C>>], which will be `None` if the
    /// reservation cannot be granted (e.g., if the peer is already connected, blocked or already
    /// has an active reservation).
    Dial {
        /// The public key of the peer to reserve.
        public_key: C,

        /// sender to respond with the reservation.
        reservation: oneshot::Sender<Option<Reservation<E, C>>>,
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
    /// The tracker will respond with an [Option<Reservation<E, C>>], which will be `None` if  the
    /// reservation cannot be granted (e.g., if the peer is already connected, blocked or already
    /// has an active reservation).
    Listen {
        /// The public key of the peer to reserve.
        public_key: C,

        /// The sender to respond with the reservation.
        reservation: oneshot::Sender<Option<Reservation<E, C>>>,
    },

    // ---------- Used by reservation ----------
    /// Release a reservation.
    Release {
        /// The metadata of the reservation to release.
        metadata: Metadata<C>,
    },
}

impl<E: Spawner + Metrics, C: PublicKey> Mailbox<Message<E, C>> {
    /// Send a `Connect` message to the tracker.
    pub async fn connect(&mut self, public_key: C, peer: Mailbox<peer::Message>) {
        self.send(Message::Connect { public_key, peer })
            .await
            .unwrap();
    }

    /// Send a `Block` message to the tracker.
    pub async fn dialable(&mut self) -> Vec<C> {
        let (sender, receiver) = oneshot::channel();
        self.send(Message::Dialable { responder: sender })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    /// Send a `Dial` message to the tracker.
    pub async fn dial(&mut self, public_key: C) -> Option<Reservation<E, C>> {
        let (tx, rx) = oneshot::channel();
        self.send(Message::Dial {
            public_key,
            reservation: tx,
        })
        .await
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
        .await
        .unwrap();
        rx.await.unwrap()
    }

    /// Send a `Listen` message to the tracker.
    pub async fn listen(&mut self, public_key: C) -> Option<Reservation<E, C>> {
        let (tx, rx) = oneshot::channel();
        self.send(Message::Listen {
            public_key,
            reservation: tx,
        })
        .await
        .unwrap();
        rx.await.unwrap()
    }
}

/// Allows releasing reservations
#[derive(Clone)]
pub struct Releaser<E: Spawner + Metrics, C: PublicKey> {
    sender: mpsc::Sender<Message<E, C>>,
}

impl<E: Spawner + Metrics, C: PublicKey> Releaser<E, C> {
    /// Create a new releaser.
    pub(super) fn new(sender: mpsc::Sender<Message<E, C>>) -> Self {
        Self { sender }
    }

    /// Try to release a reservation.
    ///
    /// Returns `true` if the reservation was released, `false` if the mailbox is full.
    pub fn try_release(&mut self, metadata: Metadata<C>) -> bool {
        match self.sender.try_send(Message::Release { metadata }) {
            Ok(()) => true,
            Err(e) if e.is_full() => false,
            // If receiver is gone (shutdown), consider reservation released.
            Err(e) if e.is_disconnected() => true,
            Err(_e) => false,
        }
    }

    /// Release a reservation.
    ///
    /// This method will block if the mailbox is full.
    pub async fn release(&mut self, metadata: Metadata<C>) {
        // Ignore errors if receiver is gone (shutdown in progress)
        let _ = self.sender.send(Message::Release { metadata }).await;
    }
}

/// Mechanism to register authorized peers.
///
/// Peers that are not explicitly authorized
/// will be blocked by commonware-p2p.
#[derive(Clone)]
pub struct Oracle<E: Spawner + Metrics, C: PublicKey> {
    sender: mpsc::Sender<Message<E, C>>,
}

impl<E: Spawner + Metrics, C: PublicKey> Oracle<E, C> {
    pub(super) fn new(sender: mpsc::Sender<Message<E, C>>) -> Self {
        Self { sender }
    }

    /// Register a set of authorized peers at a given index.
    ///
    /// # Parameters
    ///
    /// * `index` - Index of the set of authorized peers (like a blockchain height).
    ///   Should be monotonically increasing.
    /// * `peers` - Vector of authorized peers at an `index` (does not need to be sorted).
    ///   Each element is a tuple containing the public key and the socket address of the peer.
    pub async fn register(&mut self, index: u64, peers: Vec<(C, SocketAddr)>) {
        let _ = self.sender.send(Message::Register { index, peers }).await;
    }
}

impl<E: Spawner + Metrics, C: PublicKey> crate::Blocker for Oracle<E, C> {
    type PublicKey = C;

    async fn block(&mut self, public_key: Self::PublicKey) {
        let _ = self.sender.send(Message::Block { public_key }).await;
    }
}
