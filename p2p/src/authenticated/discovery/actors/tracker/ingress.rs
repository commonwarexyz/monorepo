use super::Reservation;
use crate::authenticated::{
    discovery::{
        actors::{peer, tracker::Metadata},
        types,
    },
    Mailbox,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Metrics, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// Messages that can be sent to the tracker actor.
pub enum Message<E: Spawner + Metrics, C: PublicKey> {
    // ---------- Used by oracle ----------
    /// Register a peer set at a given index.
    ///
    /// The vector of peers must be sorted in ascending order by public key.
    Register { index: u64, peers: Vec<C> },

    // ---------- Used by blocker ----------
    /// Block a peer, disconnecting them if currently connected and preventing future connections
    /// for as long as the peer remains in at least one active peer set.
    Block { public_key: C },

    // ---------- Used by peer ----------
    /// Notify the tracker that a peer has been successfully connected, and that a
    /// [types::Payload::Peers] message (containing solely the local node's information) should be
    /// sent to the peer.
    Connect {
        /// The public key of the peer.
        public_key: C,

        /// `true` if we are the dialer, `false` if we are the listener.
        dialer: bool,

        /// The mailbox of the peer actor.
        peer: Mailbox<peer::Message<C>>,
    },

    /// Ready to send a [types::Payload::BitVec] message to a peer. This message doubles as a
    /// keep-alive signal to the peer.
    ///
    /// This request is formed on a recurring interval.
    Construct {
        /// The public key of the peer.
        public_key: C,

        /// The mailbox of the peer actor.
        peer: Mailbox<peer::Message<C>>,
    },

    /// Notify the tracker that a [types::Payload::BitVec] message has been received from a peer.
    ///
    /// The tracker will construct a [types::Payload::Peers] message in response.
    BitVec {
        /// The bit vector received.
        bit_vec: types::BitVec,

        /// The mailbox of the peer actor.
        peer: Mailbox<peer::Message<C>>,
    },

    /// Notify the tracker that a [types::Payload::Peers] message has been received from a peer.
    Peers {
        /// The list of peers received.
        peers: Vec<types::PeerInfo<C>>,

        /// The mailbox of the peer actor.
        peer: Mailbox<peer::Message<C>>,
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
    pub async fn connect(&mut self, public_key: C, dialer: bool, peer: Mailbox<peer::Message<C>>) {
        self.send(Message::Connect {
            public_key,
            dialer,
            peer,
        })
        .await
        .unwrap();
    }

    /// Send a `Construct` message to the tracker.
    pub async fn construct(&mut self, public_key: C, peer: Mailbox<peer::Message<C>>) {
        self.send(Message::Construct { public_key, peer })
            .await
            .unwrap();
    }

    /// Send a `BitVec` message to the tracker.
    pub async fn bit_vec(&mut self, bit_vec: types::BitVec, peer: Mailbox<peer::Message<C>>) {
        self.send(Message::BitVec { bit_vec, peer }).await.unwrap();
    }

    /// Send a `Peers` message to the tracker.
    pub async fn peers(&mut self, peers: Vec<types::PeerInfo<C>>, peer: Mailbox<peer::Message<C>>) {
        self.send(Message::Peers { peers, peer }).await.unwrap();
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
        let Err(e) = self.sender.try_send(Message::Release { metadata }) else {
            return true;
        };
        assert!(
            e.is_full(),
            "Unexpected error trying to release reservation {:?}",
            e
        );
        false
    }

    /// Release a reservation.
    ///
    /// This method will block if the mailbox is full.
    pub async fn release(&mut self, metadata: Metadata<C>) {
        self.sender
            .send(Message::Release { metadata })
            .await
            .unwrap();
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
    /// These peer sets are used to construct a bit vector (sorted by public key)
    /// to share knowledge about dialable IPs. If a peer does not yet have an index
    /// associated with a bit vector, the discovery message will be dropped.
    ///
    /// # Parameters
    ///
    /// * `index` - Index of the set of authorized peers (like a blockchain height).
    ///   Should be monotonically increasing.
    /// * `peers` - Vector of authorized peers at an `index` (does not need to be sorted).
    pub async fn register(&mut self, index: u64, peers: Vec<C>) {
        let _ = self.sender.send(Message::Register { index, peers }).await;
    }
}

impl<E: Spawner + Metrics, C: PublicKey> crate::Blocker for Oracle<E, C> {
    type PublicKey = C;

    async fn block(&mut self, public_key: Self::PublicKey) {
        let _ = self.sender.send(Message::Block { public_key }).await;
    }
}
