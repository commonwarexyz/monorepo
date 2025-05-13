use super::Reservation;
use crate::authenticated::{actors::peer, types};
use commonware_cryptography::Verifier;
use commonware_runtime::{Metrics, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// Messages that can be sent to the tracker actor.
pub enum Message<E: Spawner + Metrics, C: Verifier> {
    // ---------- Used by oracle ----------
    /// Register a peer set at a given index.
    ///
    /// The vector of peers must be sorted in ascending order by public key.
    Register {
        index: u64,
        peers: Vec<C::PublicKey>,
    },

    // ---------- Used by blocker ----------
    /// Block a peer, disconnecting them if currently connected and preventing future connections
    /// for as long as the peer remains in at least one active peer set.
    Block { public_key: C::PublicKey },

    // ---------- Used by peer ----------
    /// Notify the tracker that a peer has been successfully connected, and that a
    /// [`types::Payload::Peers`] message (containing solely the local node's information) should be
    /// sent to the peer.
    Connect {
        /// The public key of the peer.
        public_key: C::PublicKey,

        /// `true` if we are the dialer, `false` if we are the listener.
        dialer: bool,

        /// The mailbox of the peer actor.
        peer: peer::Mailbox<C>,
    },

    /// Ready to send a [`types::Payload::BitVec`] message to a peer. This message doubles as a
    /// keep-alive signal to the peer.
    ///
    /// This request is formed on a recurring interval.
    Construct {
        /// The public key of the peer.
        public_key: C::PublicKey,

        /// The mailbox of the peer actor.
        peer: peer::Mailbox<C>,
    },

    /// Notify the tracker that a [`types::Payload::BitVec`] message has been received from a peer.
    ///
    /// The tracker will construct a [`types::Payload::Peers`] message in response.
    BitVec {
        /// The bit vector received.
        bit_vec: types::BitVec,

        /// The mailbox of the peer actor.
        peer: peer::Mailbox<C>,
    },

    /// Notify the tracker that a [`types::Payload::Peers`] message has been received from a peer.
    Peers {
        /// The list of peers received.
        peers: Vec<types::PeerInfo<C>>,

        /// The mailbox of the peer actor.
        peer: peer::Mailbox<C>,
    },

    // ---------- Used by dialer ----------
    /// Request a list of dialable peers.
    Dialable {
        /// One-shot channel to send the list of dialable peers.
        responder: oneshot::Sender<Vec<C::PublicKey>>,
    },

    /// Request a reservation for a particular peer to dial.
    ///
    /// The tracker will respond with an [`Option<Reservation<E, C>>`], which will be `None` if the
    /// reservation cannot be granted (e.g., if the peer is already connected, blocked or already
    /// has an active reservation).
    Dial {
        /// The public key of the peer to reserve.
        public_key: C::PublicKey,

        /// sender to respond with the reservation.
        reservation: oneshot::Sender<Option<Reservation<E, C::PublicKey>>>,
    },

    // ---------- Used by listener ----------
    /// Request a reservation for a particular peer.
    ///
    /// The tracker will respond with an [`Option<Reservation<E, C>>`], which will be `None` if  the
    /// reservation cannot be granted (e.g., if the peer is already connected, blocked or already
    /// has an active reservation).
    Listen {
        /// The public key of the peer to reserve.
        public_key: C::PublicKey,

        /// The sender to respond with the reservation.
        reservation: oneshot::Sender<Option<Reservation<E, C::PublicKey>>>,
    },
}

/// Mailbox for sending messages to the tracker actor.
#[derive(Clone)]
pub struct Mailbox<E: Spawner + Metrics, C: Verifier> {
    sender: mpsc::Sender<Message<E, C>>,
}

impl<E: Spawner + Metrics, C: Verifier> Mailbox<E, C> {
    /// Create a new mailbox for the tracker.
    pub(super) fn new(sender: mpsc::Sender<Message<E, C>>) -> Self {
        Self { sender }
    }

    /// Send a `Connect` message to the tracker.
    pub async fn connect(
        &mut self,
        public_key: C::PublicKey,
        dialer: bool,
        peer: peer::Mailbox<C>,
    ) {
        self.sender
            .send(Message::Connect {
                public_key,
                dialer,
                peer,
            })
            .await
            .unwrap();
    }

    /// Send a `Construct` message to the tracker.
    pub async fn construct(&mut self, public_key: C::PublicKey, peer: peer::Mailbox<C>) {
        self.sender
            .send(Message::Construct { public_key, peer })
            .await
            .unwrap();
    }

    /// Send a `BitVec` message to the tracker.
    pub async fn bit_vec(&mut self, bit_vec: types::BitVec, peer: peer::Mailbox<C>) {
        self.sender
            .send(Message::BitVec { bit_vec, peer })
            .await
            .unwrap();
    }

    /// Send a `Peers` message to the tracker.
    pub async fn peers(&mut self, peers: Vec<types::PeerInfo<C>>, peer: peer::Mailbox<C>) {
        self.sender
            .send(Message::Peers { peers, peer })
            .await
            .unwrap();
    }

    /// Send a `Block` message to the tracker.
    pub async fn dialable(&mut self) -> Vec<C::PublicKey> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Dialable { responder: sender })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    /// Send a `Dial` message to the tracker.
    pub async fn dial(&mut self, public_key: C::PublicKey) -> Option<Reservation<E, C::PublicKey>> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Message::Dial {
                public_key,
                reservation: tx,
            })
            .await
            .unwrap();
        rx.await.unwrap()
    }

    /// Send a `Listen` message to the tracker.
    pub async fn listen(
        &mut self,
        public_key: C::PublicKey,
    ) -> Option<Reservation<E, C::PublicKey>> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Message::Listen {
                public_key,
                reservation: tx,
            })
            .await
            .unwrap();
        rx.await.unwrap()
    }
}

/// Mechanism to register authorized peers.
///
/// Peers that are not explicitly authorized
/// will be blocked by commonware-p2p.
#[derive(Clone)]
pub struct Oracle<E: Spawner + Metrics, C: Verifier> {
    sender: mpsc::Sender<Message<E, C>>,
}

impl<E: Spawner + Metrics, C: Verifier> Oracle<E, C> {
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
    pub async fn register(&mut self, index: u64, peers: Vec<C::PublicKey>) {
        let _ = self.sender.send(Message::Register { index, peers }).await;
    }
}

impl<E: Spawner + Metrics, C: Verifier> crate::Blocker for Oracle<E, C> {
    type PublicKey = C::PublicKey;

    async fn block(&mut self, public_key: Self::PublicKey) {
        let _ = self.sender.send(Message::Block { public_key }).await;
    }
}
