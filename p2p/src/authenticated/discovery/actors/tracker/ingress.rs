use super::Reservation;
use crate::authenticated::{
    discovery::{
        actors::{peer, tracker::Metadata},
        types,
    },
    mailbox::UnboundedMailbox,
    Mailbox,
};
use commonware_cryptography::PublicKey;
use commonware_utils::ordered::Set;
use futures::channel::{mpsc, oneshot};

/// Messages that can be sent to the tracker actor.
#[derive(Debug)]
pub enum Message<C: PublicKey> {
    // ---------- Used by oracle ----------
    /// Register a peer set at a given index.
    Register { index: u64, peers: Set<C> },

    // ---------- Used by peer set provider ----------
    /// Fetch the peer set at a given index.
    PeerSet {
        /// The index of the peer set to fetch.
        index: u64,
        /// One-shot channel to send the peer set.
        responder: oneshot::Sender<Option<Set<C>>>,
    },
    /// Subscribe to notifications when new peer sets are added.
    Subscribe {
        /// One-shot channel to send the subscription receiver.
        #[allow(clippy::type_complexity)]
        responder: oneshot::Sender<mpsc::UnboundedReceiver<(u64, Set<C>, Set<C>)>>,
    },

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
        peers: Vec<types::Info<C>>,
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
    pub async fn connect(&mut self, public_key: C, dialer: bool, peer: Mailbox<peer::Message<C>>) {
        self.send(Message::Connect {
            public_key,
            dialer,
            peer,
        })
        .unwrap();
    }

    /// Send a `Construct` message to the tracker.
    pub fn construct(&mut self, public_key: C, peer: Mailbox<peer::Message<C>>) {
        self.send(Message::Construct { public_key, peer }).unwrap();
    }

    /// Send a `BitVec` message to the tracker.
    pub fn bit_vec(&mut self, bit_vec: types::BitVec, peer: Mailbox<peer::Message<C>>) {
        self.send(Message::BitVec { bit_vec, peer }).unwrap();
    }

    /// Send a `Peers` message to the tracker.
    pub fn peers(&mut self, peers: Vec<types::Info<C>>) {
        self.send(Message::Peers { peers }).unwrap();
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
    pub(super) const fn new(sender: UnboundedMailbox<Message<C>>) -> Self {
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
#[derive(Debug, Clone)]
pub struct Oracle<C: PublicKey> {
    sender: UnboundedMailbox<Message<C>>,
}

impl<C: PublicKey> Oracle<C> {
    pub(super) const fn new(sender: UnboundedMailbox<Message<C>>) -> Self {
        Self { sender }
    }
}

impl<C: PublicKey> crate::Manager for Oracle<C> {
    type PublicKey = C;
    type Peers = Set<C>;

    /// Register a set of authorized peers at a given index.
    ///
    /// These peer sets are used to construct a bit vector (sorted by public key)
    /// to share knowledge about dialable IPs. If a peer does not yet have an index
    /// associated with a bit vector, the discovery message will be dropped.
    ///
    /// # Parameters
    ///
    /// * `index` - Index of the set of authorized peers (like a blockchain height).
    ///   Must be monotonically increasing, per the rules of [Set].
    /// * `peers` - Vector of authorized peers at an `index` (does not need to be sorted).
    async fn update(&mut self, index: u64, peers: Self::Peers) {
        let _ = self.sender.send(Message::Register { index, peers });
    }

    async fn peer_set(&mut self, id: u64) -> Option<Set<Self::PublicKey>> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::PeerSet {
                index: id,
                responder: sender,
            })
            .unwrap();
        receiver.await.unwrap()
    }

    async fn subscribe(
        &mut self,
    ) -> mpsc::UnboundedReceiver<(u64, Set<Self::PublicKey>, Set<Self::PublicKey>)> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Subscribe { responder: sender })
            .unwrap();
        receiver.await.unwrap()
    }
}

impl<C: PublicKey> crate::Blocker for Oracle<C> {
    type PublicKey = C;

    async fn block(&mut self, public_key: Self::PublicKey) {
        let _ = self.sender.send(Message::Block { public_key });
    }
}
