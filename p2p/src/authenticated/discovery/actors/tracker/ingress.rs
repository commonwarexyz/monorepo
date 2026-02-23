use super::Reservation;
use crate::{
    authenticated::{
        discovery::{
            actors::{peer, tracker::Metadata},
            types,
        },
        mailbox::UnboundedMailbox,
        Mailbox,
    },
    PeerSetSubscription,
};
use commonware_cryptography::PublicKey;
use commonware_utils::{
    channel::{fallible::FallibleExt, mpsc, oneshot},
    ordered::Set,
};

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
        responder: oneshot::Sender<PeerSetSubscription<C>>,
    },

    // ---------- Used by blocker ----------
    /// Block a peer, disconnecting them if currently connected and preventing future connections
    /// for as long as the peer remains in at least one active peer set.
    Block { public_key: C },

    // ---------- Used by peer ----------
    /// Notify the tracker that a peer has been successfully connected.
    ///
    /// The tracker responds with the greeting info that must be sent to the peer
    /// before any other messages. If the peer is not eligible, the channel is dropped
    /// (signaling termination).
    Connect {
        /// The public key of the peer.
        public_key: C,

        /// `true` if we are the dialer, `false` if we are the listener.
        dialer: bool,

        /// One-shot channel to return the greeting info. Dropped if peer is not eligible.
        responder: oneshot::Sender<types::Info<C>>,
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
    /// Send a `Connect` message to the tracker and receive the greeting info.
    ///
    /// Returns `Some(info)` if the peer is eligible, `None` if the channel was
    /// dropped (peer not eligible or tracker shut down).
    pub async fn connect(&mut self, public_key: C, dialer: bool) -> Option<types::Info<C>> {
        self.0
            .request(|responder| Message::Connect {
                public_key,
                dialer,
                responder,
            })
            .await
    }

    /// Send a `Construct` message to the tracker.
    pub fn construct(&mut self, public_key: C, peer: Mailbox<peer::Message<C>>) {
        self.0.send_lossy(Message::Construct { public_key, peer });
    }

    /// Send a `BitVec` message to the tracker.
    pub fn bit_vec(&mut self, bit_vec: types::BitVec, peer: Mailbox<peer::Message<C>>) {
        self.0.send_lossy(Message::BitVec { bit_vec, peer });
    }

    /// Send a `Peers` message to the tracker.
    pub fn peers(&mut self, peers: Vec<types::Info<C>>) {
        self.0.send_lossy(Message::Peers { peers });
    }

    /// Request a list of dialable peers from the tracker.
    ///
    /// Returns an empty list if the tracker is shut down.
    pub async fn dialable(&mut self) -> Vec<C> {
        self.0
            .request_or_default(|responder| Message::Dialable { responder })
            .await
    }

    /// Send a `Dial` message to the tracker.
    ///
    /// Returns `None` if the tracker is shut down.
    pub async fn dial(&mut self, public_key: C) -> Option<Reservation<C>> {
        self.0
            .request(|reservation| Message::Dial {
                public_key,
                reservation,
            })
            .await
            .flatten()
    }

    /// Send an `Acceptable` message to the tracker.
    ///
    /// Returns `false` if the tracker is shut down.
    pub async fn acceptable(&mut self, public_key: C) -> bool {
        self.0
            .request_or(
                |responder| Message::Acceptable {
                    public_key,
                    responder,
                },
                false,
            )
            .await
    }

    /// Send a `Listen` message to the tracker.
    ///
    /// Returns `None` if the tracker is shut down.
    pub async fn listen(&mut self, public_key: C) -> Option<Reservation<C>> {
        self.0
            .request(|reservation| Message::Listen {
                public_key,
                reservation,
            })
            .await
            .flatten()
    }
}

/// Allows releasing reservations
#[derive(Clone, Debug)]
pub struct Releaser<C: PublicKey> {
    sender: UnboundedMailbox<Message<C>>,
}

impl<C: PublicKey> Releaser<C> {
    /// Create a new releaser.
    pub(crate) const fn new(sender: UnboundedMailbox<Message<C>>) -> Self {
        Self { sender }
    }

    /// Release a reservation.
    pub fn release(&mut self, metadata: Metadata<C>) {
        self.sender.0.send_lossy(Message::Release { metadata });
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

impl<C: PublicKey> crate::Provider for Oracle<C> {
    type PublicKey = C;

    async fn peer_set(&mut self, id: u64) -> Option<Set<Self::PublicKey>> {
        self.sender
            .0
            .request(|responder| Message::PeerSet {
                index: id,
                responder,
            })
            .await
            .flatten()
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
        self.sender
            .0
            .request(|responder| Message::Subscribe { responder })
            .await
            .unwrap_or_else(|| {
                let (_, rx) = mpsc::unbounded_channel();
                rx
            })
    }
}

impl<C: PublicKey> crate::Manager for Oracle<C> {
    async fn track(&mut self, index: u64, peers: Set<Self::PublicKey>) {
        self.sender.0.send_lossy(Message::Register { index, peers });
    }
}

impl<C: PublicKey> crate::Blocker for Oracle<C> {
    type PublicKey = C;

    async fn block(&mut self, public_key: Self::PublicKey) {
        self.sender.0.send_lossy(Message::Block { public_key });
    }
}
