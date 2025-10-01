use super::Reservation;
use crate::authenticated::{
    discovery::{
        actors::{peer, tracker::Metadata},
        types,
    },
    Mailbox,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Handle, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};

/// Messages that can be sent to the tracker actor.
pub enum Message<C: PublicKey> {
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
    /// The tracker will respond with an [Option<Reservation<C>>], which will be `None` if the
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
    /// The tracker will respond with an [Option<Reservation<C>>], which will be `None` if  the
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

impl<C: PublicKey> Mailbox<Message<C>> {
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
    pub async fn dial(&mut self, public_key: C) -> Option<Reservation<C>> {
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
    pub async fn listen(&mut self, public_key: C) -> Option<Reservation<C>> {
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

/// Owns the release worker for reservations.
pub struct Releaser<E: Spawner, C: PublicKey> {
    context: E,
    sender: mpsc::Sender<Message<C>>,
    backlog: mpsc::UnboundedReceiver<Metadata<C>>,
}

impl<E: Spawner, C: PublicKey> Releaser<E, C> {
    /// Creates a new releaser and associated handle for issuing release requests.
    pub(super) fn new(context: E, sender: mpsc::Sender<Message<C>>) -> (Self, ReleaserHandle<C>) {
        let (backlog_tx, backlog_rx) = mpsc::unbounded();
        let handle_sender = sender.clone();
        (
            Self {
                context,
                sender,
                backlog: backlog_rx,
            },
            ReleaserHandle {
                sender: handle_sender,
                backlog: backlog_tx,
            },
        )
    }

    /// Spawns the worker that drains the backlog and forwards releases to the tracker mailbox.
    pub(super) fn start(mut self) -> Handle<()> {
        self.context.spawn(|_| async move {
            while let Some(metadata) = self.backlog.next().await {
                if self
                    .sender
                    .send(Message::Release { metadata })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        })
    }
}

/// Handle used by reservations to request releases.
#[derive(Clone)]
pub struct ReleaserHandle<C: PublicKey> {
    sender: mpsc::Sender<Message<C>>,
    backlog: mpsc::UnboundedSender<Metadata<C>>,
}

impl<C: PublicKey> ReleaserHandle<C> {
    /// Releases a reservation, queueing it if the tracker mailbox is currently full.
    pub fn release(&mut self, metadata: Metadata<C>) {
        match self.sender.try_send(Message::Release {
            metadata: metadata.clone(),
        }) {
            Ok(()) => {}
            Err(e) if e.is_disconnected() => {}
            Err(e) if e.is_full() => {
                let _ = self.backlog.unbounded_send(metadata);
            }
            Err(_) => {}
        }
    }
}

/// Mechanism to register authorized peers.
///
/// Peers that are not explicitly authorized
/// will be blocked by commonware-p2p.
#[derive(Clone)]
pub struct Oracle<C: PublicKey> {
    sender: mpsc::Sender<Message<C>>,
}

impl<C: PublicKey> Oracle<C> {
    pub(super) fn new(sender: mpsc::Sender<Message<C>>) -> Self {
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

impl<C: PublicKey> crate::Blocker for Oracle<C> {
    type PublicKey = C;

    async fn block(&mut self, public_key: Self::PublicKey) {
        let _ = self.sender.send(Message::Block { public_key }).await;
    }
}
