use super::Reservation;
use crate::{
    authenticated::{
        dialing::Dialable,
        discovery::{
            actors::{dialer, listener, peer, spawner, tracker::Metadata},
            types,
        },
        Mailbox,
    },
    PeerSetSubscription, TrackedPeers,
};
use commonware_cryptography::PublicKey;
use commonware_utils::{
    channel::{
        actor::{self, MessagePolicy}, Feedback,
        ring, oneshot,
    },
    NZUsize,
};
use std::collections::VecDeque;

/// Messages that can be sent to the tracker actor.
#[derive(Debug)]
pub(crate) enum Message<C: PublicKey> {
    // ---------- Used by oracle ----------
    /// Register a peer set at a given index.
    Register { index: u64, peers: TrackedPeers<C> },

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
    ConnectForSpawner {
        /// The public key of the peer.
        public_key: C,

        /// `true` if we are the dialer, `false` if we are the listener.
        dialer: bool,

        /// The spawner task mailbox that should receive the response.
        spawner: Mailbox<spawner::Connect<C>>,
    },

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
    /// Request a list of dialable peers for the dialer actor.
    DialableForDialer {
        /// The dialer mailbox that should receive the response.
        dialer: Mailbox<dialer::Message<C>>,
    },

    /// Request a list of dialable peers.
    Dialable {
        /// One-shot channel to send the dialable peers and next query deadline.
        responder: oneshot::Sender<Dialable<C>>,
    },

    /// Request a reservation for a particular peer to dial and send the response to the dialer.
    DialForDialer {
        /// The public key of the peer to reserve.
        public_key: C,

        /// The dialer mailbox that should receive the response.
        dialer: Mailbox<dialer::Message<C>>,
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
    AcceptableForListener {
        /// The public key of the peer to check.
        public_key: C,

        /// The listener mailbox that should receive the response.
        listener: Mailbox<listener::Message<C>>,
    },

    /// Check if a peer is acceptable (can accept an incoming connection from them).
    Acceptable {
        /// The public key of the peer to check.
        public_key: C,

        /// The sender to respond with whether the peer is acceptable.
        responder: oneshot::Sender<bool>,
    },

    /// Request a reservation for a particular peer.
    ListenForListener {
        /// The public key of the peer to reserve.
        public_key: C,

        /// The listener mailbox that should receive the response.
        listener: Mailbox<listener::Message<C>>,
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

impl<C: PublicKey> MessagePolicy for Message<C> {
    fn backpressure(queue: &mut VecDeque<Self>, message: Self) -> Feedback {
        actor::replace_or_retain(match message {
            Self::Register { index, peers } => actor::replace_last(
                queue,
                Self::Register { index, peers },
                |pending| matches!(pending, Self::Register { index: pending, .. } if *pending == index),
            ),
            Self::Block { public_key } => {
                let expected = public_key.clone();
                actor::replace_last(
                    queue,
                    Self::Block { public_key },
                    |pending| matches!(pending, Self::Block { public_key: pending } if pending == &expected),
                )
            }
            Self::Construct { public_key, peer } => {
                let expected = public_key.clone();
                actor::replace_last(
                    queue,
                    Self::Construct { public_key, peer },
                    |pending| matches!(pending, Self::Construct { public_key: pending, .. } if pending == &expected),
                )
            }
            Self::BitVec { bit_vec, peer } => actor::replace_last(
                queue,
                Self::BitVec { bit_vec, peer },
                |pending| matches!(pending, Self::BitVec { .. }),
            ),
            Self::Peers { peers } => actor::replace_last(
                queue,
                Self::Peers { peers },
                |pending| matches!(pending, Self::Peers { .. }),
            ),
            Self::DialableForDialer { dialer } => actor::replace_last(
                queue,
                Self::DialableForDialer { dialer },
                |pending| matches!(pending, Self::DialableForDialer { .. }),
            ),
            Self::Release { metadata } => {
                let expected = metadata.public_key().clone();
                actor::replace_last(
                    queue,
                    Self::Release { metadata },
                    |pending| matches!(pending, Self::Release { metadata } if metadata.public_key() == &expected),
                )
            }
            message => Err(message),
        }, queue)
    }
}

impl<C: PublicKey> Mailbox<Message<C>> {
    /// Send a `Connect` message to the tracker and receive the greeting info.
    ///
    /// Returns `Some(info)` if the peer is eligible, `None` if the channel was
    /// dropped (peer not eligible or tracker shut down).
    pub async fn connect(&self, public_key: C, dialer: bool) -> Option<types::Info<C>> {
        let (responder, receiver) = oneshot::channel();
        match self.enqueue(Message::Connect {
            public_key,
            dialer,
            responder,
        }) {
            Feedback::Ok | Feedback::Backoff => receiver.await.ok(),
            Feedback::Dropped | Feedback::Closed => None,
        }
    }

    /// Send a `Connect` message to the tracker and send the response to the spawner task.
    pub fn request_connect(
        &self,
        public_key: C,
        dialer: bool,
        spawner: Mailbox<spawner::Connect<C>>,
    ) -> Feedback {
        self.enqueue(Message::ConnectForSpawner {
            public_key,
            dialer,
            spawner,
        })
    }

    /// Send a `Construct` message to the tracker.
    pub fn construct(&self, public_key: C, peer: Mailbox<peer::Message<C>>) -> Feedback {
        self.enqueue(Message::Construct { public_key, peer })
    }

    /// Send a `BitVec` message to the tracker.
    pub fn bit_vec(
        &self,
        bit_vec: types::BitVec,
        peer: Mailbox<peer::Message<C>>,
    ) -> Feedback {
        self.enqueue(Message::BitVec { bit_vec, peer })
    }

    /// Send a `Peers` message to the tracker.
    pub fn peers(&self, peers: Vec<types::Info<C>>) -> Feedback {
        self.enqueue(Message::Peers { peers })
    }

    /// Request dialable peers from the tracker and send the response to the dialer actor.
    pub fn request_dialable(&self, dialer: Mailbox<dialer::Message<C>>) -> Feedback {
        self.enqueue(Message::DialableForDialer { dialer })
    }

    /// Request a dial reservation from the tracker and send the response to the dialer actor.
    pub fn request_dial(
        &self,
        public_key: C,
        dialer: Mailbox<dialer::Message<C>>,
    ) -> Feedback {
        self.enqueue(Message::DialForDialer { public_key, dialer })
    }

    /// Request an acceptable-peer decision from the tracker and send the response to the listener.
    pub fn request_acceptable(
        &self,
        public_key: C,
        listener: Mailbox<listener::Message<C>>,
    ) -> Feedback {
        self.enqueue(Message::AcceptableForListener {
            public_key,
            listener,
        })
    }

    /// Request a listen reservation from the tracker and send the response to the listener.
    pub fn request_listen(
        &self,
        public_key: C,
        listener: Mailbox<listener::Message<C>>,
    ) -> Feedback {
        self.enqueue(Message::ListenForListener {
            public_key,
            listener,
        })
    }

    /// Request dialable peers from the tracker.
    ///
    /// Returns an empty response if the tracker is shut down.
    pub async fn dialable(&self) -> Dialable<C> {
        let (responder, receiver) = oneshot::channel();
        match self.enqueue(Message::Dialable { responder }) {
            Feedback::Ok | Feedback::Backoff => receiver.await.unwrap_or_default(),
            Feedback::Dropped | Feedback::Closed => Dialable::default(),
        }
    }

    /// Send a `Dial` message to the tracker.
    ///
    /// Returns `None` if the tracker is shut down.
    pub async fn dial(&self, public_key: C) -> Option<Reservation<C>> {
        let (reservation, receiver) = oneshot::channel();
        match self.enqueue(Message::Dial {
            public_key,
            reservation,
        }) {
            Feedback::Ok | Feedback::Backoff => receiver.await.ok().flatten(),
            Feedback::Dropped | Feedback::Closed => None,
        }
    }

    /// Send an `Acceptable` message to the tracker.
    ///
    /// Returns `false` if the tracker is shut down.
    pub async fn acceptable(&self, public_key: C) -> bool {
        let (responder, receiver) = oneshot::channel();
        match self.enqueue(Message::Acceptable {
            public_key,
            responder,
        }) {
            Feedback::Ok | Feedback::Backoff => receiver.await.unwrap_or(false),
            Feedback::Dropped | Feedback::Closed => false,
        }
    }

    /// Send a `Listen` message to the tracker.
    ///
    /// Returns `None` if the tracker is shut down.
    pub async fn listen(&self, public_key: C) -> Option<Reservation<C>> {
        let (reservation, receiver) = oneshot::channel();
        match self.enqueue(Message::Listen {
            public_key,
            reservation,
        }) {
            Feedback::Ok | Feedback::Backoff => receiver.await.ok().flatten(),
            Feedback::Dropped | Feedback::Closed => None,
        }
    }
}

/// Allows releasing reservations
#[derive(Clone, Debug)]
pub struct Releaser<C: PublicKey> {
    sender: Mailbox<Message<C>>,
}

impl<C: PublicKey> Releaser<C> {
    /// Create a new releaser.
    pub(crate) fn new(sender: Mailbox<Message<C>>) -> Self {
        Self { sender }
    }

    /// Release a reservation.
    pub fn release(&mut self, metadata: Metadata<C>) {
        let _ = self.sender.enqueue(Message::Release { metadata });
    }
}

/// Mechanism to register authorized peers.
///
/// Peers that are not explicitly authorized
/// will be blocked by commonware-p2p.
#[derive(Debug, Clone)]
pub struct Oracle<C: PublicKey> {
    sender: Mailbox<Message<C>>,
}

impl<C: PublicKey> Oracle<C> {
    pub(super) fn new(sender: Mailbox<Message<C>>) -> Self {
        Self { sender }
    }
}

impl<C: PublicKey> crate::Provider for Oracle<C> {
    type PublicKey = C;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
        let (responder, receiver) = oneshot::channel();
        match self.sender.enqueue(Message::PeerSet {
            index: id,
            responder,
        }) {
            Feedback::Ok | Feedback::Backoff => receiver.await.ok().flatten(),
            Feedback::Dropped | Feedback::Closed => None,
        }
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
        let (responder, receiver) = oneshot::channel();
        match self.sender.enqueue(Message::Subscribe { responder }) {
            Feedback::Ok | Feedback::Backoff => receiver.await.unwrap_or_else(|_| {
                let (_, rx) = ring::channel(NZUsize!(1));
                rx
            }),
            Feedback::Dropped | Feedback::Closed => {
                let (_, rx) = ring::channel(NZUsize!(1));
                rx
            }
        }
    }
}

impl<C: PublicKey> crate::Manager for Oracle<C> {
    fn track<R>(&mut self, index: u64, peers: R) -> Feedback
    where
        R: Into<TrackedPeers<Self::PublicKey>>,
    {
        self.sender.enqueue(Message::Register {
            index,
            peers: peers.into(),
        })
    }
}

impl<C: PublicKey> crate::Blocker for Oracle<C> {
    type PublicKey = C;

    fn block(&mut self, public_key: Self::PublicKey) -> Feedback {
        self.sender.enqueue(Message::Block { public_key })
    }
}
