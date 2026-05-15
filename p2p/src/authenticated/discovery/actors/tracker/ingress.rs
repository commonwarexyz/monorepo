use super::Reservation;
use crate::{
    authenticated::{
        dialing::Dialable,
        discovery::{
            actors::{peer, tracker::Metadata},
            types,
        },
    },
    utils::{
        mailbox_enqueue as enqueue, mailbox_request as request, mailbox_request_or as request_or,
        mailbox_request_or_default as request_or_default,
    },
    PeerSetSubscription, TrackedPeers,
};
use commonware_actor::{
    mailbox::{self, Policy},
    Feedback,
};
use commonware_cryptography::PublicKey;
use commonware_utils::channel::{mpsc, oneshot};
use std::collections::VecDeque;

/// Messages that can be sent to the tracker actor.
#[derive(Debug)]
pub enum Message<C: PublicKey> {
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
        peer: peer::Mailbox<C>,
    },

    /// Notify the tracker that a [types::Payload::BitVec] message has been received from a peer.
    ///
    /// The tracker will construct a [types::Payload::Peers] message in response.
    BitVec {
        /// The bit vector received.
        bit_vec: types::BitVec,

        /// The mailbox of the peer actor.
        peer: peer::Mailbox<C>,
    },

    /// Notify the tracker that a [types::Payload::Peers] message has been received from a peer.
    Peers {
        /// The list of peers received.
        peers: Vec<types::Info<C>>,
    },

    // ---------- Used by dialer ----------
    /// Request a list of dialable peers.
    Dialable {
        /// One-shot channel to send the dialable peers and next query deadline.
        responder: oneshot::Sender<Dialable<C>>,
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

    /// Send a `Connect` message to the tracker and receive the greeting info.
    ///
    /// Returns `Some(info)` if the peer is eligible, `None` if the channel was
    /// dropped (peer not eligible or tracker shut down).
    pub(crate) async fn connect(
        &self,
        public_key: C,
        dialer: bool,
    ) -> Option<types::Info<C>> {
        request(&self.0, move |responder| Message::Connect {
            public_key,
            dialer,
            responder,
        })
        .await
    }

    /// Send a `Construct` message to the tracker.
    pub(crate) fn construct(&self, public_key: C, peer: peer::Mailbox<C>) -> Feedback {
        enqueue(&self.0, Message::Construct { public_key, peer })
    }

    /// Send a `BitVec` message to the tracker.
    pub(crate) fn bit_vec(&self, bit_vec: types::BitVec, peer: peer::Mailbox<C>) -> Feedback {
        enqueue(&self.0, Message::BitVec { bit_vec, peer })
    }

    /// Send a `Peers` message to the tracker.
    pub(crate) fn peers(&self, peers: Vec<types::Info<C>>) -> Feedback {
        enqueue(&self.0, Message::Peers { peers })
    }

    /// Request dialable peers from the tracker.
    ///
    /// Returns an empty response if the tracker is shut down.
    pub(crate) async fn dialable(&self) -> Dialable<C> {
        request_or_default(&self.0, |responder| Message::Dialable { responder }).await
    }

    /// Send a `Dial` message to the tracker.
    ///
    /// Returns `None` if the tracker is shut down.
    pub(crate) async fn dial(&self, public_key: C) -> Option<Reservation<C>> {
        request(&self.0, move |reservation| Message::Dial {
            public_key,
            reservation,
        })
        .await
        .flatten()
    }

    /// Send an `Acceptable` message to the tracker.
    ///
    /// Returns `false` if the tracker is shut down.
    pub(crate) async fn acceptable(&self, public_key: C) -> bool {
        request_or(
            &self.0,
            move |responder| Message::Acceptable {
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
    pub(crate) async fn listen(&self, public_key: C) -> Option<Reservation<C>> {
        request(&self.0, move |reservation| Message::Listen {
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
    sender: mailbox::Sender<Message<C>>,
}

impl<C: PublicKey> Releaser<C> {
    /// Create a new releaser.
    pub(crate) const fn new(sender: mailbox::Sender<Message<C>>) -> Self {
        Self { sender }
    }

    /// Release a reservation.
    pub fn release(&mut self, metadata: Metadata<C>) -> Feedback {
        enqueue(&self.sender, Message::Release { metadata })
    }
}

/// Mechanism to register authorized peers.
///
/// Peers that are not explicitly authorized
/// will be blocked by commonware-p2p.
#[derive(Debug, Clone)]
pub struct Oracle<C: PublicKey> {
    sender: mailbox::Sender<Message<C>>,
}

impl<C: PublicKey> Oracle<C> {
    pub(super) const fn new(sender: mailbox::Sender<Message<C>>) -> Self {
        Self { sender }
    }
}

impl<C: PublicKey> crate::Provider for Oracle<C> {
    type PublicKey = C;

    async fn peer_set(&mut self, id: u64) -> Option<TrackedPeers<Self::PublicKey>> {
        request(&self.sender, move |responder| Message::PeerSet {
            index: id,
            responder,
        })
        .await
        .flatten()
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
        request(&self.sender, |responder| Message::Subscribe { responder })
            .await
            .unwrap_or_else(|| {
                let (_, rx) = mpsc::unbounded_channel();
                rx
            })
    }
}

impl<C: PublicKey> crate::Manager for Oracle<C> {
    fn track<R>(&mut self, index: u64, peers: R) -> Feedback
    where
        R: Into<TrackedPeers<Self::PublicKey>> + Send,
    {
        enqueue(
            &self.sender,
            Message::Register {
                index,
                peers: peers.into(),
            },
        )
    }
}

impl<C: PublicKey> crate::Blocker for Oracle<C> {
    type PublicKey = C;

    fn block(&mut self, public_key: Self::PublicKey) -> Feedback {
        enqueue(&self.sender, Message::Block { public_key })
    }
}
