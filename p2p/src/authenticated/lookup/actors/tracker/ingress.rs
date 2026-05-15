use super::Reservation;
use crate::{
    authenticated::{
        dialing::Dialable,
        lookup::actors::{peer, tracker::Metadata},
        Mailbox as PeerMailbox,
    },
    types::Address,
    AddressableTrackedPeers, Ingress, PeerSetSubscription, TrackedPeers,
};
use commonware_actor::{
    mailbox::{self, Policy},
    Feedback,
};
use commonware_cryptography::PublicKey;
use commonware_utils::{
    channel::{mpsc, oneshot},
    ordered::Map,
};
use std::{collections::VecDeque, future::Future, net::IpAddr};

/// Messages that can be sent to the tracker actor.
#[derive(Debug)]
pub enum Message<C: PublicKey> {
    // ---------- Used by oracle ----------
    /// Register a peer set at a given index.
    Register {
        index: u64,
        peers: AddressableTrackedPeers<C>,
    },

    /// Update addresses for multiple peers without creating a new peer set.
    Overwrite { peers: Map<C, Address> },

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
        peer: PeerMailbox<peer::Message>,
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
        reservation: oneshot::Sender<Option<(Reservation<C>, Ingress)>>,
    },

    // ---------- Used by listener ----------
    /// Check if a peer is acceptable (can accept an incoming connection from them).
    Acceptable {
        /// The public key of the peer to check.
        public_key: C,

        /// The IP address the peer connected from.
        source_ip: IpAddr,

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

fn enqueue<C: PublicKey>(sender: &mailbox::Sender<Message<C>>, message: Message<C>) -> Feedback {
    sender.enqueue(message)
}

async fn request<C, R, F>(sender: &mailbox::Sender<Message<C>>, make_msg: F) -> Option<R>
where
    C: PublicKey,
    R: Send,
    F: FnOnce(oneshot::Sender<R>) -> Message<C> + Send,
{
    let (tx, rx) = oneshot::channel();
    let _ = sender.enqueue(make_msg(tx));
    rx.await.ok()
}

async fn request_or<C, R, F>(sender: &mailbox::Sender<Message<C>>, make_msg: F, default: R) -> R
where
    C: PublicKey,
    R: Send,
    F: FnOnce(oneshot::Sender<R>) -> Message<C> + Send,
{
    request(sender, make_msg).await.unwrap_or(default)
}

async fn request_or_default<C, R, F>(sender: &mailbox::Sender<Message<C>>, make_msg: F) -> R
where
    C: PublicKey,
    R: Default + Send,
    F: FnOnce(oneshot::Sender<R>) -> Message<C> + Send,
{
    request(sender, make_msg).await.unwrap_or_default()
}

/// Convenience methods for the tracker mailbox sender.
pub trait SenderExt<C: PublicKey> {
    /// Send a `Connect` message to the tracker.
    fn connect(&self, public_key: C, peer: PeerMailbox<peer::Message>) -> Feedback;

    /// Request dialable peers from the tracker.
    ///
    /// Returns an empty response if the tracker is shut down.
    fn dialable(&self) -> impl Future<Output = Dialable<C>> + Send;

    /// Send a `Dial` message to the tracker.
    ///
    /// Returns `None` if the tracker is shut down.
    fn dial(&self, public_key: C)
        -> impl Future<Output = Option<(Reservation<C>, Ingress)>> + Send;

    /// Send an `Acceptable` message to the tracker.
    ///
    /// Returns `false` if the tracker is shut down.
    fn acceptable(&self, public_key: C, source_ip: IpAddr) -> impl Future<Output = bool> + Send;

    /// Send a `Listen` message to the tracker.
    ///
    /// Returns `None` if the tracker is shut down.
    fn listen(&self, public_key: C) -> impl Future<Output = Option<Reservation<C>>> + Send;
}

impl<C: PublicKey> SenderExt<C> for mailbox::Sender<Message<C>> {
    fn connect(&self, public_key: C, peer: PeerMailbox<peer::Message>) -> Feedback {
        enqueue(self, Message::Connect { public_key, peer })
    }

    fn dialable(&self) -> impl Future<Output = Dialable<C>> + Send {
        request_or_default(self, |responder| Message::Dialable { responder })
    }

    fn dial(
        &self,
        public_key: C,
    ) -> impl Future<Output = Option<(Reservation<C>, Ingress)>> + Send {
        async move {
            request(self, move |reservation| Message::Dial {
                public_key,
                reservation,
            })
            .await
            .flatten()
        }
    }

    fn acceptable(&self, public_key: C, source_ip: IpAddr) -> impl Future<Output = bool> + Send {
        request_or(
            self,
            move |responder| Message::Acceptable {
                public_key,
                source_ip,
                responder,
            },
            false,
        )
    }

    fn listen(&self, public_key: C) -> impl Future<Output = Option<Reservation<C>>> + Send {
        async move {
            request(self, move |reservation| Message::Listen {
                public_key,
                reservation,
            })
            .await
            .flatten()
        }
    }
}

/// Allows releasing reservations
#[derive(Clone, Debug)]
pub struct Releaser<C: PublicKey> {
    sender: mailbox::Sender<Message<C>>,
}

impl<C: PublicKey> Releaser<C> {
    /// Create a new releaser.
    pub(crate) fn new(sender: mailbox::Sender<Message<C>>) -> Self {
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
    pub(super) fn new(sender: mailbox::Sender<Message<C>>) -> Self {
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

impl<C: PublicKey> crate::AddressableManager for Oracle<C> {
    fn track<R>(&mut self, index: u64, peers: R) -> Feedback
    where
        R: Into<AddressableTrackedPeers<Self::PublicKey>> + Send,
    {
        enqueue(
            &self.sender,
            Message::Register {
                index,
                peers: peers.into(),
            },
        )
    }

    fn overwrite(&mut self, peers: Map<Self::PublicKey, Address>) -> Feedback {
        enqueue(&self.sender, Message::Overwrite { peers })
    }
}

impl<C: PublicKey> crate::Blocker for Oracle<C> {
    type PublicKey = C;

    fn block(&mut self, public_key: Self::PublicKey) -> Feedback {
        enqueue(&self.sender, Message::Block { public_key })
    }
}
