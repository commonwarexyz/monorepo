use super::Reservation;
use crate::authenticated::{
    lookup::actors::{peer, tracker::Metadata},
    Mailbox,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Handle, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::net::SocketAddr;

/// Messages that can be sent to the tracker actor.
pub enum Message<C: PublicKey> {
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

impl<C: PublicKey> Mailbox<Message<C>> {
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

/// Owns the worker that drains deferred release requests when the main tracker
/// mailbox is full.
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

impl<C: PublicKey> crate::Blocker for Oracle<C> {
    type PublicKey = C;

    async fn block(&mut self, public_key: Self::PublicKey) {
        let _ = self.sender.send(Message::Block { public_key }).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{ed25519::PrivateKey, PrivateKeyExt, Signer};
    use commonware_runtime::{deterministic::Runner, Runner as _};
    use futures::StreamExt;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn releaser_drains_backlog_when_mailbox_full() {
        let executor = Runner::default();
        executor.start(|context| async move {
            // mailbox has capacity for only 1 element
            let (sender, mut receiver) = mpsc::channel(1);
            let (releaser, mut handle) = Releaser::new(context.clone(), sender);
            releaser.start();

            let metadata_a = Metadata::Dialer(
                PrivateKey::from_seed(1).public_key(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1337),
            );
            let metadata_b = Metadata::Listener(PrivateKey::from_seed(2).public_key());

            // the first release request should go through directly to the mailbox
            handle.release(metadata_a.clone());
            // the second release request should be queued in the backlog
            handle.release(metadata_b.clone());

            let first = receiver.next().await.unwrap();
            assert!(matches!(
                first,
                Message::Release { ref metadata } if metadata.public_key() == metadata_a.public_key()
            ));

            let second = receiver.next().await.unwrap();
            assert!(matches!(
                second,
                Message::Release { ref metadata } if metadata.public_key() == metadata_b.public_key()
            ));
        });
    }
}
