use crate::authenticated::{actors::peer, types};
use commonware_cryptography::Verifier;
use commonware_runtime::{Metrics, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::net::SocketAddr;

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
    /// Ready to send a [`types::Payload::BitVec`] message to a peer. This message doubles as a
    /// keep-alive signal to the peer.
    ///
    /// This request is formed upon connection establishment and also on a recurring interval.
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

    // ---------- Used by reservation ----------
    /// Release a reservation for a particular peer.
    Release { public_key: C::PublicKey },

    // ---------- Used by dialer ----------
    /// Request a list of dialable peers.
    ///
    /// The tracker will respond with a list of tuples containing the public key, socket address,
    /// and reservation for each dialable peer. This list won't include peers that are already
    /// connected, blocked, or already have an active reservation.
    Dialable {
        #[allow(clippy::type_complexity)]
        peers: oneshot::Sender<Vec<(C::PublicKey, SocketAddr, Reservation<E, C>)>>,
    },

    // ---------- Used by listener ----------
    /// Request a reservation for a particular peer.
    ///
    /// The tracker will respond with an [`Option<Reservation<E, C>>`], which will be `None` if  the
    /// reservation cannot be granted (e.g., if the peer is already connected, blocked or already
    /// has an active reservation).
    Reserve {
        public_key: C::PublicKey,
        reservation: oneshot::Sender<Option<Reservation<E, C>>>,
    },
}

#[derive(Clone)]
pub struct Mailbox<E: Spawner + Metrics, C: Verifier> {
    sender: mpsc::Sender<Message<E, C>>,
}

impl<E: Spawner + Metrics, C: Verifier> Mailbox<E, C> {
    pub(super) fn new(sender: mpsc::Sender<Message<E, C>>) -> Self {
        Self { sender }
    }

    pub async fn construct(&mut self, public_key: C::PublicKey, peer: peer::Mailbox<C>) {
        self.sender
            .send(Message::Construct { public_key, peer })
            .await
            .unwrap();
    }

    pub async fn bit_vec(&mut self, bit_vec: types::BitVec, peer: peer::Mailbox<C>) {
        self.sender
            .send(Message::BitVec { bit_vec, peer })
            .await
            .unwrap();
    }

    pub async fn peers(&mut self, peers: Vec<types::PeerInfo<C>>, peer: peer::Mailbox<C>) {
        self.sender
            .send(Message::Peers { peers, peer })
            .await
            .unwrap();
    }

    pub async fn dialable(&mut self) -> Vec<(C::PublicKey, SocketAddr, Reservation<E, C>)> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Dialable { peers: response })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn reserve(&mut self, public_key: C::PublicKey) -> Option<Reservation<E, C>> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Message::Reserve {
                public_key,
                reservation: tx,
            })
            .await
            .unwrap();
        rx.await.unwrap()
    }

    pub fn try_release(&mut self, public_key: C::PublicKey) -> bool {
        let Err(e) = self.sender.try_send(Message::Release { public_key }) else {
            return true;
        };
        if e.is_full() {
            return false;
        }

        // If any other error occurs, we should panic!
        panic!(
            "unexpected error while trying to release reservation: {:?}",
            e
        );
    }

    pub async fn release(&mut self, public_key: C::PublicKey) {
        self.sender
            .send(Message::Release { public_key })
            .await
            .unwrap();
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

pub struct Reservation<E: Spawner + Metrics, C: Verifier> {
    context: E,
    closer: Option<(C::PublicKey, Mailbox<E, C>)>,
}

impl<E: Spawner + Metrics, C: Verifier> Reservation<E, C> {
    pub fn new(context: E, peer: C::PublicKey, mailbox: Mailbox<E, C>) -> Self {
        Self {
            context,
            closer: Some((peer, mailbox)),
        }
    }
}

impl<E: Spawner + Metrics, C: Verifier> Drop for Reservation<E, C> {
    fn drop(&mut self) {
        let (peer, mut mailbox) = self.closer.take().unwrap();

        // If the mailbox is not full, we can release the reservation immediately without spawning a task.
        if mailbox.try_release(peer.clone()) {
            return;
        }

        // If the mailbox is full, we need to spawn a task to handle the release. If we used `block_on` here,
        // it could cause a deadlock.
        self.context.spawn_ref()(async move {
            mailbox.release(peer).await;
        });
    }
}
