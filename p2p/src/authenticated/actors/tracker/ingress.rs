use crate::authenticated::{actors::peer, wire};
use commonware_cryptography::PublicKey;
use commonware_runtime::Spawner;
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};

pub enum Message<E: Spawner> {
    // Used by oracle
    Register {
        index: u64,
        peers: Vec<PublicKey>,
    },

    // Used by peer
    Construct {
        public_key: PublicKey,
        peer: peer::Mailbox,
    },
    BitVec {
        bit_vec: wire::BitVec,
        peer: peer::Mailbox,
    },
    Peers {
        peers: wire::Peers,
        peer: peer::Mailbox,
    },

    // Used by dialer
    Dialable {
        peers: oneshot::Sender<Vec<(PublicKey, SocketAddr, Reservation<E>)>>,
    },

    // Used by listener
    Reserve {
        peer: PublicKey,
        reservation: oneshot::Sender<Option<Reservation<E>>>,
    },

    // Used by peer
    Release {
        peer: PublicKey,
    },
}

#[derive(Clone)]
pub struct Mailbox<E: Spawner> {
    sender: mpsc::Sender<Message<E>>,
}

impl<E: Spawner> Mailbox<E> {
    pub(super) fn new(sender: mpsc::Sender<Message<E>>) -> Self {
        Self { sender }
    }

    pub async fn construct(&self, public_key: PublicKey, peer: peer::Mailbox) {
        self.sender
            .send(Message::Construct { public_key, peer })
            .await
            .unwrap();
    }

    pub async fn bit_vec(&self, bit_vec: wire::BitVec, peer: peer::Mailbox) {
        self.sender
            .send(Message::BitVec { bit_vec, peer })
            .await
            .unwrap();
    }

    pub async fn peers(&self, peers: wire::Peers, peer: peer::Mailbox) {
        self.sender
            .send(Message::Peers { peers, peer })
            .await
            .unwrap();
    }

    pub async fn dialable(&self) -> Vec<(PublicKey, SocketAddr, Reservation<E>)> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Dialable { peers: response })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn reserve(&self, peer: PublicKey) -> Option<Reservation<E>> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Message::Reserve {
                peer,
                reservation: tx,
            })
            .await
            .unwrap();
        rx.await.unwrap()
    }

    pub async fn release(&self, peer: PublicKey) {
        self.sender.send(Message::Release { peer }).await.unwrap();
    }
}

/// Mechanism to register authorized peers.
///
/// Peers that are not explicitly authorized
/// will be blocked by commonware-p2p.
#[derive(Clone)]
pub struct Oracle<E: Spawner> {
    sender: mpsc::Sender<Message<E>>,
}

impl<E: Spawner> Oracle<E> {
    pub(super) fn new(sender: mpsc::Sender<Message<E>>) -> Self {
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
    pub async fn register(&self, index: u64, peers: Vec<PublicKey>) {
        let _ = self.sender.send(Message::Register { index, peers }).await;
    }
}

pub struct Reservation<E: Spawner> {
    context: E,
    closer: Option<(PublicKey, Mailbox<E>)>,
}

impl<E: Spawner> Reservation<E> {
    pub fn new(context: E, peer: PublicKey, mailbox: Mailbox<E>) -> Self {
        Self {
            context,
            closer: Some((peer, mailbox)),
        }
    }
}

impl<E: Spawner> Drop for Reservation<E> {
    fn drop(&mut self) {
        let (peer, mailbox) = self.closer.take().unwrap();
        self.context.spawn(async move {
            mailbox.release(peer).await;
        });
    }
}
