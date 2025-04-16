use crate::authenticated::{actors::peer, types};
use commonware_cryptography::Verifier;
use commonware_runtime::{Metrics, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    executor::block_on,
    SinkExt,
};
use std::net::SocketAddr;

pub enum Message<E: Spawner + Metrics, C: Verifier> {
    // Used by oracle
    Register {
        index: u64,
        peers: Vec<C::PublicKey>,
    },

    // Used by peer
    Construct {
        public_key: C::PublicKey,
        peer: peer::Mailbox<C>,
    },
    BitVec {
        bit_vec: types::BitVec,
        peer: peer::Mailbox<C>,
    },
    Peers {
        peers: Vec<types::PeerInfo<C>>,
        peer: peer::Mailbox<C>,
    },

    // Used by dialer
    Dialable {
        #[allow(clippy::type_complexity)]
        peers: oneshot::Sender<Vec<(C::PublicKey, SocketAddr, Reservation<E, C>)>>,
    },

    // Used by listener
    Reserve {
        peer: C::PublicKey,
        reservation: oneshot::Sender<Option<Reservation<E, C>>>,
    },

    // Used by peer
    Release {
        peer: C::PublicKey,
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

    pub async fn reserve(&mut self, peer: C::PublicKey) -> Option<Reservation<E, C>> {
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

    pub async fn release(&mut self, peer: C::PublicKey) {
        self.sender.send(Message::Release { peer }).await.unwrap();
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

pub struct Reservation<E: Spawner + Metrics, C: Verifier> {
    closer: Option<(C::PublicKey, Mailbox<E, C>)>,
}

impl<E: Spawner + Metrics, C: Verifier> Reservation<E, C> {
    pub fn new(peer: C::PublicKey, mailbox: Mailbox<E, C>) -> Self {
        Self {
            closer: Some((peer, mailbox)),
        }
    }
}

impl<E: Spawner + Metrics, C: Verifier> Drop for Reservation<E, C> {
    fn drop(&mut self) {
        let (peer, mut mailbox) = self.closer.take().unwrap();
        block_on(mailbox.release(peer));
    }
}
