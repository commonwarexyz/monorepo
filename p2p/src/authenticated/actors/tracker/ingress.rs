use crate::authenticated::{actors::peer, wire};
use commonware_cryptography::Component;
use commonware_runtime::Spawner;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::net::SocketAddr;

pub enum Message<E: Spawner, P: Component> {
    // Used by oracle
    Register {
        index: u64,
        peers: Vec<P>,
    },

    // Used by peer
    Construct {
        public_key: P,
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
        peers: oneshot::Sender<Vec<(P, SocketAddr, Reservation<E, P>)>>,
    },

    // Used by listener
    Reserve {
        peer: P,
        reservation: oneshot::Sender<Option<Reservation<E, P>>>,
    },

    // Used by peer
    Release {
        peer: P,
    },
}

#[derive(Clone)]
pub struct Mailbox<E: Spawner, P: Component> {
    sender: mpsc::Sender<Message<E, P>>,
}

impl<E: Spawner, P: Component> Mailbox<E, P> {
    pub(super) fn new(sender: mpsc::Sender<Message<E, P>>) -> Self {
        Self { sender }
    }

    pub async fn construct(&mut self, public_key: P, peer: peer::Mailbox) {
        self.sender
            .send(Message::Construct { public_key, peer })
            .await
            .unwrap();
    }

    pub async fn bit_vec(&mut self, bit_vec: wire::BitVec, peer: peer::Mailbox) {
        self.sender
            .send(Message::BitVec { bit_vec, peer })
            .await
            .unwrap();
    }

    pub async fn peers(&mut self, peers: wire::Peers, peer: peer::Mailbox) {
        self.sender
            .send(Message::Peers { peers, peer })
            .await
            .unwrap();
    }

    pub async fn dialable(&mut self) -> Vec<(P, SocketAddr, Reservation<E, P>)> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Dialable { peers: response })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn reserve(&mut self, peer: P) -> Option<Reservation<E, P>> {
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

    pub async fn release(&mut self, peer: P) {
        self.sender.send(Message::Release { peer }).await.unwrap();
    }
}

/// Mechanism to register authorized peers.
///
/// Peers that are not explicitly authorized
/// will be blocked by commonware-p2p.
#[derive(Clone)]
pub struct Oracle<E: Spawner, P: Component> {
    sender: mpsc::Sender<Message<E, P>>,
}

impl<E: Spawner, P: Component> Oracle<E, P> {
    pub(super) fn new(sender: mpsc::Sender<Message<E, P>>) -> Self {
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
    pub async fn register(&mut self, index: u64, peers: Vec<P>) {
        let _ = self.sender.send(Message::Register { index, peers }).await;
    }
}

pub struct Reservation<E: Spawner, P: Component> {
    runtime: E,
    closer: Option<(P, Mailbox<E, P>)>,
}

impl<E: Spawner, P: Component> Reservation<E, P> {
    pub fn new(runtime: E, peer: P, mailbox: Mailbox<E, P>) -> Self {
        Self {
            runtime,
            closer: Some((peer, mailbox)),
        }
    }
}

impl<E: Spawner, P: Component> Drop for Reservation<E, P> {
    fn drop(&mut self) {
        let (peer, mut mailbox) = self.closer.take().unwrap();
        self.runtime.spawn("reservation", async move {
            mailbox.release(peer).await;
        });
    }
}
