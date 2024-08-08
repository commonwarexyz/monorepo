use crate::{actors::peer, crypto::PublicKey, wire};
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};

pub enum Message {
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
        peers: oneshot::Sender<Vec<(PublicKey, SocketAddr, Reservation)>>,
    },

    // Used by listener
    Reserve {
        peer: PublicKey,
        reservation: oneshot::Sender<Option<Reservation>>,
    },

    // Used by peer
    Release {
        peer: PublicKey,
    },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
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

    pub async fn dialable(&self) -> Vec<(PublicKey, SocketAddr, Reservation)> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Dialable { peers: response })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn reserve(&self, peer: PublicKey) -> Option<Reservation> {
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

#[derive(Clone)]
pub struct Oracle {
    sender: mpsc::Sender<Message>,
}

impl Oracle {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub async fn register(&self, index: u64, peers: Vec<PublicKey>) {
        let _ = self.sender.send(Message::Register { index, peers }).await;
    }
}

pub struct Reservation {
    closer: Option<(PublicKey, Mailbox)>,
}

impl Reservation {
    pub fn new(peer: PublicKey, mailbox: Mailbox) -> Self {
        Self {
            closer: Some((peer, mailbox)),
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let (peer, mailbox) = self.closer.take().unwrap();
        tokio::spawn(async move {
            mailbox.release(peer).await;
        });
    }
}
