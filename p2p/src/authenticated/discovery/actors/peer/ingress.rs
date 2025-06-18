use crate::authenticated::discovery::types;
use commonware_cryptography::PublicKey;
use futures::{channel::mpsc, SinkExt};

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message<C: PublicKey> {
    /// Send a bit vector to the peer.
    BitVec(types::BitVec),

    /// Send a list of [types::PeerInfo] to the peer.
    Peers(Vec<types::PeerInfo<C>>),

    /// Kill the peer actor.
    Kill,
}

#[derive(Clone)]
pub struct Mailbox<C: PublicKey> {
    sender: mpsc::Sender<Message<C>>,
}

impl<C: PublicKey> Mailbox<C> {
    pub(super) fn new(sender: mpsc::Sender<Message<C>>) -> Self {
        Self { sender }
    }

    #[cfg(test)]
    pub fn test() -> (Self, mpsc::Receiver<Message<C>>) {
        let (sender, receiver) = mpsc::channel(1);
        (Self { sender }, receiver)
    }

    pub async fn bit_vec(&mut self, bit_vec: types::BitVec) {
        let _ = self.sender.send(Message::BitVec(bit_vec)).await;
    }

    pub async fn peers(&mut self, peers: Vec<types::PeerInfo<C>>) {
        let _ = self.sender.send(Message::Peers(peers)).await;
    }

    pub async fn kill(&mut self) {
        let _ = self.sender.send(Message::Kill).await;
    }
}
