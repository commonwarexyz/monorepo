use crate::authenticated::{discovery::types, peer_info::PeerInfo, Mailbox};
use commonware_cryptography::PublicKey;
use futures::SinkExt;

/// Messages that can be sent to the peer [`Actor`](`super::Actor`).
#[derive(Clone, Debug)]
pub enum Message<C: PublicKey> {
    /// Send a bit vector to the peer.
    BitVec(types::BitVec),

    /// Send a list of [PeerInfo] to the peer.
    Peers(Vec<PeerInfo<C>>),

    /// Kill the peer actor.
    Kill,
}

impl<C: PublicKey> Mailbox<Message<C>> {
    pub async fn bit_vec(&mut self, bit_vec: types::BitVec) {
        let _ = self.0.send(Message::BitVec(bit_vec)).await;
    }

    pub async fn peers(&mut self, peers: Vec<PeerInfo<C>>) {
        let _ = self.0.send(Message::Peers(peers)).await;
    }

    pub async fn kill(&mut self) {
        let _ = self.0.send(Message::Kill).await;
    }
}
