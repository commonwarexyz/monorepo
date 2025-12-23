use crate::authenticated::{discovery::types, Mailbox};
use commonware_cryptography::PublicKey;

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message<C: PublicKey> {
    /// Send a bit vector to the peer.
    BitVec(types::BitVec),

    /// Send a list of [types::Info] to the peer.
    Peers(Vec<types::Info<C>>),

    /// Kill the peer actor.
    Kill,
}

impl<C: PublicKey> Mailbox<Message<C>> {
    pub async fn bit_vec(&mut self, bit_vec: types::BitVec) {
        let _ = self.send(Message::BitVec(bit_vec)).await;
    }

    pub async fn peers(&mut self, peers: Vec<types::Info<C>>) {
        let _ = self.send(Message::Peers(peers)).await;
    }

    pub async fn kill(&mut self) {
        let _ = self.send(Message::Kill).await;
    }
}
