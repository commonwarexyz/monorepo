use crate::authenticated::{discovery::types, Mailbox};
use commonware_cryptography::PublicKey;
use commonware_utils::channel::fallible::AsyncFallibleExt;

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
    pub fn bit_vec(&mut self, bit_vec: types::BitVec) -> bool {
        self.0.try_send_lossy(Message::BitVec(bit_vec))
    }

    pub fn peers(&mut self, peers: Vec<types::Info<C>>) -> bool {
        self.0.try_send_lossy(Message::Peers(peers))
    }

    pub fn kill(&mut self) -> bool {
        self.0.try_send_lossy(Message::Kill)
    }
}
