use crate::authenticated::discovery::types;
use commonware_actor::mailbox::{self, Policy};
use commonware_cryptography::PublicKey;
use std::{collections::VecDeque, fmt, num::NonZeroUsize};

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

impl<C: PublicKey> Policy for Message<C> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if matches!(message, Self::Kill) {
            overflow.clear();
            overflow.push_back(message);
        }
    }
}

pub struct Mailbox<C: PublicKey>(mailbox::Sender<Message<C>>);

impl<C: PublicKey> Mailbox<C> {
    pub fn new(size: NonZeroUsize) -> (Self, mailbox::Receiver<Message<C>>) {
        let (sender, receiver) = mailbox::new(size);
        (Self(sender), receiver)
    }

    pub fn bit_vec(&self, bit_vec: types::BitVec) -> bool {
        self.0.enqueue(Message::BitVec(bit_vec)).accepted()
    }

    pub fn peers(&self, peers: Vec<types::Info<C>>) -> bool {
        self.0.enqueue(Message::Peers(peers)).accepted()
    }

    pub fn kill(&self) -> bool {
        self.0.enqueue(Message::Kill).accepted()
    }
}

impl<C: PublicKey> Clone for Mailbox<C> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<C: PublicKey> fmt::Debug for Mailbox<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Mailbox").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::ed25519;
    use commonware_utils::NZUsize;

    #[test]
    fn kill_retained_on_overflow() {
        let (mailbox, mut receiver) = Mailbox::<ed25519::PublicKey>::new(NZUsize!(1));
        mailbox.peers(Vec::new());
        mailbox.peers(Vec::new());
        mailbox.kill();

        assert!(matches!(receiver.try_recv(), Ok(Message::Peers(_))));
        assert!(matches!(receiver.try_recv(), Ok(Message::Kill)));
        assert!(receiver.try_recv().is_err());
    }
}
