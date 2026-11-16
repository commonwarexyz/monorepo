use crate::authenticated::{
    connection::{Kill, Killed},
    discovery::types,
};
use commonware_actor::mailbox::{self, UnreliablePolicy};
use commonware_cryptography::PublicKey;
use commonware_runtime::Metrics;
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

impl<C: PublicKey> UnreliablePolicy for Message<C> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) -> bool {
        if matches!(message, Self::Kill) {
            overflow.clear();
            overflow.push_back(message);
            true
        } else {
            false
        }
    }
}

pub struct Mailbox<C: PublicKey> {
    control: mailbox::UnreliableSender<Message<C>>,
    kill: Kill,
}

impl<C: PublicKey> Mailbox<C> {
    pub fn new(
        metrics: impl Metrics,
        size: NonZeroUsize,
    ) -> (Self, mailbox::UnreliableReceiver<Message<C>>) {
        let (sender, receiver) = mailbox::new_unreliable(metrics, size);
        (
            Self {
                control: sender,
                kill: Kill::new(),
            },
            receiver,
        )
    }

    pub fn bit_vec(&self, bit_vec: types::BitVec) {
        let _ = self.control.enqueue(Message::BitVec(bit_vec));
    }

    pub fn peers(&self, peers: Vec<types::Info<C>>) {
        let _ = self.control.enqueue(Message::Peers(peers));
    }

    pub fn kill(&self) {
        self.kill.fire();
        let _ = self.control.enqueue(Message::Kill);
    }

    pub(crate) fn killed(&self) -> Killed {
        self.kill.subscribe()
    }
}

impl<C: PublicKey> Clone for Mailbox<C> {
    fn clone(&self) -> Self {
        Self {
            control: self.control.clone(),
            kill: self.kill.clone(),
        }
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
        let (mailbox, mut receiver) =
            Mailbox::<ed25519::PublicKey>::new(crate::utils::mocks::Metrics, NZUsize!(1));
        mailbox.peers(Vec::new());
        mailbox.peers(Vec::new());
        mailbox.kill();

        assert!(matches!(receiver.try_recv(), Ok(Message::Peers(_))));
        assert!(matches!(receiver.try_recv(), Ok(Message::Kill)));
        assert!(receiver.try_recv().is_err());
    }
}
