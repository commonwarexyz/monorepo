use crate::authenticated::discovery::types;
use commonware_actor::mailbox::{self, UnreliablePolicy};
use commonware_cryptography::PublicKey;
use commonware_runtime::Metrics;
use commonware_utils::{NZUsize, channel::ring};
use futures::Sink;
#[cfg(test)]
use futures::StreamExt as _;
#[cfg(test)]
use std::sync::mpsc::TryRecvError;
use std::{collections::VecDeque, fmt, num::NonZeroUsize, pin::Pin};

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message<C: PublicKey> {
    /// Send a bit vector to the peer.
    BitVec(types::BitVec),

    /// Send a list of [types::Info] to the peer.
    Peers(Vec<types::Info<C>>),
}

impl<C: PublicKey> UnreliablePolicy for Message<C> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        false
    }
}

pub struct Mailbox<C: PublicKey> {
    messages: mailbox::UnreliableSender<Message<C>>,
    kill: ring::Sender<()>,
}

pub struct Receiver<C: PublicKey> {
    pub(super) messages: mailbox::UnreliableReceiver<Message<C>>,
    pub(super) kill: ring::Receiver<()>,
}

#[cfg(test)]
impl<C: PublicKey> Receiver<C> {
    pub async fn recv(&mut self) -> Option<Message<C>> {
        self.messages.recv().await
    }

    pub fn try_recv(&mut self) -> Result<Message<C>, TryRecvError> {
        self.messages.try_recv()
    }

    pub async fn killed(&mut self) -> bool {
        self.kill.next().await.is_some()
    }
}

impl<C: PublicKey> Mailbox<C> {
    pub fn new(metrics: impl Metrics, size: NonZeroUsize) -> (Self, Receiver<C>) {
        let (messages, receiver) = mailbox::new_unreliable(metrics, size);
        let (kill, kill_receiver) = ring::channel(NZUsize!(1));
        (
            Self { messages, kill },
            Receiver {
                messages: receiver,
                kill: kill_receiver,
            },
        )
    }

    pub fn bit_vec(&self, bit_vec: types::BitVec) {
        let _ = self.messages.enqueue(Message::BitVec(bit_vec));
    }

    pub fn peers(&self, peers: Vec<types::Info<C>>) {
        let _ = self.messages.enqueue(Message::Peers(peers));
    }

    pub fn kill(&self) {
        let mut kill = self.kill.clone();
        let _ = Pin::new(&mut kill).start_send(());
    }
}

impl<C: PublicKey> Clone for Mailbox<C> {
    fn clone(&self) -> Self {
        Self {
            messages: self.messages.clone(),
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
    use futures::FutureExt as _;

    #[test]
    fn kill_delivered_despite_full_mailbox() {
        let (mailbox, mut receiver) =
            Mailbox::<ed25519::PublicKey>::new(crate::utils::mocks::Metrics, NZUsize!(1));
        mailbox.peers(Vec::new());
        mailbox.peers(Vec::new());
        mailbox.kill();

        assert!(matches!(receiver.try_recv(), Ok(Message::Peers(_))));
        assert!(receiver.try_recv().is_err());
        assert!(matches!(receiver.killed().now_or_never(), Some(true)));
    }
}
