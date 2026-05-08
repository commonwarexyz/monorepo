use crate::authenticated::{discovery::types, Mailbox};
use commonware_cryptography::PublicKey;
use commonware_utils::channel::{actor::{self, Backpressure}, Feedback};
use std::collections::VecDeque;

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

impl<C: PublicKey> Backpressure for Message<C> {
    fn handle(queue: &mut VecDeque<Self>, message: Self) -> Feedback {
        match message {
            Self::BitVec(bit_vec) => actor::replace_or_retain(actor::replace_last(queue, Self::BitVec(bit_vec), |pending| {
                matches!(pending, Self::BitVec(_))
            }), queue),
            Self::Peers(peers) => actor::replace_or_retain(actor::replace_last(queue, Self::Peers(peers), |pending| {
                matches!(pending, Self::Peers(_))
            }), queue),
            Self::Kill => {
                if let Some(pending) = queue.back_mut() {
                    *pending = Self::Kill;
                    Feedback::Backoff
                } else {
                    actor::retain(queue, Self::Kill)
                }
            }
        }
    }
}

impl<C: PublicKey> Mailbox<Message<C>> {
    pub fn bit_vec(&mut self, bit_vec: types::BitVec) -> Feedback {
        self.enqueue(Message::BitVec(bit_vec))
    }

    pub fn peers(&mut self, peers: Vec<types::Info<C>>) -> Feedback {
        self.enqueue(Message::Peers(peers))
    }

    pub fn kill(&mut self) -> Feedback {
        self.enqueue(Message::Kill)
    }
}
