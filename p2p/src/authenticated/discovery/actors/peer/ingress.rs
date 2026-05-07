use crate::authenticated::{discovery::types, Mailbox};
use commonware_cryptography::PublicKey;
use commonware_utils::channel::actor::{self, Enqueue, FullPolicy, MessagePolicy};
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

impl<C: PublicKey> MessagePolicy for Message<C> {
    fn kind(&self) -> &'static str {
        match self {
            Self::BitVec(_) => "bit_vec",
            Self::Peers(_) => "peers",
            Self::Kill => "kill",
        }
    }

    fn full_policy(&self) -> FullPolicy {
        FullPolicy::Replace
    }

    fn replace(queue: &mut VecDeque<Self>, message: Self) -> Result<(), Self> {
        match message {
            Self::BitVec(bit_vec) => actor::replace_last(queue, Self::BitVec(bit_vec), |pending| {
                matches!(pending, Self::BitVec(_))
            }),
            Self::Peers(peers) => actor::replace_last(queue, Self::Peers(peers), |pending| {
                matches!(pending, Self::Peers(_))
            }),
            Self::Kill => {
                if let Some(pending) = queue.back_mut() {
                    *pending = Self::Kill;
                    Ok(())
                } else {
                    Err(Self::Kill)
                }
            }
        }
    }
}

impl<C: PublicKey> Mailbox<Message<C>> {
    pub fn bit_vec(&mut self, bit_vec: types::BitVec) -> Enqueue<Message<C>> {
        self.enqueue(Message::BitVec(bit_vec))
    }

    pub fn peers(&mut self, peers: Vec<types::Info<C>>) -> Enqueue<Message<C>> {
        self.enqueue(Message::Peers(peers))
    }

    pub fn kill(&mut self) -> Enqueue<Message<C>> {
        self.enqueue(Message::Kill)
    }
}
