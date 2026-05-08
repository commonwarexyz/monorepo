//! Inbound communication channel for epoch transitions.

use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::primitives::{group, sharing::Sharing, variant::Variant},
    PublicKey,
};
use commonware_utils::{
    channel::{
        actor::{self, ActorMailbox, Backpressure, MessagePolicy},
        Feedback,
    },
    ordered::Set,
};
use std::collections::VecDeque;

/// Messages that can be sent to the orchestrator.
pub enum Message<V: Variant, P: PublicKey> {
    Enter(EpochTransition<V, P>),
    Exit(Epoch),
}

impl<V: Variant, P: PublicKey> Message<V, P> {
    const fn epoch(&self) -> Epoch {
        match self {
            Self::Enter(transition) => transition.epoch,
            Self::Exit(epoch) => *epoch,
        }
    }
}

impl<V: Variant, P: PublicKey> MessagePolicy for Message<V, P> {
    fn backpressure(queue: &mut VecDeque<Self>, message: Self) -> Backpressure<Self> {
        let epoch = message.epoch();
        Backpressure::replace_or_retain(
            actor::replace_last(queue, message, |pending| pending.epoch() == epoch),
            queue,
        )
    }
}

/// A notification of an epoch transition.
pub struct EpochTransition<V: Variant, P: PublicKey> {
    /// The epoch to transition to.
    pub epoch: Epoch,
    /// The public polynomial for the epoch.
    pub poly: Option<Sharing<V>>,
    /// The share for the local participant for the epoch, if participating.
    pub share: Option<group::Share>,
    /// The dealers for the epoch.
    pub dealers: Set<P>,
}

/// Inbound communication channel for epoch transitions.
#[derive(Debug, Clone)]
pub struct Mailbox<V: Variant, P: PublicKey> {
    sender: ActorMailbox<Message<V, P>>,
}

impl<V: Variant, P: PublicKey> Mailbox<V, P> {
    /// Create a new [Mailbox].
    pub const fn new(sender: ActorMailbox<Message<V, P>>) -> Self {
        Self { sender }
    }

    pub fn enter(&mut self, transition: EpochTransition<V, P>) -> Feedback {
        self.sender.enqueue(Message::Enter(transition))
    }

    pub fn exit(&mut self, epoch: Epoch) -> Feedback {
        self.sender.enqueue(Message::Exit(epoch))
    }
}
