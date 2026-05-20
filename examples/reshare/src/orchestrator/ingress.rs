//! Inbound communication channel for epoch transitions.

use commonware_actor::mailbox::{Policy, Sender};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::primitives::{group, sharing::Sharing, variant::Variant},
    Digest, PublicKey,
};
use commonware_utils::ordered::Set;
use std::collections::VecDeque;
use tracing::error;

/// Messages that can be sent to the orchestrator.
pub enum Message<V: Variant, P: PublicKey, D: Digest> {
    Enter(EpochTransition<V, P, D>),
    Exit(Epoch),
}

impl<V: Variant, P: PublicKey, D: Digest> Policy for Message<V, P, D> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match message {
            Self::Enter(transition) => {
                let epoch = transition.epoch;
                if let Some(index) = overflow
                    .iter()
                    .position(|pending| matches!(pending, Self::Exit(pending) if *pending == epoch))
                {
                    overflow.remove(index);
                } else {
                    overflow.push_back(Self::Enter(transition));
                }
            }
            Self::Exit(epoch) => {
                if let Some(index) = overflow.iter().position(
                    |pending| matches!(pending, Self::Enter(pending) if pending.epoch == epoch),
                ) {
                    overflow.remove(index);
                } else {
                    overflow.push_back(Self::Exit(epoch));
                }
            }
        }
        true
    }
}

/// A notification of an epoch transition.
pub struct EpochTransition<V: Variant, P: PublicKey, D: Digest> {
    /// The epoch to transition to.
    pub epoch: Epoch,
    /// The finalized parent digest that anchors this epoch.
    pub floor: D,
    /// The public polynomial for the epoch.
    pub poly: Option<Sharing<V>>,
    /// The share for the local participant for the epoch, if participating.
    pub share: Option<group::Share>,
    /// The dealers for the epoch.
    pub dealers: Set<P>,
}

/// Inbound communication channel for epoch transitions.
#[derive(Debug, Clone)]
pub struct Mailbox<V: Variant, P: PublicKey, D: Digest> {
    sender: Sender<Message<V, P, D>>,
}

impl<V: Variant, P: PublicKey, D: Digest> Mailbox<V, P, D> {
    /// Create a new [Mailbox].
    pub const fn new(sender: Sender<Message<V, P, D>>) -> Self {
        Self { sender }
    }

    pub fn enter(&mut self, transition: EpochTransition<V, P, D>) {
        if !self.sender.enqueue(Message::Enter(transition)).accepted() {
            error!("failed to send epoch transition");
        }
    }

    pub fn exit(&mut self, epoch: Epoch) {
        if !self.sender.enqueue(Message::Exit(epoch)).accepted() {
            error!("failed to send epoch exit");
        }
    }
}
