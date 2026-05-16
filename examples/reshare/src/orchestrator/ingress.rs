//! Inbound communication channel for epoch transitions.

use commonware_actor::mailbox::{Policy, Sender};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::primitives::{group, sharing::Sharing, variant::Variant},
    PublicKey,
};
use commonware_utils::ordered::Set;
use std::collections::VecDeque;
use tracing::error;

/// Messages that can be sent to the orchestrator.
pub enum Message<V: Variant, P: PublicKey> {
    Enter(EpochTransition<V, P>),
    Exit(Epoch),
}

impl<V: Variant, P: PublicKey> Policy for Message<V, P> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        overflow.push_back(message);
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
    sender: Sender<Message<V, P>>,
}

impl<V: Variant, P: PublicKey> Mailbox<V, P> {
    /// Create a new [Mailbox].
    pub const fn new(sender: Sender<Message<V, P>>) -> Self {
        Self { sender }
    }

    pub fn enter(&mut self, transition: EpochTransition<V, P>) {
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
