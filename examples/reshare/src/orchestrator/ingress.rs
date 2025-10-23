//! Inbound communication channel for epoch transitions.

use commonware_consensus::{types::Epoch, Reporter};
use commonware_cryptography::{
    bls12381::primitives::{group, poly::Public, variant::Variant},
    PublicKey,
};
use commonware_utils::set::Set;
use futures::{channel::mpsc, SinkExt};

/// Messages that can be sent to the orchestrator.
pub enum Message<V: Variant, P: PublicKey> {
    Enter(EpochTransition<V, P>),
    Exit(Epoch),
}

/// A notification of an epoch transition.
pub struct EpochTransition<V: Variant, P: PublicKey> {
    /// The epoch to transition to.
    pub epoch: Epoch,
    /// The new public polynomial for the epoch.
    pub poly: Option<Public<V>>,
    /// The share for the local participant for the epoch, if participating.
    pub share: Option<group::Share>,
    /// The new participants for the epoch.
    pub participants: Set<P>,
}

/// Inbound communication channel for epoch transitions.
#[derive(Debug, Clone)]
pub struct Mailbox<V: Variant, P: PublicKey> {
    sender: mpsc::Sender<Message<V, P>>,
}

impl<V: Variant, P: PublicKey> Mailbox<V, P> {
    /// Create a new [Mailbox].
    pub fn new(sender: mpsc::Sender<Message<V, P>>) -> Self {
        Self { sender }
    }
}

impl<V: Variant, P: PublicKey> Reporter for Mailbox<V, P> {
    type Activity = Message<V, P>;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(activity)
            .await
            .expect("failed to send epoch transition")
    }
}
