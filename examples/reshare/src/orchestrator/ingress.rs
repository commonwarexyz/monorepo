//! Inbound communication channel for epoch transitions.

use commonware_consensus::{types::Epoch, Reporter};
use commonware_cryptography::{
    bls12381::primitives::{group, poly::Public, variant::Variant},
    Hasher,
};
use futures::{channel::mpsc, SinkExt};

/// A notification of an epoch transition.
pub struct EpochTransition<V: Variant, H: Hasher> {
    /// The epoch to transition to.
    pub epoch: Epoch,
    /// The seed for the new epoch.
    pub seed: H::Digest,
    /// The new public polynomial for the epoch.
    pub poly: Public<V>,
    /// The share for the local participant for the epoch.
    pub share: group::Share,
}

/// Inbound communication channel for epoch transitions.
#[derive(Debug, Clone)]
pub struct Mailbox<V: Variant, H: Hasher> {
    sender: mpsc::Sender<EpochTransition<V, H>>,
}

impl<V: Variant, H: Hasher> Mailbox<V, H> {
    /// Create a new [Mailbox].
    pub fn new(sender: mpsc::Sender<EpochTransition<V, H>>) -> Self {
        Self { sender }
    }
}

impl<V: Variant, H: Hasher> Reporter for Mailbox<V, H> {
    type Activity = EpochTransition<V, H>;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(activity)
            .await
            .expect("failed to send epoch transition")
    }
}
