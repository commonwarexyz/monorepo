//! Inbound communication channel for epoch transitions.

use commonware_consensus::{types::Epoch, Reporter};
use commonware_cryptography::{
    bls12381::primitives::{group, poly::Public, variant::Variant},
    Hasher, PublicKey,
};
use futures::{channel::mpsc, SinkExt};

/// A notification of an epoch transition.
pub struct EpochTransition<V: Variant, H: Hasher, P: PublicKey> {
    /// The epoch to transition to.
    pub epoch: Epoch,
    /// The seed for the new epoch.
    pub seed: H::Digest,
    /// The new public polynomial for the epoch.
    pub poly: Public<V>,
    /// The share for the local participant for the epoch, if participating.
    pub share: Option<group::Share>,
    /// The new participants for the epoch.
    pub participants: Vec<P>,
}

/// Inbound communication channel for epoch transitions.
#[derive(Debug, Clone)]
pub struct Mailbox<V: Variant, H: Hasher, P: PublicKey> {
    sender: mpsc::Sender<EpochTransition<V, H, P>>,
}

impl<V: Variant, H: Hasher, P: PublicKey> Mailbox<V, H, P> {
    /// Create a new [Mailbox].
    pub fn new(sender: mpsc::Sender<EpochTransition<V, H, P>>) -> Self {
        Self { sender }
    }
}

impl<V: Variant, H: Hasher, P: PublicKey> Reporter for Mailbox<V, H, P> {
    type Activity = EpochTransition<V, H, P>;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(activity)
            .await
            .expect("failed to send epoch transition")
    }
}
