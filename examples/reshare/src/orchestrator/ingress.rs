//! Inbound communication channel for epoch transitions.

use commonware_consensus::{types::Epoch, Reporter};
use commonware_cryptography::{
    bls12381::primitives::{group, poly::Public, variant::MinSig},
    Hasher,
};
use futures::{channel::mpsc, SinkExt};

pub struct EpochTransition<H: Hasher> {
    pub epoch: Epoch,
    pub seed: H::Digest,
    pub poly: Public<MinSig>,
    pub share: group::Share,
}

#[derive(Debug, Clone)]
pub struct Mailbox<H: Hasher> {
    sender: mpsc::Sender<EpochTransition<H>>,
}

impl<H: Hasher> Mailbox<H> {
    pub fn new(sender: mpsc::Sender<EpochTransition<H>>) -> Self {
        Self { sender }
    }
}

impl<H: Hasher> Reporter for Mailbox<H> {
    type Activity = EpochTransition<H>;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(activity)
            .await
            .expect("failed to send epoch transition")
    }
}
