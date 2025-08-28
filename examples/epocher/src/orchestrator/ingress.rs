use commonware_consensus::{types::Epoch, Reporter};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use futures::{channel::mpsc, SinkExt};

/// Epoch transition update including selection seed.
#[derive(Clone, Copy, Debug)]
pub struct EpochUpdate {
    pub epoch: Epoch,
    pub seed: Sha256Digest,
}

pub enum Message {
    EnterEpoch { epoch: Epoch, seed: Sha256Digest },
}

/// Mailbox for the orchestrator.
#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

impl Reporter for Mailbox {
    type Activity = EpochUpdate;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(Message::EnterEpoch {
                epoch: activity.epoch,
                seed: activity.seed,
            })
            .await
            .expect("Failed to send enter epoch");
    }
}
