use commonware_consensus::{types::Epoch, Reporter};
use futures::{channel::mpsc, SinkExt};

pub enum Message {
    EnterEpoch { epoch: Epoch },
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
    type Activity = Epoch;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(Message::EnterEpoch { epoch: activity })
            .await
            .expect("Failed to send enter epoch");
    }
}
