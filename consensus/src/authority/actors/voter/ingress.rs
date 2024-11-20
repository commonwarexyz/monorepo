use crate::authority::{wire, View};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};

// If either of these requests fails, it will not send a reply.
pub enum Message {
    Proposed {
        view: View,
        payload: Digest,
    },
    Verified {
        view: View,
    },
    Backfilled {
        notarizations: Vec<wire::Notarization>,
    },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub async fn proposed(&mut self, view: View, payload: Digest) {
        self.sender
            .send(Message::Proposed { view, payload })
            .await
            .unwrap();
    }

    pub async fn verified(&mut self, view: View) {
        self.sender.send(Message::Verified { view }).await.unwrap();
    }

    pub(crate) async fn backfilled(&mut self, notarizations: Vec<wire::Notarization>) {
        self.sender
            .send(Message::Backfilled { notarizations })
            .await
            .unwrap();
    }
}
