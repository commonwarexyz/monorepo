use crate::authority::{wire, Height, View};
use commonware_cryptography::{Digest, PublicKey};
use futures::{channel::mpsc, SinkExt};

pub enum Message {
    Notarizations {
        containers: Vec<View>,
        null: Vec<View>,
    },
    Notarized {
        // TODO: cancel any outstanding fetches if we get a non-null notarized view
        // higher than what we are requesting.
        view: View,
        notarization: wire::Notarization,

        // Used to indicate when to drop old notarizations
        // we are caching in memory.
        last_finalized: View,
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

    pub async fn notarizations(&mut self, containers: Vec<View>, null: Vec<View>) {
        self.sender
            .send(Message::Notarizations { view, children })
            .await
            .expect("Failed to send notarizations");
    }

    pub async fn cancel_notarizations(&mut self) {
        self.sender
            .send(Message::CancelNotarizations {})
            .await
            .expect("Failed to send cancel notarizations");
    }

    pub async fn notarized(
        &mut self,
        view: View,
        notarization: wire::Notarization,
        last_finalized: View,
    ) {
        self.sender
            .send(Message::Notarized {
                view,
                notarization,
                last_finalized,
            })
            .await
            .expect("Failed to send notarization");
    }
}