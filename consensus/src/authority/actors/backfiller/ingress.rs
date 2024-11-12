use crate::authority::{wire, View};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};

pub enum Message {
    // From resolver
    Proposals {
        digest: Digest,
        parents: u32,
    },
    Notarizations {
        view: View,
        children: u32,
    },
    // From voter
    Notarization {
        view: View,
        notarization: wire::Notarization,

        // Used to indicate when to drop old notarizations
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

    pub async fn proposals(&self, digest: Digest, parents: u32) {
        self.sender
            .clone()
            .send(Message::Proposals { digest, parents })
            .await
            .expect("Failed to send proposals");
    }

    pub async fn notarizations(&self, view: View, children: u32) {
        self.sender
            .clone()
            .send(Message::Notarizations { view, children })
            .await
            .expect("Failed to send notarizations");
    }

    pub async fn notarization(
        &self,
        view: View,
        notarization: wire::Notarization,
        last_finalized: View,
    ) {
        self.sender
            .clone()
            .send(Message::Notarization {
                view,
                notarization,
                last_finalized,
            })
            .await
            .expect("Failed to send notarization");
    }
}
