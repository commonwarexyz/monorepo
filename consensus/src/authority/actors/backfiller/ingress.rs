use crate::authority::{wire, Height, View};
use commonware_cryptography::{Digest, PublicKey};
use futures::{channel::mpsc, SinkExt};

pub enum Message {
    // From resolver
    Proposals {
        digest: Digest,
        parents: Height,
    },
    FilledProposals {
        recipient: PublicKey,
        proposals: Vec<wire::Proposal>,
    },
    Notarizations {
        view: View,
        children: View,
    },
    // From voter
    Notarized {
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

    pub async fn proposals(&self, digest: Digest, parents: Height) {
        self.sender
            .clone()
            .send(Message::Proposals { digest, parents })
            .await
            .expect("Failed to send proposals");
    }

    pub async fn filled_proposals(&self, recipient: PublicKey, proposals: Vec<wire::Proposal>) {
        self.sender
            .clone()
            .send(Message::FilledProposals {
                recipient,
                proposals,
            })
            .await
            .expect("Failed to send filled proposals");
    }

    pub async fn notarizations(&self, view: View, children: View) {
        self.sender
            .clone()
            .send(Message::Notarizations { view, children })
            .await
            .expect("Failed to send notarizations");
    }

    pub async fn notarized(
        &self,
        view: View,
        notarization: wire::Notarization,
        last_finalized: View,
    ) {
        self.sender
            .clone()
            .send(Message::Notarized {
                view,
                notarization,
                last_finalized,
            })
            .await
            .expect("Failed to send notarization");
    }
}
