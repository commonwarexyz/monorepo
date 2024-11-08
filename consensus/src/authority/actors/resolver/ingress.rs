use crate::authority::{actors::Proposal, wire, View};
use commonware_cryptography::{Digest, PublicKey};
use futures::{channel::mpsc, SinkExt};

pub enum Message {
    Propose {
        view: View,
        proposer: PublicKey, // will be self
    },
    Verify {
        container: Digest,
        proposal: wire::Proposal,
    },
    Notarized {
        proposal: Proposal,
    },
    Finalized {
        proposal: Proposal,
    },
    Backfilled {
        container: Digest,
        proposals: Vec<wire::Proposal>,
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

    pub async fn propose(&mut self, view: View, proposer: PublicKey) {
        self.sender
            .send(Message::Propose { view, proposer })
            .await
            .unwrap();
    }

    pub async fn verify(&mut self, container: Digest, proposal: wire::Proposal) {
        self.sender
            .send(Message::Verify {
                container,
                proposal,
            })
            .await
            .unwrap();
    }

    pub async fn notarized(&mut self, proposal: Proposal) {
        self.sender
            .send(Message::Notarized { proposal })
            .await
            .unwrap();
    }

    pub async fn finalized(&mut self, proposal: Proposal) {
        self.sender
            .send(Message::Finalized { proposal })
            .await
            .unwrap();
    }

    pub async fn backfilled(&mut self, container: Digest, proposals: Vec<wire::Proposal>) {
        self.sender
            .send(Message::Backfilled {
                container,
                proposals,
            })
            .await
            .unwrap();
    }
}
