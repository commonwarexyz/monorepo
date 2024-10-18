use crate::{
    authority::{actors::Proposal, wire},
    Hash, PublicKey, View,
};
use futures::{channel::mpsc, SinkExt};

pub enum Message {
    Propose {
        view: View,
        proposer: PublicKey, // will be self
    },
    Verify {
        hash: Hash,
        proposal: wire::Proposal,
    },
    Notarized {
        proposal: Proposal,
    },
    Finalized {
        proposal: Proposal,
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

    pub async fn verify(&mut self, hash: Hash, proposal: wire::Proposal) {
        self.sender
            .send(Message::Verify { hash, proposal })
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
}
