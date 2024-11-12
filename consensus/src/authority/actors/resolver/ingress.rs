use crate::authority::{actors::Proposal, wire, View};
use commonware_cryptography::{Digest, PublicKey};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

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
    Proposals {
        digest: Digest,
        parents: u32,

        size_limit: usize,
        response: oneshot::Sender<Vec<wire::Proposal>>,
    },
    BackfilledProposals {
        proposals: Vec<wire::Proposal>,
    },
    BackfilledNotarizations {
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

    pub async fn proposals(
        &mut self,
        digest: Digest,
        parents: u32,
        size_limit: usize,
        response: oneshot::Sender<Vec<wire::Proposal>>,
    ) {
        self.sender
            .send(Message::Proposals {
                digest,
                parents,
                size_limit,
                response,
            })
            .await
            .unwrap();
    }

    pub async fn backfilled_proposals(&mut self, proposals: Vec<wire::Proposal>) {
        self.sender
            .send(Message::BackfilledProposals { proposals })
            .await
            .unwrap();
    }

    pub async fn backfilled_notarizations(&mut self, notarizations: Vec<wire::Notarization>) {
        self.sender
            .send(Message::BackfilledNotarizations { notarizations })
            .await
            .unwrap();
    }
}
