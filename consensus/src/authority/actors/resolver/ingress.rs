use std::time::SystemTime;

use crate::authority::{actors::Proposal, wire, Height, View};
use commonware_cryptography::{Digest, PublicKey};
use futures::{channel::mpsc, SinkExt};

pub enum Message {
    // Sent from voter to resolver
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

    // Request from backfiller for some peer
    Proposals {
        digest: Digest,
        parents: u32,
        size_limit: usize,

        // Recipient already rate-limited by p2p layer, this is just functionally
        // required to send the response back.
        recipient: PublicKey,
        // Avoid processing anything that is past the deadline (would occur if there is a backup of requests).
        deadline: SystemTime,
    },

    // Resolved requests from peers
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
        parents: Height,
        size_limit: usize,
        recipient: PublicKey,
        deadline: SystemTime,
    ) {
        self.sender
            .send(Message::Proposals {
                digest,
                parents,
                size_limit,
                recipient,
                deadline,
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
