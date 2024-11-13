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
        parents: Height,

        // Recipient already rate-limited by p2p layer, this is just functionally
        // required to send the response back.
        recipient: PublicKey,
        // Avoid processing anything that is past the deadline (would occur if there is a backup of requests).
        deadline: u64, // TODO: change to UNIX_SECONDS type
    },

    // Resolved requests from peers
    BackfilledProposals {
        proposals: Vec<(Digest, wire::Proposal)>,
    },
    BackfilledNotarizations {
        notarizations: Vec<wire::Notarization>,
    },
}

#[derive(Clone)]
pub struct Mailbox {
    // Messages from Backfiller
    low: mpsc::Sender<Message>,
    // Messages from Voter
    high: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(low: mpsc::Sender<Message>, high: mpsc::Sender<Message>) -> Self {
        Self { low, high }
    }

    pub async fn propose(&mut self, view: View, proposer: PublicKey) {
        self.high
            .send(Message::Propose { view, proposer })
            .await
            .unwrap();
    }

    pub async fn verify(&mut self, container: Digest, proposal: wire::Proposal) {
        self.high
            .send(Message::Verify {
                container,
                proposal,
            })
            .await
            .unwrap();
    }

    pub async fn notarized(&mut self, proposal: Proposal) {
        self.high
            .send(Message::Notarized { proposal })
            .await
            .unwrap();
    }

    pub async fn finalized(&mut self, proposal: Proposal) {
        self.high
            .send(Message::Finalized { proposal })
            .await
            .unwrap();
    }

    pub async fn proposals(
        &mut self,
        digest: Digest,
        parents: Height,
        recipient: PublicKey,
        deadline: u64,
    ) {
        self.low
            .send(Message::Proposals {
                digest,
                parents,
                recipient,
                deadline,
            })
            .await
            .unwrap();
    }

    pub async fn backfilled_proposals(&mut self, proposals: Vec<(Digest, wire::Proposal)>) {
        self.low
            .send(Message::BackfilledProposals { proposals })
            .await
            .unwrap();
    }

    pub async fn backfilled_notarizations(&mut self, notarizations: Vec<wire::Notarization>) {
        self.low
            .send(Message::BackfilledNotarizations { notarizations })
            .await
            .unwrap();
    }
}
