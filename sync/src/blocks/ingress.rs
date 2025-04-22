use alto_types::{Block, Finalization, Notarization, Seed};
use commonware_cryptography::sha256::Digest;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

pub enum Message {
    Get {
        // Only populated if parent (notarized)
        view: Option<u64>,
        payload: Digest,
        response: oneshot::Sender<Block>,
    },
    Verified {
        view: u64,
        payload: Block,
    },
    Notarized {
        proof: Notarization,
        seed: Seed,
    },
    Finalized {
        proof: Finalization,
        seed: Seed,
    },
}

/// Mailbox for the application.
#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    /// Get is a best-effort attempt to retrieve a given payload from the syncer. It is not an indication to go
    /// fetch the payload from the network.
    pub async fn get(&mut self, view: Option<u64>, payload: Digest) -> oneshot::Receiver<Block> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get {
                view,
                payload,
                response,
            })
            .await
            .expect("Failed to send get");
        receiver
    }

    pub async fn verified(&mut self, view: u64, payload: Block) {
        self.sender
            .send(Message::Verified { view, payload })
            .await
            .expect("Failed to send lock");
    }

    pub async fn notarized(&mut self, proof: Notarization, seed: Seed) {
        self.sender
            .send(Message::Notarized { proof, seed })
            .await
            .expect("Failed to send lock");
    }

    pub async fn finalized(&mut self, proof: Finalization, seed: Seed) {
        self.sender
            .send(Message::Finalized { proof, seed })
            .await
            .expect("Failed to send lock");
    }
}
