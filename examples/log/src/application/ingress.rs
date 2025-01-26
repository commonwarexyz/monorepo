use commonware_consensus::{
    simplex::Context, Automaton as Au, Committer as Co, DigestBytes, Proof, Relay as Re,
};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

pub enum Message {
    Genesis {
        response: oneshot::Sender<DigestBytes>,
    },
    Propose {
        response: oneshot::Sender<DigestBytes>,
    },
    Verify {
        payload: DigestBytes,
        response: oneshot::Sender<bool>,
    },
    Prepared {
        proof: Proof,
        payload: DigestBytes,
    },
    Finalized {
        proof: Proof,
        payload: DigestBytes,
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
}

impl Au for Mailbox {
    type Context = Context;

    async fn genesis(&mut self) -> DigestBytes {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { response })
            .await
            .expect("Failed to send genesis");
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(&mut self, _: Context) -> oneshot::Receiver<DigestBytes> {
        // If we linked payloads to their parent, we would include
        // the parent in the `Context` in the payload.
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Propose { response })
            .await
            .expect("Failed to send propose");
        receiver
    }

    async fn verify(&mut self, _: Context, payload: DigestBytes) -> oneshot::Receiver<bool> {
        // If we linked payloads to their parent, we would verify
        // the parent included in the payload matches the provided `Context`.
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Verify { payload, response })
            .await
            .expect("Failed to send verify");
        receiver
    }
}

impl Re for Mailbox {
    async fn broadcast(&mut self, _: DigestBytes) {
        // We don't broadcast our raw messages to other peers.
        //
        // If we were building an EVM blockchain, for example, we'd
        // send the block to other peers here.
    }
}

impl Co for Mailbox {
    async fn prepared(&mut self, proof: Proof, payload: DigestBytes) {
        self.sender
            .send(Message::Prepared { proof, payload })
            .await
            .expect("Failed to send notarized");
    }

    async fn finalized(&mut self, proof: Proof, payload: DigestBytes) {
        self.sender
            .send(Message::Finalized { proof, payload })
            .await
            .expect("Failed to send finalized");
    }
}
