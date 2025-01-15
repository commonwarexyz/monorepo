use commonware_consensus::{
    threshold_simplex::{Context, View},
    Automaton as Au, Committer as Co, Proof, Relay as Re,
};
use commonware_cryptography::Digest;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

pub enum Message {
    Genesis {
        response: oneshot::Sender<Digest>,
    },
    Propose {
        index: View,
        response: oneshot::Sender<Digest>,
    },
    Verify {
        payload: Digest,
        response: oneshot::Sender<bool>,
    },
    Prepared {
        proof: Proof,
        payload: Digest,
    },
    Finalized {
        proof: Proof,
        payload: Digest,
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

    async fn genesis(&mut self) -> Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { response })
            .await
            .expect("Failed to send genesis");
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(&mut self, context: Context) -> oneshot::Receiver<Digest> {
        // If we linked payloads to their parent, we would include
        // the parent in the `Context` in the payload.
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Propose {
                index: context.view,
                response,
            })
            .await
            .expect("Failed to send propose");
        receiver
    }

    async fn verify(&mut self, _: Context, payload: Digest) -> oneshot::Receiver<bool> {
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
    async fn broadcast(&mut self, _: Digest) {
        // We don't broadcast our raw messages to other peers.
        //
        // If we were building an EVM blockchain, for example, we'd
        // send the block to other peers here.
    }
}

impl Co for Mailbox {
    async fn prepared(&mut self, proof: Proof, payload: Digest) {
        self.sender
            .send(Message::Prepared { proof, payload })
            .await
            .expect("Failed to send notarized");
    }

    async fn finalized(&mut self, proof: Proof, payload: Digest) {
        self.sender
            .send(Message::Finalized { proof, payload })
            .await
            .expect("Failed to send finalized");
    }
}
