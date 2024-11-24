use commonware_cryptography::Digest;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

use crate::{authority::Context, Automaton, Finalizer, Proof, Relay};

pub enum Message {
    Genesis {
        response: oneshot::Sender<Digest>,
    },
    Propose {
        context: Context,
        response: oneshot::Sender<Digest>,
    },
    Verify {
        context: Context,
        payload: Digest,
        response: oneshot::Sender<bool>,
    },
    Broadcast {
        payload: Digest,
    },
    Notarized {
        proof: Proof,
        payload: Digest,
    },
    Finalized {
        proof: Proof,
        payload: Digest,
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
}

impl Automaton for Mailbox {
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
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Propose { context, response })
            .await
            .expect("Failed to send propose");
        receiver
    }

    async fn verify(&mut self, context: Context, payload: Digest) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Verify {
                context,
                payload,
                response,
            })
            .await
            .expect("Failed to send verify");
        receiver
    }
}

impl Relay for Mailbox {
    async fn broadcast(&mut self, payload: Digest) {
        self.sender
            .send(Message::Broadcast { payload })
            .await
            .expect("Failed to send broadcast");
    }
}

impl Finalizer for Mailbox {
    async fn notarized(&mut self, proof: Proof, payload: Digest) {
        self.sender
            .send(Message::Notarized { proof, payload })
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
