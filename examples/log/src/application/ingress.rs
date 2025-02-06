use commonware_consensus::{
    simplex::Context, Automaton as Au, Committer as Co, Proof, Relay as Re,
};
use commonware_cryptography::FormattedBytes;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

pub enum Message<D: FormattedBytes> {
    Genesis { response: oneshot::Sender<D> },
    Propose { response: oneshot::Sender<D> },
    Verify { response: oneshot::Sender<bool> },
    Prepared { proof: Proof, payload: D },
    Finalized { proof: Proof, payload: D },
}

/// Mailbox for the application.
#[derive(Clone)]
pub struct Mailbox<D: FormattedBytes> {
    sender: mpsc::Sender<Message<D>>,
}

impl<D: FormattedBytes> Mailbox<D> {
    pub(super) fn new(sender: mpsc::Sender<Message<D>>) -> Self {
        Self { sender }
    }
}

impl<D: FormattedBytes> Au for Mailbox<D> {
    type Digest = D;
    type Context = Context<Self::Digest>;

    async fn genesis(&mut self) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { response })
            .await
            .expect("Failed to send genesis");
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(&mut self, _: Context<Self::Digest>) -> oneshot::Receiver<Self::Digest> {
        // If we linked payloads to their parent, we would include
        // the parent in the `Context` in the payload.
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Propose { response })
            .await
            .expect("Failed to send propose");
        receiver
    }

    async fn verify(
        &mut self,
        _: Context<Self::Digest>,
        _: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        // Digests are already verified by consensus, so we don't need to check they are valid.
        //
        // If we linked payloads to their parent, we would verify
        // the parent included in the payload matches the provided `Context`.
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Verify { response })
            .await
            .expect("Failed to send verify");
        receiver
    }
}

impl<D: FormattedBytes> Re for Mailbox<D> {
    type Digest = D;

    async fn broadcast(&mut self, _: Self::Digest) {
        // We don't broadcast our raw messages to other peers.
        //
        // If we were building an EVM blockchain, for example, we'd
        // send the block to other peers here.
    }
}

impl<D: FormattedBytes> Co for Mailbox<D> {
    type Digest = D;

    async fn prepared(&mut self, proof: Proof, payload: Self::Digest) {
        self.sender
            .send(Message::Prepared { proof, payload })
            .await
            .expect("Failed to send notarized");
    }

    async fn finalized(&mut self, proof: Proof, payload: Self::Digest) {
        self.sender
            .send(Message::Finalized { proof, payload })
            .await
            .expect("Failed to send finalized");
    }
}
