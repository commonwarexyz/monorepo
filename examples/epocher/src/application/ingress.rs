use crate::types::block::Block;
use commonware_consensus::{
    threshold_simplex::types::Context, types::Epoch, Automaton as Au, Epochable, Relay as Re,
    Reporter,
};
use commonware_cryptography::Digest;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

#[allow(clippy::large_enum_variant)]
pub enum Message<D: Digest> {
    Genesis {
        epoch: Epoch,
        response: oneshot::Sender<D>,
    },
    Propose {
        context: Context<D>,
        response: oneshot::Sender<D>,
    },
    Verify {
        context: Context<D>,
        payload: D,
        response: oneshot::Sender<bool>,
    },
    Report {
        block: Block,
        response: oneshot::Sender<()>,
    },
}

/// Mailbox for the application.
#[derive(Clone)]
pub struct Mailbox<D: Digest> {
    sender: mpsc::Sender<Message<D>>,
}

impl<D: Digest> Mailbox<D> {
    pub(super) fn new(sender: mpsc::Sender<Message<D>>) -> Self {
        Self { sender }
    }
}

impl<D: Digest> Au for Mailbox<D> {
    type Digest = D;
    type Context = Context<Self::Digest>;

    async fn genesis(&mut self, epoch: <Self::Context as Epochable>::Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { epoch, response })
            .await
            .expect("Failed to send genesis");
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(&mut self, context: Context<Self::Digest>) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Propose { context, response })
            .await
            .expect("Failed to send propose");
        receiver
    }

    async fn verify(
        &mut self,
        context: Context<Self::Digest>,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
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

impl<D: Digest> Re for Mailbox<D> {
    type Digest = D;

    async fn broadcast(&mut self, _: Self::Digest) {}
}

impl<D: Digest> Reporter for Mailbox<D> {
    type Activity = Block;

    async fn report(&mut self, activity: Self::Activity) {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Message::Report {
                block: activity,
                response: tx,
            })
            .await
            .expect("Failed to send report");
        let _ = rx.await; // It's ok if the receiver is dropped
    }
}
