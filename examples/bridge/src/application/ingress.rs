use commonware_consensus::{
    threshold_simplex::types::{Activity, Context, View},
    Automaton as Au, Relay as Re, Reporter,
};
use commonware_cryptography::Digest;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

#[allow(clippy::large_enum_variant)]
pub enum Message<D: Digest> {
    Genesis {
        response: oneshot::Sender<D>,
    },
    Propose {
        index: View,
        response: oneshot::Sender<D>,
    },
    Verify {
        payload: D,
        response: oneshot::Sender<bool>,
    },
    Report {
        activity: Activity<D>,
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

    async fn genesis(&mut self) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { response })
            .await
            .expect("Failed to send genesis");
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(&mut self, context: Context<Self::Digest>) -> oneshot::Receiver<Self::Digest> {
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

    async fn verify(
        &mut self,
        _: Context<Self::Digest>,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
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

impl<D: Digest> Re for Mailbox<D> {
    type Digest = D;

    async fn broadcast(&mut self, _: Self::Digest) {
        // We don't broadcast our raw messages to other peers.
        //
        // If we were building an EVM blockchain, for example, we'd
        // send the block to other peers here.
    }
}

impl<D: Digest> Reporter for Mailbox<D> {
    type Activity = Activity<D>;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(Message::Report { activity })
            .await
            .expect("Failed to send report");
    }
}
