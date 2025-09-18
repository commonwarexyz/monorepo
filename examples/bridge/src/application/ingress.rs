use commonware_consensus::{
    threshold_simplex::types::{Activity, Context},
    types::{Epoch, Round},
    Automaton as Au, Epochable, Relay as Re, Reporter,
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, Digest};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use async_trait::async_trait;

#[allow(clippy::large_enum_variant)]
pub enum Message<D: Digest> {
    Genesis {
        epoch: Epoch,
        response: oneshot::Sender<D>,
    },
    Propose {
        round: Round,
        response: oneshot::Sender<D>,
    },
    Verify {
        payload: D,
        response: oneshot::Sender<bool>,
    },
    Report {
        activity: Activity<MinSig, D>,
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

#[async_trait]
impl<D: Digest + Send + 'static> Au for Mailbox<D> {
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

    async fn propose(&mut self, context: Context<Self::Digest>) -> Self::Digest {
        // If we linked payloads to their parent, we would include
        // the parent in the `Context` in the payload.
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Propose {
                round: context.round,
                response,
            })
            .await
            .expect("Failed to send propose");
        receiver.await.expect("Failed to receive propose")
    }

    async fn verify(
        &mut self,
        _: Context<Self::Digest>,
        payload: Self::Digest,
    ) -> bool {
        // If we linked payloads to their parent, we would verify
        // the parent included in the payload matches the provided `Context`.
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Verify { payload, response })
            .await
            .expect("Failed to send verify");
        receiver.await.expect("Failed to receive verify")
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
    type Activity = Activity<MinSig, D>;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(Message::Report { activity })
            .await
            .expect("Failed to send report");
    }
}
