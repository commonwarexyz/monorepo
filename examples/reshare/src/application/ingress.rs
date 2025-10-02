//! Application ingress (mailbox and messages).

use crate::application::types::{B, D};
use commonware_consensus::{
    threshold_simplex::types::Context, types::View, Automaton, Epochable, Relay, Reporter, Viewable,
};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// Messages that can be sent to the application [Actor].
///
/// [Actor]: super::Actor
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// A request for the genesis payload.
    Genesis { response: oneshot::Sender<D> },

    /// A request to propose a new payload.
    Propose {
        view: View,
        parent: (View, D),
        response: oneshot::Sender<D>,
    },

    /// A request to verify a payload.
    Verify {
        view: View,
        parent: (View, D),
        digest: D,
        response: oneshot::Sender<bool>,
    },

    /// A notification that a payload should be broadcasted to peers.
    Broadcast { digest: D },

    /// A notification that a block has been finalized.
    Finalized { block: B },
}

/// Mailbox for the application.
#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    /// Create a new application mailbox.
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

impl Automaton for Mailbox {
    type Digest = D;
    type Context = Context<Self::Digest>;

    async fn genesis(&mut self, _: <Self::Context as Epochable>::Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { response })
            .await
            .expect("Failed to send genesis");
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(&mut self, context: Context<Self::Digest>) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Propose {
                view: context.view(),
                parent: context.parent,
                response,
            })
            .await
            .expect("Failed to send propose");
        receiver
    }

    async fn verify(
        &mut self,
        context: Context<Self::Digest>,
        digest: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Verify {
                view: context.view(),
                parent: context.parent,
                digest,
                response,
            })
            .await
            .expect("Failed to send verify");
        receiver
    }
}

impl Relay for Mailbox {
    type Digest = D;

    async fn broadcast(&mut self, digest: Self::Digest) {
        self.sender
            .send(Message::Broadcast { digest })
            .await
            .expect("Failed to send broadcast");
    }
}

impl Reporter for Mailbox {
    type Activity = B;

    async fn report(&mut self, block: Self::Activity) {
        self.sender
            .send(Message::Finalized { block })
            .await
            .expect("Failed to send finalized");
    }
}
