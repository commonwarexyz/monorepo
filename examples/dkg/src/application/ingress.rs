//! Application ingress (mailbox and messages).

use crate::application::Block;
use commonware_consensus::{
    threshold_simplex::types::Context,
    types::{Epoch, Round, View},
    Automaton, Epochable, Relay, Reporter,
};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Hasher, Signer};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// Messages that can be sent to the application [Actor].
///
/// [Actor]: super::Actor
#[allow(clippy::large_enum_variant)]
pub enum Message<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// A request for the genesis payload.
    Genesis {
        epoch: Epoch,
        response: oneshot::Sender<H::Digest>,
    },

    /// A request to propose a new payload.
    Propose {
        round: Round,
        parent: (View, H::Digest),
        response: oneshot::Sender<H::Digest>,
    },

    /// A request to verify a payload.
    Verify {
        round: Round,
        parent: (View, H::Digest),
        digest: H::Digest,
        response: oneshot::Sender<bool>,
    },

    /// A notification that a payload should be broadcasted to peers.
    Broadcast { digest: H::Digest },

    /// A notification that a block has been finalized.
    Finalized { block: Block<H, C, V> },
}

/// Mailbox for the application.
#[derive(Clone)]
pub struct Mailbox<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    sender: mpsc::Sender<Message<H, C, V>>,
}

impl<H, C, V> Mailbox<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    /// Create a new application mailbox.
    pub(super) fn new(sender: mpsc::Sender<Message<H, C, V>>) -> Self {
        Self { sender }
    }
}

impl<H, C, V> Automaton for Mailbox<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Digest = H::Digest;
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
            .send(Message::Propose {
                round: context.round,
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
                round: context.round,
                parent: context.parent,
                digest,
                response,
            })
            .await
            .expect("Failed to send verify");
        receiver
    }
}

impl<H, C, V> Relay for Mailbox<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Digest = H::Digest;

    async fn broadcast(&mut self, digest: Self::Digest) {
        self.sender
            .send(Message::Broadcast { digest })
            .await
            .expect("Failed to send broadcast");
    }
}

impl<H, C, V> Reporter for Mailbox<H, C, V>
where
    H: Hasher,
    C: Signer,
    V: Variant,
{
    type Activity = Block<H, C, V>;

    async fn report(&mut self, block: Self::Activity) {
        self.sender
            .send(Message::Finalized { block })
            .await
            .expect("Failed to send finalized");
    }
}
