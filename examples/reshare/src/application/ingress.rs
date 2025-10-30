//! Application ingress (mailbox and messages).

use commonware_consensus::{
    simplex::types::Context,
    types::{Epoch, Round, View},
    Automaton, Epochable, Relay,
};
use commonware_cryptography::{Hasher, PublicKey};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::marker::PhantomData;

/// Messages that can be sent to the application [Actor].
///
/// [Actor]: super::Actor
#[allow(clippy::large_enum_variant)]
pub enum Message<H>
where
    H: Hasher,
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
}

/// Mailbox for the application.
#[derive(Clone)]
pub struct Mailbox<H, P>
where
    H: Hasher,
{
    sender: mpsc::Sender<Message<H>>,
    _marker: PhantomData<P>,
}

impl<H, P> Mailbox<H, P>
where
    H: Hasher,
{
    /// Create a new application mailbox.
    pub(super) fn new(sender: mpsc::Sender<Message<H>>) -> Self {
        Self {
            sender,
            _marker: PhantomData,
        }
    }
}

impl<H, P> Automaton for Mailbox<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Digest = H::Digest;
    type Context = Context<Self::Digest, P>;

    async fn genesis(&mut self, epoch: <Self::Context as Epochable>::Epoch) -> Self::Digest {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Genesis { epoch, response })
            .await
            .expect("Failed to send genesis");
        receiver.await.expect("Failed to receive genesis")
    }

    async fn propose(
        &mut self,
        context: Context<Self::Digest, P>,
    ) -> oneshot::Receiver<Self::Digest> {
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
        context: Context<Self::Digest, P>,
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

impl<H, P> Relay for Mailbox<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Digest = H::Digest;

    async fn broadcast(&mut self, digest: Self::Digest) {
        self.sender
            .send(Message::Broadcast { digest })
            .await
            .expect("Failed to send broadcast");
    }
}
