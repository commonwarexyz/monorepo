use super::ActorArtifact;
use crate::dkg::ReshareBlock;
use commonware_actor::mailbox::{Policy, Sender};
use commonware_consensus::{
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    simplex::scheme::Scheme,
};
use commonware_cryptography::Signer;
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

/// Messages sent to the DKG probe actor.
pub(crate) enum Message<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
{
    /// Subscribe to the probe artifact (see [`Mailbox::subscribe`]).
    Subscribe {
        /// Channel used to resolve the subscriber.
        response: oneshot::Sender<ActorArtifact<S, V>>,
    },
    /// Attach marshal to serve boundary requests (see [`Mailbox::attach`]).
    Attach {
        /// Marshal mailbox used to serve boundary requests.
        marshal: MarshalMailbox<S, V>,
    },
}

impl<S, V> Policy for Message<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

/// Mailbox for a running DKG probe actor.
#[derive(Clone)]
pub struct Mailbox<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
{
    sender: Sender<Message<S, V>>,
}

impl<S, V> Mailbox<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
{
    pub(crate) const fn new(sender: Sender<Message<S, V>>) -> Self {
        Self { sender }
    }

    /// Subscribes to the probe artifact.
    ///
    /// The first live subscriber starts discovery. Dropping the returned
    /// receiver cancels the subscription. If discovery has already resolved, the
    /// receiver gets the cached artifact immediately. If the actor has stopped,
    /// or is serving without an artifact, the receiver closes without a value.
    pub fn subscribe(&self) -> oneshot::Receiver<ActorArtifact<S, V>> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Subscribe { response });
        receiver
    }

    /// Attaches marshal so the actor can serve peers' requests.
    ///
    /// If subscribers are pending, the actor starts serving once they are
    /// resolved or dropped. A source node can attach marshal without ever
    /// subscribing, so it serves without sending discovery requests.
    pub fn attach(&self, marshal: MarshalMailbox<S, V>) {
        let _ = self.sender.enqueue(Message::Attach { marshal });
    }
}
