use super::ActorArtifact;
use crate::dkg::ReshareBlock;
use commonware_actor::mailbox::{Policy, Sender};
use commonware_consensus::{
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    simplex::scheme::Scheme,
};
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

/// Messages sent to the anchor actor.
pub(crate) enum Message<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
{
    /// Subscribe to the anchor artifact.
    Subscribe {
        /// Channel used to resolve the subscriber.
        response: oneshot::Sender<ActorArtifact<S, V>>,
    },
    /// Attach marshal and transition to boundary-serving mode once discovery no
    /// no longer has pending subscribers.
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
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

/// Mailbox for a running anchor actor.
#[derive(Clone)]
pub struct Mailbox<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
{
    sender: Sender<Message<S, V>>,
}

impl<S, V> Mailbox<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
{
    pub(crate) const fn new(sender: Sender<Message<S, V>>) -> Self {
        Self { sender }
    }

    /// Subscribe to the anchor artifact.
    ///
    /// The first live subscriber causes discovery to pay attention to the
    /// Simplex certificate channel. Dropping the returned receiver cancels the
    /// subscription. If discovery has already resolved, late subscribers receive
    /// the cached artifact immediately.
    pub fn subscribe(&self) -> oneshot::Receiver<ActorArtifact<S, V>> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Subscribe { response });
        receiver
    }

    /// Attach marshal so the actor can serve peers' boundary requests.
    ///
    /// If discovery has pending subscribers, the actor waits until they are
    /// resolved or dropped before entering serving. A source node can attach
    /// marshal without ever subscribing, causing it to serve boundaries without
    /// issuing discovery requests.
    pub fn attach(&self, marshal: MarshalMailbox<S, V>) {
        let _ = self.sender.enqueue(Message::Attach { marshal });
    }
}
