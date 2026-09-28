use commonware_actor::mailbox::{Policy, Sender};
use commonware_consensus::{
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    simplex::types::Finalization,
};
use commonware_cryptography::certificate::Scheme;
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

/// A message that can be sent to the [`Probe`](super::Probe).
pub(crate) enum Message<S, V>
where
    S: Scheme,
    V: Variant,
{
    /// A subscription to the floor (see [`Mailbox::subscribe`]).
    Subscribe {
        response: oneshot::Sender<Finalization<S, V::Commitment>>,
    },
    /// A marshal from which to serve peers (see [`Mailbox::attach`]).
    Attach { marshal: MarshalMailbox<S, V> },
}

impl<S, V> Policy for Message<S, V>
where
    S: Scheme,
    V: Variant,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

/// Handle to the mailbox of the [`Probe`](super::Probe).
#[derive(Clone)]
pub struct Mailbox<S, V>
where
    S: Scheme,
    V: Variant,
{
    sender: Sender<Message<S, V>>,
}

impl<S, V> Mailbox<S, V>
where
    S: Scheme,
    V: Variant,
{
    pub(crate) const fn new(sender: Sender<Message<S, V>>) -> Self {
        Self { sender }
    }

    /// Subscribes to the floor.
    ///
    /// The receiver resolves immediately if a floor has been selected. Otherwise, while the actor
    /// is discovering, the subscription starts a request round if no other subscriber is waiting,
    /// and the receiver resolves once a floor is selected.
    ///
    /// Dropping the receiver cancels the subscription. If every subscriber is dropped before a
    /// floor is selected, discovery pauses until the next subscription. Once the actor serves peers
    /// without a floor, later receivers close without resolving.
    ///
    /// Callers that need a floor must keep the receiver alive until it resolves and should attach a
    /// marshal only after consuming the floor. See the
    /// [module documentation](crate::stateful::probe#lifecycle).
    pub fn subscribe(&self) -> oneshot::Receiver<Finalization<S, V::Commitment>> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Subscribe { response: tx });
        rx
    }

    /// Attaches a marshal from which the actor answers peers' requests.
    ///
    /// The actor stops discovery once no subscriber awaits a floor: after a selected floor has been
    /// delivered, or after every pending subscriber has been dropped. If no floor was selected, it
    /// serves peers without one. Attachments made after the actor starts serving are ignored.
    pub fn attach(&self, marshal: MarshalMailbox<S, V>) {
        let _ = self.sender.enqueue(Message::Attach { marshal });
    }
}
