use commonware_actor::mailbox::{Policy, Sender};
use commonware_consensus::{
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    simplex::types::Finalization,
};
use commonware_cryptography::certificate::Scheme;
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

/// A message that can be sent to the [`FloorDiscovery`](super::FloorDiscovery).
pub(crate) enum Message<S, V>
where
    S: Scheme,
    V: Variant,
{
    /// Subscribe for the receipt of the floor finalization from peers.
    Subscribe {
        /// The response channel to send the finalization to.
        response: oneshot::Sender<Finalization<S, V::Commitment>>,
    },
    /// Attach a marshal mailbox, transitioning the actor from discovery to serving once any
    /// discovered floor has been consumed. Serving answers peers' `RequestLatest` from the
    /// attached marshal and never issues outbound requests.
    Attach {
        /// The marshal mailbox to serve the latest finalization from.
        marshal: MarshalMailbox<S, V>,
    },
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

/// Handle to the mailbox of the [`FloorDiscovery`](super::FloorDiscovery).
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

    /// Open a subscription to the receipt of the floor finalization from peers.
    ///
    /// If the floor finalization has already been selected, returns it immediately.
    pub fn subscribe(&self) -> oneshot::Receiver<Finalization<S, V::Commitment>> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Subscribe { response: tx });
        rx
    }

    /// Attach a marshal mailbox so the actor can serve the latest finalization to peers.
    ///
    /// This transitions the actor from discovery to serving. It is applied only after any
    /// discovered floor has been delivered to its subscribers.
    pub fn attach(&self, marshal: MarshalMailbox<S, V>) {
        let _ = self.sender.enqueue(Message::Attach { marshal });
    }
}
