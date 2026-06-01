use commonware_actor::mailbox::{Policy, Sender};
use commonware_consensus::{
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    simplex::types::Finalization,
};
use commonware_cryptography::certificate::Scheme;
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

/// A message that can be sent to the [`Bootstrap`](super::Bootstrap).
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
    /// Attach a marshal mailbox, allowing the actor to answer peers' request messages from the
    /// attached marshal.
    Attach {
        /// The marshal mailbox to answer latest-finalization requests from.
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

/// Handle to the mailbox of the [`Bootstrap`](super::Bootstrap).
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
    /// Before marshal is attached, this starts sampling if no floor has been selected yet.
    /// Dropping the receiver cancels this subscription; if all subscribers are dropped before a
    /// floor is selected, sampling may be abandoned. If marshal is later attached without a cached
    /// floor, later subscriptions will not restart sampling.
    ///
    /// Callers that need a floor must keep the receiver alive until it resolves and should attach
    /// only after consuming that floor.
    ///
    /// If a floor has already been selected, the receiver resolves immediately.
    pub fn subscribe(&self) -> oneshot::Receiver<Finalization<S, V::Commitment>> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Subscribe { response: tx });
        rx
    }

    /// Attach a marshal mailbox so the actor can answer peers' latest-finalization requests.
    ///
    /// Once attached, the actor can answer peers' latest-finalization requests. If no floor was
    /// ever requested, or every pending subscriber was dropped before a floor was selected, the
    /// actor answers peers without a cached floor for local subscribers.
    pub fn attach(&self, marshal: MarshalMailbox<S, V>) {
        let _ = self.sender.enqueue(Message::Attach { marshal });
    }
}
