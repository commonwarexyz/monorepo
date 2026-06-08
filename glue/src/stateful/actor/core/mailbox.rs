//! Mailbox for the [`super::Stateful`] actor.

use crate::stateful::Application;
use commonware_actor::{
    mailbox::{Overflow, Policy, Sender},
    Feedback,
};
use commonware_consensus::{marshal::Update, Application as ConsensusApplication, Reporter};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::{acknowledgement::Exact, channel::oneshot};
use futures::Stream;
use rand::Rng;
use std::{collections::VecDeque, pin::Pin};

/// Type alias for an ancestor stream sent through the actor mailbox.
pub(crate) type ErasedAncestorStream<B> = Pin<Box<dyn Stream<Item = B> + Send>>;

/// Messages processed by the actor loop.
pub(crate) enum Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// A request to propose a block.
    Propose {
        context: (E, A::Context),
        ancestry: ErasedAncestorStream<A::Block>,
        response: oneshot::Sender<Option<A::Block>>,
    },

    /// A request to verify a block.
    Verify {
        context: (E, A::Context),
        ancestry: ErasedAncestorStream<A::Block>,
        response: oneshot::Sender<bool>,
    },

    /// A reporting of a new finalized block.
    Finalized {
        block: A::Block,
        acknowledgement: Exact,
    },

    /// Requests the attached database set.
    ///
    /// The actor replies once the database set has been attached to the
    /// serving stateful actor, or immediately if that has already happened.
    SubscribeDatabases {
        response: oneshot::Sender<A::Databases>,
    },
}

impl<E, A> Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn response_closed(&self) -> bool {
        match self {
            Self::Propose { response, .. } => response.is_closed(),
            Self::Verify { response, .. } => response.is_closed(),
            Self::SubscribeDatabases { response } => response.is_closed(),
            Self::Finalized { .. } => false,
        }
    }
}

pub(crate) struct Pending<E, A>(VecDeque<Message<E, A>>)
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>;

impl<E, A> Default for Pending<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<E, A> Overflow<Message<E, A>> for Pending<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<E, A>) -> Option<Message<E, A>>,
    {
        while let Some(message) = self.0.pop_front() {
            if message.response_closed() {
                continue;
            }

            if let Some(message) = push(message) {
                self.0.push_front(message);
                break;
            }
        }
    }
}

impl<E, A> Policy for Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    type Overflow = Pending<E, A>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if message.response_closed() {
            return;
        }
        overflow.0.push_back(message);
    }
}

/// Channel-based proxy to the [`Stateful`](super::Stateful) actor.
///
/// Implements the consensus application and verifying traits by forwarding
/// each call to the actor via a message and awaiting the response.
pub struct Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    sender: Sender<Message<E, A>>,
}

impl<E, A> Clone for Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<E, A> Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Create a mailbox from the send half of the actor's message channel.
    pub(crate) const fn new(sender: Sender<Message<E, A>>) -> Self {
        Self { sender }
    }
}

impl<E, A> Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Wait for the attached database set.
    ///
    /// This resolves once startup handoff has attached the database set to the
    /// serving actor. Late callers receive the current database set
    /// immediately.
    ///
    /// Holders must never manually prune these databases. Stateful glue uses
    /// [`MaintenanceConfig`](crate::stateful::MaintenanceConfig) to
    /// schedule safe maintenance without pruning past the rewind window needed
    /// for crash reconciliation. With pruning enabled, glue keeps a retention
    /// window configured by [`MaintenanceConfig::retention`].
    pub async fn subscribe_databases(&self) -> A::Databases {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::SubscribeDatabases { response });
        receiver
            .await
            .expect("stateful actor dropped during subscribe_databases")
    }
}

impl<E, A> ConsensusApplication<E> for Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    type SigningScheme = A::SigningScheme;
    type Context = A::Context;
    type Block = A::Block;

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Self::Block> + Send + 'static,
    ) -> Option<Self::Block> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Propose {
            context,
            ancestry: Box::pin(ancestry),
            response,
        });
        receiver.await.ok().flatten()
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Stream<Item = Self::Block> + Send + 'static,
    ) -> bool {
        // We must panic if we don't get a response; We cannot override the decision
        // of the application based on the availabilitiy of the actor.
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Verify {
            context,
            ancestry: Box::pin(ancestry),
            response,
        });
        receiver
            .await
            .expect("stateful actor dropped during verify")
    }
}

impl<E, A> Reporter for Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    type Activity = Update<A::Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let message = match activity {
            Update::Tip(_, _, _) => return Feedback::Ok,
            Update::Block(block, acknowledgement) => Message::Finalized {
                block,
                acknowledgement,
            },
        };

        self.sender.enqueue(message)
    }
}
