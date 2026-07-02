//! Mailbox for the [`super::Stateful`] actor.

use crate::stateful::Application;
use commonware_actor::{
    mailbox::{Overflow, Policy, Sender},
    Feedback,
};
use commonware_consensus::{
    marshal::{
        ancestry::{Ancestry, BoxedAncestry},
        Update,
    },
    Application as ConsensusApplication, CertifiableBlock, Epochable, Reporter, Viewable,
};
use commonware_cryptography::Digestible;
use commonware_runtime::{telemetry::traces::TracedExt as _, Clock, Metrics, Spawner};
use commonware_utils::{acknowledgement::Exact, channel::oneshot};
use rand::Rng;
use std::collections::VecDeque;
use tracing::{info_span, Span};

/// Messages processed by the actor loop.
pub(crate) enum Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// A request to propose a block.
    Propose {
        span: Span,
        context: (E, A::Context),
        ancestry: BoxedAncestry<A::Block>,
        parent: A::Input,
        response: oneshot::Sender<Option<A::Block>>,
    },

    /// A request to verify a block.
    Verify {
        span: Span,
        context: (E, A::Context),
        ancestry: BoxedAncestry<A::Block>,
        response: oneshot::Sender<bool>,
    },

    /// A reporting of a new finalized block.
    Finalized {
        span: Span,
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
    /// ## Safety
    ///
    /// Holders must never manually prune these databases. Stateful uses
    /// [`Config::prune_config`](crate::stateful::Config::prune_config) to
    /// schedule safe pruning without pruning past the rewind window needed for
    /// crash reconciliation. With pruning enabled, glue keeps a
    /// `max_pending_acks + 1` finalized-target window plus the configured
    /// extra block windows before pruning.
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
    type Input = A::Input;

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        parent: Self::Input,
    ) -> Option<Self::Block> {
        let (response, receiver) = oneshot::channel();
        let span = info_span!(
            "stateful.mailbox.propose",
            epoch = context.1.epoch().traced(),
            view = context.1.view().traced()
        );
        let _ = self.sender.enqueue(Message::Propose {
            span,
            context,
            ancestry: BoxedAncestry::new(ancestry),
            parent,
            response,
        });
        receiver.await.ok().flatten()
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        // We must panic if we don't get a response; We cannot override the decision
        // of the application based on the availabilitiy of the actor.
        let (response, receiver) = oneshot::channel();
        let span = info_span!(
            "stateful.mailbox.verify",
            epoch = context.1.epoch().traced(),
            view = context.1.view().traced()
        );
        let _ = self.sender.enqueue(Message::Verify {
            span,
            context,
            ancestry: BoxedAncestry::new(ancestry),
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
            Update::Block(block, acknowledgement) => {
                let context = block.context();
                let span = info_span!(
                    "stateful.mailbox.finalized",
                    epoch = context.epoch().traced(),
                    view = context.view().traced(),
                    digest = %block.digest()
                );
                Message::Finalized {
                    span,
                    block,
                    acknowledgement,
                }
            }
        };

        self.sender.enqueue(message)
    }
}
