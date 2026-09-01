//! Mailbox for the [`super::Stateful`] actor.

use crate::stateful::Application;
use commonware_actor::{
    Feedback,
    mailbox::{Overflow, Policy, Sender},
};
use commonware_consensus::{
    Application as ConsensusApplication, Block, CertifiableBlock, Epochable, Reporter, Viewable,
    marshal::{
        Update,
        ancestry::{Ancestry, BoxedAncestry},
    },
};
use commonware_cryptography::Digestible;
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::traces::TracedExt as _};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use rand_core::Rng;
use std::{
    collections::VecDeque,
    sync::{Arc, Weak},
};
use tracing::{Span, info_span};

/// Re-enqueues live verification requests after finalization or pruning stops
/// their active attempt.
type RetryMailbox<E, A> = Arc<dyn Fn(Message<E, A>) + Send + Sync>;

/// A non-owning reference to ancestry owned by the verification caller.
///
/// Queued and deferred requests carry this handle so caller cancellation
/// releases the ancestry's backing blocks. Each active attempt clones an
/// independent cursor from the same caller-owned ancestry.
pub(in crate::stateful::actor) struct WeakAncestry<B: Block>(Weak<Mutex<BoxedAncestry<B>>>);

impl<B: Block> WeakAncestry<B> {
    /// Returns the caller-owned ancestry and a non-owning request handle.
    fn new(ancestry: impl Ancestry<B>) -> (Arc<Mutex<BoxedAncestry<B>>>, Self) {
        let owner = Arc::new(Mutex::new(BoxedAncestry::new(ancestry)));
        let reference = Self(Arc::downgrade(&owner));
        (owner, reference)
    }

    /// Upgrades to an independent cursor while the caller still owns the ancestry.
    ///
    /// Returns `None` once caller cancellation releases the strong owner.
    pub(in crate::stateful::actor) fn upgrade(&self) -> Option<BoxedAncestry<B>> {
        self.0.upgrade().map(|ancestry| ancestry.lock().clone())
    }
}

/// A verification is scoped to its caller.
pub(in crate::stateful::actor) struct Verification {
    response: oneshot::Sender<bool>,
}

impl Verification {
    pub(in crate::stateful::actor) async fn wait_for_cancellation(&mut self) {
        self.response.closed().await;
    }

    pub(in crate::stateful::actor) fn is_cancelled(&self) -> bool {
        self.response.is_closed()
    }

    pub(in crate::stateful::actor) fn respond(self, valid: bool) {
        self.response.send_lossy(valid);
    }
}

/// Messages processed by the actor loop.
pub(super) enum Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// A request to propose a block.
    Propose {
        span: Span,
        context: (E, A::Context),
        ancestry: BoxedAncestry<A::Block>,
        upstream: A::Input,
        response: oneshot::Sender<Option<A::Block>>,
    },

    /// A request to verify a block.
    Verify {
        span: Span,
        context: (E, A::Context),
        ancestry: WeakAncestry<A::Block>,
        verification: Verification,
    },

    /// A reporting of a new finalized block.
    Finalized {
        span: Span,
        block: Arc<A::Block>,
        acknowledgement: Exact,
        retry_mailbox: RetryMailbox<E, A>,
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
    fn is_obsolete(&self) -> bool {
        match self {
            Self::Propose { response, .. } => response.is_closed(),
            Self::Verify { verification, .. } => verification.is_cancelled(),
            Self::SubscribeDatabases { response } => response.is_closed(),
            Self::Finalized { .. } => false,
        }
    }
}

/// FIFO overflow for reliable messages that do not fit in the bounded mailbox.
///
/// Caller-scoped requests are discarded after their response channel closes.
pub(super) struct Pending<E, A>(VecDeque<Message<E, A>>)
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
            if message.is_obsolete() {
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
        if message.is_obsolete() {
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
    retry_mailbox: RetryMailbox<E, A>,
}

impl<E, A> Clone for Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            retry_mailbox: self.retry_mailbox.clone(),
        }
    }
}

impl<E, A> Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Create a mailbox from the send half of the actor's message channel.
    pub(super) fn new(sender: Sender<Message<E, A>>) -> Self {
        let retry_sender = sender.clone();
        let retry_mailbox = Arc::new(move |message| {
            let _ = retry_sender.enqueue(message);
        });
        Self {
            sender,
            retry_mailbox,
        }
    }

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
        upstream: Self::Input,
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
            upstream,
            response,
        });
        receiver.await.ok().flatten()
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        // Scope the strong ancestry owner to this caller. Queued work receives only a weak
        // handle, so cancellation releases backing blocks before the actor drains the request.
        let (response, receiver) = oneshot::channel();
        let (ancestry_owner, ancestry) = WeakAncestry::new(ancestry);
        let span = info_span!(
            "stateful.mailbox.verify",
            epoch = context.1.epoch().traced(),
            view = context.1.view().traced()
        );
        let _ = self.sender.enqueue(Message::Verify {
            span,
            context,
            ancestry,
            verification: Verification { response },
        });

        // Retain ancestry through the application verdict. Actor shutdown remains an error.
        let result = receiver
            .await
            .expect("stateful actor dropped during verify");
        drop(ancestry_owner);
        result
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
                    retry_mailbox: self.retry_mailbox.clone(),
                }
            }
        };

        self.sender.enqueue(message)
    }
}
