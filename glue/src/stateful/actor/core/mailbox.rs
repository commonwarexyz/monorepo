//! Mailbox for the [`super::Stateful`] actor.

use crate::stateful::{Application, actor::core::verifications::Request};
use commonware_actor::{
    Feedback,
    mailbox::{Overflow, Policy, Sender},
};
use commonware_consensus::{
    Application as ConsensusApplication, Block, CertifiableBlock, Epochable, Handoff, Reporter,
    Viewable,
    marshal::{
        Update,
        ancestry::{Ancestry, BoxedAncestry},
    },
};
use commonware_cryptography::{Digested, Digestible};
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
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
/// Queued and deferred requests carry this handle, so caller cancellation releases the ancestry's
/// blocks.
pub(in crate::stateful::actor) struct WeakAncestry<B: Block>(Weak<Mutex<BoxedAncestry<B>>>);

impl<B: Block> WeakAncestry<B> {
    /// Returns the caller-owned ancestry and a non-owning request handle.
    fn new(ancestry: impl Ancestry<B>) -> (Arc<Mutex<BoxedAncestry<B>>>, Self) {
        let owner = Arc::new(Mutex::new(BoxedAncestry::new(ancestry)));
        let reference = Self(Arc::downgrade(&owner));
        (owner, reference)
    }

    /// Returns an independent cursor over the ancestry, or `None` once the caller has cancelled.
    pub(in crate::stateful::actor) fn upgrade(&self) -> Option<BoxedAncestry<B>> {
        self.0.upgrade().map(|ancestry| ancestry.lock().clone())
    }
}

/// Response channel for a caller-scoped verification request.
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

/// Response channel for a proposal request, by request kind.
pub(in crate::stateful::actor) enum Proposal<B> {
    /// A proposal on a parent that has not yet certified: the block under the application's
    /// decision, or [`Handoff::Wait`] if none is built.
    Prepare(oneshot::Sender<Handoff<B>>),
    /// An ordinary proposal: the block, or `None` if none is built.
    Propose(oneshot::Sender<Option<B>>),
}

impl<B> Proposal<B> {
    pub(in crate::stateful::actor) async fn wait_for_cancellation(&mut self) {
        match self {
            Self::Prepare(response) => response.closed().await,
            Self::Propose(response) => response.closed().await,
        }
    }

    pub(in crate::stateful::actor) fn is_cancelled(&self) -> bool {
        match self {
            Self::Prepare(response) => response.is_closed(),
            Self::Propose(response) => response.is_closed(),
        }
    }

    /// Answers that no block was built.
    pub(in crate::stateful::actor) fn decline(self) {
        match self {
            Self::Prepare(response) => {
                response.send_lossy(Handoff::Wait);
            }
            Self::Propose(response) => {
                response.send_lossy(None);
            }
        }
    }
}

/// Messages processed by the actor loop.
pub(super) enum Message<E, A>
where
    A: Application<E>,
{
    /// A request to prepare or propose a block.
    Propose {
        span: Span,
        context: (E, A::Context),
        ancestry: BoxedAncestry<A::Block>,
        upstream: A::Input,
        proposal: Proposal<Digested<A::Block>>,
    },

    /// A request to verify a block.
    Verify(Request<E, A>),

    /// A finalized block and its marshal acknowledgement.
    Finalized {
        span: Span,
        block: Digested<A::Block>,
        acknowledgement: Exact,
        retry_mailbox: RetryMailbox<E, A>,
    },

    /// Requests the database set (see [`Mailbox::subscribe_databases`]).
    SubscribeDatabases {
        response: oneshot::Sender<A::Databases>,
    },
}

impl<E, A> Message<E, A>
where
    A: Application<E>,
{
    fn is_obsolete(&self) -> bool {
        match self {
            Self::Propose { proposal, .. } => proposal.is_cancelled(),
            Self::Verify(request) => request.verification.is_cancelled(),
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
    A: Application<E>;

impl<E, A> Default for Pending<E, A>
where
    A: Application<E>,
{
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<E, A> Overflow<Message<E, A>> for Pending<E, A>
where
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

/// Handle to the [`Stateful`](super::Stateful) actor.
///
/// Implements the consensus [`Application`](commonware_consensus::Application) and receives
/// finalized blocks from marshal as a [`Reporter`]. The mailbox forwards proposal, verification,
/// and reporting calls to the actor. If the actor stops before responding, `prepare` returns
/// [`Handoff::Wait`], `propose` returns `None`, and `verify` panics with "stateful actor dropped
/// during verify".
pub struct Mailbox<E, A>
where
    A: Application<E>,
{
    sender: Sender<Message<E, A>>,
    retry_mailbox: RetryMailbox<E, A>,
}

impl<E, A> Clone for Mailbox<E, A>
where
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
    E: Send + 'static,
    A: Application<E>,
{
    /// Creates a mailbox from the send half of the actor's message channel.
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

    /// Returns the database set once startup completes.
    ///
    /// Resolves after the set is attached to the resolvers that serve peers (and after state sync,
    /// if it runs). After startup, each call resolves when the actor reaches it in mailbox order.
    ///
    /// Holders MUST NOT prune these databases. [`Stateful`](super::Stateful) prunes according to
    /// [`Config::prune_config`](crate::stateful::Config::prune_config) and never past the history
    /// needed for crash recovery.
    ///
    /// # Panics
    ///
    /// Panics if the actor stops before replying.
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
    E: Send + 'static,
    A: Application<E>,
{
    type SigningScheme = A::SigningScheme;
    type Context = A::Context;
    type Block = A::Block;
    type Input = A::Input;

    /// Builds through [`Application::prepare`] on the actor, which owns the database batches.
    async fn prepare(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        upstream: Self::Input,
    ) -> Handoff<Digested<Self::Block>> {
        let (response, receiver) = oneshot::channel();
        let span = info_span!(
            "stateful.mailbox.prepare",
            epoch = context.1.epoch().traced(),
            view = context.1.view().traced()
        );
        let _ = self.sender.enqueue(Message::Propose {
            span,
            context,
            ancestry: BoxedAncestry::new(ancestry),
            upstream,
            proposal: Proposal::Prepare(response),
        });
        receiver.await.unwrap_or(Handoff::Wait)
    }

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        upstream: Self::Input,
    ) -> Option<Digested<Self::Block>> {
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
            proposal: Proposal::Propose(response),
        });
        receiver.await.ok().flatten()
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        // The actor holds only a weak handle, so dropping this future releases the ancestry's
        // blocks even while the request is queued.
        let (response, receiver) = oneshot::channel();
        let (ancestry_owner, ancestry) = WeakAncestry::new(ancestry);
        let span = info_span!(
            "stateful.mailbox.verify",
            epoch = context.1.epoch().traced(),
            view = context.1.view().traced()
        );
        let _ = self.sender.enqueue(Message::Verify(Request {
            span,
            context,
            ancestry,
            verification: Verification { response },
        }));

        let result = receiver
            .await
            .expect("stateful actor dropped during verify");
        drop(ancestry_owner);
        result
    }
}

impl<E, A> Reporter for Mailbox<E, A>
where
    E: Send + 'static,
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
