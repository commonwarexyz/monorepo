//! Mailbox for the [`super::Stateful`] actor.

use crate::stateful::{Application, actor::core::Deferred};
use commonware_actor::{
    Feedback,
    mailbox::{Overflow, Policy, Sender},
};
use commonware_consensus::{
    Application as ConsensusApplication, CertifiableBlock, Epochable, Reporter, Viewable,
    marshal::{
        Update,
        ancestry::{Ancestry, BoxedAncestry},
    },
};
use commonware_cryptography::Digestible;
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::traces::TracedExt as _};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot},
    sync::Mutex,
};
use rand_core::Rng;
use std::{collections::VecDeque, sync::Arc};
use tracing::{Span, info_span};

/// Tracks the verification that can continue after caller cancellation.
#[derive(Clone, Default)]
struct Verifications(Arc<Mutex<Option<oneshot::Receiver<()>>>>);

impl Verifications {
    fn begin(&self) -> oneshot::Sender<()> {
        let (superseded, current) = oneshot::channel();
        self.0.lock().replace(current);
        superseded
    }

    /// Marks the current verification as superseded.
    fn supersede(&self) {
        self.0.lock().take();
    }
}

/// A verification is cancellable once its caller is gone and newer work exists.
pub(crate) struct Verification {
    response: oneshot::Sender<bool>,
    superseded: oneshot::Sender<()>,
}

impl Verification {
    pub(in crate::stateful::actor) async fn wait_for_cancellation(&mut self) {
        self.response.closed().await;
        self.superseded.closed().await;
    }

    pub(in crate::stateful::actor) fn is_cancelled(&self) -> bool {
        self.response.is_closed() && self.superseded.is_closed()
    }

    pub(in crate::stateful::actor) fn respond(self, valid: bool) {
        self.response.send_lossy(valid);
    }
}

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
        upstream: A::Input,
        response: oneshot::Sender<Option<A::Block>>,
    },

    /// A request to verify a block.
    Verify {
        span: Span,
        context: A::Context,
        ancestry: BoxedAncestry<A::Block>,
        verification: Verification,
    },

    /// A reporting of a new finalized block.
    Finalized {
        span: Span,
        block: Arc<A::Block>,
        acknowledgement: Deferred,
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
    verifications: Verifications,
}

impl<E, A> Clone for Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            verifications: self.verifications.clone(),
        }
    }
}

impl<E, A> Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Create a mailbox from the send half of the actor's message channel.
    pub(crate) fn new(sender: Sender<Message<E, A>>) -> Self {
        Self {
            sender,
            verifications: Verifications::default(),
        }
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
        self.verifications.supersede();
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
        self.verifications.supersede();
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
        // Actor availability cannot override the application's decision.
        let (_, context) = context;
        let (response, receiver) = oneshot::channel();
        let superseded = self.verifications.begin();
        let span = info_span!(
            "stateful.mailbox.verify",
            epoch = context.epoch().traced(),
            view = context.view().traced()
        );
        let _ = self.sender.enqueue(Message::Verify {
            span,
            context,
            ancestry: BoxedAncestry::new(ancestry),
            verification: Verification {
                response,
                superseded,
            },
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
                self.verifications.supersede();
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
                    acknowledgement: acknowledgement.into(),
                }
            }
        };

        self.sender.enqueue(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_requires_abandonment_and_supersession() {
        let verifications = Verifications::default();
        let superseded = verifications.begin();
        let (response, receiver) = oneshot::channel();
        let old = Verification {
            response,
            superseded,
        };

        let latest_superseded = verifications.begin();
        assert!(
            !old.is_cancelled(),
            "supersession must not cancel a verification with a live caller"
        );
        drop(receiver);
        assert!(old.is_cancelled());

        let (response, receiver) = oneshot::channel();
        drop(receiver);
        let latest = Verification {
            response,
            superseded: latest_superseded,
        };
        assert!(
            !latest.is_cancelled(),
            "the latest abandoned verification should remain useful"
        );
        let _newest = verifications.begin();
        assert!(latest.is_cancelled());
    }
}
