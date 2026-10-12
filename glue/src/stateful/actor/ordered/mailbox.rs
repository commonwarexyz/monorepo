//! The executor's view of the ordered [`Stateful`](super::Stateful) actor.

use crate::{
    executor::{Context, Execute, Update},
    stateful::{
        db::DatabaseSet,
        ordered::{Application, Execution},
    },
};
use commonware_actor::{
    Feedback,
    mailbox::{Policy, Sender},
};
use commonware_consensus::{Reporter, ancestry::Ancestry, marshal::Finalized, types::Height};
use commonware_cryptography::Digestible;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::channel::{oneshot, ring};
use rand_core::Rng;
use std::{
    collections::VecDeque,
    future,
    sync::{Arc, OnceLock},
};

type Digest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type SyncTargets<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets;
type Unmerkleized<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Unmerkleized;
pub(super) type Merkleized<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::Merkleized;

/// A request to the actor.
pub(super) enum Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The executor resumes from `tip`, the newest block it recorded as applied.
    Resume(Arc<A::Block>),
    /// State-syncs the databases to `target`, following newer targets from `updates`, and
    /// returns the block they reached.
    Sync {
        target: Arc<A::Block>,
        updates: ring::Receiver<Update<A::Block>>,
        response: oneshot::Sender<Arc<A::Block>>,
    },
    /// A checkpoint certified an executed block.
    Certified(Arc<A::Block>),
    /// Returns batches holding the state after the block at `height - 1`, with that block's sync
    /// targets.
    Fork {
        height: Height,
        response: oneshot::Sender<(Unmerkleized<A, E>, SyncTargets<A, E>)>,
    },
    /// The block at `height` was executed on the batches forked for it.
    Executed {
        height: Height,
        digest: Digest<A, E>,
        targets: SyncTargets<A, E>,
        /// The batches the block commits to, or `None` if it left state unchanged.
        merkleized: Option<Merkleized<A, E>>,
    },
    /// The executor delivered an executed block to apply.
    Finalized(Finalized<A::Block>),
    /// Returns the databases once they are open.
    Databases {
        response: oneshot::Sender<A::Databases>,
    },
}

/// Keeps every message in order, and drops requests whose caller left.
impl<E, A> Policy for Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        let abandoned = match &message {
            Self::Fork { response, .. } => response.is_closed(),
            Self::Sync { response, .. } => response.is_closed(),
            Self::Databases { response } => response.is_closed(),
            Self::Resume(_) | Self::Certified(_) | Self::Executed { .. } | Self::Finalized(_) => {
                false
            }
        };
        if !abandoned {
            overflow.push_back(message);
        }
    }
}

/// The executor's application and consumer, backed by the ordered
/// [`Stateful`](super::Stateful) actor.
///
/// Pass one clone as the executor's `execute` and another as its `consumer`. Each execution
/// reports its block to the actor before returning it, so the actor sees a block executed before
/// the executor delivers it.
pub struct Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    sender: Sender<Message<E, A>>,
    application: A,
    /// The databases, once the actor opens them.
    databases: Arc<OnceLock<A::Databases>>,
}

impl<E, A> Clone for Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            application: self.application.clone(),
            databases: Arc::clone(&self.databases),
        }
    }
}

impl<E, A> Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    pub(super) const fn new(
        sender: Sender<Message<E, A>>,
        application: A,
        databases: Arc<OnceLock<A::Databases>>,
    ) -> Self {
        Self {
            sender,
            application,
            databases,
        }
    }

    /// Returns the databases once the actor opens them, or `None` if it stops first.
    ///
    /// Holders may read the databases but must not apply, finalize, or prune them: the actor owns
    /// every mutation.
    pub async fn subscribe_databases(&self) -> Option<A::Databases> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Databases { response });
        receiver.await.ok()
    }
}

impl<E, A> Execute<E> for Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    type Input = A::Input;
    type Block = A::Block;

    fn genesis(&mut self) -> impl Future<Output = A::Block> + Send {
        self.application.genesis()
    }

    fn resume(&mut self, tip: Arc<A::Block>) {
        let _ = self.sender.enqueue(Message::Resume(tip));
    }

    fn certified(&mut self, block: Arc<A::Block>) {
        let _ = self.sender.enqueue(Message::Certified(block));
    }

    async fn sync(
        &mut self,
        target: Arc<A::Block>,
        updates: ring::Receiver<Update<A::Block>>,
    ) -> Arc<A::Block> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Sync {
            target,
            updates,
            response,
        });
        match receiver.await {
            Ok(base) => base,
            // The actor stopped, and the executor stops without a base.
            Err(_) => future::pending().await,
        }
    }

    /// Executes `input` on batches the actor forks from the parent's state, and checks that the
    /// block commits to the state it produced before the executor archives it.
    async fn execute(
        mut self,
        context: (E, Context<<A::Input as Digestible>::Digest>),
        ancestry: impl Ancestry<A::Block>,
        input: Arc<A::Input>,
    ) -> A::Block {
        let height = context.1.height;
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Fork { height, response });
        let Ok((batches, parent)) = receiver.await else {
            // The actor stopped, and the executor stops without this block.
            return future::pending().await;
        };
        let (block, merkleized) = match self
            .application
            .execute(context, ancestry, input, batches)
            .await
        {
            Execution::Changed { block, merkleized } => (block, Some(merkleized)),
            Execution::Unchanged { block } => (block, None),
        };
        let targets = A::sync_targets(&block);
        match &merkleized {
            Some(batches) => assert!(
                A::Databases::matches_sync_targets(batches, &targets),
                "executed block does not commit to the batches it produced"
            ),
            None => assert!(
                targets == parent,
                "unchanged block does not commit to its parent's state"
            ),
        }
        let _ = self.sender.enqueue(Message::Executed {
            height,
            digest: block.digest(),
            targets,
            merkleized,
        });
        block
    }

    /// Prepares `input` through [`Application::prepare`] with readers of the databases, or does
    /// nothing while they are not open.
    async fn prepare(mut self, context: E, input: Arc<A::Input>) {
        if let Some(databases) = self.databases.get() {
            let readers = databases.readers();
            self.application.prepare(context, input, readers).await;
        }
    }
}

impl<E, A> Reporter for Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    type Activity = Finalized<A::Block>;

    fn report(&mut self, block: Self::Activity) -> Feedback {
        self.sender.enqueue(Message::Finalized(block))
    }
}
