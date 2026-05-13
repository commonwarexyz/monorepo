//! Mailbox for the [`super::Stateful`] actor.

use crate::stateful::{db::Anchor, Application};
use commonware_consensus::{
    marshal::{
        ancestry::{AncestorStream, BlockProvider, ErasedBlockProvider},
        Update,
    },
    types::Height,
    Application as ConsensusApplication, Reporter,
};
use commonware_cryptography::Digestible;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::AsyncFallibleExt, mpsc, oneshot},
};
use rand::Rng;

/// Type alias for an ancestor stream with an erased block provider.
pub(crate) type ErasedAncestorStream<B> = AncestorStream<ErasedBlockProvider<B>, B>;

/// Messages processed by the actor loop.
pub(crate) enum Message<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// A request for the genesis block.
    Genesis { response: oneshot::Sender<A::Block> },

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

    /// A new finalized tip observed by marshal.
    ///
    /// During state sync, the actor uses this to fetch the block and
    /// extract updated sync targets. In processing mode, this is a no-op.
    Tip {
        height: Height,
        digest: <A::Block as Digestible>::Digest,
    },

    /// Signals that state sync is complete and the actor should transition
    /// to `Mode::Processing`.
    SyncComplete {
        databases: A::Databases,
        last_processed: Anchor<<A::Block as Digestible>::Digest>,
    },

    /// Requests the attached database set.
    ///
    /// The actor replies once the database set is attached, or immediately if
    /// it is already available.
    SubscribeDatabases {
        response: oneshot::Sender<A::Databases>,
    },
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
    sender: mpsc::Sender<Message<E, A>>,
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
    pub(crate) const fn new(sender: mpsc::Sender<Message<E, A>>) -> Self {
        Self { sender }
    }
}

impl<E, A> Mailbox<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Signal that state sync is complete, providing the constructed databases
    /// and the finalized digest to transition the actor to processing mode.
    pub async fn sync_complete(
        &self,
        databases: A::Databases,
        last_processed: Anchor<<A::Block as Digestible>::Digest>,
    ) {
        self.sender
            .send(Message::SyncComplete {
                databases,
                last_processed,
            })
            .await
            .expect("stateful actor dropped during sync_complete");
    }

    /// Wait for the attached database set.
    ///
    /// This resolves when startup bootstrap finishes and the actor has
    /// attached the database set. Late callers receive the current database
    /// set immediately.
    pub async fn subscribe_databases(&self) -> A::Databases {
        self.sender
            .request(|response| Message::SubscribeDatabases { response })
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

    async fn genesis(&mut self) -> Self::Block {
        self.sender
            .request(|response| Message::Genesis { response })
            .await
            .expect("stateful actor dropped during genesis")
    }

    async fn propose<BP>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<BP, Self::Block>,
    ) -> Option<Self::Block>
    where
        BP: BlockProvider<Block = Self::Block> + Send + Sync,
    {
        let ancestry = ancestry.erase();
        self.sender
            .request(|response| Message::Propose {
                context,
                ancestry,
                response,
            })
            .await
            .flatten()
    }

    async fn verify<BP>(
        &mut self,
        context: (E, Self::Context),
        ancestry: AncestorStream<BP, Self::Block>,
    ) -> bool
    where
        BP: BlockProvider<Block = Self::Block> + Send + Sync,
    {
        let ancestry = ancestry.erase();

        // We must panic if we don't get a response; We cannot override the decision
        // of the application based on the availabilitiy of the actor.
        self.sender
            .request(|response| Message::Verify {
                context,
                ancestry,
                response,
            })
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

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Update::Tip(_, height, digest) => {
                self.sender
                    .send_lossy(Message::Tip { height, digest })
                    .await;
            }
            Update::Block(block, acknowledgement) => {
                self.sender
                    .send_lossy(Message::Finalized {
                        block,
                        acknowledgement,
                    })
                    .await;
            }
        }
    }
}
