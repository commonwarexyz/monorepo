//! Requests to the promoter.

use super::actor::Error;
use crate::multimmit::{
    actors::util::ask,
    marshal::{
        actors::delivery::HotOutput,
        types::{BodyValues, OutputIndex, Reply},
    },
    types::{BlockRef, Body, TransactionBlock},
};
use commonware_actor::{
    Feedback,
    mailbox::{self, Policy},
};
use commonware_cryptography::Hasher;
use commonware_runtime::Metrics as RuntimeMetrics;
use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc};
use tracing::Span;

/// A request to the promoter.
pub(crate) enum Message<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// A published commit moved the promotion target to `through`.
    Published {
        through: OutputIndex,
        /// Committed outputs whose bodies the catalog still held.
        hot: Vec<HotOutput<H, B>>,
    },
    /// A floor installation moved every chain to at least `frontiers`.
    Installed {
        floor_generation: u64,
        /// Committed output of the installed checkpoint.
        through: Option<OutputIndex>,
        /// Installed frontier, one reference per chain in chain order.
        frontiers: Vec<BlockRef<H::Digest>>,
    },
    /// A read of the immutable archive, processed under the caller's span.
    Lookup { span: Span, lookup: Lookup<H, B> },
}

/// A read of the immutable archive.
pub(crate) enum Lookup<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// The block named by `reference`.
    Block {
        reference: BlockRef<H::Digest>,
        reply: Reply<Option<Arc<TransactionBlock<H, B>>>, Error>,
    },
    /// The block named by each reference, in request order.
    Blocks {
        references: Vec<BlockRef<H::Digest>>,
        reply: Reply<BodyValues<H, B>, Error>,
    },
    /// The block with `digest`.
    BlockByDigest {
        digest: H::Digest,
        reply: Reply<Option<Arc<TransactionBlock<H, B>>>, Error>,
    },
}

/// Keeps one publication in overflow, advanced to the newest target and without bodies, so
/// queued publications never hold more than one handoff batch; installations and lookups keep
/// their order.
impl<H, B> Policy for Message<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        match message {
            Self::Published { through, .. } => {
                if let Some(Self::Published {
                    through: pending,
                    hot: pending_hot,
                }) = overflow.back_mut()
                {
                    if through > *pending {
                        *pending = through;
                        pending_hot.clear();
                    }
                } else {
                    overflow.push_back(Self::Published {
                        through,
                        hot: Vec::new(),
                    });
                }
            }
            message => overflow.push_back(message),
        }
    }
}

/// The receiving half of the promoter mailbox.
pub(crate) type Receiver<H, B> = mailbox::Receiver<Message<H, B>>;

/// The promoter's client for publications, installations and immutable reads.
pub(crate) struct Mailbox<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    sender: mailbox::Sender<Message<H, B>>,
}

impl<H, B> Clone for Mailbox<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<H, B> Mailbox<H, B>
where
    H: Hasher,
    B: Body<H>,
{
    /// Moves the promotion target to `through`, offering the bodies the catalog still holds.
    pub(crate) fn published(&self, through: OutputIndex, hot: Vec<HotOutput<H, B>>) -> Feedback {
        self.sender.enqueue(Message::Published { through, hot })
    }

    /// Advances every chain to an installed floor.
    pub(crate) fn installed(
        &self,
        floor_generation: u64,
        through: Option<OutputIndex>,
        frontiers: Vec<BlockRef<H::Digest>>,
    ) -> Feedback {
        self.sender.enqueue(Message::Installed {
            floor_generation,
            through,
            frontiers,
        })
    }

    async fn request<T>(
        &self,
        make: impl FnOnce(Reply<T, Error>) -> Lookup<H, B>,
    ) -> Result<T, Error> {
        ask(
            |lookup| {
                self.sender.enqueue(Message::Lookup {
                    span: Span::current(),
                    lookup,
                })
            },
            make,
            Error::Closed,
        )
        .await
    }

    /// Returns the immutable block named by `reference`, if promoted.
    pub(crate) async fn block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        self.request(|reply| Lookup::Block { reference, reply })
            .await
    }

    /// Returns the immutable block with `digest`, if promoted.
    pub(crate) async fn block_by_digest(
        &self,
        digest: H::Digest,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        self.request(|reply| Lookup::BlockByDigest { digest, reply })
            .await
    }

    /// Returns the immutable block named by each reference, in request order.
    pub(crate) async fn blocks(
        &self,
        references: Vec<BlockRef<H::Digest>>,
    ) -> Result<BodyValues<H, B>, Error> {
        self.request(|reply| Lookup::Blocks { references, reply })
            .await
    }
}

/// Creates the promoter mailbox.
///
/// The catalog needs this mailbox before the promoter exists, and the promoter reads committed
/// outputs through the catalog, so the channel is created first and its receiver is passed to
/// [`super::Actor::new`].
pub(crate) fn channel<H, B>(
    metrics: impl RuntimeMetrics,
    capacity: NonZeroUsize,
) -> (Mailbox<H, B>, Receiver<H, B>)
where
    H: Hasher,
    B: Body<H>,
{
    let (sender, receiver) = mailbox::new(metrics, capacity);
    (Mailbox { sender }, receiver)
}
