//! The public mailbox.

use super::{
    input::{Lane, Message, Reply},
    relay::Staged,
    store::blocks::Block,
    types::{Custody, Error, Floor, MarshalProgress, OutputIndex},
};
use crate::{
    Reporter,
    multimmit::{
        scheme::Scheme,
        types::{Activity, BlockRef, Body, CertificateId, Lqc},
    },
};
use commonware_actor::Feedback;
use commonware_cryptography::Hasher;
use commonware_utils::{
    channel::{mpsc, oneshot},
    sync::Mutex,
};
use std::{num::NonZeroUsize, sync::Arc};

/// The handle to a running marshal: requests, and the reporter consensus feeds.
///
/// Requests other than [`Mailbox::subscribe_block`] fail with [`Error::Busy`] when marshal's
/// queue is full; a subscription waits for room instead.
pub struct Mailbox<H: Hasher, S: Scheme, B: Body<H>> {
    sender: mpsc::Sender<Message<H, S, B>>,
    lane: Arc<Lane<S, H::Digest>>,
    staged: Option<Arc<Mutex<Staged<H, B>>>>,
    max_pending_acks: NonZeroUsize,
}

impl<H: Hasher, S: Scheme, B: Body<H>> Clone for Mailbox<H, S, B> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            lane: Arc::clone(&self.lane),
            staged: self.staged.clone(),
            max_pending_acks: self.max_pending_acks,
        }
    }
}

impl<H: Hasher, S: Scheme, B: Body<H>> Mailbox<H, S, B> {
    pub(super) const fn new(
        sender: mpsc::Sender<Message<H, S, B>>,
        lane: Arc<Lane<S, H::Digest>>,
        staged: Option<Arc<Mutex<Staged<H, B>>>>,
        max_pending_acks: NonZeroUsize,
    ) -> Self {
        Self {
            sender,
            lane,
            staged,
            max_pending_acks,
        }
    }

    /// Returns the most delivered outputs awaiting acknowledgement at once.
    pub const fn max_pending_acks(&self) -> NonZeroUsize {
        self.max_pending_acks
    }

    /// Sends a request built around its reply channel and waits for the reply.
    async fn request<T>(
        &self,
        build: impl FnOnce(Reply<T>) -> Message<H, S, B>,
    ) -> Result<T, Error> {
        let (reply, receiver) = oneshot::channel();
        match self.sender.try_send(build(reply)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => return Err(Error::Busy),
            Err(mpsc::error::TrySendError::Closed(_)) => return Err(Error::Closed),
        }
        receiver.await.unwrap_or(Err(Error::Closed))
    }

    /// Holds a complete block durably.
    ///
    /// Returns once marshal accepted the block; the returned [`Custody`] resolves when the block
    /// is crash-recoverable. With a [`Relay`](super::Relay), the block is also kept for
    /// broadcast.
    pub async fn stage_block(&self, block: impl Into<Block<H, B>>) -> Result<Custody, Error> {
        let block = block.into();
        let staged = self.staged.as_ref().map(|_| Arc::clone(&block));
        let custody = self
            .request(|reply| Message::Stage { block, reply })
            .await?;
        if let (Some(set), Some(block)) = (&self.staged, staged) {
            set.lock().insert(block);
        }
        Ok(custody)
    }

    /// Holds a complete block durably and waits until it is crash-recoverable.
    pub async fn put_block(&self, block: impl Into<Block<H, B>>) -> Result<(), Error> {
        self.stage_block(block).await?.wait().await
    }

    /// Returns the retained L-QC with exactly `id`, without asking peers.
    pub async fn get_certificate(
        &self,
        id: CertificateId<H::Digest>,
    ) -> Result<Option<Arc<Lqc<S, H::Digest>>>, Error> {
        self.request(|reply| Message::Certificate {
            id,
            fetch: false,
            reply,
        })
        .await
    }

    /// Returns the L-QC with exactly `id`, asking peers when it is not retained. Dropping the
    /// future stops waiting.
    pub async fn fetch_certificate(
        &self,
        id: CertificateId<H::Digest>,
    ) -> Result<Arc<Lqc<S, H::Digest>>, Error> {
        self.request(|reply| Message::Certificate {
            id,
            fetch: true,
            reply,
        })
        .await?
        .ok_or(Error::Closed)
    }

    /// Returns the held block with exactly `reference`, without asking peers.
    pub async fn get_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<Block<H, B>>, Error> {
        self.request(|reply| Message::Get {
            block: reference,
            reply,
        })
        .await
    }

    /// Returns the block with exactly `reference`, asking peers when it is not held. Dropping the
    /// future stops waiting.
    pub async fn fetch_block(&self, reference: BlockRef<H::Digest>) -> Result<Block<H, B>, Error> {
        self.request(|reply| Message::Fetch {
            block: reference,
            reply,
        })
        .await
    }

    /// Returns the block with exactly `reference` once marshal holds it durably, from local
    /// custody or the broadcast buffer. Never asks peers.
    pub async fn subscribe_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Block<H, B>, Error> {
        let (reply, receiver) = oneshot::channel();
        self.sender
            .send(Message::Subscribe {
                block: reference,
                reply,
            })
            .await
            .map_err(|_| Error::Closed)?;
        let block = receiver.await.unwrap_or(Err(Error::Closed))?;
        if let Some(staged) = &self.staged {
            staged.lock().remember(Arc::clone(&block));
        }
        Ok(block)
    }

    /// Returns the newest retained floor whose index is at most `at`, with its index.
    pub async fn floor_at(
        &self,
        at: OutputIndex,
    ) -> Result<Option<(OutputIndex, Floor<S, H::Digest>)>, Error> {
        self.request(|reply| Message::FloorAt { at, reply }).await
    }

    /// Verifies and installs a newer floor, resuming delivery after it.
    ///
    /// Fails with [`Error::Rejected`], leaving marshal unchanged, when the floor does not verify,
    /// is not newer than the installed one, or is behind the acknowledged output.
    pub async fn install_floor(&self, floor: Floor<S, H::Digest>) -> Result<(), Error> {
        self.request(|reply| Message::Install { floor, reply })
            .await
    }

    /// Drops what the newest floor at or below `below` (and at or below the acknowledged output)
    /// makes obsolete, keeping that floor servable and every block the engine may still verify.
    pub async fn prune(&self, below: OutputIndex) -> Result<(), Error> {
        self.request(|reply| Message::Prune { below, reply }).await
    }

    /// Returns marshal's progress.
    pub async fn progress(&self) -> Result<MarshalProgress<H::Digest>, Error> {
        self.request(|reply| Message::Progress { reply }).await
    }
}

/// Consensus reports its activity here. Only proofs, placement and certificate records matter
/// to marshal; reporting never blocks consensus.
impl<H: Hasher, S: Scheme, B: Body<H>> Reporter for Mailbox<H, S, B> {
    type Activity = Activity<S, H::Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.lane.report(activity)
    }
}
