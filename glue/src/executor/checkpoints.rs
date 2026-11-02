//! The executed chain as a source of aggregation checkpoints.

use super::Mailbox;
use commonware_actor::Feedback;
use commonware_consensus::{
    Automaton, Block, Reporter, aggregation::types::Certificate, types::Height,
};
use commonware_cryptography::{Digested, Digestible as _, certificate::Scheme};
use commonware_utils::{
    channel::{fallible::OneshotExt as _, oneshot},
    sync::Mutex,
};
use std::{num::NonZeroU64, sync::Arc};

/// The newest certified checkpoint, shared by every clone of [`Checkpoints`].
type Latest<S, D> = Arc<Mutex<Option<Certificate<S, D>>>>;

/// Returns the height of the block checkpoint `checkpoint` certifies when checkpoints are taken
/// every `interval` blocks, or `None` if it exceeds the height space.
pub(super) fn height(checkpoint: Height, interval: NonZeroU64) -> Option<Height> {
    checkpoint
        .get()
        .checked_add(1)?
        .checked_mul(interval.get())
        .map(|end| Height::new(end - 1))
}

/// Feeds the executed chain's checkpoints to [`aggregation`] and applies its outcomes.
///
/// Checkpoint `k` certifies the block at height `(k + 1) * interval - 1`, the last block of every
/// run of `interval` blocks. Each block's digest commits to its parent, so a checkpoint covers the
/// whole executed chain below it.
///
/// As aggregation's [`Automaton`], it answers each checkpoint with the digest of the executed block
/// once the executor produces it. As aggregation's [`Reporter`], it keeps the newest certificate,
/// keeps the executor from pruning the certified block or the inputs after it, and halts the
/// executor once a certificate names a block other than the executed one. The caller configures
/// aggregation with the executor's fixed epoch and checkpoint range. An application archive
/// retains every reported certificate for resolver recovery, independently of the newest one.
///
/// [`aggregation`]: commonware_consensus::aggregation
pub struct Checkpoints<S: Scheme, B: Block> {
    chain: Mailbox<B>,
    interval: NonZeroU64,
    latest: Latest<S, B::Digest>,
}

impl<S: Scheme, B: Block> Clone for Checkpoints<S, B> {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            interval: self.interval,
            latest: Arc::clone(&self.latest),
        }
    }
}

impl<S: Scheme, B: Block> Checkpoints<S, B> {
    /// Creates checkpoints of `chain` every `interval` blocks.
    pub fn new(chain: Mailbox<B>, interval: NonZeroU64) -> Self {
        Self {
            chain,
            interval,
            latest: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns the height of the block checkpoint `checkpoint` certifies, or `None` if it exceeds
    /// the height space.
    pub fn height(&self, checkpoint: Height) -> Option<Height> {
        height(checkpoint, self.interval)
    }

    /// Returns the newest certified checkpoint, if any.
    pub fn latest(&self) -> Option<Certificate<S, B::Digest>> {
        self.latest.lock().clone()
    }

    /// Returns the number of blocks per checkpoint.
    pub const fn interval(&self) -> NonZeroU64 {
        self.interval
    }

    /// Returns the newest certified checkpoint and the executed block it certifies, if that
    /// block is retained and is the one the checkpoint certifies.
    pub async fn latest_retained(&self) -> Option<(Certificate<S, B::Digest>, Digested<B>)> {
        let certificate = self.latest()?;
        let block = self
            .chain
            .block_at(self.height(certificate.item.position)?)
            .await?;
        (block.digest() == certificate.item.digest).then_some((certificate, block))
    }
}

impl<S: Scheme, B: Block> Automaton for Checkpoints<S, B> {
    type Context = Height;
    type Digest = B::Digest;

    /// Answers with the digest of the block `checkpoint` certifies once it is executed.
    ///
    /// Dropping the answer, which aggregation treats as declining the checkpoint, means the block
    /// was executed but is no longer retained, or lies below the block a state sync started the
    /// chain from and was never offered as a target.
    async fn propose(&mut self, checkpoint: Height) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        if let Some(height) = self.height(checkpoint) {
            self.chain.subscribe(
                height,
                Box::new(move |block| {
                    response.send_lossy(block.digest());
                }),
            );
        }
        receiver
    }

    /// Answers whether `digest` is the digest of the block `checkpoint` certifies.
    async fn verify(
        &mut self,
        checkpoint: Height,
        digest: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        if let Some(height) = self.height(checkpoint) {
            self.chain.subscribe(
                height,
                Box::new(move |block| {
                    response.send_lossy(block.digest() == digest);
                }),
            );
        }
        receiver
    }
}

impl<S: Scheme, B: Block> Reporter for Checkpoints<S, B> {
    type Activity = Certificate<S, B::Digest>;

    fn report(&mut self, certificate: Self::Activity) -> Feedback {
        let Some(height) = self.height(certificate.item.position) else {
            return Feedback::Ok;
        };
        let digest = certificate.item.digest;
        {
            let mut latest = self.latest.lock();
            if latest
                .as_ref()
                .is_none_or(|latest| latest.item.position < certificate.item.position)
            {
                *latest = Some(certificate);
            }
        }
        self.chain.certified(height, digest)
    }
}
