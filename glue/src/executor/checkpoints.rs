//! The executed chain as a source of aggregation checkpoints.

use super::Mailbox;
use commonware_actor::Feedback;
use commonware_consensus::{
    Automaton, Block, Monitor, Reporter,
    aggregation::types::{Activity, Certificate},
    types::{Epoch, Height},
};
use commonware_cryptography::certificate::Scheme;
use commonware_utils::{
    channel::{fallible::OneshotExt as _, mpsc, oneshot},
    sync::Mutex,
};
use std::{num::NonZeroU64, sync::Arc};

/// The newest certified checkpoint, shared by every clone of [`Checkpoints`].
type Latest<S, D> = Arc<Mutex<Option<Certificate<S, D>>>>;

/// Senders of every epoch subscription, kept open because the epoch never changes.
type Subscriptions = Arc<Mutex<Vec<mpsc::Sender<Epoch>>>>;

/// Feeds the executed chain's checkpoints to [`aggregation`] and applies its outcomes.
///
/// Checkpoint `k` certifies the block at height `(k + 1) * interval - 1`, the last block of every
/// run of `interval` blocks. Each block's digest commits to its parent, so a checkpoint covers the
/// whole executed chain below it.
///
/// As aggregation's [`Automaton`], it answers each checkpoint with the digest of the executed block
/// once the executor produces it. As aggregation's [`Reporter`], it keeps the newest certificate,
/// keeps the executor from pruning the certified block or the inputs after it, and halts the
/// executor once a certificate or aggregation's divergence report names a block other than the
/// executed one. As aggregation's [`Monitor`], it reports the executor's single epoch.
///
/// [`aggregation`]: commonware_consensus::aggregation
pub struct Checkpoints<S: Scheme, B: Block> {
    chain: Mailbox<B>,
    interval: NonZeroU64,
    latest: Latest<S, B::Digest>,
    subscriptions: Subscriptions,
}

impl<S: Scheme, B: Block> Clone for Checkpoints<S, B> {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            interval: self.interval,
            latest: Arc::clone(&self.latest),
            subscriptions: Arc::clone(&self.subscriptions),
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
            subscriptions: Arc::default(),
        }
    }

    /// Returns the height of the block checkpoint `checkpoint` certifies, or `None` if it exceeds
    /// the height space.
    pub fn height(&self, checkpoint: Height) -> Option<Height> {
        checkpoint
            .get()
            .checked_add(1)?
            .checked_mul(self.interval.get())
            .map(|end| Height::new(end - 1))
    }

    /// Returns the newest certified checkpoint, if any.
    pub fn latest(&self) -> Option<Certificate<S, B::Digest>> {
        self.latest.lock().clone()
    }
}

impl<S: Scheme, B: Block> Automaton for Checkpoints<S, B> {
    type Context = Height;
    type Digest = B::Digest;

    /// Answers with the digest of the block `checkpoint` certifies once it is executed.
    ///
    /// Dropping the answer, which aggregation treats as declining the checkpoint, means the block
    /// was executed but is no longer retained, or lies below the block a state sync started the
    /// chain from.
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
    type Activity = Activity<S, B::Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Activity::Certified(certificate) => {
                let Some(height) = self.height(certificate.item.height) else {
                    return Feedback::Ok;
                };
                let digest = certificate.item.digest;
                {
                    let mut latest = self.latest.lock();
                    if latest
                        .as_ref()
                        .is_none_or(|latest| latest.item.height < certificate.item.height)
                    {
                        *latest = Some(certificate);
                    }
                }
                self.chain.certified(height, digest)
            }
            Activity::Diverged(item) => match self.height(item.height) {
                Some(height) => self.chain.diverged(height),
                None => Feedback::Ok,
            },
            Activity::Ack(_) | Activity::Tip(_) => Feedback::Ok,
        }
    }
}

impl<S: Scheme, B: Block> Monitor for Checkpoints<S, B> {
    type Index = Epoch;

    /// Answers with the executor's epoch, which never changes.
    async fn subscribe(&mut self) -> (Epoch, mpsc::Receiver<Epoch>) {
        let (sender, receiver) = mpsc::channel(1);
        self.subscriptions.lock().push(sender);
        (self.chain.epoch(), receiver)
    }
}
