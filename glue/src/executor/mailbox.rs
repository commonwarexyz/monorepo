//! Ingress for the engine's marshal and the executed chain for consumers.

use commonware_actor::{
    Feedback,
    mailbox::{Policy, Sender},
};
use commonware_consensus::{
    Block, Reporter,
    ancestry::BlockProvider,
    marshal::{Delivery, Finalized, Ledger, Linear},
    types::{Epoch, Height, OutputIndex},
};
use commonware_cryptography::Digestible;
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, future::Future, num::NonZeroUsize, sync::Arc};

/// Called with an executed block.
pub(super) type Subscriber<B> = Box<dyn FnOnce(&Arc<B>) + Send>;

/// An input the engine's marshal finalized.
pub(super) struct Input<I, A>(pub(super) Finalized<I, A>);

/// Keeps every input, in order.
impl<I, A> Policy for Input<I, A>
where
    I: Send + Sync + 'static,
    A: Send + 'static,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, input: Self) {
        overflow.push_back(input);
    }
}

/// A request to the executor.
pub(super) enum Message<B: Digestible> {
    /// Returns the executed block at `height`, if retained.
    Block {
        height: Height,
        response: oneshot::Sender<Option<Arc<B>>>,
    },
    /// Calls `subscriber` with the block at `height` once it is executed, or drops it if that
    /// block is no longer retained.
    Subscribe {
        height: Height,
        subscriber: Subscriber<B>,
    },
    /// Allows pruning executed blocks, and the inputs they executed, below `below`.
    Prune { below: Height },
    /// A checkpoint certified `digest` as the block at `height`.
    Certified { height: Height, digest: B::Digest },
    /// More validators than can be faulty signed a block other than the executed one at
    /// `height`.
    Diverged { height: Height },
}

/// Keeps every request in order, and drops reads whose caller left.
impl<B: Digestible + Send + Sync + 'static> Policy for Message<B> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if let Self::Block { response, .. } = &message
            && response.is_closed()
        {
            return;
        }
        overflow.push_back(message);
    }
}

/// The executor's ingress for the engine's marshal, which reports finalized inputs to it.
pub struct Inbox<U: Delivery> {
    sender: Sender<Input<U::Block, U::Acknowledgement>>,
}

impl<U: Delivery> Clone for Inbox<U> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<U: Delivery> Inbox<U> {
    pub(super) const fn new(sender: Sender<Input<U::Block, U::Acknowledgement>>) -> Self {
        Self { sender }
    }
}

impl<U: Delivery> Reporter for Inbox<U> {
    type Activity = U;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity.finalized() {
            Some(input) => self.sender.enqueue(Input(input)),
            None => Feedback::Ok,
        }
    }
}

/// The executor stopped, so the executed chain no longer serves requests.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("executor stopped")]
pub struct Stopped;

/// The executed chain, for its consumers.
///
/// The executed chain is [`Linear`]: the block at height `h` executed the input at index `h`, and
/// its parent is the block at height `h - 1`.
pub struct Mailbox<B: Block> {
    sender: Sender<Message<B>>,
    ack_window: NonZeroUsize,
    /// The epoch of every input.
    epoch: Epoch,
}

impl<B: Block> Clone for Mailbox<B> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            ack_window: self.ack_window,
            epoch: self.epoch,
        }
    }
}

impl<B: Block> Mailbox<B> {
    pub(super) const fn new(
        sender: Sender<Message<B>>,
        ack_window: NonZeroUsize,
        epoch: Epoch,
    ) -> Self {
        Self {
            sender,
            ack_window,
            epoch,
        }
    }

    /// Returns the epoch of every input.
    pub(super) const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the executed block at `height`, if retained, or `None` once the executor stopped.
    pub async fn block_at(&self, height: Height) -> Option<Arc<B>> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Block { height, response });
        receiver.await.ok().flatten()
    }

    /// Calls `subscriber` with the block at `height` once it is executed.
    pub(super) fn subscribe(&self, height: Height, subscriber: Subscriber<B>) {
        let _ = self
            .sender
            .enqueue(Message::Subscribe { height, subscriber });
    }

    /// Reports that a checkpoint certified `digest` as the block at `height`.
    pub(super) fn certified(&self, height: Height, digest: B::Digest) -> Feedback {
        self.sender.enqueue(Message::Certified { height, digest })
    }

    /// Reports that more validators than can be faulty signed another block at `height`.
    pub(super) fn diverged(&self, height: Height) -> Feedback {
        self.sender.enqueue(Message::Diverged { height })
    }
}

impl<B: Block> Ledger for Mailbox<B> {
    type Block = B;
    type Error = Stopped;

    async fn prune(&self, below: OutputIndex) -> Result<(), Stopped> {
        let below = Height::new(below.get());
        if self.sender.enqueue(Message::Prune { below }).accepted() {
            Ok(())
        } else {
            Err(Stopped)
        }
    }

    fn ack_window(&self) -> NonZeroUsize {
        self.ack_window
    }
}

impl<B: Block> Linear for Mailbox<B> {}

impl<B: Block> BlockProvider for Mailbox<B> {
    type Block = B;

    fn subscribe_parent(&self, block: &B) -> impl Future<Output = Option<Arc<B>>> + Send + 'static {
        let mailbox = self.clone();
        let parent = block.height().previous();
        async move { mailbox.block_at(parent?).await }
    }
}
