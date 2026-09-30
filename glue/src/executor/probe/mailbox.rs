//! Requests to the [`Probe`](super::Probe).

use super::Sampled;
use commonware_actor::mailbox::{Policy, Sender};
use commonware_consensus::{Block, aggregation::scheme::Scheme};
use commonware_utils::channel::oneshot;
use std::collections::VecDeque;

/// A request to the probe.
pub(super) enum Message<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block,
{
    /// Samples the validators' newest checkpoints.
    Sample {
        response: oneshot::Sender<Sampled<S, B, F>>,
    },
}

/// Drops samples whose caller left.
impl<S, B, F> Policy for Message<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block,
    F: Send + 'static,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        let Self::Sample { response } = &message;
        if !response.is_closed() {
            overflow.push_back(message);
        }
    }
}

/// Requests to the [`Probe`](super::Probe).
pub struct Mailbox<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block,
    F: Send + 'static,
{
    sender: Sender<Message<S, B, F>>,
}

impl<S, B, F> Clone for Mailbox<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block,
    F: Send + 'static,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<S, B, F> Mailbox<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block,
    F: Send + 'static,
{
    pub(super) const fn new(sender: Sender<Message<S, B, F>>) -> Self {
        Self { sender }
    }

    /// Samples the validators' newest checkpoints and returns the newest one, with every floor
    /// the replies carried, or `None` if the probe stopped first.
    ///
    /// A call joins the sample in progress, or starts one that asks every validator, and counts
    /// the replies that arrive while it waits. Replies carry no request identifier, so a late reply
    /// to an earlier request may count too.
    pub async fn sample(&self) -> Option<Sampled<S, B, F>> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Sample { response });
        receiver.await.ok()
    }
}
