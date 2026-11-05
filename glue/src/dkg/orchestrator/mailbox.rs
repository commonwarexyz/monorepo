//! Mailbox for the [`Actor`].
//!
//! [`Actor`]: super::Actor

use crate::dkg::ReshareBlock;
use commonware_actor::{
    Feedback,
    mailbox::{Policy, Sender},
};
use commonware_consensus::{
    Reporter,
    marshal::{Finality, Update},
    simplex::scheme::Scheme,
};
use commonware_cryptography::{Digest, Digested};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use std::collections::VecDeque;

/// Messages that can be sent to the orchestrator.
pub enum Message<B, S, D, A = Exact>
where
    B: ReshareBlock,
    S: Scheme<D>,
    D: Digest,
    A: Acknowledgement,
{
    /// A block finalized by marshal and its [`Finality`].
    ///
    /// The orchestrator acknowledges the final block of the active epoch only after
    /// entering the next epoch, and every earlier block immediately. It panics on
    /// a later block, which means marshal skipped the final block.
    Finalized {
        block: Digested<B>,
        finality: Finality<S, D>,
        acknowledgement: A,
    },
}

impl<B, S, D, A> Policy for Message<B, S, D, A>
where
    B: ReshareBlock,
    S: Scheme<D>,
    D: Digest,
    A: Acknowledgement,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        // A dropped report would leave its block unacknowledged.
        overflow.push_back(message);
    }
}

/// Marshal reporter that forwards finalized blocks to the orchestrator (other
/// updates are ignored).
#[derive(Debug, Clone)]
pub struct Mailbox<B, S, D, A = Exact>
where
    B: ReshareBlock,
    S: Scheme<D>,
    D: Digest,
    A: Acknowledgement,
{
    sender: Sender<Message<B, S, D, A>>,
}

impl<B, S, D, A> Mailbox<B, S, D, A>
where
    B: ReshareBlock,
    S: Scheme<D>,
    D: Digest,
    A: Acknowledgement,
{
    /// Creates a mailbox that sends to `sender`.
    pub const fn new(sender: Sender<Message<B, S, D, A>>) -> Self {
        Self { sender }
    }
}

impl<B, S, D, A> Reporter for Mailbox<B, S, D, A>
where
    B: ReshareBlock,
    S: Scheme<D>,
    D: Digest,
    A: Acknowledgement,
{
    type Activity = Update<B, S, D, A>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update::Block(block, finality, acknowledgement) = activity else {
            return Feedback::Ok;
        };
        self.sender.enqueue(Message::Finalized {
            block,
            finality,
            acknowledgement,
        })
    }
}
