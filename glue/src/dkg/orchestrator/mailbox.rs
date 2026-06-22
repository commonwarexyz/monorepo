//! Mailbox for the [`Actor`].
//!
//! [`Actor`]: super::Actor

use crate::dkg::ReshareBlock;
use commonware_actor::{
    mailbox::{Policy, Sender},
    Feedback,
};
use commonware_consensus::{marshal::Update, Reporter};
use commonware_utils::{acknowledgement::Exact, Acknowledgement};
use std::collections::VecDeque;

/// Messages that can be sent to the orchestrator.
pub enum Message<B, A = Exact>
where
    B: ReshareBlock,
    A: Acknowledgement,
{
    Finalized { block: B, acknowledgement: A },
}

impl<B, A> Policy for Message<B, A>
where
    B: ReshareBlock,
    A: Acknowledgement,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut VecDeque<Self>, message: Self) {
        // Ensure delivery
        overflow.push_back(message);
    }
}

/// Inbound communication channel for epoch transitions.
#[derive(Debug, Clone)]
pub struct Mailbox<B, A = Exact>
where
    B: ReshareBlock,
    A: Acknowledgement,
{
    sender: Sender<Message<B, A>>,
}

impl<B, A> Mailbox<B, A>
where
    B: ReshareBlock,
    A: Acknowledgement,
{
    /// Create a new [Mailbox].
    pub const fn new(sender: Sender<Message<B, A>>) -> Self {
        Self { sender }
    }
}

impl<B, A> Reporter for Mailbox<B, A>
where
    B: ReshareBlock,
    A: Acknowledgement,
{
    type Activity = Update<B, A>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update::Block(block, acknowledgement) = activity else {
            return Feedback::Ok;
        };
        self.sender.enqueue(Message::Finalized {
            block,
            acknowledgement,
        })
    }
}
