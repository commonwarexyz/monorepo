use crate::authenticated::Mailbox;
use commonware_utils::channel::actor::{Backpressure, Enqueue, MessagePolicy};
use std::collections::VecDeque;

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

impl MessagePolicy for Message {
    fn backpressure(queue: &mut VecDeque<Self>, message: Self) -> Backpressure<Self> {
        Backpressure::retain(queue, message)
    }
}

impl Mailbox<Message> {
    pub fn kill(&mut self) -> Enqueue<Message> {
        self.enqueue(Message::Kill)
    }
}
