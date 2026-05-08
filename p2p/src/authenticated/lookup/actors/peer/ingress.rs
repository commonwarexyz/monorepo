use crate::authenticated::Mailbox;
use commonware_utils::channel::{actor::{self, Backpressure}, Feedback};
use std::collections::VecDeque;

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

impl Backpressure for Message {
    fn handle(queue: &mut VecDeque<Self>, message: Self) -> Feedback {
        actor::retain(queue, message)
    }
}

impl Mailbox<Message> {
    pub fn kill(&mut self) -> Feedback {
        self.enqueue(Message::Kill)
    }
}
