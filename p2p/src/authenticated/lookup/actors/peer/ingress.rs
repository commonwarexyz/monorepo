use crate::authenticated::Mailbox;
use commonware_utils::channel::{actor::{self, Backpressure}, Feedback};

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

impl Backpressure for Message {
    fn handle(overflow: &mut actor::Overflow<'_, Self>, message: Self) -> Feedback {
        overflow.spill(message)
    }
}

impl Mailbox<Message> {
    pub fn kill(&mut self) -> Feedback {
        self.enqueue(Message::Kill)
    }
}
