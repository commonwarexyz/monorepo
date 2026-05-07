use crate::authenticated::Mailbox;
use commonware_utils::channel::actor::{Enqueue, FullPolicy, MessagePolicy};

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

impl MessagePolicy for Message {
    fn kind(&self) -> &'static str {
        "kill"
    }

    fn full_policy(&self) -> FullPolicy {
        FullPolicy::Replace
    }
}

impl Mailbox<Message> {
    pub fn kill(&mut self) -> Enqueue<Message> {
        self.enqueue(Message::Kill)
    }
}
