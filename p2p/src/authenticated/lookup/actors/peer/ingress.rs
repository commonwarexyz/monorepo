use commonware_actor::mailbox::{self, Policy};
use std::{collections::VecDeque, fmt, num::NonZeroUsize};

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

impl Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.clear();
        overflow.push_back(message);
    }
}

pub struct Mailbox(mailbox::Sender<Message>);

impl Mailbox {
    pub fn new(size: NonZeroUsize) -> (Self, mailbox::Receiver<Message>) {
        let (sender, receiver) = mailbox::new(size);
        (Self(sender), receiver)
    }

    pub fn kill(&self) {
        let _ = self.0.enqueue(Message::Kill);
    }
}

impl Clone for Mailbox {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Mailbox").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZUsize;

    #[test]
    fn kill_retained_on_overflow() {
        let (mailbox, mut receiver) = Mailbox::new(NZUsize!(1));
        mailbox.kill();
        mailbox.kill();

        assert!(matches!(receiver.try_recv(), Ok(Message::Kill)));
        assert!(matches!(receiver.try_recv(), Ok(Message::Kill)));
        assert!(receiver.try_recv().is_err());
    }
}
