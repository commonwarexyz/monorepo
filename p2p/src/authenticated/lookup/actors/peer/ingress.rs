use commonware_utils::channel::ring;
use std::{fmt, num::NonZeroUsize};

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

pub struct Mailbox(ring::Sender<Message>);

impl Mailbox {
    pub fn new(size: NonZeroUsize) -> (Self, ring::Receiver<Message>) {
        let (sender, receiver) = ring::channel(size);
        (Self(sender), receiver)
    }

    pub fn kill(&self) {
        let _ = self.0.send_lossy(Message::Kill);
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
    use commonware_utils::{NZUsize, channel::ring::TryRecvError};

    #[test]
    fn kill_retained_on_overflow() {
        let (mailbox, mut receiver) = Mailbox::new(NZUsize!(1));
        mailbox.kill();
        mailbox.kill();

        assert!(matches!(receiver.try_recv(), Ok(Message::Kill)));
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
    }
}
