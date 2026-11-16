use crate::authenticated::connection::{Kill, Killed};
use commonware_utils::channel::ring;
use std::{fmt, num::NonZeroUsize};

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

pub struct Mailbox {
    control: ring::Sender<Message>,
    kill: Kill,
}

impl Mailbox {
    pub fn new(size: NonZeroUsize) -> (Self, ring::Receiver<Message>) {
        let (sender, receiver) = ring::channel(size);
        (
            Self {
                control: sender,
                kill: Kill::new(),
            },
            receiver,
        )
    }

    pub fn kill(&self) {
        self.kill.fire();
        let _ = self.control.send_lossy(Message::Kill);
    }

    pub(crate) fn killed(&self) -> Killed {
        self.kill.subscribe()
    }
}

impl Clone for Mailbox {
    fn clone(&self) -> Self {
        Self {
            control: self.control.clone(),
            kill: self.kill.clone(),
        }
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
    use futures::{FutureExt, StreamExt};

    #[test]
    fn kill_retained_on_overflow() {
        let (mailbox, mut receiver) = Mailbox::new(NZUsize!(1));
        mailbox.kill();
        mailbox.kill();

        assert!(matches!(
            receiver.next().now_or_never(),
            Some(Some(Message::Kill))
        ));
        assert!(receiver.next().now_or_never().is_none());
    }
}
