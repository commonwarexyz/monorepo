use crate::authenticated::mailbox::UnboundedMailbox;
use commonware_utils::channel::fallible::FallibleExt;

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

impl UnboundedMailbox<Message> {
    pub fn kill(&mut self) {
        self.0.send_lossy(Message::Kill);
    }
}
