use crate::authenticated::Mailbox;
use commonware_utils::channel::fallible::AsyncFallibleExt;

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

impl Mailbox<Message> {
    pub async fn kill(&mut self) {
        self.0.send_lossy(Message::Kill).await;
    }
}
