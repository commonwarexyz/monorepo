use crate::authenticated::Mailbox;
use commonware_macros::ready;
use commonware_utils::channels::fallible::AsyncFallibleExt;

/// Messages that can be sent to the peer [super::Actor].
#[ready(2)]
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
