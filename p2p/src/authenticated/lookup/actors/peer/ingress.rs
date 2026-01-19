use crate::authenticated::Mailbox;
use commonware_macros::ready;
use commonware_utils::channels::fallible::AsyncFallibleExt;

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
#[ready(0)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

impl Mailbox<Message> {
    pub async fn kill(&mut self) {
        self.0.send_lossy(Message::Kill).await;
    }
}
