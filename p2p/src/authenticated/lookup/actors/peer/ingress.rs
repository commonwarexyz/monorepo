use crate::authenticated::Mailbox;

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

impl Mailbox<Message> {
    pub async fn kill(&mut self) {
        let _ = self.send(Message::Kill).await;
    }
}
