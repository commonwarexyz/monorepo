use crate::authenticated::Mailbox;
use futures::SinkExt;

/// Messages that can be sent to the peer [`Actor`](`super::Actor`).
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

impl Mailbox<Message> {
    pub async fn kill(&mut self) {
        let _ = self.0.send(Message::Kill).await;
    }
}
