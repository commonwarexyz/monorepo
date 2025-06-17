use futures::{channel::mpsc, SinkExt};

/// Messages that can be sent to the peer [super::Actor].
#[derive(Clone, Debug)]
pub enum Message {
    /// Kill the peer actor.
    Kill,
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    #[cfg(test)]
    pub fn test() -> (Self, mpsc::Receiver<Message>) {
        let (sender, receiver) = mpsc::channel(1);
        (Self { sender }, receiver)
    }

    pub async fn kill(&mut self) {
        let _ = self.sender.send(Message::Kill).await;
    }
}
