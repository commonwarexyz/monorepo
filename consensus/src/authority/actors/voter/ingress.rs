use crate::authority::wire;
use futures::{channel::mpsc, SinkExt};

// If either of these requests fails, it will not send a reply.
pub enum Message {
    Backfilled {
        notarizations: Vec<wire::Notarization>,
        nullifications: Vec<wire::Nullification>,
    },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub(crate) async fn backfilled(
        &mut self,
        notarizations: Vec<wire::Notarization>,
        nullifications: Vec<wire::Nullification>,
    ) {
        self.sender
            .send(Message::Backfilled {
                notarizations,
                nullifications,
            })
            .await
            .unwrap();
    }
}
