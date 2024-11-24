use crate::authority::{wire, View};
use futures::{channel::mpsc, SinkExt};

pub enum Message {
    Fetch {
        proposals: Vec<View>,
        null: Vec<View>,
    },
    Notarized {
        notarization: wire::Notarization,

        // Used to indicate when to drop old notarizations
        // we are caching in memory.
        last_finalized: View,
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

    pub async fn fetch(&mut self, proposals: Vec<View>, null: Vec<View>) {
        self.sender
            .send(Message::Fetch { proposals, null })
            .await
            .expect("Failed to send notarizations");
    }

    pub async fn notarized(&mut self, notarization: wire::Notarization, last_finalized: View) {
        self.sender
            .send(Message::Notarized {
                view,
                notarization,
                last_finalized,
            })
            .await
            .expect("Failed to send notarization");
    }
}
