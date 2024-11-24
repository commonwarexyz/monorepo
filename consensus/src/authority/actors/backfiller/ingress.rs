use crate::authority::{wire, View};
use futures::{channel::mpsc, SinkExt};

pub enum Message {
    Fetch {
        notarizations: Vec<View>,
        nullifications: Vec<View>,
    },
    Notarized {
        notarization: wire::Notarization,
    },
    Nullified {
        nullification: wire::Nullification,
    },
    Finalized {
        // Used to indicate when to prune old notarizations/nullifications.
        view: View,
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

    pub async fn fetch(&mut self, notarizations: Vec<View>, nullifications: Vec<View>) {
        self.sender
            .send(Message::Fetch {
                notarizations,
                nullifications,
            })
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
