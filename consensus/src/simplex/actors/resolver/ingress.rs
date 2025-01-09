use crate::simplex::{wire, View};
use futures::{channel::mpsc, SinkExt};

pub enum Message {
    Fetch {
        seeds: Vec<View>,
        notarizations: Vec<View>,
        nullifications: Vec<View>,
    },
    Seeded {
        seed: wire::Seed,
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

    pub async fn fetch(
        &mut self,
        seeds: Vec<View>,
        notarizations: Vec<View>,
        nullifications: Vec<View>,
    ) {
        self.sender
            .send(Message::Fetch {
                seeds,
                notarizations,
                nullifications,
            })
            .await
            .expect("Failed to send notarizations");
    }

    pub async fn seeded(&mut self, seed: wire::Seed) {
        self.sender
            .send(Message::Seeded { seed })
            .await
            .expect("Failed to send seed");
    }

    pub async fn notarized(&mut self, notarization: wire::Notarization) {
        self.sender
            .send(Message::Notarized { notarization })
            .await
            .expect("Failed to send notarization");
    }

    pub async fn nullified(&mut self, nullification: wire::Nullification) {
        self.sender
            .send(Message::Nullified { nullification })
            .await
            .expect("Failed to send nullification");
    }

    pub async fn finalized(&mut self, view: View) {
        self.sender
            .send(Message::Finalized { view })
            .await
            .expect("Failed to send finalized view");
    }
}
