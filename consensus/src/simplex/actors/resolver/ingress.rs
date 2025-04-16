use crate::simplex::types::{Notarization, Nullification, View};
use commonware_cryptography::Digest;
use commonware_utils::Array;
use futures::{channel::mpsc, SinkExt};

pub enum Message<S: Array, D: Digest> {
    Fetch {
        notarizations: Vec<View>,
        nullifications: Vec<View>,
    },
    Notarized {
        notarization: Notarization<S, D>,
    },
    Nullified {
        nullification: Nullification<S>,
    },
    Finalized {
        // Used to indicate when to prune old notarizations/nullifications.
        view: View,
    },
}

#[derive(Clone)]
pub struct Mailbox<S: Array, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Array, D: Digest> Mailbox<S, D> {
    pub(super) fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
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

    pub async fn notarized(&mut self, notarization: Notarization<S, D>) {
        self.sender
            .send(Message::Notarized { notarization })
            .await
            .expect("Failed to send notarization");
    }

    pub async fn nullified(&mut self, nullification: Nullification<S>) {
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
