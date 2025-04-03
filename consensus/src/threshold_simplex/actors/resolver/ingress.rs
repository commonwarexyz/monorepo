use crate::threshold_simplex::types::{Notarization, Nullification, View};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};

pub enum Message<D: Digest> {
    Fetch {
        notarizations: Vec<View>,
        nullifications: Vec<View>,
    },
    Notarized {
        notarization: Notarization<D>,
    },
    Nullified {
        nullification: Nullification,
    },
    Finalized {
        // Used to indicate when to prune old notarizations/nullifications.
        view: View,
    },
}

#[derive(Clone)]
pub struct Mailbox<D: Digest> {
    sender: mpsc::Sender<Message<D>>,
}

impl<D: Digest> Mailbox<D> {
    pub(super) fn new(sender: mpsc::Sender<Message<D>>) -> Self {
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

    pub async fn notarized(&mut self, notarization: Notarization<D>) {
        self.sender
            .send(Message::Notarized { notarization })
            .await
            .expect("Failed to send notarization");
    }

    pub async fn nullified(&mut self, nullification: Nullification) {
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
