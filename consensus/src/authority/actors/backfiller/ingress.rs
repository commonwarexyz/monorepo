use crate::authority::{actors::Proposal, wire, View};
use commonware_cryptography::{Digest, PublicKey};
use futures::{channel::mpsc, SinkExt};

pub enum Message {
    Proposals { digest: Digest, parents: u32 },
    Notarizations { view: View, children: u32 },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub async fn proposals(&mut self, digest: Digest, parents: u32) {
        self.sender
            .send(Message::Proposals { digest, parents })
            .await
            .unwrap();
    }

    pub async fn notarizations(&mut self, view: View, children: u32) {
        self.sender
            .send(Message::Notarizations { view, children })
            .await
            .unwrap();
    }
}
