use crate::threshold_simplex::types::{Proposal, View, Voter};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Digest};
use futures::{channel::mpsc, SinkExt};

pub enum Message<V: Variant, D: Digest> {
    Update {
        latest: View,
        leader: u32,
        oldest: View,
    },
    Message(Voter<V, D>),
}

#[derive(Clone)]
pub struct Mailbox<V: Variant, D: Digest> {
    sender: mpsc::Sender<Message<V, D>>,
}

impl<V: Variant, D: Digest> Mailbox<V, D> {
    pub fn new(sender: mpsc::Sender<Message<V, D>>) -> Self {
        Self { sender }
    }

    pub async fn update(&mut self, latest: View, leader: u32, oldest: View) {
        self.sender
            .send(Message::Update {
                latest,
                leader,
                oldest,
            })
            .await
            .expect("Failed to send update");
    }

    pub async fn message(&mut self, message: Voter<V, D>) {
        self.sender
            .send(Message::Message(message))
            .await
            .expect("Failed to send message");
    }
}
