use crate::threshold_simplex::types::{View, Voter};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Digest};
use futures::{channel::mpsc, SinkExt};

pub enum Message<V: Variant, D: Digest> {
    Update {
        current: View,
        leader: u32,
        finalized: View,
    },
    Verified(Voter<V, D>),
}

#[derive(Clone)]
pub struct Mailbox<V: Variant, D: Digest> {
    sender: mpsc::Sender<Message<V, D>>,
}

impl<V: Variant, D: Digest> Mailbox<V, D> {
    pub fn new(sender: mpsc::Sender<Message<V, D>>) -> Self {
        Self { sender }
    }

    pub async fn update(&mut self, current: View, leader: u32, finalized: View) {
        self.sender
            .send(Message::Update {
                current,
                leader,
                finalized,
            })
            .await
            .expect("Failed to send update");
    }

    pub async fn verified(&mut self, message: Voter<V, D>) {
        self.sender
            .send(Message::Verified(message))
            .await
            .expect("Failed to send message");
    }
}
