use crate::{threshold_simplex::types::Voter, types::View};
use commonware_cryptography::{Digest, PublicKey, bls12381::primitives::variant::Variant};
use futures::{
    SinkExt,
    channel::{mpsc, oneshot},
};

pub enum Message<P: PublicKey, V: Variant, D: Digest> {
    Update {
        current: View,
        leader: P,
        finalized: View,

        active: oneshot::Sender<bool>,
    },
    Constructed(Voter<V, D>),
}

#[derive(Clone)]
pub struct Mailbox<P: PublicKey, V: Variant, D: Digest> {
    sender: mpsc::Sender<Message<P, V, D>>,
}

impl<P: PublicKey, V: Variant, D: Digest> Mailbox<P, V, D> {
    pub fn new(sender: mpsc::Sender<Message<P, V, D>>) -> Self {
        Self { sender }
    }

    pub async fn update(&mut self, current: View, leader: P, finalized: View) -> bool {
        let (active, active_receiver) = oneshot::channel();
        self.sender
            .send(Message::Update {
                current,
                leader,
                finalized,
                active,
            })
            .await
            .expect("Failed to send update");
        active_receiver.await.unwrap()
    }

    pub async fn constructed(&mut self, message: Voter<V, D>) {
        self.sender
            .send(Message::Constructed(message))
            .await
            .expect("Failed to send message");
    }
}
