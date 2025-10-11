use crate::{
    threshold_simplex::types::{SigningScheme, Voter},
    types::View,
};
use commonware_cryptography::{Digest, PublicKey};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

pub enum Message<P: PublicKey, S: SigningScheme, D: Digest> {
    Update {
        current: View,
        leader: P,
        finalized: View,

        active: oneshot::Sender<bool>,
    },
    Constructed(Voter<S, D>),
}

#[derive(Clone)]
pub struct Mailbox<P: PublicKey, S: SigningScheme, D: Digest> {
    sender: mpsc::Sender<Message<P, S, D>>,
}

impl<P: PublicKey, S: SigningScheme, D: Digest> Mailbox<P, S, D> {
    pub fn new(sender: mpsc::Sender<Message<P, S, D>>) -> Self {
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

    pub async fn constructed(&mut self, message: Voter<S, D>) {
        self.sender
            .send(Message::Constructed(message))
            .await
            .expect("Failed to send message");
    }
}
