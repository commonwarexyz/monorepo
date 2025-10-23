use crate::{
    simplex::{signing_scheme::Scheme, types::Voter},
    types::View,
};
use commonware_cryptography::{Digest, PublicKey};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use tracing::error;

pub enum Message<P: PublicKey, S: Scheme, D: Digest> {
    Update {
        current: View,
        leader: P,
        finalized: View,

        active: oneshot::Sender<bool>,
    },
    Constructed(Voter<S, D>),
}

#[derive(Clone)]
pub struct Mailbox<P: PublicKey, S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<P, S, D>>,
}

impl<P: PublicKey, S: Scheme, D: Digest> Mailbox<P, S, D> {
    pub fn new(sender: mpsc::Sender<Message<P, S, D>>) -> Self {
        Self { sender }
    }

    pub async fn update(&mut self, current: View, leader: P, finalized: View) -> bool {
        let (active, active_receiver) = oneshot::channel();
        if let Err(err) = self
            .sender
            .send(Message::Update {
                current,
                leader,
                finalized,
                active,
            })
            .await
        {
            error!(?err, "failed to send update message");
            return false;
        }
        match active_receiver.await {
            Ok(active) => active,
            Err(err) => {
                error!(?err, "failed to receive active response");
                false
            }
        }
    }

    pub async fn constructed(&mut self, message: Voter<S, D>) {
        if let Err(err) = self.sender.send(Message::Constructed(message)).await {
            error!(?err, "failed to send constructed message");
        }
    }
}
