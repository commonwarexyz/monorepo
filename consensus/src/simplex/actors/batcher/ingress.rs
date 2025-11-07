use crate::{
    simplex::{signing_scheme::Scheme, types::Voter},
    types::View,
};
use commonware_cryptography::Digest;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use tracing::error;

pub enum Message<S: Scheme, D: Digest> {
    Update {
        current: View,
        leader: u32,
        finalized: View,

        active: oneshot::Sender<bool>,
    },
    Constructed(Voter<S, D>),
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    pub fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    pub async fn update(&mut self, current: View, leader: u32, finalized: View) -> bool {
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
            return true; // default to active
        }
        match active_receiver.await {
            Ok(active) => active,
            Err(err) => {
                error!(?err, "failed to receive active response");
                true // default to active
            }
        }
    }

    pub async fn constructed(&mut self, message: Voter<S, D>) {
        if let Err(err) = self.sender.send(Message::Constructed(message)).await {
            error!(?err, "failed to send constructed message");
        }
    }
}
