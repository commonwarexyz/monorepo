use bytes::Bytes;
use futures::{channel::mpsc, SinkExt, StreamExt};

use crate::{
    linked::{signer, Context},
    Application as A, Broadcaster, Digest,
};

enum Message {
    Broadcast(Bytes),
    Verify(Context, Digest),
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub async fn broadcast(&mut self, payload: Bytes) {
        let _ = self.sender.send(Message::Broadcast(payload)).await;
    }
}

impl A for Mailbox {
    type Context = Context;

    async fn verify(&mut self, context: Self::Context, payload: Digest) {
        let _ = self.sender.send(Message::Verify(context, payload)).await;
    }
}

pub struct Application {
    mailbox: mpsc::Receiver<Message>,
}

impl Application {
    pub fn new() -> (Self, Mailbox) {
        let (sender, receiver) = mpsc::channel(1024);
        (Application { mailbox: receiver }, Mailbox { sender })
    }

    pub async fn run(&mut self, mut signer: signer::Mailbox) {
        while let Some(msg) = self.mailbox.next().await {
            match msg {
                Message::Broadcast(payload) => {
                    let receiver = signer.broadcast(payload).await;
                    receiver.await.expect("Failed to broadcast");
                }
                Message::Verify(context, payload) => {
                    // Act as-if the application is verifying the payload.
                    signer.verified(context, payload).await;
                }
            }
        }
    }
}
