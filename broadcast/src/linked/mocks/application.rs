use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt, StreamExt};

use crate::{
    linked::{signer, Context},
    Application as A, Broadcaster,
};

enum Message<D: Digest> {
    Broadcast(D),
    Verify(Context, D),
}

#[derive(Clone)]
pub struct Mailbox<D: Digest> {
    sender: mpsc::Sender<Message<D>>,
}

impl<D: Digest> Mailbox<D> {
    pub async fn broadcast(&mut self, payload: D) {
        let _ = self.sender.send(Message::Broadcast(payload)).await;
    }
}

impl<D: Digest> A for Mailbox<D> {
    type Context = Context;
    type Digest = D;

    async fn verify(&mut self, context: Self::Context, payload: Self::Digest) {
        let _ = self.sender.send(Message::Verify(context, payload)).await;
    }
}

pub struct Application<D: Digest> {
    mailbox: mpsc::Receiver<Message<D>>,
}

impl<D: Digest> Application<D> {
    pub fn new() -> (Self, Mailbox<D>) {
        let (sender, receiver) = mpsc::channel(1024);
        (Application { mailbox: receiver }, Mailbox { sender })
    }

    pub async fn run(&mut self, mut signer: signer::Mailbox<D>) {
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
