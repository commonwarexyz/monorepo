use bytes::Bytes;
use commonware_cryptography::Digest;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use tracing::debug;

use crate::{
    linked::{actors::signer, Context},
    Application as A, Broadcaster, Collector as Z,
};

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Bytes>,
}

impl Mailbox {
    pub async fn broadcast(&mut self, payload: Bytes) {
        let _ = self.sender.send(payload).await;
    }
}

impl A for Mailbox {
    type Context = Context;
    async fn verify(
        &mut self,
        _context: Self::Context,
        _payload: commonware_cryptography::Digest,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        sender
            .send(true)
            .expect("Failed to send verification result");
        receiver
    }
}

impl Z for Mailbox {
    type Context = Context;
    type Proof = Bytes;
    async fn acknowledged(
        &mut self,
        _context: Self::Context,
        _payload: Digest,
        _proof: Self::Proof,
    ) {
        debug!("acknowledged");
    }
}

pub struct Application {
    mailbox: mpsc::Receiver<Bytes>,
}

impl Application {
    pub fn new() -> (Self, Mailbox) {
        let (sender, receiver) = mpsc::channel(1024);
        (Application { mailbox: receiver }, Mailbox { sender })
    }

    pub async fn run(&mut self, mut signer: signer::Mailbox) {
        while let Some(payload) = self.mailbox.next().await {
            let _ = signer.broadcast(payload).await;
        }
    }
}
