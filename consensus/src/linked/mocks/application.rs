use crate::{linked::Context, Application as A, Broadcaster};
use commonware_utils::Array;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use tracing::error;

enum Message<D: Array, P: Array> {
    Broadcast(D),
    Verify(Context<P>, D, oneshot::Sender<bool>),
}

#[derive(Clone)]
pub struct Mailbox<D: Array, P: Array> {
    sender: mpsc::Sender<Message<D, P>>,
}

impl<D: Array, P: Array> Mailbox<D, P> {
    pub async fn broadcast(&mut self, payload: D) {
        let _ = self.sender.send(Message::Broadcast(payload)).await;
    }
}

impl<D: Array, P: Array> A for Mailbox<D, P> {
    type Context = Context<P>;
    type Digest = D;

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        let _ = self
            .sender
            .send(Message::Verify(context, payload, sender))
            .await;
        receiver
    }
}

pub struct Application<D: Array, P: Array> {
    mailbox: mpsc::Receiver<Message<D, P>>,
}

impl<D: Array, P: Array> Application<D, P> {
    pub fn new() -> (Self, Mailbox<D, P>) {
        let (sender, receiver) = mpsc::channel(1024);
        (Application { mailbox: receiver }, Mailbox { sender })
    }

    pub async fn run(mut self, mut engine: impl Broadcaster<Digest = D>) {
        while let Some(msg) = self.mailbox.next().await {
            match msg {
                Message::Broadcast(payload) => {
                    let receiver = engine.broadcast(payload).await;
                    let result = receiver.await;
                    match result {
                        Ok(true) => {}
                        Ok(false) => {
                            error!("broadcast returned false")
                        }
                        Err(_) => {
                            error!("broadcast dropped")
                        }
                    }
                }
                Message::Verify(_context, _payload, sender) => {
                    let result = sender.send(true);
                    if result.is_err() {
                        error!("verify dropped");
                    }
                }
            }
        }
    }
}
