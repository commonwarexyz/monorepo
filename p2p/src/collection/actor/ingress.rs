use crate::{collection::Collector, Recipients};
use commonware_cryptography::{Committable, Digest, Digestible, PublicKey};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::{collections::HashMap, fmt::Debug};

pub enum Message<
    D: Digest,
    P: PublicKey,
    Req: Committable + Digestible<Digest = D>,
    Res: Digestible<Digest = D>,
> {
    Send {
        request: Req,
        recipients: Recipients<P>,
        responder: oneshot::Sender<Vec<P>>,
    },
    Peek {
        digest: D,
        sender: oneshot::Sender<HashMap<P, Res>>,
    },
    Cancel {
        digest: D,
    },
}

#[derive(Clone)]
pub struct Mailbox<
    D: Digest,
    P: PublicKey,
    Req: Committable + Digestible<Digest = D>,
    Res: Digestible<Digest = D>,
> {
    sender: mpsc::Sender<Message<D, P, Req, Res>>,
}

impl<
        D: Digest,
        P: PublicKey,
        Req: Committable + Digestible<Digest = D>,
        Res: Digestible<Digest = D>,
    > Mailbox<D, P, Req, Res>
{
    pub fn new(sender: mpsc::Sender<Message<D, P, Req, Res>>) -> Self {
        Self { sender }
    }
}

impl<
        D: Digest,
        P: PublicKey,
        Req: Committable + Digestible<Digest = D> + Debug,
        Res: Digestible<Digest = D> + Debug,
    > Collector<D> for Mailbox<D, P, Req, Res>
{
    type Request = Req;
    type Response = Res;
    type PublicKey = P;

    async fn send(&mut self, request: Req, recipients: Recipients<P>) -> Vec<P> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .sender
            .send(Message::Send {
                request,
                recipients,
                responder: tx,
            })
            .await;
        rx.await.unwrap()
    }

    async fn peek(&mut self, digest: D) -> Option<HashMap<P, Res>> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(Message::Peek { digest, sender: tx }).await;
        rx.await.ok()
    }

    async fn cancel(&mut self, digest: D) {
        let _ = self.sender.send(Message::Cancel { digest }).await;
    }
}
