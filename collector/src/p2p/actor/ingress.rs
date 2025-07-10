use crate::p2p::Originator;
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_p2p::Recipients;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::{collections::HashMap, fmt::Debug};

pub enum Message<
    P: PublicKey,
    Rq: Committable + Digestible,
    Rs: Committable<Commitment = Rq::Commitment> + Digestible<Digest = Rq::Digest>,
> {
    Send {
        request: Rq,
        recipients: Recipients<P>,
        responder: oneshot::Sender<Vec<P>>,
    },
    Peek {
        commitment: Rq::Commitment,
        sender: oneshot::Sender<HashMap<P, Rs>>,
    },
    Cancel {
        commitment: Rq::Commitment,
    },
}

#[derive(Clone)]
pub struct Mailbox<
    P: PublicKey,
    Rq: Committable + Digestible,
    Rs: Committable<Commitment = Rq::Commitment> + Digestible<Digest = Rq::Digest>,
> {
    sender: mpsc::Sender<Message<P, Rq, Rs>>,
}

impl<
        P: PublicKey,
        Rq: Committable + Digestible,
        Rs: Committable<Commitment = Rq::Commitment> + Digestible<Digest = Rq::Digest>,
    > Mailbox<P, Rq, Rs>
{
    pub fn new(sender: mpsc::Sender<Message<P, Rq, Rs>>) -> Self {
        Self { sender }
    }
}

impl<
        P: PublicKey,
        Rq: Committable + Digestible + Debug,
        Rs: Committable<Commitment = Rq::Commitment> + Digestible<Digest = Rq::Digest> + Debug,
    > Originator for Mailbox<P, Rq, Rs>
{
    type Request = Rq;
    type Response = Rs;
    type PublicKey = P;

    async fn send(&mut self, request: Rq, recipients: Recipients<P>) -> Vec<P> {
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

    async fn peek(&mut self, commitment: Rq::Commitment) -> Option<HashMap<P, Rs>> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .sender
            .send(Message::Peek {
                commitment,
                sender: tx,
            })
            .await;
        rx.await.ok()
    }

    async fn cancel(&mut self, commitment: Rq::Commitment) {
        let _ = self.sender.send(Message::Cancel { commitment }).await;
    }
}
