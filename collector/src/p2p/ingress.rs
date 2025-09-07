use crate::Originator;
use commonware_codec::Codec;
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_p2p::Recipients;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// Messages that can be sent to a [Mailbox].
pub enum Message<P: PublicKey, R: Committable + Digestible + Codec> {
    Send {
        request: R,
        recipients: Recipients<P>,
        responder: oneshot::Sender<Vec<P>>,
    },
    Cancel {
        commitment: R::Commitment,
    },
}

/// A mailbox that can be used to send and receive [Message]s.
#[derive(Clone)]
pub struct Mailbox<P: PublicKey, R: Committable + Digestible + Codec> {
    sender: mpsc::Sender<Message<P, R>>,
}

impl<P: PublicKey, R: Committable + Digestible + Codec> Mailbox<P, R> {
    /// Creates a new [Mailbox] with the given [mpsc::Sender].
    pub fn new(sender: mpsc::Sender<Message<P, R>>) -> Self {
        Self { sender }
    }
}

impl<P: PublicKey, R: Committable + Digestible + Codec> Originator for Mailbox<P, R> {
    type Request = R;
    type PublicKey = P;

    async fn send(&mut self, recipients: Recipients<P>, request: R) -> Vec<P> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .sender
            .send(Message::Send {
                request,
                recipients,
                responder: tx,
            })
            .await;
        rx.await.unwrap_or_default()
    }

    async fn cancel(&mut self, commitment: R::Commitment) {
        let _ = self.sender.send(Message::Cancel { commitment }).await;
    }
}
