use crate::Originator;
use commonware_codec::Codec;
use commonware_cryptography::{Committable, Digestible};
use commonware_p2p::{Recipients, Sender};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// Messages that can be sent to a [Mailbox].
pub enum Message<S: Sender, R: Committable + Digestible + Codec> {
    Send {
        request: R,
        recipients: Recipients<S::PublicKey>,
        responder: oneshot::Sender<Result<Vec<S::PublicKey>, S::Error>>,
    },
    Cancel {
        commitment: R::Commitment,
    },
}

/// A mailbox that can be used to send and receive [Message]s.
#[derive(Clone)]
pub struct Mailbox<S: Sender, R: Committable + Digestible + Codec> {
    sender: mpsc::Sender<Message<S, R>>,
}

impl<S: Sender, R: Committable + Digestible + Codec> Mailbox<S, R> {
    /// Creates a new [Mailbox] with the given [mpsc::Sender].
    pub fn new(sender: mpsc::Sender<Message<S, R>>) -> Self {
        Self { sender }
    }
}

impl<S: Sender, R: Committable + Digestible + Codec> Originator for Mailbox<S, R> {
    type Sender = S;
    type Request = R;

    async fn send(
        &mut self,
        recipients: Recipients<S::PublicKey>,
        request: R,
    ) -> Result<Vec<S::PublicKey>, S::Error> {
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

    async fn cancel(&mut self, commitment: R::Commitment) {
        let _ = self.sender.send(Message::Cancel { commitment }).await;
    }
}
