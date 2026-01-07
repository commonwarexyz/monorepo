use crate::Broadcaster;
use commonware_codec::Codec;
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channels::fallible::AsyncFallibleExt;
use commonware_utils::Subscribable;
use futures::channel::{mpsc, oneshot};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// Message types that can be sent to the `Mailbox`
pub enum Message<P: PublicKey, M: Committable + Digestible> {
    /// Broadcast a [crate::Broadcaster::Message] to the network.
    ///
    /// The responder will be sent a list of peers that received the message.
    Broadcast {
        recipients: Recipients<P>,
        message: M,
        responder: oneshot::Sender<Vec<P>>,
    },

    /// Subscribe to receive a message by digest.
    ///
    /// The responder will be sent the first message for an commitment when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    Subscribe {
        peer: Option<P>,
        commitment: M::Commitment,
        digest: Option<M::Digest>,
        responder: oneshot::Sender<M>,
    },

    /// Get all messages for an commitment.
    Get {
        peer: Option<P>,
        commitment: M::Commitment,
        digest: Option<M::Digest>,
        responder: oneshot::Sender<Vec<M>>,
    },
}

/// Ingress mailbox for [super::Engine].
#[derive(Clone)]
pub struct Mailbox<P: PublicKey, M: Committable + Digestible + Codec> {
    sender: mpsc::Sender<Message<P, M>>,
}

impl<P: PublicKey, M: Committable + Digestible + Codec> Mailbox<P, M> {
    pub(super) const fn new(sender: mpsc::Sender<Message<P, M>>) -> Self {
        Self { sender }
    }
}

impl<P: PublicKey, M: Committable + Digestible + Codec> Broadcaster for Mailbox<P, M> {
    type Recipients = Recipients<P>;
    type Message = M;
    type Response = Vec<P>;

    /// Broadcast a message to recipients.
    ///
    /// If the engine has shut down, the returned receiver will resolve to `Canceled`.
    async fn broadcast(
        &mut self,
        recipients: Self::Recipients,
        message: Self::Message,
    ) -> oneshot::Receiver<Self::Response> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send_lossy(Message::Broadcast {
                recipients,
                message,
                responder: sender,
            })
            .await;
        receiver
    }
}

impl<P: PublicKey, M: Committable + Digestible + Codec> Subscribable for Mailbox<P, M> {
    type Key = M::Commitment;
    type Value = M;

    async fn get(&mut self, key: M::Commitment) -> Option<M> {
        let (responder, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get {
                peer: None,
                commitment: key,
                digest: None,
                responder,
            })
            .await
            .expect("mailbox closed");
        receiver.await.expect("mailbox closed").into_iter().next()
    }

    async fn subscribe(&mut self, key: M::Commitment) -> oneshot::Receiver<M> {
        let (responder, receiver) = oneshot::channel();
        self.sender
            .send(Message::Subscribe {
                peer: None,
                commitment: key,
                digest: None,
                responder,
            })
            .await
            .expect("mailbox closed");
        receiver
    }
}
