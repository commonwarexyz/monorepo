use crate::Broadcaster;
use commonware_codec::Codec;
use commonware_cryptography::{Committable, Digest, Digestible};
use commonware_p2p::Recipients;
use commonware_utils::Array;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

/// Message types that can be sent to the `Mailbox`
pub enum Message<P: Array, Dc: Digest, Dd: Digest, M: Committable<Dc> + Digestible<Dd>> {
    /// Broadcast a [`Message`](crate::Broadcaster::Message) to the network.
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
        commitment: Dc,
        digest: Option<Dd>,
        responder: oneshot::Sender<M>,
    },

    /// Get all messages for an commitment.
    Get {
        peer: Option<P>,
        commitment: Dc,
        digest: Option<Dd>,
        responder: oneshot::Sender<Vec<M>>,
    },
}

/// Ingress mailbox for [`Engine`](super::Engine).
#[derive(Clone)]
pub struct Mailbox<P: Array, Dc: Digest, Dd: Digest, M: Committable<Dc> + Digestible<Dd> + Codec> {
    sender: mpsc::Sender<Message<P, Dc, Dd, M>>,
}

impl<P: Array, Dc: Digest, Dd: Digest, M: Committable<Dc> + Digestible<Dd> + Codec>
    Mailbox<P, Dc, Dd, M>
{
    pub(super) fn new(sender: mpsc::Sender<Message<P, Dc, Dd, M>>) -> Self {
        Self { sender }
    }
}

impl<P: Array, Dc: Digest, Dd: Digest, M: Committable<Dc> + Digestible<Dd> + Codec>
    Mailbox<P, Dc, Dd, M>
{
    /// Subscribe to a message by peer (optionally), commitment, and digest (optionally).
    ///
    /// The responder will be sent the first message for an commitment when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    pub async fn subscribe(
        &mut self,
        peer: Option<P>,
        commitment: Dc,
        digest: Option<Dd>,
    ) -> oneshot::Receiver<M> {
        let (responder, receiver) = oneshot::channel();
        self.sender
            .send(Message::Subscribe {
                peer,
                commitment,
                digest,
                responder,
            })
            .await
            .expect("mailbox closed");
        receiver
    }

    /// Subscribe to a message by peer (optionally), commitment, and digest (optionally) with an
    /// externally prepared responder.
    ///
    /// The responder will be sent the first message for an commitment when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    pub async fn subscribe_prepared(
        &mut self,
        peer: Option<P>,
        commitment: Dc,
        digest: Option<Dd>,
        responder: oneshot::Sender<M>,
    ) {
        self.sender
            .send(Message::Subscribe {
                peer,
                commitment,
                digest,
                responder,
            })
            .await
            .expect("mailbox closed");
    }

    /// Get all messages for an commitment.
    pub async fn get(&mut self, peer: Option<P>, commitment: Dc, digest: Option<Dd>) -> Vec<M> {
        let (responder, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get {
                peer,
                commitment,
                digest,
                responder,
            })
            .await
            .expect("mailbox closed");
        receiver.await.expect("mailbox closed")
    }
}

impl<P: Array, Dc: Digest, Dd: Digest, M: Committable<Dc> + Digestible<Dd> + Codec> Broadcaster
    for Mailbox<P, Dc, Dd, M>
{
    type Recipients = Recipients<P>;
    type Message = M;
    type Response = Vec<P>;

    async fn broadcast(
        &mut self,
        recipients: Self::Recipients,
        message: Self::Message,
    ) -> oneshot::Receiver<Self::Response> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Broadcast {
                recipients,
                message,
                responder: sender,
            })
            .await
            .expect("mailbox closed");
        receiver
    }
}
