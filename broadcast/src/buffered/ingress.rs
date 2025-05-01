use crate::Broadcaster;
use commonware_codec::{Codec, Config as CodecConfig};
use commonware_cryptography::{Digest, Digestible, Identifiable};
use commonware_p2p::Recipients;
use commonware_utils::Array;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::marker::PhantomData;

/// Message types that can be sent to the `Mailbox`
pub enum Message<P: Array, Di: Digest, Dd: Digest, M: Identifiable<Di> + Digestible<Dd>> {
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
    /// The responder will be sent the first message for an identity when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    Subscribe {
        sender: Option<P>,
        identity: Di,
        digest: Option<Dd>,
        responder: oneshot::Sender<M>,
    },

    /// Get all messages for an identity.
    Get {
        sender: Option<P>,
        identity: Di,
        digest: Option<Dd>,
        responder: oneshot::Sender<Vec<M>>,
    },
}

/// Ingress mailbox for [`Engine`](super::Engine).
#[derive(Clone)]
pub struct Mailbox<
    P: Array,
    Di: Digest,
    Dd: Digest,
    MCfg: CodecConfig,
    M: Identifiable<Di> + Digestible<Dd> + Codec<MCfg>,
> {
    sender: mpsc::Sender<Message<P, Di, Dd, M>>,
    _phantom: PhantomData<MCfg>,
}

impl<
        P: Array,
        Di: Digest,
        Dd: Digest,
        MCfg: CodecConfig,
        M: Identifiable<Di> + Digestible<Dd> + Codec<MCfg>,
    > Mailbox<P, Di, Dd, MCfg, M>
{
    pub(super) fn new(sender: mpsc::Sender<Message<P, Di, Dd, M>>) -> Self {
        Self {
            sender,
            _phantom: PhantomData,
        }
    }
}

impl<
        P: Array,
        Di: Digest,
        Dd: Digest,
        MCfg: CodecConfig,
        M: Identifiable<Di> + Digestible<Dd> + Codec<MCfg>,
    > Mailbox<P, Di, Dd, MCfg, M>
{
    /// Subscribe to a message by sender (optionally), identity, and digest (optionally).
    ///
    /// The responder will be sent the first message for an identity when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    pub async fn subscribe(
        &mut self,
        sender: Option<P>,
        identity: Di,
        digest: Option<Dd>,
    ) -> oneshot::Receiver<M> {
        let (responder, receiver) = oneshot::channel();
        self.sender
            .send(Message::Subscribe {
                sender,
                identity,
                digest,
                responder,
            })
            .await
            .expect("mailbox closed");
        receiver
    }

    /// Subscribe to a message by sender (optionally), identity, and digest (optionally) with an
    /// externally prepared responder.
    ///
    /// The responder will be sent the first message for an identity when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    pub async fn subscribe_prepared(
        &mut self,
        sender: Option<P>,
        identity: Di,
        digest: Option<Dd>,
        responder: oneshot::Sender<M>,
    ) {
        self.sender
            .send(Message::Subscribe {
                sender,
                identity,
                digest,
                responder,
            })
            .await
            .expect("mailbox closed");
    }

    /// Get all messages for an identity.
    pub async fn get(&mut self, sender: Option<P>, identity: Di, digest: Option<Dd>) -> Vec<M> {
        let (responder, receiver) = oneshot::channel();
        self.sender
            .send(Message::Get {
                sender,
                identity,
                digest,
                responder,
            })
            .await
            .expect("mailbox closed");
        receiver.await.expect("mailbox closed")
    }
}

impl<
        P: Array,
        Di: Digest,
        Dd: Digest,
        MCfg: CodecConfig,
        M: Identifiable<Di> + Digestible<Dd> + Codec<MCfg>,
    > Broadcaster for Mailbox<P, Di, Dd, MCfg, M>
{
    type PublicKey = P;
    type MessageDecoder = MCfg;
    type Message = M;
    type Response = Vec<P>;

    async fn broadcast(
        &mut self,
        recipients: Recipients<P>,
        message: Self::Message,
    ) -> oneshot::Receiver<Vec<P>> {
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
