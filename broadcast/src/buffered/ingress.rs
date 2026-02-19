use crate::Broadcaster;
use commonware_codec::Codec;
use commonware_cryptography::{Committable, Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::{fallible::AsyncFallibleExt, mpsc, oneshot};

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

    /// Subscribe to a message by peer (optionally), commitment, and digest (optionally).
    ///
    /// The responder will be sent the first message for an commitment when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    ///
    /// If the engine has shut down, the returned receiver will resolve to `Canceled`.
    pub async fn subscribe(
        &self,
        peer: Option<P>,
        commitment: M::Commitment,
        digest: Option<M::Digest>,
    ) -> oneshot::Receiver<M> {
        let (responder, receiver) = oneshot::channel();
        self.sender
            .send_lossy(Message::Subscribe {
                peer,
                commitment,
                digest,
                responder,
            })
            .await;
        receiver
    }

    /// Subscribe to a message by peer (optionally), commitment, and digest (optionally) with an
    /// externally prepared responder.
    ///
    /// The responder will be sent the first message for an commitment when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    ///
    /// If the engine has shut down, this is a no-op.
    pub async fn subscribe_prepared(
        &self,
        peer: Option<P>,
        commitment: M::Commitment,
        digest: Option<M::Digest>,
        responder: oneshot::Sender<M>,
    ) {
        self.sender
            .send_lossy(Message::Subscribe {
                peer,
                commitment,
                digest,
                responder,
            })
            .await;
    }

    /// Get all messages for an commitment.
    ///
    /// If the engine has shut down, returns an empty vector.
    pub async fn get(
        &self,
        peer: Option<P>,
        commitment: M::Commitment,
        digest: Option<M::Digest>,
    ) -> Vec<M> {
        self.sender
            .request(|responder| Message::Get {
                peer,
                commitment,
                digest,
                responder,
            })
            .await
            .unwrap_or_default()
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
