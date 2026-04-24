use crate::Broadcaster;
use commonware_codec::Codec;
use commonware_cryptography::{Digestible, PublicKey};
use commonware_p2p::Recipients;
use commonware_utils::channel::{fallible::AsyncFallibleExt, mpsc, oneshot};

/// Message types that can be sent to the `Mailbox`
pub enum Message<P: PublicKey, M: Digestible> {
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
    /// The responder will be sent the message when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    Subscribe {
        digest: M::Digest,
        responder: oneshot::Sender<M>,
    },

    /// Get a message by digest.
    Get {
        digest: M::Digest,
        responder: oneshot::Sender<Option<M>>,
    },
}

/// Ingress mailbox for [super::Engine].
#[derive(Clone)]
pub struct Mailbox<P: PublicKey, M: Digestible + Codec> {
    sender: mpsc::Sender<Message<P, M>>,
}

impl<P: PublicKey, M: Digestible + Codec> Mailbox<P, M> {
    pub(super) const fn new(sender: mpsc::Sender<Message<P, M>>) -> Self {
        Self { sender }
    }

    /// Subscribe to a message by digest.
    ///
    /// The responder will be sent the message when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    ///
    /// If the engine has shut down, the returned receiver will resolve to `Canceled`.
    pub async fn subscribe(&self, digest: M::Digest) -> oneshot::Receiver<M> {
        let (responder, receiver) = oneshot::channel();
        self.sender
            .send_lossy(Message::Subscribe { digest, responder })
            .await;
        receiver
    }

    /// Subscribe to a message by digest with an externally prepared responder.
    ///
    /// The responder will be sent the message when it is available; either
    /// instantly (if cached) or when it is received from the network. The request can be canceled
    /// by dropping the responder.
    ///
    /// If the engine has shut down, this is a no-op.
    pub async fn subscribe_prepared(&self, digest: M::Digest, responder: oneshot::Sender<M>) {
        self.sender
            .send_lossy(Message::Subscribe { digest, responder })
            .await;
    }

    /// Get a message by digest.
    ///
    /// If the engine has shut down, returns `None`.
    pub async fn get(&self, digest: M::Digest) -> Option<M> {
        self.sender
            .request(|responder| Message::Get { digest, responder })
            .await
            .unwrap_or_default()
    }
}

impl<P: PublicKey, M: Digestible + Codec> Broadcaster for Mailbox<P, M> {
    type Recipients = Recipients<P>;
    type Message = M;
    type Response = Vec<P>;

    /// Broadcast a message to recipients.
    ///
    /// If the engine has shut down, the returned receiver will resolve to `Canceled`.
    async fn broadcast(
        &self,
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
