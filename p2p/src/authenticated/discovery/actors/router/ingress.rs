use crate::{
    authenticated::{
        data::{Data, EncodedData},
        discovery::{channels::Channels, types},
        relay::Relay,
        Mailbox,
    },
    utils::limited::Connected,
    Channel, Recipients,
};
use commonware_codec::Encode;
use commonware_cryptography::PublicKey;
use commonware_runtime::IoBufMut;
use commonware_utils::{
    channel::{fallible::AsyncFallibleExt, oneshot, ring},
    NZUsize,
};

/// Messages that can be processed by the router.
#[derive(Debug)]
pub enum Message<P: PublicKey> {
    /// Notify the router that a peer is ready to communicate.
    Ready {
        peer: P,
        relay: Relay<EncodedData>,
        channels: oneshot::Sender<Channels<P>>,
    },
    /// Notify the router that a peer is no longer available.
    Release { peer: P },
    /// Send pre-encoded data to one or more recipients.
    Content {
        recipients: Recipients<P>,
        encoded: EncodedData,
        priority: bool,
        success: oneshot::Sender<Vec<P>>,
    },
    /// Get a subscription to peers known by the router.
    SubscribePeers {
        response: oneshot::Sender<ring::Receiver<Vec<P>>>,
    },
}

impl<P: PublicKey> Mailbox<Message<P>> {
    /// Notify the router that a peer is ready to communicate.
    ///
    /// Returns `None` if the router has shut down.
    pub async fn ready(&mut self, peer: P, relay: Relay<EncodedData>) -> Option<Channels<P>> {
        self.0
            .request(|channels| Message::Ready {
                peer,
                relay,
                channels,
            })
            .await
    }

    /// Notify the router that a peer is no longer available.
    ///
    /// This may fail during shutdown if the router has already exited,
    /// which is harmless since the router no longer tracks any peers.
    pub async fn release(&mut self, peer: P) {
        self.0.send_lossy(Message::Release { peer }).await;
    }
}

/// Sends messages containing content to the router to send to peers.
#[derive(Clone, Debug)]
pub struct Messenger<P: PublicKey> {
    sender: Mailbox<Message<P>>,
}

impl<P: PublicKey> Messenger<P> {
    /// Returns a new [Messenger] with the given sender.
    /// (The router has the corresponding receiver.)
    pub const fn new(sender: Mailbox<Message<P>>) -> Self {
        Self { sender }
    }

    /// Sends a message to the given `recipients`.
    ///
    /// Encodes the message once and shares the encoded bytes across all recipients.
    /// Returns an empty list if the router has shut down.
    pub async fn content(
        &mut self,
        recipients: Recipients<P>,
        channel: Channel,
        message: IoBufMut,
        priority: bool,
    ) -> Vec<P> {
        // Build Data and encode Payload::Data once for all recipients
        let data = Data {
            channel,
            message: message.freeze(),
        };
        let payload_bytes = types::Payload::<P>::Data(data).encode();
        let encoded = EncodedData {
            channel,
            payload: payload_bytes.into(),
        };

        self.sender
            .0
            .request_or_default(|success| Message::Content {
                recipients,
                encoded,
                priority,
                success,
            })
            .await
    }
}

impl<P: PublicKey> Connected for Messenger<P> {
    type PublicKey = P;

    async fn subscribe(&mut self) -> ring::Receiver<Vec<Self::PublicKey>> {
        self.sender
            .0
            .request(|response| Message::SubscribePeers { response })
            .await
            .unwrap_or_else(|| {
                let (_, rx) = ring::channel(NZUsize!(1));
                rx
            })
    }
}
