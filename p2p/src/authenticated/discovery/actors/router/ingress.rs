use crate::{
    authenticated::{
        data::EncodedData,
        discovery::types,
        relay::Relay,
        Mailbox,
    },
    utils::limited::Connected,
    Channel, Recipients,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{BufferPool, IoBufs};
use commonware_utils::{
    channel::{
        actor::{self, Enqueue, FullPolicy, MessagePolicy},
        oneshot, ring,
    },
    NZUsize,
};
use std::collections::VecDeque;

/// Messages that can be processed by the router.
#[derive(Debug)]
pub enum Message<P: PublicKey> {
    /// Notify the router that a peer is ready to communicate.
    Ready {
        peer: P,
        relay: Relay<EncodedData>,
    },
    /// Notify the router that a peer is no longer available.
    Release { peer: P },
    /// Send pre-encoded data to one or more recipients.
    Content {
        recipients: Recipients<P>,
        encoded: EncodedData,
        priority: bool,
        success: Option<oneshot::Sender<Vec<P>>>,
    },
    /// Get a subscription to peers known by the router.
    SubscribePeers {
        response: oneshot::Sender<ring::Receiver<Vec<P>>>,
    },
}

impl<P: PublicKey> MessagePolicy for Message<P> {
    fn kind(&self) -> &'static str {
        match self {
            Self::Ready { .. } => "ready",
            Self::Release { .. } => "release",
            Self::Content { .. } => "content",
            Self::SubscribePeers { .. } => "subscribe_peers",
        }
    }

    fn full_policy(&self) -> FullPolicy {
        match self {
            Self::Ready { .. } | Self::Release { .. } => FullPolicy::Replace,
            Self::Content { .. } => FullPolicy::Retain,
            Self::SubscribePeers { .. } => FullPolicy::Reject,
        }
    }

    fn replace(queue: &mut VecDeque<Self>, protected: usize, message: Self) -> Result<(), Self> {
        match message {
            Self::Ready { peer, relay } => {
                let key = peer.clone();
                actor::replace_last(queue, protected, Self::Ready { peer, relay }, |pending| {
                    matches!(
                        pending,
                        Self::Ready { peer, .. } | Self::Release { peer } if peer == &key
                    )
                })
            }
            Self::Release { peer } => {
                let key = peer.clone();
                actor::replace_last(queue, protected, Self::Release { peer }, |pending| {
                    matches!(
                        pending,
                        Self::Ready { peer, .. } | Self::Release { peer } if peer == &key
                    )
                })
            }
            message => Err(message),
        }
    }
}

impl<P: PublicKey> Mailbox<Message<P>> {
    /// Notify the router that a peer is ready to communicate.
    ///
    /// Returns `None` if the router has shut down.
    pub fn ready(&mut self, peer: P, relay: Relay<EncodedData>) -> Enqueue<Message<P>> {
        self.enqueue(Message::Ready { peer, relay })
    }

    /// Notify the router that a peer is no longer available.
    ///
    /// This may fail during shutdown if the router has already exited,
    /// which is harmless since the router no longer tracks any peers.
    pub fn release(&mut self, peer: P) -> Enqueue<Message<P>> {
        self.enqueue(Message::Release { peer })
    }
}

/// Sends messages containing content to the router to send to peers.
#[derive(Clone, Debug)]
pub struct Messenger<P: PublicKey> {
    pool: BufferPool,
    sender: Mailbox<Message<P>>,
}

impl<P: PublicKey> Messenger<P> {
    /// Returns a new [Messenger] with the given sender.
    /// (The router has the corresponding receiver.)
    pub const fn new(pool: BufferPool, sender: Mailbox<Message<P>>) -> Self {
        Self { pool, sender }
    }

    /// Sends a message to the given `recipients`.
    ///
    /// Encodes the message once and shares the encoded bytes across all recipients.
    /// Returns an empty list if the router has shut down.
    pub async fn content(
        &mut self,
        recipients: Recipients<P>,
        channel: Channel,
        message: IoBufs,
        priority: bool,
    ) -> Vec<P> {
        // Build Data and encode Payload::Data once for all recipients
        let encoded = types::Payload::<P>::encode_data(&self.pool, channel, message);

        let (success, receiver) = oneshot::channel();
        match self.sender.enqueue(Message::Content {
                recipients,
                encoded,
                priority,
                success: Some(success),
            }) {
            Enqueue::Queued | Enqueue::Replaced => receiver.await.unwrap_or_default(),
            Enqueue::Rejected(_) | Enqueue::Closed(_) => Vec::new(),
        }
    }

    /// Enqueue a message to the router without waiting for delivery feedback.
    pub fn enqueue_content(
        &self,
        recipients: Recipients<P>,
        channel: Channel,
        message: IoBufs,
        priority: bool,
    ) -> Enqueue<Message<P>> {
        let encoded = types::Payload::<P>::encode_data(&self.pool, channel, message);
        self.sender.enqueue(Message::Content {
            recipients,
            encoded,
            priority,
            success: None,
        })
    }
}

impl<P: PublicKey> Connected for Messenger<P> {
    type PublicKey = P;

    async fn subscribe(&mut self) -> ring::Receiver<Vec<Self::PublicKey>> {
        let (response, receiver) = oneshot::channel();
        match self.sender.enqueue(Message::SubscribePeers { response }) {
            Enqueue::Queued | Enqueue::Replaced => receiver.await.unwrap_or_else(|_| {
                let (_, rx) = ring::channel(NZUsize!(1));
                rx
            }),
            Enqueue::Rejected(_) | Enqueue::Closed(_) => {
                let (_, rx) = ring::channel(NZUsize!(1));
                rx
            }
        }
    }
}
