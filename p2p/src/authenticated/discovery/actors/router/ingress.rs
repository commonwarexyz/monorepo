use crate::{
    authenticated::{
        data::EncodedData,
        discovery::{channels::Channels, types},
        relay::Relay,
    },
    utils::limited::Connected,
    Channel, Recipients,
};
use commonware_actor::{
    mailbox::{self, Policy},
    Feedback,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{BufferPool, IoBufs};
use commonware_utils::{
    channel::{oneshot, ring},
    NZUsize,
};
use std::{collections::VecDeque, fmt};

/// Messages that can be processed by the router.
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
    },
    /// Register a subscription to peers known by the router.
    SubscribePeers { sender: ring::Sender<Vec<P>> },
}

impl<P: PublicKey> Policy for Message<P> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        match message {
            Self::Content { .. } => {}
            message => overflow.push_back(message),
        }
    }
}

/// Mailbox for the router actor.
pub struct Mailbox<P: PublicKey>(mailbox::Sender<Message<P>>);

impl<P: PublicKey> Clone for Mailbox<P> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P: PublicKey> fmt::Debug for Mailbox<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Mailbox").field(&self.0).finish()
    }
}

impl<P: PublicKey> Mailbox<P> {
    /// Returns a router mailbox around the provided sender.
    pub const fn new(sender: mailbox::Sender<Message<P>>) -> Self {
        Self(sender)
    }

    /// Notify the router that a peer is ready to communicate.
    ///
    /// Returns `None` if the router has shut down.
    pub async fn ready(&self, peer: P, relay: Relay<EncodedData>) -> Option<Channels<P>> {
        let (channels, receiver) = oneshot::channel();
        let _ = self.0.enqueue(Message::Ready {
            peer,
            relay,
            channels,
        });
        receiver.await.ok()
    }

    /// Notify the router that a peer is no longer available.
    ///
    /// This may fail during shutdown if the router has already exited,
    /// which is harmless since the router no longer tracks any peers.
    pub fn release(&self, peer: P) -> Feedback {
        self.0.enqueue(Message::Release { peer })
    }
}

/// Sends messages containing content to the router to send to peers.
#[derive(Clone, Debug)]
pub struct Messenger<P: PublicKey> {
    pool: BufferPool,
    sender: Mailbox<P>,
}

impl<P: PublicKey> Messenger<P> {
    /// Returns a new [Messenger] with the given sender.
    /// (The router has the corresponding receiver.)
    pub const fn new(pool: BufferPool, sender: Mailbox<P>) -> Self {
        Self { pool, sender }
    }

    /// Sends a message to the given `recipients`.
    ///
    /// Encodes the message once and shares the encoded bytes across all recipients.
    /// Returns feedback from enqueueing the router message.
    pub fn content(
        &self,
        recipients: Recipients<P>,
        channel: Channel,
        message: IoBufs,
        priority: bool,
    ) -> Feedback {
        // Build Data and encode Payload::Data once for all recipients
        let encoded = types::Payload::<P>::encode_data(&self.pool, channel, message);

        self.sender.0.enqueue(Message::Content {
            recipients,
            encoded,
            priority,
        })
    }
}

impl<P: PublicKey> Connected for Messenger<P> {
    type PublicKey = P;

    fn subscribe(&self) -> ring::Receiver<Vec<Self::PublicKey>> {
        let (sender, receiver) = ring::channel(NZUsize!(1));
        let _ = self.sender.0.enqueue(Message::SubscribePeers { sender });
        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer as _,
    };
    use commonware_runtime::{
        deterministic, BufferPooler as _, IoBuf, Runner as _, Supervisor as _,
    };

    #[test]
    fn test_overflow_drops_content_but_retains_control() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (control_sender, mut receiver) =
                mailbox::new::<Message<PublicKey>>(context.child("control_mailbox"), NZUsize!(1));
            let mailbox = Mailbox::new(control_sender.clone());
            let messenger = Messenger::new(
                context.network_buffer_pool().clone(),
                Mailbox::new(control_sender),
            );
            let peer = PrivateKey::from_seed(1).public_key();

            assert_eq!(
                messenger.content(
                    Recipients::One(peer.clone()),
                    7,
                    IoBuf::from(b"one").into(),
                    false
                ),
                Feedback::Ok
            );
            assert_eq!(
                messenger.content(Recipients::One(peer), 7, IoBuf::from(b"two").into(), false),
                Feedback::Backoff
            );
            assert_eq!(
                mailbox.release(PrivateKey::from_seed(2).public_key()),
                Feedback::Backoff
            );

            match receiver.try_recv().unwrap() {
                Message::Content { encoded, .. } => assert_eq!(encoded.channel, 7),
                _ => panic!("expected content"),
            }
            match receiver.try_recv().unwrap() {
                Message::Release { .. } => {}
                _ => panic!("expected release"),
            }
            assert!(receiver.try_recv().is_err());
        });
    }
}
