use crate::{
    Channel, Recipients,
    authenticated::{channels::Channels, data::EncodedData, relay::Relay},
    utils::limited::Connected,
};
use commonware_actor::{
    Feedback, Unreliable,
    mailbox::{self, UnreliablePolicy},
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{BufferPool, IoBufs, Metrics};
use commonware_utils::{
    NZUsize,
    channel::{oneshot, ring},
    sync::Mutex,
};
use std::{
    collections::VecDeque,
    fmt,
    num::NonZeroUsize,
    sync::{Arc, OnceLock},
};

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

impl<P: PublicKey> UnreliablePolicy for Message<P> {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) -> bool {
        match message {
            Self::Content { .. } => false,
            message => {
                overflow.push_back(message);
                true
            }
        }
    }
}

/// Mailbox for the router actor.
pub struct Mailbox<P: PublicKey>(mailbox::UnreliableSender<Message<P>>);

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
    pub const fn new(sender: mailbox::UnreliableSender<Message<P>>) -> Self {
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
        match self.0.enqueue(Message::Release { peer }) {
            Unreliable::Outcome(feedback) => feedback,
            Unreliable::Rejected => unreachable!("router release cannot be rejected"),
        }
    }
}

/// Keeps the pre-start mailbox open until the network starts or is dropped.
pub(in crate::authenticated) struct Staging<P: PublicKey>(mailbox::UnreliableReceiver<Message<P>>);

/// Sends messages containing content to the router to send to peers.
struct MessengerState<P: PublicKey> {
    mailbox: OnceLock<Mailbox<P>>,
    staging: Mutex<Option<Mailbox<P>>>,
}

impl<P: PublicKey> MessengerState<P> {
    fn bound(mailbox: Mailbox<P>) -> Self {
        Self {
            mailbox: OnceLock::from(mailbox),
            staging: Mutex::new(None),
        }
    }

    const fn unbound(staging: Mailbox<P>) -> Self {
        Self {
            mailbox: OnceLock::new(),
            staging: Mutex::new(Some(staging)),
        }
    }

    fn enqueue(&self, message: Message<P>) -> Unreliable<Feedback> {
        if let Some(mailbox) = self.mailbox.get() {
            return mailbox.0.enqueue(message);
        }

        let staging = self.staging.lock();
        if let Some(mailbox) = self.mailbox.get() {
            return mailbox.0.enqueue(message);
        }
        staging
            .as_ref()
            .expect("unbound router messenger missing staging mailbox")
            .0
            .enqueue(message)
    }

    fn grow_staging(&self, mailbox: Mailbox<P>, staging: &mut Staging<P>, replacement: Staging<P>) {
        // The staging lock excludes every producer, so an empty receive means all previously
        // accepted messages have been transferred before the replacement becomes visible.
        let mut staging_slot = self.staging.lock();
        assert!(
            self.mailbox.get().is_none(),
            "router messenger already bound"
        );
        assert!(
            staging_slot.is_some(),
            "unbound router messenger missing staging mailbox"
        );
        while let Ok(message) = staging.0.try_recv() {
            assert!(
                mailbox.0.enqueue(message).accepted(),
                "staged router message must be accepted by larger mailbox"
            );
        }
        *staging = replacement;
        *staging_slot = Some(mailbox);
    }

    fn bind(&self, mailbox: Mailbox<P>, mut staging: Staging<P>) {
        // Publish the final mailbox only after draining staging while holding the lock. A
        // concurrent sender therefore either enters staging first or waits and enters the final
        // mailbox after every staged message.
        let mut staging_slot = self.staging.lock();
        assert!(
            self.mailbox.get().is_none(),
            "router messenger already bound"
        );
        let _staging_sender = staging_slot
            .take()
            .expect("unbound router messenger missing staging mailbox");
        while let Ok(message) = staging.0.try_recv() {
            assert!(
                mailbox.0.enqueue(message).accepted(),
                "staged router message must be accepted by final mailbox"
            );
        }
        assert!(
            self.mailbox.set(mailbox).is_ok(),
            "router messenger already bound"
        );
        drop(staging_slot);
    }
}

#[derive(Clone)]
pub struct Messenger<P: PublicKey> {
    pool: BufferPool,
    state: Arc<MessengerState<P>>,
}

impl<P: PublicKey> fmt::Debug for Messenger<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Messenger")
            .field("bound", &self.state.mailbox.get().is_some())
            .finish()
    }
}

impl<P: PublicKey> Messenger<P> {
    /// Returns a new [Messenger] with the given sender.
    /// (The router has the corresponding receiver.)
    pub fn new(pool: BufferPool, sender: Mailbox<P>) -> Self {
        Self {
            pool,
            state: Arc::new(MessengerState::bound(sender)),
        }
    }

    pub(in crate::authenticated) fn unbound<M: Metrics>(
        pool: BufferPool,
        metrics: M,
        capacity: NonZeroUsize,
    ) -> (Self, Staging<P>) {
        let (sender, receiver) = mailbox::new_unreliable(metrics.child("mailbox"), capacity);
        (
            Self {
                pool,
                state: Arc::new(MessengerState::unbound(Mailbox::new(sender))),
            },
            Staging(receiver),
        )
    }

    pub(in crate::authenticated) fn bind(&self, mailbox: Mailbox<P>, staging: Staging<P>) {
        self.state.bind(mailbox, staging);
    }

    pub(in crate::authenticated) fn grow_staging<M: Metrics>(
        &self,
        staging: &mut Staging<P>,
        metrics: M,
        capacity: NonZeroUsize,
    ) {
        let (sender, receiver) = mailbox::new_unreliable(metrics.child("mailbox"), capacity);
        self.state
            .grow_staging(Mailbox::new(sender), staging, Staging(receiver));
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
    ) -> Unreliable<Feedback> {
        // Encode the data frame once for all recipients
        let encoded = EncodedData::new(&self.pool, channel, message);

        self.state.enqueue(Message::Content {
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
        let _ = self.state.enqueue(Message::SubscribePeers { sender });
        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{
        BufferPooler as _, IoBuf, Runner as _, Supervisor as _, deterministic,
    };

    #[test]
    fn test_unbound_messenger_closes_when_staging_dropped() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (messenger, staging) = Messenger::<PublicKey>::unbound(
                context.network_buffer_pool().clone(),
                context.child("router_staging"),
                NZUsize!(1),
            );
            drop(staging);

            assert_eq!(
                messenger.content(Recipients::All, 7, IoBuf::from(b"message").into(), false),
                Unreliable::new(Feedback::Closed)
            );
        });
    }

    #[test]
    fn test_unbound_messenger_buffers_content() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (messenger, mut staging) = Messenger::<PublicKey>::unbound(
                context.network_buffer_pool().clone(),
                context.child("router_staging"),
                NZUsize!(1),
            );
            let peer = PrivateKey::from_seed(1).public_key();

            assert_eq!(format!("{messenger:?}"), "Messenger { bound: false }");
            assert_eq!(
                messenger.content(
                    Recipients::One(peer.clone()),
                    7,
                    IoBuf::from(b"message").into(),
                    false
                ),
                Unreliable::new(Feedback::Ok)
            );
            assert_eq!(
                messenger.content(
                    Recipients::One(peer.clone()),
                    7,
                    IoBuf::from(b"overflow").into(),
                    false
                ),
                Unreliable::Rejected
            );
            messenger.grow_staging(&mut staging, context.child("router_staging"), NZUsize!(2));
            assert_eq!(
                messenger.content(
                    Recipients::One(peer.clone()),
                    8,
                    IoBuf::from(b"after growth").into(),
                    true
                ),
                Unreliable::new(Feedback::Ok)
            );
            let _subscription = messenger.subscribe();
            let (sender, mut receiver) = mailbox::new_unreliable::<Message<PublicKey>>(
                context.child("router_mailbox"),
                NZUsize!(2),
            );
            messenger.bind(Mailbox::new(sender), staging);
            assert_eq!(format!("{messenger:?}"), "Messenger { bound: true }");

            match receiver.try_recv().unwrap() {
                Message::Content {
                    recipients: Recipients::One(recipient),
                    encoded,
                    priority,
                } => {
                    assert_eq!(recipient, peer);
                    assert_eq!(encoded.channel, 7);
                    assert!(!priority);
                }
                _ => panic!("expected content"),
            }
            match receiver.try_recv().unwrap() {
                Message::Content {
                    recipients: Recipients::One(recipient),
                    encoded,
                    priority,
                } => {
                    assert_eq!(recipient, peer);
                    assert_eq!(encoded.channel, 8);
                    assert!(priority);
                }
                _ => panic!("expected content"),
            }
            match receiver.try_recv().unwrap() {
                Message::SubscribePeers { .. } => {}
                _ => panic!("expected peer subscription"),
            }
            assert!(receiver.try_recv().is_err());
        });
    }

    #[test]
    fn test_overflow_rejects_content_but_retains_control() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (control_sender, mut receiver) = mailbox::new_unreliable::<Message<PublicKey>>(
                context.child("control_mailbox"),
                NZUsize!(1),
            );
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
                Unreliable::new(Feedback::Ok)
            );
            assert_eq!(
                messenger.content(Recipients::One(peer), 7, IoBuf::from(b"two").into(), false),
                Unreliable::Rejected
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
