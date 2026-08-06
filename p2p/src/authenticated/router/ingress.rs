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
use commonware_runtime::{BufferPool, IoBufs};
use commonware_utils::{
    NZUsize,
    channel::{oneshot, ring},
    sync::Mutex,
};
use std::{
    collections::VecDeque,
    fmt,
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

// The router mailbox is created after channel registration determines its capacity.
// Retain subscriptions made before then so binding can forward them.
struct MessengerState<P: PublicKey> {
    mailbox: OnceLock<Mailbox<P>>,
    pending_subscriptions: Mutex<Vec<ring::Sender<Vec<P>>>>,
}

impl<P: PublicKey> MessengerState<P> {
    const fn new() -> Self {
        Self {
            mailbox: OnceLock::new(),
            pending_subscriptions: Mutex::new(Vec::new()),
        }
    }

    fn bind(&self, mailbox: Mailbox<P>) {
        // Publish the mailbox before draining pending subscriptions. Subscribers that observed it
        // unbound recheck while holding the same lock, so they are either queued or send directly.
        assert!(
            self.mailbox.set(mailbox).is_ok(),
            "router messenger already bound"
        );
        let mut pending_subscriptions = self.pending_subscriptions.lock();
        let mailbox = self.mailbox.get().unwrap();
        for sender in pending_subscriptions.drain(..) {
            let _ = mailbox.0.enqueue(Message::SubscribePeers { sender });
        }
    }
}

/// Sends messages containing content to the router to send to peers.
#[derive(Clone)]
pub struct Messenger<P: PublicKey> {
    pool: BufferPool,
    state: Arc<MessengerState<P>>,
}

impl<P: PublicKey> fmt::Debug for Messenger<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Messenger")
            .field("bound", &self.state.mailbox.get().is_some())
            .finish_non_exhaustive()
    }
}

impl<P: PublicKey> Messenger<P> {
    pub(in crate::authenticated) fn unbound(pool: BufferPool) -> Self {
        Self {
            pool,
            state: Arc::new(MessengerState::new()),
        }
    }

    pub(in crate::authenticated) fn bind(&self, mailbox: Mailbox<P>) {
        self.state.bind(mailbox);
    }

    /// Sends a message to the given `recipients`.
    ///
    /// Encodes the message once and shares the encoded bytes across all recipients.
    /// Returns feedback from enqueueing the router message. Before the router is bound, the
    /// submission is accepted and dropped without encoding.
    pub fn content(
        &self,
        recipients: Recipients<P>,
        channel: Channel,
        message: IoBufs,
        priority: bool,
    ) -> Unreliable<Feedback> {
        // Treat sends before the router is bound as sends with no connected peers. Nothing can
        // receive the content, so accept the submission without encoding or enqueueing it.
        let Some(mailbox) = self.state.mailbox.get() else {
            return Unreliable::new(Feedback::Ok);
        };

        // Encode the data frame once for all recipients
        let encoded = EncodedData::new(&self.pool, channel, message);

        mailbox.0.enqueue(Message::Content {
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
        if let Some(mailbox) = self.state.mailbox.get() {
            let _ = mailbox.0.enqueue(Message::SubscribePeers { sender });
            return receiver;
        }

        let mut pending_subscriptions = self.state.pending_subscriptions.lock();
        if let Some(mailbox) = self.state.mailbox.get() {
            drop(pending_subscriptions);
            let _ = mailbox.0.enqueue(Message::SubscribePeers { sender });
        } else {
            pending_subscriptions.push(sender);
        }
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
    fn test_unbound_messenger_accepts_and_drops_content() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let messenger = Messenger::<PublicKey>::unbound(context.network_buffer_pool().clone());
            assert_eq!(
                messenger.content(Recipients::All, 7, IoBuf::from(b"message").into(), false),
                Unreliable::new(Feedback::Ok)
            );

            let (sender, mut receiver) = mailbox::new_unreliable::<Message<PublicKey>>(
                context.child("router_mailbox"),
                NZUsize!(1),
            );
            messenger.bind(Mailbox::new(sender));
            assert!(receiver.try_recv().is_err());
        });
    }

    #[test]
    fn test_unbound_messenger_defers_subscriptions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let messenger = Messenger::<PublicKey>::unbound(context.network_buffer_pool().clone());
            let _subscription = messenger.subscribe();
            let (sender, mut receiver) = mailbox::new_unreliable::<Message<PublicKey>>(
                context.child("router_mailbox"),
                NZUsize!(1),
            );

            messenger.bind(Mailbox::new(sender));

            assert!(matches!(
                receiver.try_recv(),
                Ok(Message::SubscribePeers { .. })
            ));
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
            let messenger = Messenger::unbound(context.network_buffer_pool().clone());
            messenger.bind(Mailbox::new(control_sender));
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
