use super::router::Messenger;
use crate::{
    Channel, Message as NetworkMessage, Recipients,
    utils::limited::{CheckedSender, LimitedSender},
};
use commonware_actor::{
    Feedback, Unreliable,
    mailbox::{self, UnreliablePolicy},
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, IoBufs, Metrics, Quota};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Debug,
    num::NonZeroUsize,
    time::SystemTime,
};
use thiserror::Error;

/// Returns the backlog required to hold one quota burst from every peer.
///
/// This covers a synchronized burst, including from honest peers, but does not account for
/// receiver stalls or sustained ingress above the receiver's drain rate.
///
/// # Panics
///
/// Panics if the aggregate burst does not fit in a `usize`.
pub const fn backlog(peers: usize, rate: Quota) -> usize {
    peers
        .checked_mul(rate.burst_size().get() as usize)
        .expect("message backlog overflow")
}

/// Errors that can occur when interacting with the network.
#[derive(Error, Debug)]
pub enum Error {
    #[error("network closed")]
    NetworkClosed,
}

pub(crate) struct Inbound<P: PublicKey>(pub(crate) NetworkMessage<P>);

impl<P: PublicKey> UnreliablePolicy for Inbound<P> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        false
    }
}

/// An interior sender that enforces message size limits and
/// supports sending arbitrary bytes to a set of recipients over
/// a pre-defined [`Channel`].
#[derive(Debug, Clone)]
pub struct UnlimitedSender<P: PublicKey> {
    channel: Channel,
    max_size: u32,
    messenger: Messenger<P>,
}

impl<P: PublicKey> crate::UnlimitedSender for UnlimitedSender<P> {
    type PublicKey = P;

    fn send(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> Unreliable<Feedback> {
        let message = message.into();
        assert!(
            message.len() <= self.max_size as usize,
            "message too large: {} > {}",
            message.len(),
            self.max_size
        );

        self.messenger
            .content(recipients, self.channel, message, priority)
    }
}

/// Sends arbitrary bytes over one registered channel.
///
/// The channel's quota is shared across clones and enforced independently for each recipient.
/// All registered channels share one outbound router mailbox. A channel's configured backlog adds
/// to that mailbox's capacity but does not reserve capacity exclusively for the channel.
pub struct Sender<P: PublicKey, C: Clock> {
    limited_sender: LimitedSender<C, UnlimitedSender<P>, Messenger<P>>,
}

impl<P: PublicKey, C: Clock> Clone for Sender<P, C> {
    fn clone(&self) -> Self {
        Self {
            limited_sender: self.limited_sender.clone(),
        }
    }
}

impl<P: PublicKey, C: Clock> Sender<P, C> {
    pub(super) fn new(
        channel: Channel,
        max_size: u32,
        messenger: Messenger<P>,
        clock: C,
        quota: Quota,
    ) -> Self {
        let master_sender = UnlimitedSender {
            channel,
            max_size,
            messenger: messenger.clone(),
        };
        let limited_sender = LimitedSender::new(master_sender, quota, clock, messenger);
        Self { limited_sender }
    }
}

impl<P, C> crate::LimitedSender for Sender<P, C>
where
    P: PublicKey,
    C: Clock + Send + 'static,
{
    type PublicKey = P;
    type Checked<'a>
        = CheckedSender<'a, UnlimitedSender<P>>
    where
        Self: 'a;

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        self.limited_sender.check(recipients)
    }
}

/// Lossy receiver for one registered channel.
///
/// Every peer connection feeds the same bounded inbound mailbox after independent per-peer rate
/// limiting. If the mailbox is full, the arriving message is dropped and queued messages remain.
/// Configure its capacity through `Network::register` using the aggregate peer burst, expected
/// receiver stalls, and memory budget.
pub struct Receiver<P: PublicKey> {
    receiver: mailbox::UnreliableReceiver<Inbound<P>>,
}

impl<P: PublicKey> Debug for Receiver<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver").finish_non_exhaustive()
    }
}

impl<P: PublicKey> Receiver<P> {
    pub(super) const fn new(receiver: mailbox::UnreliableReceiver<Inbound<P>>) -> Self {
        Self { receiver }
    }
}

impl<P: PublicKey> crate::Receiver for Receiver<P> {
    type Error = Error;
    type PublicKey = P;

    /// Receives a message from the channel.
    ///
    /// This method will block until a message is received or the underlying
    /// network shuts down.
    async fn recv(&mut self) -> Result<NetworkMessage<Self::PublicKey>, Error> {
        let Inbound((sender, message)) = self.receiver.recv().await.ok_or(Error::NetworkClosed)?;

        // We don't check that the message is too large here because we already enforce
        // that on the network layer.
        Ok((sender, message))
    }
}

#[derive(Clone, Debug)]
pub struct Channels<P: PublicKey> {
    messenger: Messenger<P>,
    max_size: u32,
    outbound_backlog: usize,
    receivers: BTreeMap<Channel, (Quota, mailbox::UnreliableSender<Inbound<P>>)>,
}

impl<P: PublicKey> Channels<P> {
    pub const fn new(messenger: Messenger<P>, max_size: u32) -> Self {
        Self {
            messenger,
            max_size,
            outbound_backlog: 0,
            receivers: BTreeMap::new(),
        }
    }

    pub(super) fn outbound_mailbox_size(&self, base: NonZeroUsize) -> NonZeroUsize {
        base.checked_add(self.outbound_backlog)
            .expect("router mailbox capacity overflow")
    }

    pub(super) fn bind(&self, mailbox: super::router::Mailbox<P>) {
        self.messenger.bind(mailbox);
    }

    pub fn register<C: Clock + Metrics>(
        &mut self,
        channel: Channel,
        rate: Quota,
        backlog: usize,
        context: C,
    ) -> (Sender<P, C>, Receiver<P>) {
        let backlog = NonZeroUsize::new(backlog).expect("message backlog must be non-zero");
        if self.receivers.contains_key(&channel) {
            panic!("duplicate channel registration: {channel}");
        }
        self.outbound_backlog = self
            .outbound_backlog
            .checked_add(backlog.get())
            .expect("router mailbox capacity overflow");
        let (sender, receiver) = mailbox::new_unreliable(context.child("mailbox"), backlog);
        let previous = self.receivers.insert(channel, (rate, sender));
        assert!(previous.is_none());
        (
            Sender::new(
                channel,
                self.max_size,
                self.messenger.clone(),
                context,
                rate,
            ),
            Receiver::new(receiver),
        )
    }

    pub fn collect(self) -> BTreeMap<u64, (Quota, mailbox::UnreliableSender<Inbound<P>>)> {
        self.receivers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CheckedSender as _, LimitedSender as _,
        authenticated::router::{self, Actor},
    };
    use commonware_cryptography::{
        Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{
        BufferPooler as _, IoBuf, Runner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{NZU32, NZUsize};

    #[test]
    fn backlog_aggregates_peers() {
        let rate = Quota::per_second(NZU32!(128));

        assert_eq!(backlog(7, rate), 896);
    }

    #[test]
    fn registered_backlogs_size_shared_outbound_mailbox() {
        deterministic::Runner::default().start(|context| async move {
            let messenger = Messenger::unbound(context.network_buffer_pool().clone());
            let mut channels = Channels::new(messenger, 1024);
            let quota = Quota::per_second(NZU32!(100));
            let (mut first, _) = channels.register(1, quota, 2, context.child("first"));
            let (mut second, _) = channels.register(2, quota, 2, context.child("second"));
            let capacity = channels.outbound_mailbox_size(NZUsize!(2));
            let (_router, mailbox, _) = Actor::<_, PublicKey>::new(
                context.child("router"),
                router::Config {
                    mailbox_size: capacity,
                },
            );
            channels.bind(mailbox);
            let peer = PrivateKey::from_seed(1).public_key();

            for sender in [&mut first, &mut second] {
                for _ in 0..2 {
                    let feedback = sender
                        .check(Recipients::One(peer.clone()))
                        .unwrap()
                        .send(IoBuf::from(b"message"), false);
                    assert!(feedback.accepted());
                }
            }

            let feedback = first
                .check(Recipients::One(peer))
                .unwrap()
                .send(IoBuf::from(b"overflow"), false);
            assert_eq!(feedback, Unreliable::Rejected);
        });
    }

    #[test]
    #[should_panic(expected = "router mailbox capacity overflow")]
    fn outbound_mailbox_size_panics_on_overflow() {
        deterministic::Runner::default().start(|context| async move {
            let messenger = Messenger::unbound(context.network_buffer_pool().clone());
            let mut channels = Channels::<PublicKey>::new(messenger, 1024);
            channels.outbound_backlog = 1;

            channels.outbound_mailbox_size(NonZeroUsize::new(usize::MAX).unwrap());
        });
    }

    #[test]
    #[should_panic(expected = "message backlog overflow")]
    fn backlog_panics_on_overflow() {
        let rate = Quota::per_second(NZU32!(2));

        backlog(usize::MAX, rate);
    }
}
