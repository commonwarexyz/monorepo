use super::router::{Messenger, OwnedMessenger};
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
    sync::Arc,
    time::SystemTime,
};
use thiserror::Error;

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
/// All registered channels share one outbound router mailbox. Each channel contributes one quota
/// burst for every configured peer, but does not reserve that capacity exclusively.
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
/// Its capacity holds one quota burst from every peer allowed by the network configuration.
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
    messenger: Arc<OwnedMessenger<P>>,
    max_size: u32,
    max_peers: NonZeroUsize,
    outbound_capacity: usize,
    receivers: BTreeMap<Channel, (Quota, mailbox::UnreliableSender<Inbound<P>>)>,
}

impl<P: PublicKey> Channels<P> {
    pub const fn new(
        messenger: Arc<OwnedMessenger<P>>,
        max_size: u32,
        max_peers: NonZeroUsize,
    ) -> Self {
        Self {
            messenger,
            max_size,
            max_peers,
            outbound_capacity: 0,
            receivers: BTreeMap::new(),
        }
    }

    /// Adds internal-message headroom to the capacity derived from registered channel quotas.
    ///
    /// Internal and application messages share the entire router mailbox.
    pub(super) const fn outbound_mailbox_size(&self, base: NonZeroUsize) -> NonZeroUsize {
        base.checked_add(self.outbound_capacity)
            .expect("router mailbox capacity overflow")
    }

    /// Connects every registered channel sender to the router mailbox.
    pub(super) fn bind(&self, mailbox: super::router::Mailbox<P>) {
        self.messenger.bind(mailbox);
    }

    pub fn register<C: Clock + Metrics>(
        &mut self,
        channel: Channel,
        rate: Quota,
        context: C,
    ) -> (Sender<P, C>, Receiver<P>) {
        if self.receivers.contains_key(&channel) {
            panic!("duplicate channel registration: {channel}");
        }
        let capacity = self
            .max_peers
            .get()
            .checked_mul(rate.burst_size().get() as usize)
            .and_then(NonZeroUsize::new)
            .expect("channel mailbox capacity overflow");
        self.outbound_capacity = self
            .outbound_capacity
            .checked_add(capacity.get())
            .expect("router mailbox capacity overflow");
        let (sender, receiver) = mailbox::new_unreliable(context.child("mailbox"), capacity);
        assert!(self.receivers.insert(channel, (rate, sender)).is_none());
        (
            Sender::new(
                channel,
                self.max_size,
                self.messenger.handle(),
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
    use commonware_cryptography::{
        Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{
        BufferPooler as _, IoBuf, Runner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{NZU32, NZUsize};

    #[test]
    fn registered_rate_sizes_inbound_mailbox_for_every_peer() {
        deterministic::Runner::default().start(|context| async move {
            let messenger = Messenger::unbound(context.network_buffer_pool().clone());
            let mut channels = Channels::new(messenger, 1024, NZUsize!(2));
            let quota = Quota::per_second(NZU32!(2));
            let (_, mut receiver) = channels.register(1, quota, context.child("channel"));
            let inbound = channels.receivers.get(&1).unwrap().1.clone();
            let peer = PrivateKey::from_seed(1).public_key();

            // Two peers can each contribute a two-message quota burst. Overflow leaves the four
            // accepted messages queued.
            for _ in 0..4 {
                assert!(
                    inbound
                        .enqueue(Inbound((peer.clone(), IoBuf::from(b"message"))))
                        .accepted()
                );
            }
            assert_eq!(
                inbound.enqueue(Inbound((peer, IoBuf::from(b"overflow")))),
                Unreliable::Rejected
            );

            for _ in 0..4 {
                assert!(receiver.receiver.try_recv().is_ok());
            }
        });
    }

    #[test]
    fn registered_rates_size_shared_outbound_mailbox() {
        deterministic::Runner::default().start(|context| async move {
            let messenger = Messenger::<PublicKey>::unbound(context.network_buffer_pool().clone());
            let mut channels = Channels::new(messenger, 1024, NZUsize!(2));
            let quota = Quota::per_second(NZU32!(2));
            let _ = channels.register(1, quota, context.child("first"));
            let _ = channels.register(2, quota, context.child("second"));

            // Two units of base headroom plus two channels with four slots each.
            assert_eq!(channels.outbound_mailbox_size(NZUsize!(2)), NZUsize!(10));
        });
    }

    #[test]
    #[should_panic(expected = "router mailbox capacity overflow")]
    fn outbound_mailbox_size_panics_on_overflow() {
        deterministic::Runner::default().start(|context| async move {
            let messenger = Messenger::unbound(context.network_buffer_pool().clone());
            let mut channels = Channels::<PublicKey>::new(messenger, 1024, NZUsize!(1));
            channels.outbound_capacity = 1;

            channels.outbound_mailbox_size(NonZeroUsize::new(usize::MAX).unwrap());
        });
    }

    #[test]
    #[should_panic(expected = "channel mailbox capacity overflow")]
    fn derived_capacity_panics_on_overflow() {
        let rate = Quota::per_second(NZU32!(2));
        deterministic::Runner::default().start(|context| async move {
            let messenger = Messenger::unbound(context.network_buffer_pool().clone());
            let mut channels =
                Channels::<PublicKey>::new(messenger, 1024, NonZeroUsize::new(usize::MAX).unwrap());
            let _ = channels.register(0, rate, context);
        });
    }
}
