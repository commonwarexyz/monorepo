use super::Error;
use crate::{
    authenticated::lookup::actors::router::{self, Messenger},
    utils::limited::{CheckedSender, LimitedSender},
    Channel, Message as NetworkMessage, Recipients,
};
use commonware_actor::{
    mailbox::{self, Policy},
    Feedback,
};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, IoBufs, Metrics, Quota};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Debug,
    num::NonZeroUsize,
    time::SystemTime,
};

pub(crate) struct Inbound<P: PublicKey>(pub(crate) NetworkMessage<P>);

impl<P: PublicKey> Policy for Inbound<P> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) {}
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
    ) -> Feedback {
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

/// Sender is the mechanism used to send arbitrary bytes to a set of recipients over a pre-defined channel.
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

/// Channel to asynchronously receive messages from a channel.
pub struct Receiver<P: PublicKey> {
    receiver: mailbox::Receiver<Inbound<P>>,
}

impl<P: PublicKey> Debug for Receiver<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver").finish_non_exhaustive()
    }
}

impl<P: PublicKey> Receiver<P> {
    pub(super) const fn new(receiver: mailbox::Receiver<Inbound<P>>) -> Self {
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
    messenger: router::Messenger<P>,
    max_size: u32,
    receivers: BTreeMap<Channel, (Quota, mailbox::Sender<Inbound<P>>)>,
}

impl<P: PublicKey> Channels<P> {
    pub const fn new(messenger: router::Messenger<P>, max_size: u32) -> Self {
        Self {
            messenger,
            max_size,
            receivers: BTreeMap::new(),
        }
    }

    pub fn register<C: Clock + Metrics>(
        &mut self,
        channel: Channel,
        rate: Quota,
        backlog: usize,
        context: C,
    ) -> (Sender<P, C>, Receiver<P>) {
        let backlog = NonZeroUsize::new(backlog).expect("message backlog must be non-zero");
        let (sender, receiver) = mailbox::new(context.child("mailbox"), backlog);
        if self.receivers.insert(channel, (rate, sender)).is_some() {
            panic!("duplicate channel registration: {channel}");
        }
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

    pub fn collect(self) -> BTreeMap<u64, (Quota, mailbox::Sender<Inbound<P>>)> {
        self.receivers
    }
}
