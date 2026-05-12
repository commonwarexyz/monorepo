use super::Error;
use crate::{
    authenticated::lookup::actors::router::{self, Messenger},
    utils::limited::{CheckedSender, LimitedSender},
    Channel, Message, Recipients,
};
use commonware_actor::Feedback;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, IoBufs, Quota};
use commonware_utils::channel::mpsc;
use std::{collections::BTreeMap, fmt::Debug, time::SystemTime};

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
    type Error = Error;
    type PublicKey = P;

    async fn send(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> Result<Vec<Self::PublicKey>, Self::Error> {
        let message = message.into();
        if message.len() > self.max_size as usize {
            return Err(Error::MessageTooLarge(message.len()));
        }

        Ok(self
            .messenger
            .content(recipients, self.channel, message, priority)
            .await)
    }
}

impl<P: PublicKey> UnlimitedSender<P> {
    fn send_lossy(
        &self,
        recipients: Recipients<P>,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> Feedback {
        let message = message.into();
        if message.len() > self.max_size as usize {
            return Feedback::Dropped;
        }

        self.messenger
            .enqueue_content(recipients, self.channel, message, priority)
    }
}

/// Sender is the mechanism used to send arbitrary bytes to a set of recipients over a pre-defined channel.
pub struct Sender<P: PublicKey, C: Clock> {
    limited_sender: LimitedSender<C, UnlimitedSender<P>, Messenger<P>>,
    mailbox_sender: UnlimitedSender<P>,
}

impl<P: PublicKey, C: Clock> Clone for Sender<P, C> {
    fn clone(&self) -> Self {
        Self {
            limited_sender: self.limited_sender.clone(),
            mailbox_sender: self.mailbox_sender.clone(),
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
        let limited_sender = LimitedSender::new(master_sender.clone(), quota, clock, messenger);
        Self {
            limited_sender,
            mailbox_sender: master_sender,
        }
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

    async fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        self.limited_sender.check(recipients).await
    }
}

impl<P, C> crate::Sender for Sender<P, C>
where
    P: PublicKey,
    C: Clock + Send + 'static,
{
    fn send_lossy(
        &self,
        recipients: Recipients<Self::PublicKey>,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> (Feedback, Vec<Self::PublicKey>) {
        let message = message.into();
        if message.len() > self.mailbox_sender.max_size as usize {
            return (Feedback::Dropped, Vec::new());
        }
        let Ok(recipients) = self.limited_sender.check_lossy(recipients) else {
            return (Feedback::Dropped, Vec::new());
        };
        let accepted = accepted_recipients(&recipients);
        let feedback = self.mailbox_sender.send_lossy(recipients, message, priority);
        if matches!(feedback, commonware_actor::Feedback::Ok | commonware_actor::Feedback::Backoff) {
            (feedback, accepted)
        } else {
            (feedback, Vec::new())
        }
    }
}

fn accepted_recipients<P: PublicKey>(recipients: &Recipients<P>) -> Vec<P> {
    match recipients {
        Recipients::One(peer) => vec![peer.clone()],
        Recipients::Some(peers) => peers.clone(),
        Recipients::All => Vec::new(),
    }
}

/// Channel to asynchronously receive messages from a channel.
#[derive(Debug)]
pub struct Receiver<P: PublicKey> {
    receiver: mpsc::Receiver<Message<P>>,
}

impl<P: PublicKey> Receiver<P> {
    pub(super) const fn new(receiver: mpsc::Receiver<Message<P>>) -> Self {
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
    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Error> {
        let (sender, message) = self.receiver.recv().await.ok_or(Error::NetworkClosed)?;

        // We don't check that the message is too large here because we already enforce
        // that on the network layer.
        Ok((sender, message))
    }
}

#[derive(Clone, Debug)]
pub struct Channels<P: PublicKey> {
    messenger: router::Messenger<P>,
    max_size: u32,
    receivers: BTreeMap<Channel, (Quota, mpsc::Sender<Message<P>>)>,
}

impl<P: PublicKey> Channels<P> {
    pub const fn new(messenger: router::Messenger<P>, max_size: u32) -> Self {
        Self {
            messenger,
            max_size,
            receivers: BTreeMap::new(),
        }
    }

    pub fn register<C: Clock>(
        &mut self,
        channel: Channel,
        rate: Quota,
        backlog: usize,
        clock: C,
    ) -> (Sender<P, C>, Receiver<P>) {
        let (sender, receiver) = mpsc::channel(backlog);
        if self.receivers.insert(channel, (rate, sender)).is_some() {
            panic!("duplicate channel registration: {channel}");
        }
        (
            Sender::new(channel, self.max_size, self.messenger.clone(), clock, rate),
            Receiver::new(receiver),
        )
    }

    pub fn collect(self) -> BTreeMap<u64, (Quota, mpsc::Sender<Message<P>>)> {
        self.receivers
    }
}
