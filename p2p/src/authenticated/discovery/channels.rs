use super::{actors::Messenger, Error};
use crate::{Channel, Message, Recipients};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use futures::{channel::mpsc, StreamExt};
use governor::Quota;
use std::collections::BTreeMap;

/// Sender is the mechanism used to send arbitrary bytes to
/// a set of recipients over a pre-defined channel.
#[derive(Clone, Debug)]
pub struct Sender<P: PublicKey> {
    channel: Channel,
    max_size: usize,
    messenger: Messenger<P>,
}

impl<P: PublicKey> Sender<P> {
    pub(super) fn new(channel: Channel, max_size: usize, messenger: Messenger<P>) -> Self {
        Self {
            channel,
            max_size,
            messenger,
        }
    }
}

impl<P: PublicKey> crate::Sender for Sender<P> {
    type Error = Error;
    type PublicKey = P;

    /// Sends a message to a set of recipients.
    ///
    /// # Offline Recipients
    ///
    /// If a recipient is offline at the time a message is sent, the message will be dropped.
    /// It is up to the application to handle retries (if necessary).
    ///
    /// # Parameters
    ///
    /// * `recipients` - The set of recipients to send the message to.
    /// * `message` - The message to send.
    /// * `priority` - Whether the message should be sent with priority (across
    ///   all channels).
    ///
    /// # Returns
    ///
    /// A vector of recipients that the message was sent to, or an error if the message is too large.
    ///
    /// Note: a successful send does not guarantee that the recipient will receive the message.
    async fn send(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        message: Bytes,
        priority: bool,
    ) -> Result<Vec<Self::PublicKey>, Error> {
        // Ensure message isn't too large
        let message_len = message.len();
        if message_len > self.max_size {
            return Err(Error::MessageTooLarge(message_len));
        }

        // Wait for messenger to let us know who we sent to
        Ok(self
            .messenger
            .content(recipients, self.channel, message, priority)
            .await)
    }
}

/// Channel to asynchronously receive messages from a channel.
#[derive(Debug)]
pub struct Receiver<P: PublicKey> {
    receiver: mpsc::Receiver<Message<P>>,
}

impl<P: PublicKey> Receiver<P> {
    pub(super) fn new(receiver: mpsc::Receiver<Message<P>>) -> Self {
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
        let (sender, message) = self.receiver.next().await.ok_or(Error::NetworkClosed)?;

        // We don't check that the message is too large here because we already enforce
        // that on the network layer.
        Ok((sender, message))
    }
}

#[derive(Clone)]
pub struct Channels<P: PublicKey> {
    messenger: Messenger<P>,
    max_size: usize,
    receivers: BTreeMap<Channel, (Quota, mpsc::Sender<Message<P>>)>,
}

impl<P: PublicKey> Channels<P> {
    pub fn new(messenger: Messenger<P>, max_size: usize) -> Self {
        Self {
            messenger,
            max_size,
            receivers: BTreeMap::new(),
        }
    }

    pub fn register(
        &mut self,
        channel: Channel,
        rate: governor::Quota,
        backlog: usize,
    ) -> (Sender<P>, Receiver<P>) {
        let (sender, receiver) = mpsc::channel(backlog);
        if self.receivers.insert(channel, (rate, sender)).is_some() {
            panic!("duplicate channel registration: {channel}");
        }
        (
            Sender::new(channel, self.max_size, self.messenger.clone()),
            Receiver::new(receiver),
        )
    }

    pub fn collect(self) -> BTreeMap<u64, (Quota, mpsc::Sender<Message<P>>)> {
        self.receivers
    }
}
