use super::Error;
use crate::{authenticated::lookup::actors::router, Channel, Message, Recipients};
use bytes::Bytes;
use commonware_codec::Codec;
use commonware_cryptography::PublicKey;
use futures::{channel::mpsc, StreamExt};
use governor::Quota;
use std::collections::BTreeMap;

/// Sender is the mechanism used to send codec messages to
/// a set of recipients over a pre-defined channel.
#[derive(Clone, Debug)]
pub struct Sender<P: PublicKey, V: Codec + Send + 'static> {
    channel: Channel,
    max_size: usize,
    messenger: router::Messenger<P>,
    _phantom_v: std::marker::PhantomData<V>,
}

impl<P: PublicKey, V: Codec + Send + 'static> Sender<P, V> {
    pub(super) fn new(channel: Channel, max_size: usize, messenger: router::Messenger<P>) -> Self {
        Self {
            channel,
            max_size,
            messenger,
            _phantom_v: std::marker::PhantomData,
        }
    }
}

impl<P: PublicKey, V: Codec + Send + Clone + std::fmt::Debug + 'static> crate::Sender<V>
    for Sender<P, V>
{
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
        message: V,
        priority: bool,
    ) -> Result<Vec<Self::PublicKey>, Error> {
        // Encode the message
        let encoded = message.encode();
        let message_bytes = Bytes::from(encoded);

        // Ensure message isn't too large
        let message_len = message_bytes.len();
        if message_len > self.max_size {
            return Err(Error::MessageTooLarge(message_len));
        }

        // Wait for messenger to let us know who we sent to
        Ok(self
            .messenger
            .content(recipients, self.channel, message_bytes, priority)
            .await)
    }
}

/// Channel to asynchronously receive messages from a channel.
#[derive(Debug)]
pub struct Receiver<P: PublicKey, V: Codec + Send + 'static> {
    config: V::Cfg,
    receiver: mpsc::Receiver<Message<P>>,
}

impl<P: PublicKey, V: Codec + Send + 'static> Receiver<P, V> {
    pub(super) fn new(config: V::Cfg, receiver: mpsc::Receiver<Message<P>>) -> Self {
        Self { config, receiver }
    }
}

impl<P: PublicKey, V: Codec + Send + Clone + std::fmt::Debug + 'static> crate::Receiver<V>
    for Receiver<P, V>
{
    type Error = Error;
    type PublicKey = P;

    /// Receives a message from the channel.
    ///
    /// This method will block until a message is received or the underlying
    /// network shuts down.
    async fn recv(&mut self) -> Result<crate::WrappedMessage<Self::PublicKey, V>, Error> {
        let (sender, message_bytes) = self.receiver.next().await.ok_or(Error::NetworkClosed)?;

        // Decode the message
        let decoded = match V::decode_cfg(message_bytes.as_ref(), &self.config) {
            Ok(decoded) => Ok(decoded),
            Err(e) => Err(e),
        };

        Ok((sender, decoded))
    }
}

#[derive(Clone)]
pub struct Channels<P: PublicKey> {
    messenger: router::Messenger<P>,
    max_size: usize,
    receivers: BTreeMap<Channel, (Quota, mpsc::Sender<Message<P>>)>,
}

impl<P: PublicKey> Channels<P> {
    pub fn new(messenger: router::Messenger<P>, max_size: usize) -> Self {
        Self {
            messenger,
            max_size,
            receivers: BTreeMap::new(),
        }
    }

    pub fn register<V: Codec + Send + 'static>(
        &mut self,
        channel: Channel,
        rate: governor::Quota,
        backlog: usize,
        config: V::Cfg,
    ) -> (Sender<P, V>, Receiver<P, V>) {
        let (sender, receiver) = mpsc::channel(backlog);
        if self.receivers.insert(channel, (rate, sender)).is_some() {
            panic!("duplicate channel registration: {channel}");
        }
        (
            Sender::new(channel, self.max_size, self.messenger.clone()),
            Receiver::new(config, receiver),
        )
    }

    pub fn collect(self) -> BTreeMap<u64, (Quota, mpsc::Sender<Message<P>>)> {
        self.receivers
    }
}
