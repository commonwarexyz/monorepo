use super::{actors::Messenger, Error};
use crate::{authenticated::Padding, Channel, Message, Recipients};
use bytes::Bytes;
use commonware_utils::Array;
use futures::{channel::mpsc, StreamExt};
use governor::Quota;
use std::collections::BTreeMap;
use zstd::bulk::{compress, decompress};

/// Configuration for a channel.
#[derive(Clone, Debug)]
pub struct Config {
    /// The unique identifier of the channel.
    pub channel: Channel,

    /// Maximum size of a message that can be sent over the channel.
    pub max_size: usize,

    /// Compression level to use when sending messages.
    ///
    /// If `None`, compression is disabled.
    pub compression: Option<i32>,

    /// The padding strategy to use for messages sent over the channel.
    pub padding: Padding,
}

/// Sender is the mechanism used to send arbitrary bytes to
/// a set of recipients over a pre-defined channel.
#[derive(Clone, Debug)]
pub struct Sender<P: Array> {
    config: Config,
    messenger: Messenger<P>,
}

impl<P: Array> Sender<P> {
    pub(super) fn new(config: Config, messenger: Messenger<P>) -> Self {
        Self { config, messenger }
    }
}

impl<P: Array> crate::Sender for Sender<P> {
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
    /// If the message can be compressed (if enabled) and the message is `< max_size`, The set of recipients
    /// that the message was sent to. Note, a successful send does not mean that the recipient will
    /// receive the message (connection may no longer be active and we may not know that yet).
    async fn send(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
        mut message: Bytes,
        priority: bool,
    ) -> Result<Vec<Self::PublicKey>, Error> {
        // If compression is enabled, compress the message before sending.
        if let Some(level) = self.config.compression {
            let compressed = compress(&message, level).map_err(|_| Error::CompressionFailed)?;
            message = compressed.into();
        }

        // Pad the message
        message = self.config.padding.pad(message)?;

        // Ensure message isn't too large
        let message_len = message.len();
        if message_len > self.config.max_size {
            return Err(Error::MessageTooLarge(message_len));
        }

        // Wait for messenger to let us know who we sent to
        Ok(self
            .messenger
            .content(recipients, self.config.channel, message, priority)
            .await)
    }
}

/// Channel to asynchronously receive messages from a channel.
#[derive(Debug)]
pub struct Receiver<P: Array> {
    config: Config,
    receiver: mpsc::Receiver<Message<P>>,
}

impl<P: Array> Receiver<P> {
    pub(super) fn new(config: Config, receiver: mpsc::Receiver<Message<P>>) -> Self {
        Self { config, receiver }
    }
}

impl<P: Array> crate::Receiver for Receiver<P> {
    type Error = Error;
    type PublicKey = P;

    /// Receives a message from the channel.
    ///
    /// This method will block until a message is received or the underlying
    /// network shuts down.
    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Error> {
        let (sender, mut message) = self.receiver.next().await.ok_or(Error::NetworkClosed)?;

        // Unpad the message
        message = self.config.padding.unpad(message)?;

        // If compression is enabled, decompress the message before returning.
        if self.config.compression.is_some() {
            let buf = decompress(&message, self.config.max_size)
                .map_err(|_| Error::DecompressionFailed)?;
            message = buf.into();
        }

        // We don't check that the message is too large here because we already enforce
        // that on the network layer.
        Ok((sender, message))
    }
}

#[derive(Clone)]
pub struct Channels<P: Array> {
    messenger: Messenger<P>,
    max_size: usize,
    receivers: BTreeMap<Channel, (Quota, mpsc::Sender<Message<P>>)>,
}

impl<P: Array> Channels<P> {
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
        compression: Option<i32>,
        padding: Padding,
    ) -> (Sender<P>, Receiver<P>) {
        let (sender, receiver) = mpsc::channel(backlog);
        if self.receivers.insert(channel, (rate, sender)).is_some() {
            panic!("duplicate channel registration: {}", channel);
        }
        let config = Config {
            channel,
            max_size: self.max_size,
            compression,
            padding,
        };
        (
            Sender::new(config.clone(), self.messenger.clone()),
            Receiver::new(config, receiver),
        )
    }

    pub fn collect(self) -> BTreeMap<u32, (Quota, mpsc::Sender<Message<P>>)> {
        self.receivers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression() {
        let message = b"hello world";
        let compressed = compress(message, 3).unwrap();
        let buf = decompress(&compressed, message.len()).unwrap();
        assert_eq!(message, buf.as_slice());
    }
}
