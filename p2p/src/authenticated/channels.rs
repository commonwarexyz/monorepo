use super::{actors::Messenger, Error};
use crate::{Message, Recipients};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use futures::{channel::mpsc, StreamExt};
use governor::Quota;
use std::collections::BTreeMap;
use zstd::bulk::{compress, decompress};

/// Sender is the mechanism used to send arbitrary bytes to
/// a set of recipients over a pre-defined channel.
#[derive(Clone, Debug)]
pub struct Sender {
    channel: u32,
    max_size: usize,
    compression: Option<u8>,
    messenger: Messenger,
}

impl Sender {
    pub(super) fn new(
        channel: u32,
        max_size: usize,
        compression: Option<u8>,
        messenger: Messenger,
    ) -> Self {
        Self {
            channel,
            max_size,
            compression,
            messenger,
        }
    }
}

impl crate::Sender for Sender {
    type Error = Error;

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
        recipients: Recipients,
        mut message: Bytes,
        priority: bool,
    ) -> Result<Vec<PublicKey>, Error> {
        // If compression is enabled, compress the message before sending.
        if let Some(level) = self.compression {
            let compressed =
                compress(&message, level as i32).map_err(|_| Error::CompressionFailed)?;
            message = compressed.into();
        }

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
pub struct Receiver {
    max_size: usize,
    compression: bool,
    receiver: mpsc::Receiver<Message>,
}

impl Receiver {
    pub(super) fn new(
        max_size: usize,
        compression: bool,
        receiver: mpsc::Receiver<Message>,
    ) -> Self {
        Self {
            max_size,
            compression,
            receiver,
        }
    }
}

impl crate::Receiver for Receiver {
    type Error = Error;

    /// Receives a message from the channel.
    ///
    /// This method will block until a message is received or the underlying
    /// network shuts down.
    async fn recv(&mut self) -> Result<Message, Error> {
        let (sender, mut message) = self.receiver.next().await.ok_or(Error::NetworkClosed)?;

        // If compression is enabled, decompress the message before returning.
        if self.compression {
            let buf =
                decompress(&message, self.max_size).map_err(|_| Error::DecompressionFailed)?;
            message = buf.into();
        }

        // We don't check that the message is too large here because we already enforce
        // that on the network layer.
        Ok((sender, message))
    }
}

#[derive(Clone)]
pub struct Channels {
    messenger: Messenger,
    receivers: BTreeMap<u32, (Quota, usize, mpsc::Sender<Message>)>,
}

impl Channels {
    pub fn new(messenger: Messenger) -> Self {
        Self {
            messenger,
            receivers: BTreeMap::new(),
        }
    }

    pub fn register(
        &mut self,
        channel: u32,
        rate: governor::Quota,
        max_size: usize,
        backlog: usize,
        compression: Option<u8>,
    ) -> (Sender, Receiver) {
        let (sender, receiver) = mpsc::channel(backlog);
        if self
            .receivers
            .insert(channel, (rate, max_size, sender))
            .is_some()
        {
            panic!("duplicate channel registration: {}", channel);
        }
        (
            Sender::new(channel, max_size, compression, self.messenger.clone()),
            Receiver::new(max_size, compression.is_some(), receiver),
        )
    }

    pub fn collect(self) -> BTreeMap<u32, (Quota, usize, mpsc::Sender<Message>)> {
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
