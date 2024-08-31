use crate::{actors::Messenger, Error};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use governor::Quota;
use std::collections::HashMap;
use tokio::sync::mpsc;
use zstd::bulk::{compress, decompress_to_buffer};

/// Tuple representing a message received from a given public key.
///
/// This message is guranteed to adhere to the configuration of the channel and
/// will already be decrypted and authenticated.
pub type Message = (PublicKey, Bytes);

/// Enum indicating the set of recipients to send a message to.
#[derive(Clone)]
pub enum Recipients {
    All,
    Some(Vec<PublicKey>),
    One(PublicKey),
}

/// Sender is the mechanism used to send arbitrary bytes to
/// a set of recipients over a pre-defined channel.
#[derive(Clone)]
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
    pub async fn send(
        &self,
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

    /// Receives a message from the channel.
    ///
    /// This method will block until a message is received.
    pub async fn recv(&mut self) -> Result<Message, Error> {
        let (sender, mut message) = self.receiver.recv().await.ok_or(Error::NetworkClosed)?;

        // If compression is enabled, decompress the message before returning.
        if self.compression {
            let mut buf = Vec::with_capacity(self.max_size);
            decompress_to_buffer(&message, &mut buf).map_err(|_| Error::DecompressionFailed)?;
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
    receivers: HashMap<u32, (Quota, usize, mpsc::Sender<Message>)>,
}

impl Channels {
    pub fn new(messenger: Messenger) -> Self {
        Self {
            messenger,
            receivers: HashMap::new(),
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

    pub fn collect(self) -> HashMap<u32, (Quota, usize, mpsc::Sender<Message>)> {
        self.receivers
    }
}
