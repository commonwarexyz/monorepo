use crate::actors::Messenger;
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use governor::Quota;
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot};

/// Tuple representing a message received from a given public key.
///
/// This message is guranteed to adhere to the configuration of the channel and
/// will already be decrypted and authenticated.
pub type Message = (PublicKey, Bytes);
/// Channel to asynchronously receive messages from a channel.
pub type Receiver = mpsc::Receiver<Message>;

/// Sender is the mechanism used to send arbitrary bytes to
/// a set of recipients over a pre-defined channel.
#[derive(Clone)]
pub struct Sender {
    channel: u32,
    messenger: Messenger,
}

impl Sender {
    pub(super) fn new(channel: u32, messenger: Messenger) -> Self {
        Self { channel, messenger }
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
    /// * `recipients` - If `Some`, the set of recipients to send the message to. If `None`,
    ///   all connected peers that we are tracking across registered peer sets (that have
    ///   yet to be pruned).
    /// * `message` - The message to send.
    /// * `priority` - Whether the message should be sent with priority (across
    ///   all channels).
    ///
    /// # Returns
    ///
    /// The set of recipients that the message was sent to. Note, a successful send does not
    /// mean that the recipient will receive the message (connection may no longer be active and
    /// we may not know that yet).
    pub async fn send(
        &self,
        recipients: Option<Vec<PublicKey>>,
        message: Bytes,
        priority: bool,
    ) -> Vec<PublicKey> {
        self.messenger
            .content(recipients, self.channel, message, priority)
            .await;
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
    ) -> (Sender, Receiver) {
        let (sender, receiver) = mpsc::channel(backlog);
        if self
            .receivers
            .insert(channel, (rate, max_size, sender))
            .is_some()
        {
            panic!("duplicate channel registration: {}", channel);
        }
        (Sender::new(channel, self.messenger.clone()), receiver)
    }

    pub fn collect(self) -> HashMap<u32, (Quota, usize, mpsc::Sender<Message>)> {
        self.receivers
    }
}
