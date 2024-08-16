use crate::{actors::Messenger, crypto::PublicKey};
use bytes::Bytes;
use governor::Quota;
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Tuple representing a message received from a given public key.
///
/// This message is guranteed to adhere to the configuration of the channel and
/// will already be decrypted and authenticated.
pub type Message = (PublicKey, Bytes);
/// Channel to asynchronously receive messages from a channel.
pub type Receiver = mpsc::Receiver<Message>;

/// Sender is the mechanism used to send arbitrary bytes to
/// a set of recipients over a pre-defined channel.
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
    /// # Parameters
    ///
    /// * `recipients` - If `Some`, the set of recipients to send the message to. If `None`,
    ///   all connected peers that we are tracking across registered peer sets (that have
    ///   yet to be pruned).
    /// * `message` - The message to send.
    /// * `priority` - Whether the message should be sent with priority (across
    ///   all channels).
    pub async fn send(&self, recipients: Option<Vec<PublicKey>>, message: Bytes, priority: bool) {
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
