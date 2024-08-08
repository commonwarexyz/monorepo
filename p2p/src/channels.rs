use crate::{actors::Messenger, crypto::PublicKey};
use bytes::Bytes;
use governor::Quota;
use std::collections::HashMap;
use tokio::sync::mpsc;

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
    /// * `recipients` - The set of recipients to send the message to.
    /// * `message` - The message to send.
    /// * `priority` - Whether the message should be sent with priority (across
    /// all channels).
    pub async fn send(&self, recipients: Vec<PublicKey>, message: Bytes, priority: bool) {
        self.messenger
            .content(recipients, self.channel, message, priority)
            .await;
    }
}

pub type Message = (PublicKey, Bytes);
pub type Receiver = mpsc::Receiver<Message>;

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
