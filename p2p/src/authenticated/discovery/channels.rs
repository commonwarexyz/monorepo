use super::{actors::Messenger, Error};
use crate::{Channel, Message, Recipients};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::RateLimiter;
use futures::{channel::mpsc, lock::Mutex, StreamExt};
use governor::{clock::Clock as GClock, Quota};
use std::{collections::BTreeMap, fmt::Debug, sync::Arc};

/// Sender is the mechanism used to send arbitrary bytes to
/// a set of recipients over a pre-defined channel.
#[derive(Clone)]
pub struct Sender<P: PublicKey, C: GClock> {
    channel: Channel,
    max_size: usize,
    messenger: Messenger<P>,
    rate_limiter: Option<Arc<Mutex<RateLimiter<P, C>>>>,
}

impl<P: PublicKey, C: GClock> Sender<P, C> {
    pub(super) fn new(
        channel: Channel,
        max_size: usize,
        messenger: Messenger<P>,
        per_peer_quota: Option<(C, Quota)>,
    ) -> Self {
        let rate_limiter = per_peer_quota.map(|(clock, quota)| {
            let inner = RateLimiter::hashmap_with_clock(quota, clock);
            Arc::new(Mutex::new(inner))
        });
        Self {
            channel,
            max_size,
            messenger,
            rate_limiter,
        }
    }
}

impl<P, C> crate::Sender for Sender<P, C>
where
    P: PublicKey,
    C: GClock + Clone + Send + 'static,
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
    /// # Rate Limiting
    ///
    /// If outbound rate limiting is enabled, recipients that exceed their rate limit
    /// will be skipped. The message is still sent to non-limited recipients. Check the
    /// returned vector to see which peers were sent the message.
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
    /// A vector of recipients that the message was sent to, or an error if the
    /// message is too large.
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

        // Get the concrete list of peers to send to
        let peers: Vec<Self::PublicKey> = match recipients {
            Recipients::One(peer) => vec![peer],
            Recipients::Some(peers) => peers,
            Recipients::All => self.messenger.connected().await,
        };

        // Filter peers by rate limit, consuming rate tokens only for allowed peers
        let allowed_peers = if let Some(ref rate_limiter) = self.rate_limiter {
            let rate_limiter = rate_limiter.lock().await;
            let filtered = peers
                .into_iter()
                .filter(|peer| rate_limiter.check_key(peer).is_ok())
                .collect::<Vec<_>>();

            // Clean up limiter state
            rate_limiter.shrink_to_fit();

            filtered
        } else {
            peers
        };

        // If no recipients are allowed, short-circuit and signal that no peers could
        // be sent the message.
        if allowed_peers.is_empty() {
            return Ok(Vec::new());
        }

        // Send and return who we sent to
        Ok(self
            .messenger
            .content(
                Recipients::Some(allowed_peers),
                self.channel,
                message,
                priority,
            )
            .await)
    }
}

impl<P: PublicKey, C: GClock> Debug for Sender<P, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sender")
            .field("channel", &self.channel)
            .field("max_size", &self.max_size)
            .finish()
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
    pub const fn new(messenger: Messenger<P>, max_size: usize) -> Self {
        Self {
            messenger,
            max_size,
            receivers: BTreeMap::new(),
        }
    }

    pub fn register<C: GClock>(
        &mut self,
        channel: Channel,
        rate: governor::Quota,
        backlog: usize,
        outbound_rate_limit_clock: Option<C>,
    ) -> (Sender<P, C>, Receiver<P>) {
        let (sender, receiver) = mpsc::channel(backlog);
        if self.receivers.insert(channel, (rate, sender)).is_some() {
            panic!("duplicate channel registration: {channel}");
        }
        (
            Sender::new(
                channel,
                self.max_size,
                self.messenger.clone(),
                outbound_rate_limit_clock.map(|clock| (clock, rate)),
            ),
            Receiver::new(receiver),
        )
    }

    pub fn collect(self) -> BTreeMap<u64, (Quota, mpsc::Sender<Message<P>>)> {
        self.receivers
    }
}
