use super::Error;
use crate::{authenticated::lookup::actors::router, Channel, Message, Recipients};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::RateLimiter;
use commonware_utils::channels::ring;
use futures::{channel::mpsc, lock::Mutex, FutureExt, StreamExt};
use governor::{clock::Clock as GClock, Quota};
use std::{collections::BTreeMap, fmt::Debug, sync::Arc};

/// Sender is the mechanism used to send arbitrary bytes to
/// a set of recipients over a pre-defined channel.
pub struct Sender<P: PublicKey, C: GClock> {
    channel: Channel,
    max_size: usize,
    messenger: router::Messenger<P>,
    rate_limiter: Arc<Mutex<RateLimiter<P, C>>>,
    peer_subscription: Option<ring::Receiver<Vec<P>>>,
    known_peers: Vec<P>,
}

impl<P: PublicKey, C: GClock> Sender<P, C> {
    pub(super) fn new(
        channel: Channel,
        max_size: usize,
        messenger: router::Messenger<P>,
        clock: C,
        quota: Quota,
    ) -> Self {
        let rate_limiter = Arc::new(Mutex::new(RateLimiter::hashmap_with_clock(quota, clock)));
        Self {
            channel,
            max_size,
            messenger,
            rate_limiter,
            peer_subscription: None,
            known_peers: Vec::new(),
        }
    }
}

impl<P: PublicKey, C: GClock> Clone for Sender<P, C> {
    fn clone(&self) -> Self {
        Self {
            channel: self.channel,
            max_size: self.max_size,
            messenger: self.messenger.clone(),
            rate_limiter: self.rate_limiter.clone(),
            peer_subscription: None,
            known_peers: Vec::new(),
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
    /// Recipients that exceed their rate limit will be skipped. The message is still sent to
    /// non-limited recipients. Check the returned vector to see which peers were sent the message.
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

        // If a subscription to peers is not yet established, do so now.
        let subscription = if let Some(ref mut subscription) = self.peer_subscription {
            subscription
        } else {
            let new_subscription = self.messenger.subscribe_peers().await;
            self.peer_subscription = Some(new_subscription);
            self.peer_subscription.as_mut().unwrap()
        };

        // Attempt to update known peers if there's a new update, but do not
        // wait for one.
        //
        // When the subscription is first created, it is guaranteed to have
        // the initial list of peers ready immediately.
        let rate_limiter = self.rate_limiter.lock().await;
        if let Some(peers) = subscription.next().now_or_never().flatten() {
            self.known_peers = peers;

            // Clean up limiter state
            rate_limiter.shrink_to_fit();
        }

        // Get the concrete list of peers to send to
        let peers: Vec<Self::PublicKey> = match recipients {
            Recipients::One(peer) => vec![peer],
            Recipients::Some(peers) => peers,
            Recipients::All => self.known_peers.clone(),
        };

        // Filter peers by rate limit, consuming rate tokens only for allowed peers
        let allowed_peers: Vec<_> = peers
            .into_iter()
            .filter(|peer| rate_limiter.check_key(peer).is_ok())
            .collect();
        drop(rate_limiter);

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
    messenger: router::Messenger<P>,
    max_size: usize,
    receivers: BTreeMap<Channel, (Quota, mpsc::Sender<Message<P>>)>,
}

impl<P: PublicKey> Channels<P> {
    pub const fn new(messenger: router::Messenger<P>, max_size: usize) -> Self {
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
