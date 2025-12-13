//! Message router for simulated networks.
//!
//! The router manages links between peers and handles message delivery
//! through the transmitter, applying link conditions (latency, jitter, success rate).

use super::{
    transmitter::{Completion, State as Transmitter},
    Link,
};
use bytes::Bytes;
use rand::Rng;
use std::{
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    time::{Duration, SystemTime},
};

/// A message that has been delivered and is ready for the recipient.
#[derive(Clone, Debug)]
pub struct Delivery<P, C> {
    /// The peer that sent the message.
    pub origin: P,
    /// The peer that should receive the message.
    pub recipient: P,
    /// The channel the message was sent on.
    pub channel: C,
    /// The message payload.
    pub message: Bytes,
    /// When the message should be delivered (None if dropped).
    pub deliver_at: Option<SystemTime>,
}

impl<P, C> From<Completion<P, C>> for Delivery<P, C> {
    fn from(c: Completion<P, C>) -> Self {
        Self {
            origin: c.origin,
            recipient: c.recipient,
            channel: c.channel,
            message: c.message,
            deliver_at: c.deliver_at,
        }
    }
}

/// Configuration for a link between two peers.
///
/// This is stored internally and used to sample latency and determine delivery.
#[derive(Clone, Debug)]
struct LinkConfig {
    link: Link,
}

/// A router that manages message delivery between peers.
///
/// The router handles:
/// - Link management between peer pairs
/// - Bandwidth limiting per peer
/// - Message scheduling via the transmitter
/// - Applying link conditions (latency, jitter, success rate)
///
/// # Type Parameters
///
/// - `P`: Peer identifier type (e.g., `PublicKey`, `Ipv4Addr`)
/// - `C`: Channel identifier type (e.g., `u64`, `u32`)
pub struct Router<P, C> {
    /// Links between peer pairs (sender, receiver) -> link config
    links: HashMap<(P, P), LinkConfig>,
    /// The transmitter that schedules message delivery
    transmitter: Transmitter<P, C>,
}

impl<P: Clone + Ord + Hash + Debug, C: Clone + Debug> Router<P, C> {
    /// Create a new router.
    pub fn new() -> Self {
        Self {
            links: HashMap::new(),
            transmitter: Transmitter::new(),
        }
    }

    /// Add or update a unidirectional link between two peers.
    ///
    /// The link configuration determines latency, jitter, and success rate
    /// for messages sent from `sender` to `receiver`.
    ///
    /// Returns `true` if a new link was added, `false` if an existing link was updated.
    pub fn add_link(&mut self, sender: P, receiver: P, link: Link) -> bool {
        let key = (sender, receiver);
        let is_new = !self.links.contains_key(&key);
        self.links.insert(key, LinkConfig { link });
        is_new
    }

    /// Remove a link between two peers.
    ///
    /// Returns the removed link configuration, or `None` if no link existed.
    pub fn remove_link(&mut self, sender: P, receiver: P) -> Option<Link> {
        self.links.remove(&(sender, receiver)).map(|c| c.link)
    }

    /// Check if a link exists between two peers.
    pub fn has_link(&self, sender: &P, receiver: &P) -> bool {
        self.links.contains_key(&(sender.clone(), receiver.clone()))
    }

    /// Get the link configuration between two peers.
    pub fn get_link(&self, sender: &P, receiver: &P) -> Option<&Link> {
        self.links
            .get(&(sender.clone(), receiver.clone()))
            .map(|c| &c.link)
    }

    /// Set bandwidth limits for a peer.
    ///
    /// Returns any completions that result from rebalancing.
    pub fn limit_bandwidth(
        &mut self,
        now: SystemTime,
        peer: &P,
        egress: Option<usize>,
        ingress: Option<usize>,
    ) -> Vec<Delivery<P, C>> {
        self.transmitter
            .limit(now, peer, egress, ingress)
            .into_iter()
            .map(Delivery::from)
            .collect()
    }

    /// Send a message from one peer to another.
    ///
    /// The message will be scheduled for delivery based on the link configuration
    /// and bandwidth limits. Returns any immediate completions.
    ///
    /// # Arguments
    ///
    /// - `now`: Current time
    /// - `rng`: Random number generator for sampling latency and success
    /// - `origin`: The sending peer
    /// - `recipient`: The receiving peer
    /// - `channel`: The channel to send on
    /// - `message`: The message payload
    ///
    /// # Returns
    ///
    /// - `None` if there is no link between the peers
    /// - `Some(deliveries)` with any immediate completions
    pub fn send<R: Rng>(
        &mut self,
        now: SystemTime,
        rng: &mut R,
        origin: P,
        recipient: P,
        channel: C,
        message: Bytes,
    ) -> Option<Vec<Delivery<P, C>>> {
        // Check if link exists
        let key = (origin.clone(), recipient.clone());
        let link_config = self.links.get(&key)?;

        // Sample latency from link
        let latency = link_config.link.sample_latency(rng);

        // Determine if message should be delivered
        let should_deliver = link_config.link.should_deliver(rng);

        // Enqueue to transmitter
        let completions = self.transmitter.enqueue(
            now,
            origin,
            recipient,
            channel,
            message,
            latency,
            should_deliver,
        );

        Some(completions.into_iter().map(Delivery::from).collect())
    }

    /// Send a message with explicit latency and delivery flag.
    ///
    /// This bypasses the link configuration and uses the provided values directly.
    /// Useful when the caller has already sampled the link or wants custom behavior.
    ///
    /// Returns `None` if no link exists, otherwise returns any immediate completions.
    #[allow(clippy::too_many_arguments)]
    pub fn send_raw(
        &mut self,
        now: SystemTime,
        origin: P,
        recipient: P,
        channel: C,
        message: Bytes,
        latency: Duration,
        should_deliver: bool,
    ) -> Option<Vec<Delivery<P, C>>> {
        // Check if link exists
        let key = (origin.clone(), recipient.clone());
        if !self.links.contains_key(&key) {
            return None;
        }

        // Enqueue to transmitter
        let completions = self.transmitter.enqueue(
            now,
            origin,
            recipient,
            channel,
            message,
            latency,
            should_deliver,
        );

        Some(completions.into_iter().map(Delivery::from).collect())
    }

    /// Get the next scheduled event time.
    ///
    /// Returns `None` if there are no pending events.
    pub fn next(&self) -> Option<SystemTime> {
        self.transmitter.next()
    }

    /// Advance the simulation to the given time.
    ///
    /// Returns all completions that occurred up to and including `now`.
    pub fn advance(&mut self, now: SystemTime) -> Vec<Delivery<P, C>> {
        self.transmitter
            .advance(now)
            .into_iter()
            .map(Delivery::from)
            .collect()
    }
}

impl<P: Clone + Ord + Hash + Debug, C: Clone + Debug> Default for Router<P, C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::time::UNIX_EPOCH;

    type TestRouter = Router<u64, u32>;

    #[test]
    fn add_and_remove_links() {
        let mut router = TestRouter::new();

        // No link initially
        assert!(!router.has_link(&1, &2));

        // Add link
        let link = Link::new(Duration::from_millis(10), Duration::ZERO, 1.0);
        assert!(router.add_link(1, 2, link.clone()));
        assert!(router.has_link(&1, &2));

        // Update link returns false
        assert!(!router.add_link(1, 2, link));
        assert!(router.has_link(&1, &2));

        // Remove link
        assert!(router.remove_link(1, 2).is_some());
        assert!(!router.has_link(&1, &2));

        // Remove again returns None
        assert!(router.remove_link(1, 2).is_none());
    }

    #[test]
    fn send_without_link_returns_none() {
        let mut router = TestRouter::new();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let now = UNIX_EPOCH;

        let result = router.send(now, &mut rng, 1, 2, 0, Bytes::from_static(b"hello"));
        assert!(result.is_none());
    }

    #[test]
    fn send_with_link_schedules_delivery() {
        let mut router = TestRouter::new();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let now = UNIX_EPOCH;

        // Add link with 100ms latency, no jitter, 100% success
        let link = Link::new(Duration::from_millis(100), Duration::ZERO, 1.0);
        router.add_link(1, 2, link);

        // Send message
        let deliveries = router
            .send(now, &mut rng, 1, 2, 0, Bytes::from_static(b"hello"))
            .unwrap();

        // With no bandwidth limits, message should complete immediately
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].origin, 1);
        assert_eq!(deliveries[0].recipient, 2);
        assert_eq!(
            deliveries[0].deliver_at,
            Some(now + Duration::from_millis(100))
        );
    }

    #[test]
    fn bandwidth_limited_delivery() {
        let mut router = TestRouter::new();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let now = UNIX_EPOCH;

        // Add link
        let link = Link::new(Duration::from_millis(50), Duration::ZERO, 1.0);
        router.add_link(1, 2, link);

        // Set bandwidth limit: 1KB/s egress for peer 1
        router.limit_bandwidth(now, &1, Some(1000), None);

        // Send 1KB message
        let message = Bytes::from(vec![0u8; 1000]);
        let deliveries = router.send(now, &mut rng, 1, 2, 0, message).unwrap();

        // No immediate completion due to bandwidth limit
        assert!(deliveries.is_empty());

        // Should complete after 1 second (1KB at 1KB/s)
        let next = router.next().unwrap();
        assert_eq!(next, now + Duration::from_secs(1));

        // Advance to completion
        let deliveries = router.advance(next);
        assert_eq!(deliveries.len(), 1);
        // Delivery time = completion time + latency
        assert_eq!(
            deliveries[0].deliver_at,
            Some(next + Duration::from_millis(50))
        );
    }

    #[test]
    fn dropped_messages() {
        let mut router = TestRouter::new();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let now = UNIX_EPOCH;

        // Add link with 0% success rate
        let link = Link::new(Duration::from_millis(10), Duration::ZERO, 0.0);
        router.add_link(1, 2, link);

        // Send message - should be marked as dropped
        let deliveries = router
            .send(now, &mut rng, 1, 2, 0, Bytes::from_static(b"drop me"))
            .unwrap();

        assert_eq!(deliveries.len(), 1);
        assert!(deliveries[0].deliver_at.is_none()); // Dropped
    }
}
