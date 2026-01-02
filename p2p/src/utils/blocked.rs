//! Utility for tracking blocked peers with expiration.

use commonware_runtime::Clock;
use prometheus_client::metrics::gauge::Gauge;
use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    sync::atomic::AtomicI64,
    time::SystemTime,
};

/// Tracks blocked peers with expiration times.
///
/// Uses a `HashMap` for O(1) lookup of blocked status and a `VecDeque` for
/// ordered expiration processing. Blocks persist even if peers are removed
/// from other data structures.
pub struct Queue<K> {
    /// Maps peer -> unblock time for O(1) lookup.
    blocked: HashMap<K, SystemTime>,

    /// Queue of (unblock_time, peer) entries, ordered by time (oldest first).
    queue: VecDeque<(SystemTime, K)>,

    /// Metric tracking the number of blocked peers.
    metric: Gauge<i64, AtomicI64>,
}

impl<K: Eq + Hash + Clone> Queue<K> {
    /// Create a new empty block queue with the given metric.
    pub fn new(metric: Gauge<i64, AtomicI64>) -> Self {
        Self {
            blocked: HashMap::new(),
            queue: VecDeque::new(),
            metric,
        }
    }

    /// Block a peer until the given time.
    ///
    /// Returns `true` if the peer was newly blocked, `false` if already blocked.
    pub fn block(&mut self, peer: K, until: SystemTime) -> bool {
        if self.blocked.contains_key(&peer) {
            return false;
        }
        self.blocked.insert(peer.clone(), until);
        self.queue.push_back((until, peer));
        self.metric.inc();
        true
    }

    /// Returns `true` if the peer is currently blocked.
    pub fn is_blocked(&self, peer: &K) -> bool {
        self.blocked.contains_key(peer)
    }

    /// Returns the time when the peer will be unblocked, if blocked.
    pub fn blocked_until(&self, peer: &K) -> Option<SystemTime> {
        self.blocked.get(peer).copied()
    }

    /// Unblock all peers whose block has expired.
    ///
    /// Returns the list of peers that were unblocked.
    pub fn unblock_expired(&mut self, now: SystemTime) -> Vec<K> {
        let mut unblocked = Vec::new();

        while let Some((until, _)) = self.queue.front() {
            if *until > now {
                break;
            }
            let (_, peer) = self.queue.pop_front().unwrap();
            if self.blocked.remove(&peer).is_some() {
                self.metric.dec();
                unblocked.push(peer);
            }
        }

        unblocked
    }

    /// Returns the next unblock deadline, if any peers are blocked.
    pub fn next_deadline(&self) -> Option<SystemTime> {
        self.queue.front().map(|(time, _)| *time)
    }
}

/// Sleep until the next deadline, or wait forever if none.
pub async fn wait_for<E: Clock>(context: &E, deadline: Option<SystemTime>) {
    match deadline {
        Some(time) => context.sleep_until(time).await,
        None => futures::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1000)
    }

    fn new_queue<K: Eq + Hash + Clone>() -> Queue<K> {
        Queue::new(Gauge::default())
    }

    #[test]
    fn test_block_and_is_blocked() {
        let mut queue = new_queue();
        let peer = "peer1";
        let until = now() + Duration::from_secs(100);

        assert!(!queue.is_blocked(&peer));
        assert!(queue.block(peer, until));
        assert!(queue.is_blocked(&peer));
        assert_eq!(queue.metric.get(), 1);

        // Blocking again returns false
        assert!(!queue.block(peer, until));
        assert_eq!(queue.metric.get(), 1);
    }

    #[test]
    fn test_blocked_until() {
        let mut queue = new_queue();
        let peer = "peer1";
        let until = now() + Duration::from_secs(100);

        assert!(queue.blocked_until(&peer).is_none());
        queue.block(peer, until);
        assert_eq!(queue.blocked_until(&peer), Some(until));
    }

    #[test]
    fn test_unblock_expired() {
        let mut queue = new_queue();
        let peer1 = "peer1";
        let peer2 = "peer2";
        let until1 = now() + Duration::from_secs(100);
        let until2 = now() + Duration::from_secs(200);

        queue.block(peer1, until1);
        queue.block(peer2, until2);
        assert_eq!(queue.metric.get(), 2);

        // Nothing expired yet
        let unblocked = queue.unblock_expired(now());
        assert!(unblocked.is_empty());
        assert!(queue.is_blocked(&peer1));
        assert!(queue.is_blocked(&peer2));
        assert_eq!(queue.metric.get(), 2);

        // Only peer1 expired
        let unblocked = queue.unblock_expired(until1 + Duration::from_secs(1));
        assert_eq!(unblocked, vec![peer1]);
        assert!(!queue.is_blocked(&peer1));
        assert!(queue.is_blocked(&peer2));
        assert_eq!(queue.metric.get(), 1);

        // peer2 expired
        let unblocked = queue.unblock_expired(until2 + Duration::from_secs(1));
        assert_eq!(unblocked, vec![peer2]);
        assert!(!queue.is_blocked(&peer2));
        assert_eq!(queue.metric.get(), 0);
    }

    #[test]
    fn test_next_deadline() {
        let mut queue: Queue<&str> = new_queue();

        assert!(queue.next_deadline().is_none());

        let until1 = now() + Duration::from_secs(100);
        let until2 = now() + Duration::from_secs(200);

        queue.block("peer1", until1);
        assert_eq!(queue.next_deadline(), Some(until1));

        queue.block("peer2", until2);
        assert_eq!(queue.next_deadline(), Some(until1));

        queue.unblock_expired(until1 + Duration::from_secs(1));
        assert_eq!(queue.next_deadline(), Some(until2));

        queue.unblock_expired(until2 + Duration::from_secs(1));
        assert!(queue.next_deadline().is_none());
    }

    #[test]
    fn test_block_persists_after_unblock_expired_with_no_match() {
        let mut queue = new_queue();
        let peer = "peer1";
        let until = now() + Duration::from_secs(100);

        queue.block(peer, until);

        // Calling unblock_expired before expiration should not affect the block
        queue.unblock_expired(now());
        assert!(queue.is_blocked(&peer));
    }
}
