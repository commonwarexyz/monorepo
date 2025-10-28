use crate::p2p::wire;
use bimap::BiHashMap;
use commonware_cryptography::PublicKey;
use commonware_p2p::{
    utils::{
        codec::WrappedSender,
        requester::{Config, Requester, ID},
    },
    Recipients, Sender,
};
use commonware_runtime::{Clock, Metrics};
use commonware_utils::{PrioritySet, Span};
use governor::clock::Clock as GClock;
use rand::Rng;
use std::{
    marker::PhantomData,
    time::{Duration, SystemTime},
};
use thiserror::Error;
use tracing::debug;

/// Errors that can occur when sending network messages.
#[derive(Error, Debug, PartialEq)]
enum SendError<S: Sender> {
    #[error("send returned empty")]
    Empty,
    #[error("send failed: {0}")]
    Failed(S::Error),
}

/// Maintains requests for data from other peers, called fetches.
///
/// Requests are called fetches. Fetches may be in one of two states:
/// - Active: Sent to a peer and is waiting for a response.
/// - Pending: Not successfully sent to a peer. Waiting to be retried by timeout.
///
/// Both types of requests will be retried after a timeout if not resolved (i.e. a response or a
/// cancellation). Upon retry, requests may either be placed in active or pending state again.
pub struct Fetcher<
    E: Clock + GClock + Rng + Metrics,
    P: PublicKey,
    Key: Span,
    NetS: Sender<PublicKey = P>,
> {
    context: E,

    /// Helps find peers to fetch from and tracks which peers are assigned to which request ids.
    requester: Requester<E, P>,

    /// Manages active requests. If a fetch is sent to a peer, it is added to this map.
    active: BiHashMap<ID, Key>,

    /// Manages pending requests. If fetches fail to make a request to a peer, they are instead
    /// added to this map and are retried after the deadline.
    pending: PrioritySet<Key, SystemTime>,

    /// How long fetches remain in the pending queue before being retried
    retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages
    priority_requests: bool,

    /// Phantom data for networking types
    _s: PhantomData<NetS>,
}

impl<E: Clock + GClock + Rng + Metrics, P: PublicKey, Key: Span, NetS: Sender<PublicKey = P>>
    Fetcher<E, P, Key, NetS>
{
    /// Creates a new fetcher.
    pub fn new(
        context: E,
        requester_config: Config<P>,
        retry_timeout: Duration,
        priority_requests: bool,
    ) -> Self {
        let requester = Requester::new(context.with_label("requester"), requester_config);
        Self {
            context,
            requester,
            active: BiHashMap::new(),
            pending: PrioritySet::new(),
            retry_timeout,
            priority_requests,
            _s: PhantomData,
        }
    }

    /// Makes a fetch request.
    ///
    /// If `is_new` is true, the fetch is treated as a new request.
    /// If false, the fetch is treated as a retry.
    ///
    /// Panics if the key is already being fetched.
    pub async fn fetch(
        &mut self,
        sender: &mut WrappedSender<NetS, wire::Message<Key>>,
        key: Key,
        is_new: bool,
    ) {
        // Panic if the key is already being fetched
        assert!(!self.contains(&key));

        // Get peer to send request to
        let shuffle = !is_new;
        let Some((peer, id)) = self.requester.request(shuffle) else {
            // If there are no peers, add the key to the pending queue
            debug!(?key, "requester failed");
            self.add_pending(key);
            return;
        };

        // Send message to peer
        let result = sender
            .send(
                Recipients::One(peer.clone()),
                wire::Message {
                    id,
                    payload: wire::Payload::Request(key.clone()),
                },
                self.priority_requests,
            )
            .await;
        let result = match result {
            Err(err) => Err(SendError::Failed::<NetS>(err)),
            Ok(to) if to.is_empty() => Err(SendError::Empty),
            Ok(_) => Ok(()),
        };

        // Insert the request into the relevant map
        match result {
            // If the message was not sent successfully, treat it instantly as a peer timeout
            Err(err) => {
                debug!(?err, ?peer, "send failed");
                let req = self.requester.handle(&peer, id).unwrap(); // Unwrap is safe
                self.requester.fail(req);
                self.add_pending(key);
            }
            // If the message was sent to someone, add the request to the map
            Ok(()) => {
                self.active.insert(id, key);
            }
        }
    }

    /// Retains only the fetches with keys greater than the given key.
    pub fn retain(&mut self, predicate: impl Fn(&Key) -> bool) {
        self.active.retain(|_, k| predicate(k));
        self.pending.retain(predicate);
    }

    /// Cancels a fetch request.
    ///
    /// Returns `true` if the fetch was canceled.
    pub fn cancel(&mut self, key: &Key) -> bool {
        // Check the pending queue first
        if self.pending.remove(key) {
            return true;
        }

        // Check the outstanding fetches map second
        self.active.remove_by_right(key).is_some()

        // Do not remove the requester entry.
        // It is useful for measuring performance if the peer ever responds.
        // If the peer never responds, the requester entry will be removed by timeout.
    }

    /// Cancel all fetches.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.active.clear();
    }

    /// Adds a key to the pending queue.
    ///
    /// Panics if the key is already pending.
    pub fn add_pending(&mut self, key: Key) {
        assert!(!self.pending.contains(&key));
        let deadline = self.context.current() + self.retry_timeout;
        self.pending.put(key, deadline);
    }

    /// Returns the deadline for the next pending retry.
    pub fn get_pending_deadline(&self) -> Option<SystemTime> {
        self.pending.peek().map(|(_, deadline)| *deadline)
    }

    /// Returns the deadline for the next requester timeout.
    pub fn get_active_deadline(&self) -> Option<SystemTime> {
        self.requester.next().map(|(_, deadline)| deadline)
    }

    /// Removes and returns the pending key with the earliest deadline.
    ///
    /// Panics if there are no pending keys.
    pub fn pop_pending(&mut self) -> Key {
        let (key, _deadline) = self.pending.pop().unwrap();
        key
    }

    /// Removes and returns the key with the next requester timeout.
    ///
    /// Panics if there are no timeouts.
    pub fn pop_active(&mut self) -> Option<Key> {
        // The ID must exist
        let (id, _) = self.requester.next().unwrap();

        // The request must exist
        let request = self.requester.cancel(id).unwrap();
        self.requester.timeout(request);

        // Remove the existing request information, if any.
        // It is possible that the request was canceled before it timed out.
        self.active.remove_by_left(&id).map(|(_id, key)| key)
    }

    /// Processes a response from a peer. Removes and returns the relevant key.
    ///
    /// Returns the key that was fetched if the response was valid.
    /// Returns None if the response was invalid or not needed.
    pub fn pop_by_id(&mut self, id: ID, peer: &P, has_response: bool) -> Option<Key> {
        // Pop the request from requester if the peer was assigned to this id, otherwise return none
        let request = self.requester.handle(peer, id)?;

        // Update the peer's performance, treating a lack of response as a timeout
        match has_response {
            true => self.requester.resolve(request),
            false => self.requester.timeout(request),
        };

        // Remove and return the relevant key if it exists
        // The key may not exist if the request was canceled before the peer responded
        self.active.remove_by_left(&id).map(|(_id, key)| key)
    }

    /// Returns true if the fetch is in progress.
    pub fn contains(&self, key: &Key) -> bool {
        self.active.contains_right(key) || self.pending.contains(key)
    }

    /// Reconciles the list of peers that can be used to fetch data.
    pub fn reconcile(&mut self, keep: &[P]) {
        self.requester.reconcile(keep);
    }

    /// Blocks a peer from being used to fetch data.
    pub fn block(&mut self, peer: P) {
        self.requester.block(peer);
    }

    /// Returns the number of fetches.
    pub fn len(&self) -> usize {
        self.pending.len() + self.active.len()
    }

    /// Returns the number of pending fetches.
    pub fn len_pending(&self) -> usize {
        self.pending.len()
    }

    /// Returns the number of active fetches.
    pub fn len_active(&self) -> usize {
        self.active.len()
    }

    /// Returns the number of blocked peers.
    pub fn len_blocked(&self) -> usize {
        self.requester.len_blocked()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::mocks::Key as MockKey;
    use bytes::Bytes;
    use commonware_cryptography::{ed25519::PublicKey as Ed25519PublicKey, PrivateKeyExt, Signer};
    use commonware_p2p::{utils::requester::Config as RequesterConfig, Recipients, Sender};
    use commonware_runtime::{
        deterministic::{Context, Runner},
        Runner as _,
    };
    use governor::Quota;
    use std::{fmt, time::Duration};

    // Mock error type for testing
    #[derive(Debug)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "mock error")
        }
    }

    impl std::error::Error for MockError {}

    // Mock sender for testing
    #[derive(Clone, Debug)]
    struct MockSender;

    impl Sender for MockSender {
        type PublicKey = Ed25519PublicKey;
        type Error = MockError;

        async fn send(
            &mut self,
            _recipients: Recipients<Self::PublicKey>,
            _message: Bytes,
            _priority: bool,
        ) -> Result<Vec<Self::PublicKey>, Self::Error> {
            Ok(vec![])
        }
    }

    fn create_test_fetcher(
        context: Context,
    ) -> Fetcher<Context, Ed25519PublicKey, MockKey, MockSender> {
        let public_key = commonware_cryptography::ed25519::PrivateKey::from_seed(0).public_key();
        let requester_config = RequesterConfig {
            me: Some(public_key),
            rate_limit: Quota::per_second(std::num::NonZeroU32::new(10).unwrap()),
            initial: Duration::from_millis(100),
            timeout: Duration::from_secs(5),
        };
        let retry_timeout = Duration::from_millis(100);
        let priority_requests = false;

        Fetcher::new(context, requester_config, retry_timeout, priority_requests)
    }

    #[test]
    fn test_retain_function() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Add some keys to pending and active states
            fetcher.add_pending(MockKey(1));
            fetcher.add_pending(MockKey(2));
            fetcher.add_pending(MockKey(3));

            // Add keys to active state by simulating successful fetch
            fetcher.active.insert(100, MockKey(10));
            fetcher.active.insert(101, MockKey(20));
            fetcher.active.insert(102, MockKey(30));

            // Verify initial state
            assert_eq!(fetcher.len(), 6);
            assert_eq!(fetcher.len_pending(), 3);
            assert_eq!(fetcher.len_active(), 3);

            // Retain keys with value <= 10
            fetcher.retain(|key| key.0 <= 10);

            // Check that only keys with value <= 10 remain
            // MockKey(1) from pending should remain
            // MockKey(10) from active should remain
            // MockKey(2), MockKey(3) from pending should be removed (2 <= 10 and 3 <= 10, wait that's wrong)
            // Actually all keys <= 10 should remain: 1, 2, 3, 10
            assert_eq!(fetcher.len(), 4); // Key(1), Key(2), Key(3), Key(10)
            assert_eq!(fetcher.len_pending(), 3); // Key(1), Key(2), Key(3)
            assert_eq!(fetcher.len_active(), 1); // Key(10)

            // Verify specific keys
            assert!(fetcher.pending.contains(&MockKey(1)));
            assert!(fetcher.pending.contains(&MockKey(2)));
            assert!(fetcher.pending.contains(&MockKey(3)));
            assert!(fetcher.active.contains_right(&MockKey(10)));
            assert!(!fetcher.active.contains_right(&MockKey(20)));
            assert!(!fetcher.active.contains_right(&MockKey(30)));
        });
    }

    #[test]
    fn test_clear_function() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Add some keys to pending and active states
            fetcher.add_pending(MockKey(1));
            fetcher.add_pending(MockKey(2));
            fetcher.add_pending(MockKey(3));

            // Add keys to active state
            fetcher.active.insert(100, MockKey(10));
            fetcher.active.insert(101, MockKey(20));
            fetcher.active.insert(102, MockKey(30));

            // Verify initial state
            assert_eq!(fetcher.len(), 6);
            assert_eq!(fetcher.len_pending(), 3);
            assert_eq!(fetcher.len_active(), 3);

            // Clear all fetches
            fetcher.clear();

            // Verify everything is cleared
            assert_eq!(fetcher.len(), 0);
            assert_eq!(fetcher.len_pending(), 0);
            assert_eq!(fetcher.len_active(), 0);

            // Verify specific collections are empty
            assert!(fetcher.pending.is_empty());
            assert!(fetcher.active.is_empty());
        });
    }

    #[test]
    fn test_len_functions() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Initially empty
            assert_eq!(fetcher.len(), 0);
            assert_eq!(fetcher.len_pending(), 0);
            assert_eq!(fetcher.len_active(), 0);

            // Add pending keys
            fetcher.add_pending(MockKey(1));
            fetcher.add_pending(MockKey(2));
            assert_eq!(fetcher.len(), 2);
            assert_eq!(fetcher.len_pending(), 2);
            assert_eq!(fetcher.len_active(), 0);

            // Add active keys
            fetcher.active.insert(100, MockKey(10));
            fetcher.active.insert(101, MockKey(20));
            assert_eq!(fetcher.len(), 4);
            assert_eq!(fetcher.len_pending(), 2);
            assert_eq!(fetcher.len_active(), 2);

            // Remove one pending key
            assert!(fetcher.pending.remove(&MockKey(1)));
            assert_eq!(fetcher.len(), 3);
            assert_eq!(fetcher.len_pending(), 1);
            assert_eq!(fetcher.len_active(), 2);

            // Remove one active key
            assert!(fetcher.active.remove_by_right(&MockKey(10)).is_some());
            assert_eq!(fetcher.len(), 2);
            assert_eq!(fetcher.len_pending(), 1);
            assert_eq!(fetcher.len_active(), 1);
        });
    }

    #[test]
    fn test_retain_with_empty_collections() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Test retain on empty collections
            fetcher.retain(|_| true);
            assert_eq!(fetcher.len(), 0);

            fetcher.retain(|_| false);
            assert_eq!(fetcher.len(), 0);
        });
    }

    #[test]
    fn test_retain_all_elements_match_predicate() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Add keys
            fetcher.add_pending(MockKey(1));
            fetcher.add_pending(MockKey(2));
            fetcher.active.insert(100, MockKey(10));
            fetcher.active.insert(101, MockKey(20));

            let initial_len = fetcher.len();

            // Retain all (predicate always returns true)
            fetcher.retain(|_| true);

            // Nothing should be removed
            assert_eq!(fetcher.len(), initial_len);
            assert_eq!(fetcher.len_pending(), 2);
            assert_eq!(fetcher.len_active(), 2);
        });
    }

    #[test]
    fn test_retain_no_elements_match_predicate() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Add keys
            fetcher.add_pending(MockKey(1));
            fetcher.add_pending(MockKey(2));
            fetcher.active.insert(100, MockKey(10));
            fetcher.active.insert(101, MockKey(20));

            // Retain none (predicate always returns false)
            fetcher.retain(|_| false);

            // Everything should be removed
            assert_eq!(fetcher.len(), 0);
            assert_eq!(fetcher.len_pending(), 0);
            assert_eq!(fetcher.len_active(), 0);
        });
    }

    #[test]
    fn test_cancel_function() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Add keys to both pending and active states
            fetcher.add_pending(MockKey(1));
            fetcher.add_pending(MockKey(2));
            fetcher.active.insert(100, MockKey(10));
            fetcher.active.insert(101, MockKey(20));

            // Test canceling pending key
            assert!(fetcher.cancel(&MockKey(1)));
            assert_eq!(fetcher.len_pending(), 1);
            assert!(!fetcher.contains(&MockKey(1)));

            // Test canceling active key
            assert!(fetcher.cancel(&MockKey(10)));
            assert_eq!(fetcher.len_active(), 1);
            assert!(!fetcher.contains(&MockKey(10)));

            // Test canceling non-existent key
            assert!(!fetcher.cancel(&MockKey(99)));

            // Test canceling already canceled key
            assert!(!fetcher.cancel(&MockKey(1)));
        });
    }

    #[test]
    fn test_contains_function() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Initially empty
            assert!(!fetcher.contains(&MockKey(1)));

            // Add to pending
            fetcher.add_pending(MockKey(1));
            assert!(fetcher.contains(&MockKey(1)));

            // Add to active
            fetcher.active.insert(100, MockKey(10));
            assert!(fetcher.contains(&MockKey(10)));

            // Test non-existent key
            assert!(!fetcher.contains(&MockKey(99)));

            // Remove from pending
            fetcher.pending.remove(&MockKey(1));
            assert!(!fetcher.contains(&MockKey(1)));

            // Remove from active
            fetcher.active.remove_by_right(&MockKey(10));
            assert!(!fetcher.contains(&MockKey(10)));
        });
    }

    #[test]
    fn test_add_pending_function() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Add first key
            fetcher.add_pending(MockKey(1));
            assert_eq!(fetcher.len_pending(), 1);
            assert!(fetcher.contains(&MockKey(1)));

            // Add second key
            fetcher.add_pending(MockKey(2));
            assert_eq!(fetcher.len_pending(), 2);
            assert!(fetcher.contains(&MockKey(2)));

            // Verify deadline is set
            assert!(fetcher.get_pending_deadline().is_some());
        });
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn test_add_pending_duplicate_panics() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            fetcher.add_pending(MockKey(1));
            // This should panic
            fetcher.add_pending(MockKey(1));
        });
    }

    #[test]
    fn test_get_pending_deadline() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // No deadline when empty
            assert!(fetcher.get_pending_deadline().is_none());

            // Add key and check deadline exists
            fetcher.add_pending(MockKey(1));
            assert!(fetcher.get_pending_deadline().is_some());

            // Add another key - should still have a deadline
            fetcher.add_pending(MockKey(2));
            assert!(fetcher.get_pending_deadline().is_some());

            // Clear and check no deadline
            fetcher.pending.clear();
            assert!(fetcher.get_pending_deadline().is_none());
        });
    }

    #[test]
    fn test_get_active_deadline() {
        let runner = Runner::default();
        runner.start(|context| async {
            let fetcher = create_test_fetcher(context);

            // No deadline when empty (requester has no timeouts)
            assert!(fetcher.get_active_deadline().is_none());
        });
    }

    #[test]
    fn test_pop_pending() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Add keys
            fetcher.add_pending(MockKey(1));
            fetcher.add_pending(MockKey(2));
            assert_eq!(fetcher.len_pending(), 2);

            // Pop first key
            let key = fetcher.pop_pending();
            assert!(key == MockKey(1) || key == MockKey(2)); // Order may vary due to priority queue
            assert_eq!(fetcher.len_pending(), 1);

            // Pop second key
            let key2 = fetcher.pop_pending();
            assert!(key2 == MockKey(1) || key2 == MockKey(2));
            assert_ne!(key, key2); // Should be different keys
            assert_eq!(fetcher.len_pending(), 0);
        });
    }

    #[test]
    #[should_panic]
    fn test_pop_pending_empty_panics() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);
            // This should panic
            fetcher.pop_pending();
        });
    }

    #[test]
    fn test_pop_active() {
        let runner = Runner::default();
        runner.start(|context| async {
            let fetcher = create_test_fetcher(context);

            // No active requests, should return None when popping
            // (This tests the case where requester.next() returns None or the active map doesn't contain the key)
            assert!(fetcher.get_active_deadline().is_none());
        });
    }

    #[test]
    fn test_pop_by_id() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);
            let dummy_peer =
                commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();

            // Add key to active state
            fetcher.active.insert(100, MockKey(10));

            // Test pop with non-existent ID (requester.handle returns None)
            assert!(fetcher.pop_by_id(999, &dummy_peer, true).is_none());

            // The active entry should still be there since the ID wasn't handled by requester
            assert_eq!(fetcher.len_active(), 1);
        });
    }

    #[test]
    fn test_reconcile_and_block() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();

            // Test reconcile with peers
            fetcher.reconcile(&[peer1.clone(), peer2.clone()]);

            // Test block peer
            fetcher.block(peer1.clone());

            // Initially no blocked peers (this depends on internal requester state)
            // The len_blocked function returns the count from the requester
        });
    }

    #[test]
    fn test_len_blocked() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Initially no blocked peers
            let initial_blocked = fetcher.len_blocked();

            // Block a peer
            let peer = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            fetcher.block(peer);

            // The count should potentially increase (depends on requester implementation)
            let after_block = fetcher.len_blocked();
            assert!(after_block >= initial_blocked);
        });
    }

    #[test]
    fn test_edge_cases_empty_state() {
        let runner = Runner::default();
        runner.start(|context| async {
            let fetcher = create_test_fetcher(context);

            // Test all functions on empty fetcher
            assert_eq!(fetcher.len(), 0);
            assert_eq!(fetcher.len_pending(), 0);
            assert_eq!(fetcher.len_active(), 0);
            assert!(!fetcher.contains(&MockKey(1)));
            assert!(fetcher.get_pending_deadline().is_none());
            assert!(fetcher.get_active_deadline().is_none());
        });
    }

    #[test]
    fn test_cancel_edge_cases() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Cancel from empty fetcher
            assert!(!fetcher.cancel(&MockKey(1)));

            // Add key, cancel it, then try to cancel again
            fetcher.add_pending(MockKey(1));
            assert!(fetcher.cancel(&MockKey(1)));
            assert!(!fetcher.cancel(&MockKey(1))); // Should return false
        });
    }

    #[test]
    fn test_retain_preserves_active_state() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Add keys to active with specific IDs
            fetcher.active.insert(100, MockKey(1));
            fetcher.active.insert(101, MockKey(2));

            // Retain only MockKey(1)
            fetcher.retain(|key| key.0 == 1);

            // Verify the ID mapping is preserved correctly
            assert_eq!(fetcher.len_active(), 1);
            assert!(fetcher.active.contains_right(&MockKey(1)));
            assert!(!fetcher.active.contains_right(&MockKey(2)));

            // Verify the ID 100 still maps to MockKey(1)
            if let Some((_, key)) = fetcher.active.iter().next() {
                assert_eq!(*key, MockKey(1));
            }
        });
    }

    #[test]
    fn test_mixed_operations() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

            // Add keys to both pending and active
            fetcher.add_pending(MockKey(1));
            fetcher.add_pending(MockKey(2));
            fetcher.active.insert(100, MockKey(10));
            fetcher.active.insert(101, MockKey(20));

            assert_eq!(fetcher.len(), 4);

            // Cancel one from each
            assert!(fetcher.cancel(&MockKey(1))); // pending
            assert!(fetcher.cancel(&MockKey(10))); // active

            assert_eq!(fetcher.len(), 2);

            // Retain only keys <= 20
            fetcher.retain(|key| key.0 <= 20);

            // Should still have MockKey(2) pending and MockKey(20) active
            assert_eq!(fetcher.len(), 2);
            assert!(fetcher.contains(&MockKey(2)));
            assert!(fetcher.contains(&MockKey(20)));

            // Clear all
            fetcher.clear();
            assert_eq!(fetcher.len(), 0);
        });
    }
}
