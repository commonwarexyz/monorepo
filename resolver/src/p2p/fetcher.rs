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
use commonware_utils::{PrioritySet, Span, SystemTimeExt};
use governor::clock::Clock as GClock;
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
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
///
/// # Hints
///
/// Peers can be registered as "hints" for specific keys, indicating they likely have the data.
/// When fetching, hinted peers are tried first. On failure (timeout, error, send failure),
/// only the failing peer is removed from hints. When all hints fail, the fetcher falls back
/// to trying any peer. Hints are cleared on successful fetch.
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

    /// Manages pending requests. When a request is registered (for both the first time and after
    /// a retry), it is added to this set.
    ///
    /// The value is a tuple of the next time to try the request and a boolean indicating if the request
    /// is a retry (in which case the request should be made to a random peer).
    pending: PrioritySet<Key, (SystemTime, bool)>,

    /// If no peers are ready to handle a request (due to rate limiting), the waiter is set
    /// to the next time to try the request (this is often after the first value in pending).
    waiter: Option<SystemTime>,

    /// How long fetches remain in the pending queue before being retried
    retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages
    priority_requests: bool,

    /// Per-key hint peers indicating which peers likely have data for each key.
    /// Hinted peers are tried first, waiting for them if rate-limited. If all hinted
    /// peers are unavailable (disconnected or blocked), hints are cleared and any peer
    /// is tried. On failure, only the failing peer is removed; on success, all hints
    /// for that key are cleared.
    hints: HashMap<Key, HashSet<P>>,

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
            waiter: None,
            retry_timeout,
            priority_requests,
            hints: HashMap::new(),
            _s: PhantomData,
        }
    }

    /// Attempts to send a fetch request for the next pending key.
    ///
    /// If hints exist for the key, only hinted peers are considered. If all hinted
    /// peers are unavailable (disconnected or blocked), hints are cleared and any peer
    /// is tried. If hinted peers exist but are rate-limited, the fetch waits for them.
    ///
    /// On send failure, the key is retried (and if the peer was hinted, it is removed).
    pub async fn fetch(&mut self, sender: &mut WrappedSender<NetS, wire::Message<Key>>) {
        // Reset waiter
        self.waiter = None;

        // Peek at the pending key to check for hints
        let (key, (_, retry)) = self.pending.peek().unwrap();

        // Get peer to send request to, using hints if available
        let result = match self.hints.get(key) {
            Some(hints) => {
                match self
                    .requester
                    .request_filtered(*retry, |p| hints.contains(p))
                {
                    Ok(selection) => Ok(selection),
                    Err(wait) if wait == Duration::MAX => {
                        // No hinted peers available - clear hints, try any peer
                        self.hints.remove(key);
                        self.requester.request(*retry)
                    }
                    Err(wait) => Err(wait), // Hinted peers rate-limited, wait for them
                }
            }
            _ => self.requester.request(*retry),
        };

        let (peer, id) = match result {
            Ok(selection) => selection,
            Err(next) => {
                let waiter = self.context.current().saturating_add(next);
                self.waiter = Some(waiter);
                return;
            }
        };

        // Wait to pop a key until we know we can make a request
        let key = self.pop_pending();

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
                self.remove_hint(&key, &peer);
                self.add_retry(key);
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
        self.pending.retain(&predicate);
        self.hints.retain(|k, _| predicate(k));
    }

    /// Cancels a fetch request.
    ///
    /// Returns `true` if the fetch was canceled.
    pub fn cancel(&mut self, key: &Key) -> bool {
        // Remove hints for this key
        self.clear_hints(key);

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
        self.hints.clear();
    }

    /// Adds a key to the front of the pending queue.
    pub fn add_ready(&mut self, key: Key) {
        assert!(!self.pending.contains(&key));
        self.pending.put(key, (self.context.current(), false));
    }

    /// Adds a key to the pending queue.
    ///
    /// Panics if the key is already pending.
    pub fn add_retry(&mut self, key: Key) {
        assert!(!self.pending.contains(&key));
        let deadline = self.context.current() + self.retry_timeout;
        self.pending.put(key, (deadline, true));
    }

    /// Returns the deadline for the next pending retry.
    pub fn get_pending_deadline(&self) -> Option<SystemTime> {
        // Pending may be emptied by cancel/retain
        if self.pending.is_empty() {
            return None;
        }

        // Return the greater of the waiter and the next pending deadline
        let pending_deadline = self.peek_pending().map(|(deadline, _)| deadline);
        pending_deadline.max(self.waiter)
    }

    /// Returns the deadline for the next requester timeout.
    pub fn get_active_deadline(&self) -> Option<SystemTime> {
        self.requester.next().map(|(_, deadline)| deadline)
    }

    /// Returns whether the next item in the pending queue is a retry.
    pub fn peek_pending(&self) -> Option<(SystemTime, bool)> {
        self.pending.peek().map(|(_, value)| *value)
    }

    /// Removes and returns the pending key with the earliest deadline.
    ///
    /// Panics if there are no pending keys.
    pub fn pop_pending(&mut self) -> Key {
        let (key, _) = self.pending.pop().unwrap();
        key
    }

    /// Removes and returns the key with the next requester timeout. If the peer
    /// was hinted for this key, it is removed from hints.
    ///
    /// Panics if there are no timeouts.
    pub fn pop_active(&mut self) -> Option<Key> {
        // The ID must exist
        let (id, _) = self.requester.next().unwrap();

        // The request must exist
        let request = self.requester.cancel(id).unwrap();
        let peer = request.participant.clone();
        self.requester.timeout(request);

        // Remove the existing request information, if any.
        // It is possible that the request was canceled before it timed out.
        let result = self.active.remove_by_left(&id).map(|(_, key)| key);

        // Remove the timed-out peer from hints
        if let Some(ref key) = result {
            self.remove_hint(key, &peer);
        }

        result
    }

    /// Processes a response from a peer. Removes and returns the relevant key.
    ///
    /// Returns `(key, hinted)` if the response was valid, where `hinted` indicates
    /// if the peer was hinted for this key. Returns None if the response was invalid
    /// or not needed.
    ///
    /// On error response (`has_response=false`), only this peer is removed from hints.
    /// On data response (`has_response=true`), **no hint cleanup is performed** since the caller
    /// must validate the response data. On valid data it should then call `clear_hints()`,
    /// otherwise it should block the peer, which removes any hints associated with it.
    pub fn pop_by_id(&mut self, id: ID, peer: &P, has_response: bool) -> Option<(Key, bool)> {
        // Pop the request from requester if the peer was assigned to this id, otherwise return none
        let request = self.requester.handle(peer, id)?;

        // Update the peer's performance, treating a lack of response as a timeout
        match has_response {
            true => self.requester.resolve(request),
            false => self.requester.timeout(request),
        };

        // Remove and return the relevant key if it exists
        // The key may not exist if the request was canceled before the peer responded
        self.active.remove_by_left(&id).map(|(_, key)| {
            // On error response, remove this peer from hints and use return value
            // On data response, just check if peer is hinted (caller handles hint cleanup)
            let hinted = if has_response {
                self.hints
                    .get(&key)
                    .map(|h| h.contains(peer))
                    .unwrap_or(false)
            } else {
                self.remove_hint(&key, peer)
            };

            (key, hinted)
        })
    }

    /// Reconciles the list of peers that can be used to fetch data.
    pub fn reconcile(&mut self, keep: &[P]) {
        self.requester.reconcile(keep);

        // Clear waiter (may no longer apply)
        self.waiter = None;
    }

    /// Blocks a peer from being used to fetch data.
    ///
    /// Also removes the peer from all hint sets.
    pub fn block(&mut self, peer: P) {
        // Remove peer from all hint sets
        for hints in self.hints.values_mut() {
            hints.remove(&peer);
        }

        // Clean up empty hint sets
        self.hints.retain(|_, v| !v.is_empty());

        self.requester.block(peer);
    }

    /// Register a peer as likely having data for a key.
    ///
    /// Hinted peers are tried first when fetching. If a hinted peer fails
    /// (timeout, error response, or send failure), only that peer is removed.
    /// When hints become empty, all peers are used as fallback.
    ///
    /// Multiple hints can be registered for the same key. Hints can be added
    /// before or after the fetch starts - new hints will be used on retry.
    pub fn hint(&mut self, key: Key, peer: P) {
        self.hints.entry(key).or_default().insert(peer);
    }

    /// Clear all hints for a key.
    pub fn clear_hints(&mut self, key: &Key) {
        self.hints.remove(key);
    }

    /// Removes a specific peer from hints for a key.
    ///
    /// Returns `true` if the peer was in the hints (and thus removed).
    /// Removes the hints entry for the key if it becomes empty.
    fn remove_hint(&mut self, key: &Key, peer: &P) -> bool {
        let Some(hints) = self.hints.get_mut(key) else {
            return false;
        };
        let removed = hints.remove(peer);
        if hints.is_empty() {
            self.clear_hints(key);
        }
        removed
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

    /// Returns the total number of hints (sum of all hints across all keys).
    pub fn len_hints(&self) -> usize {
        self.hints.values().map(|v| v.len()).sum()
    }

    /// Returns true if the fetch is in progress.
    #[cfg(test)]
    pub fn contains(&self, key: &Key) -> bool {
        self.active.contains_right(key) || self.pending.contains(key)
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
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "mock error")
        }
    }

    impl std::error::Error for MockError {}

    // Mock sender that fails
    #[derive(Clone, Debug)]
    struct FailMockSender;

    impl Sender for FailMockSender {
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

    // Mock sender that succeeds
    #[derive(Clone, Debug)]
    struct SuccessMockSender;

    impl Sender for SuccessMockSender {
        type PublicKey = Ed25519PublicKey;
        type Error = MockError;

        async fn send(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
            _message: Bytes,
            _priority: bool,
        ) -> Result<Vec<Self::PublicKey>, Self::Error> {
            match recipients {
                Recipients::One(peer) => Ok(vec![peer]),
                _ => unimplemented!(),
            }
        }
    }

    fn create_test_fetcher<S: Sender<PublicKey = Ed25519PublicKey>>(
        context: Context,
    ) -> Fetcher<Context, Ed25519PublicKey, MockKey, S> {
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
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add some keys to pending and active states
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
            fetcher.add_retry(MockKey(3));

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
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add some keys to pending and active states
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
            fetcher.add_retry(MockKey(3));

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
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Initially empty
            assert_eq!(fetcher.len(), 0);
            assert_eq!(fetcher.len_pending(), 0);
            assert_eq!(fetcher.len_active(), 0);

            // Add pending keys
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
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
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

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
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add keys
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
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
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add keys
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
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
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add keys to both pending and active states
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
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

            // Cancel remaining pending key
            assert!(fetcher.cancel(&MockKey(2)));
            assert_eq!(fetcher.len_pending(), 0);

            // Ensure pending deadline is None
            assert!(fetcher.get_pending_deadline().is_none());
        });
    }

    #[test]
    fn test_contains_function() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Initially empty
            assert!(!fetcher.contains(&MockKey(1)));

            // Add to pending
            fetcher.add_retry(MockKey(1));
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
    fn test_add_retry_function() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add first key
            fetcher.add_retry(MockKey(1));
            assert_eq!(fetcher.len_pending(), 1);
            assert!(fetcher.contains(&MockKey(1)));

            // Add second key
            fetcher.add_retry(MockKey(2));
            assert_eq!(fetcher.len_pending(), 2);
            assert!(fetcher.contains(&MockKey(2)));

            // Verify deadline is set
            assert!(fetcher.get_pending_deadline().is_some());
        });
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn test_add_retry_duplicate_panics() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            fetcher.add_retry(MockKey(1));
            // This should panic
            fetcher.add_retry(MockKey(1));
        });
    }

    #[test]
    fn test_get_pending_deadline() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // No deadline when empty
            assert!(fetcher.get_pending_deadline().is_none());

            // Add key and check deadline exists
            fetcher.add_retry(MockKey(1));
            assert!(fetcher.get_pending_deadline().is_some());

            // Add another key - should still have a deadline
            fetcher.add_retry(MockKey(2));
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
            let fetcher = create_test_fetcher::<FailMockSender>(context);

            // No deadline when empty (requester has no timeouts)
            assert!(fetcher.get_active_deadline().is_none());
        });
    }

    #[test]
    fn test_pop_pending() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add keys
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
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
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            // This should panic
            fetcher.pop_pending();
        });
    }

    #[test]
    fn test_pop_active() {
        let runner = Runner::default();
        runner.start(|context| async {
            let fetcher = create_test_fetcher::<FailMockSender>(context);

            // No active requests, should return None when popping
            // (This tests the case where requester.next() returns None or the active map doesn't contain the key)
            assert!(fetcher.get_active_deadline().is_none());
        });
    }

    #[test]
    fn test_pop_by_id() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
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
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();

            // Test reconcile with peers
            fetcher.reconcile(&[peer1.clone(), peer2]);

            // Test block peer
            fetcher.block(peer1);

            // Initially no blocked peers (this depends on internal requester state)
            // The len_blocked function returns the count from the requester
        });
    }

    #[test]
    fn test_len_blocked() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

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
            let fetcher = create_test_fetcher::<FailMockSender>(context);

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
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Cancel from empty fetcher
            assert!(!fetcher.cancel(&MockKey(1)));

            // Add key, cancel it, then try to cancel again
            fetcher.add_retry(MockKey(1));
            assert!(fetcher.cancel(&MockKey(1)));
            assert!(!fetcher.cancel(&MockKey(1))); // Should return false
        });
    }

    #[test]
    fn test_retain_preserves_active_state() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

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
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add keys to both pending and active
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
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

    #[test]
    fn test_ready_vs_retry() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context.clone());

            // Add some keys to pending and active states
            fetcher.add_retry(MockKey(1));
            fetcher.add_ready(MockKey(2));

            // Verify initial state
            assert_eq!(fetcher.len(), 2);
            assert_eq!(fetcher.len_pending(), 2);
            assert_eq!(fetcher.len_active(), 0);

            // Get next
            let deadline = fetcher.get_pending_deadline().unwrap();
            assert_eq!(deadline, context.current());

            // Pop key
            let key = fetcher.pop_pending();
            assert_eq!(key, MockKey(2));

            // Get next
            let deadline = fetcher.get_pending_deadline().unwrap();
            assert_eq!(deadline, context.current() + Duration::from_millis(100));

            // Pop key
            let key = fetcher.pop_pending();
            assert_eq!(key, MockKey(1));
        });
    }

    #[test]
    fn test_waiter_after_empty() {
        let runner = Runner::default();
        runner.start(|context| async move {
            // Create fetcher
            let public_key =
                commonware_cryptography::ed25519::PrivateKey::from_seed(0).public_key();
            let requester_config = RequesterConfig {
                me: Some(public_key.clone()),
                rate_limit: Quota::per_second(std::num::NonZeroU32::new(1).unwrap()),
                initial: Duration::from_millis(100),
                timeout: Duration::from_secs(5),
            };
            let retry_timeout = Duration::from_millis(100);
            let other_public_key =
                commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let mut fetcher = Fetcher::new(context.clone(), requester_config, retry_timeout, false);
            fetcher.reconcile(&[public_key, other_public_key]);
            let mut sender = WrappedSender::new(FailMockSender {});

            // Add a key to pending
            fetcher.add_ready(MockKey(1));
            fetcher.fetch(&mut sender).await; // won't be delivered, so immediately re-added
            fetcher.fetch(&mut sender).await; // waiter activated

            // Check pending deadline
            assert_eq!(fetcher.len_pending(), 1);
            let pending_deadline = fetcher.get_pending_deadline().unwrap();
            assert_eq!(pending_deadline, context.current() + Duration::from_secs(1));

            // Cancel key
            assert!(fetcher.cancel(&MockKey(1)));
            assert!(fetcher.get_pending_deadline().is_none());

            // Advance time past previous deadline
            context.sleep(Duration::from_secs(10)).await;

            // Add a new key for retry (should be larger than original waiter wait)
            fetcher.add_retry(MockKey(2));
            let next_deadline = fetcher.get_pending_deadline().unwrap();
            assert_eq!(
                next_deadline,
                context.current() + Duration::from_millis(100)
            );
        });
    }

    #[test]
    fn test_hint() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();

            // Initially no hints
            assert!(fetcher.hints.is_empty());

            // Add hint for a key
            fetcher.hint(MockKey(1), peer1.clone());
            assert_eq!(fetcher.hints.len(), 1);
            assert!(fetcher.hints.get(&MockKey(1)).unwrap().contains(&peer1));

            // Add another hint for the same key
            fetcher.hint(MockKey(1), peer2.clone());
            assert_eq!(fetcher.hints.len(), 1);
            let hints = fetcher.hints.get(&MockKey(1)).unwrap();
            assert_eq!(hints.len(), 2);
            assert!(hints.contains(&peer1));
            assert!(hints.contains(&peer2));

            // Add hint for a different key
            fetcher.hint(MockKey(2), peer1.clone());
            assert_eq!(fetcher.hints.len(), 2);
            assert!(fetcher.hints.get(&MockKey(2)).unwrap().contains(&peer1));

            // Adding duplicate hint is idempotent
            fetcher.hint(MockKey(1), peer1);
            assert_eq!(fetcher.hints.get(&MockKey(1)).unwrap().len(), 2);
        });
    }

    #[test]
    fn test_hints_cleanup() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();

            // cancel() clears hints for key
            fetcher.hint(MockKey(1), peer1.clone());
            fetcher.hint(MockKey(2), peer1.clone());
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
            assert_eq!(fetcher.hints.len(), 2);

            assert!(fetcher.cancel(&MockKey(1)));
            assert!(!fetcher.hints.contains_key(&MockKey(1)));
            assert!(fetcher.hints.contains_key(&MockKey(2)));

            assert!(fetcher.cancel(&MockKey(2)));
            assert!(fetcher.hints.is_empty());

            // clear() clears all hints
            fetcher.hint(MockKey(1), peer1.clone());
            fetcher.hint(MockKey(1), peer2.clone());
            fetcher.hint(MockKey(2), peer1.clone());
            fetcher.hint(MockKey(3), peer2);
            assert_eq!(fetcher.hints.len(), 3);

            fetcher.clear();
            assert!(fetcher.hints.is_empty());

            // retain() filters hints
            fetcher.hint(MockKey(1), peer1.clone());
            fetcher.hint(MockKey(2), peer1.clone());
            fetcher.hint(MockKey(10), peer1.clone());
            fetcher.hint(MockKey(20), peer1);
            assert_eq!(fetcher.hints.len(), 4);

            fetcher.retain(|key| key.0 <= 5);
            assert_eq!(fetcher.hints.len(), 2);
            assert!(fetcher.hints.contains_key(&MockKey(1)));
            assert!(fetcher.hints.contains_key(&MockKey(2)));
            assert!(!fetcher.hints.contains_key(&MockKey(10)));
            assert!(!fetcher.hints.contains_key(&MockKey(20)));
        });
    }

    #[test]
    fn test_block_removes_from_hints() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();
            let peer3 = commonware_cryptography::ed25519::PrivateKey::from_seed(3).public_key();

            // Add hints for multiple keys with various peers
            fetcher.hint(MockKey(1), peer1.clone());
            fetcher.hint(MockKey(1), peer2.clone());
            fetcher.hint(MockKey(2), peer1.clone());
            fetcher.hint(MockKey(2), peer3.clone());
            fetcher.hint(MockKey(3), peer2.clone());

            // Verify initial state
            assert_eq!(fetcher.hints.get(&MockKey(1)).unwrap().len(), 2);
            assert_eq!(fetcher.hints.get(&MockKey(2)).unwrap().len(), 2);
            assert_eq!(fetcher.hints.get(&MockKey(3)).unwrap().len(), 1);

            // Block peer1
            fetcher.block(peer1.clone());

            // peer1 should be removed from all hint sets
            let key1_hints = fetcher.hints.get(&MockKey(1)).unwrap();
            assert_eq!(key1_hints.len(), 1);
            assert!(!key1_hints.contains(&peer1));
            assert!(key1_hints.contains(&peer2));

            let key2_hints = fetcher.hints.get(&MockKey(2)).unwrap();
            assert_eq!(key2_hints.len(), 1);
            assert!(!key2_hints.contains(&peer1));
            assert!(key2_hints.contains(&peer3));

            // MockKey(3) shouldn't be affected (peer1 wasn't a hint)
            let key3_hints = fetcher.hints.get(&MockKey(3)).unwrap();
            assert_eq!(key3_hints.len(), 1);
            assert!(key3_hints.contains(&peer2));

            // Block peer2 - should remove from MockKey(1) and MockKey(3)
            fetcher.block(peer2);

            // MockKey(1) now has no hints
            assert!(!fetcher.hints.contains_key(&MockKey(1)));

            // MockKey(2) still has peer3
            let key2_hints = fetcher.hints.get(&MockKey(2)).unwrap();
            assert_eq!(key2_hints.len(), 1);
            assert!(key2_hints.contains(&peer3));

            // MockKey(3) now has no hints
            assert!(!fetcher.hints.contains_key(&MockKey(3)));
        });
    }

    #[test]
    fn test_hint_behavior_on_send_failure() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context.clone());
            let public_key =
                commonware_cryptography::ed25519::PrivateKey::from_seed(0).public_key();
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();
            let peer3 = commonware_cryptography::ed25519::PrivateKey::from_seed(3).public_key();
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone(), peer3.clone()]);
            let mut sender = WrappedSender::new(FailMockSender {});

            // Hints filter peer selection
            fetcher.hint(MockKey(1), peer3.clone());
            assert!(fetcher.hints.get(&MockKey(1)).unwrap().contains(&peer3));
            fetcher.add_ready(MockKey(1));
            fetcher.fetch(&mut sender).await;
            // The hint should be removed as the send failed
            assert!(!fetcher.hints.contains_key(&MockKey(1)));
            assert!(fetcher.pending.contains(&MockKey(1)));
            fetcher.cancel(&MockKey(1));

            // Send failure removes only the tried peer from hints
            fetcher.hint(MockKey(2), peer1.clone());
            fetcher.hint(MockKey(2), peer2.clone());
            fetcher.add_ready(MockKey(2));
            assert_eq!(fetcher.hints.get(&MockKey(2)).unwrap().len(), 2);
            fetcher.fetch(&mut sender).await;
            assert_eq!(fetcher.hints.get(&MockKey(2)).unwrap().len(), 1);
            assert!(fetcher.pending.contains(&MockKey(2)));
        });
    }

    #[test]
    fn test_hint_removal_on_pop() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.clone());
            let public_key =
                commonware_cryptography::ed25519::PrivateKey::from_seed(0).public_key();
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone()]);
            let mut sender = WrappedSender::new(SuccessMockSender {});

            // Timeout removes hint
            fetcher.hint(MockKey(1), peer1.clone());
            fetcher.hint(MockKey(1), peer2.clone());
            fetcher.add_ready(MockKey(1));
            assert_eq!(fetcher.hints.get(&MockKey(1)).unwrap().len(), 2);
            fetcher.fetch(&mut sender).await;
            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(fetcher.pop_active(), Some(MockKey(1)));
            // Timeout should remove the timed-out peer from hints
            assert_eq!(fetcher.hints.get(&MockKey(1)).unwrap().len(), 1);
            fetcher.hints.clear();

            // Error response removes hint
            fetcher.hint(MockKey(2), peer1.clone());
            fetcher.add_ready(MockKey(2));
            fetcher.fetch(&mut sender).await;
            let id = *fetcher.active.iter().next().unwrap().0;
            assert_eq!(
                fetcher.pop_by_id(id, &peer1, false),
                Some((MockKey(2), true))
            );
            assert!(!fetcher.hints.contains_key(&MockKey(2)));

            // Data response preserves hints
            // (caller must clear hints after data validation)
            fetcher.hint(MockKey(3), peer1.clone());
            fetcher.add_ready(MockKey(3));
            fetcher.fetch(&mut sender).await;
            let id = *fetcher.active.iter().next().unwrap().0;
            assert_eq!(
                fetcher.pop_by_id(id, &peer1, true),
                Some((MockKey(3), true))
            );
            assert!(fetcher.hints.contains_key(&MockKey(3)));
        });
    }

    #[test]
    fn test_hints_cleared_when_no_hinted_peers_available() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.clone());
            let public_key =
                commonware_cryptography::ed25519::PrivateKey::from_seed(0).public_key();
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();
            let peer3 = commonware_cryptography::ed25519::PrivateKey::from_seed(3).public_key();

            // Add only peer1 and peer2 to the peer set (peer3 is NOT in the peer set)
            fetcher.reconcile(&[public_key, peer1, peer2]);

            // Hint peer3, which is NOT in the peer set (disconnected)
            fetcher.hint(MockKey(1), peer3);
            assert!(fetcher.hints.contains_key(&MockKey(1)));

            // Add key to pending
            fetcher.add_ready(MockKey(1));

            // Fetch should clear hints (peer3 not available) and fall back to any peer
            let mut sender = WrappedSender::new(SuccessMockSender {});
            fetcher.fetch(&mut sender).await;

            // Hints should be cleared since the hinted peer wasn't available
            assert!(!fetcher.hints.contains_key(&MockKey(1)));

            // Key should be in active state (fallback to available peer succeeded)
            assert_eq!(fetcher.len_active(), 1);
        });
    }
}
