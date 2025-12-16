use crate::p2p::wire;
use bimap::BiHashMap;
use commonware_cryptography::PublicKey;
use commonware_p2p::{
    utils::{
        codec::WrappedSender,
        requester::{Config, Error, Requester, ID},
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
/// # Targets
///
/// Peers can be registered as "targets" for specific keys, restricting fetches to only those
/// peers. Targets represent "the only peers who might eventually have the data". When fetching,
/// only target peers are tried. There is no fallback to other peers, if all targets are
/// unavailable, the fetch waits for them.
///
/// Targets persist through transient failures (timeout, "no data" response, send failure) since
/// the peer might be slow or might receive the data later. Targets are only removed when:
/// - A peer is blocked (sent invalid data)
/// - The fetch succeeds (all targets for that key are cleared)
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

    /// Per-key target peers restricting which peers are used to fetch each key.
    /// Only target peers are tried, waiting for them if rate-limited. There is no
    /// fallback to other peers. Targets persist through transient failures, they are
    /// only removed when blocked (invalid data) or cleared on successful fetch.
    targets: HashMap<Key, HashSet<P>>,

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
            targets: HashMap::new(),
            _s: PhantomData,
        }
    }

    /// Attempts to send a fetch request for a pending key.
    ///
    /// Iterates through pending keys in priority order until one succeeds or all
    /// participants are rate-limited. Targeted requests that fail due to rate limiting
    /// are skipped, allowing untargeted requests (or requests with different targets)
    /// to proceed. Once an untargeted request is rate-limited, iteration stops since
    /// all participants are busy.
    ///
    /// On send failure, the key is retried. Targets are not removed on send failure.
    pub async fn fetch(&mut self, sender: &mut WrappedSender<NetS, wire::Message<Key>>) {
        // Reset waiter
        self.waiter = None;

        // Try pending keys until one succeeds or all participants are rate-limited
        let mut min_wait: Option<Duration> = None;
        let mut selected = None;
        for (key, (_, retry)) in self.pending.iter() {
            // Try to find a peer for the key
            let (result, is_targeted) = match self.targets.get(key) {
                Some(targets) if targets.is_empty() => (Err(Error::NoEligibleParticipants), true),
                Some(targets) => (
                    self.requester
                        .request_filtered(*retry, |p| targets.contains(p)),
                    true,
                ),
                None => (self.requester.request(*retry), false),
            };

            // Handle the result
            match result {
                Ok((peer, id)) => {
                    selected = Some((key.clone(), peer, id));
                    break;
                }
                Err(Error::RateLimited(wait)) => {
                    min_wait = Some(min_wait.map_or(wait, |w| w.min(wait)));
                    if !is_targeted {
                        // If a request with no targets fails to find a peer, all participants are busy
                        break;
                    }
                    // If a request with targets fails to find a peer, other keys may still be fetchable
                }
                Err(Error::NoEligibleParticipants) => {
                    // If a request with no valid targets exists (blocked or targets no longer allowed), we
                    // should skip it (may eventually become fetchable if the peer set changes).
                }
            }
        }

        // Send request if we found a key to fetch
        if let Some((key, peer, id)) = selected {
            self.pending.remove(&key);
            return self.send_request(sender, key, peer, id).await;
        }

        // No keys could be fetched, set waiter to the next time
        self.waiter = Some(
            self.context
                .current()
                .saturating_add(min_wait.unwrap_or(Duration::MAX)),
        );
    }

    /// Sends a fetch request to a peer.
    async fn send_request(
        &mut self,
        sender: &mut WrappedSender<NetS, wire::Message<Key>>,
        key: Key,
        peer: <NetS as Sender>::PublicKey,
        id: ID,
    ) {
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
        self.targets.retain(|k, _| predicate(k));

        // Clear waiter since the key that caused it may have been removed
        self.waiter = None;
    }

    /// Cancels a fetch request.
    ///
    /// Returns `true` if the fetch was canceled.
    pub fn cancel(&mut self, key: &Key) -> bool {
        // Remove targets for this key
        self.clear_targets(key);

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
        self.targets.clear();
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
        let pending_deadline = self.pending.peek().map(|(_, (deadline, _))| *deadline);
        pending_deadline.max(self.waiter)
    }

    /// Returns the deadline for the next requester timeout.
    pub fn get_active_deadline(&self) -> Option<SystemTime> {
        self.requester.next().map(|(_, deadline)| deadline)
    }

    /// Removes and returns the key with the next requester timeout.
    ///
    /// Targets are not removed on timeout.
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
        self.active.remove_by_left(&id).map(|(_, key)| key)
    }

    /// Processes a response from a peer. Removes and returns the relevant key.
    ///
    /// Returns the key if the response was valid. Returns `None` if the response was
    /// invalid or unsolicited.
    ///
    /// Targets are not removed here, regardless of response type. Targets persist through
    /// "no data" responses (peer might get data later). On valid data response, caller
    /// should call `clear_targets()`. On invalid data, caller should block the peer which
    /// removes them from all target sets.
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
        self.active.remove_by_left(&id).map(|(_, key)| key)
    }

    /// Reconciles the list of peers that can be used to fetch data.
    pub fn reconcile(&mut self, keep: &[P]) {
        self.requester.reconcile(keep);

        // Clear waiter (may no longer apply)
        self.waiter = None;
    }

    /// Blocks a peer from being used to fetch data.
    ///
    /// Also removes the peer from all target sets.
    pub fn block(&mut self, peer: P) {
        // Remove peer from all target sets (keeping empty entries)
        for targets in self.targets.values_mut() {
            targets.remove(&peer);
        }

        self.requester.block(peer);
    }

    /// Add target peers for fetching a key.
    ///
    /// Targets are added to any existing targets for this key.
    ///
    /// Clears the waiter to allow immediate retry if the fetch was blocked waiting for targets.
    pub fn add_targets(&mut self, key: Key, peers: impl IntoIterator<Item = P>) {
        self.targets.entry(key).or_default().extend(peers);

        // Clear waiter to allow retry with new targets
        self.waiter = None;
    }

    /// Clear targeting for a key.
    ///
    /// If there is an ongoing fetch for this key, it will try any available peer instead
    /// of being restricted to targets. Also used to clean up targets after a successful
    /// or cancelled fetch.
    ///
    /// Clears the waiter to allow immediate retry with any available peer.
    pub fn clear_targets(&mut self, key: &Key) {
        self.targets.remove(key);

        // Clear waiter to allow retry without targets
        self.waiter = None;
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
    use commonware_cryptography::{ed25519::PublicKey as Ed25519PublicKey, Signer};
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
            // Pending: MockKey(1), MockKey(2), MockKey(3) all remain (1, 2, 3 <= 10)
            // Active: MockKey(10) remains, MockKey(20) and MockKey(30) removed (20, 30 > 10)
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

            // Get next (should be the ready key with current time deadline)
            let deadline = fetcher.get_pending_deadline().unwrap();
            assert_eq!(deadline, context.current());

            // Pop key (ready key should come first)
            let (key, _) = fetcher.pending.pop().unwrap();
            assert_eq!(key, MockKey(2));

            // Get next (should be the retry key with delayed deadline)
            let deadline = fetcher.get_pending_deadline().unwrap();
            assert_eq!(deadline, context.current() + Duration::from_millis(100));

            // Pop key
            let (key, _) = fetcher.pending.pop().unwrap();
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
    fn test_waiter_cleared_on_target_modification() {
        let runner = Runner::default();
        runner.start(|context| async move {
            // Create fetcher with participants
            let public_key =
                commonware_cryptography::ed25519::PrivateKey::from_seed(0).public_key();
            let requester_config = RequesterConfig {
                me: Some(public_key.clone()),
                rate_limit: Quota::per_second(std::num::NonZeroU32::new(10).unwrap()),
                initial: Duration::from_millis(100),
                timeout: Duration::from_secs(5),
            };
            let retry_timeout = Duration::from_millis(100);
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let blocked_peer =
                commonware_cryptography::ed25519::PrivateKey::from_seed(99).public_key();
            let mut fetcher = Fetcher::new(context.clone(), requester_config, retry_timeout, false);
            fetcher.reconcile(&[public_key, peer1.clone()]);
            let mut sender = WrappedSender::new(FailMockSender {});

            // Block the peer we'll use as target, so fetch has no eligible participants
            fetcher.block(blocked_peer.clone());

            // Add key with targets pointing only to blocked peer
            fetcher.add_ready(MockKey(1));
            fetcher.add_targets(MockKey(1), [blocked_peer.clone()]);
            fetcher.fetch(&mut sender).await;

            // Waiter should be set to far future (no eligible participants)
            assert!(fetcher.waiter.is_some());
            let far_future = fetcher.waiter.unwrap();
            assert!(far_future > context.current() + Duration::from_secs(1000));

            // Add targets should clear the waiter
            fetcher.add_targets(MockKey(1), [peer1.clone()]);
            assert!(fetcher.waiter.is_none());

            // Pending deadline should now be reasonable
            let deadline = fetcher.get_pending_deadline().unwrap();
            assert!(deadline <= context.current() + retry_timeout);

            // Set waiter again by targeting blocked peer
            fetcher.clear_targets(&MockKey(1));
            fetcher.add_targets(MockKey(1), [blocked_peer.clone()]);
            fetcher.fetch(&mut sender).await;
            assert!(fetcher.waiter.is_some());

            // clear_targets should clear the waiter
            fetcher.clear_targets(&MockKey(1));
            assert!(fetcher.waiter.is_none());
        });
    }

    #[test]
    fn test_add_targets() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();
            let peer3 = commonware_cryptography::ed25519::PrivateKey::from_seed(3).public_key();

            // Initially no targets
            assert!(fetcher.targets.is_empty());

            // Add targets for a key
            fetcher.add_targets(MockKey(1), [peer1.clone()]);
            assert_eq!(fetcher.targets.len(), 1);
            assert!(fetcher.targets.get(&MockKey(1)).unwrap().contains(&peer1));

            // Add more targets for the same key (accumulates)
            fetcher.add_targets(MockKey(1), [peer2.clone()]);
            assert_eq!(fetcher.targets.len(), 1);
            let targets = fetcher.targets.get(&MockKey(1)).unwrap();
            assert_eq!(targets.len(), 2);
            assert!(targets.contains(&peer1));
            assert!(targets.contains(&peer2));

            // Add target for a different key
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            assert_eq!(fetcher.targets.len(), 2);
            assert!(fetcher.targets.get(&MockKey(2)).unwrap().contains(&peer1));

            // Adding duplicate target is idempotent
            fetcher.add_targets(MockKey(1), [peer1.clone()]);
            assert_eq!(fetcher.targets.get(&MockKey(1)).unwrap().len(), 2);

            // Add more to reach three targets
            fetcher.add_targets(MockKey(1), [peer3.clone()]);
            assert_eq!(fetcher.targets.get(&MockKey(1)).unwrap().len(), 3);
            assert!(fetcher.targets.get(&MockKey(1)).unwrap().contains(&peer3));

            // clear_targets() removes all targets for a key
            fetcher.clear_targets(&MockKey(1));
            assert!(!fetcher.targets.contains_key(&MockKey(1)));

            // Add targets on non-existent key creates new entry
            fetcher.add_targets(MockKey(3), [peer1.clone()]);
            assert!(fetcher.targets.get(&MockKey(3)).unwrap().contains(&peer1));
        });
    }

    #[test]
    fn test_targets_cleanup() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();

            // cancel() clears targets for key
            fetcher.add_targets(MockKey(1), [peer1.clone()]);
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
            assert_eq!(fetcher.targets.len(), 2);

            assert!(fetcher.cancel(&MockKey(1)));
            assert!(!fetcher.targets.contains_key(&MockKey(1)));
            assert!(fetcher.targets.contains_key(&MockKey(2)));

            assert!(fetcher.cancel(&MockKey(2)));
            assert!(fetcher.targets.is_empty());

            // clear() clears all targets
            fetcher.add_targets(MockKey(1), [peer1.clone(), peer2.clone()]);
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_targets(MockKey(3), [peer2]);
            assert_eq!(fetcher.targets.len(), 3);

            fetcher.clear();
            assert!(fetcher.targets.is_empty());

            // retain() filters targets
            fetcher.add_targets(MockKey(1), [peer1.clone()]);
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_targets(MockKey(10), [peer1.clone()]);
            fetcher.add_targets(MockKey(20), [peer1]);
            assert_eq!(fetcher.targets.len(), 4);

            fetcher.retain(|key| key.0 <= 5);
            assert_eq!(fetcher.targets.len(), 2);
            assert!(fetcher.targets.contains_key(&MockKey(1)));
            assert!(fetcher.targets.contains_key(&MockKey(2)));
            assert!(!fetcher.targets.contains_key(&MockKey(10)));
            assert!(!fetcher.targets.contains_key(&MockKey(20)));
        });
    }

    #[test]
    fn test_block_removes_from_targets() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();
            let peer3 = commonware_cryptography::ed25519::PrivateKey::from_seed(3).public_key();

            // Add targets for multiple keys with various peers
            fetcher.add_targets(MockKey(1), [peer1.clone(), peer2.clone()]);
            fetcher.add_targets(MockKey(2), [peer1.clone(), peer3.clone()]);
            fetcher.add_targets(MockKey(3), [peer2.clone()]);

            // Verify initial state
            assert_eq!(fetcher.targets.get(&MockKey(1)).unwrap().len(), 2);
            assert_eq!(fetcher.targets.get(&MockKey(2)).unwrap().len(), 2);
            assert_eq!(fetcher.targets.get(&MockKey(3)).unwrap().len(), 1);

            // Block peer1
            fetcher.block(peer1.clone());

            // peer1 should be removed from all target sets
            let key1_targets = fetcher.targets.get(&MockKey(1)).unwrap();
            assert_eq!(key1_targets.len(), 1);
            assert!(!key1_targets.contains(&peer1));
            assert!(key1_targets.contains(&peer2));

            let key2_targets = fetcher.targets.get(&MockKey(2)).unwrap();
            assert_eq!(key2_targets.len(), 1);
            assert!(!key2_targets.contains(&peer1));
            assert!(key2_targets.contains(&peer3));

            // MockKey(3) shouldn't be affected (peer1 wasn't a target)
            let key3_targets = fetcher.targets.get(&MockKey(3)).unwrap();
            assert_eq!(key3_targets.len(), 1);
            assert!(key3_targets.contains(&peer2));

            // Block peer2 - should remove from MockKey(1) and MockKey(3)
            fetcher.block(peer2);

            // MockKey(1) now has empty targets (entry kept to prevent fallback)
            assert!(fetcher.targets.contains_key(&MockKey(1)));
            assert!(fetcher.targets.get(&MockKey(1)).unwrap().is_empty());

            // MockKey(2) still has peer3
            let key2_targets = fetcher.targets.get(&MockKey(2)).unwrap();
            assert_eq!(key2_targets.len(), 1);
            assert!(key2_targets.contains(&peer3));

            // MockKey(3) now has empty targets (entry kept to prevent fallback)
            assert!(fetcher.targets.contains_key(&MockKey(3)));
            assert!(fetcher.targets.get(&MockKey(3)).unwrap().is_empty());
        });
    }

    #[test]
    fn test_target_behavior_on_send_failure() {
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

            // Add targets and attempt fetch
            fetcher.add_targets(MockKey(2), [peer1.clone(), peer2.clone()]);
            fetcher.add_ready(MockKey(2));
            assert_eq!(fetcher.targets.get(&MockKey(2)).unwrap().len(), 2);
            fetcher.fetch(&mut sender).await;
            // Both targets should still be present (not removed on send failure)
            assert_eq!(fetcher.targets.get(&MockKey(2)).unwrap().len(), 2);
            assert!(fetcher.pending.contains(&MockKey(2)));
        });
    }

    #[test]
    fn test_target_retention_on_pop() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.clone());
            let public_key =
                commonware_cryptography::ed25519::PrivateKey::from_seed(0).public_key();
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone()]);
            let mut sender = WrappedSender::new(SuccessMockSender {});

            // Timeout does not remove target
            fetcher.add_targets(MockKey(1), [peer1.clone(), peer2.clone()]);
            fetcher.add_ready(MockKey(1));
            assert_eq!(fetcher.targets.get(&MockKey(1)).unwrap().len(), 2);
            fetcher.fetch(&mut sender).await;
            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(fetcher.pop_active(), Some(MockKey(1)));
            // Both targets should still be present after timeout
            assert_eq!(fetcher.targets.get(&MockKey(1)).unwrap().len(), 2);
            fetcher.targets.clear();

            // Error response ("no data") does not remove target
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_ready(MockKey(2));
            fetcher.fetch(&mut sender).await;
            let id = *fetcher.active.iter().next().unwrap().0;
            assert_eq!(fetcher.pop_by_id(id, &peer1, false), Some(MockKey(2)));
            // Target should still be present after "no data" response
            assert!(fetcher.targets.get(&MockKey(2)).unwrap().contains(&peer1));
            fetcher.targets.clear();

            // Data response also preserves targets
            // (caller must clear targets after data validation)
            fetcher.add_targets(MockKey(3), [peer1.clone()]);
            fetcher.add_ready(MockKey(3));
            fetcher.fetch(&mut sender).await;
            let id = *fetcher.active.iter().next().unwrap().0;
            assert_eq!(fetcher.pop_by_id(id, &peer1, true), Some(MockKey(3)));
            assert!(fetcher.targets.get(&MockKey(3)).unwrap().contains(&peer1));
        });
    }

    #[test]
    fn test_no_fallback_when_targets_unavailable() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.clone());
            let public_key =
                commonware_cryptography::ed25519::PrivateKey::from_seed(0).public_key();
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();
            let peer3 = commonware_cryptography::ed25519::PrivateKey::from_seed(3).public_key();

            // Add only peer1 and peer2 to the peer set (peer3 is not in the peer set)
            fetcher.reconcile(&[public_key, peer1, peer2]);

            // Target peer3, which is not in the peer set (disconnected)
            fetcher.add_targets(MockKey(1), [peer3]);
            assert!(fetcher.targets.contains_key(&MockKey(1)));

            // Add key to pending
            fetcher.add_ready(MockKey(1));

            // Fetch should not fallback to any peer - it should wait indefinitely
            let mut sender = WrappedSender::new(SuccessMockSender {});
            fetcher.fetch(&mut sender).await;

            // Targets should still exist (no fallback cleared them)
            assert!(fetcher.targets.contains_key(&MockKey(1)));

            // Key should still be in pending state (no fallback to available peers)
            assert_eq!(fetcher.len_pending(), 1);
            assert_eq!(fetcher.len_active(), 0);

            // Waiter should be set to far future (waiting for target peer)
            assert!(fetcher.waiter.is_some());
        });
    }

    #[test]
    fn test_clear_targets() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();

            // Add targets
            fetcher.add_targets(MockKey(1), [peer1.clone(), peer2]);
            fetcher.add_targets(MockKey(2), [peer1]);
            assert_eq!(fetcher.targets.len(), 2);

            // clear_targets() removes the targets entry entirely
            fetcher.clear_targets(&MockKey(1));
            assert!(!fetcher.targets.contains_key(&MockKey(1)));
            assert!(fetcher.targets.contains_key(&MockKey(2)));

            // clear_targets() on non-existent key is a no-op
            fetcher.clear_targets(&MockKey(99));
            assert_eq!(fetcher.targets.len(), 1);

            // clear_targets() remaining key
            fetcher.clear_targets(&MockKey(2));
            assert!(fetcher.targets.is_empty());
        });
    }

    #[test]
    fn test_skips_keys_with_rate_limited_targets() {
        let runner = Runner::default();
        runner.start(|context| async move {
            // Create fetcher with rate limit of 1 per second
            let public_key =
                commonware_cryptography::ed25519::PrivateKey::from_seed(0).public_key();
            let requester_config = RequesterConfig {
                me: Some(public_key.clone()),
                rate_limit: Quota::per_second(std::num::NonZeroU32::new(1).unwrap()),
                initial: Duration::from_millis(100),
                timeout: Duration::from_secs(5),
            };
            let retry_timeout = Duration::from_millis(100);
            let peer1 = commonware_cryptography::ed25519::PrivateKey::from_seed(1).public_key();
            let peer2 = commonware_cryptography::ed25519::PrivateKey::from_seed(2).public_key();
            let mut fetcher = Fetcher::new(context.clone(), requester_config, retry_timeout, false);
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone()]);
            let mut sender = WrappedSender::new(SuccessMockSender {});

            // Add three keys with different targets:
            // - MockKey(1) targeted to peer1
            // - MockKey(2) targeted to peer1 (same peer, will be rate-limited after first)
            // - MockKey(3) targeted to peer2
            fetcher.add_targets(MockKey(1), [peer1.clone()]);
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_targets(MockKey(3), [peer2.clone()]);
            fetcher.add_ready(MockKey(1));
            context.sleep(Duration::from_millis(1)).await;
            fetcher.add_ready(MockKey(2));
            context.sleep(Duration::from_millis(1)).await;
            fetcher.add_ready(MockKey(3));

            // First fetch: should pick MockKey(1) targeting peer1
            fetcher.fetch(&mut sender).await;
            assert_eq!(fetcher.len_active(), 1);
            assert_eq!(fetcher.len_pending(), 2);
            assert!(!fetcher.pending.contains(&MockKey(1))); // MockKey(1) was fetched

            // Second fetch: MockKey(2) is blocked (peer1 rate-limited), should skip to MockKey(3)
            fetcher.fetch(&mut sender).await;
            assert_eq!(fetcher.len_active(), 2);
            assert_eq!(fetcher.len_pending(), 1);
            assert!(fetcher.pending.contains(&MockKey(2))); // MockKey(2) is still pending
            assert!(!fetcher.pending.contains(&MockKey(3))); // MockKey(3) was fetched

            // Third fetch: only MockKey(2) remains, but peer1 is still rate-limited
            fetcher.fetch(&mut sender).await;
            assert_eq!(fetcher.len_active(), 2); // No change
            assert_eq!(fetcher.len_pending(), 1); // MockKey(2) still pending
            assert!(fetcher.waiter.is_some()); // Waiter set

            // Wait for rate limit to reset
            context.sleep(Duration::from_secs(1)).await;

            // Now MockKey(2) can be fetched
            fetcher.fetch(&mut sender).await;
            assert_eq!(fetcher.len_active(), 3);
            assert_eq!(fetcher.len_pending(), 0);
        });
    }
}
