use crate::p2p::wire;
use commonware_cryptography::PublicKey;
use commonware_p2p::{utils::codec::WrappedSender, Recipients, Sender};
use commonware_runtime::{
    telemetry::metrics::{
        histogram::Buckets,
        status::{self, CounterExt, GaugeExt, Status},
    },
    Clock, Metrics,
};
use commonware_utils::{PrioritySet, Span, SystemTimeExt};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{family::Family, gauge::Gauge, histogram::Histogram},
};
use rand::{seq::SliceRandom, Rng};
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    time::{Duration, SystemTime},
};
use tracing::debug;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct Peer {
    peer: String,
}

/// Unique identifier for a request.
///
/// Once u64 requests have been made, the ID wraps around (resetting to zero).
/// As long as there are less than u64 requests outstanding, this should not be
/// an issue.
pub type ID = u64;

/// Tracks an active request that has been sent to a peer.
struct ActiveRequest<P, Key> {
    key: Key,
    peer: P,
    start: SystemTime,
}

/// Configuration for the fetcher.
pub struct Config<P: PublicKey> {
    /// Local identity of the participant (if any).
    pub me: Option<P>,

    /// Initial expected performance for new participants.
    pub initial: Duration,

    /// Timeout for requests.
    pub timeout: Duration,

    /// How long fetches remain in the pending queue before being retried.
    pub retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages.
    pub priority_requests: bool,
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
pub struct Fetcher<E, P, Key, NetS>
where
    E: Clock + Rng + Metrics,
    P: PublicKey,
    Key: Span,
    NetS: Sender<PublicKey = P>,
{
    context: E,

    // Peer management
    /// Local identity (to exclude from requests)
    me: Option<P>,
    /// Participants to exclude from requests (blocked peers)
    excluded: HashSet<P>,
    /// Participants and their performance (lower is better, in milliseconds)
    participants: PrioritySet<P, u128>,

    // Request tracking
    /// Next ID to use for a request
    request_id: ID,
    /// Active requests ordered by deadline (ID -> deadline)
    active: PrioritySet<ID, SystemTime>,
    /// Request data for active requests (ID -> request details)
    requests: HashMap<ID, ActiveRequest<P, Key>>,
    /// Reverse lookup from key to request ID
    key_to_id: HashMap<Key, ID>,

    // Config
    /// Initial expected performance for new participants
    initial: Duration,
    /// Timeout for requests
    timeout: Duration,

    /// Manages pending requests. When a request is registered (for both the first time and after
    /// a retry), it is added to this set.
    ///
    /// The value is a tuple of the next time to try the request and a boolean indicating if the request
    /// is a retry (in which case the request should be made to a random peer).
    pending: PrioritySet<Key, (SystemTime, bool)>,

    /// If no peers are ready to handle a request (all filtered out or send failed), the waiter is set
    /// to the next time to try the request.
    waiter: Option<SystemTime>,

    /// How long fetches remain in the pending queue before being retried
    retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages
    priority_requests: bool,

    /// Per-key target peers restricting which peers are used to fetch each key.
    /// Only target peers are tried, waiting for them if unavailable. There is no
    /// fallback to other peers. Targets persist through transient failures, they are
    /// only removed when blocked (invalid data) or cleared on successful fetch.
    targets: HashMap<Key, HashSet<P>>,

    /// Per-peer performance metric (exponential moving average of response time in ms)
    performance: Family<Peer, Gauge>,

    /// Status of request creation attempts (Success when eligible peers exist, Dropped otherwise)
    requests_created: status::Counter,

    /// Status of individual network requests sent to peers
    requests_sent: status::Counter,

    /// Histogram of successful response durations
    resolves: Histogram,

    /// Phantom data for networking types
    _s: PhantomData<NetS>,
}

impl<E, P, Key, NetS> Fetcher<E, P, Key, NetS>
where
    E: Clock + Rng + Metrics,
    P: PublicKey,
    Key: Span,
    NetS: Sender<PublicKey = P>,
{
    /// Creates a new fetcher.
    pub fn new(context: E, config: Config<P>) -> Self {
        let performance = Family::<Peer, Gauge>::default();
        context.register(
            "peer_performance",
            "Per-peer performance (exponential moving average of response time in ms)",
            performance.clone(),
        );
        let requests_created = status::Counter::default();
        context.register(
            "requests_created",
            "Status of request creation attempts",
            requests_created.clone(),
        );
        let requests_sent = status::Counter::default();
        context.register(
            "requests_sent",
            "Status of individual network requests sent to peers",
            requests_sent.clone(),
        );
        let resolves = Histogram::new(Buckets::NETWORK);
        context.register(
            "resolves",
            "Number and duration of requests that were resolved",
            resolves.clone(),
        );
        Self {
            context,
            me: config.me,
            excluded: HashSet::new(),
            participants: PrioritySet::new(),
            request_id: 0,
            active: PrioritySet::new(),
            requests: HashMap::new(),
            key_to_id: HashMap::new(),
            initial: config.initial,
            timeout: config.timeout,
            pending: PrioritySet::new(),
            waiter: None,
            retry_timeout: config.retry_timeout,
            priority_requests: config.priority_requests,
            targets: HashMap::new(),
            performance,
            requests_created,
            requests_sent,
            resolves,
            _s: PhantomData,
        }
    }

    /// Generate the next request ID.
    const fn next_id(&mut self) -> ID {
        let id = self.request_id;
        self.request_id = self.request_id.wrapping_add(1);
        id
    }

    /// Calculate a participant's new priority using exponential moving average.
    fn update_performance(&mut self, participant: &P, elapsed: Duration) {
        let Some(past) = self.participants.get(participant) else {
            return;
        };
        let next = past.saturating_add(elapsed.as_millis()) / 2;
        self.participants.put(participant.clone(), next);
        let label = Peer {
            peer: participant.to_string(),
        };
        let _ = self.performance.get_or_create(&label).try_set(next);
    }

    /// Get eligible peers for a key in priority order.
    ///
    /// If `shuffle` is true, the peers are shuffled (used for retries to try different peers).
    fn get_eligible_peers(&mut self, key: &Key, shuffle: bool) -> Vec<P> {
        let targets = self.targets.get(key);

        // Prepare participant iterator
        let participant_iter = self.participants.iter();

        // Collect eligible peers
        let mut eligible: Vec<P> = participant_iter
            .filter(|(p, _)| self.me.as_ref() != Some(p)) // not self
            .filter(|(p, _)| !self.excluded.contains(p)) // not blocked
            .filter(|(p, _)| targets.is_none_or(|t| t.contains(p))) // matches target if any
            .map(|(p, _)| p.clone())
            .collect();

        // Shuffle if requested
        if shuffle {
            eligible.shuffle(&mut self.context);
        }
        eligible
    }

    /// Attempts to send a fetch request for a pending key.
    ///
    /// Iterates through pending keys until a send succeeds. For each key, tries
    /// eligible peers in priority order. On success, the key moves from pending
    /// to active. On failure, the key remains pending for retry.
    ///
    /// Sets `self.waiter` to control when the next fetch attempt should occur:
    /// - Rate limit expiry time if any peer was rate-limited
    /// - `retry_timeout` if peers exist but all sends failed
    /// - `Duration::MAX` if no eligible peers (wait for external changes)
    pub async fn fetch(&mut self, sender: &mut WrappedSender<NetS, wire::Message<Key>>) {
        self.waiter = None;

        // Collect keys to try (need to clone since we mutate self during iteration)
        let pending_keys: Vec<(Key, bool)> = self
            .pending
            .iter()
            .map(|(k, (_, retry))| (k.clone(), *retry))
            .collect();

        // Try each pending key until one succeeds
        let mut earliest_rate_limit: Option<SystemTime> = None;
        let mut found_eligible_peers = false;
        for (key, retry) in pending_keys {
            // Skip keys with no eligible peers
            let peers = self.get_eligible_peers(&key, retry);
            if peers.is_empty() {
                self.requests_created.inc(Status::Dropped);
                continue;
            }

            // Mark that an eligible peer was found
            self.requests_created.inc(Status::Success);
            found_eligible_peers = true;

            // Try each peer until one succeeds
            for peer in peers {
                // Check rate limit (consumes a token if not rate-limited)
                let checked = match sender.check(Recipients::One(peer.clone())).await {
                    Ok(checked) => checked,
                    Err(not_until) => {
                        // Peer is rate-limited, track earliest retry time
                        earliest_rate_limit =
                            Some(earliest_rate_limit.map_or(not_until, |t| t.min(not_until)));
                        continue;
                    }
                };

                // Attempt send
                let id = self.next_id();
                let message = wire::Message {
                    id,
                    payload: wire::Payload::Request(key.clone()),
                };
                match checked.send(message, self.priority_requests).await {
                    Ok(sent) if !sent.is_empty() => {
                        // Success - move from pending to active
                        self.requests_sent.inc(Status::Success);
                        self.pending.remove(&key);
                        let now = self.context.current();
                        let deadline = now.checked_add(self.timeout).expect("time overflowed");
                        self.active.put(id, deadline);
                        self.requests.insert(
                            id,
                            ActiveRequest {
                                key: key.clone(),
                                peer,
                                start: now,
                            },
                        );
                        self.key_to_id.insert(key, id);
                        return;
                    }
                    Ok(_) => {
                        // Peer dropped message, try next peer
                        self.requests_sent.inc(Status::Dropped);
                        debug!(?peer, "send returned empty");
                        self.update_performance(&peer, self.timeout);
                    }
                    Err(err) => {
                        // Send failed, try next peer
                        self.requests_sent.inc(Status::Failure);
                        debug!(?err, ?peer, "send failed");
                        self.update_performance(&peer, self.timeout);
                    }
                }
            }
        }

        // Set waiter for next fetch attempt
        self.waiter = Some(if let Some(rate_limit_time) = earliest_rate_limit {
            // Use rate limit expiry time
            rate_limit_time
        } else if found_eligible_peers {
            // Peers exist but all sends failed - use retry timeout
            self.context.current() + self.retry_timeout
        } else {
            // No eligible peers - wait for external changes
            self.context.current().saturating_add(Duration::MAX)
        });
    }

    /// Retains only the fetches with keys greater than the given key.
    pub fn retain(&mut self, predicate: impl Fn(&Key) -> bool) {
        // Collect IDs to remove based on key predicate
        let ids_to_remove: Vec<ID> = self
            .requests
            .iter()
            .filter(|(_, req)| !predicate(&req.key))
            .map(|(id, _)| *id)
            .collect();
        for id in ids_to_remove {
            self.active.remove(&id);
            self.requests.remove(&id);
        }
        self.key_to_id.retain(|k, _| predicate(k));
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

        // Check the active fetches
        if let Some(id) = self.key_to_id.remove(key) {
            self.active.remove(&id);
            self.requests.remove(&id);
            return true;
        }

        false
    }

    /// Cancel all fetches.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.active.clear();
        self.requests.clear();
        self.key_to_id.clear();
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

    /// Returns the deadline for the next active request timeout.
    pub fn get_active_deadline(&self) -> Option<SystemTime> {
        self.active.peek().map(|(_, deadline)| *deadline)
    }

    /// Removes and returns the key with the next request timeout.
    ///
    /// Targets are not removed on timeout.
    pub fn pop_active(&mut self) -> Option<Key> {
        // Pop the next deadline
        let (id, _) = self.active.pop()?;

        // Remove the request and update performance with timeout penalty
        let req = self.requests.remove(&id)?;
        self.key_to_id.remove(&req.key);
        self.update_performance(&req.peer, self.timeout);

        Some(req.key)
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
        // Confirm ID exists and is for the peer
        let req = self.requests.get(&id)?;
        if &req.peer != peer {
            return None;
        }

        // Remove the request
        let req = self.requests.remove(&id)?;
        self.active.remove(&id);
        self.key_to_id.remove(&req.key);

        // Update the peer's performance
        if has_response {
            // Compute elapsed time and update performance
            let elapsed = self
                .context
                .current()
                .duration_since(req.start)
                .unwrap_or_default();
            self.update_performance(&req.peer, elapsed);
            self.resolves.observe(elapsed.as_secs_f64());
        } else {
            // Treat lack of response as a timeout
            self.update_performance(&req.peer, self.timeout);
        }

        Some(req.key)
    }

    /// Reconciles the list of peers that can be used to fetch data.
    pub fn reconcile(&mut self, keep: &[P]) {
        self.participants.reconcile(keep, self.initial.as_millis());

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

        self.excluded.insert(peer);
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

    /// Returns whether a key has targets set.
    pub fn has_targets(&self, key: &Key) -> bool {
        self.targets.contains_key(key)
    }

    /// Returns the number of fetches.
    pub fn len(&self) -> usize {
        self.pending.len() + self.requests.len()
    }

    /// Returns the number of pending fetches.
    pub fn len_pending(&self) -> usize {
        self.pending.len()
    }

    /// Returns the number of active fetches.
    pub fn len_active(&self) -> usize {
        self.requests.len()
    }

    /// Returns the number of blocked peers.
    pub fn len_blocked(&self) -> usize {
        self.excluded.len()
    }

    /// Returns true if the fetch is in progress.
    #[cfg(test)]
    pub fn contains(&self, key: &Key) -> bool {
        self.key_to_id.contains_key(key) || self.pending.contains(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::mocks::Key as MockKey;
    use bytes::Bytes;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_p2p::{LimitedSender, Recipients, UnlimitedSender};
    use commonware_runtime::{
        deterministic::{self, Context, Runner},
        KeyedRateLimiter, Quota, Runner as _, RwLock,
    };
    use commonware_utils::NZU32;
    use std::{fmt, sync::Arc, time::Duration};

    // Mock error type for testing
    #[derive(Debug)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "mock error")
        }
    }

    impl std::error::Error for MockError {}

    #[derive(Debug)]
    struct CheckedSender<'a, S: UnlimitedSender> {
        sender: &'a mut S,
        recipients: Recipients<S::PublicKey>,
    }

    impl<'a, S: UnlimitedSender> commonware_p2p::CheckedSender for CheckedSender<'a, S> {
        type PublicKey = S::PublicKey;
        type Error = S::Error;

        async fn send(
            self,
            message: Bytes,
            priority: bool,
        ) -> Result<Vec<Self::PublicKey>, Self::Error> {
            self.sender.send(self.recipients, message, priority).await
        }
    }

    #[derive(Default, Clone, Debug)]
    struct FailMockSenderInner;

    impl UnlimitedSender for FailMockSenderInner {
        type PublicKey = PublicKey;
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

    // Mock sender that fails
    #[derive(Default, Clone, Debug)]
    struct FailMockSender(FailMockSenderInner);

    impl LimitedSender for FailMockSender {
        type PublicKey = PublicKey;
        type Checked<'a> = CheckedSender<'a, FailMockSenderInner>;

        async fn check<'a>(
            &'a mut self,
            recipients: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'a>, SystemTime> {
            Ok(CheckedSender {
                sender: &mut self.0,
                recipients,
            })
        }
    }

    // Mock sender that succeeds
    #[derive(Default, Clone, Debug)]
    struct SuccessMockSenderInner;

    impl UnlimitedSender for SuccessMockSenderInner {
        type PublicKey = PublicKey;
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

    // Mock sender that succeeds
    #[derive(Default, Clone, Debug)]
    struct SuccessMockSender(SuccessMockSenderInner);

    impl LimitedSender for SuccessMockSender {
        type PublicKey = PublicKey;
        type Checked<'a> = CheckedSender<'a, SuccessMockSenderInner>;

        async fn check<'a>(
            &'a mut self,
            recipients: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'a>, SystemTime> {
            Ok(CheckedSender {
                sender: &mut self.0,
                recipients,
            })
        }
    }

    // Mock sender that rate-limits per peer
    #[derive(Clone)]
    struct LimitedMockSender<E: Clock> {
        inner: SuccessMockSenderInner,
        rate_limiter: Arc<RwLock<KeyedRateLimiter<PublicKey, E>>>,
    }

    impl<E: Clock> LimitedMockSender<E> {
        fn new(quota: Quota, clock: E) -> Self {
            Self {
                inner: SuccessMockSenderInner,
                rate_limiter: Arc::new(RwLock::new(KeyedRateLimiter::hashmap_with_clock(
                    quota, clock,
                ))),
            }
        }
    }

    impl<E: Clock> LimitedSender for LimitedMockSender<E> {
        type PublicKey = PublicKey;
        type Checked<'a> = CheckedSender<'a, SuccessMockSenderInner>;

        async fn check<'a>(
            &'a mut self,
            recipients: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'a>, SystemTime> {
            let peer = match &recipients {
                Recipients::One(p) => p,
                _ => unimplemented!(),
            };

            {
                let rate_limiter = self.rate_limiter.write().await;
                if let Err(not_until) = rate_limiter.check_key(peer) {
                    return Err(not_until.earliest_possible());
                }
            }

            Ok(CheckedSender {
                sender: &mut self.inner,
                recipients,
            })
        }
    }

    fn create_test_fetcher<S: Sender<PublicKey = PublicKey>>(
        context: Context,
    ) -> Fetcher<Context, PublicKey, MockKey, S> {
        let public_key = PrivateKey::from_seed(0).public_key();
        let config = Config {
            me: Some(public_key),
            initial: Duration::from_millis(100),
            timeout: Duration::from_secs(5),
            retry_timeout: Duration::from_millis(100),
            priority_requests: false,
        };

        Fetcher::new(context, config)
    }

    /// Helper to add an active request directly for testing
    fn add_test_active<S: Sender<PublicKey = PublicKey>>(
        fetcher: &mut Fetcher<Context, PublicKey, MockKey, S>,
        id: ID,
        key: MockKey,
    ) {
        let peer = PrivateKey::from_seed(1).public_key();
        let now = fetcher.context.current();
        let deadline = now + Duration::from_secs(5);
        fetcher.active.put(id, deadline);
        fetcher.requests.insert(
            id,
            ActiveRequest {
                key: key.clone(),
                peer,
                start: now,
            },
        );
        fetcher.key_to_id.insert(key, id);
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
            add_test_active(&mut fetcher, 100, MockKey(10));
            add_test_active(&mut fetcher, 101, MockKey(20));
            add_test_active(&mut fetcher, 102, MockKey(30));

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
            assert!(fetcher.key_to_id.contains_key(&MockKey(10)));
            assert!(!fetcher.key_to_id.contains_key(&MockKey(20)));
            assert!(!fetcher.key_to_id.contains_key(&MockKey(30)));
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
            add_test_active(&mut fetcher, 100, MockKey(10));
            add_test_active(&mut fetcher, 101, MockKey(20));
            add_test_active(&mut fetcher, 102, MockKey(30));

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
            assert!(fetcher.requests.is_empty());
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
            add_test_active(&mut fetcher, 100, MockKey(10));
            add_test_active(&mut fetcher, 101, MockKey(20));
            assert_eq!(fetcher.len(), 4);
            assert_eq!(fetcher.len_pending(), 2);
            assert_eq!(fetcher.len_active(), 2);

            // Remove one pending key
            assert!(fetcher.pending.remove(&MockKey(1)));
            assert_eq!(fetcher.len(), 3);
            assert_eq!(fetcher.len_pending(), 1);
            assert_eq!(fetcher.len_active(), 2);

            // Remove one active key via cancel
            assert!(fetcher.cancel(&MockKey(10)));
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
            add_test_active(&mut fetcher, 100, MockKey(10));
            add_test_active(&mut fetcher, 101, MockKey(20));

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
            add_test_active(&mut fetcher, 100, MockKey(10));
            add_test_active(&mut fetcher, 101, MockKey(20));

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
            add_test_active(&mut fetcher, 100, MockKey(10));
            add_test_active(&mut fetcher, 101, MockKey(20));

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
            add_test_active(&mut fetcher, 100, MockKey(10));
            assert!(fetcher.contains(&MockKey(10)));

            // Test non-existent key
            assert!(!fetcher.contains(&MockKey(99)));

            // Remove from pending
            fetcher.pending.remove(&MockKey(1));
            assert!(!fetcher.contains(&MockKey(1)));

            // Remove from active via cancel
            fetcher.cancel(&MockKey(10));
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
            let dummy_peer = PrivateKey::from_seed(1).public_key();

            // Add key to active state
            add_test_active(&mut fetcher, 100, MockKey(10));

            // Test pop with non-existent ID
            assert!(fetcher.pop_by_id(999, &dummy_peer, true).is_none());

            // The active entry should still be there since the ID wasn't found
            assert_eq!(fetcher.len_active(), 1);

            // Test pop with correct ID and peer
            assert_eq!(fetcher.pop_by_id(100, &dummy_peer, true), Some(MockKey(10)));
            assert_eq!(fetcher.len_active(), 0);
        });
    }

    #[test]
    fn test_reconcile_and_block() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();

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
            let peer = PrivateKey::from_seed(1).public_key();
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
            add_test_active(&mut fetcher, 100, MockKey(1));
            add_test_active(&mut fetcher, 101, MockKey(2));

            // Retain only MockKey(1)
            fetcher.retain(|key| key.0 == 1);

            // Verify the ID mapping is preserved correctly
            assert_eq!(fetcher.len_active(), 1);
            assert!(fetcher.key_to_id.contains_key(&MockKey(1)));
            assert!(!fetcher.key_to_id.contains_key(&MockKey(2)));

            // Verify the request data for MockKey(1) is preserved
            let id = fetcher.key_to_id.get(&MockKey(1)).unwrap();
            assert!(fetcher.requests.contains_key(id));
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
            add_test_active(&mut fetcher, 100, MockKey(10));
            add_test_active(&mut fetcher, 101, MockKey(20));

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
            let public_key = PrivateKey::from_seed(0).public_key();
            let other_public_key = PrivateKey::from_seed(1).public_key();
            let config = Config {
                me: Some(public_key.clone()),
                initial: Duration::from_millis(100),
                timeout: Duration::from_secs(5),
                retry_timeout: Duration::from_millis(100),
                priority_requests: false,
            };
            let mut fetcher: Fetcher<_, _, MockKey, FailMockSender> =
                Fetcher::new(context.clone(), config);
            fetcher.reconcile(&[public_key, other_public_key]);
            let mut sender = WrappedSender::new(FailMockSender::default());

            // Add a key to pending
            fetcher.add_ready(MockKey(1));
            fetcher.fetch(&mut sender).await; // won't be delivered, so immediately re-added
            fetcher.fetch(&mut sender).await; // waiter activated

            // Check pending deadline
            assert_eq!(fetcher.len_pending(), 1);
            let pending_deadline = fetcher.get_pending_deadline().unwrap();
            assert!(pending_deadline > context.current());

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
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let blocked_peer = PrivateKey::from_seed(99).public_key();
            let config = Config {
                me: Some(public_key.clone()),
                initial: Duration::from_millis(100),
                timeout: Duration::from_secs(5),
                retry_timeout: Duration::from_millis(100),
                priority_requests: false,
            };
            let mut fetcher: Fetcher<_, _, MockKey, FailMockSender> =
                Fetcher::new(context.clone(), config);
            fetcher.reconcile(&[public_key, peer1.clone()]);
            let mut sender = WrappedSender::new(FailMockSender::default());

            // Block the peer we'll use as target, so fetch has no eligible participants
            fetcher.block(blocked_peer.clone());

            // Add key with targets pointing only to blocked peer
            fetcher.add_ready(MockKey(1));
            fetcher.add_targets(MockKey(1), [blocked_peer.clone()]);
            fetcher.fetch(&mut sender).await;

            // Waiter should be set to far future (no eligible peers at all)
            assert!(fetcher.waiter.is_some());
            let waiter_time = fetcher.waiter.unwrap();
            assert!(waiter_time > context.current() + Duration::from_secs(1000));

            // Add targets should clear the waiter
            fetcher.add_targets(MockKey(1), [peer1.clone()]);
            assert!(fetcher.waiter.is_none());

            // Pending deadline should now be reasonable
            let deadline = fetcher.get_pending_deadline().unwrap();
            assert!(deadline <= context.current() + Duration::from_millis(100));

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
    fn test_waiter_uses_retry_timeout_on_send_failure() {
        let cfg = deterministic::Config::default().with_timeout(Some(Duration::from_secs(5)));
        let runner = Runner::new(cfg);
        runner.start(|context| async move {
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            let retry_timeout = Duration::from_millis(100);
            let config = Config {
                me: Some(public_key.clone()),
                initial: Duration::from_millis(100),
                timeout: Duration::from_secs(5),
                retry_timeout,
                priority_requests: false,
            };
            let mut fetcher: Fetcher<_, _, MockKey, FailMockSender> =
                Fetcher::new(context.clone(), config);
            // Add peers (FailMockSender doesn't rate limit, just fails sends)
            fetcher.reconcile(&[public_key, peer1, peer2]);
            let mut sender = WrappedSender::new(FailMockSender::default());

            // Add key and attempt fetch - all sends will fail
            fetcher.add_ready(MockKey(1));
            fetcher.fetch(&mut sender).await;

            // Key should still be pending (send failed)
            assert_eq!(fetcher.len_pending(), 1);

            // Waiter should be set to retry_timeout from now, not Duration::MAX
            let pending_deadline = fetcher.get_pending_deadline().unwrap();
            let max_expected = context.current() + retry_timeout + Duration::from_millis(10);
            assert!(
                pending_deadline <= max_expected,
                "pending deadline {:?} should be within retry_timeout of now, not Duration::MAX",
                pending_deadline.duration_since(context.current())
            );

            // Wait for pending deadline and retry - should succeed quickly
            let wait_duration = pending_deadline
                .duration_since(context.current())
                .unwrap_or(Duration::ZERO);
            context.sleep(wait_duration).await;

            // Should be able to fetch again (this would hang if waiter was Duration::MAX)
            fetcher.fetch(&mut sender).await;
        });
    }

    #[test]
    fn test_add_targets() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            let peer3 = PrivateKey::from_seed(3).public_key();

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
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();

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
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            let peer3 = PrivateKey::from_seed(3).public_key();

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
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            let peer3 = PrivateKey::from_seed(3).public_key();
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone(), peer3.clone()]);
            let mut sender = WrappedSender::new(FailMockSender::default());

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
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone()]);
            let mut sender = WrappedSender::new(SuccessMockSender::default());

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
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            let peer3 = PrivateKey::from_seed(3).public_key();

            // Add only peer1 and peer2 to the peer set (peer3 is not in the peer set)
            fetcher.reconcile(&[public_key, peer1, peer2]);

            // Target peer3, which is not in the peer set (disconnected)
            fetcher.add_targets(MockKey(1), [peer3]);
            assert!(fetcher.targets.contains_key(&MockKey(1)));

            // Add key to pending
            fetcher.add_ready(MockKey(1));

            // Fetch should not fallback to any peer - it should wait for targets
            let mut sender = WrappedSender::new(SuccessMockSender::default());
            fetcher.fetch(&mut sender).await;

            // Targets should still exist (no fallback cleared them)
            assert!(fetcher.targets.contains_key(&MockKey(1)));

            // Key should still be in pending state (no fallback to available peers)
            assert_eq!(fetcher.len_pending(), 1);
            assert_eq!(fetcher.len_active(), 0);

            // Waiter should be set to far future (no eligible peers at all)
            assert!(fetcher.waiter.is_some());
            let waiter_time = fetcher.waiter.unwrap();
            assert!(waiter_time > context.current() + Duration::from_secs(1000));
        });
    }

    #[test]
    fn test_clear_targets() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();

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
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            let config = Config {
                me: Some(public_key.clone()),
                initial: Duration::from_millis(100),
                timeout: Duration::from_secs(5),
                retry_timeout: Duration::from_millis(100),
                priority_requests: false,
            };
            let mut fetcher: Fetcher<_, _, MockKey, LimitedMockSender<Context>> =
                Fetcher::new(context.clone(), config);
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone()]);
            let quota = Quota::per_second(NZU32!(1));
            let mut sender = WrappedSender::new(LimitedMockSender::new(quota, context.clone()));

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

    #[test]
    fn test_peer_prioritization() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            let peer3 = PrivateKey::from_seed(3).public_key();

            // Add peers with initial performance (100ms)
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone(), peer3.clone()]);

            // Simulate different response times by updating performance:
            // - peer1: very fast (10ms)
            // - peer2: slow (500ms)
            // - peer3: medium (200ms)
            // After update_performance with EMA: new = (past + elapsed) / 2

            // peer1: simulate multiple fast responses to drive down its priority
            for _ in 0..5 {
                fetcher.update_performance(&peer1, Duration::from_millis(10));
            }

            // peer2: simulate slow responses to increase its priority
            for _ in 0..5 {
                fetcher.update_performance(&peer2, Duration::from_millis(500));
            }

            // peer3: simulate medium responses
            for _ in 0..5 {
                fetcher.update_performance(&peer3, Duration::from_millis(200));
            }

            // Get eligible peers - should be ordered by priority (fastest first)
            let peers = fetcher.get_eligible_peers(&MockKey(1), false);

            // Verify we have 3 peers (excluding self)
            assert_eq!(peers.len(), 3);

            // Verify order: peer1 (fastest) should come first, peer2 (slowest) last
            assert_eq!(
                peers[0], peer1,
                "Fastest peer should be first, got {:?}",
                peers
            );
            assert_eq!(
                peers[1], peer3,
                "Medium peer should be second, got {:?}",
                peers
            );
            assert_eq!(
                peers[2], peer2,
                "Slowest peer should be last, got {:?}",
                peers
            );

            // Verify that shuffling (used on retry) changes the order
            // Note: shuffling is random, so we check that it CAN change order
            // by calling multiple times and checking for any different order
            let mut found_different_order = false;
            for _ in 0..10 {
                let shuffled = fetcher.get_eligible_peers(&MockKey(1), true);
                if shuffled != peers {
                    found_different_order = true;
                    break;
                }
            }
            assert!(
                found_different_order,
                "Shuffling should produce different orders"
            );
        });
    }
}
