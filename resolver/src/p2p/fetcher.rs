use crate::p2p::wire;
use commonware_actor::{Feedback, Unreliable};
use commonware_cryptography::PublicKey;
use commonware_p2p::{Recipients, Sender, utils::codec::WrappedSender};
use commonware_runtime::{
    Clock, Metrics,
    telemetry::metrics::{
        EncodeStruct, GaugeExt, GaugeFamily, Histogram, MetricsExt as _,
        histogram::Buckets,
        status::{self, Status},
    },
};
use commonware_utils::{PrioritySet, Span, SystemTimeExt, time::NANOS_PER_SEC};
use rand::seq::SliceRandom;
use rand_core::Rng;
use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    marker::PhantomData,
    mem,
    time::{Duration, SystemTime},
};
use tracing::debug;

/// Per-peer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
struct Peer<P: PublicKey> {
    peer: P,
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

/// Throughput of a response in bytes per second (higher is better).
///
/// A response that delivers no bytes contributes a zero-throughput sample.
/// Timeouts, missing data, and failed sends contribute the same sample because
/// they too deliver no data. Elapsed time is floored at one nanosecond to avoid
/// dividing by zero for an instantaneous response.
fn throughput(elapsed: Duration, bytes: usize) -> u128 {
    (bytes as u128)
        .saturating_mul(NANOS_PER_SEC)
        .saturating_div(elapsed.as_nanos().max(1))
}

/// Configuration for the fetcher.
pub struct Config<P: PublicKey> {
    /// Local identity of the participant (if any).
    pub me: Option<P>,

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
/// the peer might be slow or might receive the data later, and are cleared when the fetch
/// succeeds. A blocked target is skipped until the network unblocks it, so a fetch whose every
/// target is blocked stays outstanding and resumes once one of them is unblocked.
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
    /// Peers the network currently blocks, replaced wholesale on every update.
    blocked: HashSet<P>,
    /// Participants and their performance (throughput in bytes per second, higher is
    /// better). Stored as `Reverse` so the set orders the best-performing peer first.
    participants: PrioritySet<P, Reverse<u128>>,

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
    /// Timeout for requests
    timeout: Duration,

    /// Manages pending requests. When a request is registered (for both the first time and after
    /// a retry), it is added to this set.
    ///
    /// Fresh requests precede retries. Within each class, requests are ordered
    /// by the next time they should be attempted. Retried requests use a random
    /// peer rather than the best-performing peer.
    pending: PrioritySet<Key, (bool, SystemTime)>,

    /// If no peers are ready to handle a request (all filtered out or send failed), the waiter is set
    /// to the next time to try the request.
    waiter: Option<SystemTime>,

    /// How long fetches remain in the pending queue before being retried
    retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages
    priority_requests: bool,

    /// Per-key target peers restricting which peers are used to fetch each key.
    /// Only target peers are tried, waiting for them if unavailable. There is no
    /// fallback to other peers. Targets persist through transient failures and are
    /// cleared on successful fetch. Blocked targets are skipped until unblocked.
    targets: HashMap<Key, HashSet<P>>,

    /// Per-peer performance metric (exponential moving average of throughput in bytes per second)
    performance: GaugeFamily<Peer<P>>,

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
        let performance = context.family(
            "peer_performance",
            "Per-peer performance (exponential moving average of throughput in bytes per second)",
        );
        let requests_created =
            context.family("requests_created", "Status of request creation attempts");
        let requests_sent = context.family(
            "requests_sent",
            "Status of individual network requests sent to peers",
        );
        let resolves = context.histogram(
            "resolves",
            "Number and duration of requests that were resolved",
            Buckets::NETWORK,
        );
        Self {
            context,
            me: config.me,
            blocked: HashSet::new(),
            participants: PrioritySet::new(),
            request_id: 0,
            active: PrioritySet::new(),
            requests: HashMap::new(),
            key_to_id: HashMap::new(),
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

    /// Update a participant's throughput estimate (higher is better) using an
    /// exponential moving average.
    fn update_performance(&mut self, participant: &P, throughput: u128) {
        let Some(Reverse(past)) = self.participants.get(participant) else {
            return;
        };
        let next = past.saturating_add(throughput) / 2;
        self.participants.put(participant.clone(), Reverse(next));
        let _ = self.performance.get_or_create_by(participant).try_set(next);
    }

    /// Get eligible peers for a key, best-performing first.
    ///
    /// If `shuffle` is true, the peers are shuffled (used for retries to try different peers).
    fn get_eligible_peers(&mut self, key: &Key, shuffle: bool) -> Vec<P> {
        let targets = self.targets.get(key);

        // Prepare participant iterator. The set stores throughput as `Reverse`,
        // so it iterates best-performing peer first.
        let participant_iter = self.participants.iter();

        // Collect eligible peers
        let mut eligible: Vec<P> = participant_iter
            .filter(|(p, _)| self.me.as_ref() != Some(p)) // not self
            .filter(|(p, _)| !self.blocked.contains(p)) // not blocked
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
    /// to active. On failure, the key remains pending for retry. Before trying a
    /// key, the engine checks whether any response receiver remains open.
    /// Abandoned keys are removed and returned for engine cleanup.
    ///
    /// Sets `self.waiter` to control when the next fetch attempt should occur:
    /// - Rate limit expiry time if any peer was rate-limited
    /// - `retry_timeout` if peers exist but all sends failed
    /// - `Duration::MAX` if no eligible peers (wait for external changes)
    pub fn fetch(
        &mut self,
        sender: &mut WrappedSender<NetS, wire::Message<Key>>,
        mut live: impl FnMut(&Key) -> bool,
    ) -> Vec<Key> {
        self.waiter = None;

        // Try each pending key until one succeeds
        let mut earliest_rate_limit: Option<SystemTime> = None;
        let mut found_eligible_peers = false;

        // Detach the queue to leave skipped entries untouched and remove only the
        // successfully sent key.
        let pending = mem::replace(&mut self.pending, PrioritySet::new());
        let mut sent = None;
        let mut abandoned = Vec::new();
        'pending: for (key, &(retry, _)) in pending.iter() {
            if !live(key) {
                abandoned.push(key.clone());
                continue;
            }

            // Skip keys with no eligible peers
            let peers = self.get_eligible_peers(key, retry);
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
                let checked = match sender.check(Recipients::One(peer.clone())) {
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
                match checked.send(message, self.priority_requests) {
                    Unreliable::Outcome(Feedback::Ok | Feedback::Backoff) => {
                        // Success - move from pending to active
                        self.requests_sent.inc(Status::Success);
                        let now = self.context.current();
                        sent = Some((key.clone(), id, peer, now));
                        break 'pending;
                    }
                    feedback @ (Unreliable::Rejected | Unreliable::Outcome(Feedback::Closed)) => {
                        // Send was not handled, try next peer
                        self.requests_sent.inc(Status::Dropped);
                        debug!(?peer, ?feedback, "send failed");

                        // Nothing was delivered, so score zero throughput.
                        self.update_performance(&peer, 0);
                    }
                }
            }
        }

        // Restore the pending queue before moving a successful request to active tracking.
        self.pending = pending;
        for key in &abandoned {
            assert!(self.remove(key));
        }
        if let Some((key, id, peer, start)) = sent {
            assert!(self.pending.remove(&key));
            let deadline = start.checked_add(self.timeout).expect("time overflowed");
            self.active.put(id, deadline);
            self.requests.insert(
                id,
                ActiveRequest {
                    key: key.clone(),
                    peer,
                    start,
                },
            );
            self.key_to_id.insert(key, id);
            return abandoned;
        }

        if self.pending.is_empty() {
            return abandoned;
        }

        // Set waiter for next fetch attempt
        self.waiter = Some(if let Some(rate_limit_time) = earliest_rate_limit {
            // Use rate limit expiry time
            rate_limit_time
        } else if found_eligible_peers {
            // Peers exist but all sends failed - use retry timeout
            self.context.current() + self.retry_timeout
        } else {
            // No eligible peers yet. The engine still keeps polling; this just defers the next
            // outbound attempt until some external change (like a peer set update) clears it.
            self.context.current().saturating_add_ext(Duration::MAX)
        });
        abandoned
    }

    /// Removes all fetch state for `key`.
    pub fn remove(&mut self, key: &Key) -> bool {
        let mut removed = self.pending.remove(key);
        if let Some(id) = self.key_to_id.remove(key) {
            removed |= self.active.remove(&id);
            removed |= self.requests.remove(&id).is_some();
        }
        removed |= self.targets.remove(key).is_some();

        if removed {
            self.waiter = None;
        }
        removed
    }

    /// Adds a key to the front of the pending queue.
    pub fn add_ready(&mut self, key: Key) {
        assert!(!self.pending.contains(&key));
        // A previous pending key may have pushed the waiter far into the future
        // because no eligible peer could serve it. A new ready key can still be
        // fetchable, so wake pending processing immediately.
        self.waiter = None;
        self.pending.put(key, (false, self.context.current()));
    }

    /// Adds a key to the pending queue.
    ///
    /// Panics if the key is already pending.
    pub fn add_retry(&mut self, key: Key) {
        assert!(!self.pending.contains(&key));
        // A previous pending key may have pushed the waiter far into the future
        // because no eligible peer could serve it. Clear the stale global waiter
        // so this retry can drive pending processing again.
        self.waiter = None;
        let deadline = self.context.current() + self.retry_timeout;
        self.pending.put(key, (true, deadline));
    }

    /// Returns the deadline for the next pending retry.
    pub fn get_pending_deadline(&self) -> Option<SystemTime> {
        // Pending may be emptied by cancellation.
        if self.pending.is_empty() {
            return None;
        }

        // Return the greater of the waiter and the next pending deadline
        let pending_deadline = self.pending.peek().map(|(_, (_, deadline))| *deadline);
        pending_deadline.max(self.waiter)
    }

    /// Returns the deadline for the next active request timeout.
    pub fn get_active_deadline(&self) -> Option<SystemTime> {
        self.active.peek().map(|(_, deadline)| *deadline)
    }

    /// Returns the key with the next request timeout.
    pub fn active_key(&self) -> Option<&Key> {
        let (id, _) = self.active.peek()?;
        self.requests.get(id).map(|request| &request.key)
    }

    /// Removes and returns the key with the next request timeout.
    ///
    /// Targets are not removed on timeout.
    pub fn pop_active(&mut self) -> Option<Key> {
        // Pop the next deadline
        let (id, _) = self.active.pop()?;

        // Remove the request and score zero throughput (nothing was delivered).
        let req = self.requests.remove(&id)?;
        self.key_to_id.remove(&req.key);
        self.update_performance(&req.peer, 0);

        Some(req.key)
    }

    /// Remove the active request matching `id` and `peer`.
    fn pop_request(&mut self, id: ID, peer: &P) -> Option<ActiveRequest<P, Key>> {
        let req = self.requests.get(&id)?;
        if &req.peer != peer {
            return None;
        }

        let req = self.requests.remove(&id)?;
        self.active.remove(&id);
        self.key_to_id.remove(&req.key);
        Some(req)
    }

    /// Returns the key for a response matching an active request and peer.
    pub fn response_key(&self, id: ID, peer: &P) -> Option<&Key> {
        if !self.active.contains(&id) {
            return None;
        }
        let request = self.requests.get(&id)?;
        (&request.peer == peer).then_some(&request.key)
    }

    /// Processes a data response from a peer.
    ///
    /// Removes the matching request and returns its key and network response time. The caller
    /// must report the response with [`Self::record_response`] after the consumer decides it
    /// should be attributed to the peer.
    ///
    /// Targets are not removed here. The caller clears them when the logical fetch completes or
    /// is ignored. On invalid data, the caller blocks the peer, which is then skipped until the
    /// network unblocks it.
    ///
    /// Note that this matches responses against the peer a request was already sent to. A later
    /// `reconcile()` call may remove that peer from the candidate pool for future sends, but it
    /// does not retroactively invalidate the in-flight request.
    pub fn pop_response(&mut self, id: ID, peer: &P) -> Option<(Key, Duration)> {
        let req = self.pop_request(id, peer)?;
        let elapsed = self
            .context
            .current()
            .duration_since(req.start)
            .unwrap_or_default();
        Some((req.key, elapsed))
    }

    /// Attribute a received data response to its serving peer.
    ///
    /// Performance is scored as response size divided by wall-clock time (bytes per
    /// second) so peers that deliver more bytes in the same time rank better. Ignored
    /// responses must not be recorded because the consumer declined to attribute them.
    pub fn record_response(&mut self, peer: &P, elapsed: Duration, bytes: usize) {
        self.update_performance(peer, throughput(elapsed, bytes));
        self.resolves.observe(elapsed.as_secs_f64());
    }

    /// Processes a response indicating that the peer does not have the requested data.
    ///
    /// Missing data is scored as zero throughput because the peer delivered nothing.
    pub fn pop_missing(&mut self, id: ID, peer: &P) -> Option<Key> {
        let req = self.pop_request(id, peer)?;
        self.update_performance(&req.peer, 0);
        Some(req.key)
    }

    /// Reconciles the list of peers that can be used to fetch future requests.
    pub fn reconcile(&mut self, keep: &[P]) {
        // New peers start with zero throughput, having delivered nothing yet. They
        // are tried via shuffled retries and earn a real score once they respond.
        self.participants.reconcile(keep, Reverse(0));

        // Clear waiter (may no longer apply)
        self.waiter = None;
    }

    /// Replaces the set of peers the network currently blocks.
    ///
    /// Blocked peers keep their place in any target sets and are skipped until
    /// a later update no longer lists them. Clears the waiter, since an
    /// unblocked peer may make a waiting fetch servable.
    pub fn set_blocked(&mut self, blocked: impl IntoIterator<Item = P>) {
        self.blocked = blocked.into_iter().collect();
        self.waiter = None;
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
    #[cfg(test)]
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
    use commonware_actor::Unreliable;
    use commonware_cryptography::{
        Signer,
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_p2p::{LimitedSender, Recipients, UnlimitedSender};
    use commonware_runtime::{
        BufferPooler, IoBufs, KeyedRateLimiter, Quota, Runner as _, Supervisor as _,
        deterministic::{self, Context, Runner},
    };
    use commonware_utils::{NZU32, sync::RwLock};
    use std::{sync::Arc, time::Duration};

    #[derive(Debug)]
    struct CheckedSender<'a, S: UnlimitedSender> {
        sender: &'a mut S,
        recipients: Recipients<S::PublicKey>,
    }

    impl<'a, S: UnlimitedSender> commonware_p2p::CheckedSender for CheckedSender<'a, S> {
        type PublicKey = S::PublicKey;

        fn recipients(&self) -> Vec<Self::PublicKey> {
            match &self.recipients {
                Recipients::All => Vec::new(),
                Recipients::Some(peers) => peers.clone(),
                Recipients::One(peer) => vec![peer.clone()],
            }
        }

        fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
            self.sender.send(self.recipients, message, priority)
        }
    }

    #[derive(Default, Clone, Debug)]
    struct FailMockSenderInner;

    impl UnlimitedSender for FailMockSenderInner {
        type PublicKey = PublicKey;

        fn send(
            &mut self,
            _recipients: Recipients<Self::PublicKey>,
            _message: impl Into<IoBufs> + Send,
            _priority: bool,
        ) -> Unreliable<Feedback> {
            Unreliable::Rejected
        }
    }

    // Mock sender that fails
    #[derive(Default, Clone, Debug)]
    struct FailMockSender(FailMockSenderInner);

    impl LimitedSender for FailMockSender {
        type PublicKey = PublicKey;
        type Checked<'a> = CheckedSender<'a, FailMockSenderInner>;

        fn check(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'_>, SystemTime> {
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

        fn send(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
            _message: impl Into<IoBufs> + Send,
            _priority: bool,
        ) -> Unreliable<Feedback> {
            match recipients {
                Recipients::One(_) => Unreliable::new(Feedback::Ok),
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

        fn check(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'_>, SystemTime> {
            Ok(CheckedSender {
                sender: &mut self.0,
                recipients,
            })
        }
    }

    // Mock sender that rate-limits per peer
    struct LimitedMockSender<E: Clock> {
        inner: SuccessMockSenderInner,
        rate_limiter: Arc<RwLock<KeyedRateLimiter<PublicKey, E>>>,
    }

    impl<E: Clock> Clone for LimitedMockSender<E> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
                rate_limiter: self.rate_limiter.clone(),
            }
        }
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

        fn check(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'_>, SystemTime> {
            let peer = match &recipients {
                Recipients::One(p) => p,
                _ => unimplemented!(),
            };

            {
                let rate_limiter = self.rate_limiter.write();
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
            timeout: Duration::from_secs(5),
            retry_timeout: Duration::from_millis(100),
            priority_requests: false,
        };

        Fetcher::new(context, config)
    }

    fn create_unservable_fetcher(
        context: &Context,
    ) -> (
        Fetcher<Context, PublicKey, MockKey, SuccessMockSender>,
        PublicKey,
    ) {
        let public_key = PrivateKey::from_seed(0).public_key();
        let peer = PrivateKey::from_seed(1).public_key();
        let missing_peer = PrivateKey::from_seed(2).public_key();
        let config = Config {
            me: Some(public_key.clone()),
            timeout: Duration::from_secs(5),
            retry_timeout: Duration::from_millis(100),
            priority_requests: false,
        };
        let mut fetcher = Fetcher::new(context.child("fetcher"), config);
        fetcher.reconcile(&[public_key, peer.clone()]);
        fetcher.add_targets(MockKey(1), [missing_peer]);
        fetcher.add_ready(MockKey(1));
        (fetcher, peer)
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
    fn test_remove_function() {
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

            assert!(fetcher.remove(&MockKey(20)));
            assert!(fetcher.remove(&MockKey(30)));

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

            // Remove one active key.
            assert!(fetcher.remove(&MockKey(10)));
            assert_eq!(fetcher.len(), 2);
            assert_eq!(fetcher.len_pending(), 1);
            assert_eq!(fetcher.len_active(), 1);
        });
    }

    #[test]
    fn test_remove_with_empty_collections() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            assert!(!fetcher.remove(&MockKey(1)));
            assert_eq!(fetcher.len(), 0);
        });
    }

    #[test]
    fn test_remove_nonexistent_preserves_elements() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add keys
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
            add_test_active(&mut fetcher, 100, MockKey(10));
            add_test_active(&mut fetcher, 101, MockKey(20));

            let initial_len = fetcher.len();

            assert!(!fetcher.remove(&MockKey(99)));

            // Nothing should be removed
            assert_eq!(fetcher.len(), initial_len);
            assert_eq!(fetcher.len_pending(), 2);
            assert_eq!(fetcher.len_active(), 2);
        });
    }

    #[test]
    fn test_remove_all_elements() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add keys
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
            add_test_active(&mut fetcher, 100, MockKey(10));
            add_test_active(&mut fetcher, 101, MockKey(20));

            for key in [MockKey(1), MockKey(2), MockKey(10), MockKey(20)] {
                assert!(fetcher.remove(&key));
            }

            // Everything should be removed
            assert_eq!(fetcher.len(), 0);
            assert_eq!(fetcher.len_pending(), 0);
            assert_eq!(fetcher.len_active(), 0);
        });
    }

    #[test]
    fn test_remove_drops_selected_keys() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add keys to both pending and active states
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
            add_test_active(&mut fetcher, 100, MockKey(10));
            add_test_active(&mut fetcher, 101, MockKey(20));

            // Drop a pending key.
            assert!(fetcher.remove(&MockKey(1)));
            assert_eq!(fetcher.len_pending(), 1);
            assert!(!fetcher.contains(&MockKey(1)));

            // Drop an active key.
            assert!(fetcher.remove(&MockKey(10)));
            assert_eq!(fetcher.len_active(), 1);
            assert!(!fetcher.contains(&MockKey(10)));

            // Dropping a non-existent key has no effect.
            let len = fetcher.len();
            assert!(!fetcher.remove(&MockKey(99)));
            assert_eq!(fetcher.len(), len);

            // Drop remaining pending key.
            assert!(fetcher.remove(&MockKey(2)));
            assert_eq!(fetcher.len_pending(), 0);

            // Ensure pending deadline is None
            assert!(fetcher.get_pending_deadline().is_none());
        });
    }

    #[test]
    fn test_fetch_prunes_each_examined_pending_key() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let local = PrivateKey::from_seed(0).public_key();
            let peer = PrivateKey::from_seed(1).public_key();
            let missing = PrivateKey::from_seed(2).public_key();
            let config = Config {
                me: Some(local.clone()),
                timeout: Duration::from_secs(5),
                retry_timeout: Duration::from_millis(100),
                priority_requests: false,
            };
            let mut fetcher: Fetcher<_, _, MockKey, SuccessMockSender> =
                Fetcher::new(context.child("fetcher"), config);
            fetcher.reconcile(&[local, peer]);

            // The abandoned first key and the live second key both have no
            // eligible target. The scan must prune the first, skip the second,
            // and continue to the third key that can be sent.
            fetcher.add_targets(MockKey(1), [missing.clone()]);
            fetcher.add_targets(MockKey(2), [missing]);
            fetcher.add_ready(MockKey(1));
            fetcher.add_ready(MockKey(2));
            fetcher.add_ready(MockKey(3));

            let mut examined = Vec::new();
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );
            let abandoned = fetcher.fetch(&mut sender, |key| {
                examined.push(key.clone());
                *key != MockKey(1)
            });

            assert_eq!(examined, vec![MockKey(1), MockKey(2), MockKey(3)]);
            assert_eq!(abandoned, vec![MockKey(1)]);
            assert!(!fetcher.contains(&MockKey(1)));
            assert!(!fetcher.targets.contains_key(&MockKey(1)));
            assert!(fetcher.pending.contains(&MockKey(2)));
            assert_eq!(fetcher.active_key(), Some(&MockKey(3)));
        });
    }

    #[test]
    fn test_fetch_abandons_unservable_pending_key_without_waiter() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.child("fetcher"));
            fetcher.add_ready(MockKey(1));
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );

            assert_eq!(
                fetcher.fetch(&mut sender, |key| *key != MockKey(1)),
                vec![MockKey(1)]
            );
            assert!(!fetcher.contains(&MockKey(1)));
            assert!(fetcher.get_pending_deadline().is_none());
            assert!(fetcher.waiter.is_none());
        });
    }

    #[test]
    fn test_remove_cleans_active_request_without_scoring_and_allows_replacement() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let local = PrivateKey::from_seed(0).public_key();
            let peer = PrivateKey::from_seed(1).public_key();
            let wrong_peer = PrivateKey::from_seed(2).public_key();
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.child("fetcher"));
            fetcher.reconcile(&[local, peer.clone()]);
            fetcher.record_response(&peer, Duration::from_millis(10), 100);
            let score = fetcher.participants.get(&peer);

            add_test_active(&mut fetcher, 100, MockKey(1));
            fetcher.add_targets(MockKey(1), [peer.clone()]);
            let waiter = context.current() + Duration::from_secs(10);
            fetcher.waiter = Some(waiter);

            assert_eq!(fetcher.active_key(), Some(&MockKey(1)));
            assert_eq!(fetcher.response_key(100, &peer), Some(&MockKey(1)));
            assert!(fetcher.response_key(100, &wrong_peer).is_none());
            assert!(!fetcher.remove(&MockKey(99)));
            assert_eq!(fetcher.waiter, Some(waiter));

            assert!(fetcher.remove(&MockKey(1)));
            assert!(fetcher.waiter.is_none());
            assert!(fetcher.active_key().is_none());
            assert!(fetcher.response_key(100, &peer).is_none());
            assert!(!fetcher.active.contains(&100));
            assert!(!fetcher.requests.contains_key(&100));
            assert!(!fetcher.key_to_id.contains_key(&MockKey(1)));
            assert!(!fetcher.targets.contains_key(&MockKey(1)));
            assert_eq!(fetcher.participants.get(&peer), score);
            assert!(fetcher.pop_missing(100, &peer).is_none());
            assert_eq!(fetcher.participants.get(&peer), score);

            fetcher.add_ready(MockKey(1));
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );
            assert!(fetcher.fetch(&mut sender, |_| true).is_empty());
            assert_eq!(fetcher.active_key(), Some(&MockKey(1)));
            assert_eq!(fetcher.response_key(0, &peer), Some(&MockKey(1)));
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

            // Remove from active.
            assert!(fetcher.remove(&MockKey(10)));
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
    fn test_pop_response_defers_peer_rating() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let local_peer = PrivateKey::from_seed(0).public_key();
            let peer = PrivateKey::from_seed(1).public_key();
            fetcher.reconcile(&[local_peer, peer.clone()]);

            add_test_active(&mut fetcher, 100, MockKey(10));

            assert!(fetcher.pop_response(999, &peer).is_none());
            assert_eq!(fetcher.len_active(), 1);

            fetcher.context.sleep(Duration::from_millis(20)).await;
            let (key, elapsed) = fetcher.pop_response(100, &peer).expect("matching response");
            assert_eq!(key, MockKey(10));
            assert_eq!(elapsed, Duration::from_millis(20));
            assert_eq!(fetcher.len_active(), 0);

            // Receiving bytes is not enough to score the peer: the consumer may
            // decide the key became obsolete before inspecting the response.
            // New peers start at zero throughput.
            assert_eq!(fetcher.participants.get(&peer), Some(Reverse(0)));
            fetcher.record_response(&peer, elapsed, 1);
            let observed = throughput(Duration::from_millis(20), 1);
            assert_eq!(fetcher.participants.get(&peer), Some(Reverse(observed / 2)));
        });
    }

    #[test]
    fn test_record_response_scores_by_size() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let local_peer = PrivateKey::from_seed(0).public_key();
            let small = PrivateKey::from_seed(1).public_key();
            let large = PrivateKey::from_seed(2).public_key();
            fetcher.reconcile(&[local_peer, small.clone(), large.clone()]);

            let elapsed = Duration::from_millis(20);
            fetcher.record_response(&small, elapsed, 1);
            fetcher.record_response(&large, elapsed, 1_000);

            // Same latency, larger payload -> higher (better) throughput.
            let small_score = fetcher.participants.get(&small).unwrap().0;
            let large_score = fetcher.participants.get(&large).unwrap().0;
            assert!(
                large_score > small_score,
                "larger payload should score better: large={large_score} small={small_score}"
            );

            let peers = fetcher.get_eligible_peers(&MockKey(1), false);
            assert_eq!(peers[0], large);
            assert_eq!(peers[1], small);
        });
    }

    #[test]
    fn test_empty_fast_reply_cannot_outrank_real_payload() {
        // An empty response contributes zero throughput, the same as a timeout.
        let runner = Runner::default();
        runner.start(|context| async move {
            // An empty response has zero throughput regardless of latency.
            assert_eq!(throughput(Duration::from_millis(1), 0), 0);

            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let local_peer = PrivateKey::from_seed(0).public_key();
            let empty = PrivateKey::from_seed(1).public_key();
            let real = PrivateKey::from_seed(2).public_key();
            fetcher.reconcile(&[local_peer, empty.clone(), real.clone()]);

            // Empty-and-instant repeatedly, versus a real 1 KiB payload served slowly.
            for _ in 0..3 {
                fetcher.record_response(&empty, Duration::from_millis(1), 0);
                fetcher.record_response(&real, Duration::from_millis(50), 1024);
            }

            let empty_score = fetcher.participants.get(&empty).unwrap().0;
            let real_score = fetcher.participants.get(&real).unwrap().0;
            assert!(
                real_score > empty_score,
                "real payload must outrank empty reply: real={real_score} empty={empty_score}"
            );

            let peers = fetcher.get_eligible_peers(&MockKey(1), false);
            assert_eq!(peers[0], real);
            assert_eq!(peers[1], empty);
        });
    }

    #[test]
    fn test_throughput_orders_fast_large_payloads() {
        // 10 MiB in 10ms is about 1 GB/s. Throughput stays non-zero and ranks a
        // faster peer ahead of a slower one delivering the same payload.
        let bytes = 10 * 1024 * 1024;
        let slow = throughput(Duration::from_millis(10), bytes);
        let fast = throughput(Duration::from_millis(5), bytes);
        assert_ne!(slow, 0);
        assert_ne!(fast, 0);
        assert!(fast > slow);
    }

    #[test]
    fn test_throughput_ema_rewards_faster_history() {
        // Two peers deliver the same total bytes with different histories. The EMA
        // is applied to per-response throughput, so the bursty peer's fast first
        // response outweighs its slower second response.
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let local_peer = PrivateKey::from_seed(0).public_key();
            let bursty = PrivateKey::from_seed(1).public_key();
            let steady = PrivateKey::from_seed(2).public_key();
            fetcher.reconcile(&[local_peer, bursty.clone(), steady.clone()]);

            fetcher.record_response(&bursty, Duration::from_millis(1), 1);
            fetcher.record_response(&bursty, Duration::from_millis(100), 1);
            fetcher.record_response(&steady, Duration::from_millis(40), 1);
            fetcher.record_response(&steady, Duration::from_millis(40), 1);

            let peers = fetcher.get_eligible_peers(&MockKey(1), false);
            assert_eq!(peers, vec![bursty, steady]);
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
            fetcher.reconcile(&[peer1.clone(), peer2.clone()]);

            // A blocked participant is skipped without leaving the participant set.
            fetcher.set_blocked([peer1.clone()]);
            assert_eq!(fetcher.get_eligible_peers(&MockKey(1), false), vec![peer2]);
            assert!(fetcher.participants.contains(&peer1));
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
    fn test_remove_edge_cases() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Removing from an empty fetcher is a no-op.
            assert!(!fetcher.remove(&MockKey(1)));
            assert_eq!(fetcher.len(), 0);

            // Add key, prune it, then prune it again.
            fetcher.add_retry(MockKey(1));
            assert!(fetcher.remove(&MockKey(1)));
            assert_eq!(fetcher.len(), 0);
            assert!(!fetcher.remove(&MockKey(1)));
            assert_eq!(fetcher.len(), 0);
        });
    }

    #[test]
    fn test_remove_preserves_other_active_state() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add keys to active with specific IDs
            add_test_active(&mut fetcher, 100, MockKey(1));
            add_test_active(&mut fetcher, 101, MockKey(2));

            assert!(fetcher.remove(&MockKey(2)));

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

            assert!(fetcher.remove(&MockKey(1)));
            assert!(fetcher.remove(&MockKey(10)));

            assert_eq!(fetcher.len(), 2);

            // MockKey(2) pending and MockKey(20) active remain.
            assert_eq!(fetcher.len(), 2);
            assert!(fetcher.contains(&MockKey(2)));
            assert!(fetcher.contains(&MockKey(20)));

            assert!(fetcher.remove(&MockKey(2)));
            assert!(fetcher.remove(&MockKey(20)));
            assert_eq!(fetcher.len(), 0);
        });
    }

    #[test]
    fn test_ready_vs_retry() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context.child("fetcher"));

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
    fn test_ready_requests_precede_all_retries() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context.child("fetcher"));

            fetcher.add_retry(MockKey(1));
            context.sleep(Duration::from_millis(50)).await;
            fetcher.add_retry(MockKey(2));
            context.sleep(Duration::from_millis(200)).await;
            fetcher.add_ready(MockKey(4));
            fetcher.add_ready(MockKey(3));

            let keys: Vec<_> =
                std::iter::from_fn(|| fetcher.pending.pop().map(|(key, _)| key)).collect();
            assert_eq!(keys, vec![MockKey(3), MockKey(4), MockKey(1), MockKey(2)]);
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
                timeout: Duration::from_secs(5),
                retry_timeout: Duration::from_millis(100),
                priority_requests: false,
            };
            let mut fetcher: Fetcher<_, _, MockKey, FailMockSender> =
                Fetcher::new(context.child("fetcher"), config);
            fetcher.reconcile(&[public_key, other_public_key]);
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                FailMockSender::default(),
            );

            // Add a key to pending
            fetcher.add_ready(MockKey(1));
            let _ = fetcher.fetch(&mut sender, |_| true); // won't be delivered
            let _ = fetcher.fetch(&mut sender, |_| true); // waiter activated

            // Check pending deadline
            assert_eq!(fetcher.len_pending(), 1);
            let pending_deadline = fetcher.get_pending_deadline().unwrap();
            assert!(pending_deadline > context.current());

            assert!(fetcher.remove(&MockKey(1)));
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
                timeout: Duration::from_secs(5),
                retry_timeout: Duration::from_millis(100),
                priority_requests: false,
            };
            let mut fetcher: Fetcher<_, _, MockKey, FailMockSender> =
                Fetcher::new(context.child("fetcher"), config);
            fetcher.reconcile(&[public_key, peer1.clone()]);
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                FailMockSender::default(),
            );

            // Block the peer we'll use as target, so fetch has no eligible participants
            fetcher.set_blocked([blocked_peer.clone()]);

            // Add key with targets pointing only to blocked peer
            fetcher.add_ready(MockKey(1));
            fetcher.add_targets(MockKey(1), [blocked_peer.clone()]);
            let _ = fetcher.fetch(&mut sender, |_| true);

            // Waiter should be set to far future (no eligible peers at all)
            assert!(fetcher.waiter.is_some());
            let waiter_time = fetcher.waiter.unwrap();
            assert!(waiter_time > context.current() + Duration::from_secs(1000));

            // Add targets should clear the waiter
            fetcher.add_targets(MockKey(1), [peer1]);
            assert!(fetcher.waiter.is_none());

            // Pending deadline should now be reasonable
            let deadline = fetcher.get_pending_deadline().unwrap();
            assert!(deadline <= context.current() + Duration::from_millis(100));

            // Set waiter again by targeting blocked peer
            fetcher.clear_targets(&MockKey(1));
            fetcher.add_targets(MockKey(1), [blocked_peer]);
            let _ = fetcher.fetch(&mut sender, |_| true);
            assert!(fetcher.waiter.is_some());

            // clear_targets should clear the waiter
            fetcher.clear_targets(&MockKey(1));
            assert!(fetcher.waiter.is_none());
        });
    }

    #[test]
    fn test_add_ready_clears_waiter_for_new_fetch() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer = PrivateKey::from_seed(1).public_key();
            let missing_peer = PrivateKey::from_seed(2).public_key();
            let config = Config {
                me: Some(public_key.clone()),
                timeout: Duration::from_secs(5),
                retry_timeout: Duration::from_millis(100),
                priority_requests: false,
            };
            let mut fetcher: Fetcher<_, _, MockKey, SuccessMockSender> =
                Fetcher::new(context.child("fetcher"), config);
            fetcher.reconcile(&[public_key, peer]);
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );

            fetcher.add_targets(MockKey(1), [missing_peer]);
            fetcher.add_ready(MockKey(1));
            let _ = fetcher.fetch(&mut sender, |_| true);
            assert!(fetcher.waiter.is_some());

            fetcher.add_ready(MockKey(2));
            assert_eq!(fetcher.get_pending_deadline(), Some(context.current()));

            let _ = fetcher.fetch(&mut sender, |_| true);
            assert!(fetcher.pending.contains(&MockKey(1)));
            assert!(!fetcher.pending.contains(&MockKey(2)));
            assert_eq!(fetcher.len_active(), 1);
        });
    }

    #[test]
    fn test_add_retry_clears_waiter_for_retry_deadline() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer = PrivateKey::from_seed(1).public_key();
            let missing_peer = PrivateKey::from_seed(2).public_key();
            let config = Config {
                me: Some(public_key.clone()),
                timeout: Duration::from_secs(5),
                retry_timeout: Duration::from_millis(100),
                priority_requests: false,
            };
            let mut fetcher: Fetcher<_, _, MockKey, SuccessMockSender> =
                Fetcher::new(context.child("fetcher"), config);
            fetcher.reconcile(&[public_key, peer]);
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );

            fetcher.add_targets(MockKey(1), [missing_peer]);
            fetcher.add_ready(MockKey(1));
            let _ = fetcher.fetch(&mut sender, |_| true);
            assert!(fetcher.waiter.is_some());

            fetcher.add_retry(MockKey(2));
            let deadline = fetcher.get_pending_deadline().unwrap();
            assert!(deadline <= context.current() + Duration::from_millis(100));

            context.sleep(Duration::from_millis(100)).await;
            let _ = fetcher.fetch(&mut sender, |_| true);
            assert!(fetcher.pending.contains(&MockKey(1)));
            assert!(!fetcher.pending.contains(&MockKey(2)));
            assert_eq!(fetcher.len_active(), 1);
        });
    }

    #[test]
    fn test_active_timeout_reenqueue_clears_waiter_for_retry_deadline() {
        fn run(fetch_first: bool) {
            let runner = Runner::default();
            runner.start(move |context| async move {
                let (mut fetcher, _) = create_unservable_fetcher(&context);
                add_test_active(&mut fetcher, 0, MockKey(2));

                if fetch_first {
                    let mut sender = WrappedSender::new(
                        context.network_buffer_pool().clone(),
                        SuccessMockSender::default(),
                    );
                    let _ = fetcher.fetch(&mut sender, |_| true);
                    assert!(fetcher.waiter.is_some());
                }

                let key = fetcher.pop_active().expect("active key should exist");
                fetcher.add_retry(key);
                let deadline = fetcher.get_pending_deadline().unwrap();
                assert!(deadline <= context.current() + Duration::from_millis(100));

                let mut sender = WrappedSender::new(
                    context.network_buffer_pool().clone(),
                    SuccessMockSender::default(),
                );
                let _ = fetcher.fetch(&mut sender, |_| true);
                assert!(fetcher.pending.contains(&MockKey(1)));
                assert!(!fetcher.pending.contains(&MockKey(2)));
                assert_eq!(fetcher.len_active(), 1);
            });
        }

        run(true);
        run(false);
    }

    #[test]
    fn test_add_targets_clears_waiter_for_new_target() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, peer) = create_unservable_fetcher(&context);
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );

            let _ = fetcher.fetch(&mut sender, |_| true);
            assert!(fetcher.waiter.is_some());

            fetcher.add_targets(MockKey(1), [peer]);
            assert_eq!(fetcher.get_pending_deadline(), Some(context.current()));

            let _ = fetcher.fetch(&mut sender, |_| true);
            assert!(!fetcher.pending.contains(&MockKey(1)));
            assert_eq!(fetcher.len_active(), 1);
        });
    }

    #[test]
    fn test_clear_targets_clears_waiter_for_fallback() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, _) = create_unservable_fetcher(&context);
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );

            let _ = fetcher.fetch(&mut sender, |_| true);
            assert!(fetcher.waiter.is_some());

            fetcher.clear_targets(&MockKey(1));
            assert_eq!(fetcher.get_pending_deadline(), Some(context.current()));

            let _ = fetcher.fetch(&mut sender, |_| true);
            assert!(!fetcher.pending.contains(&MockKey(1)));
            assert_eq!(fetcher.len_active(), 1);
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
                timeout: Duration::from_secs(5),
                retry_timeout,
                priority_requests: false,
            };
            let mut fetcher: Fetcher<_, _, MockKey, FailMockSender> =
                Fetcher::new(context.child("fetcher"), config);
            // Add peers (FailMockSender doesn't rate limit, just fails sends)
            fetcher.reconcile(&[public_key, peer1, peer2]);
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                FailMockSender::default(),
            );

            // Add key and attempt fetch - all sends will fail
            fetcher.add_ready(MockKey(1));
            let _ = fetcher.fetch(&mut sender, |_| true);

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
            let _ = fetcher.fetch(&mut sender, |_| true);
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

            // Removing a fetch clears its targets.
            fetcher.add_targets(MockKey(1), [peer1.clone()]);
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
            assert_eq!(fetcher.targets.len(), 2);

            assert!(fetcher.remove(&MockKey(1)));
            assert!(!fetcher.targets.contains_key(&MockKey(1)));
            assert!(fetcher.targets.contains_key(&MockKey(2)));

            assert!(fetcher.remove(&MockKey(2)));
            assert!(fetcher.targets.is_empty());

            // Removing every fetch clears all of their targets.
            fetcher.add_targets(MockKey(1), [peer1.clone(), peer2.clone()]);
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_targets(MockKey(3), [peer2]);
            assert_eq!(fetcher.targets.len(), 3);

            for key in [MockKey(1), MockKey(2), MockKey(3)] {
                assert!(fetcher.remove(&key));
            }
            assert!(fetcher.targets.is_empty());

            // Removing selected fetches clears only their targets.
            fetcher.add_targets(MockKey(1), [peer1.clone()]);
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_targets(MockKey(10), [peer1.clone()]);
            fetcher.add_targets(MockKey(20), [peer1]);
            assert_eq!(fetcher.targets.len(), 4);

            assert!(fetcher.remove(&MockKey(10)));
            assert!(fetcher.remove(&MockKey(20)));
            assert_eq!(fetcher.targets.len(), 2);
            assert!(fetcher.targets.contains_key(&MockKey(1)));
            assert!(fetcher.targets.contains_key(&MockKey(2)));
            assert!(!fetcher.targets.contains_key(&MockKey(10)));
            assert!(!fetcher.targets.contains_key(&MockKey(20)));
        });
    }

    #[test]
    fn test_blocked_peers_keep_targets_until_unblocked() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.child("fetcher"));
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone()]);
            fetcher.add_targets(MockKey(1), [peer1.clone()]);
            fetcher.add_targets(MockKey(2), [peer1.clone(), peer2.clone()]);

            // A blocked peer keeps its place in every target set but is not eligible.
            fetcher.set_blocked([peer1.clone()]);
            assert!(fetcher.targets.get(&MockKey(1)).unwrap().contains(&peer1));
            assert!(fetcher.get_eligible_peers(&MockKey(1), false).is_empty());
            assert_eq!(fetcher.get_eligible_peers(&MockKey(2), false), vec![peer2]);

            // Lifting the block makes the peer eligible again and wakes the fetcher.
            fetcher.waiter = Some(context.current());
            fetcher.set_blocked([]);
            assert!(fetcher.waiter.is_none());
            assert_eq!(fetcher.get_eligible_peers(&MockKey(1), false), vec![peer1]);
        });
    }

    #[test]
    fn test_target_behavior_on_send_failure() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context.child("fetcher"));
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            let peer3 = PrivateKey::from_seed(3).public_key();
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone(), peer3]);
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                FailMockSender::default(),
            );

            // Add targets and attempt fetch
            fetcher.add_targets(MockKey(2), [peer1, peer2]);
            fetcher.add_ready(MockKey(2));
            assert_eq!(fetcher.targets.get(&MockKey(2)).unwrap().len(), 2);
            let _ = fetcher.fetch(&mut sender, |_| true);
            // Both targets should still be present (not removed on send failure)
            assert_eq!(fetcher.targets.get(&MockKey(2)).unwrap().len(), 2);
            assert!(fetcher.pending.contains(&MockKey(2)));
        });
    }

    #[test]
    fn test_target_retention_on_pop() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.child("fetcher"));
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone()]);
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );

            // Timeout does not remove target
            fetcher.add_targets(MockKey(1), [peer1.clone(), peer2.clone()]);
            fetcher.add_ready(MockKey(1));
            assert_eq!(fetcher.targets.get(&MockKey(1)).unwrap().len(), 2);
            let _ = fetcher.fetch(&mut sender, |_| true);
            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(fetcher.pop_active(), Some(MockKey(1)));
            // Both targets should still be present after timeout
            assert_eq!(fetcher.targets.get(&MockKey(1)).unwrap().len(), 2);
            fetcher.targets.clear();

            // Error response ("no data") does not remove target
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_ready(MockKey(2));
            let _ = fetcher.fetch(&mut sender, |_| true);
            let id = *fetcher.active.iter().next().unwrap().0;
            assert_eq!(fetcher.pop_missing(id, &peer1), Some(MockKey(2)));
            // Target should still be present after "no data" response
            assert!(fetcher.targets.get(&MockKey(2)).unwrap().contains(&peer1));
            fetcher.targets.clear();

            // Data response also preserves targets
            // (caller must clear targets after data validation)
            fetcher.add_targets(MockKey(3), [peer1.clone()]);
            fetcher.add_ready(MockKey(3));
            let _ = fetcher.fetch(&mut sender, |_| true);
            let id = *fetcher.active.iter().next().unwrap().0;
            assert_eq!(
                fetcher.pop_response(id, &peer1).map(|(key, _)| key),
                Some(MockKey(3))
            );
            assert!(fetcher.targets.get(&MockKey(3)).unwrap().contains(&peer1));
        });
    }

    #[test]
    fn test_no_fallback_when_targets_unavailable() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.child("fetcher"));
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
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );
            let _ = fetcher.fetch(&mut sender, |_| true);

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
                timeout: Duration::from_secs(5),
                retry_timeout: Duration::from_millis(100),
                priority_requests: false,
            };
            let mut fetcher: Fetcher<_, _, MockKey, LimitedMockSender<Context>> =
                Fetcher::new(context.child("fetcher"), config);
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone()]);
            let quota = Quota::per_second(NZU32!(1));
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                LimitedMockSender::new(quota, context.child("rate_limiter")),
            );

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
            let _ = fetcher.fetch(&mut sender, |_| true);
            assert_eq!(fetcher.len_active(), 1);
            assert_eq!(fetcher.len_pending(), 2);
            assert!(!fetcher.pending.contains(&MockKey(1))); // MockKey(1) was fetched

            // Second fetch: MockKey(2) is blocked (peer1 rate-limited), should skip to MockKey(3)
            let _ = fetcher.fetch(&mut sender, |_| true);
            assert_eq!(fetcher.len_active(), 2);
            assert_eq!(fetcher.len_pending(), 1);
            assert!(fetcher.pending.contains(&MockKey(2))); // MockKey(2) is still pending
            assert!(!fetcher.pending.contains(&MockKey(3))); // MockKey(3) was fetched

            // Third fetch: only MockKey(2) remains, but peer1 is still rate-limited
            let _ = fetcher.fetch(&mut sender, |_| true);
            assert_eq!(fetcher.len_active(), 2); // No change
            assert_eq!(fetcher.len_pending(), 1); // MockKey(2) still pending
            assert!(fetcher.waiter.is_some()); // Waiter set

            // Wait for rate limit to reset
            context.sleep(Duration::from_secs(1)).await;

            // Now MockKey(2) can be fetched
            let _ = fetcher.fetch(&mut sender, |_| true);
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

            // Add peers with zero initial throughput
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone(), peer3.clone()]);

            // Simulate different response times by updating performance:
            // - peer1: very fast (10ms)
            // - peer2: slow (500ms)
            // - peer3: medium (200ms)
            // After update_performance with EMA: new = (past + throughput) / 2

            // peer1: simulate multiple fast responses to raise its throughput
            for _ in 0..5 {
                fetcher.update_performance(&peer1, throughput(Duration::from_millis(10), 1));
            }

            // peer2: simulate slow responses to keep its throughput low
            for _ in 0..5 {
                fetcher.update_performance(&peer2, throughput(Duration::from_millis(500), 1));
            }

            // peer3: simulate medium responses
            for _ in 0..5 {
                fetcher.update_performance(&peer3, throughput(Duration::from_millis(200), 1));
            }

            // Get eligible peers - should be ordered best first (highest throughput)
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
