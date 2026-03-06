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
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
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

/// Tracks an active request that has been sent to one or more peers.
///
/// For [`Regular`](crate::RequestType::Regular) requests, `peers` contains a
/// single entry. For [`Urgent`](crate::RequestType::Urgent) requests, `peers`
/// contains every peer the request was fanned out to, along with the time
/// that peer was sent the request. As peers respond, they are removed from
/// the map; when it is empty the request is considered exhausted and eligible
/// for retry.
struct ActiveRequest<P, Key> {
    key: Key,
    peers: HashMap<P, SystemTime>,
}

/// Outcome of attempting to start a single pending request.
///
/// Returned by [`start_pending_request`](Fetcher::start_pending_request) to
/// inform the caller how to update the waiter and escalation state.
#[derive(Default)]
struct PendingAttempt {
    /// The request was sent to at least one peer and moved to active.
    started: bool,
    /// At least one eligible peer existed (independent of send outcome).
    found_eligible_peers: bool,
    /// Earliest rate-limit expiry among peers that could not be sent to.
    earliest_rate_limit: Option<SystemTime>,
}

/// Desired escalation scheduling for an urgent key.
enum UrgentTrigger {
    /// Remove any pending escalation.
    Clear,
    /// Schedule an immediate escalation (deadline = now).
    Immediate,
    /// Schedule escalation at the given rate-limit expiry time.
    RateLimited(SystemTime),
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
///
/// # Regular vs Urgent Requests
///
/// A [`Regular`](crate::RequestType::Regular) request sends to the single best-performing peer.
/// An [`Urgent`](crate::RequestType::Urgent) request fans out to every eligible peer under the
/// same request ID. Urgency is a one-way upgrade (never downgraded) and is cleared on resolution
/// or cancellation.
///
/// For urgent requests, [`pop_by_id`](Self::pop_by_id) returns `exhausted = false` until every
/// peer in the fan-out has responded. The caller should only retry when `exhausted` is true.
/// Peers whose responses arrive after the key is canceled (e.g. because a faster peer already
/// provided valid data) are silently dropped without performance updates.
///
/// When an urgent fan-out is partially blocked by outbound rate limits, the fetcher schedules a
/// retry via [`escalation_pending`](Self::escalation_pending) for when the earliest rate limit
/// expires.
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

    /// If no peers are ready to handle the currently-due requests (all filtered out or send
    /// failed), the waiter is set to the next time those requests should be retried.
    ///
    /// The waiter is always clamped by the earliest request that was not part of the last
    /// attempted due snapshot, so later pending deadlines cannot be starved.
    waiter: Option<SystemTime>,

    /// Urgent fetches that should be retried when additional peers exit rate limiting.
    ///
    /// This can apply to keys that are still active or have timed out into pending.
    escalation_pending: PrioritySet<Key, SystemTime>,

    /// How long fetches remain in the pending queue before being retried
    retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages
    priority_requests: bool,

    /// Per-key target peers restricting which peers are used to fetch each key.
    /// Only target peers are tried, waiting for them if unavailable. There is no
    /// fallback to other peers. Targets persist through transient failures, they are
    /// only removed when blocked (invalid data) or cleared on successful fetch.
    targets: HashMap<Key, HashSet<P>>,

    /// Keys that should fan out to every eligible peer instead of only the best one.
    /// A key's urgent flag is cleared when the fetch resolves or is canceled
    /// ([`cancel`](Self::cancel)).
    urgent: HashSet<Key>,

    /// Per-peer performance metric (exponential moving average of response time in ms)
    performance: Family<Peer, Gauge>,

    /// Status of request creation attempts (Success when eligible peers exist, Dropped otherwise)
    requests_created: status::Counter,

    /// Status of individual network requests sent to peers
    requests_sent: status::Counter,

    /// Number of fetches escalated to urgent handling
    requests_escalated: Counter,

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
        let requests_escalated = Counter::default();
        context.register(
            "requests_escalated",
            "Number of fetches escalated to urgent handling",
            requests_escalated.clone(),
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
            escalation_pending: PrioritySet::new(),
            retry_timeout: config.retry_timeout,
            priority_requests: config.priority_requests,
            targets: HashMap::new(),
            urgent: HashSet::new(),
            performance,
            requests_created,
            requests_sent,
            requests_escalated,
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
        self.retry_due_escalations(sender).await;
        let now = self.context.current();
        if self.waiter.is_some_and(|waiter| waiter > now) {
            return;
        }

        // Collect only pending keys whose retry deadline has arrived.
        let pending_keys: Vec<(Key, bool)> = self
            .pending
            .iter()
            .take_while(|(_, (deadline, _))| *deadline <= now)
            .map(|(k, (_, retry))| (k.clone(), *retry))
            .collect();
        if pending_keys.is_empty() {
            return;
        }
        let next_unattempted_pending_deadline = self
            .pending
            .iter()
            .find_map(|(_, (deadline, _))| (*deadline > now).then_some(*deadline));

        self.waiter = None;

        // Try each pending key until one succeeds
        let mut earliest_rate_limit: Option<SystemTime> = None;
        let mut found_eligible_peers = false;
        for (key, retry) in pending_keys {
            let attempt = self.start_pending_request(&key, retry, sender).await;
            self.sync_urgent_after_pending_attempt(&key, &attempt);
            if attempt.started {
                return;
            }
            earliest_rate_limit = match (earliest_rate_limit, attempt.earliest_rate_limit) {
                (Some(current), Some(next)) => Some(current.min(next)),
                (deadline, None) | (None, deadline) => deadline,
            };
            found_eligible_peers |= attempt.found_eligible_peers;
        }

        // Set waiter for next fetch attempt
        let waiter = if let Some(rate_limit_time) = earliest_rate_limit {
            // Use rate limit expiry time
            rate_limit_time
        } else if found_eligible_peers {
            // Peers exist but all sends failed - use retry timeout
            self.context.current() + self.retry_timeout
        } else {
            // No eligible peers - wait for external changes
            self.context.current().saturating_add_ext(Duration::MAX)
        };
        self.waiter =
            Some(next_unattempted_pending_deadline.map_or(waiter, |deadline| waiter.min(deadline)));
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
        self.urgent.retain(&predicate);
        self.escalation_pending.retain(|key| {
            predicate(key)
                && self.urgent.contains(key)
                && (self.pending.contains(key) || self.key_to_id.contains_key(key))
        });

        // Clear waiter since the key that caused it may have been removed
        self.waiter = None;
    }

    /// Marks a key as urgent.
    ///
    /// Returns `true` when this upgraded the key from regular to urgent.
    pub fn mark_urgent(&mut self, key: Key) -> bool {
        self.urgent.insert(key)
    }

    /// Returns whether the key is urgent.
    pub fn is_urgent(&self, key: &Key) -> bool {
        self.urgent.contains(key)
    }

    /// Updates the escalation trigger for an urgent tracked key.
    fn sync_urgent_trigger(&mut self, key: &Key, trigger: UrgentTrigger) {
        if !self.is_urgent(key) || !self.is_tracked(key) {
            self.escalation_pending.remove(key);
            return;
        }

        match trigger {
            UrgentTrigger::Clear => {
                self.escalation_pending.remove(key);
            }
            UrgentTrigger::Immediate => {
                self.escalation_pending
                    .put(key.clone(), self.context.current());
            }
            UrgentTrigger::RateLimited(deadline) => {
                self.escalation_pending.put(key.clone(), deadline);
            }
        }
    }

    /// Updates urgent escalation state after trying to start a pending request.
    ///
    /// If no eligible peers exist, we clear the escalation and wait for an
    /// external topology or target change to wake the urgent key.
    fn sync_urgent_after_pending_attempt(&mut self, key: &Key, attempt: &PendingAttempt) {
        let trigger = if let Some(not_until) = attempt.earliest_rate_limit {
            UrgentTrigger::RateLimited(not_until)
        } else {
            UrgentTrigger::Clear
        };
        self.sync_urgent_trigger(key, trigger);
    }

    /// Wakes a tracked urgent key for an immediate escalation attempt.
    fn wake_urgent_escalation(&mut self, key: &Key) {
        if self.is_tracked(key) {
            self.sync_urgent_trigger(key, UrgentTrigger::Immediate);
        }
    }

    /// Wakes all tracked urgent keys for an immediate escalation attempt.
    fn wake_urgent_escalations(&mut self) {
        let keys: Vec<_> = self
            .urgent
            .iter()
            .filter(|key| self.is_tracked(key))
            .cloned()
            .collect();
        for key in keys {
            self.sync_urgent_trigger(&key, UrgentTrigger::Immediate);
        }
    }

    /// Re-prioritizes an urgent fetch immediately, preserving in-flight work.
    ///
    /// If the key is pending, it is moved to the front of the queue. If the
    /// key is active, the existing request ID is kept alive and the same ID is
    /// fanned out to any additional eligible peers that have not already seen it.
    pub async fn escalate(
        &mut self,
        key: &Key,
        sender: &mut WrappedSender<NetS, wire::Message<Key>>,
    ) {
        if !self.is_tracked(key) {
            return;
        }

        self.urgent.insert(key.clone());
        self.requests_escalated.inc();
        self.sync_urgent_trigger(key, UrgentTrigger::Clear);

        if self.pending.contains(key) {
            self.pending
                .put(key.clone(), (self.context.current(), false));
            self.waiter = None;
            return;
        }

        let Some(id) = self.key_to_id.get(key).copied() else {
            return;
        };
        let Some(existing) = self.requests.get(&id) else {
            return;
        };
        let sent_already: HashSet<_> = existing.peers.keys().cloned().collect();
        let peers = self.get_eligible_peers(key, false);
        let message = wire::Message {
            id,
            payload: wire::Payload::Request(key.clone()),
        };
        let mut sent_now = Vec::new();
        let mut earliest_rate_limit: Option<SystemTime> = None;

        for peer in peers {
            if sent_already.contains(&peer) {
                continue;
            }

            let checked = match sender.check(Recipients::One(peer.clone())).await {
                Ok(checked) => checked,
                Err(not_until) => {
                    earliest_rate_limit =
                        Some(earliest_rate_limit.map_or(not_until, |t| t.min(not_until)));
                    continue;
                }
            };

            match checked.send(message.clone(), self.priority_requests).await {
                Ok(sent) if !sent.is_empty() => {
                    let now = self.context.current();
                    self.requests_sent
                        .inc_by(Status::Success, sent.len() as u64);
                    sent_now.extend(sent.into_iter().map(|peer| (peer, now)));
                }
                Ok(_) => {
                    self.requests_sent.inc(Status::Dropped);
                    debug!(?peer, "send returned empty");
                    self.update_performance(&peer, self.timeout);
                }
                Err(err) => {
                    self.requests_sent.inc(Status::Failure);
                    debug!(?err, ?peer, "send failed");
                    self.update_performance(&peer, self.timeout);
                }
            }
        }

        if let Some(not_until) = earliest_rate_limit {
            self.sync_urgent_trigger(key, UrgentTrigger::RateLimited(not_until));
        }

        if sent_now.is_empty() {
            return;
        }

        let now = self.context.current();
        let deadline = now.checked_add(self.timeout).expect("time overflowed");
        self.active.put(id, deadline);
        let req = self
            .requests
            .get_mut(&id)
            .expect("active request must exist");
        req.peers.extend(sent_now);
    }

    fn clear_request_state(&mut self, key: &Key) {
        self.clear_targets(key);
        self.urgent.remove(key);
        self.escalation_pending.remove(key);
    }

    /// Returns whether the key is currently tracked (pending or active).
    pub fn is_tracked(&self, key: &Key) -> bool {
        self.pending.contains(key) || self.key_to_id.contains_key(key)
    }

    fn remove_active_request(&mut self, id: ID) -> Option<ActiveRequest<P, Key>> {
        self.active.remove(&id);
        let req = self.requests.remove(&id)?;
        self.key_to_id.remove(&req.key);
        Some(req)
    }

    /// Cancels a fetch request.
    ///
    /// Returns `true` if the fetch was canceled. Always clears per-key metadata
    /// (targets, urgent flag, escalation) even if the active request was already
    /// removed by [`pop_by_id`](Self::pop_by_id).
    pub fn cancel(&mut self, key: &Key) -> bool {
        let existed = self.is_tracked(key);
        self.remove_request(key);
        self.clear_request_state(key);
        existed
    }

    /// Cancel all fetches.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.active.clear();
        self.requests.clear();
        self.key_to_id.clear();
        self.escalation_pending.clear();
        self.targets.clear();
        self.urgent.clear();
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
        let pending_deadline = if let Some((_, (deadline, _))) = self.pending.peek() {
            let deadline = *deadline;
            Some(self.waiter.map_or(deadline, |w| deadline.max(w)))
        } else {
            None
        };
        let escalation_deadline = self
            .escalation_pending
            .peek()
            .map(|(_, deadline)| *deadline);

        match (pending_deadline, escalation_deadline) {
            (Some(pending_deadline), Some(escalation_deadline)) => {
                Some(pending_deadline.min(escalation_deadline))
            }
            (deadline, None) | (None, deadline) => deadline,
        }
    }

    /// Returns the deadline for the next active request timeout.
    pub fn get_active_deadline(&self) -> Option<SystemTime> {
        self.active.peek().map(|(_, deadline)| *deadline)
    }

    /// Removes and returns the key with the next request timeout.
    ///
    /// Targets are not removed on timeout.
    pub fn pop_active(&mut self) -> Option<Key> {
        let (id, _) = self.active.pop()?;
        let req = self.remove_active_request(id)?;
        for peer in req.peers.keys() {
            self.update_performance(peer, self.timeout);
        }

        Some(req.key)
    }

    async fn retry_due_escalations(
        &mut self,
        sender: &mut WrappedSender<NetS, wire::Message<Key>>,
    ) {
        let now = self.context.current();
        let keys: Vec<_> = self
            .escalation_pending
            .iter()
            .take_while(|(_, deadline)| **deadline <= now)
            .map(|(key, _)| key.clone())
            .collect();

        for key in keys {
            self.escalation_pending.remove(&key);
            if self.key_to_id.contains_key(&key) {
                self.escalate(&key, sender).await;
                continue;
            }

            if self.pending.contains(&key) {
                let attempt = self.start_pending_request(&key, false, sender).await;
                self.sync_urgent_after_pending_attempt(&key, &attempt);
            }
        }
    }

    async fn start_pending_request(
        &mut self,
        key: &Key,
        retry: bool,
        sender: &mut WrappedSender<NetS, wire::Message<Key>>,
    ) -> PendingAttempt {
        let peers = self.get_eligible_peers(key, retry);
        if peers.is_empty() {
            self.requests_created.inc(Status::Dropped);
            return PendingAttempt::default();
        }

        self.requests_created.inc(Status::Success);
        let urgent = self.is_urgent(key);
        let id = self.next_id();
        let message = wire::Message {
            id,
            payload: wire::Payload::Request(key.clone()),
        };
        let mut sent_peers = HashMap::new();
        let mut earliest_rate_limit: Option<SystemTime> = None;

        // Regular requests stop at the first successful send. Urgent requests
        // fan out the same request ID to every eligible peer.
        for peer in peers {
            let checked = match sender.check(Recipients::One(peer.clone())).await {
                Ok(checked) => checked,
                Err(not_until) => {
                    earliest_rate_limit =
                        Some(earliest_rate_limit.map_or(not_until, |t| t.min(not_until)));
                    continue;
                }
            };

            match checked.send(message.clone(), self.priority_requests).await {
                Ok(sent) if !sent.is_empty() => {
                    let sent_at = self.context.current();
                    self.requests_sent
                        .inc_by(Status::Success, sent.len() as u64);
                    sent_peers.extend(sent.into_iter().map(|peer| (peer, sent_at)));
                    if !urgent {
                        break;
                    }
                }
                Ok(_) => {
                    self.requests_sent.inc(Status::Dropped);
                    debug!(?peer, "send returned empty");
                    self.update_performance(&peer, self.timeout);
                }
                Err(err) => {
                    self.requests_sent.inc(Status::Failure);
                    debug!(?err, ?peer, "send failed");
                    self.update_performance(&peer, self.timeout);
                }
            }
        }

        if sent_peers.is_empty() {
            return PendingAttempt {
                started: false,
                found_eligible_peers: true,
                earliest_rate_limit,
            };
        }

        self.pending.remove(key);
        let deadline = self
            .context
            .current()
            .checked_add(self.timeout)
            .expect("time overflowed");
        self.active.put(id, deadline);
        self.requests.insert(
            id,
            ActiveRequest {
                key: key.clone(),
                peers: sent_peers,
            },
        );
        self.key_to_id.insert(key.clone(), id);
        PendingAttempt {
            started: true,
            found_eligible_peers: true,
            earliest_rate_limit,
        }
    }

    /// Removes a key from pending or active state without clearing per-key metadata.
    fn remove_request(&mut self, key: &Key) {
        if self.pending.remove(key) {
            return;
        }
        if let Some(id) = self.key_to_id.get(key).copied() {
            self.remove_active_request(id);
        }
    }

    /// Processes a response from a peer.
    ///
    /// Returns `(key, exhausted)` where `exhausted` is true when every peer
    /// that was sent this request has now responded (or been removed). The
    /// caller should only retry the key when `exhausted` is true, to avoid
    /// redundant retries while other peers are still in flight.
    ///
    /// Returns `None` if the response ID is unknown or the peer was not
    /// part of this request (unsolicited or duplicate response).
    ///
    /// Targets are not removed here, regardless of response type. Targets persist through
    /// "no data" responses (peer might get data later). On valid data response, caller
    /// should call [`cancel`](Self::cancel). On invalid data, caller should block the
    /// peer which removes them from all target sets.
    pub fn pop_by_id(&mut self, id: ID, peer: &P, has_response: bool) -> Option<(Key, bool)> {
        let (key, exhausted, elapsed) = {
            // Confirm ID exists and the peer is still outstanding for it.
            let req = self.requests.get_mut(&id)?;
            let start = req.peers.remove(peer)?;
            let elapsed = has_response.then(|| {
                self.context
                    .current()
                    .duration_since(start)
                    .unwrap_or_default()
            });
            (req.key.clone(), req.peers.is_empty(), elapsed)
        };

        if let Some(elapsed) = elapsed {
            self.update_performance(peer, elapsed);
            self.resolves.observe(elapsed.as_secs_f64());
        } else {
            self.update_performance(peer, self.timeout);
        }

        if exhausted {
            self.remove_active_request(id);
        }

        Some((key, exhausted))
    }

    /// Reconciles the list of peers that can be used to fetch data.
    pub fn reconcile(&mut self, keep: &[P]) {
        let expanded = keep.iter().any(|peer| !self.participants.contains(peer));
        self.participants.reconcile(keep, self.initial.as_millis());
        if expanded {
            self.wake_urgent_escalations();
        }

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
    /// Clears the waiter and wakes urgent tracked fetches to retry target changes immediately.
    pub fn add_targets(&mut self, key: Key, peers: impl IntoIterator<Item = P>) {
        self.targets.entry(key.clone()).or_default().extend(peers);
        self.wake_urgent_escalation(&key);

        // Clear waiter to allow retry with new targets
        self.waiter = None;
    }

    /// Clear targeting for a key.
    ///
    /// If there is an ongoing fetch for this key, it will try any available peer instead
    /// of being restricted to targets. Also used to clean up targets after a successful
    /// or cancelled fetch.
    ///
    /// Clears the waiter and wakes urgent tracked fetches to retry without targets immediately.
    pub fn clear_targets(&mut self, key: &Key) {
        self.targets.remove(key);
        self.wake_urgent_escalation(key);

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::mocks::Key as MockKey;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_p2p::{utils::codec::WrappedSender, LimitedSender, Recipients, UnlimitedSender};
    use commonware_runtime::{
        deterministic::{self, Context, Runner},
        BufferPooler, IoBufs, KeyedRateLimiter, Quota, Runner as _,
    };
    use commonware_utils::{sync::RwLock, NZU32};
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
            message: impl Into<IoBufs> + Send,
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
            _message: impl Into<IoBufs> + Send,
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
            _message: impl Into<IoBufs> + Send,
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

    #[derive(Clone)]
    struct DelayedSuccessMockSenderInner {
        context: Context,
        delay: Duration,
    }

    impl DelayedSuccessMockSenderInner {
        fn new(context: Context, delay: Duration) -> Self {
            Self { context, delay }
        }
    }

    impl UnlimitedSender for DelayedSuccessMockSenderInner {
        type PublicKey = PublicKey;
        type Error = MockError;

        async fn send(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
            _message: impl Into<IoBufs> + Send,
            _priority: bool,
        ) -> Result<Vec<Self::PublicKey>, Self::Error> {
            self.context.sleep(self.delay).await;
            match recipients {
                Recipients::One(peer) => Ok(vec![peer]),
                _ => unimplemented!(),
            }
        }
    }

    #[derive(Clone)]
    struct DelayedSuccessMockSender(DelayedSuccessMockSenderInner);

    impl DelayedSuccessMockSender {
        fn new(context: Context, delay: Duration) -> Self {
            Self(DelayedSuccessMockSenderInner::new(context, delay))
        }
    }

    impl LimitedSender for DelayedSuccessMockSender {
        type PublicKey = PublicKey;
        type Checked<'a> = CheckedSender<'a, DelayedSuccessMockSenderInner>;

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
                peers: HashMap::from([(peer, now)]),
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
            assert!(!fetcher.is_tracked(&MockKey(1)));

            // Test canceling active key
            assert!(fetcher.cancel(&MockKey(10)));
            assert_eq!(fetcher.len_active(), 1);
            assert!(!fetcher.is_tracked(&MockKey(10)));

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
            assert!(!fetcher.is_tracked(&MockKey(1)));

            // Add to pending
            fetcher.add_retry(MockKey(1));
            assert!(fetcher.is_tracked(&MockKey(1)));

            // Add to active
            add_test_active(&mut fetcher, 100, MockKey(10));
            assert!(fetcher.is_tracked(&MockKey(10)));

            // Test non-existent key
            assert!(!fetcher.is_tracked(&MockKey(99)));

            // Remove from pending
            fetcher.pending.remove(&MockKey(1));
            assert!(!fetcher.is_tracked(&MockKey(1)));

            // Remove from active via cancel
            fetcher.cancel(&MockKey(10));
            assert!(!fetcher.is_tracked(&MockKey(10)));
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
            assert!(fetcher.is_tracked(&MockKey(1)));

            // Add second key
            fetcher.add_retry(MockKey(2));
            assert_eq!(fetcher.len_pending(), 2);
            assert!(fetcher.is_tracked(&MockKey(2)));

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
    fn test_pop_active() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let key = MockKey(10);
            let target = PrivateKey::from_seed(2).public_key();

            add_test_active(&mut fetcher, 100, key.clone());
            fetcher.mark_urgent(key.clone());
            fetcher.add_targets(key.clone(), [target]);
            fetcher.escalation_pending.put(
                key.clone(),
                fetcher.context.current() + Duration::from_secs(1),
            );

            assert_eq!(fetcher.pop_active(), Some(key.clone()));
            assert_eq!(fetcher.len_active(), 0);
            assert!(!fetcher.key_to_id.contains_key(&key));
            assert!(fetcher.is_urgent(&key));
            assert!(fetcher.has_targets(&key));
            assert!(fetcher.escalation_pending.contains(&key));
        });
    }

    #[test]
    fn test_pop_by_id() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let dummy_peer = PrivateKey::from_seed(1).public_key();
            let key = MockKey(10);
            let target = PrivateKey::from_seed(2).public_key();

            // Add key to active state
            add_test_active(&mut fetcher, 100, key.clone());
            fetcher.mark_urgent(key.clone());
            fetcher.add_targets(key.clone(), [target]);
            fetcher.escalation_pending.put(
                key.clone(),
                fetcher.context.current() + Duration::from_secs(1),
            );

            // Test pop with non-existent ID
            assert!(fetcher.pop_by_id(999, &dummy_peer, true).is_none());

            // The active entry should still be there since the ID wasn't found
            assert_eq!(fetcher.len_active(), 1);

            // Test pop with correct ID and peer
            assert_eq!(
                fetcher.pop_by_id(100, &dummy_peer, true),
                Some((key.clone(), true))
            );
            assert_eq!(fetcher.len_active(), 0);
            assert!(!fetcher.key_to_id.contains_key(&key));
            assert!(fetcher.is_urgent(&key));
            assert!(fetcher.has_targets(&key));
            assert!(fetcher.escalation_pending.contains(&key));
        });
    }

    #[test]
    fn test_cancel_clears_request_metadata() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let key = MockKey(11);
            let target = PrivateKey::from_seed(2).public_key();

            add_test_active(&mut fetcher, 101, key.clone());
            fetcher.mark_urgent(key.clone());
            fetcher.add_targets(key.clone(), [target]);
            fetcher.escalation_pending.put(
                key.clone(),
                fetcher.context.current() + Duration::from_secs(1),
            );

            assert!(fetcher.cancel(&key));
            assert_eq!(fetcher.len_active(), 0);
            assert!(!fetcher.key_to_id.contains_key(&key));
            assert!(!fetcher.is_urgent(&key));
            assert!(!fetcher.has_targets(&key));
            assert!(!fetcher.escalation_pending.contains(&key));
        });
    }

    #[test]
    fn test_reconcile_and_block() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();

            assert_eq!(fetcher.len_blocked(), 0);

            fetcher.reconcile(&[peer1.clone(), peer2]);
            fetcher.block(peer1);
            assert_eq!(fetcher.len_blocked(), 1);
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
            assert!(fetcher.is_tracked(&MockKey(2)));
            assert!(fetcher.is_tracked(&MockKey(20)));

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
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                FailMockSender::default(),
            );

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
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                FailMockSender::default(),
            );

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
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                FailMockSender::default(),
            );

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
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                FailMockSender::default(),
            );

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
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );

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
            assert_eq!(
                fetcher.pop_by_id(id, &peer1, false),
                Some((MockKey(2), true))
            );
            // Target should still be present after "no data" response
            assert!(fetcher.targets.get(&MockKey(2)).unwrap().contains(&peer1));
            fetcher.targets.clear();

            // Data response also preserves targets
            // (caller must clear targets after data validation)
            fetcher.add_targets(MockKey(3), [peer1.clone()]);
            fetcher.add_ready(MockKey(3));
            fetcher.fetch(&mut sender).await;
            let id = *fetcher.active.iter().next().unwrap().0;
            assert_eq!(
                fetcher.pop_by_id(id, &peer1, true),
                Some((MockKey(3), true))
            );
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
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );
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
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                LimitedMockSender::new(quota, context.clone()),
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

    #[test]
    fn test_successful_completion_does_not_update_remaining_in_flight_peer_performance() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context.clone());
            let winner = PrivateKey::from_seed(1).public_key();
            let loser = PrivateKey::from_seed(2).public_key();
            let key = MockKey(9);
            let id = 42;
            let start = context.current();
            let deadline = start + Duration::from_secs(5);

            fetcher.reconcile(&[winner.clone(), loser.clone()]);
            fetcher.active.put(id, deadline);
            fetcher.requests.insert(
                id,
                ActiveRequest {
                    key: key.clone(),
                    peers: HashMap::from([(winner.clone(), start), (loser.clone(), start)]),
                },
            );
            fetcher.key_to_id.insert(key.clone(), id);

            context.sleep(Duration::from_millis(80)).await;
            assert_eq!(
                fetcher.pop_by_id(id, &winner, true),
                Some((key.clone(), false))
            );
            assert_eq!(fetcher.participants.get(&winner), Some(90));

            assert!(fetcher.cancel(&key));

            assert_eq!(fetcher.participants.get(&winner), Some(90));
            assert_eq!(fetcher.participants.get(&loser), Some(100));
            assert!(!fetcher.requests.contains_key(&id));
            assert!(!fetcher.key_to_id.contains_key(&key));
        });
    }

    #[test]
    fn test_cancel_does_not_update_in_flight_peer_performance() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context.clone());
            let peer = PrivateKey::from_seed(1).public_key();
            let key = MockKey(10);
            let id = 43;
            let start = context.current();
            let deadline = start + Duration::from_secs(5);

            fetcher.reconcile(std::slice::from_ref(&peer));
            fetcher.active.put(id, deadline);
            fetcher.requests.insert(
                id,
                ActiveRequest {
                    key: key.clone(),
                    peers: HashMap::from([(peer.clone(), start)]),
                },
            );
            fetcher.key_to_id.insert(key.clone(), id);

            context.sleep(Duration::from_millis(80)).await;
            assert!(fetcher.cancel(&key));

            assert_eq!(fetcher.participants.get(&peer), Some(100));
            assert!(!fetcher.requests.contains_key(&id));
            assert!(!fetcher.key_to_id.contains_key(&key));
        });
    }

    #[test]
    fn test_escalate_schedules_retry_when_additional_peers_are_rate_limited() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<LimitedMockSender<Context>>(context.clone());
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                LimitedMockSender::new(
                    Quota::with_period(Duration::from_millis(100)).unwrap(),
                    context.clone(),
                ),
            );

            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            let peer3 = PrivateKey::from_seed(3).public_key();
            let key = MockKey(11);
            let id = 7;
            let now = context.current();

            fetcher.reconcile(&[peer1.clone(), peer2.clone(), peer3.clone()]);
            fetcher.active.put(id, now + Duration::from_secs(5));
            fetcher.requests.insert(
                id,
                ActiveRequest {
                    key: key.clone(),
                    peers: HashMap::from([(peer1, now)]),
                },
            );
            fetcher.key_to_id.insert(key.clone(), id);

            for peer in [&peer2, &peer3] {
                sender
                    .check(Recipients::One((*peer).clone()))
                    .await
                    .unwrap()
                    .send(
                        wire::Message {
                            id: 0,
                            payload: wire::Payload::Request(MockKey(99)),
                        },
                        false,
                    )
                    .await
                    .unwrap();
            }

            fetcher.escalate(&key, &mut sender).await;
            let deadline = fetcher
                .get_pending_deadline()
                .expect("expected escalation retry wakeup");
            assert!(deadline > context.current());

            context.sleep(Duration::from_millis(100)).await;
            fetcher.fetch(&mut sender).await;

            let peers = &fetcher.requests.get(&id).unwrap().peers;
            assert!(peers.contains_key(&peer2));
            assert!(peers.contains_key(&peer3));
        });
    }

    #[test]
    fn test_waiter_does_not_starve_later_pending_deadlines() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.clone());
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );

            let me = PrivateKey::from_seed(0).public_key();
            let eligible_peer = PrivateKey::from_seed(1).public_key();
            let unavailable_target = PrivateKey::from_seed(99).public_key();
            let blocked_key = MockKey(70);
            let later_key = MockKey(71);

            fetcher.reconcile(&[me, eligible_peer]);
            fetcher.add_ready(blocked_key.clone());
            fetcher.add_targets(blocked_key.clone(), [unavailable_target]);
            fetcher.add_retry(later_key.clone());

            fetcher.fetch(&mut sender).await;
            context.sleep(Duration::from_millis(150)).await;
            fetcher.fetch(&mut sender).await;

            assert!(
                fetcher.key_to_id.contains_key(&later_key),
                "later key should still be attempted even if another key has no eligible peers"
            );
        });
    }

    #[test]
    fn test_urgent_fetch_schedules_retry_when_additional_peers_are_rate_limited() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<LimitedMockSender<Context>>(context.clone());
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                LimitedMockSender::new(
                    Quota::with_period(Duration::from_millis(100)).unwrap(),
                    context.clone(),
                ),
            );

            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            let key = MockKey(12);

            fetcher.reconcile(&[peer1.clone(), peer2.clone()]);
            fetcher.mark_urgent(key.clone());
            fetcher.add_ready(key.clone());

            sender
                .check(Recipients::One(peer2.clone()))
                .await
                .unwrap()
                .send(
                    wire::Message {
                        id: 0,
                        payload: wire::Payload::Request(MockKey(99)),
                    },
                    false,
                )
                .await
                .unwrap();

            fetcher.fetch(&mut sender).await;

            let id = *fetcher
                .key_to_id
                .get(&key)
                .expect("urgent fetch should become active");
            let peers = &fetcher.requests.get(&id).unwrap().peers;
            assert!(peers.contains_key(&peer1));
            assert!(!peers.contains_key(&peer2));
            assert!(
                fetcher.get_pending_deadline().is_some(),
                "urgent fetch should schedule an escalation retry for the rate-limited peer"
            );

            context.sleep(Duration::from_millis(100)).await;
            fetcher.fetch(&mut sender).await;

            let peers = &fetcher.requests.get(&id).unwrap().peers;
            assert!(peers.contains_key(&peer1));
            assert!(peers.contains_key(&peer2));
        });
    }

    #[test]
    fn test_escalation_wakeup_does_not_bypass_pending_waiter() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.clone());
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer = PrivateKey::from_seed(1).public_key();
            let regular_key = MockKey(12);
            let urgent_key = MockKey(13);
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );

            fetcher.reconcile(&[public_key, peer]);
            fetcher.add_ready(regular_key.clone());
            fetcher.waiter = Some(context.current() + Duration::from_secs(1));
            add_test_active(&mut fetcher, 99, urgent_key.clone());
            fetcher
                .escalation_pending
                .put(urgent_key.clone(), context.current());

            fetcher.fetch(&mut sender).await;

            assert!(fetcher.pending.contains(&regular_key));
            assert!(!fetcher.key_to_id.contains_key(&regular_key));
            assert!(fetcher.key_to_id.contains_key(&urgent_key));
        });
    }

    #[test]
    fn test_pending_escalation_wakeup_does_not_bypass_pending_waiter() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.clone());
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer = PrivateKey::from_seed(1).public_key();
            let regular_key = MockKey(14);
            let urgent_key = MockKey(15);
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );

            fetcher.reconcile(&[public_key, peer]);
            fetcher.add_ready(regular_key.clone());
            fetcher.add_ready(urgent_key.clone());
            fetcher.mark_urgent(urgent_key.clone());
            fetcher.waiter = Some(context.current() + Duration::from_secs(1));
            fetcher
                .escalation_pending
                .put(urgent_key.clone(), context.current());

            fetcher.fetch(&mut sender).await;

            assert!(fetcher.pending.contains(&regular_key));
            assert!(!fetcher.key_to_id.contains_key(&regular_key));
            assert!(!fetcher.pending.contains(&urgent_key));
            assert!(fetcher.key_to_id.contains_key(&urgent_key));
        });
    }

    #[test]
    fn test_urgent_pending_escalation_not_rearmed_on_reconcile() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.clone());
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );
            let me = PrivateKey::from_seed(0).public_key();
            let available_peer = PrivateKey::from_seed(1).public_key();
            let unavailable_peer = PrivateKey::from_seed(99).public_key();
            let key = MockKey(16);

            fetcher.reconcile(std::slice::from_ref(&me));
            fetcher.add_retry(key.clone());
            fetcher.mark_urgent(key.clone());
            fetcher.add_targets(key.clone(), [unavailable_peer]);
            fetcher
                .escalation_pending
                .put(key.clone(), context.current());

            fetcher.fetch(&mut sender).await;

            fetcher.clear_targets(&key);
            fetcher.reconcile(&[me, available_peer]);

            let deadline = fetcher.get_pending_deadline().unwrap();
            assert!(
                deadline <= context.current(),
                "urgent key should be retried immediately after peers become available"
            );
        });
    }

    #[test]
    fn test_urgent_pending_without_eligible_peers_does_not_stay_immediately_due() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.clone());
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );
            let me = PrivateKey::from_seed(0).public_key();
            let key = MockKey(17);

            fetcher.reconcile(std::slice::from_ref(&me));
            fetcher.add_ready(key.clone());
            fetcher.mark_urgent(key.clone());

            fetcher.fetch(&mut sender).await;

            let deadline = fetcher.get_pending_deadline().unwrap();
            assert!(
                deadline > context.current(),
                "urgent key without eligible peers should wait for an external change instead of remaining immediately due"
            );
        });
    }

    #[test]
    fn test_active_urgent_fetch_rearmed_on_reconcile() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.clone());
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                SuccessMockSender::default(),
            );
            let me = PrivateKey::from_seed(0).public_key();
            let first_peer = PrivateKey::from_seed(1).public_key();
            let second_peer = PrivateKey::from_seed(2).public_key();
            let key = MockKey(18);

            fetcher.reconcile(&[me.clone(), first_peer.clone()]);
            fetcher.mark_urgent(key.clone());
            fetcher.add_ready(key.clone());
            fetcher.fetch(&mut sender).await;

            let id = *fetcher
                .key_to_id
                .get(&key)
                .expect("urgent fetch should become active");
            let peers = &fetcher.requests.get(&id).unwrap().peers;
            assert!(peers.contains_key(&first_peer));
            assert!(!peers.contains_key(&second_peer));

            fetcher.reconcile(&[me, first_peer.clone(), second_peer.clone()]);

            let deadline = fetcher
                .get_pending_deadline()
                .expect("active urgent fetch should schedule immediate escalation on peer-set expansion");
            assert!(deadline <= context.current());

            fetcher.fetch(&mut sender).await;

            let peers = &fetcher.requests.get(&id).unwrap().peers;
            assert!(peers.contains_key(&first_peer));
            assert!(peers.contains_key(&second_peer));
        });
    }

    #[test]
    fn test_urgent_request_tracks_per_peer_send_times() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<DelayedSuccessMockSender>(context.clone());
            let me = PrivateKey::from_seed(0).public_key();
            let p1 = PrivateKey::from_seed(1).public_key();
            let p2 = PrivateKey::from_seed(2).public_key();
            let key = MockKey(99);

            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                DelayedSuccessMockSender::new(context.clone(), Duration::from_millis(20)),
            );

            fetcher.reconcile(&[me, p1, p2]);
            fetcher.mark_urgent(key.clone());
            fetcher.add_ready(key.clone());
            fetcher.fetch(&mut sender).await;

            let id = *fetcher.key_to_id.get(&key).unwrap();
            let req = fetcher.requests.get(&id).unwrap();
            let mut starts: Vec<_> = req.peers.values().copied().collect();
            starts.sort();
            assert_eq!(starts.len(), 2);
            assert!(
                starts[0] < starts[1],
                "each peer should retain its own send timestamp"
            );
        });
    }
}
