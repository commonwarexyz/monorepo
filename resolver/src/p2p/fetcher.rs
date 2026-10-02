use crate::p2p::wire;
use bytes::Bytes;
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
    collections::{HashMap, HashSet, hash_map::Entry},
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

/// A key whose response the consumer is judging.
struct Judging<P> {
    /// Start of the request whose response is judged.
    start: SystemTime,
    /// A response to another request for the key, received during the judgment.
    held: Option<Held<P>>,
}

/// A data response held until the consumer judges an earlier response for the same key.
struct Held<P> {
    peer: P,
    start: SystemTime,
    elapsed: Duration,
    response: Bytes,
}

/// Next step for a key whose judged response was rejected.
pub enum Rejected<P> {
    /// Judge the response held during the rejected judgment.
    Judge(P, Duration, Bytes),
    /// Another request for the key is active.
    Wait,
    /// No request for the key remains.
    Retry,
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
/// # Rotation
///
/// Retries and hedges prefer eligible peers not yet tried for the key in the current rotation. A
/// tried peer receives the key again only when no untried peer accepts the send. Once every
/// eligible peer has been tried, a new rotation begins. Retiring or removing the key ends its
/// rotation.
///
/// # Hedging
///
/// A request sent while its key has no other active request is hedged once it has been
/// outstanding for half the timeout: the key is also sent to an eligible peer without an active
/// request for the key. A timeout or missing-data response for one request leaves the key to the
/// other, which is not hedged again.
///
/// The other request keeps running while the consumer judges a data response. A data response it
/// returns during the judgment is held. An accepted response cancels the other request or
/// discards its held response, and scores it as a timeout if it was sent first. A rejected
/// response leaves the key to the held response or to the other request.
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
    /// Reverse lookup from key to its active request IDs, oldest first
    key_to_ids: HashMap<Key, Vec<ID>>,
    /// Keys whose single active request is not yet hedged, ordered by hedge time
    hedges: PrioritySet<Key, SystemTime>,
    /// Keys whose data response the consumer is judging
    judging: HashMap<Key, Judging<P>>,

    // Config
    /// Timeout for requests
    timeout: Duration,

    /// How long a request is outstanding before its key is hedged
    hedge: Duration,

    /// Manages pending requests. When a request is registered (for both the first time and after
    /// a retry), it is added to this set.
    ///
    /// Fresh requests precede retries. Within each class, requests are ordered
    /// by the next time they should be attempted. Retried requests use a random
    /// untried peer rather than the best-performing peer.
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

    /// Per-key peers attempted in the current rotation. An entry is removed when
    /// its key is retired, is retained away, or starts a new rotation.
    tried: HashMap<Key, HashSet<P>>,

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
            key_to_ids: HashMap::new(),
            hedges: PrioritySet::new(),
            judging: HashMap::new(),
            timeout: config.timeout,
            hedge: config.timeout / 2,
            pending: PrioritySet::new(),
            waiter: None,
            retry_timeout: config.retry_timeout,
            priority_requests: config.priority_requests,
            targets: HashMap::new(),
            tried: HashMap::new(),
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

    /// Get eligible peers for a key, untried peers first.
    ///
    /// Peers not yet tried for the key in the current rotation precede tried peers, and each
    /// group is ordered best-performing first. Once every eligible peer has been tried, a new
    /// rotation begins with all of them.
    ///
    /// If `shuffle` is true, each group is shuffled (used for retries to try different peers).
    fn get_eligible_peers(&mut self, key: &Key, shuffle: bool) -> Vec<P> {
        let targets = self.targets.get(key);
        let seen = self.tried.get(key);

        // Prepare participant iterator. The set stores throughput as `Reverse`,
        // so it iterates best-performing peer first.
        let participant_iter = self.participants.iter();

        // Collect eligible peers, split by whether they were tried in this rotation
        let (mut untried, mut tried): (Vec<P>, Vec<P>) = participant_iter
            .filter(|(p, _)| self.me.as_ref() != Some(p)) // not self
            .filter(|(p, _)| !self.blocked.contains(p)) // not blocked
            .filter(|(p, _)| targets.is_none_or(|t| t.contains(p))) // matches target if any
            .map(|(p, _)| p.clone())
            .partition(|p| seen.is_none_or(|t| !t.contains(p)));

        // Start a new rotation once every eligible peer has been tried
        if untried.is_empty() {
            self.tried.remove(key);
            mem::swap(&mut untried, &mut tried);
        }

        // Shuffle if requested
        if shuffle {
            untried.shuffle(&mut self.context);
            tried.shuffle(&mut self.context);
        }
        untried.extend(tried);
        untried
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
    pub fn fetch(&mut self, sender: &mut WrappedSender<NetS, wire::Message<Key>>) {
        self.waiter = None;

        // Try each pending key until one succeeds
        let mut earliest_rate_limit: Option<SystemTime> = None;
        let mut found_eligible_peers = false;

        // Detach the queue to leave skipped entries untouched and remove only the
        // successfully sent key.
        let pending = mem::replace(&mut self.pending, PrioritySet::new());
        let mut sent = None;
        'pending: for (key, &(retry, _)) in pending.iter() {
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
                self.tried
                    .entry(key.clone())
                    .or_default()
                    .insert(peer.clone());
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
        if let Some((key, id, peer, start)) = sent {
            assert!(self.pending.remove(&key));
            self.track(key, id, peer, start);
            return;
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
    }

    /// Tracks a sent request as active and schedules the hedge of a key's first request.
    fn track(&mut self, key: Key, id: ID, peer: P, start: SystemTime) {
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
        let ids = self.key_to_ids.entry(key.clone()).or_default();
        ids.push(id);
        if ids.len() == 1 {
            let hedge = start.checked_add(self.hedge).expect("time overflowed");
            self.hedges.put(key, hedge);
        }
    }

    /// Removes `id` from the active requests of `key`.
    ///
    /// Returns whether the key has no other active request and no judged response.
    fn untrack(&mut self, key: &Key, id: ID) -> bool {
        let ids = self
            .key_to_ids
            .get_mut(key)
            .expect("active request must be tracked by key");
        ids.retain(|other| *other != id);
        if !ids.is_empty() {
            return false;
        }
        self.key_to_ids.remove(key);
        self.hedges.remove(key);
        !self.judging.contains_key(key)
    }

    /// Removes every active request for `key` and returns them.
    fn cancel(&mut self, key: &Key) -> Vec<ActiveRequest<P, Key>> {
        self.hedges.remove(key);
        self.key_to_ids
            .remove(key)
            .unwrap_or_default()
            .into_iter()
            .map(|id| {
                self.active.remove(&id);
                self.requests
                    .remove(&id)
                    .expect("tracked request must be active")
            })
            .collect()
    }

    /// Sends a second request for every key whose hedge is due.
    ///
    /// The request goes to an eligible peer without an active request for the key, untried peers
    /// first. A key with no such peer that accepts the send is not hedged.
    pub fn hedge(&mut self, sender: &mut WrappedSender<NetS, wire::Message<Key>>) {
        let now = self.context.current();
        while self
            .hedges
            .peek()
            .is_some_and(|(_, deadline)| *deadline <= now)
        {
            let (key, _) = self.hedges.pop().expect("peeked hedge must exist");
            let active: Vec<P> = self.key_to_ids[&key]
                .iter()
                .map(|id| self.requests[id].peer.clone())
                .collect();
            let peers = self.get_eligible_peers(&key, true);
            for peer in peers.into_iter().filter(|peer| !active.contains(peer)) {
                let Ok(checked) = sender.check(Recipients::One(peer.clone())) else {
                    continue;
                };
                self.tried
                    .entry(key.clone())
                    .or_default()
                    .insert(peer.clone());
                let id = self.next_id();
                let message = wire::Message {
                    id,
                    payload: wire::Payload::Request(key.clone()),
                };
                match checked.send(message, self.priority_requests) {
                    Unreliable::Outcome(Feedback::Ok | Feedback::Backoff) => {
                        self.requests_sent.inc(Status::Success);
                        self.track(key.clone(), id, peer, now);
                        break;
                    }
                    feedback @ (Unreliable::Rejected | Unreliable::Outcome(Feedback::Closed)) => {
                        self.requests_sent.inc(Status::Dropped);
                        debug!(?peer, ?feedback, "hedge send failed");
                        self.update_performance(&peer, 0);
                    }
                }
            }
        }
    }

    /// Returns the deadline for the next hedge.
    pub fn get_hedge_deadline(&self) -> Option<SystemTime> {
        self.hedges.peek().map(|(_, deadline)| *deadline)
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
        self.key_to_ids.retain(|k, _| predicate(k));
        self.hedges.retain(&predicate);
        self.judging.retain(|k, _| predicate(k));
        self.pending.retain(&predicate);
        self.targets.retain(|k, _| predicate(k));
        self.tried.retain(|k, _| predicate(k));

        // Clear waiter since the key that caused it may have been removed
        self.waiter = None;
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
        // Pending may be emptied by cancel/retain
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

    /// Removes the request with the next timeout and returns its key if the key has no other
    /// active request and no judged response.
    ///
    /// Targets are not removed on timeout.
    pub fn pop_active(&mut self) -> Option<Key> {
        // Pop the next deadline
        let (id, _) = self.active.pop()?;

        // Remove the request and score zero throughput (nothing was delivered).
        let req = self.requests.remove(&id)?;
        self.update_performance(&req.peer, 0);
        self.untrack(&req.key, id).then_some(req.key)
    }

    /// Remove the active request matching `id` and `peer`, leaving it tracked by key.
    fn pop_request(&mut self, id: ID, peer: &P) -> Option<ActiveRequest<P, Key>> {
        let req = self.requests.get(&id)?;
        if &req.peer != peer {
            return None;
        }

        let req = self.requests.remove(&id)?;
        self.active.remove(&id);
        Some(req)
    }

    /// Processes a data response from a peer.
    ///
    /// Removes the matching request and returns its key, network response time, and data for the
    /// consumer to judge. Other active requests for the key keep running. If the consumer is
    /// already judging a response for the key, the data is held for [`Self::reject`] and nothing
    /// is returned. The caller reports the outcome with [`Self::resolve`] or [`Self::reject`].
    ///
    /// The caller must score the response with [`Self::record_response`] after the consumer
    /// decides it should be attributed to the peer.
    ///
    /// Targets are not removed here. The caller clears them when the logical fetch completes or
    /// is ignored. On invalid data, the caller blocks the peer, which is then skipped until the
    /// network unblocks it.
    ///
    /// Note that this matches responses against the peer a request was already sent to. A later
    /// `reconcile()` call may remove that peer from the candidate pool for future sends, but it
    /// does not retroactively invalidate the in-flight request.
    pub fn pop_response(
        &mut self,
        id: ID,
        peer: &P,
        response: Bytes,
    ) -> Option<(Key, Duration, Bytes)> {
        let req = self.pop_request(id, peer)?;
        self.untrack(&req.key, id);
        let elapsed = self
            .context
            .current()
            .duration_since(req.start)
            .unwrap_or_default();
        match self.judging.entry(req.key) {
            Entry::Occupied(mut judging) => {
                let judging = judging.get_mut();
                assert!(
                    judging.held.is_none(),
                    "key has at most two active requests"
                );
                judging.held = Some(Held {
                    peer: req.peer,
                    start: req.start,
                    elapsed,
                    response,
                });
                None
            }
            Entry::Vacant(judging) => {
                let key = judging.key().clone();
                judging.insert(Judging {
                    start: req.start,
                    held: None,
                });
                Some((key, elapsed, response))
            }
        }
    }

    /// Ends the judgment of a key whose response the consumer accepted.
    ///
    /// Cancels the other active requests for the key and discards any held response. Each one
    /// sent before the accepted request is scored as a timeout.
    pub fn resolve(&mut self, key: &Key) {
        let judging = self
            .judging
            .remove(key)
            .expect("accepted response must be judged");
        if let Some(held) = judging.held
            && held.start <= judging.start
        {
            self.update_performance(&held.peer, 0);
        }
        for other in self.cancel(key) {
            if other.start <= judging.start {
                self.update_performance(&other.peer, 0);
            }
        }
    }

    /// Ends the judgment of a key whose response the consumer rejected.
    ///
    /// Returns the held response for the consumer to judge next, if any. Otherwise returns
    /// whether another request for the key is active.
    pub fn reject(&mut self, key: &Key) -> Rejected<P> {
        if let Some(judging) = self.judging.get_mut(key) {
            if let Some(held) = judging.held.take() {
                judging.start = held.start;
                return Rejected::Judge(held.peer, held.elapsed, held.response);
            }
            self.judging.remove(key);
        }
        if self.key_to_ids.contains_key(key) {
            Rejected::Wait
        } else {
            Rejected::Retry
        }
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
    /// Returns the key if it has no other active request and no judged response. Missing data is
    /// scored as zero throughput because the peer delivered nothing.
    pub fn pop_missing(&mut self, id: ID, peer: &P) -> Option<Key> {
        let req = self.pop_request(id, peer)?;
        self.update_performance(&req.peer, 0);
        self.untrack(&req.key, id).then_some(req.key)
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

    /// Drops the requests, judgment, targets, and rotation of a retired key.
    pub fn finish(&mut self, key: &Key) {
        self.cancel(key);
        self.judging.remove(key);
        self.tried.remove(key);
        self.clear_targets(key);
    }

    /// Returns the number of fetches.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.pending.len() + self.key_to_ids.len()
    }

    /// Returns the number of pending fetches.
    pub fn len_pending(&self) -> usize {
        self.pending.len()
    }

    /// Returns the number of active fetches.
    pub fn len_active(&self) -> usize {
        self.key_to_ids.len()
    }

    /// Returns true if the fetch is in progress.
    #[cfg(test)]
    pub fn contains(&self, key: &Key) -> bool {
        self.key_to_ids.contains_key(key) || self.pending.contains(key)
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
        fetcher.key_to_ids.entry(key).or_default().push(id);
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
            assert!(fetcher.key_to_ids.contains_key(&MockKey(10)));
            assert!(!fetcher.key_to_ids.contains_key(&MockKey(20)));
            assert!(!fetcher.key_to_ids.contains_key(&MockKey(30)));
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

            // Remove one active key via retain.
            fetcher.retain(|key| *key != MockKey(10));
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
    fn test_retain_drops_selected_keys() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Add keys to both pending and active states
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
            add_test_active(&mut fetcher, 100, MockKey(10));
            add_test_active(&mut fetcher, 101, MockKey(20));

            // Drop a pending key.
            fetcher.retain(|key| *key != MockKey(1));
            assert_eq!(fetcher.len_pending(), 1);
            assert!(!fetcher.contains(&MockKey(1)));

            // Drop an active key.
            fetcher.retain(|key| *key != MockKey(10));
            assert_eq!(fetcher.len_active(), 1);
            assert!(!fetcher.contains(&MockKey(10)));

            // Dropping a non-existent key has no effect.
            let len = fetcher.len();
            fetcher.retain(|key| *key != MockKey(99));
            assert_eq!(fetcher.len(), len);

            // Drop remaining pending key.
            fetcher.retain(|key| *key != MockKey(2));
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

            // Remove from active via retain.
            fetcher.retain(|key| *key != MockKey(10));
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

            assert!(fetcher.pop_response(999, &peer, Bytes::new()).is_none());
            assert_eq!(fetcher.len_active(), 1);

            fetcher.context.sleep(Duration::from_millis(20)).await;
            let (key, elapsed, _) = fetcher
                .pop_response(100, &peer, Bytes::new())
                .expect("matching response");
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
    fn test_retain_edge_cases() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context);

            // Retain on an empty fetcher is a no-op.
            fetcher.retain(|key| *key != MockKey(1));
            assert_eq!(fetcher.len(), 0);

            // Add key, prune it, then prune it again.
            fetcher.add_retry(MockKey(1));
            fetcher.retain(|key| *key != MockKey(1));
            assert_eq!(fetcher.len(), 0);
            fetcher.retain(|key| *key != MockKey(1));
            assert_eq!(fetcher.len(), 0);
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
            assert!(fetcher.key_to_ids.contains_key(&MockKey(1)));
            assert!(!fetcher.key_to_ids.contains_key(&MockKey(2)));

            // Verify the request data for MockKey(1) is preserved
            let id = fetcher.key_to_ids[&MockKey(1)][0];
            assert!(fetcher.requests.contains_key(&id));
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

            // Prune one from each collection.
            fetcher.retain(|key| *key != MockKey(1) && *key != MockKey(10));

            assert_eq!(fetcher.len(), 2);

            // Retain only keys <= 20
            fetcher.retain(|key| key.0 <= 20);

            // Should still have MockKey(2) pending and MockKey(20) active
            assert_eq!(fetcher.len(), 2);
            assert!(fetcher.contains(&MockKey(2)));
            assert!(fetcher.contains(&MockKey(20)));

            // Prune all.
            fetcher.retain(|_| false);
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
            fetcher.fetch(&mut sender); // won't be delivered, so immediately re-added
            fetcher.fetch(&mut sender); // waiter activated

            // Check pending deadline
            assert_eq!(fetcher.len_pending(), 1);
            let pending_deadline = fetcher.get_pending_deadline().unwrap();
            assert!(pending_deadline > context.current());

            // Prune key.
            fetcher.retain(|key| *key != MockKey(1));
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
            fetcher.fetch(&mut sender);

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
            fetcher.fetch(&mut sender);
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
            fetcher.fetch(&mut sender);
            assert!(fetcher.waiter.is_some());

            fetcher.add_ready(MockKey(2));
            assert_eq!(fetcher.get_pending_deadline(), Some(context.current()));

            fetcher.fetch(&mut sender);
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
            fetcher.fetch(&mut sender);
            assert!(fetcher.waiter.is_some());

            fetcher.add_retry(MockKey(2));
            let deadline = fetcher.get_pending_deadline().unwrap();
            assert!(deadline <= context.current() + Duration::from_millis(100));

            context.sleep(Duration::from_millis(100)).await;
            fetcher.fetch(&mut sender);
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
                    fetcher.fetch(&mut sender);
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
                fetcher.fetch(&mut sender);
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

            fetcher.fetch(&mut sender);
            assert!(fetcher.waiter.is_some());

            fetcher.add_targets(MockKey(1), [peer]);
            assert_eq!(fetcher.get_pending_deadline(), Some(context.current()));

            fetcher.fetch(&mut sender);
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

            fetcher.fetch(&mut sender);
            assert!(fetcher.waiter.is_some());

            fetcher.clear_targets(&MockKey(1));
            assert_eq!(fetcher.get_pending_deadline(), Some(context.current()));

            fetcher.fetch(&mut sender);
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
            fetcher.fetch(&mut sender);

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
            fetcher.fetch(&mut sender);
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

            // retain() clears targets for pruned keys.
            fetcher.add_targets(MockKey(1), [peer1.clone()]);
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_retry(MockKey(1));
            fetcher.add_retry(MockKey(2));
            assert_eq!(fetcher.targets.len(), 2);

            fetcher.retain(|key| *key != MockKey(1));
            assert!(!fetcher.targets.contains_key(&MockKey(1)));
            assert!(fetcher.targets.contains_key(&MockKey(2)));

            fetcher.retain(|key| *key != MockKey(2));
            assert!(fetcher.targets.is_empty());

            // Retaining nothing clears all targets.
            fetcher.add_targets(MockKey(1), [peer1.clone(), peer2.clone()]);
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_targets(MockKey(3), [peer2]);
            assert_eq!(fetcher.targets.len(), 3);

            fetcher.retain(|_| false);
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
            fetcher.fetch(&mut sender);
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
            fetcher.fetch(&mut sender);
            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(fetcher.pop_active(), Some(MockKey(1)));
            // Both targets should still be present after timeout
            assert_eq!(fetcher.targets.get(&MockKey(1)).unwrap().len(), 2);
            fetcher.targets.clear();

            // Error response ("no data") does not remove target
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_ready(MockKey(2));
            fetcher.fetch(&mut sender);
            let id = *fetcher.active.iter().next().unwrap().0;
            assert_eq!(fetcher.pop_missing(id, &peer1), Some(MockKey(2)));
            // Target should still be present after "no data" response
            assert!(fetcher.targets.get(&MockKey(2)).unwrap().contains(&peer1));
            fetcher.targets.clear();

            // Data response also preserves targets
            // (caller must clear targets after data validation)
            fetcher.add_targets(MockKey(3), [peer1.clone()]);
            fetcher.add_ready(MockKey(3));
            fetcher.fetch(&mut sender);
            let id = *fetcher.active.iter().next().unwrap().0;
            assert_eq!(
                fetcher
                    .pop_response(id, &peer1, Bytes::new())
                    .map(|(key, _, _)| key),
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
            fetcher.fetch(&mut sender);

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
            fetcher.fetch(&mut sender);
            assert_eq!(fetcher.len_active(), 1);
            assert_eq!(fetcher.len_pending(), 2);
            assert!(!fetcher.pending.contains(&MockKey(1))); // MockKey(1) was fetched

            // Second fetch: MockKey(2) is blocked (peer1 rate-limited), should skip to MockKey(3)
            fetcher.fetch(&mut sender);
            assert_eq!(fetcher.len_active(), 2);
            assert_eq!(fetcher.len_pending(), 1);
            assert!(fetcher.pending.contains(&MockKey(2))); // MockKey(2) is still pending
            assert!(!fetcher.pending.contains(&MockKey(3))); // MockKey(3) was fetched

            // Third fetch: only MockKey(2) remains, but peer1 is still rate-limited
            fetcher.fetch(&mut sender);
            assert_eq!(fetcher.len_active(), 2); // No change
            assert_eq!(fetcher.len_pending(), 1); // MockKey(2) still pending
            assert!(fetcher.waiter.is_some()); // Waiter set

            // Wait for rate limit to reset
            context.sleep(Duration::from_secs(1)).await;

            // Now MockKey(2) can be fetched
            fetcher.fetch(&mut sender);
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

    type TestFetcher = Fetcher<Context, PublicKey, MockKey, SuccessMockSender>;
    type TestSender = WrappedSender<SuccessMockSender, wire::Message<MockKey>>;

    /// Sends the next pending fetch and returns the peer that received `key`.
    fn send_next(fetcher: &mut TestFetcher, sender: &mut TestSender, key: &MockKey) -> PublicKey {
        fetcher.fetch(sender);
        let id = fetcher.key_to_ids[key][0];
        fetcher.requests[&id].peer.clone()
    }

    /// Creates a fetcher over `count` remote peers and returns it with its sender and peers.
    fn create_rotation_fetcher(
        context: &Context,
        count: u64,
    ) -> (TestFetcher, TestSender, Vec<PublicKey>) {
        let mut fetcher = create_test_fetcher::<SuccessMockSender>(context.child("fetcher"));
        let sender = WrappedSender::new(
            context.network_buffer_pool().clone(),
            SuccessMockSender::default(),
        );
        let peers: Vec<_> = (1..=count)
            .map(|seed| PrivateKey::from_seed(seed).public_key())
            .collect();
        let mut participants = peers.clone();
        participants.push(PrivateKey::from_seed(0).public_key());
        fetcher.reconcile(&participants);
        (fetcher, sender, peers)
    }

    /// A retry skips every peer that failed the key while an untried eligible peer remains.
    #[test]
    fn test_retry_skips_tried_peers() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, _) = create_rotation_fetcher(&context, 3);
            for i in 0..16 {
                let key = MockKey(i);

                // The first attempt times out.
                fetcher.add_ready(key.clone());
                let first = send_next(&mut fetcher, &mut sender, &key);
                assert_eq!(fetcher.pop_active(), Some(key.clone()));
                fetcher.add_retry(key.clone());

                // The retry goes to another peer, which reports missing data.
                let second = send_next(&mut fetcher, &mut sender, &key);
                assert_ne!(second, first);
                let id = fetcher.key_to_ids[&key][0];
                assert_eq!(fetcher.pop_missing(id, &second), Some(key.clone()));
                fetcher.add_retry(key.clone());

                // The next retry goes to the last untried peer.
                let third = send_next(&mut fetcher, &mut sender, &key);
                assert_ne!(third, first);
                assert_ne!(third, second);

                // Cancel the key before the next round.
                fetcher.retain(|k| *k != key);
            }
        });
    }

    /// A retry starts a new rotation once every eligible peer has been tried for the key.
    #[test]
    fn test_retry_rotation_restarts() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, _) = create_rotation_fetcher(&context, 2);
            for i in 0..16 {
                let key = MockKey(i);

                // Both peers time out.
                fetcher.add_ready(key.clone());
                let first = send_next(&mut fetcher, &mut sender, &key);
                assert_eq!(fetcher.pop_active(), Some(key.clone()));
                fetcher.add_retry(key.clone());
                let second = send_next(&mut fetcher, &mut sender, &key);
                assert_ne!(second, first);
                assert_eq!(fetcher.pop_active(), Some(key.clone()));
                fetcher.add_retry(key.clone());

                // The next retry starts a new rotation with either peer.
                let third = send_next(&mut fetcher, &mut sender, &key);
                assert_eq!(fetcher.pop_active(), Some(key.clone()));
                fetcher.add_retry(key.clone());

                // The new rotation skips the peer it already tried.
                let fourth = send_next(&mut fetcher, &mut sender, &key);
                assert_ne!(fourth, third);

                // Cancel the key before the next round.
                fetcher.retain(|k| *k != key);
            }
        });
    }

    /// Retiring the key or retaining it away drops the key's rotation. A data response keeps it.
    #[test]
    fn test_retry_rotation_cleared() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, _) = create_rotation_fetcher(&context, 3);
            let resolved = MockKey(1);
            let cancelled = MockKey(2);

            // The first key times out, its retry receives a data response, and the key is
            // retired.
            fetcher.add_ready(resolved.clone());
            let first = send_next(&mut fetcher, &mut sender, &resolved);
            assert_eq!(fetcher.pop_active(), Some(resolved.clone()));
            fetcher.add_retry(resolved.clone());
            assert_eq!(fetcher.tried[&resolved], HashSet::from([first.clone()]));
            let second = send_next(&mut fetcher, &mut sender, &resolved);
            assert_eq!(
                fetcher.tried[&resolved],
                HashSet::from([first, second.clone()])
            );
            let id = fetcher.key_to_ids[&resolved][0];
            assert!(fetcher.pop_response(id, &second, Bytes::new()).is_some());
            assert_eq!(fetcher.tried[&resolved].len(), 2);
            fetcher.finish(&resolved);
            assert!(fetcher.tried.is_empty());

            // The second key times out and is retained away while pending.
            fetcher.add_ready(cancelled.clone());
            let peer = send_next(&mut fetcher, &mut sender, &cancelled);
            assert_eq!(fetcher.pop_active(), Some(cancelled.clone()));
            fetcher.add_retry(cancelled.clone());
            assert_eq!(fetcher.tried[&cancelled], HashSet::from([peer]));
            fetcher.retain(|k| *k != cancelled);
            assert!(fetcher.tried.is_empty());
        });
    }

    /// A failed send counts as an attempt in the key's rotation.
    #[test]
    fn test_retry_rotation_records_failed_sends() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher::<FailMockSender>(context.child("fetcher"));
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                FailMockSender::default(),
            );
            let peers: Vec<_> = (1..=3)
                .map(|seed| PrivateKey::from_seed(seed).public_key())
                .collect();
            fetcher.reconcile(&peers);

            // Every send fails. Every peer is recorded and the key stays pending.
            fetcher.add_ready(MockKey(1));
            fetcher.fetch(&mut sender);
            assert!(fetcher.pending.contains(&MockKey(1)));
            assert_eq!(fetcher.tried[&MockKey(1)], peers.into_iter().collect());
        });
    }

    /// A key with a single eligible peer keeps retrying that peer.
    #[test]
    fn test_retry_single_peer() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, peers) = create_rotation_fetcher(&context, 1);
            let key = MockKey(1);

            // The only peer times out.
            fetcher.add_ready(key.clone());
            assert_eq!(send_next(&mut fetcher, &mut sender, &key), peers[0]);
            assert_eq!(fetcher.pop_active(), Some(key.clone()));
            fetcher.add_retry(key.clone());

            // The retry goes to the same peer, which reports missing data.
            assert_eq!(send_next(&mut fetcher, &mut sender, &key), peers[0]);
            let id = fetcher.key_to_ids[&key][0];
            assert_eq!(fetcher.pop_missing(id, &peers[0]), Some(key.clone()));
            fetcher.add_retry(key.clone());

            // The peer is retried again.
            assert_eq!(send_next(&mut fetcher, &mut sender, &key), peers[0]);
        });
    }

    /// Rotation covers only the key's targets.
    #[test]
    fn test_retry_rotation_respects_targets() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, peers) = create_rotation_fetcher(&context, 4);
            let targets = [peers[0].clone(), peers[1].clone()];
            for i in 0..16 {
                let key = MockKey(i);
                fetcher.add_targets(key.clone(), targets.clone());

                // The first attempt goes to a target and times out.
                fetcher.add_ready(key.clone());
                let first = send_next(&mut fetcher, &mut sender, &key);
                assert!(targets.contains(&first));
                assert_eq!(fetcher.pop_active(), Some(key.clone()));
                fetcher.add_retry(key.clone());

                // The retry goes to the other target and times out.
                let second = send_next(&mut fetcher, &mut sender, &key);
                assert!(targets.contains(&second));
                assert_ne!(second, first);
                assert_eq!(fetcher.pop_active(), Some(key.clone()));
                fetcher.add_retry(key.clone());

                // The new rotation stays within the targets.
                let third = send_next(&mut fetcher, &mut sender, &key);
                assert!(targets.contains(&third));

                // Cancel the key before the next round.
                fetcher.retain(|k| *k != key);
            }
        });
    }

    /// A blocked untried peer does not hold back a new rotation.
    #[test]
    fn test_retry_rotation_skips_blocked_peers() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, peers) = create_rotation_fetcher(&context, 3);
            let key = MockKey(1);

            // The first attempt times out.
            fetcher.add_ready(key.clone());
            let first = send_next(&mut fetcher, &mut sender, &key);
            assert_eq!(fetcher.pop_active(), Some(key.clone()));
            fetcher.add_retry(key.clone());

            // Block one untried peer. The retry goes to the other untried peer and times out.
            let blocked = peers.iter().find(|p| **p != first).unwrap().clone();
            fetcher.set_blocked([blocked.clone()]);
            let second = send_next(&mut fetcher, &mut sender, &key);
            assert_ne!(second, first);
            assert_ne!(second, blocked);
            assert_eq!(fetcher.pop_active(), Some(key.clone()));
            fetcher.add_retry(key.clone());

            // Every unblocked peer has been tried. The retry starts a new rotation.
            let third = send_next(&mut fetcher, &mut sender, &key);
            assert_ne!(third, blocked);
        });
    }

    /// Returns the peer of each active request for `key`, oldest first.
    fn active_peers(fetcher: &TestFetcher, key: &MockKey) -> Vec<PublicKey> {
        fetcher.key_to_ids[key]
            .iter()
            .map(|id| fetcher.requests[id].peer.clone())
            .collect()
    }

    /// A retry after a response the consumer could not use goes to another peer.
    #[test]
    fn test_retry_after_response_skips_answering_peer() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, _) = create_rotation_fetcher(&context, 2);
            for i in 0..16 {
                let key = MockKey(i);

                // One peer answers, and the rejected response is retried.
                fetcher.add_ready(key.clone());
                let first = send_next(&mut fetcher, &mut sender, &key);
                let id = fetcher.key_to_ids[&key][0];
                assert!(fetcher.pop_response(id, &first, Bytes::new()).is_some());
                assert!(matches!(fetcher.reject(&key), Rejected::Retry));
                fetcher.add_retry(key.clone());

                // The retry goes to the other peer.
                assert_ne!(send_next(&mut fetcher, &mut sender, &key), first);

                // Cancel the key before the next round.
                fetcher.retain(|k| *k != key);
            }
        });
    }

    /// A key whose request is outstanding for half the timeout is also sent to another peer.
    /// Accepting the second response cancels the first request and scores it as a timeout.
    #[test]
    fn test_hedge_sends_second_request_after_half_timeout() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, peers) = create_rotation_fetcher(&context, 3);
            let key = MockKey(1);

            // The best-performing peer receives the fresh request.
            fetcher.record_response(&peers[0], Duration::from_millis(1), 1000);
            let Some(Reverse(score)) = fetcher.participants.get(&peers[0]) else {
                panic!("peer must be a participant");
            };
            fetcher.add_ready(key.clone());
            assert_eq!(send_next(&mut fetcher, &mut sender, &key), peers[0]);

            // No hedge is sent before half the timeout.
            fetcher.hedge(&mut sender);
            assert_eq!(active_peers(&fetcher, &key).len(), 1);
            let deadline = fetcher.get_hedge_deadline().unwrap();
            assert_eq!(
                deadline,
                fetcher.requests[&fetcher.key_to_ids[&key][0]].start + Duration::from_millis(2500)
            );

            // At half the timeout, a second request goes to another peer.
            context.sleep(Duration::from_millis(2500)).await;
            fetcher.hedge(&mut sender);
            let active = active_peers(&fetcher, &key);
            assert_eq!(active.len(), 2);
            assert_ne!(active[1], peers[0]);
            assert!(fetcher.get_hedge_deadline().is_none());
            assert_eq!(fetcher.len_active(), 1);

            // The second request answers first. The first keeps running while the response is
            // judged.
            let hedge_id = fetcher.key_to_ids[&key][1];
            let first_id = fetcher.key_to_ids[&key][0];
            assert!(
                fetcher
                    .pop_response(hedge_id, &active[1], Bytes::new())
                    .is_some()
            );
            assert_eq!(active_peers(&fetcher, &key), vec![peers[0].clone()]);
            assert_eq!(fetcher.participants.get(&peers[0]), Some(Reverse(score)));

            // Accepting the response cancels the first request and scores it as a timeout.
            fetcher.resolve(&key);
            assert!(fetcher.requests.is_empty());
            assert!(fetcher.get_active_deadline().is_none());
            assert_eq!(
                fetcher.participants.get(&peers[0]),
                Some(Reverse(score / 2))
            );
            assert!(
                fetcher
                    .pop_response(first_id, &peers[0], Bytes::new())
                    .is_none()
            );
        });
    }

    /// A response held during an accepted judgment is discarded. It is scored as a timeout only
    /// if its request was sent before the accepted one.
    #[test]
    fn test_accepted_judgment_scores_held_earlier_response() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, peers) = create_rotation_fetcher(&context, 3);
            let key = MockKey(1);

            // The best-performing peer receives the fresh request, and the key is hedged.
            fetcher.record_response(&peers[0], Duration::from_millis(1), 1000);
            let Some(Reverse(score)) = fetcher.participants.get(&peers[0]) else {
                panic!("peer must be a participant");
            };
            fetcher.add_ready(key.clone());
            assert_eq!(send_next(&mut fetcher, &mut sender, &key), peers[0]);
            context.sleep(Duration::from_millis(2500)).await;
            fetcher.hedge(&mut sender);
            let active = active_peers(&fetcher, &key);
            assert_eq!(active.len(), 2);
            let first_id = fetcher.key_to_ids[&key][0];
            let hedge_id = fetcher.key_to_ids[&key][1];

            // The hedge answers first and is judged. The first request answers during the
            // judgment and is held.
            assert!(
                fetcher
                    .pop_response(hedge_id, &active[1], Bytes::new())
                    .is_some()
            );
            assert!(
                fetcher
                    .pop_response(first_id, &peers[0], Bytes::new())
                    .is_none()
            );

            // Accepting the hedge response discards the held response and scores the first
            // request as a timeout.
            fetcher.resolve(&key);
            assert!(!fetcher.contains(&key));
            assert_eq!(
                fetcher.participants.get(&peers[0]),
                Some(Reverse(score / 2))
            );

            // A second key is hedged. Its first request answers first and is judged. The hedge
            // answers during the judgment and is held.
            let key = MockKey(2);
            let Some(Reverse(score)) = fetcher.participants.get(&peers[0]) else {
                panic!("peer must be a participant");
            };
            fetcher.add_ready(key.clone());
            assert_eq!(send_next(&mut fetcher, &mut sender, &key), peers[0]);
            context.sleep(Duration::from_millis(2500)).await;
            fetcher.hedge(&mut sender);
            let active = active_peers(&fetcher, &key);
            assert_eq!(active.len(), 2);
            let hedge_score = fetcher.participants.get(&active[1]);
            let first_id = fetcher.key_to_ids[&key][0];
            let hedge_id = fetcher.key_to_ids[&key][1];
            assert!(
                fetcher
                    .pop_response(first_id, &peers[0], Bytes::new())
                    .is_some()
            );
            assert!(
                fetcher
                    .pop_response(hedge_id, &active[1], Bytes::new())
                    .is_none()
            );

            // Accepting the first response discards the held hedge response without scoring
            // either peer.
            fetcher.resolve(&key);
            assert!(!fetcher.contains(&key));
            assert_eq!(fetcher.participants.get(&peers[0]), Some(Reverse(score)));
            assert_eq!(fetcher.participants.get(&active[1]), hedge_score);
        });
    }

    /// Rejecting the second response of a hedged key leaves the key to the first request without
    /// scoring it. The first request's response is then judged.
    #[test]
    fn test_rejected_hedge_response_keeps_first_request() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, peers) = create_rotation_fetcher(&context, 3);
            let key = MockKey(1);

            // The best-performing peer receives the fresh request, and the key is hedged.
            fetcher.record_response(&peers[0], Duration::from_millis(1), 1000);
            let score = fetcher.participants.get(&peers[0]);
            fetcher.add_ready(key.clone());
            assert_eq!(send_next(&mut fetcher, &mut sender, &key), peers[0]);
            context.sleep(Duration::from_millis(2500)).await;
            fetcher.hedge(&mut sender);
            let active = active_peers(&fetcher, &key);
            assert_eq!(active.len(), 2);

            // The hedge answers first and its response is rejected. The first request remains
            // active and unscored.
            let hedge_id = fetcher.key_to_ids[&key][1];
            let first_id = fetcher.key_to_ids[&key][0];
            assert!(
                fetcher
                    .pop_response(hedge_id, &active[1], Bytes::new())
                    .is_some()
            );
            assert!(matches!(fetcher.reject(&key), Rejected::Wait));
            assert_eq!(active_peers(&fetcher, &key), vec![peers[0].clone()]);
            assert_eq!(fetcher.participants.get(&peers[0]), score);
            assert!(fetcher.get_hedge_deadline().is_none());

            // The first request answers, and its response is judged and accepted.
            let (judged, _, _) = fetcher
                .pop_response(first_id, &peers[0], Bytes::new())
                .expect("first request must remain active");
            assert_eq!(judged, key);
            fetcher.resolve(&key);
            assert!(!fetcher.contains(&key));
            assert_eq!(fetcher.participants.get(&peers[0]), score);
        });
    }

    /// A response received while another response for the key is judged is held. A timeout of
    /// the other request does not return the key during the judgment. Rejecting the judged
    /// response yields the held one.
    #[test]
    fn test_response_during_judgment_is_held() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, _) = create_rotation_fetcher(&context, 3);
            let key = MockKey(1);

            // Send the key and hedge it.
            fetcher.add_ready(key.clone());
            send_next(&mut fetcher, &mut sender, &key);
            context.sleep(Duration::from_millis(2500)).await;
            fetcher.hedge(&mut sender);
            let active = active_peers(&fetcher, &key);
            let first_id = fetcher.key_to_ids[&key][0];
            let hedge_id = fetcher.key_to_ids[&key][1];

            // The first request answers and is judged. The hedge answers during the judgment and
            // is held.
            assert!(
                fetcher
                    .pop_response(first_id, &active[0], Bytes::from("first"))
                    .is_some()
            );
            assert!(
                fetcher
                    .pop_response(hedge_id, &active[1], Bytes::from("hedge"))
                    .is_none()
            );
            assert!(fetcher.requests.is_empty());

            // Rejecting the first response yields the held response.
            let Rejected::Judge(peer, _, response) = fetcher.reject(&key) else {
                panic!("held response must be judged");
            };
            assert_eq!(peer, active[1]);
            assert_eq!(response, Bytes::from("hedge"));

            // Rejecting the held response leaves nothing, and the key is retried.
            assert!(matches!(fetcher.reject(&key), Rejected::Retry));
            fetcher.add_retry(key.clone());
            assert!(fetcher.contains(&key));

            // A timeout during a judgment does not return the key.
            fetcher.retain(|_| false);
            fetcher.add_ready(key.clone());
            send_next(&mut fetcher, &mut sender, &key);
            context.sleep(Duration::from_millis(2500)).await;
            fetcher.hedge(&mut sender);
            let active = active_peers(&fetcher, &key);
            let first_id = fetcher.key_to_ids[&key][0];
            assert!(
                fetcher
                    .pop_response(first_id, &active[0], Bytes::new())
                    .is_some()
            );
            assert_eq!(fetcher.pop_active(), None);
            assert!(matches!(fetcher.reject(&key), Rejected::Retry));
        });
    }

    /// A timeout or missing response for one request of a hedged key leaves the key to the other
    /// request. The key is retried only once neither remains.
    #[test]
    fn test_hedge_failure_leaves_key_to_other_request() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, _) = create_rotation_fetcher(&context, 3);
            let key = MockKey(1);

            // Send the key and hedge it.
            fetcher.add_ready(key.clone());
            send_next(&mut fetcher, &mut sender, &key);
            context.sleep(Duration::from_millis(2500)).await;
            fetcher.hedge(&mut sender);
            let active = active_peers(&fetcher, &key);
            assert_eq!(active.len(), 2);

            // The hedge reports missing data, and the first request remains.
            let hedge_id = fetcher.key_to_ids[&key][1];
            assert_eq!(fetcher.pop_missing(hedge_id, &active[1]), None);
            assert_eq!(active_peers(&fetcher, &key), vec![active[0].clone()]);

            // The first request times out, and the key is returned for retry.
            assert_eq!(fetcher.pop_active(), Some(key.clone()));
            assert!(!fetcher.contains(&key));

            // A timeout with the hedge still active returns nothing.
            fetcher.add_retry(key.clone());
            send_next(&mut fetcher, &mut sender, &key);
            context.sleep(Duration::from_millis(2500)).await;
            fetcher.hedge(&mut sender);
            assert_eq!(active_peers(&fetcher, &key).len(), 2);
            assert_eq!(fetcher.pop_active(), None);
            assert_eq!(active_peers(&fetcher, &key).len(), 1);
        });
    }

    /// A key with no other eligible peer is not hedged.
    #[test]
    fn test_hedge_requires_other_peer() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, _) = create_rotation_fetcher(&context, 1);
            fetcher.add_ready(MockKey(1));
            send_next(&mut fetcher, &mut sender, &MockKey(1));
            context.sleep(Duration::from_millis(2500)).await;
            fetcher.hedge(&mut sender);
            assert_eq!(active_peers(&fetcher, &MockKey(1)).len(), 1);
            assert!(fetcher.get_hedge_deadline().is_none());
        });
    }

    /// Retaining a hedged key away cancels both of its requests.
    #[test]
    fn test_hedged_key_is_retained_away() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let (mut fetcher, mut sender, _) = create_rotation_fetcher(&context, 2);
            fetcher.add_ready(MockKey(1));
            send_next(&mut fetcher, &mut sender, &MockKey(1));
            context.sleep(Duration::from_millis(2500)).await;
            fetcher.hedge(&mut sender);
            assert_eq!(active_peers(&fetcher, &MockKey(1)).len(), 2);
            fetcher.retain(|key| *key != MockKey(1));
            assert!(fetcher.requests.is_empty());
            assert!(fetcher.get_active_deadline().is_none());
            assert!(!fetcher.contains(&MockKey(1)));
        });
    }

    /// A retry falls back to a tried peer when every untried peer is rate-limited.
    #[test]
    fn test_retry_falls_back_to_tried_peer_when_untried_is_rate_limited() {
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
            fetcher.reconcile(&[public_key, peer1, peer2]);
            let mut sender = WrappedSender::new(
                context.network_buffer_pool().clone(),
                LimitedMockSender::new(Quota::per_second(NZU32!(1)), context.child("limiter")),
            );
            let peer_of = |fetcher: &Fetcher<_, _, MockKey, LimitedMockSender<Context>>,
                           key: &MockKey| {
                fetcher.requests[&fetcher.key_to_ids[key][0]].peer.clone()
            };

            // The first key times out at one peer.
            fetcher.add_ready(MockKey(1));
            fetcher.fetch(&mut sender);
            let first = peer_of(&fetcher, &MockKey(1));
            assert_eq!(fetcher.pop_active(), Some(MockKey(1)));
            fetcher.add_retry(MockKey(1));

            // A second key spends the other peer's token.
            context.sleep(Duration::from_millis(500)).await;
            fetcher.add_ready(MockKey(2));
            fetcher.fetch(&mut sender);
            assert_ne!(peer_of(&fetcher, &MockKey(2)), first);

            // Once only the tried peer has a token, the retry goes to it.
            context.sleep(Duration::from_millis(600)).await;
            fetcher.fetch(&mut sender);
            assert_eq!(peer_of(&fetcher, &MockKey(1)), first);
        });
    }
}
