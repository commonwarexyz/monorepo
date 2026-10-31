use crate::p2p::{score::Score, wire};
use ahash::{AHashMap, AHashSet};
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
use commonware_utils::{
    PrioritySet, Span, SystemTimeExt,
    sampling::{WeightedIndex, WithoutReplacement},
};
use rand::RngExt as _;
use rand_core::Rng;
use std::{
    collections::hash_map::Entry,
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

/// Throughput scores of the latest tracked peer set in public-key order.
/// Local and blocked peers have zero sampling weight.
struct Participants<P> {
    peers: Vec<(P, Score)>,
    weights: WeightedIndex,
}

impl<P: PublicKey> Participants<P> {
    fn index(&self, peer: &P) -> Option<usize> {
        self.peers.binary_search_by(|(p, _)| p.cmp(peer)).ok()
    }

    /// Intersects a peer set with eligible participants, returning indices in public-key order.
    fn eligible_subset(&self, peers: &AHashSet<P>) -> Vec<usize> {
        // Target sets can retain many peers that are no longer participants. Look each one up
        // only while the estimated lookup work stays below one scan of the participants, so a
        // large set costs at most that scan.
        let lookup_steps = self.peers.len().checked_ilog2().unwrap_or(0) as usize + 1;
        if peers.len().saturating_mul(lookup_steps) < self.peers.len() {
            let mut indices: Vec<_> = peers
                .iter()
                .filter_map(|peer| self.index(peer))
                .filter(|&index| self.weights.weight(index) != 0)
                .collect();
            indices.sort_unstable();
            indices
        } else {
            self.peers
                .iter()
                .enumerate()
                .filter(|(index, (peer, _))| {
                    self.weights.weight(*index) != 0 && peers.contains(peer)
                })
                .map(|(index, _)| index)
                .collect()
        }
    }
}

/// The eligible pool for sending a request, either shared participants or a target subset.
enum Candidates {
    /// Uses the shared participant index.
    All,
    /// Owns an index over the eligible targets listed in `peers`, in the same order.
    Targets {
        peers: Vec<usize>,
        weights: WeightedIndex,
    },
}

impl Candidates {
    /// Starts one send loop, borrowing the shared index or consuming the target index.
    fn select(self, shared: &mut WeightedIndex) -> Selection<'_> {
        let (peers, draws) = match self {
            Self::All => (None, shared.without_replacement()),
            Self::Targets { peers, weights } => (Some(peers), weights.into_without_replacement()),
        };
        Selection { peers, draws }
    }
}

/// A send loop's remaining candidates, with temporary exclusions owned by the sampler.
struct Selection<'a> {
    /// Participant index for each target-local position, or `None` for the shared index.
    peers: Option<Vec<usize>>,
    /// Draws that cannot repeat a peer within this selection.
    draws: WithoutReplacement<'a>,
}

impl Selection<'_> {
    /// Draws an eligible participant using the retry mixture, without repeating a previous draw.
    fn next<R: Rng>(&mut self, rng: &mut R, retries: u32) -> Option<usize> {
        if self.draws.is_empty() {
            return None;
        }

        // After `r` unresolved requests, each remaining peer has probability
        // w / ((r + 1) * sum(w)) + r / ((r + 1) * eligible_peers).
        let index = if rng.random_range(0..u64::from(retries) + 1) == 0 {
            self.draws.sample(rng)?
        } else {
            self.draws.sample_uniform(rng)?
        };
        Some(self.peers.as_ref().map_or(index, |peers| peers[index]))
    }
}

/// Configuration for the fetcher.
pub struct Config<P: PublicKey> {
    /// Local identity of the participant (if any).
    pub me: Option<P>,

    /// Maximum wait for a response.
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
/// # Peer Selection
///
/// A fetch without targets may use any peer of the latest tracked peer set, whether primary or
/// secondary. A fetch with targets may use only those targets in that set, and a target outside
/// it is skipped until a later set includes it.
///
/// The first attempt samples in proportion to throughput scores. After `r` unresolved requests,
/// sampling uses those weights with probability `1 / (r + 1)` and is uniform otherwise. When a
/// send fails or the selected peer is rate-limited, the fetcher tries another eligible peer until
/// the request is sent or every eligible peer has been tried. Later retries can pick the same peer
/// again. Local send failures and rate limits do not change scores or advance the retry count.
///
/// # Targets
///
/// Peers can be registered as "targets" for specific keys, restricting fetches to only those
/// peers. Targets represent "the only peers who might eventually have the data". There is no
/// fallback to other peers: if all targets are unavailable, the fetch waits for them.
///
/// Targets persist through transient failures (timeout, "no data" response, send failure) since
/// the peer might be slow or might receive the data later, and are cleared when the fetch ends. A
/// blocked target is skipped until the network unblocks it, so a fetch whose every target is
/// blocked stays outstanding and resumes once one of them is unblocked.
pub struct Fetcher<E, P, Key>
where
    E: Clock + Rng + Metrics,
    P: PublicKey,
    Key: Span,
{
    context: E,

    // Peer management
    /// Local identity (to exclude from requests)
    me: Option<P>,
    /// Peers the network currently blocks, replaced wholesale on every update.
    blocked: AHashSet<P>,
    /// Peers of the latest tracked peer set and their throughput scores. Public-key order
    /// keeps weighted draws reproducible for a given random source.
    participants: Participants<P>,

    // Request tracking
    /// Next ID to use for a request
    request_id: ID,
    /// Active requests ordered by deadline (ID -> deadline)
    active: PrioritySet<ID, SystemTime>,
    /// Request data for active requests (ID -> request details)
    requests: AHashMap<ID, ActiveRequest<P, Key>>,

    // Config
    /// Maximum wait for a response.
    timeout: Duration,

    /// Manages pending requests. When a request is registered (for both the first time and after
    /// a retry), it is added to this set.
    ///
    /// Fresh requests precede retries. Within each class, requests are ordered
    /// by the next time they should be attempted.
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
    /// cleared when the fetch ends. Blocked targets are skipped until unblocked.
    targets: AHashMap<Key, AHashSet<P>>,

    /// Number of dispatched requests that left each key unresolved, saturating at `u32::MAX`.
    retries: AHashMap<Key, u32>,

    /// Per-peer throughput score expressed as a sampling weight.
    performance: GaugeFamily<Peer<P>>,

    /// Status of request creation attempts (Success when eligible peers exist, Dropped otherwise)
    requests_created: status::Counter,

    /// Status of individual network requests sent to peers
    requests_sent: status::Counter,

    /// Histogram of useful response durations
    resolves: Histogram,
}

impl<E, P, Key> Fetcher<E, P, Key>
where
    E: Clock + Rng + Metrics,
    P: PublicKey,
    Key: Span,
{
    /// Creates a new fetcher.
    pub fn new(context: E, config: Config<P>) -> Self {
        let performance = context.family(
            "peer_performance",
            "Per-peer throughput score expressed as a sampling weight",
        );
        let requests_created =
            context.family("requests_created", "Status of request creation attempts");
        let requests_sent = context.family(
            "requests_sent",
            "Status of individual network requests sent to peers",
        );
        let resolves = context.histogram(
            "resolves",
            "Number and duration of useful responses",
            Buckets::NETWORK,
        );
        Self {
            context,
            me: config.me,
            blocked: AHashSet::new(),
            participants: Participants {
                peers: Vec::new(),
                weights: WeightedIndex::new([]),
            },
            request_id: 0,
            active: PrioritySet::new(),
            requests: AHashMap::new(),
            timeout: config.timeout,
            pending: PrioritySet::new(),
            waiter: None,
            retry_timeout: config.retry_timeout,
            priority_requests: config.priority_requests,
            targets: AHashMap::new(),
            retries: AHashMap::new(),
            performance,
            requests_created,
            requests_sent,
            resolves,
        }
    }

    /// Records useful bytes and time spent waiting. Failures contribute zero bytes.
    fn update_performance(&mut self, participant: &P, elapsed: Duration, bytes: usize) {
        let Some(index) = self.participants.index(participant) else {
            return;
        };
        let score = &mut self.participants.peers[index].1;
        score.record(elapsed, bytes);
        let next = score.weight();

        // A score change must not make a local or blocked peer selectable.
        self.participants
            .weights
            .update(index, |weight| if weight == 0 { 0 } else { next });
        let _ = self.performance.get_or_create_by(participant).try_set(next);
    }

    /// Returns the key's eligible pool and retry count, or `None` when no peer can be tried.
    fn candidates(&self, key: &Key) -> Option<(Candidates, u32)> {
        let candidates = if let Some(targets) = self.targets.get(key) {
            let peers = self.participants.eligible_subset(targets);
            if peers.is_empty() {
                return None;
            }

            // Sample targets from their own index so weighted and uniform draws both stay within
            // the target set. Building it and excluding failed sends touch only these peers and
            // leave the shared index unchanged.
            let weights = WeightedIndex::new(
                peers
                    .iter()
                    .map(|&index| self.participants.weights.weight(index)),
            );
            Candidates::Targets { peers, weights }
        } else {
            // Eligible peers always have positive weight, so a zero total here means the
            // peer set is empty or contains only self and blocked peers.
            if self.participants.weights.total() == 0 {
                return None;
            }
            Candidates::All
        };
        let retries = self.retries.get(key).copied().unwrap_or(0);
        Some((candidates, retries))
    }

    #[cfg(test)]
    fn get_eligible_peers(&mut self, key: &Key) -> Vec<P> {
        let Some((candidates, retries)) = self.candidates(key) else {
            return Vec::new();
        };
        let mut peers = Vec::new();
        let mut selection = candidates.select(&mut self.participants.weights);
        while let Some(index) = selection.next(&mut self.context, retries) {
            peers.push(self.participants.peers[index].0.clone());
        }
        peers
    }

    /// Attempts to send a fetch request for a pending key.
    ///
    /// Iterates through pending keys until a send succeeds. For each key, tries
    /// eligible peers in selection order. On success, the key moves from pending
    /// to active. On failure, the key remains pending for retry.
    ///
    /// Sets `self.waiter` to control when the next fetch attempt should occur:
    /// - Rate limit expiry time if any peer was rate-limited
    /// - `retry_timeout` if peers exist but all sends failed
    /// - `Duration::MAX` if no eligible peers (wait for external changes)
    pub fn fetch<NetS: Sender<PublicKey = P>>(
        &mut self,
        sender: &mut WrappedSender<NetS, wire::Message<Key>>,
    ) {
        self.waiter = None;

        // Try each pending key until one succeeds
        let mut earliest_rate_limit: Option<SystemTime> = None;
        let mut found_eligible_peers = false;

        // Detach the queue to leave skipped entries untouched and remove only the
        // successfully sent key.
        let pending = mem::replace(&mut self.pending, PrioritySet::new());
        let mut sent = None;
        for (key, _) in pending.iter() {
            // Skip keys with no eligible peers
            let Some((candidates, retries)) = self.candidates(key) else {
                self.requests_created.inc(Status::Dropped);
                continue;
            };

            // Mark that an eligible peer was found
            self.requests_created.inc(Status::Success);
            found_eligible_peers = true;

            // If sending fails, try another eligible peer until one accepts the request.
            let mut selection = candidates.select(&mut self.participants.weights);
            while let Some(index) = selection.next(&mut self.context, retries) {
                let peer = self.participants.peers[index].0.clone();

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
                let id = self.request_id;
                self.request_id = self.request_id.wrapping_add(1);
                let message = wire::Message {
                    id,
                    payload: wire::Payload::Request(key.clone()),
                };
                match checked.send(message, self.priority_requests) {
                    Unreliable::Outcome(Feedback::Ok | Feedback::Backoff) => {
                        // Success, so move from pending to active
                        self.requests_sent.inc(Status::Success);
                        let now = self.context.current();
                        sent = Some((key.clone(), id, peer, now));
                        break;
                    }
                    feedback @ (Unreliable::Rejected | Unreliable::Outcome(Feedback::Closed)) => {
                        // Send was not handled, try next peer
                        self.requests_sent.inc(Status::Dropped);
                        debug!(?peer, ?feedback, "send failed");
                    }
                }
            }
            if sent.is_some() {
                break;
            }
        }

        // Restore the pending queue before moving a successful request to active tracking.
        self.pending = pending;
        if let Some((key, id, peer, start)) = sent {
            assert!(self.pending.remove(&key));
            let deadline = start.checked_add(self.timeout).expect("time overflowed");
            self.active.put(id, deadline);
            self.requests.insert(id, ActiveRequest { key, peer, start });
            return;
        }

        // Set waiter for next fetch attempt
        self.waiter = Some(if let Some(rate_limit_time) = earliest_rate_limit {
            // Use rate limit expiry time
            rate_limit_time
        } else if found_eligible_peers {
            // Peers exist but all sends failed, so use the retry timeout
            self.context.current() + self.retry_timeout
        } else {
            // No eligible peers yet. The engine still keeps polling; this just defers the next
            // outbound attempt until some external change (like a peer set update) clears it.
            self.context.current().saturating_add_ext(Duration::MAX)
        });
    }

    /// Retains only the fetches whose keys satisfy the predicate.
    pub fn retain(&mut self, predicate: impl Fn(&Key) -> bool) {
        for (id, _) in self.requests.extract_if(|_, req| !predicate(&req.key)) {
            self.active.remove(&id);
        }
        self.pending.retain(&predicate);
        self.targets.retain(|k, _| predicate(k));
        self.retries.retain(|k, _| predicate(k));

        // Clear waiter since the key that caused it may have been removed
        self.waiter = None;
    }

    /// Adds a key to the pending queue, ahead of all retries.
    ///
    /// # Panics
    ///
    /// Panics if the key is already pending.
    pub fn add_ready(&mut self, key: Key) {
        assert!(!self.pending.contains(&key));
        // A previous pending key may have pushed the waiter far into the future
        // because no eligible peer could serve it. A new ready key can still be
        // fetchable, so wake pending processing immediately.
        self.waiter = None;
        self.pending.put(key, (false, self.context.current()));
    }

    /// Schedules another attempt after a dispatched request did not resolve the key, advancing
    /// its retry count.
    ///
    /// # Panics
    ///
    /// Panics if the key is already pending.
    pub fn add_retry(&mut self, key: Key) {
        assert!(!self.pending.contains(&key));
        let retries = self.retries.entry(key.clone()).or_default();
        *retries = retries.saturating_add(1);

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

    /// Removes and returns the key with the next request timeout.
    ///
    /// Targets are not removed on timeout.
    pub fn pop_active(&mut self) -> Option<Key> {
        // Pop the next deadline
        let (id, _) = self.active.pop()?;

        // Remove the expired request and charge its peer for failing to serve it.
        let req = self.requests.remove(&id)?;
        self.update_performance(&req.peer, self.timeout, 0);

        Some(req.key)
    }

    /// Processes a response from a peer.
    ///
    /// Removes the matching request and returns its key and network response time. For a data
    /// response, the caller must report it with [`Self::record_response`] after the consumer
    /// decides it should be attributed to the peer.
    ///
    /// Targets are not removed here. The caller clears them when the logical fetch completes or
    /// is ignored. On invalid data, the caller blocks the peer, which is then skipped until the
    /// network unblocks it.
    ///
    /// Note that this matches responses against the peer a request was already sent to. A later
    /// `reconcile()` call may remove that peer from the candidate pool for future sends, but it
    /// does not retroactively invalidate the in-flight request.
    pub fn pop_response(&mut self, id: ID, peer: &P) -> Option<(Key, Duration)> {
        let req = match self.requests.entry(id) {
            Entry::Occupied(entry) if &entry.get().peer == peer => entry.remove(),
            _ => return None,
        };
        self.active.remove(&id);
        let elapsed = self
            .context
            .current()
            .duration_since(req.start)
            .unwrap_or_default();
        Some((req.key, elapsed))
    }

    /// Attributes a received data response to its serving peer.
    ///
    /// Record only responses the consumer judged complete or partially useful, and record each
    /// network response once, even when local subscribers reuse it.
    pub fn record_response(&mut self, peer: &P, elapsed: Duration, bytes: usize) {
        self.update_performance(peer, elapsed, bytes);
        self.resolves.observe(elapsed.as_secs_f64());
    }

    /// Processes a response indicating that the peer does not have the requested data.
    ///
    /// Records zero useful bytes and the time spent waiting for the reply.
    pub fn pop_missing(&mut self, id: ID, peer: &P) -> Option<Key> {
        let (key, elapsed) = self.pop_response(id, peer)?;
        self.update_performance(peer, elapsed, 0);
        Some(key)
    }

    /// Reconciles the peers available to future fetches with the latest tracked peer set.
    pub fn reconcile(&mut self, peers: &[P]) {
        // A stable, duplicate-free peer order makes both sampling modes reproducible.
        let mut peers = peers.to_vec();
        peers.sort_unstable();
        peers.dedup();

        // Retained peers keep their throughput history. New or rejoining peers start
        // without observations, at the minimum weight.
        let peers: Vec<_> = peers
            .into_iter()
            .map(|peer| {
                let score = self
                    .participants
                    .index(&peer)
                    .map_or_else(Score::default, |index| self.participants.peers[index].1);
                (peer, score)
            })
            .collect();

        // Local and blocked peers retain their roster entries but are excluded from
        // both sampling modes. Unblocking can restore their current weights in place.
        let weights = WeightedIndex::new(peers.iter().map(|(peer, score)| {
            if self.me.as_ref() == Some(peer) || self.blocked.contains(peer) {
                0
            } else {
                score.weight()
            }
        }));
        self.participants = Participants { peers, weights };

        // Clear waiter (may no longer apply)
        self.waiter = None;
    }

    /// Replaces the set of peers the network currently blocks.
    ///
    /// Blocked peers keep their place in any target sets and are skipped until
    /// a later update no longer lists them. Clears the waiter, since an
    /// unblocked peer may make a waiting fetch servable.
    pub fn set_blocked(&mut self, blocked: impl IntoIterator<Item = P>) {
        let blocked: AHashSet<P> = blocked.into_iter().collect();
        for peer in self.blocked.symmetric_difference(&blocked) {
            if self.me.as_ref() == Some(peer) {
                continue;
            }
            if let Some(index) = self.participants.index(peer) {
                let weight = if blocked.contains(peer) {
                    0
                } else {
                    self.participants.peers[index].1.weight()
                };
                self.participants.weights.set(index, weight);
            }
        }
        self.blocked = blocked;
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
    /// of being restricted to targets. Its retry count is preserved.
    ///
    /// Clears the waiter to allow immediate retry with any available peer.
    pub fn clear_targets(&mut self, key: &Key) {
        self.targets.remove(key);

        // Clear waiter to allow retry without targets
        self.waiter = None;
    }

    /// Drops the targets and peer-selection history of a key whose fetch has ended.
    pub fn clear(&mut self, key: &Key) {
        self.targets.remove(key);
        self.retries.remove(key);
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
        self.requests.values().any(|req| &req.key == key) || self.pending.contains(key)
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
        IoBufs, KeyedRateLimiter, Quota, Runner as _, Supervisor as _,
        deterministic::{self, Context, Runner},
    };
    use commonware_utils::{NZU32, sync::RwLock};
    use std::{slice, sync::Arc, time::Duration};

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

    fn create_test_fetcher(context: Context) -> Fetcher<Context, PublicKey, MockKey> {
        let public_key = PrivateKey::from_seed(0).public_key();
        let config = Config {
            me: Some(public_key),
            timeout: Duration::from_secs(5),
            retry_timeout: Duration::from_millis(100),
            priority_requests: false,
        };

        Fetcher::new(context, config)
    }

    /// Returns a fetcher waiting for a target outside its peer set, plus an eligible peer.
    fn create_unservable_fetcher(
        context: &Context,
    ) -> (Fetcher<Context, PublicKey, MockKey>, PublicKey) {
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

    /// Registers a request and its timeout for tests that bypass sending.
    fn add_test_active(fetcher: &mut Fetcher<Context, PublicKey, MockKey>, id: ID, key: MockKey) {
        let peer = PrivateKey::from_seed(1).public_key();
        let now = fetcher.context.current();
        let deadline = now + Duration::from_secs(5);
        fetcher.active.put(id, deadline);
        fetcher.requests.insert(
            id,
            ActiveRequest {
                key,
                peer,
                start: now,
            },
        );
    }

    /// Number of peer selections drawn by statistical selection tests.
    const DRAWS: usize = 1_200;

    fn peer_weight(fetcher: &Fetcher<Context, PublicKey, MockKey>, peer: &PublicKey) -> u64 {
        let index = fetcher.participants.index(peer).unwrap();
        fetcher.participants.peers[index].1.weight()
    }

    /// Counts how often each peer is drawn first for `key` over [`DRAWS`] selections.
    fn first_picks(
        fetcher: &mut Fetcher<Context, PublicKey, MockKey>,
        key: &MockKey,
    ) -> AHashMap<PublicKey, usize> {
        // These draws send no requests, so scores and retry counts stay fixed.
        let mut picks = AHashMap::new();
        for _ in 0..DRAWS {
            let first = fetcher.get_eligible_peers(key)[0].clone();
            *picks.entry(first).or_default() += 1;
        }
        picks
    }

    /// Sends the only pending fetch and returns its request ID and peer.
    fn send_next<S: Sender<PublicKey = PublicKey>>(
        fetcher: &mut Fetcher<Context, PublicKey, MockKey>,
        sender: &mut WrappedSender<S, wire::Message<MockKey>>,
    ) -> (ID, PublicKey) {
        fetcher.fetch(sender);
        assert_eq!(fetcher.len_pending(), 0);
        assert_eq!(fetcher.len_active(), 1);
        let (&id, req) = fetcher.requests.iter().next().unwrap();
        (id, req.peer.clone())
    }

    #[test]
    fn test_retain_function() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

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
            assert!(fetcher.requests.values().any(|req| req.key == MockKey(10)));
            assert!(!fetcher.requests.values().any(|req| req.key == MockKey(20)));
            assert!(!fetcher.requests.values().any(|req| req.key == MockKey(30)));
            assert_eq!(fetcher.active.len(), 1);
            assert!(fetcher.active.contains(&100));
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
            let mut fetcher = create_test_fetcher(context);

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
            let mut fetcher = create_test_fetcher(context);

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
            let mut fetcher = create_test_fetcher(context);

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
            let mut fetcher = create_test_fetcher(context);

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
            let mut fetcher = create_test_fetcher(context);

            fetcher.add_retry(MockKey(1));
            // This should panic
            fetcher.add_retry(MockKey(1));
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
            fetcher.add_retry(MockKey(1));
            assert!(fetcher.get_pending_deadline().is_some());

            // Adding another key should still leave a deadline
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
            let fetcher = create_test_fetcher(context);

            // No deadline when empty (requester has no timeouts)
            assert!(fetcher.get_active_deadline().is_none());
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
    fn test_pop_response_defers_peer_rating() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher(context);
            let local_peer = PrivateKey::from_seed(0).public_key();
            let peer = PrivateKey::from_seed(1).public_key();
            fetcher.reconcile(&[local_peer, peer.clone()]);

            add_test_active(&mut fetcher, 100, MockKey(10));

            // An unrelated response must leave the active request in place.
            assert!(fetcher.pop_response(999, &peer).is_none());
            assert_eq!(fetcher.len_active(), 1);

            // Matching the response retires the request and reports its elapsed time.
            fetcher.context.sleep(Duration::from_millis(20)).await;
            let (key, elapsed) = fetcher.pop_response(100, &peer).expect("matching response");
            assert_eq!(key, MockKey(10));
            assert_eq!(elapsed, Duration::from_millis(20));
            assert_eq!(fetcher.len_active(), 0);

            // Receiving bytes does not score the peer, because the consumer may decide the
            // key became obsolete before inspecting the response. The peer keeps its default
            // weight until the response is attributed to it.
            let initial = Score::default().weight();
            assert_eq!(peer_weight(&fetcher, &peer), initial);
            fetcher.record_response(&peer, elapsed, 1024);
            assert!(peer_weight(&fetcher, &peer) > initial);
        });
    }

    #[test]
    fn test_pop_response_requires_matching_peer() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);
            let peer = PrivateKey::from_seed(1).public_key();
            let other_peer = PrivateKey::from_seed(2).public_key();
            add_test_active(&mut fetcher, 100, MockKey(10));
            add_test_active(&mut fetcher, 101, MockKey(20));

            // A response from another peer leaves the request active
            assert!(fetcher.pop_response(100, &other_peer).is_none());
            assert_eq!(fetcher.len_active(), 2);
            assert!(fetcher.active.contains(&100));
            assert_eq!(
                fetcher.requests.get(&100).map(|req| &req.key),
                Some(&MockKey(10))
            );

            // The matching peer's response removes only that request from tracking
            let (key, _) = fetcher
                .pop_response(100, &peer)
                .expect("matching peer's response must pop the request");
            assert_eq!(key, MockKey(10));
            assert_eq!(fetcher.len_active(), 1);
            assert!(!fetcher.active.contains(&100));
            assert!(fetcher.active.contains(&101));
            assert_eq!(
                fetcher.requests.get(&101).map(|req| &req.key),
                Some(&MockKey(20))
            );

            // A repeated response is ignored
            assert!(fetcher.pop_response(100, &peer).is_none());
            assert_eq!(fetcher.len_active(), 1);
            assert!(fetcher.active.contains(&101));
        });
    }

    #[test]
    fn test_record_response_scores_by_size() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher(context);
            let local_peer = PrivateKey::from_seed(0).public_key();
            let small = PrivateKey::from_seed(1).public_key();
            let large = PrivateKey::from_seed(2).public_key();
            fetcher.reconcile(&[local_peer, small.clone(), large.clone()]);

            // Equal response times isolate the effect of payload size on the throughput score.
            let elapsed = Duration::from_millis(20);
            fetcher.record_response(&small, elapsed, 1);
            fetcher.record_response(&large, elapsed, 1_000);
            assert!(peer_weight(&fetcher, &large) > peer_weight(&fetcher, &small));

            // Weighted draws must reflect the larger payload's score advantage.
            let picks = first_picks(&mut fetcher, &MockKey(1));
            assert!(picks[&large] > DRAWS * 9 / 10, "{picks:?}");
        });
    }

    #[test]
    fn test_empty_fast_reply_cannot_outrank_real_payload() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher(context);
            let local_peer = PrivateKey::from_seed(0).public_key();
            let empty = PrivateKey::from_seed(1).public_key();
            let real = PrivateKey::from_seed(2).public_key();
            fetcher.reconcile(&[local_peer, empty.clone(), real.clone()]);

            // Repeated empty replies earn no throughput, while the slower peer serves data.
            for _ in 0..3 {
                fetcher.record_response(&empty, Duration::from_millis(1), 0);
                fetcher.record_response(&real, Duration::from_millis(50), 1024);
            }
            assert_eq!(peer_weight(&fetcher, &empty), 1);
            assert!(peer_weight(&fetcher, &real) > peer_weight(&fetcher, &empty));

            // Selection must favor the peer that actually supplied data.
            let picks = first_picks(&mut fetcher, &MockKey(1));
            assert!(picks[&real] > DRAWS * 9 / 10, "{picks:?}");
        });
    }

    /// Prompt missing-data replies cost less than delayed replies or timeouts, but none can
    /// improve the peer's weight.
    #[test]
    fn test_missing_replies_charge_elapsed_time() {
        let [immediate, delayed, silent] =
            [Some(Duration::ZERO), Some(Duration::from_millis(100)), None].map(|response_time| {
                Runner::timed(Duration::from_secs(10)).start(|context| async move {
                    let mut fetcher = create_test_fetcher(context.child("fetcher"));
                    let peer = PrivateKey::from_seed(1).public_key();
                    fetcher.reconcile(slice::from_ref(&peer));

                    // The same useful response establishes each peer's initial score.
                    fetcher.record_response(&peer, Duration::from_millis(1), 1024);
                    let initial = peer_weight(&fetcher, &peer);
                    let key = MockKey(1);
                    fetcher.add_ready(key.clone());
                    let mut sender = WrappedSender::new(SuccessMockSender::default());
                    let (id, _) = send_next(&mut fetcher, &mut sender);

                    // Missing replies end the wait when they arrive. Silence lasts until expiry.
                    let elapsed = response_time.unwrap_or(fetcher.timeout);
                    if !elapsed.is_zero() {
                        context.sleep(elapsed).await;
                    }
                    let failed = if response_time.is_some() {
                        fetcher.pop_missing(id, &peer)
                    } else {
                        fetcher.pop_active()
                    };
                    assert_eq!(failed, Some(key));
                    let weight = peer_weight(&fetcher, &peer);
                    assert!(weight <= initial);
                    weight
                })
            });

        assert!(immediate > delayed);
        assert!(delayed > silent);
    }

    /// Only successful service supplies evidence of recovery after a failed request.
    #[test]
    fn test_failures_demote_fast_peers_until_successful_service() {
        for timeout in [false, true] {
            Runner::default().start(|context| async move {
                let mut fetcher = create_test_fetcher(context.child("fetcher"));
                let fast = PrivateKey::from_seed(1).public_key();
                let steady = PrivateKey::from_seed(2).public_key();
                fetcher.reconcile(&[fast.clone(), steady.clone()]);

                // Establish a fast history whose preference must disappear after a failure.
                let mut expected = Score::default();
                expected.record(Duration::from_millis(1), 1024);
                fetcher.record_response(&fast, Duration::from_millis(1), 1024);
                fetcher.record_response(&steady, Duration::from_millis(50), 1024);
                let initial = peer_weight(&fetcher, &fast);
                assert!(initial > peer_weight(&fetcher, &steady));

                // Both failures charge zero bytes, with time measured until the reply or expiry.
                let key = MockKey(1);
                fetcher.add_targets(key.clone(), [fast.clone()]);
                fetcher.add_ready(key.clone());
                let mut sender = WrappedSender::new(SuccessMockSender::default());
                let (id, peer) = send_next(&mut fetcher, &mut sender);
                assert_eq!(peer, fast);
                let elapsed = if timeout {
                    fetcher.timeout
                } else {
                    Duration::from_millis(100)
                };
                context.sleep(elapsed).await;
                let failed = if timeout {
                    fetcher.pop_active()
                } else {
                    fetcher.pop_missing(id, &peer)
                };
                assert_eq!(failed, Some(key.clone()));
                expected.record(elapsed, 0);
                let demoted = expected.weight();
                assert_eq!(peer_weight(&fetcher, &fast), demoted);
                assert!(demoted < peer_weight(&fetcher, &steady));
                fetcher.add_retry(key.clone());

                // Neither waiting nor sampling opportunities improve the peer's score.
                context.sleep(Duration::from_secs(3_600)).await;
                assert_eq!(peer_weight(&fetcher, &fast), demoted);
                let (id, peer) = send_next(&mut fetcher, &mut sender);
                assert_eq!(peer_weight(&fetcher, &fast), demoted);
                context.sleep(Duration::from_millis(1)).await;
                let (_, elapsed) = fetcher.pop_response(id, &peer).unwrap();
                assert_eq!(peer_weight(&fetcher, &fast), demoted);
                fetcher.record_response(&peer, elapsed, 1024);
                expected.record(elapsed, 1024);
                assert_eq!(peer_weight(&fetcher, &fast), expected.weight());
                assert!(expected.weight() > demoted);
                assert!(expected.weight() < initial);
            });
        }
    }

    #[test]
    fn test_reconcile_and_block() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();

            // Test reconcile with peers
            fetcher.reconcile(&[peer1.clone(), peer2.clone()]);

            // A blocked participant is skipped without leaving the participant set.
            fetcher.set_blocked([peer1.clone()]);
            assert_eq!(fetcher.get_eligible_peers(&MockKey(1)), vec![peer2]);
            assert!(fetcher.participants.index(&peer1).is_some());
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
    fn test_retain_edge_cases() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

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
            let mut fetcher = create_test_fetcher(context);

            // Add keys to active with specific IDs
            add_test_active(&mut fetcher, 100, MockKey(1));
            add_test_active(&mut fetcher, 101, MockKey(2));

            // Retain only MockKey(1)
            fetcher.retain(|key| key.0 == 1);

            // Only the active request for MockKey(1) remains
            assert_eq!(fetcher.len_active(), 1);
            assert!(fetcher.requests.values().any(|req| req.key == MockKey(1)));
            assert!(!fetcher.requests.values().any(|req| req.key == MockKey(2)));

            // MockKey(1) keeps its original request ID
            assert!(fetcher.requests.contains_key(&100));
        });
    }

    #[test]
    fn test_mixed_operations() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);

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
            let mut fetcher = create_test_fetcher(context.child("fetcher"));

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
            let mut fetcher = create_test_fetcher(context.child("fetcher"));

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
            let mut fetcher: Fetcher<_, _, MockKey> =
                Fetcher::new(context.child("fetcher"), config);
            fetcher.reconcile(&[public_key, other_public_key]);
            let mut sender = WrappedSender::new(FailMockSender::default());

            // Rejected sends leave the key pending and arm a retry deadline, even if
            // another fetch call immediately tries to send it again.
            fetcher.add_ready(MockKey(1));
            fetcher.fetch(&mut sender);
            fetcher.fetch(&mut sender);

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
            let mut fetcher: Fetcher<_, _, MockKey> =
                Fetcher::new(context.child("fetcher"), config);
            fetcher.reconcile(&[public_key, peer1.clone()]);
            let mut sender = WrappedSender::new(FailMockSender::default());

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
            let mut fetcher: Fetcher<_, _, MockKey> =
                Fetcher::new(context.child("fetcher"), config);
            fetcher.reconcile(&[public_key, peer]);
            let mut sender = WrappedSender::new(SuccessMockSender::default());

            // Key 1 cannot find its target and parks the fetcher.
            fetcher.add_targets(MockKey(1), [missing_peer]);
            fetcher.add_ready(MockKey(1));
            fetcher.fetch(&mut sender);
            assert!(fetcher.waiter.is_some());

            // Fresh demand must wake the fetcher and progress while key 1 remains pending.
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
            let mut fetcher: Fetcher<_, _, MockKey> =
                Fetcher::new(context.child("fetcher"), config);
            fetcher.reconcile(&[public_key, peer]);
            let mut sender = WrappedSender::new(SuccessMockSender::default());

            // Key 1 cannot find its target and parks the fetcher.
            fetcher.add_targets(MockKey(1), [missing_peer]);
            fetcher.add_ready(MockKey(1));
            fetcher.fetch(&mut sender);
            assert!(fetcher.waiter.is_some());

            // New retry demand replaces the indefinite waiter with its own deadline.
            fetcher.add_retry(MockKey(2));
            let deadline = fetcher.get_pending_deadline().unwrap();
            assert!(deadline <= context.current() + Duration::from_millis(100));

            // When due, the retry progresses independently of the unavailable target.
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
                    let mut sender = WrappedSender::new(SuccessMockSender::default());
                    fetcher.fetch(&mut sender);
                    assert!(fetcher.waiter.is_some());
                }

                let key = fetcher.pop_active().expect("active key should exist");
                fetcher.add_retry(key);
                let deadline = fetcher.get_pending_deadline().unwrap();
                assert!(deadline <= context.current() + Duration::from_millis(100));

                let mut sender = WrappedSender::new(SuccessMockSender::default());
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
            let mut sender = WrappedSender::new(SuccessMockSender::default());

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
            let mut sender = WrappedSender::new(SuccessMockSender::default());

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
            let mut fetcher: Fetcher<_, _, MockKey> =
                Fetcher::new(context.child("fetcher"), config);
            // Add peers (FailMockSender doesn't rate limit, just fails sends)
            fetcher.reconcile(&[public_key, peer1, peer2]);
            let mut sender = WrappedSender::new(FailMockSender::default());

            // Add a key and attempt a fetch. Every send fails.
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

            // Reaching the retry deadline permits another send attempt.
            let wait_duration = pending_deadline
                .duration_since(context.current())
                .unwrap_or(Duration::ZERO);
            context.sleep(wait_duration).await;
            fetcher.fetch(&mut sender);
        });
    }

    /// A key without targets may use any peer of the latest tracked set. Targets restrict
    /// selection to their intersection with that set.
    #[test]
    fn test_eligible_peers_follow_latest_set_and_targets() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher(context);
            let me = PrivateKey::from_seed(0).public_key();
            let primary = PrivateKey::from_seed(1).public_key();
            let secondary = PrivateKey::from_seed(2).public_key();
            let other = PrivateKey::from_seed(3).public_key();
            let untracked = PrivateKey::from_seed(4).public_key();
            fetcher.reconcile(&[me, primary.clone(), secondary.clone(), other.clone()]);

            // Without targets, every peer of the latest set except self is eligible.
            let mut eligible = fetcher.get_eligible_peers(&MockKey(1));
            eligible.sort();
            let mut expected = vec![primary.clone(), secondary.clone(), other];
            expected.sort();
            assert_eq!(eligible, expected);

            // Targets restrict eligibility to themselves, and the untracked target is skipped.
            fetcher.add_targets(MockKey(1), [primary.clone(), secondary.clone(), untracked]);
            let eligible = fetcher.get_eligible_peers(&MockKey(1));
            assert_eq!(eligible.len(), 2);
            assert!(eligible.contains(&primary));
            assert!(eligible.contains(&secondary));

            // A single target is the only eligible peer.
            fetcher.add_targets(MockKey(2), [secondary.clone()]);
            assert_eq!(fetcher.get_eligible_peers(&MockKey(2)), vec![secondary]);
        });
    }

    #[test]
    fn test_add_targets() {
        let runner = Runner::default();
        runner.start(|context| async {
            let mut fetcher = create_test_fetcher(context);
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
            let mut fetcher = create_test_fetcher(context);
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
            let mut fetcher = create_test_fetcher(context.child("fetcher"));
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone()]);
            fetcher.add_targets(MockKey(1), [peer1.clone()]);
            fetcher.add_targets(MockKey(2), [peer1.clone(), peer2.clone()]);

            // A blocked peer keeps its place in every target set but is not eligible.
            fetcher.set_blocked([peer1.clone()]);
            assert!(fetcher.targets.get(&MockKey(1)).unwrap().contains(&peer1));
            assert!(fetcher.get_eligible_peers(&MockKey(1)).is_empty());
            assert_eq!(fetcher.get_eligible_peers(&MockKey(2)), vec![peer2]);

            // Lifting the block makes the peer eligible again and wakes the fetcher.
            fetcher.waiter = Some(context.current());
            fetcher.set_blocked([]);
            assert!(fetcher.waiter.is_none());
            assert_eq!(fetcher.get_eligible_peers(&MockKey(1)), vec![peer1]);
        });
    }

    #[test]
    fn test_target_behavior_on_send_failure() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher(context.child("fetcher"));
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            let peer3 = PrivateKey::from_seed(3).public_key();
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone(), peer3]);
            let mut sender = WrappedSender::new(FailMockSender::default());

            // Synchronous send failures leave the key pending with both targets intact.
            fetcher.add_targets(MockKey(2), [peer1, peer2]);
            fetcher.add_ready(MockKey(2));
            assert_eq!(fetcher.targets.get(&MockKey(2)).unwrap().len(), 2);
            fetcher.fetch(&mut sender);
            assert_eq!(fetcher.targets.get(&MockKey(2)).unwrap().len(), 2);
            assert!(fetcher.pending.contains(&MockKey(2)));
        });
    }

    #[test]
    fn test_target_retention_on_pop() {
        let runner = Runner::default();
        runner.start(|context| async move {
            let mut fetcher = create_test_fetcher(context.child("fetcher"));
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone()]);
            let mut sender = WrappedSender::new(SuccessMockSender::default());

            // The timeout path keeps both targets for later retries.
            fetcher.add_targets(MockKey(1), [peer1.clone(), peer2.clone()]);
            fetcher.add_ready(MockKey(1));
            assert_eq!(fetcher.targets.get(&MockKey(1)).unwrap().len(), 2);
            fetcher.fetch(&mut sender);
            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(fetcher.pop_active(), Some(MockKey(1)));
            assert_eq!(fetcher.targets.get(&MockKey(1)).unwrap().len(), 2);
            fetcher.targets.clear();

            // A no-data response also leaves the target restriction in place.
            fetcher.add_targets(MockKey(2), [peer1.clone()]);
            fetcher.add_ready(MockKey(2));
            fetcher.fetch(&mut sender);
            let id = *fetcher.active.iter().next().unwrap().0;
            assert_eq!(fetcher.pop_missing(id, &peer1), Some(MockKey(2)));
            assert!(fetcher.targets.get(&MockKey(2)).unwrap().contains(&peer1));
            fetcher.targets.clear();

            // Receiving data keeps targets until the caller retires the logical fetch.
            fetcher.add_targets(MockKey(3), [peer1.clone()]);
            fetcher.add_ready(MockKey(3));
            fetcher.fetch(&mut sender);
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
            let mut fetcher = create_test_fetcher(context.child("fetcher"));
            let public_key = PrivateKey::from_seed(0).public_key();
            let peer1 = PrivateKey::from_seed(1).public_key();
            let peer2 = PrivateKey::from_seed(2).public_key();
            let peer3 = PrivateKey::from_seed(3).public_key();

            // Add only peer1 and peer2 to the peer set (peer3 is not in the peer set)
            fetcher.reconcile(&[public_key, peer1, peer2]);

            // Target peer3 while it is outside the current peer set.
            fetcher.add_targets(MockKey(1), [peer3]);
            assert!(fetcher.targets.contains_key(&MockKey(1)));

            // Add key to pending
            fetcher.add_ready(MockKey(1));

            // Fetch should wait for targets and not fall back to any peer
            let mut sender = WrappedSender::new(SuccessMockSender::default());
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
            let mut fetcher = create_test_fetcher(context);
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
            let mut fetcher: Fetcher<_, _, MockKey> =
                Fetcher::new(context.child("fetcher"), config);
            fetcher.reconcile(&[public_key, peer1.clone(), peer2.clone()]);
            let quota = Quota::per_second(NZU32!(1));
            let mut sender =
                WrappedSender::new(LimitedMockSender::new(quota, context.child("rate_limiter")));

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
            assert_eq!(
                fetcher.get_pending_deadline(),
                Some(context.current() + Duration::from_secs(1))
            );

            // Wait for rate limit to reset
            context.sleep(Duration::from_secs(1)).await;

            // Now MockKey(2) can be fetched
            fetcher.fetch(&mut sender);
            assert_eq!(fetcher.len_active(), 3);
            assert_eq!(fetcher.len_pending(), 0);
        });
    }

    #[test]
    fn test_selection_weighted_by_service() {
        Runner::default().start(|context| async {
            let mut fetcher = create_test_fetcher(context);
            let local = PrivateKey::from_seed(0).public_key();
            let fast = PrivateKey::from_seed(1).public_key();
            let slow = PrivateKey::from_seed(2).public_key();
            let medium = PrivateKey::from_seed(3).public_key();
            fetcher.reconcile(&[local, fast.clone(), slow.clone(), medium.clone()]);

            // Equal payload sizes isolate response latency as the source of each weight.
            fetcher.record_response(&fast, Duration::from_millis(10), 1024);
            fetcher.record_response(&slow, Duration::from_millis(500), 1024);
            fetcher.record_response(&medium, Duration::from_millis(200), 1024);

            // Enumerating the candidates must visit every eligible peer exactly once.
            let mut peers = fetcher.get_eligible_peers(&MockKey(1));
            peers.sort();
            let mut expected = vec![fast.clone(), slow.clone(), medium.clone()];
            expected.sort();
            assert_eq!(peers, expected);

            // Faster responses earn more first choices, while every peer stays reachable.
            let picks = first_picks(&mut fetcher, &MockKey(1));
            assert!(picks[&fast] > DRAWS * 8 / 10, "{picks:?}");
            assert!(picks[&medium] > picks[&slow], "{picks:?}");
            assert!(picks[&slow] > 0, "{picks:?}");
        });
    }

    #[test]
    fn test_selection_uniform_without_scores() {
        Runner::default().start(|context| async {
            let mut fetcher = create_test_fetcher(context);
            let peers: Vec<_> = (1..=3)
                .map(|seed| PrivateKey::from_seed(seed).public_key())
                .collect();
            fetcher.reconcile(&peers);

            // Peers without observations receive equal positive weights, so their
            // first-choice counts should be roughly even.
            let picks = first_picks(&mut fetcher, &MockKey(1));
            for peer in &peers {
                let count = picks[peer];
                assert!((DRAWS / 4..DRAWS * 5 / 12).contains(&count), "{picks:?}");
            }
        });
    }

    /// Retries approach uniform sampling over eligible peers without widening target or block
    /// restrictions, even when an excluded peer has the highest score.
    #[test]
    fn test_retries_flatten_sampling() {
        for targeted in [false, true] {
            Runner::seeded(0).start(|context| async move {
                let mut fetcher = create_test_fetcher(context);
                let peers: Vec<_> = (0..7)
                    .map(|seed| PrivateKey::from_seed(seed).public_key())
                    .collect();
                fetcher.reconcile(&peers[..6]);
                fetcher.set_blocked([peers[5].clone()]);
                let key = MockKey(1);

                // Leave the same three peers eligible in the target or shared pool. The target
                // set also contains a blocked peer and a peer outside the current roster.
                if targeted {
                    fetcher.add_targets(key.clone(), [1, 2, 3, 5, 6].map(|i| peers[i].clone()));
                } else {
                    fetcher.set_blocked([peers[4].clone(), peers[5].clone()]);
                }

                // Give one eligible peer a large advantage and an ineligible peer an
                // even higher score, so filtering and flattening are both observable.
                fetcher.record_response(&peers[1], Duration::from_millis(1), 1024);
                fetcher.record_response(&peers[2], Duration::from_millis(100), 1024);
                fetcher.record_response(&peers[3], Duration::from_millis(100), 1024);
                fetcher.record_response(&peers[4], Duration::from_nanos(1), 1024);
                let weighted = peer_weight(&fetcher, &peers[1]) as f64
                    / (1..=3)
                        .map(|i| peer_weight(&fetcher, &peers[i]))
                        .sum::<u64>() as f64;

                // Compare each retry count with its weighted/uniform mixture, including
                // the largest counter value used by a long-lived unresolved fetch.
                let mut previous = DRAWS + 1;
                for retries in [0, 1, 7, u32::MAX] {
                    fetcher.retries.insert(key.clone(), retries);
                    let picks = first_picks(&mut fetcher, &key);
                    assert_eq!(picks.len(), 3, "{picks:?}");
                    for peer in &peers[1..=3] {
                        assert!(picks.contains_key(peer), "{picks:?}");
                    }
                    let weighted_share = 1.0 / (f64::from(retries) + 1.0);
                    let expected =
                        DRAWS as f64 * (weighted_share * weighted + (1.0 - weighted_share) / 3.0);
                    let count = picks[&peers[1]];
                    assert!(
                        (count as f64 - expected).abs() < DRAWS as f64 / 12.0,
                        "retries={retries} count={count} expected={expected}"
                    );
                    assert!(count < previous, "retries={retries}: {picks:?}");
                    previous = count;
                    assert_cached_weights(&fetcher);
                }
            });
        }
    }

    /// A completed attempt leaves its peer eligible for the next request, whether it timed out,
    /// reported missing data, or only partially resolved the fetch.
    #[test]
    fn test_retry_revisits_peers_after_each_outcome() {
        for targeted in [false, true] {
            for outcome in ["timeout", "missing", "partial"] {
                Runner::seeded(0).start(|context| async move {
                    let mut fetcher = create_test_fetcher(context.child("fetcher"));
                    let peers: Vec<_> = (1..=3)
                        .map(|seed| PrivateKey::from_seed(seed).public_key())
                        .collect();
                    fetcher.reconcile(&peers);
                    let key = MockKey(1);
                    let eligible = if targeted { &peers[..2] } else { &peers[..] };
                    if targeted {
                        fetcher.add_targets(key.clone(), eligible.iter().cloned());
                    }

                    // A dominant score makes the first peer the expected initial choice.
                    fetcher.record_response(&peers[0], Duration::from_nanos(1), 1024);
                    fetcher.add_ready(key.clone());
                    let mut sender = WrappedSender::new(SuccessMockSender::default());
                    let (id, peer) = send_next(&mut fetcher, &mut sender);
                    assert_eq!(peer, peers[0]);

                    // Exercise each way an attempt can leave the key unresolved. Retrying
                    // must preserve the serving peer's eligibility in every case.
                    match outcome {
                        "timeout" => {
                            context
                                .sleep_until(fetcher.get_active_deadline().unwrap())
                                .await;
                            assert_eq!(fetcher.pop_active(), Some(key.clone()));
                        }
                        "missing" => assert_eq!(fetcher.pop_missing(id, &peer), Some(key.clone())),
                        "partial" => {
                            let (_, elapsed) = fetcher.pop_response(id, &peer).unwrap();
                            fetcher.record_response(&peer, elapsed, 1024);
                        }
                        _ => unreachable!(),
                    }
                    fetcher.add_retry(key.clone());
                    assert_eq!(fetcher.retries[&key], 1);

                    // Every eligible peer, including the one just tried, remains available.
                    let candidates: AHashSet<_> =
                        fetcher.get_eligible_peers(&key).into_iter().collect();
                    assert_eq!(candidates, eligible.iter().cloned().collect());
                    assert!(first_picks(&mut fetcher, &key).contains_key(&peer));
                    assert_cached_weights(&fetcher);
                });
            }
        }
    }

    #[test]
    fn test_single_silent_target_is_retried() {
        Runner::default().start(|context| async move {
            let mut fetcher = create_test_fetcher(context.child("fetcher"));
            let target = PrivateKey::from_seed(1).public_key();
            let other = PrivateKey::from_seed(2).public_key();

            // An eligible non-target exposes any accidental widening after a timeout.
            fetcher.reconcile(&[target.clone(), other]);
            fetcher.add_targets(MockKey(1), [target.clone()]);
            let mut sender = WrappedSender::new(SuccessMockSender::default());
            fetcher.add_ready(MockKey(1));

            // Each timeout must lead back to the sole target, with no fallback peer.
            for _ in 0..3 {
                context
                    .sleep_until(fetcher.get_pending_deadline().unwrap())
                    .await;
                let (_, peer) = send_next(&mut fetcher, &mut sender);
                assert_eq!(peer, target);
                context
                    .sleep_until(fetcher.get_active_deadline().unwrap())
                    .await;
                assert_eq!(fetcher.pop_active(), Some(MockKey(1)));
                fetcher.add_retry(MockKey(1));
            }
        });
    }

    /// Retry counts survive target and roster changes, and end with the logical fetch.
    #[test]
    fn test_retry_history_lifecycle() {
        Runner::default().start(|context| async move {
            let mut fetcher = create_test_fetcher(context.child("fetcher"));
            let peers: Vec<_> = (1..=2)
                .map(|seed| PrivateKey::from_seed(seed).public_key())
                .collect();
            fetcher.reconcile(&peers);
            let mut sender = WrappedSender::new(SuccessMockSender::default());

            // A missing-data reply from the first target gives the key a retry count of one.
            let key = MockKey(1);
            fetcher.add_targets(key.clone(), [peers[0].clone()]);
            fetcher.add_ready(key.clone());
            let (id, peer) = send_next(&mut fetcher, &mut sender);
            assert_eq!(fetcher.pop_missing(id, &peer), Some(key.clone()));
            fetcher.add_retry(key.clone());
            assert_eq!(fetcher.retries[&key], 1);

            // Changing the target and removing the old peer preserve that history.
            fetcher.clear_targets(&key);
            fetcher.add_targets(key.clone(), [peers[1].clone()]);
            fetcher.reconcile(&peers[1..]);
            assert_eq!(fetcher.retries[&key], 1);
            context
                .sleep_until(fetcher.get_pending_deadline().unwrap())
                .await;
            let (id, peer) = send_next(&mut fetcher, &mut sender);
            assert!(fetcher.pop_response(id, &peer).is_some());
            fetcher.clear(&key);
            assert!(!fetcher.targets.contains_key(&key));
            assert!(!fetcher.retries.contains_key(&key));

            // Reusing a completed key starts fresh and accumulates its own retry count.
            fetcher.add_ready(key.clone());
            assert!(!fetcher.retries.contains_key(&key));
            send_next(&mut fetcher, &mut sender);
            context
                .sleep_until(fetcher.get_active_deadline().unwrap())
                .await;
            assert_eq!(fetcher.pop_active(), Some(key.clone()));
            fetcher.add_retry(key.clone());
            assert_eq!(fetcher.retries[&key], 1);

            // Saturating the counter must leave the key retryable and independently prunable.
            fetcher.retries.insert(key.clone(), u32::MAX);
            assert!(fetcher.pending.remove(&key));
            fetcher.add_retry(key.clone());
            assert_eq!(fetcher.retries[&key], u32::MAX);
            fetcher.add_retry(MockKey(2));
            fetcher.retain(|key| *key == MockKey(2));
            assert!(!fetcher.retries.contains_key(&key));
            assert_eq!(fetcher.retries[&MockKey(2)], 1);
        });
    }

    /// Asserts that cached weights match every participant's current score and eligibility,
    /// so a completed selection cannot leave a temporary exclusion behind.
    fn assert_cached_weights(fetcher: &Fetcher<Context, PublicKey, MockKey>) {
        let mut total = 0;
        for (index, (peer, score)) in fetcher.participants.peers.iter().enumerate() {
            let expected = if fetcher.me.as_ref() == Some(peer) || fetcher.blocked.contains(peer) {
                0
            } else {
                score.weight()
            };
            assert_eq!(fetcher.participants.weights.weight(index), expected);
            total += u128::from(expected);
        }
        assert_eq!(fetcher.participants.weights.total(), total);
    }

    /// Score updates and block changes keep cached weights in step with peer eligibility.
    #[test]
    fn test_cached_weights_follow_scores_and_blocks() {
        Runner::seeded(0).start(|context| async move {
            let mut fetcher = create_test_fetcher(context);
            let peers: Vec<_> = (0..4)
                .map(|seed| PrivateKey::from_seed(seed).public_key())
                .collect();

            // An unordered roster with a duplicate exercises normalization before indexing.
            fetcher.reconcile(&[
                peers[3].clone(),
                peers[1].clone(),
                peers[0].clone(),
                peers[2].clone(),
                peers[1].clone(),
            ]);
            assert_eq!(fetcher.participants.peers.len(), 4);

            // Update every score while keeping the local node excluded. Retain the
            // allocation address to check that later operations reuse the same roster.
            for peer in &peers {
                fetcher.record_response(peer, Duration::from_millis(10), 1024);
            }
            assert_cached_weights(&fetcher);
            let roster = fetcher.participants.peers.as_ptr();

            // A completed selection restores every weight before later observations update it.
            let peer = fetcher.get_eligible_peers(&MockKey(1))[0].clone();
            assert_cached_weights(&fetcher);
            let index = fetcher.participants.index(&peer).unwrap();
            let before = peer_weight(&fetcher, &peer);
            fetcher.update_performance(&peer, fetcher.timeout, 0);
            assert!(fetcher.participants.weights.weight(index) < before);
            assert_cached_weights(&fetcher);

            // Successful service cannot revive a peer excluded by network policy.
            fetcher.set_blocked(peers.clone());
            fetcher.record_response(&peer, Duration::ZERO, 1024);
            assert!(fetcher.candidates(&MockKey(2)).is_none());
            assert_cached_weights(&fetcher);

            // Removing blocks restores current weights while the local node stays excluded.
            fetcher.set_blocked([peers[2].clone()]);
            assert_cached_weights(&fetcher);
            fetcher.set_blocked([]);
            assert_cached_weights(&fetcher);
            assert_eq!(fetcher.participants.peers.as_ptr(), roster);

            // Completed requests release temporary exclusions and reuse the roster for
            // subsequent keys.
            let mut sender = WrappedSender::new(SuccessMockSender::default());
            for key in 3..8 {
                fetcher.add_ready(MockKey(key));
                let (id, peer) = send_next(&mut fetcher, &mut sender);
                assert!(fetcher.pop_response(id, &peer).is_some());
                fetcher.clear(&MockKey(key));
                assert_cached_weights(&fetcher);
                assert_eq!(fetcher.participants.peers.as_ptr(), roster);
            }
        });
    }

    /// Targets outside the current roster remain recorded but cannot become candidates.
    #[test]
    fn test_cached_targets_use_only_current_members() {
        Runner::seeded(0).start(|context| async move {
            let mut fetcher = create_test_fetcher(context);
            let peers: Vec<_> = (0..32)
                .map(|seed| PrivateKey::from_seed(seed).public_key())
                .collect();
            fetcher.reconcile(&peers);

            // A single target exercises binary search in the larger roster.
            let target = peers[1].clone();
            fetcher.add_targets(MockKey(1), [target.clone()]);
            assert_eq!(
                fetcher.get_eligible_peers(&MockKey(1)),
                vec![target.clone()]
            );

            // A target set larger than the roster exercises the scan path. The extra
            // identities must not become candidates.
            fetcher.add_targets(
                MockKey(1),
                (32..160).map(|seed| PrivateKey::from_seed(seed).public_key()),
            );
            assert_eq!(
                fetcher.get_eligible_peers(&MockKey(1)),
                vec![target.clone()]
            );
            assert_cached_weights(&fetcher);

            // An issued request can complete after its peer leaves the roster. Attributing
            // that response must leave the surviving peer's score unchanged.
            fetcher.record_response(&peers[2], Duration::from_millis(10), 1024);
            let surviving_weight = peer_weight(&fetcher, &peers[2]);
            let mut sender = WrappedSender::new(SuccessMockSender::default());
            fetcher.add_ready(MockKey(1));
            let (id, peer) = send_next(&mut fetcher, &mut sender);
            fetcher.reconcile(&[peers[2].clone()]);
            assert!(fetcher.pop_response(id, &peer).is_some());
            fetcher.record_response(&peer, Duration::from_nanos(1), 1024);
            assert_eq!(peer_weight(&fetcher, &peers[2]), surviving_weight);
            assert!(fetcher.get_eligible_peers(&MockKey(1)).is_empty());
            assert_cached_weights(&fetcher);

            // The target restriction survives departure. Retained peers keep their throughput
            // history. A rejoining target starts without observations.
            fetcher.reconcile(&[target.clone(), peers[2].clone()]);
            assert_eq!(peer_weight(&fetcher, &target), Score::default().weight());
            assert!(fetcher.targets[&MockKey(1)].contains(&target));
            assert_eq!(fetcher.get_eligible_peers(&MockKey(1)), vec![target]);
            assert_cached_weights(&fetcher);
        });
    }

    /// Selection depends on blocked and target set membership, not their insertion order.
    #[test]
    fn test_cached_selection_is_independent_of_set_insertion_order() {
        /// Replays the same requests with either insertion order for the peer sets.
        fn run(reverse: bool) -> Vec<PublicKey> {
            Runner::seeded(9).start(|context| async move {
                let mut fetcher = create_test_fetcher(context.child("fetcher"));
                let peers: Vec<_> = (0..12)
                    .map(|seed| PrivateKey::from_seed(seed).public_key())
                    .collect();
                fetcher.reconcile(&peers);
                for (index, peer) in peers.iter().enumerate() {
                    fetcher.record_response(peer, Duration::from_millis(index as u64 + 1), 1024);
                }

                // Vary only insertion order. Membership, scores, and the RNG seed stay fixed.
                let mut blocked = vec![peers[10].clone(), peers[11].clone()];
                let mut targets = vec![peers[1].clone(), peers[2].clone()];
                if reverse {
                    blocked.reverse();
                    targets.reverse();
                }
                fetcher.set_blocked(blocked);
                fetcher.add_targets(MockKey(1), targets);

                // Follow targeted retries, then widen to the shared index while preserving
                // the retry count. Both selection paths must remain reproducible.
                fetcher.add_ready(MockKey(1));
                let mut sender = WrappedSender::new(SuccessMockSender::default());
                let mut selected = Vec::new();
                for round in 0..10 {
                    if round == 4 {
                        fetcher.clear_targets(&MockKey(1));
                    }
                    context
                        .sleep_until(fetcher.get_pending_deadline().unwrap())
                        .await;
                    let (id, peer) = send_next(&mut fetcher, &mut sender);
                    assert_eq!(fetcher.pop_missing(id, &peer), Some(MockKey(1)));
                    fetcher.add_retry(MockKey(1));
                    selected.push(peer);
                    assert_cached_weights(&fetcher);
                }
                selected
            })
        }

        // The same random input must yield the same peers for both construction orders.
        assert_eq!(run(false), run(true));
    }

    /// A retry can reuse an available peer while another eligible peer is rate-limited,
    /// without charging the rate limit as a failed request.
    #[test]
    fn test_retry_reuses_available_peer_while_another_is_rate_limited() {
        // Exercise the target and shared pools under the same rate limits. Each seed fixes
        // whether the rate-limited peer is drawn before the available one.
        for (seed, targeted) in (0..8).flat_map(|seed| [(seed, false), (seed, true)]) {
            Runner::seeded(seed).start(|context| async move {
                let mut fetcher = create_test_fetcher(context.child("fetcher"));
                let a = PrivateKey::from_seed(1).public_key();
                let b = PrivateKey::from_seed(2).public_key();
                fetcher.reconcile(&[a.clone(), b.clone()]);
                let mut sender = WrappedSender::new(LimitedMockSender::new(
                    Quota::per_second(NZU32!(1)),
                    context.child("rate_limiter"),
                ));

                // Have B report missing data, then let its send token refill for the retry.
                fetcher.add_targets(MockKey(1), [b.clone()]);
                fetcher.add_ready(MockKey(1));
                let (id, peer) = send_next(&mut fetcher, &mut sender);
                assert_eq!(fetcher.pop_missing(id, &peer), Some(MockKey(1)));
                fetcher.add_retry(MockKey(1));
                context.sleep(Duration::from_secs(1)).await;

                // Another key consumes A's token while B is ready to accept a retry.
                fetcher.add_targets(MockKey(2), [a.clone()]);
                fetcher.add_ready(MockKey(2));
                fetcher.fetch(&mut sender);
                let weights = [peer_weight(&fetcher, &a), peer_weight(&fetcher, &b)];

                // Make both peers eligible for key 1 while A's token remains unavailable.
                if targeted {
                    fetcher.add_targets(MockKey(1), [a.clone()]);
                } else {
                    fetcher.clear_targets(&MockKey(1));
                }

                // Key 1 must use B's available token, leaving both peer scores and the
                // existing retry count unchanged until a dispatched request completes.
                fetcher.fetch(&mut sender);
                assert_eq!(fetcher.len_pending(), 0);
                assert_eq!(fetcher.len_active(), 2);
                for req in fetcher.requests.values() {
                    assert_eq!(
                        req.peer,
                        if req.key == MockKey(1) {
                            b.clone()
                        } else {
                            a.clone()
                        }
                    );
                }
                assert_eq!(fetcher.retries[&MockKey(1)], 1);
                assert_eq!(
                    [peer_weight(&fetcher, &a), peer_weight(&fetcher, &b)],
                    weights
                );
                assert_cached_weights(&fetcher);
            });
        }
    }

    /// Send availability and observed attempts for tests of local send failures.
    #[derive(Debug)]
    struct SendState {
        /// Peers whose sends the mock accepts.
        ready: AHashSet<PublicKey>,
        /// Every peer passed to send, in order, including failed sends.
        attempts: Vec<PublicKey>,
        /// Whether unavailable peers report a closed sender instead of rejecting the send.
        closed: bool,
    }

    /// Records every send and accepts only peers in the shared ready set.
    #[derive(Clone, Debug)]
    struct RecordingSender(Arc<RwLock<SendState>>);

    impl UnlimitedSender for RecordingSender {
        type PublicKey = PublicKey;

        fn send(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
            _message: impl Into<IoBufs> + Send,
            _priority: bool,
        ) -> Unreliable<Feedback> {
            let Recipients::One(peer) = recipients else {
                unreachable!()
            };

            // Failed sends count as attempts too, making repeated visits to a peer observable.
            let mut state = self.0.write();
            state.attempts.push(peer.clone());
            if state.ready.contains(&peer) {
                Unreliable::new(Feedback::Ok)
            } else if state.closed {
                Unreliable::new(Feedback::Closed)
            } else {
                Unreliable::Rejected
            }
        }
    }

    impl LimitedSender for RecordingSender {
        type PublicKey = PublicKey;
        type Checked<'a> = CheckedSender<'a, Self>;

        fn check(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'_>, SystemTime> {
            Ok(CheckedSender {
                sender: self,
                recipients,
            })
        }
    }

    /// When every send fails, each eligible peer is tried once and stays eligible for later
    /// requests. Rejected and closed sends leave peer scores and the retry count unchanged.
    #[test]
    fn test_local_send_failures_are_bounded_and_preserve_scores() {
        // Exercise the shared and target pools, rejected and closed sends, and initial and
        // heavily retried keys.
        for targeted in [false, true] {
            for closed in [false, true] {
                for retries in [None, Some(u32::MAX)] {
                    Runner::seeded(0).start(|context| async move {
                        let mut fetcher = create_test_fetcher(context.child("fetcher"));
                        let peers: Vec<_> = (1..=3)
                            .map(|seed| PrivateKey::from_seed(seed).public_key())
                            .collect();
                        fetcher.reconcile(&peers);
                        let state = Arc::new(RwLock::new(SendState {
                            ready: [peers[0].clone()].into_iter().collect(),
                            attempts: Vec::new(),
                            closed,
                        }));
                        let mut sender = WrappedSender::new(RecordingSender(state.clone()));

                        // A successful fetch gives the first peer a score worth preserving.
                        fetcher.add_targets(MockKey(0), [peers[0].clone()]);
                        fetcher.add_ready(MockKey(0));
                        let (id, peer) = send_next(&mut fetcher, &mut sender);
                        context.sleep(Duration::from_millis(1)).await;
                        let (_, elapsed) = fetcher.pop_response(id, &peer).unwrap();
                        fetcher.record_response(&peer, elapsed, 1024);
                        fetcher.clear(&MockKey(0));
                        let before = peer_weight(&fetcher, &peer);
                        state.write().ready.clear();
                        state.write().attempts.clear();

                        // Make every send fail. A targeted key must consider only its targets.
                        // An unrestricted key must consider the entire eligible roster.
                        let key = MockKey(1);
                        let eligible = if targeted { &peers[..2] } else { &peers[..] };
                        if targeted {
                            fetcher.add_targets(key.clone(), eligible.iter().cloned());
                        }
                        if let Some(retries) = retries {
                            fetcher.retries.insert(key.clone(), retries);
                        }
                        fetcher.add_ready(key.clone());
                        fetcher.fetch(&mut sender);

                        // Exact distinct attempt counts catch a repeated peer, while the
                        // score, retry count, and cached weights must remain unchanged.
                        assert_eq!(fetcher.len_active(), 0);
                        assert_eq!(fetcher.len_pending(), 1);
                        assert_eq!(state.read().attempts.len(), eligible.len());
                        assert_eq!(
                            state
                                .read()
                                .attempts
                                .iter()
                                .cloned()
                                .collect::<AHashSet<_>>(),
                            eligible.iter().cloned().collect()
                        );
                        assert_eq!(peer_weight(&fetcher, &peer), before);
                        assert_eq!(fetcher.retries.get(&key).copied(), retries);
                        assert_eq!(
                            fetcher.get_pending_deadline(),
                            Some(context.current() + fetcher.retry_timeout)
                        );
                        assert_cached_weights(&fetcher);

                        // Once the sender is available, the next call can use the same peer.
                        // Temporary exclusions must not survive the earlier failed sends.
                        state.write().ready.insert(peer.clone());
                        state.write().attempts.clear();
                        context
                            .sleep_until(fetcher.get_pending_deadline().unwrap())
                            .await;
                        let (_, retried) = send_next(&mut fetcher, &mut sender);
                        assert_eq!(retried, peer);
                        assert!(state.read().attempts.len() <= eligible.len());
                        assert_eq!(peer_weight(&fetcher, &peer), before);
                        assert_eq!(fetcher.retries.get(&key).copied(), retries);
                        assert_cached_weights(&fetcher);
                    });
                }
            }
        }
    }
}
