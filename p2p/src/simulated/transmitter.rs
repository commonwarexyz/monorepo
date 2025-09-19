use super::bandwidth::{self, Flow, Rate};
use crate::Channel;
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_utils::Ratio;
use std::{
    collections::{btree_map::Entry, BTreeMap, VecDeque},
    time::{Duration, SystemTime},
};
use tracing::trace;

/// Message that is waiting to be delivered.
#[derive(Clone, Debug)]
pub struct Completion<P: PublicKey> {
    pub origin: P,
    pub recipient: P,
    pub channel: Channel,
    pub message: Bytes,
    pub deliver: bool,
    pub arrival_complete_at: Option<SystemTime>,
}

impl<P: PublicKey> Completion<P> {
    /// Creates a completion for a delivered message.
    fn delivered(
        origin: P,
        recipient: P,
        channel: Channel,
        message: Bytes,
        arrival_complete_at: SystemTime,
    ) -> Self {
        Self {
            origin,
            recipient,
            channel,
            message,
            deliver: true,
            arrival_complete_at: Some(arrival_complete_at),
        }
    }

    /// Creates a completion for a dropped message.
    fn dropped(origin: P, recipient: P, channel: Channel, message: Bytes) -> Self {
        Self {
            origin,
            recipient,
            channel,
            message,
            deliver: false,
            arrival_complete_at: None,
        }
    }
}

/// Message that has been buffered and will be delivered later.
#[derive(Clone, Debug)]
struct Buffered {
    channel: Channel,
    message: Bytes,
    arrival_complete_at: SystemTime,
}

/// Message that is queued to be sent.
#[derive(Clone, Debug)]
struct Queued {
    channel: Channel,
    message: Bytes,
    latency: Duration,
    should_deliver: bool,
    ready_at: SystemTime,
}

/// Bandwidth limits for a peer (bytes per second, `None` => unlimited).
#[derive(Clone, Debug)]
struct Bandwidth {
    egress: Option<u128>,
    ingress: Option<u128>,
}

/// Status of a flow (a single transmission request).
#[derive(Clone, Debug)]
struct Status<P: PublicKey> {
    origin: P,
    recipient: P,
    latency: Duration,
    deliver: bool,
    channel: Channel,
    message: Bytes,
    sequence: Option<u64>,
    remaining: u128,
    rate: Rate,
    carry: u128,
    last_update: SystemTime,
}

/// Deterministic scheduler responsible for simulating link bandwidth and delivery ordering.
///
/// Orchestration overview:
/// - `enqueue` is the public entry point for sending; it records the request, then immediately
///   calls `launch`, which may start a new flow. When a flow is created, `begin` installs it and
///   invokes `rebalance` so the bandwidth planner can recompute rates.
/// - The runtime drives progression with `next`/`process`. `next` reports the earlier of the
///   next bandwidth event or transmission-ready time. `process(now)` first `wake`s transmissions
///   whose start time has arrived, then keeps draining events occurring at `now`. Inside this loop
///   `rebalance` advances active flows and calls `finish` on completions, while another `wake`
///   handles newly eligible queued work.
/// - `finish` produces `Completion`s (via `stash` + `drain`) and immediately tries to `launch` the
///   next queued message for that peer pair, allowing back-to-back transmissions without waiting
///   for another outer tick. `schedule` keeps track of the earliest queued start time so `next`
///   always reflects both bandwidth expiries and queue readiness.
pub struct State<P: PublicKey + Ord + Clone> {
    bandwidth_limits: BTreeMap<P, Bandwidth>,
    next_flow_id: u64,
    assign_sequences: BTreeMap<(P, P), u64>,
    active_flows: BTreeMap<(P, P), u64>,
    all_flows: BTreeMap<u64, Status<P>>,
    queued: BTreeMap<(P, P), VecDeque<Queued>>,
    last_arrival_complete: BTreeMap<(P, P), SystemTime>,
    next_bandwidth_event: Option<SystemTime>,
    next_transmission_ready: Option<SystemTime>,
    expected_sequences: BTreeMap<(P, P), u64>,
    buffered: BTreeMap<(P, P), BTreeMap<u64, Buffered>>,
}

impl<P: PublicKey + Ord + Clone> State<P> {
    /// Creates a new scheduler.
    pub fn new() -> Self {
        Self {
            bandwidth_limits: BTreeMap::new(),
            next_flow_id: 0,
            assign_sequences: BTreeMap::new(),
            active_flows: BTreeMap::new(),
            all_flows: BTreeMap::new(),
            queued: BTreeMap::new(),
            last_arrival_complete: BTreeMap::new(),
            next_bandwidth_event: None,
            next_transmission_ready: None,
            expected_sequences: BTreeMap::new(),
            buffered: BTreeMap::new(),
        }
    }

    /// Records the latest bandwidth limits for `peer`.
    pub fn tune(&mut self, peer: &P, egress: Option<usize>, ingress: Option<usize>) {
        self.bandwidth_limits.insert(
            peer.clone(),
            Bandwidth {
                egress: egress.map(|bps| bps as u128),
                ingress: ingress.map(|bps| bps as u128),
            },
        );
    }

    /// Returns the egress bandwidth limit for `peer`.
    fn egress_limit(&self, peer: &P) -> Option<u128> {
        self.bandwidth_limits
            .get(peer)
            .and_then(|limits| limits.egress)
    }

    /// Returns the ingress bandwidth limit for `peer`.
    fn ingress_limit(&self, peer: &P) -> Option<u128> {
        self.bandwidth_limits
            .get(peer)
            .and_then(|limits| limits.ingress)
    }

    /// Returns the earliest scheduled event (bandwidth update or send readiness).
    pub fn next(&self) -> Option<SystemTime> {
        match (self.next_bandwidth_event, self.next_transmission_ready) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    /// Advances the simulation to `now`, draining any completed transmissions.
    pub fn process(&mut self, now: SystemTime) -> Vec<Completion<P>> {
        let mut completions = self.wake(now);

        // Process events until the next event is in the future.
        while let Some(next_event) = self.next() {
            if next_event > now {
                break;
            }

            let mut handled = false;
            if self
                .next_bandwidth_event
                .map(|event| event <= now && event == next_event)
                .unwrap_or(false)
            {
                self.next_bandwidth_event = None;
                let mut outcomes = self.rebalance(next_event);
                completions.append(&mut outcomes);
                handled = true;
            }

            if self
                .next_transmission_ready
                .map(|event| event <= now && event == next_event)
                .unwrap_or(false)
            {
                self.next_transmission_ready = None;
                let mut outcomes = self.wake(next_event);
                completions.append(&mut outcomes);
                handled = true;
            }

            if !handled {
                break;
            }
        }

        completions
    }

    /// Records a transmission request.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue(
        &mut self,
        now: SystemTime,
        origin: P,
        recipient: P,
        channel: Channel,
        message: Bytes,
        latency: Duration,
        should_deliver: bool,
    ) -> Vec<Completion<P>> {
        let key = (origin.clone(), recipient.clone());
        let mut entry = Queued {
            channel,
            message,
            latency,
            should_deliver,
            ready_at: now,
        };

        entry.ready_at = entry.ready_at.max(now);
        if let Some(arrival_complete) = self.last_arrival_complete.get(&key) {
            // Respect per-link serialization: ensure the new flow cannot arrive before the
            // previous one has finished propagating.
            if let Some(limit) = arrival_complete.checked_sub(entry.latency) {
                entry.ready_at = entry.ready_at.max(limit);
            }
        }
        self.queued.entry(key.clone()).or_default().push_back(entry);

        let completions = self.launch(origin, recipient, now);
        self.schedule(now);
        completions
    }

    /// Awakens any queued transmissions that have become ready to send at `now`.
    fn wake(&mut self, now: SystemTime) -> Vec<Completion<P>> {
        let ready_pairs: Vec<(P, P)> = self
            .queued
            .iter()
            .filter_map(|(key, queue)| {
                if self.active_flows.contains_key(key) {
                    return None;
                }
                queue.front().and_then(|entry| {
                    if entry.ready_at <= now {
                        Some(key.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();

        let mut completions = Vec::new();
        for (origin, recipient) in ready_pairs {
            completions.extend(self.launch(origin, recipient, now));
        }
        self.schedule(now);
        completions
    }

    /// Recomputes bandwidth allocations and collects any flows that finished in the interval.
    fn rebalance(&mut self, now: SystemTime) -> Vec<Completion<P>> {
        let mut completed = Vec::new();

        for (&flow_id, meta) in self.all_flows.iter_mut() {
            // First, account for bytes already in flight since the previous tick.
            if meta.remaining > 0 {
                let elapsed = now
                    .duration_since(meta.last_update)
                    .unwrap_or(Duration::ZERO);
                if !elapsed.is_zero() {
                    let sent =
                        bandwidth::transfer(&meta.rate, elapsed, &mut meta.carry, meta.remaining);
                    if sent > 0 {
                        meta.remaining = meta.remaining.saturating_sub(sent);
                    }
                }
            }
            meta.last_update = now;
            if meta.remaining == 0 {
                completed.push(flow_id);
            }
        }

        completed.sort();
        completed.dedup();

        let mut active: Vec<Flow<P>> = Vec::new();
        for (&flow_id, meta) in self.all_flows.iter() {
            if meta.remaining == 0 {
                continue;
            }
            active.push(Flow {
                id: flow_id,
                origin: meta.origin.clone(),
                recipient: meta.recipient.clone(),
                requires_ingress: meta.deliver,
            });
        }

        if active.is_empty() {
            self.next_bandwidth_event = None;
            return self.finish(completed, now);
        }

        let mut egress_limit = |pk: &P| self.egress_limit(pk);
        let mut ingress_limit = |pk: &P| self.ingress_limit(pk);
        let allocations = bandwidth::allocate(&active, &mut egress_limit, &mut ingress_limit);
        let mut earliest: Option<Duration> = None;

        for (flow_id, rate) in allocations {
            if let Some(meta) = self.all_flows.get_mut(&flow_id) {
                meta.rate = rate.clone();
                meta.carry = 0;
                meta.last_update = now;

                if matches!(meta.rate, Rate::Unlimited) {
                    if meta.remaining > 0 {
                        meta.remaining = 0;
                        completed.push(flow_id);
                    }
                    continue;
                }

                if let Some(duration) = bandwidth::time_to_deplete(&meta.rate, meta.remaining) {
                    earliest = match earliest {
                        None => Some(duration),
                        Some(current) => Some(current.min(duration)),
                    };
                }
            }
        }

        completed.sort();
        completed.dedup();

        // Record the next time at which a bandwidth event should fire.
        self.next_bandwidth_event = earliest.and_then(|duration| {
            if duration.is_zero() {
                Some(now)
            } else {
                now.checked_add(duration)
            }
        });

        self.finish(completed, now)
    }

    /// Finalizes completed flows and opportunistically starts follow-on work.
    fn finish(&mut self, completed: Vec<u64>, now: SystemTime) -> Vec<Completion<P>> {
        let mut outcomes = Vec::new();

        for flow_id in completed {
            let Some(meta) = self.all_flows.remove(&flow_id) else {
                continue;
            };

            let Status {
                origin,
                recipient,
                latency,
                deliver,
                channel,
                message,
                sequence,
                ..
            } = meta;

            self.active_flows
                .remove(&(origin.clone(), recipient.clone()));

            let arrival_complete_at = if deliver {
                now.checked_add(latency)
                    .expect("latency overflow computing arrival completion")
            } else {
                now
            };

            if deliver {
                if let Some(seq) = sequence {
                    let buffered = Buffered {
                        channel,
                        message,
                        arrival_complete_at,
                    };
                    outcomes.extend(self.stash(origin.clone(), recipient.clone(), seq, buffered));
                }
            } else {
                trace!(
                    ?origin,
                    ?recipient,
                    reason = "random link failure",
                    "dropping message",
                );
                outcomes.push(Completion::dropped(
                    origin.clone(),
                    recipient.clone(),
                    channel,
                    message,
                ));
            }

            self.last_arrival_complete
                .insert((origin.clone(), recipient.clone()), arrival_complete_at);

            outcomes.extend(self.launch(origin, recipient, now));
        }
        self.schedule(now);

        outcomes
    }

    /// Buffers an arrival until preceding transmissions are released.
    fn stash(
        &mut self,
        origin: P,
        recipient: P,
        seq: u64,
        buffered: Buffered,
    ) -> Vec<Completion<P>> {
        let key = (origin.clone(), recipient.clone());
        self.buffered
            .entry(key.clone())
            .or_default()
            .insert(seq, buffered);
        self.drain(key)
    }

    /// Emits any pending deliveries for the given pair whose sequence is now in order.
    fn drain(&mut self, key: (P, P)) -> Vec<Completion<P>> {
        let expected_entry = self.expected_sequences.entry(key.clone()).or_insert(0);
        let mut delivered = Vec::new();

        loop {
            let buffered = match self.buffered.entry(key.clone()) {
                Entry::Occupied(mut occ) => {
                    if let Some(p) = occ.get_mut().remove(expected_entry) {
                        if occ.get().is_empty() {
                            occ.remove();
                        }
                        Some(p)
                    } else {
                        None
                    }
                }
                Entry::Vacant(_) => None,
            };
            let Some(buffered) = buffered else { break };

            delivered.push(Completion::delivered(
                key.0.clone(),
                key.1.clone(),
                buffered.channel,
                buffered.message,
                buffered.arrival_complete_at,
            ));

            *expected_entry += 1;
        }

        delivered
    }

    /// Updates `next_transmission_ready` by peeking at each queue head.
    fn schedule(&mut self, now: SystemTime) {
        let mut next_ready: Option<SystemTime> = None;
        for (key, queue) in self.queued.iter() {
            if self.active_flows.contains_key(key) {
                continue;
            }
            if let Some(entry) = queue.front() {
                let candidate = if entry.ready_at <= now {
                    now
                } else {
                    entry.ready_at
                };
                next_ready = match next_ready {
                    None => Some(candidate),
                    Some(current) => Some(current.min(candidate)),
                };
            }
        }
        self.next_transmission_ready = next_ready;
    }

    /// Attempts to start a new flow for the pair, optionally refreshing scheduling metadata.
    fn launch(&mut self, origin: P, recipient: P, now: SystemTime) -> Vec<Completion<P>> {
        let key = (origin.clone(), recipient.clone());
        if self.active_flows.contains_key(&key) {
            return Vec::new();
        }

        let mut entry_to_start = None;
        let mut remove_queue = false;

        if let Some(queue) = self.queued.get_mut(&key) {
            if let Some(front) = queue.front_mut() {
                let mut ready_at = front.ready_at.max(now);
                if let Some(arrival_complete) = self.last_arrival_complete.get(&key) {
                    // Enforce per-link serialization: the next hop cannot depart until the
                    // previous arrival (plus latency) has fully cleared.
                    if let Some(limit) = arrival_complete.checked_sub(front.latency) {
                        ready_at = ready_at.max(limit);
                    }
                }
                if ready_at <= now {
                    entry_to_start = queue.pop_front();
                    if queue.is_empty() {
                        remove_queue = true;
                    }
                } else {
                    front.ready_at = ready_at;
                }
            } else {
                remove_queue = true;
            }
        }

        if remove_queue {
            self.queued.remove(&key);
        }

        if let Some(entry) = entry_to_start {
            let flow_id = self.next_flow_id;
            self.next_flow_id += 1;
            self.active_flows.insert(key, flow_id);
            return self.begin(origin, recipient, flow_id, entry, now);
        }

        Vec::new()
    }

    /// Materializes a flow record and triggers a bandwidth rebalance.
    fn begin(
        &mut self,
        origin: P,
        recipient: P,
        flow_id: u64,
        entry: Queued,
        now: SystemTime,
    ) -> Vec<Completion<P>> {
        let Queued {
            channel,
            message,
            latency,
            should_deliver,
            ..
        } = entry;

        let deliver = should_deliver && origin != recipient;
        let remaining = message.len() as u128;
        let sequence = if deliver {
            Some(self.tag(&origin, &recipient))
        } else {
            None
        };

        self.all_flows.insert(
            flow_id,
            Status {
                origin: origin.clone(),
                recipient: recipient.clone(),
                latency,
                deliver,
                channel,
                message,
                sequence,
                remaining,
                rate: Rate::Finite(Ratio::zero()),
                carry: 0,
                last_update: now,
            },
        );

        trace!(
            ?origin,
            ?recipient,
            latency_ms = latency.as_millis(),
            delivered = deliver,
            "sending message",
        );

        let completions = self.rebalance(now);
        self.schedule(now);
        completions
    }

    /// Returns the next sequence identifier used to preserve FIFO delivery per link.
    fn tag(&mut self, origin: &P, recipient: &P) -> u64 {
        let key = (origin.clone(), recipient.clone());
        let counter = self.assign_sequences.entry(key).or_insert(0);
        let seq = *counter;
        *counter += 1;
        seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_cryptography::{ed25519, PrivateKeyExt as _, Signer as _};
    use std::time::{Duration, SystemTime};

    const CHANNEL: Channel = 0;

    fn key(seed: u64) -> ed25519::PublicKey {
        ed25519::PrivateKey::from_seed(seed).public_key()
    }

    #[test]
    fn queue_immediate_completion_with_unlimited_capacity() {
        let mut state = State::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = key(1);
        let recipient = key(2);

        let completions = state.enqueue(
            now,
            origin,
            recipient,
            CHANNEL,
            Bytes::from_static(b"hello"),
            Duration::ZERO,
            true,
        );

        assert_eq!(completions.len(), 1);
        let completion = &completions[0];
        assert!(completion.deliver);
        assert_eq!(completion.arrival_complete_at, Some(now));
    }

    #[test]
    fn queue_dropped_message_records_outcome() {
        let mut state = State::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = key(3);
        let recipient = key(4);

        let completions = state.enqueue(
            now,
            origin,
            recipient,
            CHANNEL,
            Bytes::from_static(b"drop"),
            Duration::ZERO,
            false,
        );

        assert_eq!(completions.len(), 1);
        assert!(!completions[0].deliver);
        assert!(completions[0].arrival_complete_at.is_none());
    }

    #[test]
    fn fifo_delivery_per_pair() {
        let mut state = State::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = key(10);
        let recipient = key(11);
        let make_bytes = |value: u8| Bytes::from(vec![value; 1_000]);

        state.tune(&origin, Some(1_000), None);

        let completions = state.enqueue(
            now,
            origin.clone(),
            recipient.clone(),
            CHANNEL,
            make_bytes(1),
            Duration::from_secs(1),
            true,
        );
        assert!(completions.is_empty());

        let first_finish = state.next().expect("first completion scheduled");
        assert_eq!(first_finish, now + Duration::from_secs(1));

        let completions = state.process(first_finish);
        assert_eq!(completions.len(), 1);
        let completion_a = &completions[0];
        assert!(completion_a.deliver);
        assert_eq!(
            completion_a.arrival_complete_at,
            Some(first_finish + Duration::from_secs(1))
        );

        let completions = state.enqueue(
            now,
            origin.clone(),
            recipient.clone(),
            CHANNEL,
            make_bytes(2),
            Duration::ZERO,
            true,
        );
        assert!(completions.is_empty());

        let completions = state.process(now);
        assert!(completions.is_empty());

        let next_ready = state.next().expect("second transfer should be scheduled");
        assert_eq!(next_ready, first_finish + Duration::from_secs(1));

        let completions = state.process(next_ready);
        assert!(completions.is_empty());

        let second_finish = state.next().expect("second completion scheduled");
        assert_eq!(second_finish, next_ready + Duration::from_secs(1));

        let completions = state.process(second_finish);
        assert_eq!(completions.len(), 1);
        let completion_b = &completions[0];
        assert!(completion_b.deliver);
        assert_eq!(completion_b.arrival_complete_at, Some(second_finish));
        assert_eq!(completion_b.message.len(), 1_000);
        assert_eq!(completion_b.message[0], 2);
    }

    #[test]
    fn staggered_latencies_allow_overlap() {
        let mut state = State::new();
        let start = SystemTime::UNIX_EPOCH;
        let origin = key(21);
        let recipient = key(22);

        state.tune(&origin, Some(500_000), None); // 500 KB/s

        let msg_a = Bytes::from(vec![0xAA; 1_000_000]);
        let msg_b = Bytes::from(vec![0xBB; 500_000]);

        let completions = state.enqueue(
            start,
            origin.clone(),
            recipient.clone(),
            CHANNEL,
            msg_a.clone(),
            Duration::from_millis(500),
            true,
        );
        assert!(completions.is_empty());

        let completions = state.enqueue(
            start,
            origin.clone(),
            recipient.clone(),
            CHANNEL,
            msg_b.clone(),
            Duration::from_millis(100),
            true,
        );
        assert!(completions.is_empty());

        let first_finish = state.next().expect("message A completion scheduled");
        assert_eq!(first_finish, start + Duration::from_millis(2000));

        let completions = state.process(first_finish);
        assert_eq!(completions.len(), 1);
        let completion_a = &completions[0];
        assert!(completion_a.deliver);
        assert_eq!(completion_a.message.len(), msg_a.len());
        assert_eq!(
            completion_a.arrival_complete_at,
            Some(first_finish + Duration::from_millis(500))
        );

        let next_ready = state.next().expect("message B send should be scheduled");
        assert_eq!(
            next_ready,
            first_finish + Duration::from_millis(500) - Duration::from_millis(100)
        );

        let completions = state.process(next_ready);
        assert!(completions.is_empty());

        let second_finish = state.next().expect("message B completion scheduled");
        assert_eq!(second_finish, next_ready + Duration::from_secs_f64(1.0));

        let completions = state.process(second_finish);
        assert_eq!(completions.len(), 1);
        let completion_b = &completions[0];
        assert!(completion_b.deliver);
        assert_eq!(completion_b.message.len(), msg_b.len());
        assert_eq!(
            completion_b.arrival_complete_at,
            Some(second_finish + Duration::from_millis(100))
        );

        assert_eq!(
            completion_a.arrival_complete_at,
            Some(start + Duration::from_millis(2500))
        );
        assert_eq!(
            completion_b.arrival_complete_at,
            Some(start + Duration::from_millis(3500))
        );
    }

    #[test]
    fn equal_split_across_destinations() {
        let mut state = State::new();
        let now = SystemTime::UNIX_EPOCH;
        let origin = key(30);
        let recipient_b = key(31);
        let recipient_c = key(32);

        state.tune(&origin, Some(1_000), None);

        let msg_b = Bytes::from(vec![0xBB; 1_000]);
        let msg_c = Bytes::from(vec![0xCC; 1_000]);

        let completions = state.enqueue(
            now,
            origin.clone(),
            recipient_b.clone(),
            CHANNEL,
            msg_b.clone(),
            Duration::ZERO,
            true,
        );
        assert!(completions.is_empty());

        let completions = state.enqueue(
            now,
            origin.clone(),
            recipient_c.clone(),
            CHANNEL,
            msg_c.clone(),
            Duration::ZERO,
            true,
        );
        assert!(completions.is_empty());

        let finish = state.next().expect("completion scheduled");
        assert_eq!(finish, now + Duration::from_secs(2));

        let completions = state.process(finish);
        assert_eq!(completions.len(), 2);

        let mut recipients: Vec<_> = completions
            .iter()
            .map(|c| {
                assert!(c.deliver);
                assert_eq!(c.message.len(), 1_000);
                assert_eq!(c.arrival_complete_at, Some(finish));
                c.recipient.clone()
            })
            .collect();
        recipients.sort();
        let mut expected = vec![recipient_b, recipient_c];
        expected.sort();
        assert_eq!(recipients, expected);

        assert!(state.next().is_none());
    }
}
